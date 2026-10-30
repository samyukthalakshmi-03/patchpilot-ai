import { groupInventoryByProduct } from "./productDiscovery.js";
import {
  buildProductSearchPlan,
  classifyAdvisorySource,
  deduplicateSources,
  normalizeSourceUrl,
} from "./sourceDiscovery.js";
import { normalizeAdvisoryPages } from "./advisoryNormalizer.js";

const SEARCH_URL = "https://api.search.tinyfish.ai";
const FETCH_URL = "https://api.fetch.tinyfish.ai";
const DEFAULT_RESEARCH_DEADLINE_MS = 300000;
const DEFAULT_REQUEST_TIMEOUT_MS = 20000;
const MAX_SOURCE_URLS_PER_PRODUCT = 2;
const MAX_TOTAL_SOURCE_URLS = 4;
const MAX_CONCURRENT_SEARCHES = 8;
const MAX_CONCURRENT_FETCHES = 3;
const MAX_TRANSIENT_HTTP_RETRIES = 2;
const TRANSIENT_HTTP_STATUSES = new Set([502, 503, 504]);

const inFlightResearch = new Map();

export class TinyFishResearchError extends Error {
  constructor(message, { code, httpStatus, cause } = {}) {
    super(message, { cause });
    this.name = "TinyFishResearchError";
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

function safeText(value, apiKey) {
  return String(value || "")
    .replaceAll(apiKey, "[REDACTED]")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, 500);
}

function errorDetail(body, apiKey) {
  try {
    const data = JSON.parse(body);
    return safeText(data.error?.message || data.message || body, apiKey);
  } catch {
    return safeText(body, apiKey);
  }
}

async function requestJson(url, options, {
  apiKey,
  fetchImpl,
  timeoutMs,
  deadline,
  logger,
}) {
  let response;
  let body;
  for (let attempt = 0; ; attempt += 1) {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      throw new TinyFishResearchError(
        "TinyFish research exceeded its configured deadline.",
        { code: "TINYFISH_RESEARCH_TIMEOUT" }
      );
    }

    try {
      response = await fetchImpl(url, {
        ...options,
        signal: AbortSignal.timeout(Math.min(timeoutMs, remainingMs)),
      });
      body = await response.text();
    } catch (error) {
      const code = error.name === "TimeoutError"
        ? "TINYFISH_REQUEST_TIMEOUT"
        : error.cause?.code || error.code || "TINYFISH_CONNECTION_ERROR";
      const message = error.name === "TimeoutError"
        ? "A TinyFish Search or Fetch request timed out."
        : "Could not connect to a TinyFish Search or Fetch service.";
      logger.error("TinyFish Search/Fetch request failed", {
        service: new URL(url).hostname,
        code,
        message: safeText(error.cause?.message || error.message, apiKey),
      });
      throw new TinyFishResearchError(message, { code, cause: error });
    }

    if (
      response.ok ||
      !TRANSIENT_HTTP_STATUSES.has(response.status) ||
      attempt >= MAX_TRANSIENT_HTTP_RETRIES
    ) {
      break;
    }

    const delayMs = 500 * (2 ** attempt);
    if (deadline - Date.now() <= delayMs) {
      throw new TinyFishResearchError(
        "TinyFish research exceeded its configured deadline while retrying a temporary service error.",
        { code: "TINYFISH_RESEARCH_TIMEOUT", httpStatus: response.status }
      );
    }
    logger.warn("Retrying a transient TinyFish HTTP response", {
      service: new URL(url).hostname,
      httpStatus: response.status,
      retry: attempt + 1,
      maxRetries: MAX_TRANSIENT_HTTP_RETRIES,
      delayMs,
    });
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }

  if (!response.ok) {
    const detail = errorDetail(body, apiKey);
    logger.error("TinyFish Search/Fetch returned an HTTP error", {
      httpStatus: response.status,
      detail,
    });
    throw new TinyFishResearchError(
      `TinyFish Search/Fetch returned HTTP ${response.status}${detail ? `: ${detail}` : ""}`,
      { code: "TINYFISH_HTTP_ERROR", httpStatus: response.status }
    );
  }

  try {
    return JSON.parse(body);
  } catch (error) {
    throw new TinyFishResearchError(
      "TinyFish Search/Fetch returned invalid JSON.",
      { code: "TINYFISH_INVALID_RESPONSE", cause: error }
    );
  }
}

function positiveMilliseconds(value, settingName) {
  const milliseconds = Number(value);
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) {
    throw new TinyFishResearchError(
      `${settingName} must be a positive whole number of milliseconds.`,
      { code: "TINYFISH_CONFIGURATION_ERROR" }
    );
  }
  return milliseconds;
}

function queryUrl(query) {
  const url = new URL(SEARCH_URL);
  for (const [key, value] of Object.entries({
    ...query,
    language: "en",
  })) {
    url.searchParams.set(key, value);
  }
  return url;
}

function searchResultsFrom(response) {
  return Array.isArray(response?.results) ? response.results : [];
}

function fetchedPagesFrom(response, sourceUrl) {
  const pages = Array.isArray(response?.results) ? [...response.results] : [];
  const structuredAdvisories = [
    response?.advisories,
    response?.result?.advisories,
    response?.data?.advisories,
    response?.result?.data?.advisories,
  ].find(Array.isArray);
  if (structuredAdvisories?.length) {
    pages.push({
      url: response.url || response.result?.url || sourceUrl,
      advisories: structuredAdvisories,
    });
  }
  return pages;
}

async function settleWithConcurrency(tasks, concurrency) {
  const results = new Array(tasks.length);
  let nextIndex = 0;
  const worker = async () => {
    while (nextIndex < tasks.length) {
      const index = nextIndex++;
      try {
        results[index] = {
          status: "fulfilled",
          value: await tasks[index](),
        };
      } catch (reason) {
        results[index] = { status: "rejected", reason };
      }
    }
  };
  await Promise.all(
    Array.from(
      { length: Math.min(concurrency, tasks.length) },
      () => worker()
    )
  );
  return results;
}

async function runUniversalResearch(assets, {
  apiKey,
  deadlineMs,
  requestTimeoutMs,
  fetchImpl,
  logger,
}) {
  if (!apiKey) {
    throw new TinyFishResearchError("TINYFISH_API_KEY is not configured.", {
      code: "TINYFISH_KEY_MISSING",
    });
  }

  const groups = groupInventoryByProduct(assets);
  if (!groups.length) {
    throw new TinyFishResearchError(
      "At least one software product is required for research.",
      { code: "SOFTWARE_PRODUCT_MISSING" }
    );
  }

  const deadline = Date.now() + deadlineMs;
  const requestOptions = {
    apiKey,
    fetchImpl,
    timeoutMs: requestTimeoutMs,
    deadline,
    logger,
  };
  const plans = groups.map(buildProductSearchPlan);
  const searchTasks = plans.flatMap((plan) =>
    plan.queries.map((query) => async () => ({
      plan,
      response: await requestJson(
        queryUrl(query),
        { headers: { "X-API-Key": apiKey } },
        requestOptions
      ),
    }))
  );
  const settledSearches = await settleWithConcurrency(
    searchTasks,
    MAX_CONCURRENT_SEARCHES
  );
  const productResearch = new Map(groups.map((group) => [
    group,
    {
      advisories: [],
      notes: [],
      searchCount: 0,
      sourceCount: 0,
      sourcesInspected: [],
    },
  ]));
  const candidateGroups = new Map();
  for (const plan of plans) {
    for (const seed of plan.knownSources) {
      const source = classifyAdvisorySource(seed.url, plan.group);
      if (!source) continue;
      const sourceKey = normalizeSourceUrl(source.url);
      const existing = candidateGroups.get(sourceKey) || {
        source: {
          ...source,
          sourceName: seed.sourceName || source.sourceName,
        },
        groups: new Set(),
        rank: 0,
      };
      existing.groups.add(plan.group);
      candidateGroups.set(sourceKey, existing);
    }
  }
  let failedSearchCount = 0;

  for (const result of settledSearches) {
    if (result.status !== "fulfilled") {
      failedSearchCount += 1;
      continue;
    }

    const { plan, response } = result.value;
    const state = productResearch.get(plan.group);
    state.searchCount += 1;
    for (const item of searchResultsFrom(response)) {
      const source = classifyAdvisorySource(item.url, plan.group);
      if (!source) continue;
      const sourceKey = normalizeSourceUrl(source.url);
      const existing = candidateGroups.get(sourceKey) || {
        source,
        groups: new Set(),
        rank: source.sourceType === "official-vendor" ||
          source.sourceType === "distribution-security-tracker" ? 0 : 1,
      };
      existing.groups.add(plan.group);
      candidateGroups.set(sourceKey, existing);
    }
  }

  if (
    failedSearchCount === searchTasks.length &&
    candidateGroups.size === 0
  ) {
    const firstError = settledSearches.find((result) =>
      result.status === "rejected"
    )?.reason;
    throw firstError || new TinyFishResearchError(
      "TinyFish Search could not complete any product research queries.",
      { code: "TINYFISH_SEARCH_FAILED" }
    );
  }

  const orderedCandidates = [...candidateGroups.values()]
    .sort((left, right) => left.rank - right.rank);
  const selectedGroupsByUrl = new Map();
  const selectedUrlsByGroup = new Map(groups.map((group) => [group, new Set()]));
  for (let sourceIndex = 0;
    sourceIndex < MAX_SOURCE_URLS_PER_PRODUCT &&
      selectedGroupsByUrl.size < MAX_TOTAL_SOURCE_URLS;
    sourceIndex += 1
  ) {
    for (const group of groups) {
      if (selectedGroupsByUrl.size >= MAX_TOTAL_SOURCE_URLS) break;
      if (selectedUrlsByGroup.get(group).size > sourceIndex) continue;
      const candidate = orderedCandidates.find((item) =>
        item.groups.has(group) &&
        !selectedUrlsByGroup.get(group).has(item.source.url)
      );
      if (!candidate) continue;

      const existing = selectedGroupsByUrl.get(candidate.source.url) || {
        source: candidate.source,
        groups: [],
      };
      if (!existing.groups.includes(group)) existing.groups.push(group);
      selectedGroupsByUrl.set(candidate.source.url, existing);
      selectedUrlsByGroup.get(group).add(candidate.source.url);
    }
  }
  const candidates = selectedGroupsByUrl;
  const sourceUrls = [...candidates.keys()];

  if (sourceUrls.length === 0) {
    for (const group of groups) {
      productResearch.get(group).notes.push(
        `No authoritative security source could be verified for ${group.vendor ? `${group.vendor} ` : ""}${group.product}.`
      );
    }
  }

  let fetchedPages = [];
  if (sourceUrls.length > 0) {
    logger.info("TinyFish Fetch inspecting official product sources", {
      sourceCount: sourceUrls.length,
      productCount: groups.length,
    });
    const fetchTasks = sourceUrls.map((sourceUrl) => async () => ({
      sourceUrl,
      response: await requestJson(FETCH_URL, {
        method: "POST",
        headers: {
          "X-API-Key": apiKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          urls: [sourceUrl],
          format: "markdown",
          ttl: 0,
        }),
      }, requestOptions),
    }));
    const settledFetches = await settleWithConcurrency(
      fetchTasks,
      MAX_CONCURRENT_FETCHES
    );

    for (const result of settledFetches) {
      if (result.status === "rejected") {
        continue;
      }
      const { sourceUrl, response } = result.value;
      const pages = fetchedPagesFrom(response, sourceUrl);
      fetchedPages.push(...pages);
      const errors = Array.isArray(response.errors) ? response.errors : [];
      if (pages.length === 0 || errors.length > 0) {
        const selected = candidates.get(sourceUrl);
        for (const group of selected?.groups || []) {
          productResearch.get(group).notes.push(
            `TinyFish could not retrieve a complete response from ${selected.source.sourceName}.`
          );
        }
      }
    }

    for (let index = 0; index < settledFetches.length; index += 1) {
      const result = settledFetches[index];
      if (result.status !== "rejected") continue;
      const selected = candidates.get(sourceUrls[index]);
      logger.warn("TinyFish source fetch failed", {
        sourceName: selected?.source.sourceName || "Unknown source",
        code: result.reason?.code || "TINYFISH_FETCH_ERROR",
        httpStatus: result.reason?.httpStatus || null,
      });
      for (const group of selected?.groups || []) {
        productResearch.get(group).notes.push(
          `TinyFish could not retrieve ${selected.source.sourceName}; other discovered sources were still checked.`
        );
      }
    }

    for (const page of fetchedPages) {
      const sourceSelection = candidates.get(normalizeSourceUrl(page.url));
      const sourceGroups = sourceSelection?.groups || [];
      for (const group of sourceGroups) {
        const normalized = normalizeAdvisoryPages(
          [page],
          group,
          classifyAdvisorySource
        );
        productResearch.get(group).advisories.push(...normalized);
        const state = productResearch.get(group);
        state.sourceCount += 1;
        state.sourcesInspected.push({
          sourceName: sourceSelection.source.sourceName,
          sourceType: sourceSelection.source.sourceType,
          sourceUrl: sourceSelection.source.url,
          sourceVerified: sourceSelection.source.verified,
        });
      }
    }
  }

  const advisories = [];
  const researchNotes = [];
  for (const group of groups) {
    const state = productResearch.get(group);
    const productLabel = group.vendor
      ? `${group.product} (vendor context: ${group.vendor})`
      : group.product;
    state.sourcesInspected = deduplicateSources(state.sourcesInspected);
    state.sourceCount = state.sourcesInspected.length;
    if (state.searchCount < plans.find((plan) => plan.group === group).queries.length) {
      state.notes.push(
        `Some TinyFish searches failed for ${productLabel}; source coverage may be incomplete.`
      );
    }
    if (state.advisories.length === 0) {
      state.notes.push(state.sourceCount === 0
        ? `No authoritative security advisory evidence could be retrieved for ${productLabel}; assessment requires review and this does not establish that the software is secure.`
        : `No CVE advisory with verifiable evidence was extracted for ${productLabel}; this does not establish that the software is secure.`);
    }
    if (
      state.sourceCount < selectedUrlsByGroup.get(group).size
    ) {
      state.notes.push(
        `TinyFish could not inspect every discovered source for ${productLabel}; coverage may be incomplete.`
      );
    }
    state.advisories = state.advisories.filter((advisory, index, all) =>
      all.findIndex((other) =>
        other.product === advisory.product &&
        other.vendor === advisory.vendor &&
        other.cveId === advisory.cveId &&
        normalizeSourceUrl(other.sourceUrl) ===
          normalizeSourceUrl(advisory.sourceUrl)
      ) === index
    );
    advisories.push(...state.advisories);
    researchNotes.push(
      `TinyFish inspected ${state.sourceCount} authoritative source page(s) for ${productLabel}.`,
      ...state.notes
    );
  }

  if (failedSearchCount > 0) {
    researchNotes.push(
      `${failedSearchCount} TinyFish search query/queries failed; findings may be incomplete.`
    );
  }

  return {
    advisories,
    research_notes: [...new Set(researchNotes)],
    product_research: groups.map((group) => {
      const state = productResearch.get(group);
      return {
        product: group.product,
        vendor: group.vendor || "UNKNOWN",
        sourceCount: state.sourceCount,
        sourcesInspected: state.sourcesInspected,
        researchNotes: [...state.notes],
      };
    }),
    sources_inspected: deduplicateSources(groups.flatMap((group) =>
      productResearch.get(group).sourcesInspected.map((source) => ({
        product: group.product,
        vendor: group.vendor || "UNKNOWN",
        ...source,
      }))
    ), { includeProduct: true }),
  };
}

export function researchWithTinyFishFast(assets, options = {}) {
  const key = JSON.stringify({
    assets: assets.map((asset) => ({
      name: asset.name,
      product: asset.product,
      softwareName: asset.softwareName,
      vendor: asset.vendor,
      version: asset.version,
      operatingSystem: asset.operatingSystem,
      buildType: asset.buildType,
      packageManager: asset.packageManager,
      architecture: asset.architecture,
      installedConfiguration: asset.installedConfiguration,
    })),
    apiKey: options.apiKey ?? process.env.TINYFISH_API_KEY,
  });
  const existing = inFlightResearch.get(key);
  if (existing) return existing;

  const run = runUniversalResearch(assets, {
    apiKey: options.apiKey ?? process.env.TINYFISH_API_KEY,
    deadlineMs: positiveMilliseconds(
      options.deadlineMs ??
      process.env.TINYFISH_RESEARCH_DEADLINE_MS ??
      DEFAULT_RESEARCH_DEADLINE_MS,
      "TINYFISH_RESEARCH_DEADLINE_MS"
    ),
    requestTimeoutMs: positiveMilliseconds(
      options.requestTimeoutMs ??
      process.env.TINYFISH_REQUEST_TIMEOUT_MS ??
      DEFAULT_REQUEST_TIMEOUT_MS,
      "TINYFISH_REQUEST_TIMEOUT_MS"
    ),
    fetchImpl: options.fetchImpl ?? fetch,
    logger: options.logger ?? console,
  });
  inFlightResearch.set(key, run);
  run.finally(() => {
    if (inFlightResearch.get(key) === run) {
      inFlightResearch.delete(key);
    }
  }).catch(() => {});
  return run;
}
