const SEARCH_URL = "https://api.search.tinyfish.ai";
const FETCH_URL = "https://api.fetch.tinyfish.ai";
const DEFAULT_RESEARCH_DEADLINE_MS = 300000;
const DEFAULT_REQUEST_TIMEOUT_MS = 20000;
const MAX_SOURCE_URLS = 8;

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
  const remainingMs = deadline - Date.now();
  if (remainingMs <= 0) {
    throw new TinyFishResearchError(
      "TinyFish research exceeded its five-minute deadline.",
      { code: "TINYFISH_RESEARCH_TIMEOUT" }
    );
  }

  const requestTimeoutMs = Math.min(timeoutMs, remainingMs);
  let response;
  let body;
  try {
    response = await fetchImpl(url, {
      ...options,
      signal: AbortSignal.timeout(requestTimeoutMs),
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
      code,
      message: safeText(error.cause?.message || error.message, apiKey),
    });
    throw new TinyFishResearchError(message, { code, cause: error });
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

function getVersionBranch(version) {
  return String(version || "").match(/\d+\.\d+/)?.[0] || "";
}

function getOfficialSourceUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") return "";

    if (
      (url.hostname === "github.com" ||
        url.hostname === "www.github.com") &&
      /^\/php\/php-src\/security\/advisories\/[A-Za-z0-9-]+\/?$/i
        .test(url.pathname)
    ) {
      return url.href;
    }

    if (
      (url.hostname === "php.net" || url.hostname === "www.php.net") &&
      /^\/(?:archive\/\d{4}\.php|releases\/\d+_\d+_\d+\.php)$/i
        .test(url.pathname)
    ) {
      return url.href;
    }
  } catch {
    return "";
  }

  return "";
}

function extractSection(text, sectionName) {
  const heading = new RegExp(
    `^#{1,6}\\s*${sectionName}\\s*$`,
    "im"
  );
  const match = heading.exec(text);
  if (!match) return "";

  const contentStart = match.index + match[0].length;
  const nextHeading = /^#{1,6}\s+.+$/gm;
  nextHeading.lastIndex = contentStart;
  const nextMatch = nextHeading.exec(text);

  return text.slice(contentStart, nextMatch?.index ?? text.length).trim();
}

function getCveContext(text, cveId) {
  const blocks = text.split(/\n{2,}/);
  const index = blocks.findIndex((block) =>
    block.toUpperCase().includes(cveId)
  );
  if (index < 0) return text;

  const heading = blocks
    .slice(0, index + 1)
    .reverse()
    .find((block) => /^#{1,6}\s+/.test(block));

  return [heading, blocks[index], blocks[index + 1]]
    .filter(Boolean)
    .join("\n\n");
}

function versionEntries(text) {
  return [...new Set(
    String(text).match(/\b\d+\.\d+\.\d+(?:-\d+)?\b/g) || []
  )];
}

function matchingVersionLine(text, branch) {
  return String(text)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) =>
      line && line.match(/\d+\.\d+/)?.[0] === branch
    )
    .join("; ");
}

function severityFromText(text) {
  const match = String(text).match(
    /^\s*(?:severity\s*:?\s*)?(critical|high|moderate|medium|low)\s*$/im
  );
  return match ? match[1].toUpperCase() : "UNKNOWN";
}

function configurationFromText(text) {
  const paragraphs = String(text).split(/\n{2,}/);
  const condition = paragraphs.find((paragraph) =>
    /\b(?:when|if|only when|only if)\b/i.test(paragraph) &&
    /\b(?:enabled|disabled|configured|configuration|setting)\b/i.test(paragraph)
  );
  return condition
    ? condition.replace(/\s+/g, " ").trim()
    : "UNKNOWN";
}

function explicitCveIds(text) {
  const ids = String(text).matchAll(
    /^[ \t]*(?:#{1,6}[ \t]*)?(?:[-*][ \t]*)?(?:CVE(?:[ \t]+ID)?[ \t]*[:#][ \t]*)?(CVE-\d{4}-\d+)(?=$|[\s:),.;])/gim
  );
  return [...new Set(
    [...ids].map((match) => match[1].toUpperCase())
  )];
}

function advisoriesFromPage(page, assets) {
  const text = String(page.text || "");
  const sourceUrl = getOfficialSourceUrl(page.url);
  if (!sourceUrl) return [];

  const isGithubAdvisory = new URL(sourceUrl).hostname === "github.com";
  const cveIds = isGithubAdvisory
    ? explicitCveIds(text)
    : [...new Set(text.match(/CVE-\d{4}-\d+/gi) || [])];
  if (cveIds.length === 0) return [];

  const affectedSection = extractSection(text, "Affected versions");
  const patchedSection = extractSection(text, "Patched versions");
  const patchedVersions = versionEntries(patchedSection);
  const pageTitle = String(page.title || "").trim();
  const heading = text.match(/^#{1,3}\s+(.+)$/m)?.[1]?.trim();
  const title = heading || pageTitle || "PHP security advisory";
  const sourceName = new URL(sourceUrl).hostname === "github.com"
    ? "PHP Security Advisory (GitHub)"
    : "PHP";
  const results = [];

  for (const cveId of cveIds) {
    const context = isGithubAdvisory
      ? text
      : getCveContext(text, cveId);
    const evidence = `${affectedSection}\n${patchedSection}\n${context}`;
    const branches = new Set(
      versionEntries(evidence)
        .map((version) => getVersionBranch(version))
        .filter(Boolean)
    );
    const isWindowsBuild =
      /\bwindows\s+builds?\b|\bon\s+windows\b|\bwindows[- ]only\b/i
        .test(context);
    const affectedOperatingSystems = isWindowsBuild
      ? "Windows"
      : "UNKNOWN";
    const buildRestrictions = isWindowsBuild
      ? "Windows-specific applicability"
      : "UNKNOWN";
    const requiredConfigurationConditions =
      configurationFromText(context);

    for (const branch of branches) {
      if (!assets.some((asset) =>
        getVersionBranch(asset.version) === branch
      )) {
        continue;
      }

      const affectedVersions = matchingVersionLine(
        affectedSection,
        branch
      ) || "UNKNOWN";
      const fixedVersion = patchedVersions.find((version) =>
        getVersionBranch(version) === branch
      ) || "UNKNOWN";

      const existing = results.find((advisory) =>
        advisory.cve_id === cveId &&
        advisory.fixed_version === fixedVersion &&
        advisory.source_url === sourceUrl
      );
      if (existing) continue;

      results.push({
        product: "PHP",
        title,
        cve_id: cveId.toUpperCase(),
        advisory_type: "SECURITY_VULNERABILITY",
        severity: severityFromText(text),
        affected_versions: affectedVersions,
        fixed_version: fixedVersion,
        operating_systems_affected: affectedOperatingSystems,
        build_restrictions: buildRestrictions,
        required_configuration_conditions: requiredConfigurationConditions,
        remediation: fixedVersion === "UNKNOWN"
          ? "UNKNOWN"
          : `Upgrade to PHP ${fixedVersion}.`,
        source_name: sourceName,
        source_url: sourceUrl,
      });
    }
  }

  return results;
}

async function runFastResearch(assets, {
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

  const branches = [...new Set(
    assets.map((asset) => getVersionBranch(asset.version)).filter(Boolean)
  )];
  if (branches.length === 0) {
    throw new TinyFishResearchError(
      "No PHP release branches could be identified in the inventory.",
      { code: "PHP_VERSION_BRANCH_MISSING" }
    );
  }

  const versions = assets.map((asset) => asset.version).join(", ");
  const platformContext = [...new Set(assets.map((asset) =>
    `operating system ${asset.operatingSystem || "Unknown"}; build type ${asset.buildType || "Unknown"}`
  ))].join(" | ");
  const searchQueries = [
    {
      query: `PHP security release advisory CVE versions ${versions}; inventory platform context: ${platformContext}`,
      include_domains: "php.net",
    },
    {
      query: `site:github.com/php/php-src/security/advisories PHP security advisory CVE ${branches.join(" ")}; inventory platform context: ${platformContext}`,
      include_domains: "github.com",
    },
  ];
  const deadline = Date.now() + deadlineMs;
  const requestOptions = {
    apiKey,
    fetchImpl,
    timeoutMs: requestTimeoutMs,
    deadline,
    logger,
  };
  const searchResponses = await Promise.allSettled(
    searchQueries.map((query) => {
      const searchUrl = new URL(SEARCH_URL);
      for (const [key, value] of Object.entries({
        ...query,
        language: "en",
      })) {
        searchUrl.searchParams.set(key, value);
      }

      return requestJson(searchUrl, {
        headers: { "X-API-Key": apiKey },
      }, requestOptions);
    })
  );

  const searchErrors = searchResponses
    .filter((result) => result.status === "rejected")
    .map((result) => result.reason);
  const searchResults = searchResponses
    .filter((result) => result.status === "fulfilled")
    .flatMap((result) => result.value.results || []);
  if (searchResults.length === 0) {
    throw searchErrors[0] || new TinyFishResearchError(
      "TinyFish Search returned no official PHP advisory results.",
      { code: "TINYFISH_NO_SEARCH_RESULTS" }
    );
  }

  const sourceUrls = [
    `https://www.php.net/archive/${new Date().getFullYear()}.php`,
    ...searchResults
      .map((result) => getOfficialSourceUrl(result.url))
      .filter(Boolean),
  ].filter((url, index, all) => all.indexOf(url) === index)
    .slice(0, MAX_SOURCE_URLS);

  const fetched = await requestJson(FETCH_URL, {
    method: "POST",
    headers: {
      "X-API-Key": apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      urls: sourceUrls,
      format: "markdown",
      ttl: 0,
    }),
  }, requestOptions);

  const pages = Array.isArray(fetched.results) ? fetched.results : [];
  if (pages.length === 0) {
    const fetchErrors = Array.isArray(fetched.errors)
      ? fetched.errors.map((item) => safeText(item.error, apiKey)).join("; ")
      : "";
    throw new TinyFishResearchError(
      fetchErrors
        ? `TinyFish could not fetch official PHP sources: ${fetchErrors}`
        : "TinyFish Fetch returned no official PHP source content.",
      { code: "TINYFISH_NO_FETCHED_SOURCES" }
    );
  }

  const advisories = pages.flatMap((page) =>
    advisoriesFromPage(page, assets)
  ).filter((advisory, index, all) =>
    all.findIndex((candidate) =>
      candidate.cve_id === advisory.cve_id &&
      candidate.fixed_version === advisory.fixed_version &&
      candidate.source_url === advisory.source_url
    ) === index
  );

  const researchNotes = [];
  if (searchErrors.length > 0) {
    researchNotes.push(
      "One TinyFish Search query failed; results may not include all official advisories."
    );
  }
  if (Array.isArray(fetched.errors) && fetched.errors.length > 0) {
    researchNotes.push(
      `${fetched.errors.length} official source page(s) could not be fetched.`
    );
  }
  researchNotes.push(
    `TinyFish Search and Fetch inspected ${pages.length} official PHP source page(s) for PHP ${branches.join(", ")}.`
  );
  if (advisories.length === 0) {
    researchNotes.push(
      "No structured CVE advisory with explicit version evidence was extracted; this does not establish that the assets are secure."
    );
  }

  return {
    advisories,
    research_notes: researchNotes,
  };
}

export function researchWithTinyFishFast(assets, options = {}) {
  const key = JSON.stringify(
    assets.map(({ name, product, version, operatingSystem, buildType }) => ({
      name,
      product,
      version,
      operatingSystem,
      buildType,
    }))
  );
  const existing = inFlightResearch.get(key);
  if (existing) return existing;

  const run = runFastResearch(assets, {
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
