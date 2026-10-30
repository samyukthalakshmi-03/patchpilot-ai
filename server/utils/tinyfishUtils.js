const AUTOMATION_URL = "https://agent.tinyfish.ai/v1/automation";
const RUNS_URL = "https://agent.tinyfish.ai/v1/runs";
const DEFAULT_POLL_INTERVAL_MS = 2000;
const DEFAULT_RESEARCH_DEADLINE_MS = 300000;
const DEFAULT_REQUEST_TIMEOUT_MS = 20000;

const NETWORK_ERROR_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "EAI_AGAIN",
  "ENETUNREACH",
  "ENOTFOUND",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
  "TINYFISH_REQUEST_TIMEOUT",
]);

const activeResearch = new Map();

export class TinyFishError extends Error {
  constructor(message, { code, httpStatus, runId, cause } = {}) {
    super(message, { cause });
    this.name = "TinyFishError";
    this.code = code;
    this.httpStatus = httpStatus;
    this.runId = runId;
  }
}

export class TinyFishTimeoutError extends TinyFishError {
  constructor(runId, deadlineMs) {
    const deadlineMinutes = Math.ceil(deadlineMs / 60000);
    super(`TinyFish research exceeded its ${deadlineMinutes}-minute deadline.`, {
      code: "TINYFISH_RESEARCH_TIMEOUT",
      runId,
    });
    this.name = "TinyFishTimeoutError";
  }
}

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function safeText(value, apiKey) {
  const text = String(value || "")
    .replaceAll(apiKey, "[REDACTED]")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim();
  return text.slice(0, 500);
}

function responseErrorMessage(body, apiKey) {
  try {
    const data = JSON.parse(body);
    return safeText(
      data.error?.message || data.message || data.error || body,
      apiKey
    );
  } catch {
    return safeText(body, apiKey);
  }
}

async function requestJson(url, options, {
  apiKey,
  fetchImpl,
  requestTimeoutMs,
  runId,
  logger,
}) {
  let response;
  let responseText;
  try {
    response = await fetchImpl(url, {
      ...options,
      signal: AbortSignal.timeout(requestTimeoutMs),
    });
    responseText = await response.text();
  } catch (error) {
    const errorCode = error.name === "TimeoutError"
      ? "TINYFISH_REQUEST_TIMEOUT"
      : error.cause?.code || error.code || error.name;
    logger.error("TinyFish request connection failed", {
      runId: runId || null,
      code: errorCode,
      message: safeText(error.cause?.message || error.message, apiKey),
    });
    throw new TinyFishError(
      runId
        ? `Lost connection while polling TinyFish run ${runId}.`
        : "Could not confirm whether TinyFish accepted the research request; it was not retried to avoid starting a duplicate run.",
      {
        code: NETWORK_ERROR_CODES.has(errorCode)
          ? errorCode
          : "TINYFISH_CONNECTION_ERROR",
        runId,
        cause: error,
      }
    );
  }

  if (!response.ok) {
    const detail = responseErrorMessage(responseText, apiKey);
    logger.error("TinyFish returned an HTTP error", {
      runId: runId || null,
      httpStatus: response.status,
      detail,
    });
    throw new TinyFishError(
      `TinyFish returned HTTP ${response.status}${detail ? `: ${detail}` : ""}`,
      {
        code: "TINYFISH_HTTP_ERROR",
        httpStatus: response.status,
        runId,
      }
    );
  }

  try {
    return JSON.parse(responseText);
  } catch (error) {
    throw new TinyFishError("TinyFish returned invalid JSON.", {
      code: "TINYFISH_INVALID_RESPONSE",
      runId,
      cause: error,
    });
  }
}

function parseResearchResult(result, runId) {
  if (typeof result !== "string") {
    return result;
  }

  const cleaned = result
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (error) {
    throw new TinyFishError(
      "TinyFish completed the run but returned invalid research JSON.",
      {
        code: "TINYFISH_INVALID_RESULT",
        runId,
        cause: error,
      }
    );
  }
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function startAndPollResearch(goal, {
  apiKey,
  pollIntervalMs,
  deadlineMs,
  requestTimeoutMs,
  fetchImpl,
  sleep,
  now,
  logger,
}) {
  if (!apiKey) {
    throw new TinyFishError("TINYFISH_API_KEY is not configured.", {
      code: "TINYFISH_KEY_MISSING",
    });
  }

  const headers = {
    "X-API-Key": apiKey,
    "Content-Type": "application/json",
  };
  const queuedRun = await requestJson(`${AUTOMATION_URL}/run-async`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      url: "https://www.php.net/releases/",
      goal,
      agent_config: {
        max_duration_seconds: Math.ceil(deadlineMs / 1000),
      },
    }),
  }, {
    apiKey,
    fetchImpl,
    requestTimeoutMs,
    logger,
  });

  const runId = queuedRun.run_id;
  if (typeof runId !== "string" || !runId.trim()) {
    const detail = safeText(queuedRun.error?.message, apiKey);
    throw new TinyFishError(
      detail || "TinyFish did not return a run ID for the research request.",
      { code: "TINYFISH_RUN_ID_MISSING" }
    );
  }

  logger.info("TinyFish research run started", { runId });
  const deadline = now() + deadlineMs;

  while (now() < deadline) {
    await sleep(Math.min(pollIntervalMs, deadline - now()));
    const remainingMs = deadline - now();
    if (remainingMs <= 0) break;

    let run;
    try {
      run = await requestJson(
        `${RUNS_URL}/${encodeURIComponent(runId)}`,
        { headers },
        {
          apiKey,
          fetchImpl,
          requestTimeoutMs: Math.min(requestTimeoutMs, remainingMs),
          runId,
          logger,
        }
      );
    } catch (error) {
      if (
        error instanceof TinyFishError &&
        NETWORK_ERROR_CODES.has(error.code) &&
        now() < deadline
      ) {
        logger.warn("Retrying TinyFish status poll after a connection error", {
          runId,
          code: error.code,
        });
        continue;
      }
      throw error;
    }

    const status = String(run.status || "").toUpperCase();
    if (status === "COMPLETED") {
      logger.info("TinyFish research run completed", { runId });
      return parseResearchResult(run.result ?? run, runId);
    }

    if (status === "FAILED" || status === "CANCELLED") {
      const detail = safeText(
        run.error?.message || run.error || `Run status: ${status}`,
        apiKey
      );
      logger.error("TinyFish research run failed", { runId, status, detail });
      throw new TinyFishError(`TinyFish run ${status.toLowerCase()}: ${detail}`, {
        code: `TINYFISH_RUN_${status}`,
        runId,
      });
    }

    if (status !== "PENDING" && status !== "RUNNING") {
      throw new TinyFishError(
        `TinyFish returned an unrecognized status for run ${runId}.`,
        {
          code: "TINYFISH_UNKNOWN_RUN_STATUS",
          runId,
        }
      );
    }
  }

  logger.error("TinyFish research run timed out", { runId, deadlineMs });
  try {
    await requestJson(`${RUNS_URL}/${encodeURIComponent(runId)}/cancel`, {
      method: "POST",
      headers,
    }, {
      apiKey,
      fetchImpl,
      requestTimeoutMs,
      runId,
      logger,
    });
  } catch (error) {
    logger.warn("Could not cancel timed-out TinyFish run", {
      runId,
      code: error.code || "TINYFISH_CANCEL_ERROR",
    });
  }
  throw new TinyFishTimeoutError(runId, deadlineMs);
}

export function researchWithTinyFish(goal, options = {}) {
  const configuration = {
    apiKey: options.apiKey ?? process.env.TINYFISH_API_KEY,
    pollIntervalMs: positiveInteger(
      options.pollIntervalMs ?? process.env.TINYFISH_POLL_INTERVAL_MS,
      DEFAULT_POLL_INTERVAL_MS
    ),
    deadlineMs: positiveInteger(
      options.deadlineMs ?? process.env.TINYFISH_RESEARCH_DEADLINE_MS,
      DEFAULT_RESEARCH_DEADLINE_MS
    ),
    requestTimeoutMs: positiveInteger(
      options.requestTimeoutMs ?? process.env.TINYFISH_REQUEST_TIMEOUT_MS,
      DEFAULT_REQUEST_TIMEOUT_MS
    ),
    fetchImpl: options.fetchImpl ?? fetch,
    sleep: options.sleep ?? wait,
    now: options.now ?? Date.now,
    logger: options.logger ?? console,
  };

  const existingRun = activeResearch.get(goal);
  if (existingRun) return existingRun;

  const researchRun = startAndPollResearch(goal, configuration);
  activeResearch.set(goal, researchRun);
  researchRun.finally(() => {
    if (activeResearch.get(goal) === researchRun) {
      activeResearch.delete(goal);
    }
  }).catch(() => {});

  return researchRun;
}
