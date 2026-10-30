import test from "node:test";
import assert from "node:assert/strict";

import {
  researchWithTinyFish,
  TinyFishError,
  TinyFishTimeoutError,
} from "../utils/tinyfishUtils.js";

const API_KEY = "test-key-not-for-logs";

function response(data, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(data),
  };
}

function createLogger() {
  const entries = [];
  return {
    entries,
    info: (...args) => entries.push(args),
    warn: (...args) => entries.push(args),
    error: (...args) => entries.push(args),
  };
}

test("starts once, polls the documented run endpoint, and returns completed research", async () => {
  const requests = [];
  const statuses = [
    { run_id: "run-success-1", status: "RUNNING" },
    {
      run_id: "run-success-1",
      status: "COMPLETED",
      result: { advisories: [], research_notes: [] },
    },
  ];

  const result = await researchWithTinyFish("research success test", {
    apiKey: API_KEY,
    deadlineMs: 300000,
    pollIntervalMs: 10,
    sleep: async () => {},
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      if (url.endsWith("/run-async")) return response({ run_id: "run-success-1" });
      return response(statuses.shift());
    },
    logger: createLogger(),
  });

  assert.deepEqual(result, { advisories: [], research_notes: [] });
  assert.equal(requests.filter(({ url }) => url.endsWith("/run-async")).length, 1);
  assert.equal(
    requests[0].url,
    "https://agent.tinyfish.ai/v1/automation/run-async"
  );
  assert.equal(requests[0].options.method, "POST");
  assert.equal(requests[0].options.headers["X-API-Key"], API_KEY);
  const requestBody = JSON.parse(requests[0].options.body);
  assert.equal(requestBody.url, "https://www.php.net/releases/");
  assert.equal(requestBody.agent_config.max_duration_seconds, 300);
  assert.equal(
    requests[1].url,
    "https://agent.tinyfish.ai/v1/runs/run-success-1"
  );
  assert.equal(requests[1].options.method, undefined);
});

test("parses completed JSON string results", async () => {
  const result = await researchWithTinyFish("research string-result test", {
    apiKey: API_KEY,
    pollIntervalMs: 1,
    sleep: async () => {},
    fetchImpl: async (url) => url.endsWith("/run-async")
      ? response({ run_id: "run-string-result" })
      : response({
        run_id: "run-string-result",
        status: "COMPLETED",
        result: '```json\n{"advisories":[]}\n```',
      }),
    logger: createLogger(),
  });

  assert.deepEqual(result, { advisories: [] });
});

test("returns a clear error and run ID for failed TinyFish runs", async () => {
  await assert.rejects(
    researchWithTinyFish("research failure test", {
      apiKey: API_KEY,
      pollIntervalMs: 1,
      sleep: async () => {},
      fetchImpl: async (url) => url.endsWith("/run-async")
        ? response({ run_id: "run-failed-1" })
        : response({
          run_id: "run-failed-1",
          status: "FAILED",
          error: { message: "Browser execution failed" },
        }),
      logger: createLogger(),
    }),
    (error) => {
      assert.ok(error instanceof TinyFishError);
      assert.equal(error.code, "TINYFISH_RUN_FAILED");
      assert.equal(error.runId, "run-failed-1");
      assert.match(error.message, /Browser execution failed/);
      return true;
    }
  );
});

test("cancels the run and reports a clear timeout at the configured deadline", async () => {
  const calls = [];
  let time = 0;
  await assert.rejects(
    researchWithTinyFish("research timeout test", {
      apiKey: API_KEY,
      deadlineMs: 3,
      pollIntervalMs: 2,
      sleep: async (ms) => { time += ms; },
      now: () => time,
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        if (url.endsWith("/run-async")) {
          return response({ run_id: "run-timeout-1" });
        }
        if (url.endsWith("/cancel")) return response({ ok: true });
        return response({ run_id: "run-timeout-1", status: "RUNNING" });
      },
      logger: createLogger(),
    }),
    (error) => {
      assert.ok(error instanceof TinyFishTimeoutError);
      assert.equal(error.code, "TINYFISH_RESEARCH_TIMEOUT");
      assert.equal(error.runId, "run-timeout-1");
      assert.match(error.message, /1-minute deadline/);
      return true;
    }
  );

  assert.equal(calls.filter(({ url }) => url.endsWith("/run-async")).length, 1);
  assert.equal(calls.filter(({ url }) => url.endsWith("/cancel")).length, 1);
});

test("retries a transient poll connection reset without starting another run", async () => {
  let starts = 0;
  let polls = 0;
  const result = await researchWithTinyFish("research transient-poll test", {
    apiKey: API_KEY,
    pollIntervalMs: 1,
    sleep: async () => {},
    fetchImpl: async (url) => {
      if (url.endsWith("/run-async")) {
        starts += 1;
        return response({ run_id: "run-reset-1" });
      }

      polls += 1;
      if (polls === 1) {
        const error = new TypeError("fetch failed");
        error.cause = Object.assign(new Error("connection reset"), {
          code: "ECONNRESET",
        });
        throw error;
      }

      return response({
        run_id: "run-reset-1",
        status: "COMPLETED",
        result: { advisories: [] },
      });
    },
    logger: createLogger(),
  });

  assert.deepEqual(result, { advisories: [] });
  assert.equal(starts, 1);
  assert.equal(polls, 2);
});

test("shares an in-flight identical research request instead of creating duplicates", async () => {
  let releaseStart;
  let starts = 0;
  const startResponse = new Promise((resolve) => {
    releaseStart = resolve;
  });
  const options = {
    apiKey: API_KEY,
    pollIntervalMs: 1,
    sleep: async () => {},
    fetchImpl: async (url) => {
      if (url.endsWith("/run-async")) {
        starts += 1;
        return startResponse;
      }
      return response({
        run_id: "run-deduped-1",
        status: "COMPLETED",
        result: { advisories: [] },
      });
    },
    logger: createLogger(),
  };

  const first = researchWithTinyFish("identical research request", options);
  const second = researchWithTinyFish("identical research request", options);
  assert.equal(first, second);
  releaseStart(response({ run_id: "run-deduped-1" }));

  await Promise.all([first, second]);
  assert.equal(starts, 1);
});

test("redacts the API key from TinyFish HTTP errors and logs", async () => {
  const logger = createLogger();
  await assert.rejects(
    researchWithTinyFish("research safe-error test", {
      apiKey: API_KEY,
      fetchImpl: async () => response(
        { error: { message: `Rejected credential ${API_KEY}` } },
        401
      ),
      logger,
    }),
    (error) => {
      assert.equal(error.httpStatus, 401);
      assert.ok(!error.message.includes(API_KEY));
      return true;
    }
  );

  assert.ok(!JSON.stringify(logger.entries).includes(API_KEY));
});
