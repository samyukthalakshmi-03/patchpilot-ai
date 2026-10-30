import test from "node:test";
import assert from "node:assert/strict";

import {
  researchWithTinyFishFast,
  TinyFishResearchError,
} from "../utils/tinyfishResearch.js";

const API_KEY = "fast-test-key-not-for-logs";
const assets = [
  {
    name: "Web Server A",
    product: "PHP",
    version: "8.3.35",
    operatingSystem: "Unknown",
    buildType: "Unknown",
  },
];

const advisoryPage = {
  url: "https://github.com/php/php-src/security/advisories/GHSA-test-1234-abcd",
  title: "Test PHP RCE advisory",
  text: `# Test PHP RCE advisory

Critical

## Affected versions

< 8.3.36

## Patched versions

8.3.36

## Description

CVE-2026-98765 affects PHP 8.3 before the patched version.
`,
};

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

test("searches official sources, fetches them, and extracts verified advisory fields", async () => {
  const requests = [];
  const result = await researchWithTinyFishFast(assets, {
    apiKey: API_KEY,
    fetchImpl: async (url, options) => {
      requests.push({ url: String(url), options });
      if (String(url).startsWith("https://api.search.tinyfish.ai")) {
        return response({
          results: [{
            url: advisoryPage.url,
            title: advisoryPage.title,
            snippet: "PHP CVE-2026-98765 security advisory",
          }],
        });
      }

      return response({ results: [advisoryPage], errors: [] });
    },
    logger: createLogger(),
  });

  assert.equal(requests.filter(({ url }) =>
    url.startsWith("https://api.search.tinyfish.ai")
  ).length, 2);
  assert.equal(requests[0].options.headers["X-API-Key"], API_KEY);
  const searchQuery = new URL(requests[0].url).searchParams.get("query");
  assert.match(searchQuery, /operating system Unknown; build type Unknown/);
  assert.ok(!searchQuery.includes("Web Server A"));

  const fetchRequest = requests.find(({ url }) =>
    url === "https://api.fetch.tinyfish.ai"
  );
  assert.ok(fetchRequest);
  assert.equal(fetchRequest.options.method, "POST");
  assert.equal(fetchRequest.options.headers["X-API-Key"], API_KEY);
  const fetchBody = JSON.parse(fetchRequest.options.body);
  assert.equal(fetchBody.format, "markdown");
  assert.equal(fetchBody.ttl, 0);
  assert.ok(fetchBody.urls.includes(advisoryPage.url));

  assert.equal(result.advisories.length, 1);
  assert.deepEqual(result.advisories[0], {
    product: "PHP",
    title: "Test PHP RCE advisory",
    cve_id: "CVE-2026-98765",
    advisory_type: "SECURITY_VULNERABILITY",
    severity: "CRITICAL",
    affected_versions: "< 8.3.36",
    fixed_version: "8.3.36",
    operating_systems_affected: "UNKNOWN",
    build_restrictions: "UNKNOWN",
    required_configuration_conditions: "UNKNOWN",
    remediation: "Upgrade to PHP 8.3.36.",
    source_name: "PHP Security Advisory (GitHub)",
    source_url: advisoryPage.url,
  });
});

test("extracts Windows and configuration restrictions from an advisory page", async () => {
  const windowsPage = {
    url: "https://github.com/php/php-src/security/advisories/GHSA-test-windows",
    title: "PHP CGI advisory",
    text: `# PHP CGI advisory

This affects PHP CGI on Windows when it is configured with the legacy codepage setting, and bypasses CVE-2024-4577.

CVE-2026-98766

## Affected versions

< 8.3.36

## Patched versions

8.3.36
`,
  };
  const result = await researchWithTinyFishFast(assets, {
    apiKey: API_KEY,
    fetchImpl: async (url) => {
      if (String(url).startsWith("https://api.search.tinyfish.ai")) {
        return response({ results: [{ url: windowsPage.url }] });
      }
      return response({ results: [windowsPage], errors: [] });
    },
    logger: createLogger(),
  });

  assert.equal(result.advisories.length, 1);
  assert.equal(result.advisories[0].cve_id, "CVE-2026-98766");
  assert.equal(result.advisories[0].operating_systems_affected, "Windows");
  assert.equal(
    result.advisories[0].build_restrictions,
    "Windows-specific applicability"
  );
  assert.equal(
    result.advisories[0].required_configuration_conditions,
    "This affects PHP CGI on Windows when it is configured with the legacy codepage setting, and bypasses CVE-2024-4577."
  );
});

test("rejects unverified sources and non-advisory PHP changelogs", async () => {
  let fetchBody;
  const result = await researchWithTinyFishFast(assets, {
    apiKey: API_KEY,
    fetchImpl: async (url, options) => {
      if (String(url).startsWith("https://api.search.tinyfish.ai")) {
        return response({
          results: [
            { url: "https://example.com/fake-cve", title: "Fake advisory" },
            { url: "http://github.com/php/php-src/security/advisories/GHSA-1" },
            { url: "https://www.php.net/ChangeLog-8.php" },
          ],
        });
      }
      fetchBody = JSON.parse(options.body);
      return response({
        results: [{
          url: "https://www.php.net/archive/2026.php",
          title: "PHP 2026 archive",
          text: "No advisory for the supplied PHP release branch.",
        }],
        errors: [],
      });
    },
    logger: createLogger(),
  });

  assert.deepEqual(result.advisories, []);
  assert.ok(!fetchBody.urls.includes("https://www.php.net/ChangeLog-8.php"));
  assert.match(result.research_notes.join(" "), /does not establish that the assets are secure/i);
});

test("reports a TinyFish Search timeout without exposing credentials", async () => {
  const logger = createLogger();
  await assert.rejects(
    researchWithTinyFishFast(assets, {
      apiKey: API_KEY,
      fetchImpl: async () => {
        const error = new Error(`timeout ${API_KEY}`);
        error.name = "TimeoutError";
        throw error;
      },
      logger,
    }),
    (error) => {
      assert.ok(error instanceof TinyFishResearchError);
      assert.equal(error.code, "TINYFISH_REQUEST_TIMEOUT");
      assert.match(error.message, /request timed out/i);
      assert.ok(!error.message.includes(API_KEY));
      return true;
    }
  );

  assert.ok(!JSON.stringify(logger.entries).includes(API_KEY));
});

test("returns clear HTTP errors from TinyFish services", async () => {
  await assert.rejects(
    researchWithTinyFishFast(assets, {
      apiKey: API_KEY,
      fetchImpl: async () => response(
        { error: { message: "Invalid API key" } },
        401
      ),
      logger: createLogger(),
    }),
    (error) => {
      assert.ok(error instanceof TinyFishResearchError);
      assert.equal(error.code, "TINYFISH_HTTP_ERROR");
      assert.equal(error.httpStatus, 401);
      assert.match(error.message, /HTTP 401.*Invalid API key/);
      return true;
    }
  );
});

test("coalesces duplicate in-flight inventory research", async () => {
  let releaseSearch;
  let searchCalls = 0;
  const pendingSearch = new Promise((resolve) => {
    releaseSearch = resolve;
  });
  const options = {
    apiKey: API_KEY,
    fetchImpl: async (url) => {
      if (String(url).startsWith("https://api.search.tinyfish.ai")) {
        searchCalls += 1;
        return pendingSearch;
      }
      return response({ results: [advisoryPage], errors: [] });
    },
    logger: createLogger(),
  };

  const first = researchWithTinyFishFast(assets, options);
  const second = researchWithTinyFishFast(assets, options);
  assert.equal(first, second);

  releaseSearch(response({ results: [{ url: advisoryPage.url }] }));
  await Promise.all([first, second]);
  assert.equal(searchCalls, 2);
});
