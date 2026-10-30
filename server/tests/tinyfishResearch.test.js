import test from "node:test";
import assert from "node:assert/strict";

import {
  researchWithTinyFishFast,
  TinyFishResearchError,
} from "../utils/tinyfishResearch.js";
import {
  buildProductSearchPlan,
  classifyAdvisorySource,
  deduplicateSources,
} from "../utils/sourceDiscovery.js";
import { normalizeInventoryAsset } from "../utils/productDiscovery.js";
import {
  normalizeAdvisoryPages,
  normalizeAdvisoryRecord,
} from "../utils/advisoryNormalizer.js";

const API_KEY = "fast-test-key-not-for-logs";

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

function makeAsset(product, version, fields = {}) {
  return normalizeInventoryAsset({
    name: `${product} host`,
    product,
    version,
    ...fields,
  });
}

function makeAdvisoryPage({ url, product, title, cve, fixedVersion }) {
  return {
    url,
    title,
    product,
    text: `# ${title}

${product} security vulnerability

CVE ID: ${cve}

Severity: High
CVSS score: 8.1
Published: 2026-04-15

## Affected versions

< ${fixedVersion}

## Patched versions

${fixedVersion}

## Remediation

Upgrade to ${fixedVersion}.
`,
  };
}

const nodePage = makeAdvisoryPage({
  url: "https://nodejs.org/en/blog/vulnerability/test-advisory",
  product: "Node.js",
  title: "Node.js test advisory",
  cve: "CVE-2026-11001",
  fixedVersion: "22.14.1",
});
const pythonPage = makeAdvisoryPage({
  url: "https://github.com/python/cpython/security/advisories/GHSA-test-python",
  product: "Python",
  title: "Python test advisory",
  cve: "CVE-2026-11002",
  fixedVersion: "3.13.3",
});

function searchResponseFor(url, pages) {
  const query = new URL(url).searchParams.get("query") || "";
  const page = pages.find((candidate) =>
    query.toLowerCase().includes(candidate.product.toLowerCase())
  );
  return response({
    results: page ? [{ url: page.url, title: page.title }] : [],
  });
}

test("researches Node.js and normalizes verified source and CVE evidence", async () => {
  const requests = [];
  const result = await researchWithTinyFishFast(
    [makeAsset("Node.js", "22.14.0", { vendor: "OpenJS Foundation" })],
    {
      apiKey: API_KEY,
      fetchImpl: async (url, options) => {
        requests.push({ url: String(url), options });
        if (String(url).startsWith("https://api.search.tinyfish.ai")) {
          return searchResponseFor(url, [nodePage]);
        }
        return response({ results: [nodePage], errors: [] });
      },
      logger: createLogger(),
    }
  );

  const searchRequests = requests.filter(({ url }) =>
    url.startsWith("https://api.search.tinyfish.ai")
  );
  assert.equal(searchRequests.length, 2);
  assert.ok(searchRequests.every(({ options }) =>
    options.headers["X-API-Key"] === API_KEY
  ));
  assert.match(new URL(searchRequests[0].url).searchParams.get("query"), /Node\.js/);

  const fetchRequest = requests.find(({ url }) =>
    url === "https://api.fetch.tinyfish.ai"
  );
  assert.ok(fetchRequest);
  assert.deepEqual(JSON.parse(fetchRequest.options.body).urls, [nodePage.url]);

  assert.equal(result.advisories.length, 1);
  const [advisory] = result.advisories;
  assert.equal(advisory.product, "Node.js");
  assert.equal(advisory.vendor, "OpenJS Foundation");
  assert.equal(advisory.cveId, "CVE-2026-11001");
  assert.equal(advisory.severity, "HIGH");
  assert.equal(advisory.cvssScore, 8.1);
  assert.equal(advisory.affectedVersions, "< 22.14.1");
  assert.equal(advisory.fixedVersion, "22.14.1");
  assert.equal(advisory.publishedDate, "2026-04-15");
  assert.equal(advisory.sourceUrl, nodePage.url);
  assert.equal(advisory.sourceVerified, true);
  assert.ok(advisory.verifiedInformation.includes("fixed version"));
});

test("preserves structured TinyFish findings when fetch notes report incomplete extraction", async () => {
  const structuredAdvisory = {
    product: "Node.js",
    cve_id: "CVE-2026-12004",
    severity: "HIGH",
    cvss_score: 8.4,
    affected_versions: "< 22.14.1",
    fixed_version: "22.14.1",
    publication_date: "2026-04-15",
    remediation: "Upgrade to Node.js 22.14.1 or later.",
    evidence_excerpt: "Node.js versions before 22.14.1 are affected.",
  };
  const result = await researchWithTinyFishFast(
    [makeAsset("Node.js", "22.14.0")],
    {
      apiKey: API_KEY,
      fetchImpl: async (url) => {
        if (String(url).startsWith("https://api.search.tinyfish.ai")) {
          return searchResponseFor(url, [nodePage]);
        }
        return response({
          advisories: [structuredAdvisory],
          errors: [{ message: "Additional page content was unavailable." }],
        });
      },
      logger: createLogger(),
    }
  );
  const [advisory] = result.advisories;

  assert.equal(advisory.cveId, "CVE-2026-12004");
  assert.equal(advisory.cvssScore, 8.4);
  assert.equal(advisory.fixedVersion, "22.14.1");
  assert.equal(advisory.publishedDate, "2026-04-15");
  assert.equal(advisory.remediation, "Upgrade to Node.js 22.14.1 or later.");
  assert.equal(advisory.evidenceExcerpt, "Node.js versions before 22.14.1 are affected.");
  assert.match(result.research_notes.join(" "), /could not retrieve a complete response/i);
});

test("researches mixed-product inventory independently and retains source attribution", async () => {
  const pages = [nodePage, pythonPage];
  const requests = [];
  const result = await researchWithTinyFishFast([
    makeAsset("Node", "22.14.0"),
    makeAsset("Python", "3.13.2"),
  ], {
    apiKey: API_KEY,
    fetchImpl: async (url, options) => {
      requests.push({ url: String(url), options });
      if (String(url).startsWith("https://api.search.tinyfish.ai")) {
        return searchResponseFor(url, pages);
      }
      const body = JSON.parse(options.body);
      return response({
        results: pages.filter((page) => body.urls.includes(page.url)),
        errors: [],
      });
    },
    logger: createLogger(),
  });

  assert.equal(result.advisories.length, 2);
  assert.deepEqual(
    result.advisories.map((item) => item.product).sort(),
    ["Node.js", "Python"]
  );
  assert.ok(result.advisories.every((item) =>
    item.sourceUrl.startsWith("https://")
  ));
  assert.equal(result.product_research.length, 2);
  assert.equal(
    requests.filter(({ url }) => url.startsWith("https://api.search.tinyfish.ai")).length,
    4
  );
});

test("returns review notes rather than findings for unknown products without reliable sources", async () => {
  const result = await researchWithTinyFishFast(
    [makeAsset("UnknownWidget", "1.2.3", { vendor: "UnknownVendor" })],
    {
      apiKey: API_KEY,
      fetchImpl: async (url) => {
        if (String(url).startsWith("https://api.search.tinyfish.ai")) {
          return response({
            results: [{
              url: "https://random-blog.example/security/CVE-2026-12345",
              title: "UnknownWidget security issue",
            }],
          });
        }
        throw new Error("Untrusted source should not be fetched.");
      },
      logger: createLogger(),
    }
  );

  assert.deepEqual(result.advisories, []);
  assert.match(result.research_notes.join(" "), /no authoritative security source could be verified/i);
  assert.match(result.research_notes.join(" "), /does not establish that the software is secure/i);
});

for (const vendor of ["", "PHP Group"]) {
  test(`discovers PHP official security sources when vendor is ${vendor || "empty"}`, async () => {
    const asset = makeAsset("PHP", "8.3.35", {
      vendor,
      operatingSystem: "Linux",
      buildType: "Standard PHP build",
    });
    const plan = buildProductSearchPlan({
      product: asset.product,
      vendor: asset.vendor,
      assets: [asset],
    });
    const requests = [];
    const result = await researchWithTinyFishFast([asset], {
      apiKey: API_KEY,
      fetchImpl: async (url, options) => {
        requests.push({ url: String(url), options });
        if (String(url).startsWith("https://api.search.tinyfish.ai")) {
          return response({ results: [] });
        }
        const [sourceUrl] = JSON.parse(options.body).urls;
        if (sourceUrl !== "https://www.php.net/security") {
          return response({ results: [], errors: [] });
        }
        return response({
          results: [{
            url: sourceUrl,
            title: "PHP security advisory fixture",
            text: `# PHP security advisory fixture

CVE ID: CVE-2026-12345

Severity: High

## Affected versions

PHP 8.3 before 8.3.36

## Patched versions

8.3.36

## Remediation

Upgrade to PHP 8.3.36.
`,
          }],
          errors: [],
        });
      },
      logger: createLogger(),
    });
    const queryText = plan.queries.map((query) => query.query).join(" ");
    const fetches = requests.filter(({ url }) =>
      url === "https://api.fetch.tinyfish.ai"
    );
    const fetchedUrls = fetches.flatMap(({ options }) =>
      JSON.parse(options.body).urls
    );

    assert.match(queryText, /Product: PHP/);
    assert.match(queryText, /8\.3\.35/);
    assert.match(queryText, /OS: Linux; build: Standard PHP build/);
    if (vendor) {
      assert.match(queryText, /Vendor context: PHP Group/);
      assert.doesNotMatch(queryText, /PHP Group PHP/);
    } else {
      assert.doesNotMatch(queryText, /Vendor context:/);
    }
    assert.ok(plan.knownSources.some((source) =>
      source.url === "https://www.php.net/security/"
    ));
    assert.ok(plan.knownSources.some((source) =>
      source.url === "https://www.php.net/archive/"
    ));
    assert.ok(fetchedUrls.includes("https://www.php.net/security"));
    assert.ok(fetchedUrls.includes("https://www.php.net/archive"));
    assert.equal(result.product_research[0].vendor, vendor || "UNKNOWN");
    assert.equal(result.advisories.length, 1);
    assert.equal(result.advisories[0].cveId, "CVE-2026-12345");
    assert.equal(result.advisories[0].severity, "HIGH");
    assert.equal(result.advisories[0].fixedVersion, "8.3.36");
    assert.equal(result.advisories[0].remediation, "Upgrade to PHP 8.3.36.");
    assert.equal(result.advisories[0].sourceVerified, true);
    assert.equal(result.advisories[0].sourceUrl, "https://www.php.net/security");
    assert.match(result.advisories[0].evidenceStatus, /VERIFIED_SOURCE/);
    assert.match(result.research_notes.join(" "), /inspected 1 authoritative source page/i);
  });
}

test("normalizes product aliases without defaulting unknown names to PHP", () => {
  assert.equal(normalizeInventoryAsset({ product: "node" }).product, "Node.js");
  assert.equal(
    normalizeInventoryAsset({ softwareName: "Unlisted product" }).product,
    "Unlisted product"
  );
  assert.equal(
    normalizeInventoryAsset({ product: "Unknown product" }).product,
    "Unknown product"
  );
});

test("keeps vendor-domain candidates unverified and excludes unrelated sources", () => {
  const group = {
    product: "Acme Tool",
    vendor: "Acme",
  };
  const candidate = classifyAdvisorySource(
    "https://security.acme.example/advisories/CVE-2026-12345",
    group
  );
  assert.equal(candidate.verified, false);
  assert.equal(candidate.sourceType, "vendor-domain-candidate");
  assert.equal(
    classifyAdvisorySource(
      "https://random.example/advisories/CVE-2026-12345",
      group
    ),
    null
  );
  assert.equal(
    classifyAdvisorySource(
      "http://nodejs.org/en/blog/vulnerability/example",
      { product: "Node.js", vendor: "" }
    ),
    null
  );
});

test("discovers authoritative sources for PHP, Apache, MySQL, and OpenSSL", () => {
  const expectedSources = [
    ["PHP", "https://www.php.net/archive/2026.php"],
    ["Apache", "https://httpd.apache.org/security/vulnerabilities_24.html"],
    ["MySQL", "https://dev.mysql.com/doc/refman/8.4/en/security-vulnerabilities.html"],
    ["Node.js", "https://nodejs.org/en/blog/vulnerability/test"],
    ["Nginx", "https://nginx.org/en/security_advisories.html"],
    ["OpenSSL", "https://openssl.org/news/vulnerabilities.html"],
  ];
  for (const [product, url] of expectedSources) {
    const group = {
      product: normalizeInventoryAsset({ product }).product,
      vendor: "",
      assets: [],
    };
    const source = classifyAdvisorySource(url, group);
    assert.equal(source.verified, true, `${product} source should be trusted`);
    assert.equal(source.sourceType, "official-vendor");
  }
  for (const url of [
    "https://www.php.net/security/",
    "https://www.php.net/archive/",
  ]) {
    const source = classifyAdvisorySource(url, {
      product: "PHP",
      vendor: "PHP Group",
    });
    assert.equal(source.verified, true);
    assert.equal(source.sourceType, "official-vendor");
  }
  assert.equal(
    classifyAdvisorySource(
      "https://www.php.net.evil.example/security/",
      { product: "PHP", vendor: "PHP Group" }
    ),
    null
  );
});

test("accepts direct CVE, NVD, and OSV advisory records", () => {
  const group = { product: "Python", vendor: "" };
  const sources = [
    "https://www.cve.org/CVERecord?id=CVE-2026-12345",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
    "https://osv.dev/vulnerability/CVE-2026-12345",
  ];
  for (const url of sources) {
    assert.equal(classifyAdvisorySource(url, group).verified, true);
  }
});

test("extracts platform and configuration restrictions as source evidence", () => {
  const group = {
    product: "OpenSSL",
    vendor: "",
  };
  const page = {
    url: "https://github.com/openssl/openssl/security/advisories/GHSA-test-openssl",
    title: "OpenSSL Windows build advisory",
    text: `# OpenSSL Windows build advisory

The issue affects OpenSSL Windows builds when legacy compression is enabled.

CVE ID: CVE-2026-12001

## Affected versions

< 3.4.2

## Patched versions

3.4.2
`,
  };
  const [advisory] = normalizeAdvisoryPages(
    [page],
    group,
    classifyAdvisorySource
  );
  assert.equal(advisory.affectedOperatingSystems, "Windows");
  assert.equal(advisory.buildRestrictions, "Windows builds");
  assert.match(advisory.requiredConfigurationConditions, /legacy compression is enabled/i);
  assert.equal(advisory.sourceVerified, true);
});

test("keeps unavailable optional advisory fields explicitly unknown", () => {
  const advisory = normalizeAdvisoryRecord({
    cve_id: "CVE-2026-12002",
    source_url: "https://nodejs.org/en/blog/vulnerability/test-advisory",
    source_verified: true,
  });

  assert.equal(advisory.cveId, "CVE-2026-12002");
  assert.equal(advisory.fixedVersion, "UNKNOWN");
  assert.deepEqual(advisory.fixedVersions, []);
  assert.equal(advisory.publishedDate, "UNKNOWN");
  assert.equal(advisory.remediation, "UNKNOWN");
  assert.equal(advisory.cvssScore, null);
});

test("uses available fixed-version and publication aliases instead of UNKNOWN placeholders", () => {
  const advisory = normalizeAdvisoryRecord({
    fixedVersion: "UNKNOWN",
    fixedVersions: ["22.14.1"],
    publishedDate: "UNKNOWN",
    publication_date: "2026-04-15",
  });

  assert.equal(advisory.fixedVersion, "22.14.1");
  assert.equal(advisory.publishedDate, "2026-04-15");
});

test("preserves structured advisory fields, source URL, excerpt, and remediation", () => {
  const group = { product: "Node.js", vendor: "OpenJS Foundation" };
  const page = {
    url: "https://nodejs.org/en/blog/vulnerability/test-advisory",
    advisories: [{
      cve_id: "CVE-2026-12003",
      severity: "HIGH",
      cvss_score: 8.8,
      affected_versions: "< 22.14.1",
      fixed_versions: ["22.14.1", "23.5.0"],
      publication_date: "2026-04-15",
      remediation: "Upgrade to a fixed release.",
      operating_systems_affected: ["Windows", "Linux"],
      build_restrictions: "Standard builds",
      required_configuration_conditions: "Inspector enabled",
      source_url: "https://nodejs.org/en/blog/vulnerability/test-advisory",
      evidence_excerpt: "The issue affects releases before 22.14.1.",
    }],
  };
  const [advisory] = normalizeAdvisoryPages(
    [page],
    group,
    classifyAdvisorySource
  );

  assert.equal(advisory.cveId, "CVE-2026-12003");
  assert.equal(advisory.severity, "HIGH");
  assert.equal(advisory.cvssScore, 8.8);
  assert.equal(advisory.affectedVersions, "< 22.14.1");
  assert.equal(advisory.fixedVersion, "UNKNOWN");
  assert.deepEqual(advisory.fixedVersions, ["22.14.1", "23.5.0"]);
  assert.equal(advisory.publishedDate, "2026-04-15");
  assert.equal(advisory.remediation, "Upgrade to a fixed release.");
  assert.equal(advisory.affectedOperatingSystems, "Windows, Linux");
  assert.equal(advisory.buildRestrictions, "Standard builds");
  assert.equal(advisory.requiredConfigurationConditions, "Inspector enabled");
  assert.equal(advisory.sourceUrl, page.url);
  assert.equal(advisory.evidenceExcerpt, "The issue affects releases before 22.14.1.");
});

test("deduplicates normalized source URLs without upgrading unverified status", () => {
  const sources = deduplicateSources([
    {
      sourceName: "PHP official source",
      sourceUrl: "https://www.php.net/archive/2026.php/#advisory",
      sourceVerified: true,
    },
    {
      sourceName: "PHP official source",
      sourceUrl: "https://www.php.net/archive/2026.php",
      sourceVerified: true,
    },
    {
      sourceName: "Candidate source",
      sourceUrl: "https://www.php.net/archive/2026.php/",
      sourceVerified: false,
    },
  ]);

  assert.equal(sources.length, 1);
  assert.equal(sources[0].sourceUrl, "https://www.php.net/archive/2026.php");
  assert.equal(sources[0].sourceVerified, false);
});

test("adds distribution trackers when the inventory identifies Ubuntu", () => {
  const asset = makeAsset("OpenSSL", "3.0.2", {
    operatingSystem: "Ubuntu 22.04",
    packageManager: "apt",
  });
  const plan = buildProductSearchPlan({
    product: asset.product,
    vendor: asset.vendor,
    assets: [asset],
  });
  assert.equal(plan.queries.length, 3);
  assert.match(plan.queries[2].include_domains, /ubuntu\.com/);
});

test("reports TinyFish request timeouts without exposing credentials", async () => {
  const logger = createLogger();
  await assert.rejects(
    researchWithTinyFishFast([makeAsset("Python", "3.13.2")], {
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

test("keeps verified findings when one discovered source fetch fails", async () => {
  const secondPageUrl =
    "https://github.com/nodejs/node/security/advisories/GHSA-test-secondary";
  const result = await researchWithTinyFishFast(
    [makeAsset("Node.js", "22.14.0")],
    {
      apiKey: API_KEY,
      fetchImpl: async (url, options) => {
        if (String(url).startsWith("https://api.search.tinyfish.ai")) {
          return response({
            results: [
              { url: nodePage.url },
              { url: secondPageUrl },
            ],
          });
        }
        const [sourceUrl] = JSON.parse(options.body).urls;
        if (sourceUrl === secondPageUrl) {
          const error = new Error("Fetch timed out");
          error.name = "TimeoutError";
          throw error;
        }
        return response({ results: [nodePage], errors: [] });
      },
      logger: createLogger(),
    }
  );

  assert.equal(result.advisories.length, 1);
  assert.equal(result.advisories[0].sourceVerified, true);
  assert.match(result.research_notes.join(" "), /could not retrieve/i);
});

test("returns clear HTTP errors from TinyFish services", async () => {
  let requestCount = 0;
  await assert.rejects(
    researchWithTinyFishFast([makeAsset("Python", "3.13.2")], {
      apiKey: API_KEY,
      fetchImpl: async () => {
        requestCount += 1;
        return response(
          { error: { message: "Invalid API key" } },
          401
        );
      },
      logger: createLogger(),
    }),
    (error) => {
      assert.ok(error instanceof TinyFishResearchError);
      assert.equal(error.code, "TINYFISH_HTTP_ERROR");
      assert.equal(error.httpStatus, 401);
      assert.match(error.message, /HTTP 401.*Invalid API key/);
      assert.equal(requestCount, 2);
      return true;
    }
  );
});

test("retries transient TinyFish 503 responses and completes research", async () => {
  let searchCount = 0;
  const result = await researchWithTinyFishFast(
    [makeAsset("Python", "3.13.2")],
    {
      apiKey: API_KEY,
      fetchImpl: async (url) => {
        if (String(url).startsWith("https://api.search.tinyfish.ai")) {
          searchCount += 1;
          if (searchCount === 1) {
            return response(
              { error: { message: "Authentication service temporarily unavailable." } },
              503
            );
          }
          return response({ results: [] });
        }
        return response({ results: [], errors: [] });
      },
      logger: createLogger(),
    }
  );

  assert.equal(searchCount, 3);
  assert.deepEqual(result.advisories, []);
  assert.ok(result.research_notes.length > 0);
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
      return response({ results: [nodePage], errors: [] });
    },
    logger: createLogger(),
  };
  const assets = [makeAsset("Node.js", "22.14.0")];
  const first = researchWithTinyFishFast(assets, options);
  const second = researchWithTinyFishFast(assets, options);
  assert.equal(first, second);

  releaseSearch(response({ results: [{ url: nodePage.url }] }));
  await Promise.all([first, second]);
  assert.equal(searchCalls, 2);
});
