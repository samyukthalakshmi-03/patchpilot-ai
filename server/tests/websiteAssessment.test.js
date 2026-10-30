import test from "node:test";
import assert from "node:assert/strict";

import {
  assessWebsite,
  isPublicIpAddress,
  validateWebsiteUrl,
  WebsiteAssessmentError,
} from "../utils/websiteAssessment.js";
import { normalizeScanInventory } from "../utils/scanInventory.js";

const now = new Date("2026-10-30T00:00:00.000Z");
const certificate = {
  valid_from: "Oct 1 00:00:00 2026 GMT",
  valid_to: "Oct 1 00:00:00 2027 GMT",
};

const completeHeaders = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=()",
};

function fixtureRequest(responses) {
  const requests = [];
  return {
    requests,
    requestImpl: async (request) => {
      requests.push(request);
      const response = responses.shift();
      if (response instanceof Error) throw response;
      return {
        headers: {},
        body: "",
        tlsAuthorized: request.url.protocol === "https:",
        tlsAuthorizationError: "",
        peerCertificate: request.url.protocol === "https:" ? certificate : null,
        ...response,
      };
    },
  };
}

function asset(overrides = {}) {
  return {
    name: "Fixture website",
    assetType: "website",
    url: "https://fixture.test/",
    environment: "Staging",
    authorizationConfirmed: true,
    ...overrides,
  };
}

const publicResolver = async () => [
  { address: "93.184.216.34", family: 4 },
];

test("accepts HTTP and HTTPS URLs but rejects invalid protocols and credentials", () => {
  assert.equal(validateWebsiteUrl("https://example.test/path").protocol, "https:");
  assert.equal(validateWebsiteUrl("http://example.test").protocol, "http:");
  assert.throws(() => validateWebsiteUrl("file:///C:/Windows"), {
    code: "INVALID_WEBSITE_PROTOCOL",
  });
  assert.throws(() => validateWebsiteUrl("https://user:pass@example.test"), {
    code: "INVALID_WEBSITE_URL",
  });
  assert.throws(() => validateWebsiteUrl("not a URL"), {
    code: "INVALID_WEBSITE_URL",
  });
  const credentialedUrl = "https://" + ["user", "pass"].join(":") +
    "@example.test";
  assert.throws(() => validateWebsiteUrl(credentialedUrl), {
    code: "INVALID_WEBSITE_URL",
  });
});

test("blocks private, loopback, link-local, and reserved IP addresses", () => {
  for (const address of [
    "127.0.0.1",
    "10.1.2.3",
    "172.20.1.2",
    "192.168.1.1",
    "169.254.10.20",
    "100.64.1.2",
    "::1",
    "fc00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
  ]) {
    assert.equal(isPublicIpAddress(address), false, `${address} must be blocked`);
  }
  assert.equal(isPublicIpAddress("93.184.216.34"), true);
  assert.equal(isPublicIpAddress("2606:4700:4700::1111"), true);
});

test("rejects resolution to a private address before making a request", async () => {
  let requested = false;
  await assert.rejects(
    assessWebsite(asset(), {
      resolver: async () => [{ address: "127.0.0.1", family: 4 }],
      requestImpl: async () => {
        requested = true;
      },
      now,
    }),
    (error) => error.code === "PRIVATE_ADDRESS_BLOCKED"
  );
  assert.equal(requested, false);
});

test("reports HTTPS availability and valid certificate evidence", async () => {
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: {
      ...completeHeaders,
      server: "nginx/1.26.2",
    },
    body: "<html><body>Fixture</body></html>",
  }]);
  const result = await assessWebsite(asset(), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.equal(result.status, "NO_ISSUES_OBSERVED");
  assert.equal(result.http.tls.valid, true);
  assert.equal(result.http.tls.expiresAt, "2027-10-01T00:00:00.000Z");
  assert.ok(result.researchNotes.some((note) =>
    /does not establish that the website is secure/i.test(note)
  ));
  assert.equal(result.securityHeaders.length, 6);
  assert.deepEqual(result.technologies[0], {
    product: "nginx",
    version: "1.26.2",
    confidence: "HIGH",
    versionEstablished: true,
    cveCorrelationPossible: true,
    correlationReason: "",
    evidence: "Server: nginx/1.26.2",
  });
  assert.equal(fixture.requests[0].url.hostname, "fixture.test");
  assert.equal(fixture.requests[0].address, "93.184.216.34");
  assert.equal(fixture.requests[0].timeoutMs, 8000);
  assert.equal(fixture.requests[0].maxBytes, 512 * 1024);
});

test("reports missing security headers as potential risks", async () => {
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: {},
    body: "",
  }]);
  const result = await assessWebsite(asset(), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.equal(result.status, "POTENTIAL_RISK");
  assert.ok(result.securityHeaders.every((header) => !header.present));
});

test("summarizes long CSP values while retaining the complete raw policy", async () => {
  const rawPolicy = [
    "default-src 'self'",
    "script-src 'self' https://scripts.example.test 'unsafe-inline'",
    "style-src 'self'",
    `img-src 'self' ${"https://images.example.test ".repeat(30)}`,
    "frame-ancestors 'none'",
  ].join("; ");
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: { "content-security-policy": rawPolicy },
    body: "",
  }]);
  const result = await assessWebsite(asset(), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });
  const csp = result.securityHeaders.find((header) =>
    header.name === "Content-Security-Policy"
  );

  assert.equal(csp.value, rawPolicy);
  assert.equal(csp.analysis.present, true);
  assert.ok(csp.analysis.directives.some((directive) =>
    directive.name === "script-src"
  ));
  assert.ok(csp.analysis.potentialWeaknesses.some((weakness) =>
    weakness.directive === "script-src" &&
    /inline content/i.test(weakness.issue)
  ));
  assert.equal(csp.status, "POTENTIAL_RISK");
  assert.notEqual(csp.status, "CONFIRMED_MISCONFIGURATION");
  assert.ok(csp.analysis.missingRecommendedDirectives.includes("object-src"));
  assert.ok(!csp.observation.includes(rawPolicy));
});

test("reports an unsafe-inline CSP directive only as a potential concern", async () => {
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: {
      "content-security-policy":
        "default-src 'self'; script-src 'self' 'unsafe-inline'",
    },
    body: "",
  }]);
  const result = await assessWebsite(asset(), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });
  const csp = result.securityHeaders.find((header) =>
    header.name === "Content-Security-Policy"
  );

  assert.equal(csp.status, "POTENTIAL_RISK");
  assert.match(csp.analysis.potentialWeaknesses[0].implication, /depending on the application/i);
  assert.notEqual(result.status, "CONFIRMED_MISCONFIGURATION");
});

test("identifies third-party platform indicators without attributing application ownership", async () => {
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: { "x-vercel-id": "sfo1::abc" },
    body: "",
  }]);
  const result = await assessWebsite(asset({
    url: "https://demo.vercel.app/",
  }), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.equal(result.scope.submittedHostname, "demo.vercel.app");
  assert.equal(result.scope.finalHostname, "demo.vercel.app");
  assert.equal(result.scope.hostingInfrastructure.provider, "Vercel");
  assert.match(result.scope.applicationOwnership, /did not inspect application source code/i);
});

test("reports insecure HTTP without a same-host HTTPS redirect", async () => {
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: {},
    body: "",
  }]);
  const result = await assessWebsite(asset({
    url: "http://fixture.test/",
  }), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.equal(result.status, "CONFIRMED_MISCONFIGURATION");
  assert.equal(result.http.secureTransport, false);
  assert.match(result.http.redirect.observation, /did not redirect to HTTPS/i);
});

test("records an explicitly identified technology without inventing its version", async () => {
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: { server: "nginx" },
    body: "",
  }]);
  const result = await assessWebsite(asset(), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.equal(result.technologies.length, 1);
  assert.equal(result.technologies[0].product, "nginx");
  assert.equal(result.technologies[0].version, "");
  assert.equal(result.technologies[0].confidence, "MEDIUM");
  assert.equal(result.technologies[0].versionEstablished, false);
  assert.equal(result.technologies[0].cveCorrelationPossible, false);
  assert.match(result.technologies[0].correlationReason, /CVE correlation was not possible/i);
  assert.equal(result.technologyCorrelation.status, "NOT_POSSIBLE");
  assert.match(result.technologyCorrelation.reason, /CVE correlation was not possible/i);
});

test("does not mistake unrelated Apache products for Apache HTTP Server", async () => {
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: { server: "Apache Tomcat" },
    body: "",
  }]);
  const result = await assessWebsite(asset(), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.deepEqual(result.technologies, []);
});

test("reports Secure, HttpOnly, and SameSite cookie flags", async () => {
  const fixture = fixtureRequest([{
    statusCode: 200,
    headers: {
      ...completeHeaders,
      "set-cookie": [
        "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        "preference=dark; Path=/",
      ],
    },
    body: "",
  }]);
  const result = await assessWebsite(asset(), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.deepEqual(result.cookies[0], {
    cookie: "Cookie 1",
    secure: true,
    httpOnly: true,
    sameSite: "Lax",
    status: "NO_ISSUES_OBSERVED",
    observations: [],
  });
  assert.deepEqual(result.cookies[1].observations, [
    "Secure is not set",
    "HttpOnly is not set",
    "SameSite is not set",
  ]);
  assert.equal(result.status, "POTENTIAL_RISK");
});

test("follows same-host HTTP to HTTPS redirects and records the redirect", async () => {
  const fixture = fixtureRequest([
    {
      statusCode: 301,
      headers: { location: "https://fixture.test/secure" },
      body: "",
      tlsAuthorized: null,
      peerCertificate: null,
    },
    {
      statusCode: 200,
      headers: completeHeaders,
      body: "",
    },
  ]);
  const result = await assessWebsite(asset({
    url: "http://fixture.test/",
  }), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.equal(fixture.requests.length, 2);
  assert.equal(result.http.redirect.followed, true);
  assert.match(result.http.redirect.observation, /redirected to HTTPS/i);
  assert.equal(result.http.tls.valid, true);
});

test("does not follow a redirect to an unrelated host", async () => {
  const fixture = fixtureRequest([{
    statusCode: 302,
    headers: { location: "https://other.test/" },
    body: "",
    tlsAuthorized: null,
    peerCertificate: null,
  }]);
  const result = await assessWebsite(asset({
    url: "http://fixture.test/",
  }), {
    resolver: publicResolver,
    requestImpl: fixture.requestImpl,
    now,
  });

  assert.equal(fixture.requests.length, 1);
  assert.equal(result.http.redirect.followed, false);
  assert.equal(result.http.redirect.target, "https://other.test/");
  assert.equal(result.scope.submittedHostname, "fixture.test");
  assert.equal(result.scope.finalHostname, "fixture.test");
  assert.equal(result.scope.redirectTargetHostname, "other.test");
});

test("revalidates DNS addresses before following an in-scope redirect", async () => {
  let resolutionCount = 0;
  const fixture = fixtureRequest([{
    statusCode: 301,
    headers: { location: "https://fixture.test/secure" },
    body: "",
  }]);
  await assert.rejects(
    assessWebsite(asset({ url: "http://fixture.test/" }), {
      resolver: async () => {
        resolutionCount += 1;
        return [{
          address: resolutionCount === 1
            ? "93.184.216.34"
            : "127.0.0.1",
          family: 4,
        }];
      },
      requestImpl: fixture.requestImpl,
      now,
    }),
    (error) => error.code === "PRIVATE_ADDRESS_BLOCKED"
  );
  assert.equal(fixture.requests.length, 1);
});

test("reports request timeouts as errors for the API to classify as review", async () => {
  const timeout = new WebsiteAssessmentError(
    "The website did not respond before the passive assessment timeout.",
    "WEBSITE_REQUEST_TIMEOUT"
  );
  await assert.rejects(
    assessWebsite(asset(), {
      resolver: publicResolver,
      requestImpl: async () => {
        throw timeout;
      },
      now,
    }),
    (error) => error.code === "WEBSITE_REQUEST_TIMEOUT"
  );
});

test("normalizes mixed software and authorized website inventories separately", () => {
  const { softwareAssets, websiteAssets } = normalizeScanInventory([
    {
      assetType: "software",
      name: "App server",
      product: "PHP",
      version: "8.3.35",
    },
    {
      assetType: "website",
      name: "Public site",
      url: "https://example.test",
      environment: "Production",
      authorizationConfirmed: true,
    },
  ]);

  assert.equal(softwareAssets.length, 1);
  assert.equal(softwareAssets[0].softwareName, "PHP");
  assert.equal(softwareAssets[0].version, "8.3.35");
  assert.equal(websiteAssets.length, 1);
  assert.equal(websiteAssets[0].url, "https://example.test/");
  assert.equal(websiteAssets[0].assetType, "website");
  assert.throws(() => normalizeScanInventory([{
    assetType: "website",
    name: "Unauthorized",
    url: "https://example.test",
  }]), /Confirm that you are authorized/i);
});
