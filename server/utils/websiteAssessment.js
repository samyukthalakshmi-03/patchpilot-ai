import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";

const REQUEST_TIMEOUT_MS = 8000;
const DNS_TIMEOUT_MS = 4000;
const ASSESSMENT_DEADLINE_MS = 30000;
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_REDIRECTS = 5;

const SECURITY_HEADERS = [
  ["strict-transport-security", "Strict-Transport-Security"],
  ["content-security-policy", "Content-Security-Policy"],
  ["x-content-type-options", "X-Content-Type-Options"],
  ["x-frame-options", "X-Frame-Options"],
  ["referrer-policy", "Referrer-Policy"],
  ["permissions-policy", "Permissions-Policy"],
];

export class WebsiteAssessmentError extends Error {
  constructor(message, code = "WEBSITE_ASSESSMENT_ERROR") {
    super(message);
    this.name = "WebsiteAssessmentError";
    this.code = code;
  }
}

export function validateWebsiteUrl(value) {
  let url;
  try {
    url = new URL(String(value || ""));
  } catch {
    throw new WebsiteAssessmentError(
      "Enter a valid website URL.",
      "INVALID_WEBSITE_URL"
    );
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new WebsiteAssessmentError(
      "Website URLs must use HTTP or HTTPS.",
      "INVALID_WEBSITE_PROTOCOL"
    );
  }
  if (url.username || url.password) {
    throw new WebsiteAssessmentError(
      "Website URLs cannot include embedded credentials.",
      "INVALID_WEBSITE_URL"
    );
  }
  if (!url.hostname || url.hostname.length > 253 ||
    /[\s\u0000-\u001f]/.test(url.hostname)) {
    throw new WebsiteAssessmentError(
      "Enter a valid website hostname.",
      "INVALID_WEBSITE_URL"
    );
  }
  url.hash = "";
  return url;
}

function isPublicIpv4(address) {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => part < 0 || part > 255)) {
    return false;
  }
  const [a, b] = octets;
  if (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19 || b === 51)) ||
    (a === 203 && b === 0 && octets[2] === 113)
  ) {
    return false;
  }
  return true;
}

export function isPublicIpAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return isPublicIpv4(address);
  if (family !== 6) return false;
  const normalized = address.toLowerCase().split("%")[0];
  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.slice(7);
    if (net.isIP(mapped) === 4) return isPublicIpv4(mapped);
    return false;
  }
  const firstGroup = Number.parseInt(normalized.split(":")[0] || "0", 16);
  if (firstGroup < 0x2000 || firstGroup > 0x3fff) return false;
  const groups = normalized.split(":").filter(Boolean);
  const secondGroup = Number.parseInt(groups[1] || "0", 16);
  if (
    firstGroup === 0x2002 ||
    firstGroup === 0x3fff ||
    (firstGroup === 0x2001 && [0, 0x10, 0x20, 0xdb8].includes(secondGroup))
  ) {
    return false;
  }
  return true;
}

async function resolvePublicAddresses(hostname, resolver = dns.lookup) {
  const resolvedHost = hostname.replace(/^\[|\]$/g, "");
  const ipFamily = net.isIP(resolvedHost);
  let addresses;
  if (ipFamily) {
    addresses = [{ address: resolvedHost, family: ipFamily }];
  } else {
    let timeout;
    try {
      addresses = await Promise.race([
        resolver(resolvedHost, { all: true, verbatim: true }),
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new WebsiteAssessmentError(
            "Website DNS resolution exceeded its timeout.",
            "DNS_RESOLUTION_TIMEOUT"
          )), DNS_TIMEOUT_MS);
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new WebsiteAssessmentError(
      "The website hostname did not resolve to a public address.",
      "DNS_RESOLUTION_FAILED"
    );
  }
  if (addresses.some(({ address }) => !isPublicIpAddress(address))) {
    throw new WebsiteAssessmentError(
      "The website resolves to a private, loopback, or reserved IP address; the request was blocked.",
      "PRIVATE_ADDRESS_BLOCKED"
    );
  }
  return addresses;
}

function requestPinnedAddress({ url, address, family, timeoutMs, maxBytes }) {
  const transport = url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    let timer;
    const request = transport.request(url, {
      method: "GET",
      headers: {
        "User-Agent": "PatchPilot-Passive-Assessment/1.0",
        Accept: "text/html,application/xhtml+xml,*/*;q=0.1",
        "Accept-Encoding": "identity",
        Connection: "close",
      },
      timeout: timeoutMs,
      // Permit a read-only handshake so the target certificate error is reportable.
      rejectUnauthorized: url.protocol !== "https:" ? undefined : false,
      lookup: (_hostname, options, callback) => {
        if (options?.all) {
          callback(null, [{ address, family }]);
        } else {
          callback(null, address, family);
        }
      },
    }, (response) => {
      let size = 0;
      const chunks = [];
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          request.destroy(new WebsiteAssessmentError(
            "The website response exceeded the passive assessment size limit.",
            "RESPONSE_TOO_LARGE"
          ));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        clearTimeout(timer);
        resolve({
          statusCode: response.statusCode || 0,
          headers: response.headers,
          body: Buffer.concat(chunks).toString("utf8"),
          peerCertificate: url.protocol === "https:"
            ? response.socket.getPeerCertificate()
            : null,
          tlsAuthorized: url.protocol === "https:"
            ? response.socket.authorized
            : null,
          tlsAuthorizationError: url.protocol === "https:"
            ? response.socket.authorizationError?.message || ""
            : "",
        });
      });
    });
    timer = setTimeout(() => {
      request.destroy(new WebsiteAssessmentError(
        "The website did not respond before the passive assessment timeout.",
        "WEBSITE_REQUEST_TIMEOUT"
      ));
    }, timeoutMs);
    request.on("timeout", () => {
      request.destroy(new WebsiteAssessmentError(
        "The website did not respond before the passive assessment timeout.",
        "WEBSITE_REQUEST_TIMEOUT"
      ));
    });
    request.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    request.end();
  });
}

async function safeRequest(initialUrl, {
  resolver,
  requestImpl,
  timeoutMs,
  maxBytes,
  maxRedirects,
}) {
  let url = new URL(initialUrl);
  const deadline = Date.now() + ASSESSMENT_DEADLINE_MS;
  const originalHostname = url.hostname.toLowerCase();
  const originalProtocol = url.protocol;
  const originalPort = url.port || (url.protocol === "https:" ? "443" : "80");
  const redirectChain = [];
  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      throw new WebsiteAssessmentError(
        "The website assessment exceeded its overall time limit.",
        "WEBSITE_ASSESSMENT_TIMEOUT"
      );
    }
    const addresses = await resolvePublicAddresses(url.hostname, resolver);
    const address = addresses[0];
    const requestRemainingMs = deadline - Date.now();
    if (requestRemainingMs <= 0) {
      throw new WebsiteAssessmentError(
        "The website assessment exceeded its overall time limit.",
        "WEBSITE_ASSESSMENT_TIMEOUT"
      );
    }
    const response = await requestImpl({
      url,
      address: address.address,
      family: address.family || net.isIP(address.address),
      timeoutMs: Math.min(timeoutMs, requestRemainingMs),
      maxBytes,
    });
    const location = response.headers?.location;
    if (![301, 302, 303, 307, 308].includes(response.statusCode) ||
      !location) {
      return {
        ...response,
        finalUrl: url.href,
        redirectChain,
        initialStatusCode: redirectChain[0]?.statusCode || response.statusCode,
      };
    }
    let nextUrl;
    try {
      nextUrl = new URL(location, url);
    } catch {
      throw new WebsiteAssessmentError(
        "The website returned an invalid redirect; it was not followed.",
        "INVALID_REDIRECT"
      );
    }
    const nextPort = nextUrl.port ||
      (nextUrl.protocol === "https:" ? "443" : "80");
    const httpToHttpsPortChange = originalProtocol === "http:" &&
      url.protocol === "http:" &&
      nextUrl.protocol === "https:" &&
      ["80", ""].includes(originalPort) &&
      nextPort === "443";
    if (
      !["http:", "https:"].includes(nextUrl.protocol) ||
      nextUrl.hostname.toLowerCase() !== originalHostname ||
      (nextPort !== originalPort && !httpToHttpsPortChange) ||
      nextUrl.username ||
      nextUrl.password
    ) {
      return {
        ...response,
        finalUrl: url.href,
        redirectChain,
        initialStatusCode: redirectChain[0]?.statusCode || response.statusCode,
        blockedRedirect: nextUrl.href,
      };
    }
    redirectChain.push({
      statusCode: response.statusCode,
      url: url.href,
      location: nextUrl.href,
    });
    url = nextUrl;
  }
  throw new WebsiteAssessmentError(
    "The website exceeded the passive assessment redirect limit.",
    "REDIRECT_LIMIT_EXCEEDED"
  );
}

function headerValue(headers, name) {
  const value = headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value.join(", ") : String(value || "");
}

function analyzeContentSecurityPolicy(value) {
  const directives = new Map();
  for (const part of String(value || "").split(";")) {
    const [name, ...tokens] = part.trim().split(/\s+/);
    if (!name) continue;
    const key = name.toLowerCase();
    if (!directives.has(key)) directives.set(key, tokens.join(" "));
  }
  const importantNames = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "object-src",
    "base-uri",
    "frame-ancestors",
    "form-action",
    "upgrade-insecure-requests",
  ];
  const missingRecommendedDirectives = [
    "default-src",
    "script-src",
    "object-src",
    "base-uri",
    "frame-ancestors",
  ].filter((name) => !directives.has(name));
  const potentialWeaknesses = [];

  for (const [name, sources] of directives) {
    if (!/^(?:default-src|script-src|style-src)$/.test(name)) continue;
    const tokens = sources.toLowerCase().split(/\s+/);
    if (tokens.includes("'unsafe-inline'")) {
      potentialWeaknesses.push({
        directive: name,
        issue: "Allows inline content",
        implication: "Inline script or style content may reduce the protection CSP provides against injection, depending on the application and use of nonces or hashes.",
      });
    }
    if (tokens.includes("'unsafe-eval'")) {
      potentialWeaknesses.push({
        directive: name,
        issue: "Allows eval-like execution",
        implication: "Dynamic code evaluation may weaken CSP's defense against script injection.",
      });
    }
    if (tokens.includes("*")) {
      potentialWeaknesses.push({
        directive: name,
        issue: "Allows any source",
        implication: "A wildcard source can permit resources from origins the policy does not otherwise constrain.",
      });
    }
  }

  return {
    present: Boolean(value),
    directives: importantNames
      .filter((name) => directives.has(name))
      .map((name) => ({ name, value: directives.get(name) })),
    potentialWeaknesses,
    missingRecommendedDirectives,
    explanation: "CSP observations describe policy text only; they do not prove exploitability or account for application-specific nonces, hashes, or browser behavior.",
  };
}

function inspectSecurityHeaders(headers, secureTransport) {
  return SECURITY_HEADERS.map(([key, name]) => {
    const value = headerValue(headers, key);
    const cspAnalysis = key === "content-security-policy"
      ? analyzeContentSecurityPolicy(value)
      : null;
    const hasAlternativeFramePolicy = key === "x-frame-options" &&
      /(?:^|;)\s*frame-ancestors\b/i.test(
        headerValue(headers, "content-security-policy")
      );
    const present = Boolean(value) || hasAlternativeFramePolicy;
    let weakness = "";
    if (key === "strict-transport-security" && present &&
      !/\bmax-age=(?:[1-9]\d*)/i.test(value)) {
      weakness = "The HSTS max-age directive is missing or zero.";
    } else if (key === "content-security-policy" &&
      cspAnalysis.potentialWeaknesses.length) {
      weakness = "The policy contains directives that may weaken CSP protections; review the policy in application context.";
    } else if (key === "x-content-type-options" && present &&
      !/^\s*nosniff\s*$/i.test(value)) {
      weakness = "The value is not nosniff.";
    } else if (key === "x-frame-options" && value &&
      !/^\s*(?:deny|sameorigin)\s*$/i.test(value) &&
      !hasAlternativeFramePolicy) {
      weakness = "The value is not a recognized protective directive.";
    } else if (key === "referrer-policy" && present &&
      !/\b(?:no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin|origin|origin-when-cross-origin|no-referrer-when-downgrade)\b/i
        .test(value)) {
      weakness = "The value could not be matched to a recognized policy.";
    } else if (key === "permissions-policy" && /\*/.test(value)) {
      weakness = "The policy grants a feature to all origins.";
    }
    const status = present && !weakness
      ? "NO_ISSUES_OBSERVED"
      : "POTENTIAL_RISK";
    return {
      name,
      present,
      value: value || (hasAlternativeFramePolicy
        ? "Covered by Content-Security-Policy frame-ancestors"
        : ""),
      status,
      observation: weakness || (present
        ? `${name} is present.`
        : `${name} was not observed in the response.`),
      recommendation: present && !weakness
        ? ""
        : key === "strict-transport-security"
          ? "After confirming HTTPS is correctly deployed, configure an appropriate HSTS policy."
          : key === "content-security-policy"
            ? "Define a Content-Security-Policy appropriate for the application's resources."
            : key === "x-frame-options"
              ? "Set X-Frame-Options or a Content-Security-Policy frame-ancestors directive."
              : `Review whether ${name} should be configured for this application.`,
      ...(key === "strict-transport-security" && !secureTransport
        ? { status: "NEEDS_REVIEW", observation: "HSTS cannot be assessed on an unencrypted response." }
        : {}),
      ...(cspAnalysis ? { analysis: cspAnalysis } : {}),
    };
  });
}

function inspectCookies(headers) {
  const rawCookies = headers?.["set-cookie"];
  const cookies = Array.isArray(rawCookies)
    ? rawCookies
    : rawCookies
      ? [rawCookies]
      : [];
  return cookies.map((cookie, index) => {
    const attributes = cookie.split(";").slice(1).map((part) => part.trim());
    const hasAttribute = (name) => attributes.some((attribute) =>
      new RegExp(`^${name}(?:=|$)`, "i").test(attribute)
    );
    const secure = hasAttribute("Secure");
    const httpOnly = hasAttribute("HttpOnly");
    const sameSite = attributes.find((attribute) =>
      /^SameSite=/i.test(attribute)
    )?.split("=")[1] || "";
    return {
      cookie: `Cookie ${index + 1}`,
      secure,
      httpOnly,
      sameSite: sameSite || "Not set",
      ...(!secure || !httpOnly || !sameSite
        ? {
          recommendation:
            "Set Secure, HttpOnly where JavaScript access is not required, and an intentional SameSite policy.",
        }
        : {}),
      status: secure && httpOnly && sameSite
        ? "NO_ISSUES_OBSERVED"
        : "POTENTIAL_RISK",
      observations: [
        ...(!secure ? ["Secure is not set"] : []),
        ...(!httpOnly ? ["HttpOnly is not set"] : []),
        ...(!sameSite ? ["SameSite is not set"] : []),
      ],
    };
  });
}

function detectTechnologies(headers, body) {
  const candidates = [
    ["Server", headerValue(headers, "server")],
    ["X-Powered-By", headerValue(headers, "x-powered-by")],
    ["X-AspNet-Version", headerValue(headers, "x-aspnet-version")],
    ["X-Generator", headerValue(headers, "x-generator")],
  ].filter(([, value]) => value);
  const generatorTags = [...String(body || "").matchAll(
    /<meta\b[^>]*>/gi
  )].flatMap(([tag]) => {
    const name = tag.match(/\bname=["']([^"']+)["']/i)?.[1];
    const content = tag.match(/\bcontent=["']([^"']+)["']/i)?.[1];
    return name?.toLowerCase() === "generator" && content
      ? [["HTML meta generator", content]]
      : [];
  });
  const products = [
    { pattern: /\bPHP(?:\/v?(\d+\.\d+(?:\.\d+)?))?/i, product: "PHP" },
    { pattern: /\bNode\.?js(?:\/v?(\d+\.\d+(?:\.\d+)?))?/i, product: "Node.js" },
    { pattern: /\bPython(?:\/v?(\d+\.\d+(?:\.\d+)?))?/i, product: "Python" },
    { pattern: /\bApache(?:(?:\/v?(\d+\.\d+(?:\.\d+)?))|(?:\s+httpd(?:\/v?(\d+\.\d+(?:\.\d+)?))?))?(?!\s+[A-Za-z])/i, product: "Apache HTTP Server" },
    { pattern: /\bnginx(?:\/v?(\d+\.\d+(?:\.\d+)?))?/i, product: "nginx" },
    { pattern: /\bOpenSSL(?:\/v?(\d+\.\d+(?:\.\d+)?))?/i, product: "OpenSSL" },
    { pattern: /\bExpress(?:\.js)?(?:\/v?(\d+\.\d+(?:\.\d+)?))?/i, product: "Express" },
    { pattern: /\bWordPress(?:\s+(\d+\.\d+(?:\.\d+)?))?/i, product: "WordPress" },
  ];
  const technologies = [];
  for (const [source, value] of [...candidates, ...generatorTags]) {
    for (const { pattern, product } of products) {
      const match = value.match(pattern);
      if (!match) continue;
      const version = match.slice(1).find(Boolean) || "";
      technologies.push({
        product,
        version,
        confidence: version ? "HIGH" : "MEDIUM",
        versionEstablished: Boolean(version),
        cveCorrelationPossible: Boolean(version),
        correlationReason: version
          ? ""
          : "No technology version was established from the observed response, so CVE correlation was not possible.",
        evidence: `${source}: ${value.slice(0, 240)}`,
      });
    }
  }
  return technologies.filter((item, index, all) =>
    all.findIndex((other) =>
      other.product === item.product &&
      other.version === item.version
    ) === index
  );
}

function identifyHostingInfrastructure(hostname, headers) {
  const host = hostname.toLowerCase();
  const indicators = [
    [".vercel.app", "Vercel", "platform hostname"],
    [".netlify.app", "Netlify", "platform hostname"],
    [".pages.dev", "Cloudflare Pages", "platform hostname"],
    [".cloudfront.net", "Amazon CloudFront", "edge hostname"],
  ];
  const hostnameMatch = indicators.find(([suffix]) => host.endsWith(suffix));
  if (hostnameMatch) {
    return {
      provider: hostnameMatch[1],
      kind: hostnameMatch[2],
      evidence: `Hostname suffix ${hostnameMatch[0]} is publicly observable.`,
    };
  }

  const server = headerValue(headers, "server");
  if (/cloudflare/i.test(server) || headerValue(headers, "cf-ray")) {
    return {
      provider: "Cloudflare",
      kind: "edge network indicator",
      evidence: "Cloudflare Server or CF-Ray response header observed.",
    };
  }
  if (headerValue(headers, "x-amz-cf-id") ||
    headerValue(headers, "x-amz-cf-pop")) {
    return {
      provider: "Amazon CloudFront",
      kind: "edge network indicator",
      evidence: "CloudFront response header observed.",
    };
  }
  if (headerValue(headers, "x-vercel-id")) {
    return {
      provider: "Vercel",
      kind: "platform response indicator",
      evidence: "X-Vercel-Id response header observed.",
    };
  }
  if (headerValue(headers, "x-nf-request-id")) {
    return {
      provider: "Netlify",
      kind: "platform response indicator",
      evidence: "X-NF-Request-Id response header observed.",
    };
  }
  if (/\bfastly\b/i.test(
    `${headerValue(headers, "x-served-by")} ${headerValue(headers, "via")}`
  )) {
    return {
      provider: "Fastly",
      kind: "edge network indicator",
      evidence: "Fastly response header observed.",
    };
  }
  return null;
}

function certificateObservation(certificate, now, tlsAuthorized, authorizationError) {
  if (!certificate || !certificate.valid_to) {
    return {
      status: "NEEDS_REVIEW",
      valid: null,
      expiresAt: null,
      observation: "Certificate validity details were not available.",
    };
  }
  const expiry = new Date(certificate.valid_to);
  const dateValid = !Number.isNaN(expiry.getTime()) && expiry > now &&
    certificate.valid_from && new Date(certificate.valid_from) <= now;
  const valid = dateValid && tlsAuthorized === true;
  return {
    status: valid ? "NO_ISSUES_OBSERVED" : "CONFIRMED_MISCONFIGURATION",
    valid,
    expiresAt: Number.isNaN(expiry.getTime()) ? null : expiry.toISOString(),
    observation: valid
      ? `TLS certificate is valid and expires at ${expiry.toISOString()}.`
      : `TLS certificate validation failed${authorizationError
        ? `: ${authorizationError}`
        : "; it may be expired, not yet valid, or have invalid validity dates"}.`,
  };
}

export async function assessWebsite(asset, {
  resolver = dns.lookup,
  requestImpl = requestPinnedAddress,
  timeoutMs = REQUEST_TIMEOUT_MS,
  maxBytes = MAX_RESPONSE_BYTES,
  maxRedirects = MAX_REDIRECTS,
  now = new Date(),
} = {}) {
  if (asset.authorizationConfirmed !== true) {
    throw new WebsiteAssessmentError(
      "Confirm that you are authorized to assess this website.",
      "AUTHORIZATION_REQUIRED"
    );
  }
  const url = validateWebsiteUrl(asset.url);
  const assessmentTimestamp = now.toISOString();
  const initial = await safeRequest(url, {
    resolver,
    requestImpl,
    timeoutMs,
    maxBytes,
    maxRedirects,
  });
  const secureTransport = new URL(initial.finalUrl).protocol === "https:";
  const tls = secureTransport
    ? certificateObservation(
      initial.peerCertificate,
      now,
      initial.tlsAuthorized,
      initial.tlsAuthorizationError
    )
    : {
      status: "NEEDS_REVIEW",
      valid: null,
      expiresAt: null,
      observation: "The submitted URL uses HTTP; no TLS certificate was observed.",
    };
  const isHttpRedirect = initial.redirectChain.some((redirect) =>
    new URL(redirect.location).protocol === "https:"
  );
  const redirect = initial.blockedRedirect
    ? {
      status: "NEEDS_REVIEW",
      followed: false,
      observation: "A redirect to a different host or port was not followed.",
      target: initial.blockedRedirect,
      recommendation: "Review the redirect destination and assess it separately only if it is in scope and authorized.",
    }
    : {
      status: url.protocol === "https:" || isHttpRedirect
        ? "NO_ISSUES_OBSERVED"
        : "CONFIRMED_MISCONFIGURATION",
      followed: initial.finalUrl !== url.href,
      observation: url.protocol === "https"
        ? "The submitted URL uses HTTPS."
        : isHttpRedirect
          ? "HTTP redirected to HTTPS on the same host."
          : "HTTP did not redirect to HTTPS on the same host.",
      recommendation: secureTransport
        ? ""
        : "Serve the website over HTTPS and redirect HTTP requests to HTTPS.",
    };
  const headers = inspectSecurityHeaders(initial.headers, secureTransport);
  const cookies = inspectCookies(initial.headers);
  const technologies = detectTechnologies(initial.headers, initial.body);
  const finalUrl = new URL(initial.finalUrl);
  const redirectTarget = initial.blockedRedirect
    ? new URL(initial.blockedRedirect)
    : null;
  const versionedTechnologies = technologies.filter((technology) =>
    technology.version && technology.confidence === "HIGH"
  );
  const hostingInfrastructure = identifyHostingInfrastructure(
    finalUrl.hostname,
    initial.headers
  );
  const observations = [
    {
      category: "HTTPS/TLS",
      status: secureTransport ? tls.status : "CONFIRMED_MISCONFIGURATION",
      details: [
        secureTransport
          ? "HTTPS was successfully reached."
          : "The response was served over unencrypted HTTP.",
        tls.observation,
        redirect.observation,
        ...(redirect.recommendation ? [redirect.recommendation] : []),
      ],
    },
    ...headers.map((header) => ({
      category: "HTTP security headers",
      status: header.status,
      details: [
        header.observation,
        ...(header.name === "Content-Security-Policy"
          ? []
          : header.value ? [header.value] : []),
        ...(header.recommendation ? [header.recommendation] : []),
      ],
    })),
    ...cookies.map((cookie) => ({
      category: "Cookie security",
      status: cookie.status,
      details: cookie.observations.length
        ? cookie.observations
        : ["Secure, HttpOnly, and SameSite attributes were observed."],
      ...(cookie.recommendation ? { recommendation: cookie.recommendation } : {}),
    })),
  ];
  const issueStatuses = observations.map((item) => item.status);
  const status = issueStatuses.includes("CONFIRMED_MISCONFIGURATION")
    ? "CONFIRMED_MISCONFIGURATION"
    : issueStatuses.includes("POTENTIAL_RISK")
      ? "POTENTIAL_RISK"
      : issueStatuses.includes("NEEDS_REVIEW")
        ? "NEEDS_REVIEW"
        : "NO_ISSUES_OBSERVED";
  return {
    asset: {
      name: asset.name,
      assetType: "website",
      url: url.href,
      environment: asset.environment,
      technologyInfo: asset.technologyInfo || "",
    },
    scope: {
      submittedHostname: url.hostname,
      finalHostname: finalUrl.hostname,
      redirectTargetHostname: redirectTarget?.hostname || "",
      hostingInfrastructure,
      applicationOwnership:
        "Not established: this assessment inspected public HTTP responses only; it did not inspect application source code, backend systems, or ownership.",
    },
    status,
    assessmentTimestamp,
    http: {
      statusCode: initial.statusCode,
      finalUrl: initial.finalUrl,
      secureTransport,
      redirect,
      tls,
    },
    securityHeaders: headers,
    cookies,
    technologies,
    technologyCorrelation: {
      status: versionedTechnologies.length ? "PENDING" : "NOT_POSSIBLE",
      reason: versionedTechnologies.length
        ? "A high-confidence technology version was observed; public advisory correlation may be attempted."
        : "No technology version was established from strong public-response evidence, so CVE correlation was not possible.",
    },
    knownVulnerabilities: [],
    observations,
    researchNotes: [
      "NO_ISSUES_OBSERVED reflects only these passive observations and does not establish that the website is secure.",
    ],
    evidence: [{
      sourceUrl: initial.finalUrl,
      sourceName: "Submitted website response",
      sourceVerified: true,
      excerpt: [
        `HTTP ${initial.statusCode}`,
        headerValue(initial.headers, "server")
          ? `Server: ${headerValue(initial.headers, "server")}`
          : "",
      ].filter(Boolean).join(" · "),
    }],
  };
}
