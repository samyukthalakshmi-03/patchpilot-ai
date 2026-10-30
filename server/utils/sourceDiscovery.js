import {
  canonicalizeProduct,
  normalizeVendorName,
} from "./productDiscovery.js";

const PRODUCT_SOURCE_REGISTRY = new Map([
  ["apache http server", { domains: ["httpd.apache.org"] }],
  ["mysql", { domains: ["dev.mysql.com"] }],
  ["node.js", { domains: ["nodejs.org"] }],
  ["nginx", { domains: ["nginx.org"] }],
  ["openssl", { domains: ["openssl.org"] }],
  ["python", { domains: ["python.org"] }],
  ["php", {
    domains: ["php.net"],
    sources: [
      {
        url: "https://www.php.net/security/",
        sourceName: "PHP Security",
      },
      {
        url: "https://www.php.net/archive/",
        sourceName: "PHP Releases Archive",
      },
    ],
  }],
]);

const PUBLIC_ADVISORY_HOSTS = new Map([
  ["cve.org", "CVE.org"],
  ["www.cve.org", "CVE.org"],
  ["nvd.nist.gov", "NVD"],
  ["osv.dev", "OSV.dev"],
  ["github.com", "GitHub Security Advisories"],
]);

const DISTRIBUTION_HOSTS = new Map([
  ["security.debian.org", "Debian Security Tracker"],
  ["security-tracker.debian.org", "Debian Security Tracker"],
  ["ubuntu.com", "Ubuntu Security"],
  ["security.ubuntu.com", "Ubuntu Security"],
  ["access.redhat.com", "Red Hat Security"],
  ["security.almalinux.org", "AlmaLinux Security"],
  ["security.rockylinux.org", "Rocky Linux Security"],
  ["security.archlinux.org", "Arch Linux Security"],
  ["security.alpinelinux.org", "Alpine Security"],
]);

function normalizeHost(host) {
  return String(host || "").toLowerCase().replace(/^www\./, "");
}

export function normalizeSourceUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password) return "";
    url.hash = "";
    if (url.pathname.length > 1) {
      url.pathname = url.pathname.replace(/\/+$/, "");
    }
    return url.href;
  } catch {
    return "";
  }
}

export function deduplicateSources(sources, { includeProduct = false } = {}) {
  const unique = new Map();
  for (const source of sources) {
    const sourceUrl = normalizeSourceUrl(source?.sourceUrl || source?.url);
    if (!sourceUrl) continue;
    const identity = includeProduct
      ? `${source.product || ""}\u0000${source.vendor || ""}\u0000${sourceUrl}`
      : sourceUrl;
    const existing = unique.get(identity);
    if (!existing) {
      unique.set(identity, { ...source, sourceUrl });
      continue;
    }
    const verification = [
      existing.sourceVerified,
      source.sourceVerified,
    ].filter((value) => typeof value === "boolean");
    unique.set(identity, {
      ...existing,
      sourceName: existing.sourceName || source.sourceName,
      sourceType: existing.sourceType || source.sourceType,
      sourceVerified: verification.length
        ? !verification.includes(false)
        : undefined,
    });
  }
  return [...unique.values()];
}

function identityTokens(group) {
  return [group.product, group.vendor]
    .join(" ")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 3);
}

function vendorHostMatches(host, group) {
  const tokens = identityTokens(group).filter((token) => token.length >= 4);
  return tokens.some((token) => host.split(".").includes(token));
}

function githubRepositoryMatches(pathname, group) {
  const match = pathname.match(
    /^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/security\/advisories\/[A-Za-z0-9-]+\/?$/i
  );
  if (!match) return false;
  const repoIdentity = `${match[1]} ${match[2]}`.toLowerCase();
  return identityTokens(group).some((token) => repoIdentity.includes(token));
}

function productDomains(product) {
  const productKey = canonicalizeProduct(product).toLowerCase();
  return PRODUCT_SOURCE_REGISTRY.get(productKey)?.domains || [];
}

function productSourceSeeds(product) {
  const productKey = canonicalizeProduct(product).toLowerCase();
  return PRODUCT_SOURCE_REGISTRY.get(productKey)?.sources || [];
}

function distributionDomains(assets) {
  const osList = assets.map((asset) =>
    String(asset.operatingSystem || "").toLowerCase()
  );
  const domains = new Set();
  if (osList.some((os) => /debian/.test(os))) {
    domains.add("security-tracker.debian.org");
  }
  if (osList.some((os) => /ubuntu/.test(os))) {
    domains.add("ubuntu.com");
    domains.add("security.ubuntu.com");
  }
  if (osList.some((os) => /red hat|rhel|fedora/.test(os))) {
    domains.add("access.redhat.com");
  }
  if (osList.some((os) => /alpine/.test(os))) {
    domains.add("security.alpinelinux.org");
  }
  if (osList.some((os) => /arch/.test(os))) {
    domains.add("security.archlinux.org");
  }
  return [...domains];
}

export function classifyAdvisorySource(value, group) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password) return null;
  const normalizedUrl = normalizeSourceUrl(url.href);
  if (!normalizedUrl) return null;
  url = new URL(normalizedUrl);

  const host = normalizeHost(url.hostname);
  const publicSource = PUBLIC_ADVISORY_HOSTS.get(host);
  if (publicSource) {
    if (
      host === "github.com" &&
      !githubRepositoryMatches(url.pathname, group)
    ) {
      return null;
    }
    if (
      host === "nvd.nist.gov" &&
      !/^\/vuln\/detail\/CVE-\d{4}-\d+\/?$/i.test(url.pathname)
    ) return null;
    if (
      host === "cve.org" &&
      (
        !/^\/CVERecord\/?$/i.test(url.pathname) ||
        !/^CVE-\d{4}-\d+$/i.test(url.searchParams.get("id") || "")
      )
    ) return null;
    if (
      host === "osv.dev" &&
      !/^\/vulnerability\/[A-Za-z0-9.-]+\/?$/i.test(url.pathname)
    ) return null;
    return {
      url: url.href,
      sourceName: publicSource,
      sourceType: "public-advisory-database",
      verified: true,
    };
  }

  const distributionName = DISTRIBUTION_HOSTS.get(host);
  if (distributionName) {
    return {
      url: url.href,
      sourceName: distributionName,
      sourceType: "distribution-security-tracker",
      verified: true,
    };
  }

  const product = canonicalizeProduct(group.product);
  const knownProductDomain = productDomains(product)
    .some((domain) => host === domain || host.endsWith(`.${domain}`));
  if (knownProductDomain) {
    return {
      url: url.href,
      sourceName: `${product} official source`,
      sourceType: "official-vendor",
      verified: true,
    };
  }

  if (vendorHostMatches(host, group)) {
    return {
      url: url.href,
      sourceName: `${group.vendor || group.product} source`,
      sourceType: "vendor-domain-candidate",
      verified: false,
    };
  }

  return null;
}

export function buildProductSearchPlan(group) {
  const product = canonicalizeProduct(group.product);
  const vendor = normalizeVendorName(group.vendor);
  const inventoryContext = group.assets.map((asset) =>
    `${asset.version} (OS: ${asset.operatingSystem || "Unknown"}; build: ${asset.buildType || "Unknown"}; package manager: ${asset.packageManager || "Unknown"}; architecture: ${asset.architecture || "Unknown"})`
  ).join(" | ");
  const vendorContext = vendor ? `Vendor context: ${vendor}.` : "";
  const productContext = `Product: ${product}. ${vendorContext}`.trim();
  const sourceDomains = productDomains(product);
  const knownSources = productSourceSeeds(product);
  const distroDomains = distributionDomains(group.assets);
  const queries = [
    {
      query: `${productContext} Find official security advisories and release notes for installed version(s): ${inventoryContext}. Extract only source-supported CVE IDs, affected version ranges, fixed versions, explicitly stated severity, remediation, publication date, OS/build restrictions, required configuration, and direct source URLs. Do not infer or invent missing fields.`,
      ...(sourceDomains.length
        ? { include_domains: sourceDomains.join(",") }
        : {}),
    },
    {
      query: `${productContext} Search CVE.org, NVD, OSV.dev, and relevant official vendor security sources for advisories affecting installed version(s): ${inventoryContext}. Return verified CVE IDs, affected/fixed ranges, explicit severity, remediation, OS/build restrictions, and source URLs; use UNKNOWN when unavailable.`,
      include_domains: "cve.org,nvd.nist.gov,osv.dev",
    },
  ];
  if (distroDomains.length > 0) {
    queries.push({
      query: `${productContext} ${inventoryContext} distribution security tracker package backport CVE affected/fixed versions and remediation.`,
      include_domains: distroDomains.join(","),
    });
  }

  return {
    group,
    queries,
    product,
    vendor,
    knownOfficialDomains: sourceDomains,
    knownSources,
    distributionDomains: distroDomains,
  };
}
