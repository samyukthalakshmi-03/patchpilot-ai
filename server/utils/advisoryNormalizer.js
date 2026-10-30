function extractSection(text, names) {
  const headings = names.join("|");
  const heading = new RegExp(
    `^#{1,6}\\s*(?:${headings})\\s*:?\\s*$`,
    "im"
  );
  const match = heading.exec(text);
  if (!match) return "";

  const start = match.index + match[0].length;
  const nextHeading = /^#{1,6}\s+.+$/gm;
  nextHeading.lastIndex = start;
  const next = nextHeading.exec(text);
  return text.slice(start, next?.index ?? text.length).trim();
}

function findLabelValue(text, labels) {
  const label = labels.join("|");
  const normalizedText = String(text).replace(/[*`]/g, "");
  const match = normalizedText.match(
    new RegExp(`^\\s*(?:${label})\\s*:?\\s*(.+?)\\s*$`, "im")
  );
  return match?.[1]?.trim() || "";
}

function versionsIn(text) {
  return [...new Set(
    String(text).match(/(?<![\w-])v?\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?/g) || []
  )];
}

function severity(text) {
  const explicit = findLabelValue(text, ["severity", "risk level"]);
  const value = explicit.match(/\b(critical|high|moderate|medium|low)\b/i);
  if (value) return value[1].toUpperCase();

  const standalone = text.match(
    /^\s*(critical|high|moderate|medium|low)\s*$/im
  );
  return standalone?.[1]?.toUpperCase() || "UNKNOWN";
}

function cvss(text) {
  const match = text.match(
    /\bCVSS(?:\s*v?3(?:\.\d)?| v?4(?:\.\d)?)?\s*(?:score)?\s*[:=]\s*(10(?:\.0)?|[0-9](?:\.\d{1,2})?)\b/i
  );
  return match ? Number(match[1]) : null;
}

function publicationDate(text) {
  const value = findLabelValue(text, [
    "published(?: date)?",
    "publication date",
    "date published",
    "published on",
    "issued",
  ]);
  if (!value) return "";
  const date = value.match(
    /\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}\s+[A-Za-z]+\s+\d{4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})\b/
  );
  return date?.[0] || value;
}

function explicitCves(text) {
  const allIds = [
    ...new Set(
      String(text).match(/CVE-\d{4}-\d+/gi)?.map((id) => id.toUpperCase()) || []
    ),
  ];
  const explicitIds = [
    ...new Set(
      [...String(text).matchAll(
        /^\s*(?:#{1,6}\s*)?(?:CVE(?:\s+ID)?\s*[:#]\s*)?(CVE-\d{4}-\d+)\s*$/gim
      )].map((match) => match[1].toUpperCase())
    ),
  ];
  if (explicitIds.length > 0) return explicitIds;
  return allIds.length <= 1 ? allIds : [];
}

function relevantContext(text, cveId) {
  const blocks = text.split(/\n{2,}/);
  const index = blocks.findIndex((block) =>
    block.toUpperCase().includes(cveId)
  );
  if (index < 0) return text;
  const start = Math.max(0, index - 2);
  const end = Math.min(blocks.length, index + 4);
  return blocks.slice(start, end).join("\n\n");
}

function valueOrUnknown(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean).join(", ") ||
      "UNKNOWN";
  }
  return String(value ?? "").trim() || "UNKNOWN";
}

function firstPresent(record, names) {
  for (const name of names) {
    const value = record?.[name];
    if (
      value !== undefined &&
      value !== null &&
      value !== "" &&
      !(typeof value === "string" && value.trim().toUpperCase() === "UNKNOWN") &&
      !(Array.isArray(value) && value.length === 0)
    ) {
      return value;
    }
  }
  return undefined;
}

function normalizeFixedVersions(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => String(entry).trim()).filter(Boolean);
  }
  if (typeof value !== "string" || !value.trim() ||
    value.trim().toUpperCase() === "UNKNOWN") {
    return [];
  }
  return versionsIn(value);
}

export function normalizeAdvisoryRecord(advisory, defaults = {}) {
  const fixedVersions = normalizeFixedVersions(firstPresent(advisory, [
    "fixedVersions",
    "fixed_versions",
  ]));
  const explicitFixedVersion = firstPresent(advisory, [
    "fixedVersion",
    "fixed_version",
  ]);
  const fixedVersion = valueOrUnknown(explicitFixedVersion ??
    (fixedVersions.length === 1 ? fixedVersions[0] : undefined));
  const sourceUrlValue = firstPresent(advisory, [
    "sourceUrl",
    "source_url",
  ]) ?? defaults.sourceUrl;
  let sourceUrl = "";
  try {
    const parsedUrl = new URL(sourceUrlValue);
    if (parsedUrl.protocol === "https:" && !parsedUrl.username &&
      !parsedUrl.password) {
      sourceUrl = parsedUrl.href;
    }
  } catch {
    sourceUrl = "";
  }
  const sourceVerified = firstPresent(advisory, [
    "sourceVerified",
    "source_verified",
  ]) ?? defaults.sourceVerified ?? false;
  const verifiedInformation = firstPresent(advisory, [
    "verifiedInformation",
    "verified_information",
  ]);
  const inferredInformation = firstPresent(advisory, [
    "inferredInformation",
    "inferred_information",
  ]);
  const cvssScoreValue = firstPresent(advisory, [
    "cvssScore",
    "cvss_score",
    "cvss",
  ]);

  const normalized = {
    ...advisory,
    product: String(firstPresent(advisory, ["product", "softwareName"]) ??
      defaults.product ?? "Unknown"),
    softwareName: String(firstPresent(advisory, ["softwareName", "product"]) ??
      defaults.product ?? "Unknown"),
    vendor: String(firstPresent(advisory, ["vendor"]) ??
      defaults.vendor ?? "UNKNOWN"),
    title: String(firstPresent(advisory, [
      "title",
      "advisoryTitle",
      "advisory_title",
    ]) ?? "Security advisory"),
    cveId: String(firstPresent(advisory, ["cveId", "cve_id"]) ?? ""),
    severity: String(firstPresent(advisory, ["severity"]) ?? "UNKNOWN")
      .toUpperCase(),
    cvssScore: cvssScoreValue !== undefined &&
      cvssScoreValue !== null &&
      cvssScoreValue !== "" &&
      Number.isFinite(Number(cvssScoreValue))
      ? Number(cvssScoreValue)
      : null,
    advisoryType: String(firstPresent(advisory, [
      "advisoryType",
      "advisory_type",
    ]) ?? "SECURITY_VULNERABILITY").toUpperCase(),
    affectedVersions: valueOrUnknown(firstPresent(advisory, [
      "affectedVersions",
      "affected_versions",
      "affectedVersionRange",
      "affected_version_range",
    ])),
    fixedVersion,
    fixedVersions,
    affectedOperatingSystems: valueOrUnknown(firstPresent(advisory, [
      "affectedOperatingSystems",
      "operatingSystemsAffected",
      "operating_systems_affected",
      "operating_systems",
      "affected_os",
    ])),
    buildRestrictions: valueOrUnknown(firstPresent(advisory, [
      "buildRestrictions",
      "build_restrictions",
    ])),
    requiredConfigurationConditions: valueOrUnknown(firstPresent(advisory, [
      "requiredConfigurationConditions",
      "required_configuration_conditions",
      "requiredConfiguration",
      "required_configuration",
    ])),
    remediation: valueOrUnknown(firstPresent(advisory, [
      "remediation",
      "remediationSteps",
      "remediation_steps",
    ])),
    publishedDate: valueOrUnknown(firstPresent(advisory, [
      "publishedDate",
      "publicationDate",
      "published_date",
      "publication_date",
      "datePublished",
      "date_published",
    ])),
    sourceName: String(firstPresent(advisory, ["sourceName", "source_name"]) ??
      defaults.sourceName ?? ""),
    sourceUrl,
    sourceType: String(firstPresent(advisory, ["sourceType", "source_type"]) ??
      defaults.sourceType ?? "UNKNOWN"),
    sourceVerified: sourceVerified === true,
    evidenceStatus: String(firstPresent(advisory, [
      "evidenceStatus",
      "evidence_status",
    ]) ?? (sourceVerified ? "VERIFIED_SOURCE" : "UNVERIFIED_SOURCE")),
    verifiedInformation: Array.isArray(verifiedInformation)
      ? verifiedInformation
      : [],
    inferredInformation: Array.isArray(inferredInformation)
      ? inferredInformation
      : [],
    evidenceExcerpt: String(firstPresent(advisory, [
      "evidenceExcerpt",
      "evidence_excerpt",
      "evidence",
      "excerpt",
    ]) ?? ""),
  };
  if (!Array.isArray(verifiedInformation) && normalized.sourceVerified) {
    normalized.verifiedInformation = [
      ["cveId", normalized.cveId],
      ["advisory title", normalized.title],
      ["severity", normalized.severity !== "UNKNOWN" ? normalized.severity : ""],
      ["CVSS", normalized.cvssScore],
      ["affected versions", normalized.affectedVersions !== "UNKNOWN"
        ? normalized.affectedVersions
        : ""],
      ["fixed version", normalized.fixedVersion !== "UNKNOWN"
        ? normalized.fixedVersion
        : ""],
      ["publication date", normalized.publishedDate !== "UNKNOWN"
        ? normalized.publishedDate
        : ""],
      ["remediation", normalized.remediation !== "UNKNOWN"
        ? normalized.remediation
        : ""],
      ["OS restrictions", normalized.affectedOperatingSystems !== "UNKNOWN"
        ? normalized.affectedOperatingSystems
        : ""],
      ["build restrictions", normalized.buildRestrictions !== "UNKNOWN"
        ? normalized.buildRestrictions
        : ""],
      ["required configuration", normalized.requiredConfigurationConditions !==
        "UNKNOWN" ? normalized.requiredConfigurationConditions : ""],
    ].filter(([, value]) => value !== "" && value !== null)
      .map(([label]) => label);
  }
  return normalized;
}

function normalizeOne(page, group, source) {
  const text = String(page.text || page.content || "");
  const structuredAdvisories = Array.isArray(page.advisories)
    ? page.advisories
    : Array.isArray(page.data?.advisories)
      ? page.data.advisories
      : [];
  if (structuredAdvisories.length > 0) {
    return structuredAdvisories.map((advisory) => {
      const normalized = normalizeAdvisoryRecord(advisory, {
        product: group.product,
        vendor: group.vendor || "UNKNOWN",
        sourceName: source.sourceName,
        sourceType: source.sourceType,
        sourceUrl: page.url,
        sourceVerified: source.verified,
      });
      return {
        ...normalized,
        sourceVerified: source.verified,
        evidenceStatus: source.verified
          ? "VERIFIED_SOURCE"
          : "UNVERIFIED_SOURCE",
        evidenceExcerpt: normalized.evidenceExcerpt ||
          String(page.text || page.content || "").slice(0, 1200),
      };
    }).filter((advisory) => advisory.cveId);
  }
  const identity = `${group.product} ${group.vendor}`.toLowerCase();
  const identityTokens = identity
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 3);
  if (
    source.sourceType === "public-advisory-database" &&
    !identityTokens.some((token) => text.toLowerCase().includes(token))
  ) {
    return [];
  }
  const cveIds = explicitCves(text);
  if (cveIds.length === 0) return [];

  const affectedSection = extractSection(text, [
    "affected versions?",
    "vulnerable versions?",
    "affected products?",
  ]);
  const fixedSection = extractSection(text, [
    "patched versions?",
    "fixed versions?",
    "fixed in",
    "resolved versions?",
  ]) || findLabelValue(text, [
    "fixed version",
    "patched version",
    "fixed",
  ]);
  const title = String(
    text.match(/^#{1,3}\s+(.+)$/m)?.[1] ||
    page.title ||
    "Security advisory"
  ).trim();
  const affectedVersions = valueOrUnknown(
    affectedSection ||
    findLabelValue(text, ["affected versions?", "vulnerable versions?"])
  );
  const fixedEntries = versionsIn(fixedSection);
  const configuration = text
    .split(/\n{2,}/)
    .find((paragraph) =>
      /\b(?:when|if|only when|only if|requires?)\b/i.test(paragraph) &&
      /\b(?:enabled|disabled|configured|configuration|setting|option)\b/i
        .test(paragraph)
    );
  const remediation = extractSection(text, [
    "remediation",
    "solution",
    "workaround",
    "mitigation",
    "recommendation",
    "how to fix",
  ]) || findLabelValue(text, [
    "remediation",
    "solution",
    "mitigation",
    "workaround",
    "recommendation",
  ]);
  const osSection = extractSection(text, [
    "operating systems?",
    "platforms?",
    "affected platforms?",
  ]);
  const buildSection = extractSection(text, [
    "build restrictions?",
    "affected configurations?",
    "affected components?",
  ]);
  const windowsSpecific = /\b(?:php\s+)?windows builds?\b|\bwindows[- ]only\b|\bonly on windows\b|\bonly affects? windows\b|\brestricted to windows\b|\bapplies only to windows\b|\bvulnerable on windows\b/i
    .test(`${title}\n${text}`);
  const affectedOperatingSystems = osSection ||
    (windowsSpecific ? "Windows" : "UNKNOWN");
  const buildRestrictions = buildSection ||
    (windowsSpecific ? "Windows builds" : "UNKNOWN");

  return cveIds.map((cveId) => {
    const context = relevantContext(text, cveId);
    const fixedVersion = fixedEntries.length === 1
      ? fixedEntries[0]
      : "UNKNOWN";
    const advisory = {
      product: group.product,
      softwareName: group.product,
      vendor: group.vendor || "UNKNOWN",
      title,
      cveId,
      severity: severity(text),
      cvssScore: cvss(text),
      affectedVersions,
      fixedVersion,
      fixedVersions: fixedEntries,
      affectedOperatingSystems: valueOrUnknown(affectedOperatingSystems),
      buildRestrictions: valueOrUnknown(buildRestrictions),
      requiredConfigurationConditions: valueOrUnknown(configuration),
      publishedDate: publicationDate(text),
      remediation: valueOrUnknown(remediation),
      sourceName: source.sourceName,
      sourceUrl: source.url,
      sourceType: source.sourceType,
      sourceVerified: source.verified,
      evidenceStatus: source.verified ? "VERIFIED_SOURCE" : "UNVERIFIED_SOURCE",
      verifiedInformation: source.verified ? [
        "CVE identifier",
        "advisory title",
        ...(affectedVersions !== "UNKNOWN" ? ["affected versions"] : []),
        ...(fixedVersion !== "UNKNOWN" ? ["fixed version"] : []),
        ...(severity(text) !== "UNKNOWN" ? ["severity"] : []),
      ] : [],
      inferredInformation: source.verified
        ? []
        : ["Potential vendor-source association; source ownership is unverified"],
      evidenceExcerpt: context.slice(0, 1200),
    };

    return advisory;
  });
}

export function normalizeAdvisoryPages(pages, group, classifySource) {
  return pages.flatMap((page) => {
    const source = classifySource(page.url, group);
    if (!source) return [];
    return normalizeOne(page, group, source);
  });
}
