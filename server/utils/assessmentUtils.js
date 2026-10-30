import {
  productsMatch,
  validateProductVendor,
} from "./productDiscovery.js";
import {
  compareVersions,
  getVersionBranch,
  versionMatchesAffectedRange,
} from "./versionUtils.js";

function extractCveIds(advisory) {
  const text = [
    advisory.cveId,
    advisory.cve_id,
    advisory.title,
  ].filter(Boolean).join(" ").toUpperCase();
  return [...new Set(text.match(/CVE-\d{4}-\d+/g) || [])];
}

function needsReview(reason, cveIds) {
  return { assessment: "NEEDS_REVIEW", reason, cveIds };
}

function configurationEvidenceMatches(inventoryConfiguration, condition) {
  const config = String(inventoryConfiguration || "").toLowerCase();
  const required = String(condition || "").toLowerCase();
  const stopWords = new Set([
    "when", "only", "with", "without", "this", "that", "which", "from",
    "into", "through", "using", "used", "must", "should", "enabled",
    "disabled", "configured", "configuration", "setting", "option",
    "the", "and", "for", "are", "was", "can", "may", "will",
  ]);
  const terms = [...new Set(
    required.match(/[a-z][a-z0-9_.-]{3,}/g) || []
  )].filter((term) => !stopWords.has(term));
  if (terms.length === 0) return false;
  return terms.filter((term) => config.includes(term)).length >=
    Math.min(2, terms.length);
}

function operatingSystemFamily(value) {
  const os = String(value || "").trim().toLowerCase();
  if (/windows/.test(os)) return "windows";
  if (/linux|ubuntu|debian|red hat|rhel|fedora|alpine|arch|suse/.test(os)) {
    return "linux";
  }
  if (/macos|mac os|darwin/.test(os)) return "macos";
  if (/freebsd/.test(os)) return "freebsd";
  if (/solaris/.test(os)) return "solaris";
  if (/unix/.test(os)) return "unix";
  return os;
}

function isWindowsOnly(advisory) {
  const os = String(advisory.affectedOperatingSystems || "").trim();
  const build = String(advisory.buildRestrictions || "").trim();
  return /\bwindows[- ]only\b|\bonly\s+windows\b|\bwindows[- ]specific\b|\brestricted\s+to\s+windows\b/i
    .test(`${os} ${build}`) ||
    (/\bwindows\b/i.test(build) &&
      !/\b(?:linux|macos|unix)\b/i.test(build)) ||
    (/^\s*windows\s*$/i.test(os));
}

function affectedOperatingSystemFamilies(advisory) {
  const os = String(advisory.affectedOperatingSystems || "");
  const labels = os.match(/\b(windows|linux|macos|unix|freebsd|solaris)\b/gi) || [];
  return new Set(
    labels.map((label) => operatingSystemFamily(label))
  );
}

function platformAssessment(asset, advisory, cveIds) {
  const assetOS = String(asset.operatingSystem || "Unknown").trim();
  const affectedOS = String(
    advisory.affectedOperatingSystems || ""
  ).trim();
  const buildRestrictions = String(
    advisory.buildRestrictions || ""
  ).trim();

  if (isWindowsOnly(advisory)) {
    if (assetOS.toLowerCase() === "unknown") {
      return needsReview(
        "Operating system is unknown, and the advisory applies specifically to Windows.",
        cveIds
      );
    }
    if (["linux", "macos", "unix", "freebsd", "solaris"].includes(
      operatingSystemFamily(assetOS)
    )) {
      return {
        assessment: "NOT_APPLICABLE",
        reason: `The advisory is restricted to Windows, while the inventory identifies this asset as ${assetOS}.`,
        cveIds,
      };
    }
    if (operatingSystemFamily(assetOS) !== "windows") {
      return needsReview(
        "The advisory applies specifically to Windows, but this asset's operating system cannot be matched confidently.",
        cveIds
      );
    }
  } else {
    const affectedFamilies = affectedOperatingSystemFamilies(advisory);
    if (affectedFamilies.size === 1) {
      if (assetOS.toLowerCase() === "unknown") {
        return needsReview(
          `Operating system is unknown, and the advisory explicitly applies to ${affectedOS}.`,
          cveIds
        );
      }
      if (!affectedFamilies.has(operatingSystemFamily(assetOS))) {
        return {
          assessment: "NOT_APPLICABLE",
          reason: `The advisory explicitly lists ${affectedOS} as the affected platform, while the inventory identifies this asset as ${assetOS}.`,
          cveIds,
        };
      }
    }
  }

  if (buildRestrictions && buildRestrictions.toUpperCase() !== "UNKNOWN") {
    const buildType = String(asset.buildType || "Unknown").trim();
    if (buildType.toLowerCase() === "unknown") {
      return needsReview(
        "The advisory specifies build restrictions, but the inventory build type is unknown.",
        cveIds
      );
    }
    const restrictionTokens = buildRestrictions
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((token) => token.length > 2);
    const buildText = `${buildType} ${asset.architecture || ""}`
      .toLowerCase();
    if (
      restrictionTokens.some((token) => buildText.includes(token)) === false &&
      /\b(?:only|specific|restricted|build|architecture|x64|x86|arm64)\b/i
        .test(buildRestrictions)
    ) {
      return needsReview(
        "The advisory has build-specific restrictions that cannot be matched to the inventory build details.",
        cveIds
      );
    }
    const specificBuildRestriction = buildRestrictions.match(
      /\b(?:x64|x86|32[- ]bit|64[- ]bit|arm64|aarch64|thread[- ]safe|non[- ]thread[- ]safe|nts|zts|vc\d+)\b/i
    )?.[0];
    if (
      specificBuildRestriction &&
      !buildText.includes(specificBuildRestriction.toLowerCase())
    ) {
      return needsReview(
        "The advisory specifies build details that the inventory does not record, so a matching build cannot be verified.",
        cveIds
      );
    }
  }

  return null;
}

export function assessAdvisory(asset, advisory) {
  const cveIds = extractCveIds(advisory);

  if (advisory.advisoryType === "INFORMATIONAL_NOTICE") {
    return {
      assessment: "NOT_APPLICABLE",
      reason: "The source identifies an informational notice, not a security vulnerability.",
      cveIds,
    };
  }

  const vendorValidation = validateProductVendor(asset, advisory);
  if (!vendorValidation.valid) {
    return needsReview(vendorValidation.reason, cveIds);
  }

  if (!cveIds.length) {
    return needsReview("No verifiable CVE identifier was provided.", []);
  }

  if (!productsMatch(asset, advisory)) {
    return needsReview(
      "Product or vendor identity could not be confidently matched.",
      cveIds
    );
  }

  if (advisory.sourceVerified === false) {
    return needsReview(
      "The advisory source could not be verified as an authoritative vendor or public security source.",
      cveIds
    );
  }

  if (advisory.evidenceStatus === "UNVERIFIED_SOURCE") {
    return needsReview("The source evidence is unverified.", cveIds);
  }

  const platformResult = platformAssessment(asset, advisory, cveIds);
  if (platformResult) return platformResult;

  if (
    advisory.requiredConfigurationConditions &&
    advisory.requiredConfigurationConditions.toUpperCase() !== "UNKNOWN"
  ) {
    if (!String(asset.installedConfiguration || "").trim()) {
      return needsReview(
        "The advisory depends on a specific configuration, but the installed configuration was not provided.",
        cveIds
      );
    }
    if (!configurationEvidenceMatches(
      asset.installedConfiguration,
      advisory.requiredConfigurationConditions
    )) {
      return needsReview(
        "The installed configuration does not provide enough evidence to verify the advisory's required conditions.",
        cveIds
      );
    }
  }

  if (asset.buildType === "Custom/vendor build") {
    return needsReview(
      "Vendor-specific patch or backport status is not verified for this custom/vendor build.",
      cveIds
    );
  }

  if (
    asset.packageManager &&
    advisory.sourceType !== "distribution-security-tracker"
  ) {
    return needsReview(
      "The software is package-managed, but no matching distribution security evidence verifies whether vendor backports were applied.",
      cveIds
    );
  }

  const installedVersion = String(asset.version || "").trim();
  const fixedVersion = String(advisory.fixedVersion || "").trim();
  const installedBranch = getVersionBranch(installedVersion);
  const matchingFixedVersions = Array.isArray(advisory.fixedVersions)
    ? advisory.fixedVersions.filter((version) =>
      getVersionBranch(version) === installedBranch
    )
    : [];
  const effectiveFixedVersion = fixedVersion &&
    fixedVersion.toUpperCase() !== "UNKNOWN"
    ? fixedVersion
    : matchingFixedVersions.length === 1
      ? matchingFixedVersions[0]
      : "";
  const affectedVersions = String(
    advisory.affectedVersions || ""
  ).trim();
  if (!installedVersion) {
    return needsReview("Installed software version is missing.", cveIds);
  }
  if (!affectedVersions || affectedVersions.toUpperCase() === "UNKNOWN") {
    return needsReview(
      "The advisory does not provide a verified affected-version range.",
      cveIds
    );
  }
  if (!advisory.sourceUrl || !/^https:\/\//i.test(advisory.sourceUrl)) {
    return needsReview("A direct HTTPS evidence source is required.", cveIds);
  }

  const rangeMatch = versionMatchesAffectedRange(
    installedVersion,
    affectedVersions
  );
  const legacyBranch = affectedVersions.match(
    /\b(?:PHP\s*)?(\d+\.\d+)(?:\s*(?:branch|series))?\b/i
  );
  const fixedComparison = effectiveFixedVersion
    ? compareVersions(installedVersion, effectiveFixedVersion)
    : null;

  if (rangeMatch === true) {
    if (
      legacyBranch &&
      installedVersion.match(/\d+\.\d+/)?.[0] === legacyBranch[1] &&
      fixedComparison !== null
    ) {
      return fixedComparison < 0
        ? {
          assessment: "POTENTIALLY_AFFECTED",
          reason: `Installed version ${installedVersion} is older than the stated fixed version ${effectiveFixedVersion} in the affected release branch.`,
          cveIds,
        }
        : {
          assessment: "FIXED_FOR_THIS_CVE",
          reason: `Installed version ${installedVersion} meets or exceeds the stated fixed version ${effectiveFixedVersion} in the affected release branch.`,
          cveIds,
        };
    }
    if (fixedComparison !== null && fixedComparison >= 0) {
      return needsReview(
        "The installed version conflicts with the published affected range and fixed version; verify the source version semantics.",
        cveIds
      );
    }
    return {
      assessment: "POTENTIALLY_AFFECTED",
      reason: `Installed version ${installedVersion} matches the published affected-version range (${affectedVersions}).`,
      cveIds,
    };
  }

  if (rangeMatch === false) {
    if (fixedComparison !== null && fixedComparison >= 0) {
      return {
        assessment: "FIXED_FOR_THIS_CVE",
        reason: `Installed version ${installedVersion} is outside the published affected range and meets the stated fixed version ${effectiveFixedVersion}.`,
        cveIds,
      };
    }
    return needsReview(
      "The installed version is outside the stated affected range, but no matching fixed-version evidence confirms the assessment.",
      cveIds
    );
  }

  if (fixedComparison !== null) {
    if (
      legacyBranch &&
      installedVersion.match(/\d+\.\d+/)?.[0] === legacyBranch[1] &&
      fixedComparison < 0
    ) {
      return {
        assessment: "POTENTIALLY_AFFECTED",
        reason: `Installed version ${installedVersion} is older than the stated fixed version ${effectiveFixedVersion} in the affected release branch.`,
        cveIds,
      };
    }
    if (fixedComparison >= 0) {
      return {
        assessment: "FIXED_FOR_THIS_CVE",
        reason: `Installed version ${installedVersion} meets or exceeds the stated fixed version ${effectiveFixedVersion}.`,
        cveIds,
      };
    }
  }

  return needsReview(
    "The affected-version range could not be interpreted safely for this software version.",
    cveIds
  );
}
