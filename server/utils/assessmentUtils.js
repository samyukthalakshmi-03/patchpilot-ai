
import {
  compareVersions,
  getVersionBranch,
} from "./versionUtils.js";

function extractCveIds(advisory) {
  const text = [
    advisory.cveId,
    advisory.cve_id,
    advisory.title,
  ]
    .filter(Boolean)
    .join(" ")
    .toUpperCase();

  return [...new Set(text.match(/CVE-\d{4}-\d+/g) || [])];
}

function normalizeProduct(value) {
  return String(value || "").trim().toLowerCase();
}

function isHttpsSource(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isWindowsSpecific(advisory) {
  const operatingSystems = String(
    advisory.affectedOperatingSystems || ""
  ).trim();
  const buildRestrictions = String(
    advisory.buildRestrictions || ""
  ).trim();
  const evidence = `${operatingSystems} ${buildRestrictions}`;

  if (
    /\bwindows[- ]only\b|\bonly\s+windows\b|\bwindows[- ]specific\b|\brestricted\s+to\s+windows\b/i
      .test(evidence) ||
    /\bwindows\b/i.test(buildRestrictions)
  ) {
    return true;
  }

  const listedOperatingSystems = operatingSystems
    .toLowerCase()
    .match(/\b(windows|linux|macos|other)\b/g);

  return Boolean(
    listedOperatingSystems?.length === 1 &&
    listedOperatingSystems[0] === "windows"
  );
}

function requiresSpecificWindowsBuild(advisory) {
  return /\b(?:x64|x86|32[- ]bit|64[- ]bit|thread[- ]safe|non[- ]thread[- ]safe|nts|ts|vc\d+|zts)\b/i
    .test(String(advisory.buildRestrictions || ""));
}

function needsReview(reason, cveIds) {
  return {
    assessment: "NEEDS_REVIEW",
    reason,
    cveIds,
  };
}

/**
 * Assess one asset against one advisory.
 *
 * This intentionally returns NEEDS_REVIEW whenever
 * the available evidence is insufficient.
 */
export function assessAdvisory(asset, advisory) {
  const cveIds = extractCveIds(advisory);

  if (advisory.advisoryType === "INFORMATIONAL_NOTICE") {
    return {
      assessment: "NOT_APPLICABLE",
      reason: "The source identifies an informational notice, not a security vulnerability.",
      cveIds,
    };
  }

  const assetProduct = normalizeProduct(asset.product);
  const advisoryProduct = normalizeProduct(advisory.product);

  const installedVersion = String(asset.version || "").trim();
  const fixedVersion = String(advisory.fixedVersion || "").trim();
  const affectedVersions = String(
    advisory.affectedVersions || ""
  ).trim();

  if (!cveIds.length) {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "No verifiable CVE identifier was provided.",
      cveIds: [],
    };
  }

  if (!assetProduct || !advisoryProduct ||
      assetProduct !== advisoryProduct) {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "Product identity could not be confidently matched.",
      cveIds,
    };
  }

  if (isWindowsSpecific(advisory)) {
    if (!asset.operatingSystem || asset.operatingSystem === "Unknown") {
      return needsReview(
        "Operating system is unknown, and the advisory applies specifically to Windows builds.",
        cveIds
      );
    }

    if (
      asset.operatingSystem === "Linux" ||
      asset.operatingSystem === "macOS"
    ) {
      return {
        assessment: "NOT_APPLICABLE",
        reason: `The advisory is restricted to Windows builds, while the inventory identifies this asset as ${asset.operatingSystem}.`,
        cveIds,
      };
    }

    if (asset.operatingSystem !== "Windows") {
      return needsReview(
        "The advisory applies specifically to Windows builds, but this asset's operating system cannot be matched confidently.",
        cveIds
      );
    }

    const buildRestrictions = String(
      advisory.buildRestrictions || ""
    ).trim();
    const requiresWindowsBuild = /\bwindows\b/i.test(buildRestrictions);

    if (requiresWindowsBuild) {
      if (!asset.buildType || asset.buildType === "Unknown") {
        return needsReview(
          "Build type is unknown, and the advisory requires a Windows build.",
          cveIds
        );
      }

      if (asset.buildType !== "Windows build") {
        return needsReview(
          "The advisory requires a Windows build, but the inventory identifies a different or unverified build type.",
          cveIds
        );
      }
    }

    if (requiresSpecificWindowsBuild(advisory)) {
      return needsReview(
        "The advisory specifies Windows build details that the inventory does not record, so a matching build cannot be verified.",
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

  if (!affectedVersions || affectedVersions.toUpperCase() === "UNKNOWN") {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "The advisory does not provide a verified affected-version range.",
      cveIds,
    };
  }

  if (!fixedVersion || fixedVersion.toUpperCase() === "UNKNOWN") {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "No verified fixed version was provided.",
      cveIds,
    };
  }

  if (!isHttpsSource(advisory.sourceUrl)) {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "A valid HTTPS evidence source is required.",
      cveIds,
    };
  }

  const installedBranch = getVersionBranch(installedVersion);
  const fixedBranch = getVersionBranch(fixedVersion);

  if (!installedBranch || !fixedBranch) {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "The installed or fixed version could not be parsed.",
      cveIds,
    };
  }

  // Do not compare versions across different release branches.
  if (installedBranch !== fixedBranch) {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "Installed and fixed versions belong to different release branches.",
      cveIds,
    };
  }

  // This first version supports an explicitly stated major.minor
  // affected branch, such as "PHP 8.3".
  const affectedBranchPattern = new RegExp(
    `\\b${installedBranch.replace(".", "\\.")}(?:\\.\\d+)?\\b`
  );

  if (!affectedBranchPattern.test(affectedVersions)) {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "The affected-version information does not explicitly match the installed release branch.",
      cveIds,
    };
  }

  const comparison = compareVersions(
    installedVersion,
    fixedVersion
  );

  if (comparison === null) {
    return {
      assessment: "NEEDS_REVIEW",
      reason: "Version comparison could not be completed.",
      cveIds,
    };
  }

  if (comparison < 0) {
    return {
      assessment: "POTENTIALLY_AFFECTED",
      reason: `Installed version ${installedVersion} is older than the stated fixed version ${fixedVersion} in the matching release branch.`,
      cveIds,
    };
  }

  return {
    assessment: "FIXED_FOR_THIS_CVE",
    reason: `Installed version ${installedVersion} meets or exceeds the stated fixed version ${fixedVersion} for this advisory.`,
    cveIds,
  };
}
