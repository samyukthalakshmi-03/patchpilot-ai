function normalizeText(value, fieldName, maxLength, fallback = "") {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value !== "string" && typeof value !== "number") {
    throw new Error(`${fieldName} must be a string.`);
  }
  const normalized = String(value).trim();
  if (normalized.length > maxLength) {
    throw new Error(`${fieldName} must be at most ${maxLength} characters.`);
  }
  return normalized;
}

export function normalizePlatformFields(asset) {
  return {
    operatingSystem: normalizeText(
      asset.operatingSystem,
      "Operating system",
      100,
      "Unknown"
    ) || "Unknown",
    buildType: normalizeText(
      asset.buildType,
      "Build type",
      100,
      "Unknown"
    ) || "Unknown",
  };
}

export function normalizeOptionalInventoryFields(asset) {
  return {
    vendor: normalizeText(asset.vendor, "Vendor", 100),
    packageManager: normalizeText(
      asset.packageManager,
      "Package manager",
      100
    ),
    architecture: normalizeText(asset.architecture, "Architecture", 100),
    installedConfiguration: normalizeText(
      asset.installedConfiguration,
      "Installed configuration",
      1000
    ),
  };
}
