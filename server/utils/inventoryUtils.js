export const OPERATING_SYSTEMS = [
  "Unknown",
  "Windows",
  "Linux",
  "macOS",
  "Other",
];

export const BUILD_TYPES = [
  "Unknown",
  "Standard PHP build",
  "Windows build",
  "Custom/vendor build",
];

export function normalizePlatformFields(asset) {
  const normalizeField = (value, allowedValues, fieldName) => {
    const normalized = String(value ?? "").trim() || "Unknown";

    if (!allowedValues.includes(normalized)) {
      throw new Error(
        `${fieldName} must be one of: ${allowedValues.join(", ")}.`
      );
    }

    return normalized;
  };

  return {
    operatingSystem: normalizeField(
      asset.operatingSystem,
      OPERATING_SYSTEMS,
      "Operating system"
    ),
    buildType: normalizeField(
      asset.buildType,
      BUILD_TYPES,
      "Build type"
    ),
  };
}
