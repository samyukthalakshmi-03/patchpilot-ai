
/**
 * Extract and parse software versions.
 *
 * Supports:
 * 8.3.35
 * v8.3.35
 * PHP 8.3.36
 * PHP 8.3.36-1
 * 8.4.27
 */

export function parseVersion(version) {
  if (version === null || version === undefined) {
    return null;
  }

  const input = String(version).trim();

  // Find the numeric version, even when text such as "PHP"
  // appears before it. Preserve numeric build suffixes like -1.
  const match = input.match(
    /(?:^|[^\w])v?(\d+(?:\.\d+)+(?:-\d+)?)(?=$|[^\d])/i
  );

  if (!match) {
    return null;
  }

  const parts = match[1]
    .split(/[.-]/)
    .map(Number);

  if (parts.some((part) => !Number.isSafeInteger(part))) {
    return null;
  }

  return parts;
}

/**
 * Compare two software versions.
 *
 * Returns:
 * -1 if a < b
 *  0 if a === b
 *  1 if a > b
 * null if either version is invalid.
 */
export function compareVersions(a, b) {
  const left = parseVersion(a);
  const right = parseVersion(b);

  if (!left || !right) {
    return null;
  }

  const length = Math.max(left.length, right.length);

  for (let i = 0; i < length; i++) {
    const x = left[i] ?? 0;
    const y = right[i] ?? 0;

    if (x < y) return -1;
    if (x > y) return 1;
  }

  return 0;
}

/**
 * Extract the major.minor branch.
 *
 * Example:
 * PHP 8.3.36 -> 8.3
 */
export function getVersionBranch(version) {
  const parsed = parseVersion(version);

  if (!parsed || parsed.length < 2) {
    return null;
  }

  return `${parsed[0]}.${parsed[1]}`;
}
