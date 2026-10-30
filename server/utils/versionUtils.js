
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
  if (/^\d+:/.test(input)) return null;

  const match = input.match(
    /(?:^|[^\w])v?(\d+(?:\.\d+)+(?:-\d+)?)(?![\w+-]|\.\d)/i
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

export function versionMatchesAffectedRange(installedVersion, affectedRange) {
  const installed = String(installedVersion || "").trim();
  const range = String(affectedRange || "").trim();
  if (!installed || !range || range.toUpperCase() === "UNKNOWN") return null;

  const constraints = [];
  const constraintPattern =
    /(?:^|[\s,;])(?:v)?(>=|<=|>|<|=)\s*v?(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)/g;
  for (const match of range.matchAll(constraintPattern)) {
    constraints.push([match[1], match[2]]);
  }

  for (const match of range.matchAll(
    /\b(introduced|fixed|last[_ ]affected)\s*:?\s*v?(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)/gi
  )) {
    if (match[1].toLowerCase() === "introduced" && match[2] === "0") {
      continue;
    }
    constraints.push([
      match[1].toLowerCase() === "introduced"
        ? ">="
        : match[1].toLowerCase() === "fixed" ? "<" : "<=",
      match[2],
    ]);
  }

  const proseRange = [
    [/\b(?:before|prior to|less than)\s+v?(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)/gi, "<"],
    [/\b(?:through|up to|at most)\s+v?(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)/gi, "<="],
    [/\b(?:after|later than|greater than)\s+v?(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)/gi, ">"],
    [/\b(?:at least|starting with)\s+v?(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)/gi, ">="],
  ];
  for (const [pattern, operator] of proseRange) {
    for (const match of range.matchAll(pattern)) {
      constraints.push([operator, match[1]]);
    }
  }

  if (constraints.length > 0) {
    const comparisons = constraints.map(([operator, version]) => {
      const comparison = compareVersions(installed, version);
      if (comparison === null) return null;
      if (operator === "<") return comparison < 0;
      if (operator === "<=") return comparison <= 0;
      if (operator === ">") return comparison > 0;
      if (operator === ">=") return comparison >= 0;
      return comparison === 0;
    });
    if (comparisons.some((comparison) => comparison === null)) return null;
    return comparisons.every(Boolean);
  }

  const legacyBranch = range.match(
    /\b(?:PHP\s*)?(\d+\.\d+)(?:\s*(?:branch|series))?\b/i
  );
  if (legacyBranch) {
    return getVersionBranch(installed) === legacyBranch[1];
  }

  const exactVersion = range.match(
    /(?:^|[^\w])v?(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)(?:$|[^\w])/
  );
  if (exactVersion && /\b(?:exactly|only|version)\b/i.test(range)) {
    return compareVersions(installed, exactVersion[1]) === 0;
  }

  return null;
}
