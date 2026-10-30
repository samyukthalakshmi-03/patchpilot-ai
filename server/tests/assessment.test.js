
import test from "node:test";
import assert from "node:assert/strict";

import {
  compareVersions,
  parseVersion,
} from "../utils/versionUtils.js";

import {
  assessAdvisory,
} from "../utils/assessmentUtils.js";
import {
  normalizePlatformFields,
} from "../utils/inventoryUtils.js";

// Shared test advisory
const advisory = {
  product: "PHP",
  title: "Critical RCE vulnerability",
  cveId: "CVE-2026-109618",
  affectedVersions: "PHP 8.3",
  fixedVersion: "8.3.36",
  sourceUrl: "https://www.php.net/archive/2026.php",
};

// 1. Parse a standard PHP version
test("parses PHP version", () => {
  assert.deepEqual(parseVersion("8.3.35"), [8, 3, 35]);
});

// 2. Compare software versions
test("compares versions correctly", () => {
  assert.equal(compareVersions("8.3.35", "8.3.36"), -1);
  assert.equal(compareVersions("8.3.36", "8.3.36"), 0);
  assert.equal(compareVersions("8.3.37", "8.3.36"), 1);
});

// 3. Handle invalid versions
test("returns null for invalid versions", () => {
  assert.equal(compareVersions("unknown", "8.3.36"), null);
});

// 4. Identify a potentially affected version
test("identifies a potentially affected version", () => {
  const result = assessAdvisory(
    { product: "PHP", version: "8.3.35" },
    advisory
  );

  assert.equal(result.assessment, "POTENTIALLY_AFFECTED");
});

// 5. Identify a version meeting the fixed threshold
test("identifies a version meeting the fixed threshold", () => {
  const result = assessAdvisory(
    { product: "PHP", version: "8.3.36" },
    advisory
  );

  assert.equal(result.assessment, "FIXED_FOR_THIS_CVE");
});

// 6. Unknown affected range requires review
test("unknown affected range requires review", () => {
  const result = assessAdvisory(
    { product: "PHP", version: "8.3.35" },
    { ...advisory, affectedVersions: "UNKNOWN" }
  );

  assert.equal(result.assessment, "NEEDS_REVIEW");
});

// 7. Parse a version with PHP prefix
test("parses a version with PHP prefix", () => {
  assert.deepEqual(parseVersion("PHP 8.3.36"), [8, 3, 36]);
});

// 8. Parse a Windows build suffix
test("parses a Windows build suffix", () => {
  assert.deepEqual(parseVersion("PHP 8.3.36-1"), [8, 3, 36, 1]);
});

// 9. Compare PHP-prefixed fixed versions
test("compares PHP-prefixed fixed versions", () => {
  assert.equal(compareVersions("8.3.35", "PHP 8.3.36"), -1);
  assert.equal(compareVersions("8.3.36", "PHP 8.3.36"), 0);
});

// 10. Distinguish Windows build versions
test("distinguishes Windows build versions", () => {
  assert.equal(compareVersions("8.3.36", "8.3.36-1"), -1);
});

// 11. Unknown operating system requires review for a Windows-specific advisory
test("unknown OS requires review for a Windows-specific advisory", () => {
  const result = assessAdvisory(
    { product: "PHP", version: "8.3.35" },
    {
      ...advisory,
      affectedOperatingSystems: "Windows",
      buildRestrictions: "Windows builds only",
    }
  );

  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /operating system is unknown/i);
});

// 12. Explicit Windows-only restrictions do not apply to Linux
test("Linux is not applicable to an explicitly Windows-only advisory", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      version: "8.3.35",
      operatingSystem: "Linux",
    },
    {
      ...advisory,
      affectedOperatingSystems: "Windows",
      buildRestrictions: "Windows builds only",
    }
  );

  assert.equal(result.assessment, "NOT_APPLICABLE");
  assert.match(result.reason, /identifies this asset as Linux/i);
});

// 13. Windows assets use build and version evidence
test("assesses a verified Windows build against affected-version evidence", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      version: "8.3.35",
      operatingSystem: "Windows",
      buildType: "Windows build",
    },
    {
      ...advisory,
      affectedOperatingSystems: "Windows",
      buildRestrictions: "Windows builds only",
    }
  );

  assert.equal(result.assessment, "POTENTIALLY_AFFECTED");
});

// 14. Unknown build details require review when builds are restricted
test("unknown Windows build requires review when build details are required", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      version: "8.3.35",
      operatingSystem: "Windows",
      buildType: "Unknown",
    },
    {
      ...advisory,
      affectedOperatingSystems: "Windows",
      buildRestrictions: "Windows builds only",
    }
  );

  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /build type is unknown/i);
});

test("Windows build variants not represented in inventory require review", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      version: "8.3.35",
      operatingSystem: "Windows",
      buildType: "Windows build",
    },
    {
      ...advisory,
      affectedOperatingSystems: "Windows",
      buildRestrictions: "Windows x64 Thread Safe builds only",
    }
  );

  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /build details that the inventory does not record/i);
});

// 15. General PHP advisories do not require platform data
test("assesses a general PHP advisory without operating system information", () => {
  const result = assessAdvisory(
    { product: "PHP", version: "8.3.35" },
    advisory
  );

  assert.equal(result.assessment, "POTENTIALLY_AFFECTED");
});

// 16. Missing platform inventory fields default to Unknown
test("defaults missing platform fields to Unknown", () => {
  assert.deepEqual(normalizePlatformFields({}), {
    operatingSystem: "Unknown",
    buildType: "Unknown",
  });
});

// 17. Custom/vendor builds require verified vendor patch information
test("custom/vendor builds require review without verified patch information", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      version: "8.3.36",
      operatingSystem: "Linux",
      buildType: "Custom/vendor build",
    },
    advisory
  );

  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /vendor-specific patch or backport status is not verified/i);
});

test("rejects unsupported operating systems and build types", () => {
  assert.throws(
    () => normalizePlatformFields({ operatingSystem: "Solaris" }),
    /Operating system must be one of/
  );
  assert.throws(
    () => normalizePlatformFields({ buildType: "Unlisted build" }),
    /Build type must be one of/
  );
});
