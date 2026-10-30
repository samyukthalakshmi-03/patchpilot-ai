
import test from "node:test";
import assert from "node:assert/strict";

import {
  compareVersions,
  parseVersion,
  versionMatchesAffectedRange,
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

test("PHP Group Windows-only advisory remains not applicable to Linux", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      vendor: "PHP Group",
      version: "8.3.35",
      operatingSystem: "Linux",
      buildType: "Standard PHP build",
    },
    {
      ...advisory,
      vendor: "PHP Group",
      affectedOperatingSystems: "Windows",
      buildRestrictions: "Windows builds only",
    }
  );
  assert.equal(result.assessment, "NOT_APPLICABLE");
  assert.match(result.reason, /restricted to Windows/i);
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

test("Windows-only advisory with a verified fixed Windows version is fixed", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      version: "8.3.36",
      operatingSystem: "Windows",
      buildType: "Windows build",
    },
    {
      ...advisory,
      affectedOperatingSystems: "Windows",
      buildRestrictions: "Windows builds only",
    }
  );

  assert.equal(result.assessment, "FIXED_FOR_THIS_CVE");
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

test("supports arbitrary operating system and build labels", () => {
  assert.deepEqual(normalizePlatformFields({
    operatingSystem: "FreeBSD 14",
    buildType: "Hardened vendor build",
  }), {
    operatingSystem: "FreeBSD 14",
    buildType: "Hardened vendor build",
  });
});

test("matches distribution operating systems to their operating-system family", () => {
  const result = assessAdvisory(
    {
      product: "OpenSSL",
      version: "3.0.2",
      operatingSystem: "Ubuntu 22.04",
    },
    {
      product: "OpenSSL",
      cveId: "CVE-2026-12346",
      affectedVersions: "< 3.0.3",
      fixedVersion: "3.0.3",
      affectedOperatingSystems: "Linux",
      sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-12346",
    }
  );
  assert.equal(result.assessment, "POTENTIALLY_AFFECTED");
});

test("does not compare ambiguous prerelease or distribution versions", () => {
  assert.equal(compareVersions("1.2.3-rc.1", "1.2.3"), null);
  assert.equal(compareVersions("1:1.2.3-1ubuntu1", "1.2.3"), null);
});

test("unverified inventory vendor requires review instead of matching a PHP advisory", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      vendor: "Example Corp",
      version: "8.3.35",
    },
    advisory
  );
  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /not a recognized vendor for PHP/i);
});

test("explicitly unknown vendor requires review", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      vendor: "Unknown",
      version: "8.3.35",
    },
    advisory
  );
  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /vendor .* explicitly unknown/i);
});

test("known vendor aliases are accepted for recognized products", () => {
  const result = assessAdvisory(
    {
      product: "PHP",
      vendor: "The PHP Group",
      version: "8.3.35",
    },
    {
      ...advisory,
      vendor: "PHP Group",
    }
  );
  assert.equal(result.assessment, "POTENTIALLY_AFFECTED");
});

test("unmapped software and vendor identities require review", () => {
  const result = assessAdvisory(
    {
      product: "Unlisted Product",
      vendor: "Unverified Vendor",
      version: "1.2.3",
    },
    {
      product: "Unlisted Product",
      vendor: "Unverified Vendor",
      cveId: "CVE-2026-12345",
      affectedVersions: "< 1.2.4",
      fixedVersion: "1.2.4",
      sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
    }
  );
  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /cannot be verified/i);
});

for (const [product, version] of [
  ["Node.js", "22.14.0"],
  ["Python", "3.13.2"],
  ["Apache HTTP Server", "2.4.62"],
  ["MySQL", "8.4.4"],
  ["OpenSSL", "3.4.1"],
]) {
  test(`assesses version evidence for ${product}`, () => {
    const result = assessAdvisory(
      { product, version },
      {
        product,
        cveId: "CVE-2026-12345",
        affectedVersions: `< ${version.split(".").slice(0, 3).join(".")}.1`,
        fixedVersion: `${version.split(".").slice(0, 3).join(".")}.1`,
        sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
      }
    );
    assert.equal(result.assessment, "POTENTIALLY_AFFECTED");
  });
}

test("evaluates bounded and exclusive affected version ranges", () => {
  assert.equal(versionMatchesAffectedRange("1.8.2", ">= 1.0.0, < 2.0.0"), true);
  assert.equal(versionMatchesAffectedRange("2.0.0", ">= 1.0.0, < 2.0.0"), false);
  assert.equal(versionMatchesAffectedRange("3.4.1", "< 3.4.2"), true);
  assert.equal(versionMatchesAffectedRange("3.4.2", "< 3.4.2"), false);
  assert.equal(
    versionMatchesAffectedRange(
      "1.2.2",
      "Introduced: 1.2.0\nFixed: 1.2.3"
    ),
    true
  );
  assert.equal(
    versionMatchesAffectedRange(
      "1.2.3",
      "Introduced: 1.2.0\nFixed: 1.2.3"
    ),
    false
  );
  assert.equal(versionMatchesAffectedRange("unknown", "< 3.4.2"), null);
});

test("requires source evidence before assessing a version", () => {
  const result = assessAdvisory(
    { product: "Python", version: "3.13.2" },
    {
      product: "Python",
      cveId: "CVE-2026-12345",
      affectedVersions: "< 3.13.3",
      fixedVersion: "3.13.3",
    }
  );
  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /direct HTTPS evidence source/i);
});

test("package-managed builds need distribution evidence for backport status", () => {
  const result = assessAdvisory(
    {
      product: "OpenSSL",
      version: "3.0.2",
      packageManager: "apt",
      operatingSystem: "Ubuntu 22.04",
    },
    {
      product: "OpenSSL",
      cveId: "CVE-2026-12345",
      affectedVersions: "< 3.0.3",
      fixedVersion: "3.0.3",
      sourceUrl: "https://openssl.org/news/secadv/2026.txt",
      sourceVerified: true,
    }
  );
  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /distribution security evidence/i);
});

test("configuration-specific advisories are not asserted without matching inventory evidence", () => {
  const result = assessAdvisory(
    { product: "Node.js", version: "22.14.0", installedConfiguration: "debug=true" },
    {
      product: "Node.js",
      cveId: "CVE-2026-12347",
      affectedVersions: "< 22.14.1",
      fixedVersion: "22.14.1",
      requiredConfigurationConditions:
        "The vulnerability occurs when the inspector configuration is enabled.",
      sourceUrl: "https://nodejs.org/en/blog/vulnerability/test",
    }
  );
  assert.equal(result.assessment, "NEEDS_REVIEW");
  assert.match(result.reason, /configuration does not provide enough evidence/i);
});
