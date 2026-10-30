# Test execution and source verification notes

**Verification date:** 2026-10-30
**Branch tested:** `feature/testing-documentation`
**Scope:** Committed application code in this branch; local tests and local
HTTP/UI checks. No external TinyFish API request was made.

## Official security information

The CVE records were retrieved from CVE.org's CVE Services record API and
compared with the PHP-source GitHub Security Advisories and PHP's official
8.3.36 release announcement. The details below are the record state on the
verification date; check the linked sources again before operational use.

| CVE ID | Product | Affected versions | Fixed versions | Severity | Platform restrictions | Remediation |
|---|---|---|---|---|---|---|
| CVE-2026-109618 | PHP (`php-src`) | 8.2.* before 8.2.35; 8.3.* before 8.3.36; 8.4.* before 8.4.27; 8.5.* before 8.5.12 | PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12, respectively | CRITICAL, CVSS 4.0 score 9.2 | CVE affected-version entries have no OS qualifier; this is not recorded as Windows-only. The GitHub advisory confirms exploitation against Apache mod_php and discusses FPM/SAPI-specific susceptibility. A specific Windows package/build/backport is not independently established by the general source-version range. | Upgrade to the fixed release on the maintained PHP branch. The PHP advisory says updating to a release containing the patch is the only complete mitigation. |
| CVE-2026-109619 | PHP (`php-src`) | 8.2.* before 8.2.35; 8.3.* before 8.3.36; 8.4.* before 8.4.27; 8.5.* before 8.5.12 | PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12, respectively | CRITICAL, CVSS 4.0 score 9.2 | CVE affected-version entries have no OS qualifier; this is not recorded as Windows-only. The GitHub advisory discusses SAPI, request lifecycle, and configuration-dependent conditions. A specific Windows package/build/backport is not independently established by the general source-version range. | Upgrade to the fixed release on the maintained PHP branch and follow the related advisory's mitigation guidance. Do not infer platform or SAPI applicability from the version string alone. |

### Sources

- CVE-2026-109618 record: [CVE.org record](https://www.cve.org/CVERecord?id=CVE-2026-109618) · [CVE Services JSON](https://cveawg.mitre.org/api/cve/CVE-2026-109618)
- CVE-2026-109618 PHP-source advisory: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- CVE-2026-109619 record: [CVE.org record](https://www.cve.org/CVERecord?id=CVE-2026-109619) · [CVE Services JSON](https://cveawg.mitre.org/api/cve/CVE-2026-109619)
- CVE-2026-109619 PHP-source advisory: [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- PHP 8.3.36 security release: [PHP 8.3.36 release announcement](https://www.php.net/releases/8_3_36.php)
- PHP branch changelog: [PHP ChangeLog-8.php](https://www.php.net/ChangeLog-8.php)

The CVE records are the source for product, affected ranges, severity, and
fixed release thresholds. The GitHub advisories provide vendor context and
mitigation details. The release page establishes that 8.3.36 is an official
PHP security release. The PHP changelog also distinguishes general core
security fixes from explicitly Windows-only defects; do not label a general
PHP advisory Windows-only merely because Windows binaries are available.

No separate, Windows-only affected range for these two CVEs was found in the
publisher's CVE affected-version entries. Applicability to a particular
Windows binary, thread-safety/build variant, packaged distribution, or
backported vendor build remains **UNVERIFIED** unless the relevant vendor
confirms it. The advisories' SAPI/configuration detail is not interchangeable
with a Windows-only restriction.

## Test execution report

Statuses describe what actually ran. `BLOCKED` means the intended behavior
could not be exercised safely or because a required external credential was
unavailable; it is not a pass.

| Test ID | Input | Expected output | Actual output | Status | Notes |
|---|---|---|---|---|---|
| APP-UNIT | `cd server; npm test` | Existing backend unit suite passes | 32 passed, 0 failed | PASS | Includes generic 8.3.35/8.3.36 threshold, Windows applicability, TinyFish timeout/failure, and source extraction tests. Unit fixtures are not a live scan of the two published CVEs. |
| APP-BUILD | `cd client; npm run build` | Vite production build succeeds | Vite build succeeded; 17 modules transformed | PASS | No UI changes made. |
| API-HEALTH | `GET /api/health` on local port 5001 | JSON health response | HTTP 200: `{"ok":true,"service":"PatchPilot AI","tinyfishKeyConfigured":false}` | PASS | Health endpoint does not test TinyFish reachability. |
| API-VALID-SCAN | One PHP 8.3.35 asset, no API key configured | A research report with findings if TinyFish is available | HTTP 500: `{"error":"TINYFISH_API_KEY is missing from server/.env"}` | BLOCKED | No valid live scan could run without the user's TinyFish credential. No real API key was read or used. |
| API-MULTIPLE-ASSETS | PHP 8.3.35 and 8.3.36, no API key configured | One finding per asset after research | HTTP 500 with missing-key error | BLOCKED | Same configuration gate prevented research; no result is claimed for a live multi-asset scan. |
| API-EMPTY-INVENTORY | `POST /api/scan` with `{"assets":[]}` and a local non-secret placeholder key | HTTP 400 inventory error | HTTP 400: `Provide between 1 and 20 inventory assets.` | PASS | Request rejected before any TinyFish call. Without a configured key, the earlier key check returns HTTP 500 first. |
| API-MISSING-INVENTORY | `POST /api/scan` with `{}` and a local non-secret placeholder key | HTTP 400 inventory error | HTTP 400: `Provide between 1 and 20 inventory assets.` | PASS | Request rejected before any TinyFish call. |
| API-MISSING-FIELDS | One asset without `version`, using a local non-secret placeholder key | HTTP 400 required-fields error | HTTP 400: `Every asset needs a name, product and version.` | PASS | Request rejected before any TinyFish call. |
| API-MALFORMED-JSON | Request body `not-json` | HTTP 400; malformed body rejected | HTTP 400 HTML error response from Express JSON parsing, containing parser details | PASS | Rejection status is correct; response is not the API's normal JSON error envelope. |
| API-UNKNOWN-VERSION | `POST /api/scan` with PHP version `unknown` and a local non-secret placeholder key | Proposed future behavior: `NEEDS_REVIEW` rather than an upstream research failure | HTTP 502: `PHP_VERSION_BRANCH_MISSING` | FAIL | Observed behavior gap: the code fails before assessment when no version branch can be parsed. Production logic was not changed. |
| ASSESS-8334 | Assessment helper; PHP 8.3.34 with verified-range fixture `< 8.3.36` | `POTENTIALLY_AFFECTED` | `POTENTIALLY_AFFECTED` | PASS | Direct local helper probe; not a full scan. |
| ASSESS-8335 | Assessment helper; PHP 8.3.35 against separate source-backed fixtures for CVE-2026-109618 and CVE-2026-109619 | `POTENTIALLY_AFFECTED` for each ID | Both fixtures returned `POTENTIALLY_AFFECTED`, each with its own CVE ID | PASS | Direct local helper probes; not proof that TinyFish will return these advisories. |
| ASSESS-8336 | Assessment helper; PHP 8.3.36 against both separate fixtures | `FIXED_FOR_THIS_CVE` for each ID | Both fixtures returned `FIXED_FOR_THIS_CVE` | PASS | Limited to these official advisory fixtures. |
| ASSESS-8337 | Assessment helper; PHP 8.3.37 against both separate fixtures | `FIXED_FOR_THIS_CVE` for each ID | Both fixtures returned `FIXED_FOR_THIS_CVE` | PASS | Does not establish absence of other vulnerabilities. |
| ASSESS-UNKNOWN | Assessment helper with version `unknown` | `NEEDS_REVIEW` | `NEEDS_REVIEW`: installed/fixed version could not be parsed | PASS | Direct helper probe; generic parser tests also ran in `APP-UNIT`. |
| ASSESS-WINDOWS | Existing Windows platform unit cases plus unknown OS with a Windows-only synthetic advisory | Unknown OS/build yields `NEEDS_REVIEW`; verified Linux is `NOT_APPLICABLE` only for an explicitly Windows-only advisory | Existing unit cases passed; direct probe returned `NEEDS_REVIEW` | PASS | Synthetic Windows restriction is not a claim about CVE-2026-109618 or CVE-2026-109619. |
| ASSESS-NO-FIX | Assessment helper with `fixedVersion: "UNKNOWN"` | `NEEDS_REVIEW` | `NEEDS_REVIEW`: no verified fixed version | PASS | Direct local helper probe. |
| ASSESS-NO-SOURCE | Assessment helper with an empty source URL | `NEEDS_REVIEW` | `NEEDS_REVIEW`: valid HTTPS evidence source required | PASS | Direct local helper probe. |
| RESEARCH-MULTIPLE-CVES | Synthetic PHP-source advisory fixture with CVE-2026-109618 and CVE-2026-109619 on separate lines | Two unique advisories retaining both IDs | Two normalized entries returned with both IDs and fixed version 8.3.36 | PASS | Dependency-injected local parser test; synthetic content is not a claim that either official source combines the CVEs. |
| TF-MALFORMED-JSON | TinyFish module with a local stub returning `not-json` | Explicit invalid-response error | `TinyFishResearchError`, code `TINYFISH_INVALID_RESPONSE` | PASS | Dependency-injected local test; no external API request. |
| TF-FAILURE-TIMEOUT | Existing dependency-injected TinyFish suite | Explicit provider HTTP/timeout errors; no credential disclosure | Covered by existing passing HTTP-error, timeout, and redaction tests | PASS | Simulated provider responses, not an actual TinyFish outage. |
| UI-JSON-EXPORT | Browser UI with a mocked successful report; click **Export JSON** | JSON Blob, JSON MIME type, `<scanId>.json` name | Captured `application/json`, `PP-TEST-EXPORT.json`, and parseable report JSON | PASS | UI export serialization and suggested filename were verified. The report was a fixture; actual file persistence/download behavior was not verified. |

### Interpretation and unverified checks

- A live valid scan and live multi-asset scan are **BLOCKED** because no TinyFish
  credential was supplied. The local placeholder key was used only for
  validation requests that return before making a provider request.
- The app's research results are dynamic. The assessment helper was tested with
  the two official CVE IDs and official fixed threshold, but that is not an
  end-to-end confirmation that a live search run returns both CVEs every time.
- No production backend logic or frontend component was changed for this
  documentation/test task.
- Re-run live scans using an authorized TinyFish account and independently
  verify every source before using results operationally.
