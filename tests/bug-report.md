# PatchPilot test bug report

**Last reviewed:** 2026-10-30
**Branch:** `feature/testing-documentation`
**Scope:** Current `feature/testing-documentation` backend behavior. Production
code is unchanged by this report.

## Open bugs

### PP-TEST-001 — Unknown PHP version fails scan instead of returning review status

- **Status:** Open
- **Severity:** Medium
- **Test:** `API-UNKNOWN-PHP-VERSION`
- **Reproduction:** Start the backend with `TINYFISH_API_KEY` configured and
  submit `POST /api/scan` with:

  ```json
  {
    "assets": [
      {
        "name": "Unknown PHP",
        "product": "PHP",
        "version": "unknown"
      }
    ]
  }
  ```

- **Expected:** Return a documented validation response or a report with
  `NEEDS_REVIEW` for the asset. Do not treat unknown version data as proof of
  an upstream research-service failure.
- **Actual:** HTTP 502 with error code `PHP_VERSION_BRANCH_MISSING` and message
  `No PHP release branches could be identified in the inventory.`
- **Impact:** Inventory containing an unknown or malformed PHP version cannot
  receive an assessment result through the scan endpoint, despite the
  assessment helper's intended conservative `NEEDS_REVIEW` behavior.
- **Evidence:** Observed by executing the local scan endpoint with a
  non-secret placeholder API key. See `API-UNKNOWN-VERSION` in
  [verification-notes.md](verification-notes.md).
- **Suggested follow-up:** Validate parseable version branches before
  starting TinyFish research and return a clear client-side/API validation
  result or a per-asset `NEEDS_REVIEW` report. Any implementation change
  requires its own regression test.

## Closed / no bug

The following exercised behaviors matched their expected outcomes:

- `GET /api/health` returned HTTP 200 and a boolean
  `tinyfishKeyConfigured`.
- `/api/scan` returned HTTP 400 for empty or missing inventory, required
  fields, and unsupported operating-system values.
- A stubbed TinyFish HTTP 503 mapped to HTTP 502
  (`TINYFISH_HTTP_ERROR`); a stubbed timeout mapped to HTTP 504
  (`TINYFISH_REQUEST_TIMEOUT`); malformed provider JSON mapped to HTTP 502
  (`TINYFISH_INVALID_RESPONSE`).
- A synthetic Windows-only advisory produced `POTENTIALLY_AFFECTED` for a
  matching Windows build, `NOT_APPLICABLE` for Linux, and `NEEDS_REVIEW` for an
  Unknown platform.

These are local tests using synthetic/stubbed provider data, not evidence of a
live TinyFish service scan or a real Windows-only condition for either
published PHP CVE.
