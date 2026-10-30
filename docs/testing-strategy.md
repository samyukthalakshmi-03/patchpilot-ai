# Testing strategy

PatchPilot testing separates deterministic assessment behavior, provider
integration behavior, HTTP/API behavior, source verification, and frontend
report behavior. A passing local unit test is not a live scan result.

## Test layers

1. **Assessment and parsing unit tests** — run with `cd server; npm test`.
   Cover version parsing/comparison, fixed thresholds, invalid versions,
   Windows-specific conditions, platform normalization, source filtering,
   advisory extraction, timeouts, provider failures, and credential redaction.
2. **Local API smoke tests** — run the Express server without a TinyFish key to
   verify health and explicit configuration failure. For validation-only
   requests, a non-secret local placeholder key can be set; empty/invalid
   inventories return before any provider request is made.
3. **Live scan tests** — require an authorized TinyFish key, network access,
   and current official sources. They are intentionally not reported as passed
   in this test run because no API key was provided.
4. **Frontend build and export checks** — `cd client; npm run build` verifies
   bundling. UI export serialization can be checked with a mocked scan
   response; this verifies the UI's JSON Blob but not live research or
   persistent download behavior.
5. **Official-source verification** — verify the CVE record, source advisory,
   PHP fixed release, and exact product/platform scope independently before
   using any assessment as operational guidance.

## Dataset and future behavior

The machine-readable scenarios are in
[test-cases.json](../tests/test-cases.json), with expected outcomes in
[expected-results.json](../tests/expected-results.json). Each dataset case
identifies whether it is covered by the current implementation or is a
proposed regression/edge-case test.

Current code is PHP-oriented and dynamically discovers advisories; it does not
hard-code CVE-2026-109618 or CVE-2026-109619. Version threshold tests feed
verified advisory fixtures to the assessment helper. They do not prove that a
live TinyFish run always finds both records, that the records apply to a
particular binary, or that every available PHP vulnerability is covered.

## Results policy

Use the following labels in execution records:

- **PASS** — the exact test was executed and met its stated expectation.
- **FAIL** — the exact test was executed and did not meet its expectation.
- **BLOCKED** — required external credentials/services were unavailable or
  the test could not be run without using an unprovided secret.
- **PROPOSED** — a desired behavior/regression test has not been executed.

Do not convert blocked live tests into passes based on mocks. Keep actual
responses, stubbed tests, and source verification clearly distinguished.
Execution results for 2026-10-30 are recorded in
[verification-notes.md](../tests/verification-notes.md).

## Suggested CI sequence

```powershell
cd server
npm ci
npm test
cd ..\client
npm ci
npm run build
```

No additional dependencies are required for the current automated test suite.
Live provider tests should be opt-in and must never print or commit API keys.
