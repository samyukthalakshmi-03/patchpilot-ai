# API contract

The Express service defaults to `http://localhost:5000`. JSON requests are
limited to 100 KB.

## `GET /api/health`

Returns an unauthenticated service health/configuration response:

```json
{
  "ok": true,
  "service": "PatchPilot AI",
  "tinyfishKeyConfigured": false
}
```

`tinyfishKeyConfigured` is a boolean configuration hint. It does not test
credentials, network reachability, quota, or the TinyFish service.

## `POST /api/scan`

### Request

`assets` must contain between 1 and 20 objects. Every object needs non-empty
`name`, `product`, and `version` fields. The server trims and length-limits
those strings; `name` and `product` are limited to 100 characters and `version`
to 50 characters.

Supported `operatingSystem` values are `Unknown`, `Windows`, `Linux`, `macOS`,
and `Other`. Supported `buildType` values are `Unknown`, `Standard PHP build`,
`Windows build`, and `Custom/vendor build`. Omitted platform fields default to
`Unknown`.

```json
{
  "assets": [
    {
      "name": "Web Server A",
      "product": "PHP",
      "version": "8.3.35",
      "operatingSystem": "Unknown",
      "buildType": "Unknown"
    }
  ]
}
```

### Success response

The current response shape is:

```json
{
  "ok": true,
  "scanId": "PP-<timestamp>",
  "scannedAt": "<ISO-8601 timestamp>",
  "assetsScanned": 1,
  "advisoriesFound": 1,
  "findings": [
    {
      "asset": {
        "name": "Web Server A",
        "product": "PHP",
        "version": "8.3.35",
        "operatingSystem": "Unknown",
        "buildType": "Unknown"
      },
      "status": "POTENTIALLY_AFFECTED",
      "message": "<summary>",
      "advisories": [
        {
          "product": "PHP",
          "title": "<source advisory title>",
          "cveId": "CVE-YYYY-NNNN",
          "severity": "CRITICAL",
          "advisoryType": "SECURITY_VULNERABILITY",
          "affectedVersions": "<source text>",
          "fixedVersion": "<source version or UNKNOWN>",
          "affectedOperatingSystems": "UNKNOWN",
          "buildRestrictions": "UNKNOWN",
          "requiredConfigurationConditions": "UNKNOWN",
          "remediation": "<source-derived remediation>",
          "sourceName": "<source host>",
          "sourceUrl": "https://<official source>",
          "assessment": "POTENTIALLY_AFFECTED",
          "reason": "<assessment explanation>",
          "cveIds": ["CVE-YYYY-NNNN"]
        }
      ],
      "researchNotes": []
    }
  ],
  "researchNotes": [],
  "disclaimer": "<triage disclaimer>"
}
```

The arrays may be empty and advisory fields may contain `UNKNOWN` where the
research source did not provide verifiable information. `sourceUrl` is blank
when it does not pass the backend's HTTPS/official-source checks. A successful
response can report `NO_VERIFIED_MATCH` or `RESEARCH_REVIEW`; neither means
that the asset is secure.

### Errors and statuses

| HTTP status | Condition | Response behavior |
|---|---|---|
| 400 | Missing, empty, oversized-count, or invalid asset inventory | JSON `{ "error": "..." }`. Malformed JSON is rejected by Express's JSON parser with HTTP 400; its current default response is HTML, not this JSON envelope. |
| 500 | `TINYFISH_API_KEY` is not configured | JSON error stating that the key is missing. This check occurs before inventory validation. |
| 502 | TinyFish provider error or malformed research output | JSON error with a provider/research message and error code when available. |
| 504 | TinyFish request or overall research timeout | JSON error with timeout code when available. |
| 500 | Unexpected internal error | Generic JSON error; internal error details are logged server-side. |

The server does not promise a stable set/order of dynamically discovered
advisories. Callers must inspect assessment values, evidence, and notes rather
than infer that every known CVE was found.

## Browser report export

The frontend serializes the successful scan response with `JSON.stringify`,
sets Blob MIME type to `application/json`, and uses `<scanId>.json` as the
suggested download filename. Export is a browser operation; the backend has no
report-download endpoint or persistent report store.
