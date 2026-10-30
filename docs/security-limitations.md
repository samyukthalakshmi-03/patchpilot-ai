# Security limitations

PatchPilot AI is a research and remediation aid, not a vulnerability scanner,
exploitability oracle, or complete asset-management system. Findings require
human verification against vendor documentation and installed package
provenance.

## Coverage and research

- The current research and assessment workflow is PHP-focused. Do not infer
  support for arbitrary products, PHP vulnerabilities, or CVE databases.
- Results depend on TinyFish Search/Fetch, API availability, source content,
  source selection, and parser behavior. A successful scan can omit an
  advisory.
- The result is a time-specific snapshot. It is not continuously monitored.
- Official-source filtering narrows evidence but does not prove that every
  source field was parsed correctly or that the source is complete.
- Advisory severity is normalized from source text; missing or ambiguous
  severity remains `UNKNOWN`. Do not infer a CVSS vector where none was
  verified.

## Version, build, and platform judgments

- Comparison is based on version strings and fixed thresholds on a matching
  PHP major/minor branch. It does not query the installed binary or package
  manager.
- A distribution may backport a patch while retaining an older upstream
  version. The current tool cannot establish that backport without explicit
  vendor evidence.
- Custom/vendor builds require review; the tool cannot prove their source,
  patch set, or build options.
- Windows availability does not make an advisory Windows-specific. CVE
  records for CVE-2026-109618 and CVE-2026-109619 list PHP source-version
  ranges without an OS qualifier. Their advisory text describes SAPI and
  configuration conditions that require separate interpretation.
- Windows architecture, thread-safety, compiler/runtime, SAPI, and package
  provenance may affect applicability. Unknown or unrepresented variants must
  remain under review.
- Configuration and exposure conditions are extracted from text and are not
  checked against the live PHP runtime.

## Meaning of statuses

- `POTENTIALLY_AFFECTED` is a version/evidence triage signal, not proof of
  exploitability.
- `FIXED_FOR_THIS_CVE` and `FIXED_FOR_KNOWN_CVES` apply only to discovered,
  assessed advisory records. They do not mean the product has no other
  vulnerabilities.
- `NOT_APPLICABLE` requires explicit platform evidence for that advisory.
- `NEEDS_REVIEW`, `RESEARCH_REVIEW`, and `NO_VERIFIED_MATCH` indicate
  uncertainty or missing coverage; none should be interpreted as safe.

## Application and operational security

- The prototype has no authentication, authorization, tenant isolation,
  persistent inventory storage, audit log, or report access control.
- The health endpoint exposes whether a TinyFish key is configured. It does
  not verify the key or provider reachability.
- The frontend's connected badge is presentation text, not a live health
  indicator.
- The backend key must remain server-side in an ignored environment file or
  deployment secret store. Never add keys to `VITE_*` variables, source
  control, logs, screenshots, or sample JSON.
- Exported JSON contains asset inventory and research details; handle it as
  potentially sensitive operational data.
- CORS is permissive in the current prototype. Do not expose the API publicly
  without adding deployment-appropriate access controls, request protections,
  and monitoring.
- A report must not be used as the sole basis for patching, risk acceptance,
  incident response, or compliance claims.

## Out of scope

The application does not execute exploits, inspect hosts, verify installed
packages, perform authenticated scanning, assess code, guarantee remediation,
or replace PHP/vendor security advisories. Human review and vendor-specific
validation remain necessary.
