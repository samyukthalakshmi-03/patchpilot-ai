# Three-minute demo script

**Before the demo:** start the backend and frontend with a valid local TinyFish
key, verify `/api/health`, and confirm access to TinyFish. Never show or copy
the key. If a live scan is unavailable, state that clearly and use a
pre-generated report fixture only when identified as a fixture.

## 0:00–0:25 — Problem

“Teams need to know whether installed software versions fall inside a vendor's
affected range. Searching manually is slow, but a version number alone is not
enough: package backports, Windows builds, runtime configuration, and source
quality can change the conclusion. PatchPilot is a research triage aid, not an
exploit scanner or a guarantee of security.”

## 0:25–0:50 — Add PHP assets

Show the inventory fields. Point out Web Server A running PHP 8.3.35 and Web
Server B running PHP 8.3.36. Explain that OS and build fields should be filled
from inventory evidence; do not infer them from the upstream version. Keep
unknown values unknown rather than guessing.

## 0:50–1:20 — Start the TinyFish investigation

Select **Run live investigation**. Explain that the backend sends PHP advisory
searches through TinyFish, fetches a bounded set of allowed official PHP and
PHP-source advisory pages, and parses the returned evidence. If it errors,
show the explicit error and do not claim a scan succeeded.

## 1:20–1:55 — Show the two CVEs and compare versions

When returned by the live research, open the findings for
CVE-2026-109618 and CVE-2026-109619. The official records list PHP 8.3 versions
before 8.3.36 as affected and 8.3.36 as the fixed threshold on that branch.
Compare Web Server A (8.3.35) as potentially affected with Web Server B
(8.3.36) as meeting the threshold for those assessed CVEs. Emphasize that the
fixed label applies only to known advisories in this report and is not an
overall “secure” result.

## 1:55–2:20 — Open official evidence

Open the **Read source evidence** link and point to the source advisory's
affected/patched versions and mitigation. Show that evidence is reviewable
outside PatchPilot. Distinguish the general PHP release range from any
Windows-specific build or SAPI condition; verify the exact binary/vendor
package separately.

## 2:20–2:40 — Export

Select **Export JSON**. Note that the browser downloads the current report
response for sharing or further analysis. Treat the file as sensitive because
it can contain internal software inventory.

## 2:40–3:00 — Limitations and future work

“The current implementation is PHP-focused, depends on live TinyFish
research, and cannot confirm package backports, all Windows variants, runtime
configuration, or exploitability. Next steps are deterministic end-to-end
tests, richer package and platform evidence, scan history/access controls, and
additional products only after product-specific authoritative sources and
tests are in place.”

## Why TinyFish matters

TinyFish provides the live Search and Fetch boundary that lets PatchPilot
retrieve current official advisory pages instead of relying only on a
hard-coded sample. PatchPilot then normalizes selected source content and
compares it with the supplied inventory. TinyFish is important for freshness
and evidence retrieval, but it does not guarantee completeness, correct
interpretation, or that a source claim applies to a particular installed
binary.
