
import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 5000;
const TINYFISH_URL = "https://agent.tinyfish.ai/v1/automation/run";

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "PatchPilot AI",
    tinyfishKeyConfigured: Boolean(process.env.TINYFISH_API_KEY),
  });
});

async function researchWithTinyFish(goal) {
  const response = await fetch(TINYFISH_URL, {
    method: "POST",
    headers: {
      "X-API-Key": process.env.TINYFISH_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      url: "https://www.php.net/",
      goal,
    }),
signal: AbortSignal.timeout(300000),
  });

  const text = await response.text();

  if (!response.ok) {
    console.error("TinyFish HTTP error:", response.status, text.slice(0, 1000));
    throw new Error(`TinyFish returned HTTP ${response.status}`);
  }

  const apiData = JSON.parse(text);

  if (apiData.status && apiData.status !== "COMPLETED") {
    throw new Error(`TinyFish run status: ${apiData.status}`);
  }

  let result = apiData.result ?? apiData;

  // Some runs return the extracted data as a JSON string.
  if (typeof result === "string") {
    result = JSON.parse(
      result.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "")
    );
  }

  return result;
}

app.post("/api/scan", async (req, res) => {
  try {
    if (!process.env.TINYFISH_API_KEY) {
      return res.status(500).json({
        error: "TINYFISH_API_KEY is missing from server/.env",
      });
    }

    const { assets } = req.body || {};

    if (!Array.isArray(assets) || assets.length < 1 || assets.length > 20) {
      return res.status(400).json({
        error: "Provide between 1 and 20 inventory assets.",
      });
    }

    const inventory = assets.map((asset) => ({
      name: String(asset.name || "").trim().slice(0, 100),
      product: String(asset.product || "").trim().slice(0, 100),
      version: String(asset.version || "").trim().slice(0, 50),
    }));

    if (inventory.some((a) => !a.name || !a.product || !a.version)) {
      return res.status(400).json({
        error: "Every asset needs a name, product and version.",
      });
    }

 
const goal = `
Research official PHP security release information for this inventory:
${inventory.map((a) => `${a.name}: ${a.product} ${a.version}`).join("\n")}

Visit https://www.php.net/archive/2026.php and inspect the official PHP release
information. Identify up to three relevant security advisories, if any are listed.
Return JSON only in this format:
{
  "advisories": [
    {
      "product": "PHP",
      "title": "exact title from the source",
      "cve_id": "",
      "severity": "UNKNOWN",
      "affected_versions": "UNKNOWN unless explicitly stated",
      "fixed_version": "",
      "remediation": "recommendation supported by the source",
      "source_name": "PHP",
      "source_url": "direct official HTTPS URL"
    }
  ],
  "research_notes": ["limitations"]
}

Do not invent CVE IDs, severity, affected ranges, or fixed versions.
Only report facts visible on pages you actually inspect.
Use an empty advisories array if no relevant advisory is verified.
Return valid JSON without Markdown fences.
`;


    const rawResult = await researchWithTinyFish(goal);

    // Unwrap common nested response structures.
    let data = rawResult;
    if (data && typeof data === "object" && data.result !== undefined) {
      data = data.result;
    }
    if (typeof data === "string") {
      data = JSON.parse(
        data.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "")
      );
    }

    if (!data || !Array.isArray(data.advisories)) {
      console.error("Unexpected TinyFish result:", JSON.stringify(rawResult).slice(0, 1500));
      return res.status(502).json({
        error: "TinyFish completed, but the research output was not in the expected format. Please retry.",
      });
    }

    const advisories = data.advisories
      .filter((a) => a && typeof a === "object")
      .map((a) => ({
        product: String(a.product || "Unknown"),
        title: String(a.title || "Security advisory"),
        cveId: String(a.cve_id || ""),
        severity: String(a.severity || "UNKNOWN").toUpperCase(),
        affectedVersions: String(a.affected_versions || "UNKNOWN"),
        fixedVersion: String(a.fixed_version || ""),
        remediation: String(a.remediation || "Review the official advisory."),
        sourceName: String(a.source_name || ""),
        sourceUrl: /^https:\/\//i.test(a.source_url || "")
          ? a.source_url
          : "",
      }));
      const phpFixedVersions = {
  "8.2": "8.2.35",
  "8.3": "8.3.36",
  "8.4": "8.4.27",
  "8.5": "8.5.12",
};

const criticalPhpCves = new Set([
  "CVE-2026-109618",
  "CVE-2026-109619",
]);

function compareVersions(a, b) {
  const left = String(a).match(/\d+/g)?.map(Number);
  const right = String(b).match(/\d+/g)?.map(Number);

  if (!left || !right) return null;

  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const x = left[i] ?? 0;
    const y = right[i] ?? 0;

    if (x < y) return -1;
    if (x > y) return 1;
  }

  return 0;
}

function getCveId(advisory) {
  return String(
    advisory.cveId || advisory.cve_id || ""
  ).toUpperCase().trim();
}

function assessAdvisory(asset, advisory) {
  const combinedText = [
    advisory.cveId,
    advisory.cve_id,
    advisory.title,
  ]
    .filter(Boolean)
    .join(" ")
    .toUpperCase();

  const cveIds = [
    ...new Set(
      combinedText.match(/CVE-\d{4}-\d+/g) || []
    ),
  ];

  const version = String(asset.version || "").trim();
  const branch = version.match(/^\d+\.\d+/)?.[0];

  const isPhp = String(asset.product || "")
    .toLowerCase()
    .includes("php");
    const title = String(advisory.title || "").toLowerCase();

const isCriticalRceAdvisory =
  title.includes("critical") ||
  title.includes("remote code execution") ||
  title.includes("rce");

if (!isCriticalRceAdvisory) {
  return "NEEDS_REVIEW";
}

  const onlyKnownCriticalCves =
    cveIds.length > 0 &&
    cveIds.every((id) => criticalPhpCves.has(id));

  if (
    isPhp &&
    onlyKnownCriticalCves &&
    branch &&
    phpFixedVersions[branch]
  ) {
    const fixedVersion = phpFixedVersions[branch];
    const comparison = compareVersions(version, fixedVersion);

    if (comparison === null) {
      return "NEEDS_REVIEW";
    }

    return comparison < 0
      ? "POTENTIALLY_AFFECTED"
      : "FIXED_FOR_THIS_CVE";
  }

  return "NEEDS_REVIEW";
}

    
const hasResearchNotes =
  Array.isArray(data.research_notes) &&
  data.research_notes.length > 0;

const findings = inventory.map((asset) => {
  const assetProduct = String(asset.product || "")
    .toLowerCase()
    .trim();

  const relevant = advisories.filter((advisory) => {
    const advisoryProduct = String(advisory.product || "")
      .toLowerCase()
      .trim();

    return (
      advisoryProduct &&
      assetProduct &&
      (
        advisoryProduct.includes(assetProduct) ||
        assetProduct.includes(advisoryProduct)
      )
    );
  });

  const assessedAdvisories = relevant.map((advisory) => ({
    ...advisory,
    assessment: assessAdvisory(asset, advisory),
  }));

  const hasPotentiallyAffected = assessedAdvisories.some(
    (advisory) =>
      advisory.assessment === "POTENTIALLY_AFFECTED"
  );

  const hasUnverified = assessedAdvisories.some(
    (advisory) => advisory.assessment === "NEEDS_REVIEW"
  );

  const hasVerifiedFixed = assessedAdvisories.some(
    (advisory) =>
      advisory.assessment === "FIXED_FOR_THIS_CVE"
  );

  let status;
  let message;

if (hasPotentiallyAffected) {
  status = "POTENTIALLY_AFFECTED";
  message =
    "At least one identified vulnerability may affect this asset. Prioritize remediation.";
} else if (hasUnverified && hasVerifiedFixed) {
  status = "PARTIALLY_ASSESSED";
  message =
    "The asset meets the fixed-version threshold for some identified CVEs, but other advisories still need verification.";
} else if (hasUnverified) {
  status = "NEEDS_REVIEW";
  message =
    "One or more advisories need verification of affected versions, operating system, or vendor package status.";
} else if (hasVerifiedFixed) {
  status = "FIXED_FOR_KNOWN_CVES";
  message =
    "The asset meets the verified fixed-version threshold for the assessed CVEs. This does not establish that the asset is free of other vulnerabilities.";
} else if (hasResearchNotes) {
  status = "RESEARCH_REVIEW";
  message =
    "Research notes are available, but no structured advisory could be confidently assessed.";
} else {
  status = "NO_VERIFIED_MATCH";
  message =
    "No verified advisory match was returned. This does not establish that the asset is secure.";
}
  return {
    asset,
    status,
    message,
    advisories: assessedAdvisories,
    researchNotes: data.research_notes || [],
  };
});


    res.json({
      ok: true,
      scanId: `PP-${Date.now()}`,
      scannedAt: new Date().toISOString(),
      assetsScanned: inventory.length,
      advisoriesFound: advisories.length,
      findings,
      researchNotes: Array.isArray(data.research_notes)
        ? data.research_notes
        : [],
      disclaimer:
        "This is a research triage aid, not proof of exploitability. Verify vendor-specific version ranges, distribution backports and installed package provenance.",
    });
  } catch (error) {
  console.error("Scan error details:", error);
  console.error("Underlying cause:", error.cause);

  res.status(502).json({
    error: error.name === "TimeoutError"
      ? "TinyFish research timed out. Try again."
      : `Research failed: ${error.message}`,
    cause: error.cause?.message || null,
    code: error.cause?.code || null,
  });
}
});

app.listen(PORT, () => {
  console.log(`PatchPilot backend running at http://localhost:${PORT}`);
});
