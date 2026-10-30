
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { assessAdvisory } from "./utils/assessmentUtils.js";
import { normalizePlatformFields } from "./utils/inventoryUtils.js";
import {
  researchWithTinyFishFast,
  TinyFishResearchError,
} from "./utils/tinyfishResearch.js";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 5000;

// Remove Markdown code fences if TinyFish returns JSON inside them.
function parseJsonResponse(value) {
  if (typeof value !== "string") {
    return value;
  }

  const cleaned = value
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();

  return JSON.parse(cleaned);
}

// Health check
app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "PatchPilot AI",
    tinyfishKeyConfigured: Boolean(process.env.TINYFISH_API_KEY),
  });
});

// Main scan endpoint
app.post("/api/scan", async (req, res) => {
  try {
    if (!process.env.TINYFISH_API_KEY) {
      return res.status(500).json({
        error: "TINYFISH_API_KEY is missing from server/.env",
      });
    }

    const { assets } = req.body || {};

    // Validate inventory
    if (!Array.isArray(assets) || assets.length < 1 || assets.length > 20) {
      return res.status(400).json({
        error: "Provide between 1 and 20 inventory assets.",
      });
    }

    let inventory;

    try {
      inventory = assets.map((asset) => {
        if (!asset || typeof asset !== "object" || Array.isArray(asset)) {
          throw new Error("Every asset must be an object.");
        }

        return {
          name: String(asset.name || "").trim().slice(0, 100),
          product: String(asset.product || "").trim().slice(0, 100),
          version: String(asset.version || "").trim().slice(0, 50),
          ...normalizePlatformFields(asset),
        };
      });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }

    if (inventory.some((asset) => !asset.name || !asset.product || !asset.version)) {
      return res.status(400).json({
        error: "Every asset needs a name, product and version.",
      });
    }

    // Search and fetch only official PHP sources to keep scans fast and evidence-based.
    const rawResult = await researchWithTinyFishFast(inventory);

    // Unwrap common nested response structures
    let data = rawResult;

    if (
      data &&
      typeof data === "object" &&
      data.result !== undefined
    ) {
      data = data.result;
    }

    data = parseJsonResponse(data);

    if (!data || !Array.isArray(data.advisories)) {
      console.error(
        "Unexpected TinyFish result:",
        JSON.stringify(rawResult).slice(0, 1500)
      );

      return res.status(502).json({
        error:
          "TinyFish completed, but the research output was not in the expected format. Please retry.",
      });
    }

    // Normalize advisory fields
    const advisories = data.advisories
      .filter((advisory) => advisory && typeof advisory === "object")
      .map((advisory) => ({
        product: String(advisory.product || "Unknown"),
        title: String(advisory.title || "Security advisory"),
        cveId: String(advisory.cve_id || ""),
        severity: String(advisory.severity || "UNKNOWN").toUpperCase(),
        advisoryType: String(
          advisory.advisory_type || "UNKNOWN"
        ).toUpperCase(),
        affectedVersions: String(
          advisory.affected_versions || "UNKNOWN"
        ),
        fixedVersion: String(advisory.fixed_version || "UNKNOWN"),
        affectedOperatingSystems: String(
          advisory.operating_systems_affected || "UNKNOWN"
        ),
        buildRestrictions: String(
          advisory.build_restrictions || "UNKNOWN"
        ),
        requiredConfigurationConditions: String(
          advisory.required_configuration_conditions || "UNKNOWN"
        ),
        remediation: String(
          advisory.remediation || "UNKNOWN"
        ),
        sourceName: String(advisory.source_name || ""),
        sourceUrl: /^https:\/\//i.test(advisory.source_url || "")
          ? advisory.source_url
          : "",
      }));

    const hasResearchNotes =
      Array.isArray(data.research_notes) &&
      data.research_notes.length > 0;

    // Assess each inventory asset against relevant advisories
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

      // Assessment logic is now handled by assessmentUtils.js
      const assessedAdvisories = relevant.map((advisory) => {
        const result = assessAdvisory(asset, advisory);

        return {
          ...advisory,
          ...result,
        };
      });

      const hasPotentiallyAffected = assessedAdvisories.some(
        (advisory) =>
          advisory.assessment === "POTENTIALLY_AFFECTED"
      );

      const hasUnverified = assessedAdvisories.some(
        (advisory) =>
          advisory.assessment === "NEEDS_REVIEW"
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
      } else if (
        assessedAdvisories.length > 0 &&
        assessedAdvisories.every(
          (advisory) => advisory.assessment === "NOT_APPLICABLE"
        )
      ) {
        status = "NOT_APPLICABLE";
        message =
          "The verified advisories are not applicable to this asset's identified platform.";
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
        researchNotes: Array.isArray(data.research_notes)
          ? data.research_notes
          : [],
      };
    });

    // Send scan results to frontend
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
    const errorCode = error.code || error.cause?.code || null;
    const isTinyFishError = error instanceof TinyFishResearchError;
    const errorMessage = isTinyFishError
      ? error.message
      : "An unexpected error occurred while processing the scan.";

    console.error("Scan failed", {
      runId: error.runId || null,
      httpStatus: error.httpStatus || null,
      code: errorCode,
      message: error.message || errorMessage,
    });

    const statusCode = isTinyFishError
      ? errorCode?.includes("TIMEOUT") ? 504 : 502
      : 500;
    res.status(statusCode).json({
      error: errorMessage,
      cause: null,
      code: errorCode,
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`PatchPilot backend running at http://localhost:${PORT}`);
});
