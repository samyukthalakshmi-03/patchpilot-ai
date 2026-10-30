
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { assessAdvisory } from "./utils/assessmentUtils.js";
import {
  canonicalizeProduct,
  productsMatch,
  validateProductVendor,
} from "./utils/productDiscovery.js";
import {
  researchWithTinyFishFast,
  TinyFishResearchError,
} from "./utils/tinyfishResearch.js";
import { deduplicateSources } from "./utils/sourceDiscovery.js";
import { normalizeAdvisoryRecord } from "./utils/advisoryNormalizer.js";
import { assessWebsite } from "./utils/websiteAssessment.js";
import { normalizeScanInventory } from "./utils/scanInventory.js";

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
    const { assets } = req.body || {};
    let softwareInventory;
    let websiteInventory;

    try {
      ({ softwareAssets: softwareInventory, websiteAssets: websiteInventory } =
        normalizeScanInventory(assets));
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }

    if (softwareInventory.length && !process.env.TINYFISH_API_KEY) {
      return res.status(500).json({
        error: "TINYFISH_API_KEY is missing from server/.env",
      });
    }

    let data = {
      advisories: [],
      research_notes: [],
      product_research: [],
      sources_inspected: [],
    };
    if (softwareInventory.length) {
      const rawResult = await researchWithTinyFishFast(softwareInventory);

      // Unwrap common nested response structures
      data = rawResult;

      if (
        data &&
        typeof data === "object" &&
        data.result !== undefined
      ) {
        const outerData = data;
        const nestedData = parseJsonResponse(outerData.result);
        data = nestedData && typeof nestedData === "object" &&
          !Array.isArray(nestedData)
          ? { ...outerData, ...nestedData }
          : nestedData;
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
    }

    // Normalize advisory fields
    const advisories = data.advisories
      .filter((advisory) => advisory && typeof advisory === "object")
      .map((advisory) => normalizeAdvisoryRecord(advisory));

    const hasResearchNotes =
      Array.isArray(data.research_notes) &&
      data.research_notes.length > 0;

    // Assess each inventory asset against relevant advisories
    const findings = softwareInventory.map((asset) => {
      const relevant = advisories.filter((advisory) =>
        canonicalizeProduct(advisory.softwareName || advisory.product)
          .toLowerCase() ===
        canonicalizeProduct(asset.softwareName || asset.product).toLowerCase()
      );
      const vendorValidation = validateProductVendor(asset);
      const assetResearch = (Array.isArray(data.product_research)
        ? data.product_research
        : []).find((item) =>
        canonicalizeProduct(item.product).toLowerCase() ===
        canonicalizeProduct(asset.softwareName || asset.product).toLowerCase() &&
        (!asset.vendor || item.vendor === asset.vendor || item.vendor === "UNKNOWN")
      );
      const evidenceExplanation = assetResearch?.researchNotes?.find((note) =>
        /no authoritative security|no cve advisory with verifiable evidence|could not retrieve|could not inspect/i
          .test(note)
      );

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
      } else if (hasResearchNotes || assessedAdvisories.length === 0) {
        status = "NEEDS_REVIEW";
        message = evidenceExplanation ||
          "No reliable advisory evidence could be assessed for this product. This does not establish that the software is secure.";
      } else {
        status = "NO_VERIFIED_MATCH";
        message =
          "No verified advisory match was returned. This does not establish that the asset is secure.";
      }

      if (!vendorValidation.valid) {
        status = "NEEDS_REVIEW";
        message = vendorValidation.reason;
      }

      return {
        asset,
        status,
        message,
        vendorValidation,
        advisories: assessedAdvisories,
        researchNotes: (Array.isArray(data.product_research)
          ? data.product_research
          : []).filter((item) =>
          String(item.product).toLowerCase() ===
            asset.softwareName.toLowerCase() &&
          (item.vendor === "UNKNOWN" ||
            item.vendor.toLowerCase() === asset.vendor.toLowerCase())
        ).flatMap((item) => item.researchNotes || []),
        researchSources: deduplicateSources((Array.isArray(data.product_research)
          ? data.product_research
          : []).filter((item) =>
          String(item.product).toLowerCase() ===
            asset.softwareName.toLowerCase() &&
          (item.vendor === "UNKNOWN" ||
            item.vendor.toLowerCase() === asset.vendor.toLowerCase())
        ).flatMap((item) => item.sourcesInspected || [])),
      };
    });

    const websiteFindings = [];
    for (const asset of websiteInventory) {
      let websiteFinding;
      try {
        websiteFinding = await assessWebsite(asset);
      } catch (error) {
        websiteFinding = {
          asset: {
            name: asset.name,
            assetType: "website",
            url: asset.url,
            environment: asset.environment,
            technologyInfo: asset.technologyInfo,
          },
          scope: {
            submittedHostname: new URL(asset.url).hostname,
            finalHostname: new URL(asset.url).hostname,
            redirectTargetHostname: "",
            hostingInfrastructure: null,
            applicationOwnership:
              "Not established: this assessment inspected public HTTP responses only; it did not inspect application source code, backend systems, or ownership.",
          },
          status: "NEEDS_REVIEW",
          assessmentTimestamp: new Date().toISOString(),
          http: null,
          securityHeaders: [],
          cookies: [],
          technologies: [],
          technologyCorrelation: {
            status: "NOT_POSSIBLE",
            reason: "Website assessment failed before reliable technology version evidence was collected.",
          },
          knownVulnerabilities: [],
          observations: [],
          researchNotes: [
            error.message || "The passive website assessment could not complete.",
          ],
          evidence: [],
        };
      }
      websiteFindings.push(websiteFinding);
    }

    const versionedTechnologies = websiteFindings.flatMap((finding) =>
      finding.technologies
        .filter((technology) =>
          technology.version && technology.confidence === "HIGH"
        )
        .map((technology) => ({
          ...technology,
          websiteName: finding.asset.name,
        }))
    );
    if (versionedTechnologies.length > 0 && process.env.TINYFISH_API_KEY) {
      try {
        const technologyInventory = versionedTechnologies.map((technology) => ({
            name: `${technology.websiteName} detected technology`,
            product: technology.product,
            softwareName: technology.product,
            vendor: "",
            version: technology.version,
            operatingSystem: "Unknown",
            buildType: "Unknown",
            packageManager: "",
            architecture: "",
            installedConfiguration: "",
          }));
        const research = await researchWithTinyFishFast(technologyInventory);
        for (const websiteFinding of websiteFindings) {
          const siteTechnologies = websiteFinding.technologies.filter(
            (technology) => technology.version &&
              technology.confidence === "HIGH"
          );
          const correlated = (research.advisories || [])
            .filter((advisory) => advisory.sourceVerified === true)
            .flatMap((advisory) => {
              const normalized = normalizeAdvisoryRecord(advisory);
              return siteTechnologies
                .filter((technology) =>
                  productsMatch({ product: technology.product }, normalized)
                )
                .map((technology) => ({
                  ...normalized,
                  ...assessAdvisory({
                    product: technology.product,
                    version: technology.version,
                    operatingSystem: "Unknown",
                    buildType: "Unknown",
                  }, normalized),
                  technologyVersion: technology.version,
                  assessmentDisclaimer:
                    "Technology/version evidence and advisory correlation do not prove website exploitability.",
                }));
            });
          websiteFinding.knownVulnerabilities = correlated;
          if (siteTechnologies.length) {
            websiteFinding.technologyCorrelation = {
              status: "COMPLETED",
              reason: "Public advisory correlation was attempted for the high-confidence technology versions shown above; this does not prove website exploitability.",
            };
            websiteFinding.researchNotes.push(
              ...(research.research_notes || []),
              "TinyFish research corroborates public advisories only; it is not evidence that the website is exploitable."
            );
          } else {
            websiteFinding.researchNotes.push(
              "No technology version was reliably identifiable from the public response; known-CVE correlation was not attempted."
            );
          }
          if (correlated.some((advisory) =>
            advisory.assessment === "POTENTIALLY_AFFECTED"
          )) {
            websiteFinding.status = "POTENTIALLY_AFFECTED";
          } else if (
            correlated.some((advisory) =>
              advisory.assessment === "NEEDS_REVIEW"
            ) &&
            websiteFinding.status === "NO_ISSUES_OBSERVED"
          ) {
            websiteFinding.status = "NEEDS_REVIEW";
          }
          websiteFinding.evidence.push(...correlated.map((advisory) => ({
            sourceUrl: advisory.sourceUrl,
            sourceName: advisory.sourceName,
            sourceVerified: advisory.sourceVerified,
            excerpt: advisory.evidenceExcerpt,
          })).filter((item) => item.sourceUrl));
        }
      } catch (error) {
        for (const websiteFinding of websiteFindings) {
          if (!websiteFinding.technologies.some((technology) =>
            technology.version && technology.confidence === "HIGH"
          )) continue;
          websiteFinding.technologyCorrelation = {
            status: "FAILED",
            reason: "Technology versions were observed, but public advisory correlation could not be completed.",
          };
          websiteFinding.researchNotes.push(
            `Public vulnerability correlation could not be completed: ${error.message}`
          );
          if (websiteFinding.status === "NO_ISSUES_OBSERVED") {
            websiteFinding.status = "NEEDS_REVIEW";
          }
        }
      }
    } else {
      for (const websiteFinding of websiteFindings) {
        const hasVersionedTechnology = websiteFinding.technologies.some(
          (technology) => technology.version &&
            technology.confidence === "HIGH"
        );
        if (hasVersionedTechnology) {
          websiteFinding.technologyCorrelation = {
            status: "NOT_COMPLETED",
            reason: "A high-confidence version was observed, but TinyFish is not configured, so public advisory correlation was not completed.",
          };
        }
        websiteFinding.researchNotes.push(
          hasVersionedTechnology
            ? "TinyFish is not configured; detected technology versions were not correlated with public advisories."
            : "No technology version was reliably identifiable from the public response; known-CVE correlation was not attempted."
        );
        if (
          hasVersionedTechnology &&
          websiteFinding.status === "NO_ISSUES_OBSERVED"
        ) {
          websiteFinding.status = "NEEDS_REVIEW";
        }
      }
    }

    // Send scan results to frontend
    res.json({
      ok: true,
      scanId: `PP-${Date.now()}`,
      scannedAt: new Date().toISOString(),
      assetsScanned: softwareInventory.length + websiteInventory.length,
      advisoriesFound: advisories.length,
      findings,
      websiteFindings,
      researchNotes: Array.isArray(data.research_notes)
        ? data.research_notes
        : [],
      sourcesInspected: Array.isArray(data.sources_inspected)
        ? deduplicateSources(data.sources_inspected
          .filter((source) =>
            source && /^https:\/\//i.test(source.sourceUrl || "")
          )
          .map((source) => ({
            product: String(source.product || "Unknown"),
            vendor: String(source.vendor || "UNKNOWN"),
            sourceName: String(source.sourceName || "Security source"),
            sourceType: String(source.sourceType || "UNKNOWN"),
            sourceUrl: source.sourceUrl,
            sourceVerified: source.sourceVerified === true,
          })), { includeProduct: true })
        : [],
      disclaimer:
        "Passive website assessment observes only public HTTP(S) responses and is not comprehensive penetration testing or proof of exploitability. Software research is a triage aid; verify vendor-specific version ranges, distribution backports and installed package provenance.",
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
