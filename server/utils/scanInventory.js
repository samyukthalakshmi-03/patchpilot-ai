import {
  normalizeOptionalInventoryFields,
  normalizePlatformFields,
} from "./inventoryUtils.js";
import { normalizeInventoryAsset } from "./productDiscovery.js";
import { validateWebsiteUrl } from "./websiteAssessment.js";

function boundedText(value, label, maxLength, fallback = "") {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string.`);
  }
  const text = value.trim();
  if (text.length > maxLength) {
    throw new Error(`${label} must be at most ${maxLength} characters.`);
  }
  return text;
}

export function normalizeScanInventory(assets) {
  if (!Array.isArray(assets) || assets.length < 1 || assets.length > 20) {
    throw new Error("Provide between 1 and 20 inventory assets.");
  }

  const normalized = assets.map((asset) => {
    if (!asset || typeof asset !== "object" || Array.isArray(asset)) {
      throw new Error("Every asset must be an object.");
    }
    const assetType = asset.assetType || asset.type || "software";
    const name = boundedText(asset.name, "Asset name", 100);
    if (!name) throw new Error("Every asset needs a name.");

    if (assetType === "website") {
      if (asset.authorizationConfirmed !== true) {
        throw new Error(
          "Confirm that you are authorized to assess each website asset."
        );
      }
      const url = validateWebsiteUrl(asset.url).href;
      const environment = boundedText(
        asset.environment,
        "Website environment",
        30,
        "Development"
      );
      if (!["Production", "Staging", "Development"].includes(environment)) {
        throw new Error("Website environment must be Production, Staging, or Development.");
      }
      return {
        assetType: "website",
        name,
        url,
        environment,
        technologyInfo: boundedText(
          asset.technologyInfo || asset.technology,
          "Website technology information",
          500
        ),
        authorizationConfirmed: true,
      };
    }

    if (assetType !== "software") {
      throw new Error("Asset type must be Software or Website / Web Application.");
    }
    const softwareAsset = normalizeInventoryAsset({
      name,
      softwareName: String(
        asset.softwareName || asset.product || asset.software || ""
      ).trim().slice(0, 100),
      vendor: asset.vendor,
      version: String(asset.version || "").trim().slice(0, 100),
      ...normalizePlatformFields(asset),
      ...normalizeOptionalInventoryFields(asset),
    });
    if (!softwareAsset.softwareName || !softwareAsset.version) {
      throw new Error("Every software asset needs a product and installed version.");
    }
    return { ...softwareAsset, assetType: "software" };
  });

  return {
    softwareAssets: normalized.filter((asset) => asset.assetType === "software"),
    websiteAssets: normalized.filter((asset) => asset.assetType === "website"),
  };
}
