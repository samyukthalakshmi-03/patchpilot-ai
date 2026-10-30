const PRODUCT_ALIASES = new Map([
  ["node", "Node.js"],
  ["nodejs", "Node.js"],
  ["node.js", "Node.js"],
  ["python3", "Python"],
  ["apache", "Apache HTTP Server"],
  ["apache http server", "Apache HTTP Server"],
  ["httpd", "Apache HTTP Server"],
  ["mysql server", "MySQL"],
  ["openssl library", "OpenSSL"],
]);

const PRODUCT_VENDOR_ALIASES = new Map([
  ["php", ["php group", "the php group", "php"]],
  ["node.js", ["openjs foundation", "openjs", "node.js", "nodejs"]],
  ["python", ["python software foundation", "psf", "python"]],
  ["apache http server", ["apache software foundation", "apache"]],
  ["mysql", ["oracle", "oracle corporation", "mysql"]],
  ["openssl", ["openssl software foundation", "openssl"]],
  ["nginx", ["f5", "f5 inc", "nginx inc", "nginx"]],
  ["express", ["openjs foundation", "express"]],
  ["wordpress", ["automattic", "automattic inc", "wordpress"]],
]);

function clean(value, maxLength = 200) {
  return String(value ?? "").trim().slice(0, maxLength);
}

function normalizeVendor(value) {
  return clean(value).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

export function normalizeVendorName(value) {
  const vendor = clean(value).replace(/\s+/g, " ");
  return ["", "unknown", "not known", "not specified", "n a"]
    .includes(normalizeVendor(vendor))
    ? ""
    : vendor;
}

export function canonicalizeProduct(value) {
  const product = clean(value);
  if (!product) return "";
  return PRODUCT_ALIASES.get(product.toLowerCase()) || product;
}

export function validateProductVendor(asset, advisory = {}) {
  const product = canonicalizeProduct(
    asset.softwareName || asset.product
  ).toLowerCase();
  const recognizedVendors = PRODUCT_VENDOR_ALIASES.get(product);
  const inventoryVendor = normalizeVendor(asset.vendor);
  const advisoryVendor = normalizeVendor(advisory.vendor);
  const unknownValues = new Set(["", "unknown", "not known", "not specified", "n a"]);

  if (!recognizedVendors) {
    return {
      valid: false,
      reason: inventoryVendor && !unknownValues.has(inventoryVendor)
        ? `The vendor "${clean(asset.vendor)}" cannot be verified for ${clean(asset.softwareName || asset.product)}.`
        : `The vendor for ${clean(asset.softwareName || asset.product)} is unknown and cannot be verified.`,
    };
  }

  const accepted = new Set(recognizedVendors.map(normalizeVendor));
  if (inventoryVendor && unknownValues.has(inventoryVendor)) {
    return {
      valid: false,
      reason: `The inventory vendor for ${canonicalizeProduct(asset.softwareName || asset.product)} is explicitly unknown.`,
    };
  }
  if (inventoryVendor && !accepted.has(inventoryVendor)) {
    return {
      valid: false,
      reason: `The inventory vendor "${clean(asset.vendor)}" is not a recognized vendor for ${canonicalizeProduct(asset.softwareName || asset.product)}.`,
    };
  }
  if (!unknownValues.has(advisoryVendor) && !accepted.has(advisoryVendor)) {
    return {
      valid: false,
      reason: `The advisory vendor "${clean(advisory.vendor)}" is not a recognized vendor for ${canonicalizeProduct(asset.softwareName || asset.product)}.`,
    };
  }
  return { valid: true, reason: "" };
}

export function normalizeInventoryAsset(asset) {
  const softwareName = canonicalizeProduct(
    asset.softwareName || asset.product || asset.software
  );
  const product = softwareName;

  return {
    name: clean(asset.name, 100),
    softwareName,
    product,
    vendor: clean(asset.vendor, 100),
    version: clean(asset.version, 100),
    operatingSystem: clean(asset.operatingSystem, 100) || "Unknown",
    buildType: clean(asset.buildType, 100) || "Unknown",
    packageManager: clean(asset.packageManager, 100),
    architecture: clean(asset.architecture, 100),
    installedConfiguration: clean(asset.installedConfiguration, 1000),
  };
}

export function groupInventoryByProduct(assets) {
  const groups = new Map();

  for (const asset of assets) {
    const product = canonicalizeProduct(
      asset.softwareName || asset.product
    );
    const vendor = normalizeVendorName(asset.vendor);
    const key = [
      product.toLowerCase(),
      normalizeVendor(vendor),
    ].join("::");
    const group = groups.get(key) || {
      product,
      vendor,
      assets: [],
    };
    group.assets.push(asset);
    groups.set(key, group);
  }

  return [...groups.values()];
}

export function productsMatch(asset, advisory) {
  const assetProduct = canonicalizeProduct(
    asset.softwareName || asset.product
  ).toLowerCase();
  const advisoryProduct = canonicalizeProduct(
    advisory.softwareName || advisory.product
  ).toLowerCase();

  if (!assetProduct || assetProduct !== advisoryProduct) return false;

  const assetVendor = clean(asset.vendor).toLowerCase();
  const advisoryVendor = clean(advisory.vendor).toLowerCase();
  return !assetVendor || !advisoryVendor ||
    normalizeVendor(assetVendor) === normalizeVendor(advisoryVendor) ||
    validateProductVendor(asset, advisory).valid;
}
