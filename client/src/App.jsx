
import { useState } from "react";
import "./App.css";

let generatedAssetId = 0;

function createAssetId() {
  return globalThis.crypto?.randomUUID?.() ||
    `asset-${Date.now()}-${generatedAssetId++}`;
}

function createSoftwareAsset(index) {
  return {
    id: createAssetId(),
    assetType: "software",
    name: `Server ${index}`,
    product: "",
    softwareName: "",
    vendor: "",
    version: "",
    operatingSystem: "Unknown",
    buildType: "Unknown",
    packageManager: "",
    architecture: "",
    installedConfiguration: "",
  };
}

function createWebsiteAsset(index) {
  return {
    id: createAssetId(),
    assetType: "website",
    name: `Website ${index}`,
    url: "",
    environment: "Development",
    technologyInfo: "",
    authorizationConfirmed: false,
  };
}

const initialAssets = [
  {
    id: "demo-server-a",
    assetType: "software",
    name: "Web Server A",
    product: "PHP",
    softwareName: "PHP",
    vendor: "",
    version: "8.3.35",
    operatingSystem: "Unknown",
    buildType: "Unknown",
    packageManager: "",
    architecture: "",
    installedConfiguration: "",
  },
  {
    id: "demo-server-b",
    assetType: "software",
    name: "Web Server B",
    product: "PHP",
    softwareName: "PHP",
    vendor: "",
    version: "8.3.36",
    operatingSystem: "Unknown",
    buildType: "Unknown",
    packageManager: "",
    architecture: "",
    installedConfiguration: "",
  },
];

export default function App() {
  const [assets, setAssets] = useState(initialAssets);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  function updateAsset(id, field, value) {
    setAssets((prev) =>
      prev.map((a) => a.id === id ? { ...a, [field]: value } : a)
    );
  }

  async function runScan() {
    for (const asset of assets) {
      if (asset.assetType !== "website") continue;
      try {
        const url = new URL(asset.url);
        if (!["http:", "https:"].includes(url.protocol)) {
          throw new Error();
        }
      } catch {
        setError(`Enter a valid HTTP or HTTPS URL for ${asset.name || "the website asset"}.`);
        return;
      }
      if (!asset.authorizationConfirmed) {
        setError(`Confirm authorization for ${asset.name || "the website asset"} before scanning.`);
        return;
      }
    }

    setLoading(true);
    setError("");
    setReport(null);

    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL || "http://localhost:5000"}/api/scan`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            assets: assets.map((asset) => asset.assetType === "website"
              ? {
                assetType: "website",
                name: asset.name,
                url: asset.url,
                environment: asset.environment,
                technologyInfo: asset.technologyInfo,
                authorizationConfirmed: asset.authorizationConfirmed,
              }
              : {
                assetType: "software",
                name: asset.name,
                product: asset.product,
                softwareName: asset.softwareName,
                vendor: asset.vendor,
                version: asset.version,
                operatingSystem: asset.operatingSystem,
                buildType: asset.buildType,
                packageManager: asset.packageManager,
                architecture: asset.architecture,
                installedConfiguration: asset.installedConfiguration,
              }),
          }),
          signal: AbortSignal.timeout(310000),
        }
      );

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Scan failed.");
      setReport(data);
    } catch (e) {
      if (e.name === "TimeoutError") {
        setError("TinyFish research did not finish within five minutes. Try again.");
      } else if (e instanceof TypeError) {
        setError(
          "Could not reach the PatchPilot backend. Check that the server is running and try again."
        );
      } else {
        setError(e.message || "The scan could not be completed.");
      }
    } finally {
      setLoading(false);
    }
  }

  function exportReport() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${report.scanId}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="shell">
      <header className="nav">
        <div className="logo"><span> P </span> patchpilot.ai</div>
        <span className="pill">TINYFISH CONNECTED</span>
      </header>

      <section className="hero">
        <p className="eyebrow">AGENTIC SECURITY INTELLIGENCE</p>
        <h1>Find the risk.<br /><span>Know your next move.</span></h1>
        <p>
          Investigate software advisories and passively assess authorized
          websites, with evidence to review before acting.
        </p>
      </section>

      <section className="panel">
        <div className="heading">
          <div>
            <p className="eyebrow">01 / INVENTORY</p>
            <h2>Your assets</h2>
          </div>
          <div className="asset-actions">
            <button className="secondary" disabled={assets.length >= 20} onClick={() =>
              setAssets((prev) => [...prev, createSoftwareAsset(prev.length + 1)])
            }>+ Add software</button>
            <button className="secondary" disabled={assets.length >= 20} onClick={() =>
              setAssets((prev) => [...prev, createWebsiteAsset(prev.length + 1)])
            }>+ Add website</button>
          </div>
        </div>

        <div className="asset-list">
          {assets.map((a) => (
            <div className="asset" key={a.id}>
              <label>Asset type
                <select value={a.assetType || "software"} onChange={(e) =>
                  updateAsset(a.id, "assetType", e.target.value)}>
                  <option value="software">Software</option>
                  <option value="website">Website / Web Application</option>
                </select>
              </label>
              <label>Asset name
                <input value={a.name} onChange={(e) =>
                  updateAsset(a.id, "name", e.target.value)} />
              </label>
              {a.assetType === "website" ? (
                <>
                  <label>Website URL
                    <input type="url" value={a.url || ""} placeholder="https://example.com"
                      onChange={(e) => updateAsset(a.id, "url", e.target.value)} />
                  </label>
                  <label>Environment
                    <select value={a.environment || "Development"} onChange={(e) =>
                      updateAsset(a.id, "environment", e.target.value)}>
                      <option>Production</option>
                      <option>Staging</option>
                      <option>Development</option>
                    </select>
                  </label>
                  <label>Technology / framework (optional)
                    <input value={a.technologyInfo || ""} placeholder="If known"
                      onChange={(e) => updateAsset(a.id, "technologyInfo", e.target.value)} />
                  </label>
                  <label className="authorization">
                    <input type="checkbox" checked={Boolean(a.authorizationConfirmed)}
                      onChange={(e) => updateAsset(
                        a.id,
                        "authorizationConfirmed",
                        e.target.checked
                      )} />
                    I am authorized to assess this website
                  </label>
                </>
              ) : (
                <>
              <label>Product
                <input value={a.softwareName || a.product || ""}
                  placeholder="Node.js, Python, MySQL…"
                  onChange={(e) => setAssets((prev) => prev.map((asset) =>
                    asset.id === a.id
                      ? { ...asset, product: e.target.value, softwareName: e.target.value }
                      : asset
                  ))} />
              </label>
              <label>Vendor
                <input value={a.vendor || ""} placeholder="Optional" onChange={(e) =>
                  updateAsset(a.id, "vendor", e.target.value)} />
              </label>
              <label>Version
                <input value={a.version} onChange={(e) =>
                  updateAsset(a.id, "version", e.target.value)} />
              </label>
              <label>Operating system
                <input value={a.operatingSystem ?? "Unknown"} placeholder="Unknown" onChange={(e) =>
                  updateAsset(a.id, "operatingSystem", e.target.value)} />
              </label>
              <label>Build type
                <input value={a.buildType ?? "Unknown"} placeholder="Unknown" onChange={(e) =>
                  updateAsset(a.id, "buildType", e.target.value)} />
              </label>
              <label>Package manager
                <input value={a.packageManager || ""} placeholder="Optional" onChange={(e) =>
                  updateAsset(a.id, "packageManager", e.target.value)} />
              </label>
              <label>Architecture
                <input value={a.architecture || ""} placeholder="Optional" onChange={(e) =>
                  updateAsset(a.id, "architecture", e.target.value)} />
              </label>
              <label>Installed configuration
                <input value={a.installedConfiguration || ""} placeholder="Optional" onChange={(e) =>
                  updateAsset(a.id, "installedConfiguration", e.target.value)} />
              </label>
                </>
              )}
              <button className="remove-asset" disabled={assets.length <= 1}
                aria-label={`Remove ${a.name}`} onClick={() =>
                  setAssets((prev) => prev.filter((item) => item.id !== a.id))
                }>Remove</button>
            </div>
          ))}
        </div>

        <button className="primary" disabled={loading || !assets.length}
          onClick={runScan}>
          {loading ? "Assessing assets…" : "Run live investigation →"}
        </button>

        {loading && <p className="hint">
          Software advisories and passive website observations are being assessed separately.
        </p>}
        {error && <div className="error">{error}</div>}
      </section>

      {report && (
        <section className="panel">
          <div className="heading">
            <div>
              <p className="eyebrow">02 / RESULTS</p>
              <h2>Investigation report</h2>
              <p className="hint">
                {report.scanId} · {report.assetsScanned} assets scanned
              </p>
            </div>
            <button className="secondary" onClick={exportReport}>
              Export JSON ↓
            </button>
          </div>

          <div className="stats">
            <div><span>Assets</span><strong>{report.assetsScanned}</strong></div>
            <div><span>Advisories</span><strong>{report.advisoriesFound}</strong></div>
            <div><span>Research notes</span>
              <strong>{report.researchNotes?.length || 0}</strong></div>
          </div>

          {report.websiteFindings?.map((site, index) => (
            <article className="finding website-finding" key={`${site.asset.url}-${index}`}>
              <span className={`assessment ${site.status}`}>
                {site.status.replaceAll("_", " ")}
              </span>
              <h3>{site.asset.name}</h3>
              <p><a href={site.asset.url} target="_blank" rel="noreferrer">
                {site.asset.url}
              </a></p>
              <p className="hint">
                {site.asset.environment} · Assessed {site.assessmentTimestamp}
              </p>
              <div className="notes website-scope">
                <strong>Assessment scope</strong>
                <p>Submitted website hostname:{" "}
                  <code>{site.scope?.submittedHostname || new URL(site.asset.url).hostname}</code>
                </p>
                <p>Final response hostname:{" "}
                  <code>{site.scope?.finalHostname || new URL(site.http?.finalUrl || site.asset.url).hostname}</code>
                </p>
                {site.scope?.redirectTargetHostname && (
                  <p>
                    Redirect target hostname:{" "}
                    <code>{site.scope.redirectTargetHostname}</code> · not followed or assessed
                  </p>
                )}
                {site.scope?.hostingInfrastructure ? (
                  <p>
                    Observed third-party infrastructure:{" "}
                    {site.scope.hostingInfrastructure.provider} (
                    {site.scope.hostingInfrastructure.kind}) ·{" "}
                    {site.scope.hostingInfrastructure.evidence}
                  </p>
                ) : (
                  <p>No third-party hosting or edge infrastructure was confidently identified from the response.</p>
                )}
                <p className="hint">
                  {site.scope?.applicationOwnership ||
                    "Only public HTTP responses were inspected; application source code, backend systems, and ownership were not established."}
                </p>
              </div>
              {site.asset.technologyInfo && (
                <p className="hint">User-provided technology context: {site.asset.technologyInfo}</p>
              )}
              {site.http && (
                <div className="notes">
                  <strong>HTTPS / TLS</strong>
                  <p>{site.observations.find((item) =>
                    item.category === "HTTPS/TLS"
                  )?.details.join(" ")}</p>
                  <p>HTTP status: {site.http.statusCode} · Final response URL: {site.http.finalUrl}</p>
                  {site.http.redirect?.target && (
                    <p className="hint">
                      Cross-host redirect was not followed: {site.http.redirect.target}
                    </p>
                  )}
                  {site.http.tls?.expiresAt && (
                    <p>
                      Certificate: {site.http.tls.status.replaceAll("_", " ")} ·
                      expires {site.http.tls.expiresAt}
                    </p>
                  )}
                </div>
              )}
              {site.securityHeaders?.length > 0 && (
                <div className="notes">
                  <strong>HTTP security headers</strong>
                  <ul>{site.securityHeaders.map((header) => {
                    if (header.name === "Content-Security-Policy") {
                      const analysis = header.analysis;
                      return (
                        <li className="header-item csp-analysis" key={header.name}>
                          <strong>{header.name}: {header.present ? "Present" : "Not observed"}</strong>
                          {" · "}{header.status.replaceAll("_", " ")}
                          {analysis?.directives?.length > 0 && (
                            <div>
                              <span>Important directives</span>
                              <ul>{analysis.directives.map((directive) => (
                                <li key={directive.name}>
                                  <code>{directive.name}</code>
                                  {directive.value && (
                                    <> <code>
                                      {directive.value.length > 120
                                        ? `${directive.value.slice(0, 120)}…`
                                        : directive.value}
                                    </code></>
                                  )}
                                </li>
                              ))}</ul>
                            </div>
                          )}
                          {analysis?.potentialWeaknesses?.length > 0 && (
                            <div>
                              <span>Potentially weak directives</span>
                              <ul>{analysis.potentialWeaknesses.map((item) => (
                                <li key={`${item.directive}-${item.issue}`}>
                                  <code>{item.directive}</code>: {item.issue}. {item.implication}
                                </li>
                              ))}</ul>
                            </div>
                          )}
                          {analysis?.missingRecommendedDirectives?.length > 0 && (
                            <p>
                              Recommended directives not explicitly set:{" "}
                              {analysis.missingRecommendedDirectives.map((name) =>
                                <code key={name}>{name} </code>
                              )}
                            </p>
                          )}
                          {analysis?.explanation && (
                            <p className="hint">{analysis.explanation}</p>
                          )}
                          {header.value && (
                            <details>
                              <summary>Show complete raw CSP value</summary>
                              <code className="technical-value">{header.value}</code>
                            </details>
                          )}
                        </li>
                      );
                    }
                    return (
                      <li className="header-item" key={header.name}>
                        <strong>{header.name}</strong>:{" "}
                        {header.present ? header.status.replaceAll("_", " ") : "Not observed"}
                        {header.observation && <p>{header.observation}</p>}
                        {header.recommendation && <p className="hint">{header.recommendation}</p>}
                        {header.value && (
                          <details>
                            <summary>Show observed value</summary>
                            <code className="technical-value">{header.value}</code>
                          </details>
                        )}
                      </li>
                    );
                  })}</ul>
                </div>
              )}
              {site.cookies?.length > 0 && (
                <div className="notes">
                  <strong>Cookie security</strong>
                  <ul>{site.cookies.map((cookie) => (
                    <li key={cookie.cookie}>
                      {cookie.cookie}: Secure {cookie.secure ? "yes" : "no"} ·
                      HttpOnly {cookie.httpOnly ? "yes" : "no"} ·
                      SameSite {cookie.sameSite}
                      {cookie.recommendation && <p className="hint">{cookie.recommendation}</p>}
                    </li>
                  ))}</ul>
                </div>
              )}
              {site.technologies?.length > 0 && (
                <div className="notes">
                  <strong>Publicly identified technologies</strong>
                  <ul>{site.technologies.map((technology) => (
                    <li key={`${technology.product}-${technology.version}`}>
                      <strong>{technology.product}</strong> ·{" "}
                      {technology.version
                        ? `Version ${technology.version}`
                        : "Version not publicly identified"} ·{" "}
                      {technology.confidence} confidence · {technology.evidence}
                      {technology.correlationReason && (
                        <p className="hint">{technology.correlationReason}</p>
                      )}
                    </li>
                  ))}</ul>
                </div>
              )}
              <p className="hint technology-correlation">
                CVE correlation: {site.technologyCorrelation?.status?.replaceAll("_", " ") ||
                  (site.technologies?.some((technology) =>
                    technology.version && technology.confidence === "HIGH"
                  ) ? "Not completed" : "Not possible")}
                {" · "}{site.technologyCorrelation?.reason ||
                  "No technology version was established from strong public-response evidence, so CVE correlation was not possible."}
              </p>
              {site.knownVulnerabilities?.map((advisory, advisoryIndex) => (
                <div className="advisory" key={`${advisory.cveId}-${advisoryIndex}`}>
                  <h4>{advisory.cveId} · {advisory.title}</h4>
                  <p>{advisory.severity}{advisory.cvssScore !== null
                    ? ` · CVSS ${advisory.cvssScore}` : ""} · {advisory.assessment}</p>
                  <p>{advisory.reason}</p>
                  <p>Remediation: {advisory.remediation}</p>
                  {advisory.sourceUrl && <a href={advisory.sourceUrl}
                    target="_blank" rel="noreferrer">Advisory source ↗</a>}
                  {advisory.evidenceExcerpt && (
                    <p className="evidence">{advisory.evidenceExcerpt}</p>
                  )}
                </div>
              ))}
              {site.evidence?.map((evidence, evidenceIndex) => (
                <p className="hint" key={`${evidence.sourceUrl}-${evidenceIndex}`}>
                  Evidence: <a href={evidence.sourceUrl} target="_blank" rel="noreferrer">
                    {evidence.sourceName}
                  </a> · {evidence.excerpt}
                </p>
              ))}
              {site.researchNotes?.length > 0 && (
                <div className="notes">
                  <strong>Limitations / research notes</strong>
                  <ul>{site.researchNotes.map((note, noteIndex) =>
                    <li key={noteIndex}>{note}</li>
                  )}</ul>
                </div>
              )}
            </article>
          ))}

          {report.findings?.map((f, i) => (
            <article className="finding" key={f.asset.name + i}>
              <span className="status">{f.status.replaceAll("_", " ")}</span>
              <h3>{f.asset.name}</h3>
              <p className="hint">
                {f.asset.softwareName || f.asset.product} {f.asset.version}
                {f.asset.vendor ? ` · Vendor: ${f.asset.vendor}` : ""} · OS:{" "}
                {f.asset.operatingSystem || "Unknown"} · Build:{" "}
                {f.asset.buildType || "Unknown"}
              </p>
              <p className="hint">
                Package manager: {f.asset.packageManager || "Not specified"} ·
                Architecture: {f.asset.architecture || "Not specified"}
              </p>
              <p>{f.message}</p>
              {f.researchSources?.length > 0 && (
                <div className="notes">
                  <strong>Sources inspected</strong>
                  <ul>{f.researchSources.map((source) => (
                    <li key={source.sourceUrl}>
                      {source.sourceVerified ? "Verified" : "Unverified"} ·{" "}
                      <a href={source.sourceUrl} target="_blank" rel="noreferrer">
                        {source.sourceName}
                      </a>
                    </li>
                  ))}</ul>
                </div>
              )}

              {f.advisories?.map((a, j) => (
                <div className="advisory" key={`${a.cveId || a.title}-${j}`}>
                  <h4>{a.title}</h4>

                  <span className={`assessment ${
                    a.assessment || "NEEDS_REVIEW"
                  }`}>
                    {(a.assessment || "NEEDS_REVIEW").replaceAll("_", " ")}
                  </span>

                  <p>{a.cveId && !a.title?.includes(a.cveId)
                    ? `${a.cveId} · ` : ""}
                    {a.severity}{a.cvssScore !== null && a.cvssScore !== undefined
                      ? ` · CVSS ${a.cvssScore}` : ""} · {a.affectedVersions}
                  </p>

                  <p>Fixed version: {a.fixedVersion && a.fixedVersion !== "UNKNOWN"
                    ? a.fixedVersion
                    : a.fixedVersions?.length
                      ? a.fixedVersions.join(", ")
                      : "UNKNOWN"} · Published: {a.publishedDate || "UNKNOWN"}</p>
                  <p>Remediation: {a.remediation}</p>
                  <p className="hint">
                    Assessment reason: {a.reason || "The advisory could not be confidently assessed."}
                  </p>
                  <p className="hint">
                    Operating systems: {a.affectedOperatingSystems || "UNKNOWN"} · Build
                    restrictions: {a.buildRestrictions || "UNKNOWN"}
                  </p>
                  <p className="hint">
                    Required configuration:{" "}
                    {a.requiredConfigurationConditions || "UNKNOWN"}
                  </p>
                  <p className="hint">
                    Evidence: {a.verifiedInformation?.join(", ") || "No fields verified"} ·
                    Source status: {a.evidenceStatus || "UNKNOWN"}
                  </p>
                  {a.inferredInformation?.length > 0 && (
                    <p className="hint">
                      Inferred information (not used as verified evidence):{" "}
                      {a.inferredInformation.join(", ")}
                    </p>
                  )}
                  {a.evidenceExcerpt && (
                    <details>
                      <summary>Evidence excerpt ({a.sourceName || "source"})</summary>
                      <p className="evidence">{a.evidenceExcerpt}</p>
                    </details>
                  )}

                  {a.sourceUrl && (
                    <a href={a.sourceUrl} target="_blank" rel="noreferrer">
                      Read source evidence ↗
                    </a>
                  )}
                </div>
              ))}


              {f.researchNotes?.length > 0 && (
                <div className="notes">
                  <strong>Research notes — verify before acting</strong>
                  <ul>{f.researchNotes.map((note, j) =>
                    <li key={j}>{note}</li>
                  )}</ul>
                </div>
              )}
            </article>
          ))}

          <p className="disclaimer">{report.disclaimer}</p>
        </section>
      )}

      <footer>PATCHPILOT AI · READ-ONLY SECURITY TRIAGE · POWERED BY TINYFISH</footer>
    </main>
  );
}
