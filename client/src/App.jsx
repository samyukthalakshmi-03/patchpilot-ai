
import { useState } from "react";
import "./App.css";

const initialAssets = [
  {
    id: 1,
    name: "Web Server A",
    product: "PHP",
    version: "8.3.35",
    operatingSystem: "Unknown",
    buildType: "Unknown",
  },
  {
    id: 2,
    name: "Web Server B",
    product: "PHP",
    version: "8.3.36",
    operatingSystem: "Unknown",
    buildType: "Unknown",
  },
];

const operatingSystems = ["Unknown", "Windows", "Linux", "macOS", "Other"];
const buildTypes = [
  "Unknown",
  "Standard PHP build",
  "Windows build",
  "Custom/vendor build",
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
    setLoading(true);
    setError("");
    setReport(null);

    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL || "http://localhost:5000"}/api/scan`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(
            { assets: assets.map(({
              name,
              product,
              version,
              operatingSystem,
              buildType,
            }) => ({
              name,
              product,
              version,
              operatingSystem,
              buildType,
            }))
            }
          ),
          signal: AbortSignal.timeout(65000),
        }
      );

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Scan failed.");
      setReport(data);
    } catch (e) {
      if (e.name === "TimeoutError") {
        setError("TinyFish research did not finish within one minute. Try again.");
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
          Investigate official security information with TinyFish and review
          evidence against your software inventory.
        </p>
      </section>

      <section className="panel">
        <div className="heading">
          <div>
            <p className="eyebrow">01 / INVENTORY</p>
            <h2>Your software assets</h2>
          </div>
          <button className="secondary" onClick={() =>
            setAssets((prev) => [...prev, {
              id: Date.now(),
              name: `Server ${prev.length + 1}`,
              product: "PHP",
              version: "8.3.35",
              operatingSystem: "Unknown",
              buildType: "Unknown",
            }])
          }>+ Add asset</button>
        </div>

        <div className="asset-list">
          {assets.map((a) => (
            <div className="asset" key={a.id}>
              <label>Asset name
                <input value={a.name} onChange={(e) =>
                  updateAsset(a.id, "name", e.target.value)} />
              </label>
              <label>Product
                <input value={a.product} onChange={(e) =>
                  updateAsset(a.id, "product", e.target.value)} />
              </label>
              <label>Version
                <input value={a.version} onChange={(e) =>
                  updateAsset(a.id, "version", e.target.value)} />
              </label>
              <label>Operating system
                <select value={a.operatingSystem || "Unknown"} onChange={(e) =>
                  updateAsset(a.id, "operatingSystem", e.target.value)}>
                  {operatingSystems.map((operatingSystem) => (
                    <option key={operatingSystem} value={operatingSystem}>
                      {operatingSystem}
                    </option>
                  ))}
                </select>
              </label>
              <label>Build type
                <select value={a.buildType || "Unknown"} onChange={(e) =>
                  updateAsset(a.id, "buildType", e.target.value)}>
                  {buildTypes.map((buildType) => (
                    <option key={buildType} value={buildType}>
                      {buildType}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          ))}
        </div>

        <button className="primary" disabled={loading || !assets.length}
          onClick={runScan}>
          {loading ? "TinyFish is researching…" : "Run live investigation →"}
        </button>

        {loading && <p className="hint">
          TinyFish is checking official PHP advisories. This usually takes a few seconds.
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

          {report.findings?.map((f, i) => (
            <article className="finding" key={f.asset.name + i}>
              <span className="status">{f.status.replaceAll("_", " ")}</span>
              <h3>{f.asset.name}</h3>
              <p className="hint">
                {f.asset.product} {f.asset.version} · OS:{" "}
                {f.asset.operatingSystem || "Unknown"} · Build:{" "}
                {f.asset.buildType || "Unknown"}
              </p>
              <p>{f.message}</p>

             
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
      {a.severity} · {a.affectedVersions}
    </p>

    <p>{a.remediation}</p>
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

    {a.sourceUrl && (
      <a
        href={a.sourceUrl}
        target="_blank"
        rel="noreferrer"
      >
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
