import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getCompliance } from "../lib/api";

const SEV = {
  critical: "#b91c1c",
  high: "#c2410c",
  medium: "#b45309",
  low: "#475569",
};

export default function ReportPage() {
  const { assetId } = useParams();
  const navigate = useNavigate();
  const [c, setC] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    try {
      document.title = `Compliance report — ${assetId}`;
    } catch (_) { /* ignore */ }
    getCompliance(assetId)
      .then(setC)
      .catch((e) => setError(e.response?.data?.detail || e.message));
  }, [assetId]);

  const doPrint = () => window.print();

  return (
    <div className="report-sheet">
      <div className="report-toolbar">
        <button className="report-btn" onClick={doPrint}>Save as PDF</button>
        <button className="report-btn report-btn-back" onClick={() => navigate(-1)}>Back</button>
      </div>

      {error && <p className="report-error">Failed to load report: {error}</p>}

      <div className="report-head">
        <h1>TriNetra · Compliance brief</h1>
        <span>SECURITY CONTROLS MAPPING</span>
      </div>

      {!c ? (
        <p className="report-muted">Loading compliance mapping…</p>
      ) : (
        <>
          <h2 className="report-asset">{c.asset_id}</h2>
          <p className="report-sub">
            CIS Controls v8 / NIST CSF / MITRE ATT&amp;CK mapping for threat findings attributed to this asset.
          </p>

          <div className="report-grid">
            <div><b>Generated</b><span>{new Date().toLocaleString()}</span></div>
            <div><b>Asset id</b><span className="mono">{c.asset_id}</span></div>
            <div><b>Threat → control chains</b><span>{(c.controls || []).length}</span></div>
            <div><b>Findings in scope</b><span>{(c.findings || []).length}</span></div>
            <div><b>Severity</b><span>critical — action required</span></div>
            <div><b>Status</b><span className="report-pill">pending</span></div>
          </div>

          <h2 className="report-h2">Control mappings</h2>
          {(c.controls || []).map((ctrl, i) => (
            <div key={i} className="report-ctrl">
              <div className="report-ctrl-top">
                <h3>{ctrl.threat_class}</h3>
                <span style={{ color: SEV[ctrl.severity] || SEV.low }}>{ctrl.severity}</span>
              </div>
              <p className="report-muted">{ctrl.description}</p>
              <p><span className="report-k">NIST CSF</span> {ctrl.nist_csf || "—"}</p>
              <p><span className="report-k">CIS Controls</span> {(ctrl.cis_controls || []).join(" · ") || "—"}</p>
              <p><span className="report-k">MITRE ATT&amp;CK</span> {(ctrl.mitre_attack || []).join(", ") || "—"}</p>
              <p><span className="report-k">Status</span>{" "}<span className="report-pill">{ctrl.status || "pending"}</span></p>
            </div>
          ))}
          {(c.controls || []).length === 0 && (
            <p className="report-muted">No mapped controls for this asset.</p>
          )}

          <h2 className="report-h2">Attributed findings</h2>
          <table className="report-table">
            <thead>
              <tr><th>Threat class</th><th>Severity</th><th>Source</th><th>Summary</th></tr>
            </thead>
            <tbody>
              {(c.findings || []).map((f, i) => (
                <tr key={i}>
                  <td className="mono">{f.threat_class}</td>
                  <td>{f.severity}</td>
                  <td className="mono">{f.src || f.evidence?.src || (f.alert && f.alert.src) || "—"}</td>
                  <td>{f.message || f.summary || ""}</td>
                </tr>
              ))}
              {(c.findings || []).length === 0 && (
                <tr><td colSpan={4} className="report-muted">No live findings recorded for this asset in the current session.</td></tr>
              )}
            </tbody>
          </table>

          {(c.summary_markdown || "") && (
            <>
              <h2 className="report-h2">Analyst brief</h2>
              <pre className="report-pre">{c.summary_markdown}</pre>
            </>
          )}
        </>
      )}

      <footer className="report-foot">
        TriNetra Unified Logging &amp; Pipeline Framework — advisory mapping; validate against your
        organisation's current control baseline.
      </footer>
    </div>
  );
}