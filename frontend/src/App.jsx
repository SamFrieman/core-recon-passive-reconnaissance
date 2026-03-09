import { useState, useEffect, useCallback, useRef } from "react";

/* ─── Google Font: JetBrains Mono + Syne ───────────────────────────────── */
const fontLink = document.createElement("link");
fontLink.rel = "stylesheet";
fontLink.href = "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;600;800&display=swap";
document.head.appendChild(fontLink);

/* ─── CSS variables + global reset ─────────────────────────────────────── */
const injectStyles = () => {
  const style = document.createElement("style");
  style.textContent = `
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:        #0b0c0e;
      --bg2:       #111316;
      --bg3:       #181b1f;
      --border:    #242830;
      --border2:   #2e3340;
      --amber:     #f5a623;
      --amber-dim: #8a5d12;
      --green:     #39d98a;
      --green-dim: #1a6640;
      --red:       #ff4f4f;
      --red-dim:   #6b1c1c;
      --blue:      #5b8dee;
      --blue-dim:  #1e3266;
      --text:      #d4d8e1;
      --text-dim:  #5c6270;
      --text-mid:  #8a909e;
      --mono:      'JetBrains Mono', monospace;
      --display:   'Syne', sans-serif;
    }

    html, body, #root {
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: var(--mono);
      font-size: 13px;
      -webkit-font-smoothing: antialiased;
    }

    ::selection { background: var(--amber-dim); color: var(--amber); }

    ::-webkit-scrollbar { width: 4px; height: 4px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

    /* Scan progress node pulse */
    @keyframes nodePulse {
      0%, 100% { box-shadow: 0 0 0 0 rgba(245,166,35,0.6); }
      50%       { box-shadow: 0 0 0 6px rgba(245,166,35,0); }
    }
    @keyframes scanline {
      0%   { transform: translateY(-100%); opacity: 0.04; }
      100% { transform: translateY(100vh); opacity: 0.04; }
    }
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(10px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes blink {
      0%, 49% { opacity: 1; }
      50%,100% { opacity: 0; }
    }
    @keyframes progressFill {
      from { width: 0%; }
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .fade-up {
      animation: fadeUp 0.35s ease both;
    }

    .panel {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 2px;
    }

    .panel-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 10px;
      font-weight: 500;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--text-dim);
    }

    .panel-header .label { color: var(--text-mid); }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 1px 6px;
      border-radius: 2px;
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }

    .badge-ok       { background: #0d2d1c; color: var(--green);  border: 1px solid var(--green-dim); }
    .badge-timeout  { background: #2d1a0d; color: var(--amber);  border: 1px solid var(--amber-dim); }
    .badge-fail     { background: var(--red-dim); color: var(--red);    border: 1px solid #8b2020; }
    .badge-miss     { background: #1a1c22; color: var(--text-dim); border: 1px solid var(--border2); }
    .badge-scanning { background: #1a1c22; color: var(--amber);  border: 1px solid var(--amber-dim);
                      animation: nodePulse 1.4s ease-in-out infinite; }

    .risk-critical { color: var(--red); }
    .risk-high     { color: #ff8c42; }
    .risk-medium   { color: var(--amber); }
    .risk-low      { color: var(--blue); }
    .risk-minimal  { color: var(--green); }

    .dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
    .dot-green  { background: var(--green); }
    .dot-amber  { background: var(--amber); }
    .dot-red    { background: var(--red); }
    .dot-dim    { background: var(--text-dim); }
    .dot-blue   { background: var(--blue); }
  `;
  document.head.appendChild(style);
};
injectStyles();

/* ─── Helpers ───────────────────────────────────────────────────────────── */
// Use relative /api path — Vercel rewrites proxy this to Render backend.
// For local dev, vite.config.js proxies /api → http://127.0.0.1:8000
const API = "";

function riskClass(level) {
  return {
    CRITICAL: "risk-critical",
    HIGH:     "risk-high",
    MEDIUM:   "risk-medium",
    LOW:      "risk-low",
    MINIMAL:  "risk-minimal",
  }[level] ?? "risk-medium";
}

function riskDotClass(level) {
  return {
    CRITICAL: "dot dot-red",
    HIGH:     "dot dot-red",
    MEDIUM:   "dot dot-amber",
    LOW:      "dot dot-blue",
    MINIMAL:  "dot dot-green",
  }[level] ?? "dot dot-dim";
}

function moduleStatusBadge(status) {
  const map = {
    OK:          ["OK", "badge badge-ok"],
    SOFT_FAIL:   ["FAIL", "badge badge-fail"],
    TIMEOUT:     ["TIMEOUT", "badge badge-timeout"],
    UNAVAILABLE: ["N/A", "badge badge-miss"],
  };
  const [label, cls] = map[status] ?? ["...", "badge badge-scanning"];
  return <span className={cls}>{label}</span>;
}

function scoreGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/* ─── Sub-components (all defined outside App to prevent re-mount) ──────── */

/* Scan progress pipeline */
function ModulePipeline({ moduleStatus, moduleTimings, scanning }) {
  const modules = [
    { key: "infrastructure", label: "INFRA" },
    { key: "dns",            label: "DNS" },
    { key: "fingerprint",    label: "HTTP" },
    { key: "ssl_certificate",label: "TLS" },
    { key: "subdomains",     label: "SUBS" },
    { key: "wayback",        label: "WBK" },
    { key: "whois",          label: "WHOIS" },
    { key: "technology",     label: "TECH" },
  ];

  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", padding: "12px 14px" }}>
      {modules.map(({ key, label }) => {
        const status = moduleStatus?.[key]?.status;
        const timing = moduleTimings?.[key];
        const isActive = scanning && !status;

        return (
          <div key={key} style={{
            display: "flex", flexDirection: "column", alignItems: "center",
            gap: 4, minWidth: 52,
          }}>
            <div style={{
              width: 48, height: 48,
              background: isActive ? "#1a1c22" : (status === "OK" ? "#0d2d1c" : status ? "#1a1c22" : "#111316"),
              border: `1px solid ${isActive ? "var(--amber-dim)" : status === "OK" ? "var(--green-dim)" : status === "SOFT_FAIL" ? "#6b1c1c" : status === "TIMEOUT" ? "var(--amber-dim)" : "var(--border)"}`,
              borderRadius: 2,
              display: "flex", alignItems: "center", justifyContent: "center",
              animation: isActive ? "nodePulse 1.4s ease-in-out infinite" : "none",
              transition: "all 0.3s ease",
            }}>
              {status === "OK" && (
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M3 8l4 4 6-6" stroke="var(--green)" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              )}
              {(status === "SOFT_FAIL" || status === "TIMEOUT") && (
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M4 4l8 8M12 4l-8 8" stroke={status === "TIMEOUT" ? "var(--amber)" : "var(--red)"} strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              )}
              {status === "UNAVAILABLE" && (
                <span style={{ color: "var(--text-dim)", fontSize: 14, fontWeight: 700 }}>—</span>
              )}
              {isActive && (
                <div style={{
                  width: 16, height: 16, border: "2px solid transparent",
                  borderTopColor: "var(--amber)", borderRadius: "50%",
                  animation: "spin 0.8s linear infinite",
                }} />
              )}
            </div>
            <span style={{ fontSize: 9, color: isActive ? "var(--amber)" : status === "OK" ? "var(--green)" : "var(--text-dim)", letterSpacing: "0.06em", fontWeight: 600 }}>
              {label}
            </span>
            {timing > 0 && (
              <span style={{ fontSize: 8, color: "var(--text-dim)" }}>{timing}s</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* Risk gauge — score=100 is best (green), score=0 is critical (red) */
function RiskGauge({ score, level }) {
  const pct = score; // higher = better = more fill
  const trackColor = {
    MINIMAL:  "var(--green)",
    LOW:      "var(--blue)",
    MEDIUM:   "var(--amber)",
    HIGH:     "#ff8c42",
    CRITICAL: "var(--red)",
  }[level] ?? "var(--amber)";

  const grade = scoreGrade(score);

  return (
    <div style={{ padding: "14px", display: "flex", flexDirection: "column", gap: 10 }}>
      {/* Grade + score row */}
      <div style={{ display: "flex", alignItems: "flex-end", gap: 10 }}>
        <span style={{
          fontFamily: "var(--display)", fontSize: 52, fontWeight: 800, lineHeight: 1,
          color: trackColor, letterSpacing: "-0.04em",
        }}>
          {grade}
        </span>
        <div style={{ paddingBottom: 8 }}>
          <div style={{ fontFamily: "var(--display)", fontSize: 28, fontWeight: 600, color: trackColor, lineHeight: 1 }}>
            {score}
          </div>
          <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", marginTop: 2 }}>
            /100 — {level}
          </div>
        </div>
      </div>

      {/* Bar — fill = score (100 = full green, 0 = empty critical) */}
      <div style={{ position: "relative", height: 6, background: "var(--bg3)", borderRadius: 1, overflow: "hidden" }}>
        <div style={{
          position: "absolute", left: 0, top: 0, bottom: 0,
          width: `${pct}%`, background: trackColor,
          animation: "progressFill 0.8s cubic-bezier(0.4,0,0.2,1) both",
          transition: "width 0.5s ease",
        }} />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: "var(--text-dim)" }}>
        <span>CRITICAL</span>
        <span>OPTIMAL</span>
      </div>
    </div>
  );
}

/* Executive summary panel */
function ExecutiveSummaryPanel({ summary }) {
  if (!summary) return null;
  const { security_posture, key_risks = [], infrastructure_observations = [], dns_security_assessment = [], subdomain_exposure, intelligence_highlights = [] } = summary;

  return (
    <div className="panel fade-up" style={{ animationDelay: "0.1s" }}>
      <div className="panel-header">
        <span style={{ color: "var(--amber)" }}>◈</span>
        <span className="label">Executive Summary</span>
      </div>
      <div style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 14 }}>
        {security_posture && (
          <p style={{ color: "var(--text)", lineHeight: 1.7, fontSize: 12, borderLeft: "2px solid var(--amber)", paddingLeft: 10 }}>
            {security_posture}
          </p>
        )}

        {key_risks.length > 0 && (
          <div>
            <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6 }}>Key Risks</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {key_risks.map((r, i) => (
                <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                  <span style={{
                    fontSize: 9, fontWeight: 700, padding: "1px 5px", borderRadius: 2,
                    background: r.severity === "CRITICAL" ? "var(--red-dim)" : r.severity === "HIGH" ? "#2d1a0d" : "#1a1c22",
                    color: r.severity === "CRITICAL" ? "var(--red)" : r.severity === "HIGH" ? "#ff8c42" : "var(--text-dim)",
                    flexShrink: 0, marginTop: 1,
                  }}>
                    {r.severity}
                  </span>
                  <span style={{ color: "var(--text)", lineHeight: 1.5 }}>{r.finding}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {infrastructure_observations.length > 0 && (
          <div>
            <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6 }}>Infrastructure</div>
            {infrastructure_observations.map((obs, i) => (
              <div key={i} style={{ display: "flex", gap: 8, marginBottom: 3 }}>
                <span style={{ color: "var(--text-dim)", flexShrink: 0 }}>›</span>
                <span style={{ color: "var(--text-mid)" }}>{obs}</span>
              </div>
            ))}
          </div>
        )}

        {dns_security_assessment.length > 0 && (
          <div>
            <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6 }}>DNS / Email Auth</div>
            {dns_security_assessment.map((item, i) => (
              <div key={i} style={{ display: "flex", gap: 8, marginBottom: 3 }}>
                <span style={{ color: "var(--text-dim)", flexShrink: 0 }}>›</span>
                <span style={{ color: "var(--text-mid)" }}>{item}</span>
              </div>
            ))}
          </div>
        )}

        {subdomain_exposure && (
          <div style={{ padding: "8px 10px", background: "var(--bg3)", border: "1px solid var(--border2)", borderRadius: 2 }}>
            <span style={{ color: "var(--text-dim)", fontSize: 10 }}>
              {subdomain_exposure.total_subdomains} subdomains discovered
              {subdomain_exposure.high_risk_count > 0 && (
                <span style={{ color: "var(--red)", marginLeft: 6 }}>
                  — {subdomain_exposure.high_risk_count} high-risk
                </span>
              )}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

/* Intelligence correlations */
function CorrelationsPanel({ correlations = [] }) {
  if (!correlations.length) return null;
  return (
    <div className="panel fade-up" style={{ animationDelay: "0.15s" }}>
      <div className="panel-header">
        <span style={{ color: "var(--blue)" }}>⊛</span>
        <span className="label">Intelligence Correlations</span>
        <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--text-dim)" }}>{correlations.length}</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column" }}>
        {correlations.map((c, i) => (
          <div key={i} style={{
            padding: "10px 14px",
            borderBottom: i < correlations.length - 1 ? "1px solid var(--border)" : "none",
            display: "flex", gap: 10, alignItems: "flex-start",
          }}>
            <span style={{
              fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 2, flexShrink: 0,
              background: c.severity === "CRITICAL" ? "var(--red-dim)" : c.severity === "HIGH" ? "#2d1a0d" : "#1a1c22",
              color: c.severity === "CRITICAL" ? "var(--red)" : c.severity === "HIGH" ? "#ff8c42" : "var(--text-dim)",
              marginTop: 1,
            }}>
              {c.severity ?? "INFO"}
            </span>
            <div style={{ flex: 1 }}>
              {c.correlation_type && (
                <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.08em", marginBottom: 2, textTransform: "uppercase" }}>
                  {c.correlation_type}
                </div>
              )}
              <div style={{ color: "var(--text)", lineHeight: 1.5, fontSize: 12 }}>{c.description}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* Exposed assets */
function ExposedAssetsPanel({ assets = [], summary }) {
  if (!assets.length) return null;
  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, MINIMAL: 4 };
  const sorted = [...assets].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  return (
    <div className="panel fade-up" style={{ animationDelay: "0.2s" }}>
      <div className="panel-header">
        <span style={{ color: "var(--red)" }}>◉</span>
        <span className="label">Exposed Assets</span>
        <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--red)" }}>{assets.length}</span>
      </div>
      {summary && (
        <div style={{
          padding: "8px 14px", borderBottom: "1px solid var(--border)",
          display: "flex", gap: 16, fontSize: 10, color: "var(--text-dim)",
        }}>
          {summary.critical_count > 0 && <span style={{ color: "var(--red)" }}>{summary.critical_count} CRITICAL</span>}
          {summary.high_count > 0 && <span style={{ color: "#ff8c42" }}>{summary.high_count} HIGH</span>}
          {summary.medium_count > 0 && <span style={{ color: "var(--amber)" }}>{summary.medium_count} MEDIUM</span>}
        </div>
      )}
      <div style={{ maxHeight: 240, overflowY: "auto" }}>
        {sorted.slice(0, 20).map((asset, i) => (
          <div key={i} style={{
            padding: "8px 14px",
            borderBottom: "1px solid var(--border)",
            display: "flex", gap: 10, alignItems: "center",
          }}>
            <div className={riskDotClass(asset.severity)} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {asset.hostname}
              </div>
              {asset.risk_reason && (
                <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 1 }}>{asset.risk_reason}</div>
              )}
            </div>
            <span style={{
              fontSize: 9, fontWeight: 700, padding: "1px 5px",
              background: "var(--bg3)", borderRadius: 2, color: asset.severity === "CRITICAL" ? "var(--red)" : asset.severity === "HIGH" ? "#ff8c42" : "var(--text-dim)",
              flexShrink: 0,
            }}>
              {asset.exposure_type ?? asset.severity}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* Subdomains list */
function SubdomainList({ subdomains }) {
  const list = subdomains?.subdomains ?? [];
  if (!list.length) return null;
  return (
    <div className="panel fade-up">
      <div className="panel-header">
        <span style={{ color: "var(--text-dim)" }}>⊞</span>
        <span className="label">Subdomains</span>
        <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--text-dim)" }}>{list.length}</span>
      </div>
      <div style={{ maxHeight: 200, overflowY: "auto" }}>
        {list.map((sub, i) => (
          <div key={i} style={{
            padding: "5px 14px", borderBottom: "1px solid var(--border)",
            display: "flex", gap: 8, alignItems: "center", fontSize: 11,
          }}>
            <span style={{ color: "var(--text-dim)" }}>›</span>
            <span style={{ color: "var(--text)" }}>{sub}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* Technology stack */
function TechnologyStack({ technology }) {
  if (!technology) return null;

  // New module returns {category: [{name, version, eol_risk, eol_note}]}
  // Old module returned {detected_technologies: [...]}
  // Handle both gracefully
  let categories = {};
  if (technology.detected_technologies) {
    // Legacy flat array — group under "Detected"
    const arr = technology.detected_technologies;
    if (!arr.length) return null;
    categories = { "Detected": arr.map(t => ({ name: t.name ?? t, version: t.version, eol_risk: false, eol_note: null })) };
  } else {
    // New categorized object — filter out meta keys like "error"/"note"
    Object.entries(technology).forEach(([cat, items]) => {
      if (Array.isArray(items) && items.length) categories[cat] = items;
    });
  }

  if (!Object.keys(categories).length) return null;

  const totalCount = Object.values(categories).reduce((s, items) => s + items.length, 0);
  const eolCount   = Object.values(categories).flat().filter(t => t.eol_risk).length;

  // Category icon map
  const catIcon = (cat) => {
    const c = cat.toLowerCase();
    if (c.includes("server"))     return "⬡";
    if (c.includes("framework"))  return "◈";
    if (c.includes("cms"))        return "▦";
    if (c.includes("javascript") || c.includes("library")) return "◆";
    if (c.includes("css"))        return "◇";
    if (c.includes("cdn"))        return "◎";
    if (c.includes("analytic"))   return "◉";
    if (c.includes("security"))   return "◐";
    if (c.includes("e-commerce") || c.includes("ecommerce")) return "◑";
    if (c.includes("language"))   return "◭";
    return "·";
  };

  return (
    <div className="panel fade-up">
      <div className="panel-header" style={{ justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ color: "var(--amber)" }}>⬡</span>
          <span className="label">Technology Stack</span>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{totalCount} detected</span>
          {eolCount > 0 && (
            <span style={{ fontSize: 10, color: "var(--red)", background: "rgba(255,80,80,0.08)", padding: "2px 6px", borderRadius: 2 }}>
              ⚠ {eolCount} EOL
            </span>
          )}
        </div>
      </div>

      <div style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 14 }}>
        {Object.entries(categories).map(([cat, items]) => (
          <div key={cat}>
            {/* Category header */}
            <div style={{
              display: "flex", alignItems: "center", gap: 6,
              marginBottom: 8, paddingBottom: 4,
              borderBottom: "1px solid var(--border)",
            }}>
              <span style={{ color: "var(--text-dim)", fontSize: 11 }}>{catIcon(cat)}</span>
              <span style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--text-dim)", textTransform: "uppercase" }}>{cat}</span>
              <span style={{ fontSize: 10, color: "var(--border2)", marginLeft: 2 }}>({items.length})</span>
            </div>

            {/* Tech chips */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {items.map((tech, i) => (
                <div key={i} style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "4px 9px",
                  background: tech.eol_risk ? "rgba(255,80,80,0.07)" : "var(--bg3)",
                  border: `1px solid ${tech.eol_risk ? "rgba(255,80,80,0.35)" : "var(--border2)"}`,
                  borderRadius: 2,
                  fontSize: 11,
                  color: tech.eol_risk ? "var(--red)" : "var(--text-mid)",
                  title: tech.eol_note ?? "",
                  cursor: tech.eol_note ? "help" : "default",
                }} title={tech.eol_note ?? undefined}>
                  {tech.eol_risk && <span style={{ fontSize: 9, color: "var(--red)" }}>⚠</span>}
                  <span>{tech.name}</span>
                  {tech.version && tech.version !== "Detected" && (
                    <span style={{ color: "var(--text-dim)", fontSize: 10, marginLeft: 1 }}>
                      {tech.version}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* Recommendations */
function RecommendationsPanel({ recommendations = [], riskIssues = [] }) {
  if (!recommendations.length && !riskIssues.length) return null;
  return (
    <div className="panel fade-up">
      <div className="panel-header">
        <span style={{ color: "var(--green)" }}>▶</span>
        <span className="label">Recommendations</span>
      </div>
      <div style={{ padding: "10px 14px", display: "flex", flexDirection: "column", gap: 6 }}>
        {recommendations.map((rec, i) => (
          <div key={i} style={{ display: "flex", gap: 8, padding: "6px 0", borderBottom: i < recommendations.length - 1 ? "1px solid var(--border)" : "none" }}>
            <span style={{ color: "var(--green)", flexShrink: 0, marginTop: 1 }}>→</span>
            <span style={{ color: "var(--text)", lineHeight: 1.5 }}>{rec}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* History panel */
function HistoryPanel({ history = [], onSelect }) {
  if (!history.length) return null;
  return (
    <div className="panel">
      <div className="panel-header">
        <span style={{ color: "var(--text-dim)" }}>◷</span>
        <span className="label">Scan History</span>
      </div>
      <div style={{ maxHeight: 200, overflowY: "auto" }}>
        {history.map((h, i) => (
          <div key={i}
            onClick={() => onSelect(h.domain ?? h.target)}
            style={{
              padding: "8px 14px", cursor: "pointer",
              borderBottom: "1px solid var(--border)",
              display: "flex", justifyContent: "space-between", alignItems: "center",
              transition: "background 0.15s",
            }}
            onMouseEnter={e => e.currentTarget.style.background = "var(--bg3)"}
            onMouseLeave={e => e.currentTarget.style.background = "transparent"}
          >
            <span style={{ color: "var(--amber)", fontSize: 11 }}>{h.domain ?? h.target}</span>
            <span style={{ color: "var(--text-dim)", fontSize: 10 }}>{h.timestamp}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* DNS details */
function DnsPanel({ dns }) {
  if (!dns || dns.error) return null;
  const { spf, dmarc, dnssec, a_records = [], mx_records = [] } = dns;
  return (
    <div className="panel fade-up">
      <div className="panel-header">
        <span style={{ color: "var(--text-dim)" }}>⬡</span>
        <span className="label">DNS Intelligence</span>
      </div>
      <div style={{ padding: "10px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          <StatusItem label="SPF" ok={spf?.present} value={spf?.present ? "present" : "missing"} />
          <StatusItem label="DMARC" ok={dmarc?.present && dmarc?.policy !== "none"} value={dmarc?.present ? `policy=${dmarc.policy}` : "missing"} />
          <StatusItem label="DNSSEC" ok={dnssec?.enabled} value={dnssec?.enabled ? "enabled" : "disabled"} />
        </div>
        {a_records.length > 0 && (
          <div>
            <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", marginBottom: 4, textTransform: "uppercase" }}>A Records</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {a_records.slice(0, 6).map((ip, i) => (
                <span key={i} style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--text-mid)", padding: "1px 6px", background: "var(--bg3)", border: "1px solid var(--border)" }}>
                  {ip}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StatusItem({ label, ok, value }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <div className={`dot ${ok ? "dot-green" : "dot-red"}`} />
      <span style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>{label}</span>
      <span style={{ fontSize: 10, color: ok ? "var(--green)" : "var(--red)" }}>{value}</span>
    </div>
  );
}

/* TLS/SSL panel */
function TlsPanel({ ssl }) {
  if (!ssl || ssl.error) return null;
  const { grade, protocol, expires_in_days, issuer, san_count, issues = [] } = ssl;
  return (
    <div className="panel fade-up">
      <div className="panel-header">
        <span style={{ color: "var(--text-dim)" }}>🔒</span>
        <span className="label">TLS Certificate</span>
        {grade && (
          <span style={{
            marginLeft: "auto", fontFamily: "var(--display)", fontWeight: 700, fontSize: 16,
            color: grade === "A" || grade === "A+" ? "var(--green)" : grade === "B" ? "var(--blue)" : grade === "C" ? "var(--amber)" : "var(--red)",
          }}>
            {grade}
          </span>
        )}
      </div>
      <div style={{ padding: "10px 14px", display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          {protocol && <StatusItem label="Protocol" ok={protocol?.includes("1.3")} value={protocol} />}
          {expires_in_days !== undefined && (
            <StatusItem label="Expires" ok={expires_in_days > 30} value={`${expires_in_days}d`} />
          )}
          {san_count !== undefined && <StatusItem label="SANs" ok={true} value={san_count} />}
        </div>
        {issuer && <div style={{ fontSize: 10, color: "var(--text-dim)" }}>Issuer: <span style={{ color: "var(--text-mid)" }}>{issuer}</span></div>}
        {issues.length > 0 && (
          <div style={{ marginTop: 4 }}>
            {issues.map((iss, i) => (
              <div key={i} style={{ fontSize: 10, color: "var(--red)", display: "flex", gap: 6 }}>
                <span>!</span><span>{iss}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Main App ──────────────────────────────────────────────────────────── */
export default function App() {
  const [query, setQuery]           = useState("");
  const [scanning, setScanning]     = useState(false);
  const [data, setData]             = useState(null);
  const [error, setError]           = useState(null);
  const [history, setHistory]       = useState([]);
  const [moduleStatus, setModuleStatus]   = useState(null);
  const [moduleTimings, setModuleTimings] = useState(null);
  const inputRef = useRef(null);

  // Fetch history on mount
  useEffect(() => {
    fetch(`${API}/api/v1/history`)
      .then(r => r.json())
      .then(d => setHistory(Array.isArray(d) ? d : []))
      .catch(() => {});
  }, []);

  const runScan = useCallback(async (target) => {
    const q = (target ?? query).trim();
    if (!q) return;

    setScanning(true);
    setData(null);
    setError(null);
    setModuleStatus(null);
    setModuleTimings(null);

    try {
      const res = await fetch(`${API}/api/v1/recon/${encodeURIComponent(q)}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail ?? "Scan failed");
      }
      const json = await res.json();
      setData(json);
      setModuleStatus(json.module_status ?? null);
      setModuleTimings(json.module_timings ?? null);

      // Refresh history
      fetch(`${API}/api/v1/history`)
        .then(r => r.json())
        .then(d => setHistory(Array.isArray(d) ? d : []))
        .catch(() => {});
    } catch (e) {
      setError(e.message);
    } finally {
      setScanning(false);
    }
  }, [query]);

  const handleKey = (e) => {
    if (e.key === "Enter") runScan();
  };

  const riskLevel = data?.risk_level ?? "MEDIUM";
  const riskScore = data?.risk_score ?? 0;

  return (
    <div style={{
      minHeight: "100vh",
      background: "var(--bg)",
      display: "flex",
      flexDirection: "column",
    }}>
      {/* Scanline overlay */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, overflow: "hidden",
      }}>
        <div style={{
          position: "absolute", left: 0, right: 0, height: 2,
          background: "linear-gradient(180deg, transparent, rgba(245,166,35,0.08), transparent)",
          animation: "scanline 8s linear infinite",
        }} />
      </div>

      {/* Header */}
      <header style={{
        position: "sticky", top: 0, zIndex: 10,
        borderBottom: "1px solid var(--border)",
        background: "rgba(11,12,14,0.96)",
        backdropFilter: "blur(8px)",
        padding: "0 20px",
        display: "flex", alignItems: "center", height: 52, gap: 16,
      }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
          <span style={{ fontFamily: "var(--display)", fontSize: 18, fontWeight: 800, color: "var(--amber)", letterSpacing: "-0.02em" }}>
            CORE
          </span>
          <span style={{ fontFamily: "var(--display)", fontSize: 18, fontWeight: 400, color: "var(--text)" }}>
            RECON
          </span>
          <span style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", marginLeft: 4 }}>v2.2</span>
        </div>

        <div style={{ flex: 1, display: "flex", gap: 8, maxWidth: 520 }}>
          <div style={{ flex: 1, position: "relative" }}>
            <input
              ref={inputRef}
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={handleKey}
              placeholder="target domain or IP…"
              disabled={scanning}
              style={{
                width: "100%", padding: "7px 12px",
                background: "var(--bg3)", border: "1px solid var(--border2)",
                borderRadius: 2, color: "var(--text)", fontFamily: "var(--mono)",
                fontSize: 12, outline: "none", transition: "border-color 0.2s",
              }}
              onFocus={e => e.target.style.borderColor = "var(--amber-dim)"}
              onBlur={e => e.target.style.borderColor = "var(--border2)"}
            />
            {scanning && (
              <span style={{
                position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)",
                fontSize: 9, color: "var(--amber)", letterSpacing: "0.1em",
                animation: "blink 1s step-start infinite",
              }}>SCANNING</span>
            )}
          </div>
          <button
            onClick={() => runScan()}
            disabled={scanning || !query.trim()}
            style={{
              padding: "7px 16px",
              background: scanning ? "var(--bg3)" : "var(--amber)",
              border: "none", borderRadius: 2, cursor: scanning ? "not-allowed" : "pointer",
              fontFamily: "var(--mono)", fontWeight: 700, fontSize: 11,
              color: scanning ? "var(--text-dim)" : "#000",
              letterSpacing: "0.08em", transition: "all 0.15s",
            }}
          >
            {scanning ? "RUNNING" : "SCAN"}
          </button>
        </div>

        {data && (
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{data.target}</span>
            <a
              href={`${API}/api/v1/report/${encodeURIComponent(data.target)}`}
              target="_blank" rel="noopener noreferrer"
              style={{
                padding: "4px 10px", background: "var(--bg3)",
                border: "1px solid var(--border2)", borderRadius: 2,
                fontSize: 10, color: "var(--text-mid)", textDecoration: "none",
                letterSpacing: "0.06em",
              }}
            >
              ↓ PDF
            </a>
          </div>
        )}
      </header>

      {/* Body */}
      <main style={{ flex: 1, display: "flex", gap: 0, position: "relative", zIndex: 1 }}>

        {/* Left sidebar */}
        <aside style={{
          width: 220, flexShrink: 0,
          borderRight: "1px solid var(--border)",
          padding: "14px 12px",
          display: "flex", flexDirection: "column", gap: 12,
          overflowY: "auto",
        }}>
          <HistoryPanel history={history} onSelect={(d) => { setQuery(d); runScan(d); }} />
        </aside>

        {/* Content */}
        <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>

          {/* Empty state */}
          {!scanning && !data && !error && (
            <div style={{
              display: "flex", flexDirection: "column", alignItems: "center",
              justifyContent: "center", height: "60vh", gap: 12, opacity: 0.4,
            }}>
              <div style={{ fontSize: 48, color: "var(--border2)" }}>◎</div>
              <div style={{ fontFamily: "var(--display)", fontSize: 14, color: "var(--text-dim)", letterSpacing: "0.2em", textTransform: "uppercase" }}>
                Enter a target to begin recon
              </div>
              <div style={{ fontSize: 10, color: "var(--text-dim)" }}>domain · IP · URL</div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div style={{
              padding: "12px 16px",
              background: "var(--red-dim)", border: "1px solid #6b1c1c",
              borderRadius: 2, color: "var(--red)", marginBottom: 12,
            }}>
              ✕ {error}
            </div>
          )}

          {/* Scan in progress */}
          {scanning && (
            <div className="panel fade-up" style={{ marginBottom: 12 }}>
              <div className="panel-header">
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--amber)", animation: "nodePulse 1.4s ease-in-out infinite" }} />
                <span className="label">Scan in progress</span>
                <span style={{ marginLeft: "auto", animation: "blink 1.2s step-start infinite", color: "var(--amber)", fontSize: 10 }}>
                  {query}
                </span>
              </div>
              <ModulePipeline moduleStatus={null} moduleTimings={null} scanning={true} />
            </div>
          )}

          {/* Results */}
          {data && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

              {/* Top row: risk gauge + module pipeline */}
              <div style={{ display: "flex", gap: 12 }}>
                <div className="panel fade-up" style={{ width: 200, flexShrink: 0 }}>
                  <div className="panel-header">
                    <span style={{ color: "var(--text-dim)" }}>◈</span>
                    <span className="label">Risk Score</span>
                  </div>
                  <RiskGauge score={riskScore} level={riskLevel} />
                  {data.scan_duration_seconds && (
                    <div style={{ padding: "0 14px 10px", fontSize: 9, color: "var(--text-dim)" }}>
                      Scan completed in {data.scan_duration_seconds}s
                    </div>
                  )}
                </div>

                <div className="panel fade-up" style={{ flex: 1 }}>
                  <div className="panel-header">
                    <span style={{ color: "var(--text-dim)" }}>⬡</span>
                    <span className="label">Module Status</span>
                  </div>
                  <ModulePipeline
                    moduleStatus={moduleStatus}
                    moduleTimings={moduleTimings}
                    scanning={false}
                  />
                </div>
              </div>

              {/* Risk status text */}
              {data.risk_status && (
                <div style={{
                  padding: "10px 14px",
                  background: "var(--bg2)", border: "1px solid var(--border)",
                  borderLeft: `3px solid ${riskLevel === "CRITICAL" ? "var(--red)" : riskLevel === "HIGH" ? "#ff8c42" : riskLevel === "MEDIUM" ? "var(--amber)" : "var(--green)"}`,
                  borderRadius: 2, fontSize: 12, color: "var(--text)", lineHeight: 1.6,
                }}>
                  {data.risk_status}
                </div>
              )}

              {/* Executive summary */}
              <ExecutiveSummaryPanel summary={data.executive_summary} />

              {/* Correlations */}
              <CorrelationsPanel correlations={data.intelligence_correlations} />

              {/* 2-col grid for detail panels — keep even items to avoid blank cells */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <ExposedAssetsPanel assets={data.exposed_assets} summary={data.exposure_summary} />
                <RecommendationsPanel recommendations={data.recommendations} riskIssues={data.risk_issues} />
                <DnsPanel dns={data.dns} />
                <TlsPanel ssl={data.ssl_certificate} />
              </div>

              {/* Tech stack — full width, categorized */}
              <TechnologyStack technology={data.technology} />

              {/* Subdomains — full width, can be very long */}
              <SubdomainList subdomains={data.subdomains} />

              {/* WHOIS */}
              {data.whois && !data.whois.error && (
                <div className="panel fade-up">
                  <div className="panel-header">
                    <span style={{ color: "var(--text-dim)" }}>◌</span>
                    <span className="label">WHOIS</span>
                  </div>
                  <div style={{ padding: "10px 14px", display: "flex", flexWrap: "wrap", gap: 16 }}>
                    {[
                      ["Registrar", data.whois.registrar],
                      ["Registered", data.whois.creation_date],
                      ["Expires", data.whois.expiration_date],
                      ["Updated", data.whois.updated_date],
                    ].filter(([, v]) => v).map(([k, v]) => (
                      <div key={k}>
                        <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 2 }}>{k}</div>
                        <div style={{ fontSize: 11, color: "var(--text)" }}>{v}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Wayback */}
              {data.wayback && !data.wayback.error && data.wayback.total_snapshots > 0 && (
                <div className="panel fade-up">
                  <div className="panel-header">
                    <span style={{ color: "var(--text-dim)" }}>◷</span>
                    <span className="label">Web Archive</span>
                  </div>
                  <div style={{ padding: "10px 14px", display: "flex", gap: 16, flexWrap: "wrap" }}>
                    <div>
                      <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 2 }}>Snapshots</div>
                      <div style={{ fontSize: 14, fontFamily: "var(--display)", fontWeight: 700, color: "var(--text)" }}>{data.wayback.total_snapshots?.toLocaleString()}</div>
                    </div>
                    {data.wayback.first_seen && (
                      <div>
                        <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 2 }}>First seen</div>
                        <div style={{ fontSize: 11, color: "var(--text)" }}>{data.wayback.first_seen}</div>
                      </div>
                    )}
                    {data.wayback.last_seen && (
                      <div>
                        <div style={{ fontSize: 9, color: "var(--text-dim)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 2 }}>Last seen</div>
                        <div style={{ fontSize: 11, color: "var(--text)" }}>{data.wayback.last_seen}</div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Footer metadata */}
              <div style={{
                padding: "8px 0", fontSize: 9, color: "var(--text-dim)",
                borderTop: "1px solid var(--border)", marginTop: 4,
                display: "flex", gap: 16,
              }}>
                <span>Target: {data.target}</span>
                {data.timestamp && <span>Scanned: {data.timestamp}</span>}
                {data.corerecon_version && <span>CoreRecon {data.corerecon_version}</span>}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
