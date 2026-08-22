type ReportDetail = {
  scan: { id: string; targetUrl: string; profile: string; status: string; riskScore: number; overallSeverity: string; endpointCount: number; findingCount: number; createdAt: Date; completedAt: Date | null };
  endpoints: Array<{ url: string; statusCode: number; contentType: string | null; discoveredBy: string }>;
  findings: Array<{ id: string; ruleId: string; title: string; category: string; severity: string; originalSeverity: string; scoreTenth: number; confidence: string; endpoint: string; evidence: string; remediation: string; status: string; reviewerNote: string | null; reference: string }>;
  events: Array<{ label: string; detail: string; createdAt: Date }>;
};

function escapeHtml(value: string) {
  return value.replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character] || character);
}

function severityClass(severity: string) {
  return severity === "critical" ? "critical" : severity === "high" ? "high" : severity === "medium" ? "medium" : "low";
}

export function createJsonReport(detail: ReportDetail) {
  return JSON.stringify({
    generatedAt: new Date().toISOString(),
    responsibleUse: "This bounded assessment is advisory. It does not prove exploitability and must be used only for authorized targets.",
    scope: { target: detail.scan.targetUrl, profile: detail.scan.profile, endpointCount: detail.scan.endpointCount },
    riskSummary: { score: detail.scan.riskScore / 10, severity: detail.scan.overallSeverity, findingCount: detail.scan.findingCount },
    methodology: ["Strict target/redirect safety validation", "Bounded same-origin discovery", "Safe-passive header, cookie, CORS, transport, content, and disclosure inspection", "Evidence redaction before persistence and report generation"],
    findings: detail.findings.map(finding => ({ ...finding, score: finding.scoreTenth / 10 })),
    limitations: ["Unauthenticated assessment", "No destructive payloads", "No proof of exploitability", "AI guidance is advisory and never auto-applied"],
  }, null, 2);
}

export function createHtmlReport(detail: ReportDetail) {
  const score = (detail.scan.riskScore / 10).toFixed(1);
  const findingRows = detail.findings.map(item => `
    <article class="finding">
      <div class="finding-heading"><span class="badge ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span><span class="rule">${escapeHtml(item.ruleId)}</span></div>
      <h3>${escapeHtml(item.title)}</h3>
      <p class="meta">${escapeHtml(item.category)} · ${escapeHtml(item.endpoint)} · Confidence: ${escapeHtml(item.confidence)} · Score: ${(item.scoreTenth / 10).toFixed(1)}/10</p>
      <h4>Evidence</h4><pre>${escapeHtml(item.evidence)}</pre>
      <h4>Recommended remediation</h4><p>${escapeHtml(item.remediation)}</p>
      <p class="meta">Status: ${escapeHtml(item.status)}${item.reviewerNote ? ` · Reviewer note: ${escapeHtml(item.reviewerNote)}` : ""}</p>
      <p class="meta">Reference: ${escapeHtml(item.reference)}</p>
    </article>`).join("\n");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>Arzens Sentinel Assessment Report</title><style>
    :root{color-scheme:light;font-family:Inter,Arial,sans-serif}*{box-sizing:border-box}body{margin:0;color:#172128;background:#f6f7f4;line-height:1.55}.page{max-width:980px;margin:0 auto;padding:52px}.hero{background:#0c1517;color:#f4f1e8;padding:42px;border-radius:20px;border-bottom:6px solid #d8a841}.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:11px;color:#e6c576;font-weight:700}.hero h1{font-size:34px;line-height:1.1;margin:10px 0}.hero p{color:#becac6;max-width:650px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:22px 0}.metric{background:#fff;border:1px solid #dbe0dc;border-radius:14px;padding:18px}.metric strong{font-size:26px;display:block}.section{background:#fff;border:1px solid #dbe0dc;border-radius:18px;padding:28px;margin:20px 0}h2{font-size:20px;margin:0 0 10px}h3{font-size:17px;margin:12px 0 4px}h4{font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin:18px 0 6px;color:#53615e}.finding{border-top:1px solid #e3e8e3;padding:20px 0}.finding:first-of-type{border-top:0}.finding-heading{display:flex;gap:10px;align-items:center}.badge{padding:3px 8px;border-radius:99px;font-size:11px;font-weight:800;text-transform:uppercase}.critical{background:#fee2e2;color:#991b1b}.high{background:#ffedd5;color:#9a3412}.medium{background:#fef3c7;color:#854d0e}.low{background:#dbeafe;color:#1d4ed8}.rule,.meta{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#5f6c68}pre{white-space:pre-wrap;word-break:break-word;background:#f5f7f5;border:1px solid #e5e9e5;padding:12px;border-radius:10px;font-size:11px}.notice{border-left:4px solid #d8a841;background:#fff8df;padding:14px}.footer{font-size:11px;color:#5f6c68;margin-top:28px}@media print{body{background:#fff}.page{padding:0}.hero{border-radius:0}.section,.metric{break-inside:avoid}.finding{break-inside:avoid}}</style></head><body><main class="page">
    <header class="hero"><div class="eyebrow">Arzens Sentinel / Security Assessment</div><h1>Bounded Web Security Assessment</h1><p>Prepared for ${escapeHtml(detail.scan.targetUrl)}. This report is evidence-led and advisory; it does not establish exploitability or replace a professional penetration test.</p></header>
    <section class="grid"><div class="metric"><span>Risk score</span><strong>${score}/10</strong><span>${escapeHtml(detail.scan.overallSeverity)}</span></div><div class="metric"><span>Findings</span><strong>${detail.scan.findingCount}</strong><span>deduplicated</span></div><div class="metric"><span>Endpoints</span><strong>${detail.scan.endpointCount}</strong><span>same-origin scope</span></div></section>
    <section class="section"><h2>Scope & methodology</h2><p><strong>Target:</strong> ${escapeHtml(detail.scan.targetUrl)}<br/><strong>Profile:</strong> ${escapeHtml(detail.scan.profile)}<br/><strong>Completed:</strong> ${detail.scan.completedAt?.toISOString() || detail.scan.createdAt.toISOString()}</p><p>The safe-passive profile validates the URL and redirects, bounds same-origin discovery, applies timeout/page/response limits, and reviews observable transport, header, cookie, CORS, mixed-content, and disclosure signals. Values that resemble credentials or tokens are redacted before they enter the report.</p></section>
    <section class="section"><h2>Findings & remediation</h2>${findingRows || "<p>No findings were recorded in this assessment.</p>"}</section>
    <section class="section"><h2>Limitations & responsible use</h2><div class="notice">Use this report only for systems you are authorized to assess. Findings are based on bounded unauthenticated observation, not exploitation. AI-supported guidance, where available, is advisory and must be validated before use. No patch is ever applied automatically.</div></section>
    <p class="footer">Generated by Arzens Sentinel at ${new Date().toISOString()} · Redacted evidence · ${escapeHtml(detail.scan.id)}</p></main></body></html>`;
}

function pdfEscape(value: string) {
  return value.replace(/[^\x20-\x7E]/g, "?").replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

export function createPdfReport(detail: ReportDetail): Buffer {
  const lines = [
    "ARZENS SENTINEL — BOUNDED WEB SECURITY ASSESSMENT",
    `Target: ${detail.scan.targetUrl}`,
    `Profile: ${detail.scan.profile} | Risk score: ${(detail.scan.riskScore / 10).toFixed(1)}/10 (${detail.scan.overallSeverity})`,
    `Endpoints: ${detail.scan.endpointCount} | Findings: ${detail.scan.findingCount}`,
    "",
    "Scope & methodology",
    "Safe-passive, same-origin, bounded assessment with evidence redaction. No destructive payloads or exploitation.",
    "",
    "Findings",
    ...detail.findings.flatMap((item, index) => [
      `${index + 1}. [${item.severity.toUpperCase()}] ${item.ruleId} — ${item.title}`,
      `   Endpoint: ${item.endpoint}`,
      `   Evidence: ${item.evidence.replace(/\s+/g, " ").slice(0, 150)}`,
      `   Remediation: ${item.remediation.slice(0, 210)}`,
      "",
    ]),
    "Limitations & responsible use",
    "This report is advisory and does not prove exploitability. Use only for authorized systems. Verify remediation before deployment.",
  ];
  const content = ["BT", "/F1 10 Tf", "50 760 Td", "13 TL", ...lines.map((line, index) => `${index === 0 ? "" : "T* "}(${pdfEscape(line)}) Tj`), "ET"].join("\n");
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
    `<< /Length ${Buffer.byteLength(content, "utf8")} >>\nstream\n${content}\nendstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  let output = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((object, index) => { offsets.push(Buffer.byteLength(output, "utf8")); output += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(output, "utf8");
  output += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.slice(1).map(offset => `${String(offset).padStart(10, "0")} 00000 n \n`).join("")}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(output, "utf8");
}
