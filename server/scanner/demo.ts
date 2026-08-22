import type { ScanResult } from "@shared/security";
import { scoreFromFactors, severityFromScore } from "./rules";
import { RULES } from "./rules";

function demoFinding(ruleId: string, endpoint: string, evidence: string): ScanResult["findings"][number] {
  const rule = RULES[ruleId];
  const score = scoreFromFactors(rule.impact, rule.exploitability);
  return {
    id: `${ruleId}-demo-${endpoint.includes("/api") ? "api" : "home"}`,
    ruleId,
    title: rule.title,
    category: rule.category,
    severity: severityFromScore(score),
    originalSeverity: severityFromScore(score),
    score,
    confidence: rule.confidence,
    endpoint,
    evidence,
    rationale: { impact: rule.impact, exploitability: rule.exploitability, score, explanation: `Impact ${rule.impact}/10 and exploitability ${rule.exploitability}/10 produce the documented ${score}/10 assessment score.` },
    reference: rule.reference,
    remediation: rule.remediation,
    status: "open",
    source: "demo",
  };
}

export function getDemoScanResult(): ScanResult {
  const targetUrl = "https://demo.arzens.example";
  const findings = [
    demoFinding("ARS-CORS-001", `${targetUrl}/api/public/catalog`, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: false\nEvidence fixture contains no customer data."),
    demoFinding("ARS-HEAD-001", `${targetUrl}/`, "Content-Security-Policy header absent in the fixture response.\nserver: DemoGateway/1.0"),
    demoFinding("ARS-COOKIE-002", `${targetUrl}/signin`, "Set-Cookie: session=[REDACTED]; Secure; SameSite=Lax\nHttpOnly flag absent in fixture."),
    demoFinding("ARS-DISC-001", `${targetUrl}/api/health`, "x-powered-by: Express\nFixture evidence has been normalized and redacted."),
    demoFinding("ARS-HEAD-003", `${targetUrl}/assets/app.js`, "X-Content-Type-Options header absent in the fixture response."),
  ];
  const score = Math.round((findings.reduce((total, item) => total + item.score, 0) / findings.length) * 10) / 10;
  return {
    targetUrl,
    profile: "safe_passive",
    summary: { score, severity: "medium", scannedEndpoints: 5, findingCount: findings.length, durationMs: 1840 },
    endpoints: [
      { url: `${targetUrl}/`, statusCode: 200, contentType: "text/html", discoveredBy: "seed" },
      { url: `${targetUrl}/signin`, statusCode: 200, contentType: "text/html", discoveredBy: "link" },
      { url: `${targetUrl}/api/public/catalog`, statusCode: 200, contentType: "application/json", discoveredBy: "response" },
      { url: `${targetUrl}/api/health`, statusCode: 200, contentType: "application/json", discoveredBy: "link" },
      { url: `${targetUrl}/assets/app.js`, statusCode: 200, contentType: "application/javascript", discoveredBy: "link" },
    ],
    findings,
    activity: [
      { at: "2026-08-22T08:32:11.000Z", label: "Demo fixture loaded", detail: "No third-party system was contacted." },
      { at: "2026-08-22T08:32:12.000Z", label: "Scope validated", detail: "Safe Passive profile; five fixture endpoints within scope." },
      { at: "2026-08-22T08:32:13.000Z", label: "Evidence normalized", detail: "Headers and body values were redacted before storage." },
      { at: "2026-08-22T08:32:13.840Z", label: "Assessment complete", detail: "Five deduplicated, explainable findings are ready for review." },
    ],
  };
}
