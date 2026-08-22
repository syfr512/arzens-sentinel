import { createHash } from "node:crypto";
import type { ScannerFinding } from "@shared/security";
import { RULES, scoreFromFactors, severityFromScore } from "./rules";

export type ZapAlertFixture = { alert: string; riskcode: string; confidence: string; url: string; evidence?: string; reference?: string };

const ZAP_RULE_MAP: Record<string, string> = {
  "Content Security Policy (CSP) Header Not Set": "ARS-HEAD-001",
  "Strict-Transport-Security Header Not Set": "ARS-HEAD-002",
  "X-Content-Type-Options Header Missing": "ARS-HEAD-003",
  "Cross-Domain Misconfiguration": "ARS-CORS-001",
};

export function normalizeZapAlert(alert: ZapAlertFixture): ScannerFinding {
  const ruleId = ZAP_RULE_MAP[alert.alert] || "ARS-DISC-001";
  const rule = RULES[ruleId];
  const score = scoreFromFactors(rule.impact, rule.exploitability);
  return {
    id: `${ruleId}-zap-${createHash("sha256").update(`${alert.url}:${alert.alert}`).digest("hex").slice(0, 10)}`,
    ruleId,
    title: rule.title,
    category: rule.category,
    severity: severityFromScore(score),
    originalSeverity: severityFromScore(score),
    score,
    confidence: alert.confidence.toLowerCase().includes("high") ? "high" : "medium",
    endpoint: alert.url,
    evidence: alert.evidence || "Local ZAP adapter alert; preserve evidence redaction before persistence.",
    rationale: { impact: rule.impact, exploitability: rule.exploitability, score, explanation: `Normalized from local OWASP ZAP alert \"${alert.alert}\" into the stable ${ruleId} catalog rule.` },
    reference: alert.reference || rule.reference,
    remediation: rule.remediation,
    status: "open",
    source: "zap",
  };
}
