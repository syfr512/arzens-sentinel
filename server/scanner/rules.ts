import type { Severity } from "@shared/security";

export type RuleDefinition = {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  impact: number;
  exploitability: number;
  confidence: "high" | "medium" | "low";
  reference: string;
  remediation: string;
};

export const RULES: Record<string, RuleDefinition> = {
  "ARS-HEAD-001": {
    id: "ARS-HEAD-001",
    title: "Content Security Policy is not configured",
    category: "Security Headers",
    severity: "medium",
    impact: 6,
    exploitability: 5,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/CSP",
    remediation: "Define a restrictive Content-Security-Policy and tune it using report-only mode before enforcement.",
  },
  "ARS-HEAD-002": {
    id: "ARS-HEAD-002",
    title: "HTTP Strict Transport Security is not configured",
    category: "Transport Security",
    severity: "medium",
    impact: 6,
    exploitability: 4,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    remediation: "Serve HSTS over HTTPS after confirming every subdomain can support HTTPS.",
  },
  "ARS-HEAD-003": {
    id: "ARS-HEAD-003",
    title: "MIME-sniffing protection is not configured",
    category: "Security Headers",
    severity: "low",
    impact: 4,
    exploitability: 4,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
    remediation: "Return X-Content-Type-Options: nosniff with responses that declare correct Content-Type values.",
  },
  "ARS-HEAD-004": {
    id: "ARS-HEAD-004",
    title: "Referrer policy is not configured",
    category: "Privacy Headers",
    severity: "low",
    impact: 3,
    exploitability: 4,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
    remediation: "Set Referrer-Policy to strict-origin-when-cross-origin or a stricter policy appropriate for the application.",
  },
  "ARS-HEAD-005": {
    id: "ARS-HEAD-005",
    title: "Clickjacking protections are not evident",
    category: "Browser Protections",
    severity: "medium",
    impact: 5,
    exploitability: 5,
    confidence: "medium",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
    remediation: "Set frame-ancestors 'none' or an explicit allowlist in CSP, with X-Frame-Options as a legacy defense.",
  },
  "ARS-HEAD-006": {
    id: "ARS-HEAD-006",
    title: "Permissions Policy is not configured",
    category: "Browser Protections",
    severity: "low",
    impact: 3,
    exploitability: 3,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy",
    remediation: "Set a restrictive Permissions-Policy that disables unneeded powerful browser features and allowlists only approved origins.",
  },
  "ARS-HEAD-007": {
    id: "ARS-HEAD-007",
    title: "Content Security Policy permits unsafe inline script execution",
    category: "Security Headers",
    severity: "medium",
    impact: 6,
    exploitability: 5,
    confidence: "medium",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/CSP",
    remediation: "Remove 'unsafe-inline' from script-src where practical; use nonces or hashes for approved inline scripts and validate using report-only mode first.",
  },
  "ARS-COOKIE-001": {
    id: "ARS-COOKIE-001",
    title: "Cookie lacks the Secure attribute",
    category: "Session Security",
    severity: "medium",
    impact: 6,
    exploitability: 5,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Cookies",
    remediation: "Mark session cookies Secure so browsers send them only over HTTPS.",
  },
  "ARS-COOKIE-002": {
    id: "ARS-COOKIE-002",
    title: "Cookie lacks the HttpOnly attribute",
    category: "Session Security",
    severity: "medium",
    impact: 6,
    exploitability: 5,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Cookies",
    remediation: "Mark session cookies HttpOnly unless browser-side JavaScript access is strictly required.",
  },
  "ARS-COOKIE-003": {
    id: "ARS-COOKIE-003",
    title: "Cookie lacks an explicit SameSite attribute",
    category: "Session Security",
    severity: "medium",
    impact: 5,
    exploitability: 5,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
    remediation: "Set SameSite=Lax or SameSite=Strict for session cookies unless an approved cross-site flow requires SameSite=None; Secure.",
  },
  "ARS-CORS-001": {
    id: "ARS-CORS-001",
    title: "Permissive CORS origin policy detected",
    category: "Cross-Origin Controls",
    severity: "medium",
    impact: 6,
    exploitability: 5,
    confidence: "high",
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Guides/CORS",
    remediation: "Replace wildcard origins with a minimal explicit allowlist and do not combine wildcard origins with credentialed requests.",
  },
  "ARS-DISC-001": {
    id: "ARS-DISC-001",
    title: "Technology disclosure header detected",
    category: "Information Disclosure",
    severity: "low",
    impact: 3,
    exploitability: 4,
    confidence: "high",
    reference: "https://owasp.org/www-project-web-security-testing-guide/",
    remediation: "Remove or minimize framework and server disclosure headers where they are not operationally required.",
  },
  "ARS-MIXED-001": {
    id: "ARS-MIXED-001",
    title: "Potential mixed-content resource detected",
    category: "Transport Security",
    severity: "medium",
    impact: 5,
    exploitability: 5,
    confidence: "medium",
    reference: "https://developer.mozilla.org/docs/Web/Security/Mixed_content",
    remediation: "Update resource URLs to HTTPS or use protocol-relative/relative URLs only when the serving context remains secure.",
  },
  "ARS-TRANS-001": {
    id: "ARS-TRANS-001",
    title: "HTTP endpoint does not redirect to HTTPS",
    category: "Transport Security",
    severity: "high",
    impact: 7,
    exploitability: 6,
    confidence: "high",
    reference: "https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    remediation: "Redirect all HTTP requests to the canonical HTTPS origin with a permanent redirect after validating route compatibility.",
  },
};

export function scoreFromFactors(impact: number, exploitability: number): number {
  return Math.round((impact * 0.62 + exploitability * 0.38) * 10) / 10;
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 0.1) return "low";
  return "informational";
}
