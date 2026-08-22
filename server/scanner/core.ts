import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type {
  AssessmentProfile,
  DiscoveredEndpoint,
  ScanResult,
  ScannerFinding,
  Severity,
} from "@shared/security";
import { RULES, scoreFromFactors, severityFromScore } from "./rules";

const DEFAULT_LIMITS = {
  maxPages: 4,
  maxRedirects: 3,
  maxResponseBytes: 350_000,
  timeoutMs: 8_000,
};

const sensitiveHeaderNames = new Set(["authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"]);
const sensitiveBodyPatterns = [
  /(bearer\s+)[a-z0-9._~+\-/=]+/gi,
  /(api[_-]?key\s*[=:]\s*)[^\s"'&]+/gi,
  /(password\s*[=:]\s*)[^\s"'&]+/gi,
  /(token\s*[=:]\s*)[^\s"'&]+/gi,
];

export type ScannerLimits = Partial<typeof DEFAULT_LIMITS>;

export class TargetSafetyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetSafetyError";
  }
}

function isBlockedIpv4(address: string) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 192 && b === 2) ||
    (a === 198 && b === 51) ||
    (a === 203 && b === 0)
  );
}

function isBlockedIpv6(address: string) {
  const value = address.toLowerCase();
  return value === "::" || value === "::1" || value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe80") || value.startsWith("::ffff:");
}

function hostnameBlocked(hostname: string) {
  const value = hostname.toLowerCase().replace(/\.$/, "");
  return value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local") || value === "metadata.google.internal" || value === "169.254.169.254";
}

export async function assertSafeTarget(input: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new TargetSafetyError("Enter a valid absolute HTTP(S) URL.");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new TargetSafetyError("Only HTTP(S) targets are supported.");
  }
  if (url.username || url.password || hostnameBlocked(url.hostname)) {
    throw new TargetSafetyError("This target is not permitted by the safety policy.");
  }

  const directIpVersion = isIP(url.hostname);
  if (directIpVersion === 4 && isBlockedIpv4(url.hostname)) {
    throw new TargetSafetyError("Private, reserved, and loopback network targets are blocked.");
  }
  if (directIpVersion === 6 && isBlockedIpv6(url.hostname)) {
    throw new TargetSafetyError("Private, reserved, and loopback network targets are blocked.");
  }

  if (!directIpVersion) {
    let addresses: Array<{ address: string }>;
    try {
      addresses = await lookup(url.hostname, { all: true });
    } catch {
      throw new TargetSafetyError("The target hostname could not be resolved safely.");
    }
    if (!addresses.length || addresses.some(({ address }) => (isIP(address) === 4 ? isBlockedIpv4(address) : isBlockedIpv6(address)))) {
      throw new TargetSafetyError("The target resolves to a private, reserved, or loopback network address.");
    }
  }

  url.hash = "";
  return url;
}

export function redactEvidence(value: string): string {
  let redacted = value;
  for (const pattern of sensitiveBodyPatterns) redacted = redacted.replace(pattern, "$1[REDACTED]");
  return redacted.replace(/[A-Za-z0-9+/_-]{36,}/g, "[REDACTED_TOKEN]");
}

function redactHeaders(headers: Headers): string {
  return Array.from(headers.entries())
    .map(([name, value]) => `${name}: ${sensitiveHeaderNames.has(name.toLowerCase()) ? "[REDACTED]" : redactEvidence(value)}`)
    .join("\n");
}

async function readLimitedBody(response: Response, maxBytes: number) {
  const length = Number(response.headers.get("content-length") || 0);
  if (length > maxBytes) return "[Response body omitted: advertised size exceeds configured limit]";
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return "[Response body truncated: configured size limit reached]";
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks.map(chunk => Buffer.from(chunk))));
}

async function safeFetch(input: URL, limits: typeof DEFAULT_LIMITS, method: "GET" | "OPTIONS" = "GET") {
  let current = input;
  for (let redirectCount = 0; redirectCount <= limits.maxRedirects; redirectCount += 1) {
    await assertSafeTarget(current.toString());
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), limits.timeoutMs);
    let response: Response;
    try {
      response = await fetch(current, {
        method,
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "Arzens-Sentinel/1.0 (safe-passive assessment; authorized use only)",
          Accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.4",
        },
      });
    } finally {
      clearTimeout(timer);
    }
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      current = new URL(response.headers.get("location")!, current);
      continue;
    }
    return { response, finalUrl: current };
  }
  throw new TargetSafetyError("The target exceeded the configured redirect limit.");
}

function finding(ruleId: string, endpoint: string, evidence: string, source: ScannerFinding["source"] = "native"): ScannerFinding {
  const rule = RULES[ruleId];
  const score = scoreFromFactors(rule.impact, rule.exploitability);
  const findingId = `${rule.id}-${createHash("sha256").update(`${endpoint}:${rule.id}`).digest("hex").slice(0, 10)}`;
  return {
    id: findingId,
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: severityFromScore(score),
    originalSeverity: severityFromScore(score),
    score,
    confidence: rule.confidence,
    endpoint,
    evidence: redactEvidence(evidence),
    rationale: {
      impact: rule.impact,
      exploitability: rule.exploitability,
      score,
      explanation: `Impact ${rule.impact}/10 and exploitability ${rule.exploitability}/10 produce the documented ${score}/10 assessment score.`,
    },
    reference: rule.reference,
    remediation: rule.remediation,
    status: "open",
    source,
  };
}

function assessResponse(url: URL, response: Response, body: string, corsResponse?: Response | null): ScannerFinding[] {
  const findings: ScannerFinding[] = [];
  const headers = response.headers;
  const endpoint = url.toString();
  const headerEvidence = redactHeaders(headers);
  if (!headers.get("content-security-policy")) findings.push(finding("ARS-HEAD-001", endpoint, `Content-Security-Policy absent.\n${headerEvidence}`));
  if (url.protocol === "https:" && !headers.get("strict-transport-security")) findings.push(finding("ARS-HEAD-002", endpoint, `Strict-Transport-Security absent.\n${headerEvidence}`));
  if (headers.get("x-content-type-options")?.toLowerCase() !== "nosniff") findings.push(finding("ARS-HEAD-003", endpoint, `X-Content-Type-Options is not nosniff.\n${headerEvidence}`));
  if (!headers.get("referrer-policy")) findings.push(finding("ARS-HEAD-004", endpoint, `Referrer-Policy absent.\n${headerEvidence}`));
  if (!headers.get("x-frame-options") && !headers.get("content-security-policy")?.includes("frame-ancestors")) findings.push(finding("ARS-HEAD-005", endpoint, `Neither X-Frame-Options nor CSP frame-ancestors was detected.\n${headerEvidence}`));
  const cookies = headers.get("set-cookie") || "";
  if (cookies && !/;\s*secure\b/i.test(cookies)) findings.push(finding("ARS-COOKIE-001", endpoint, "Set-Cookie was observed without a Secure attribute. Cookie values have been redacted."));
  if (cookies && !/;\s*httponly\b/i.test(cookies)) findings.push(finding("ARS-COOKIE-002", endpoint, "Set-Cookie was observed without an HttpOnly attribute. Cookie values have been redacted."));
  const corsOrigin = corsResponse?.headers.get("access-control-allow-origin") || headers.get("access-control-allow-origin");
  if (corsOrigin === "*") {
    const corsEvidence = corsResponse ? redactHeaders(corsResponse.headers) : headerEvidence;
    findings.push(finding("ARS-CORS-001", endpoint, `Safe OPTIONS/response check observed Access-Control-Allow-Origin: *.\n${corsEvidence}`));
  }
  if (headers.get("server") || headers.get("x-powered-by")) findings.push(finding("ARS-DISC-001", endpoint, `Technology disclosure header observed.\n${headerEvidence}`));
  if (url.protocol === "https:" && /(?:src|href)=["']http:\/\//i.test(body)) findings.push(finding("ARS-MIXED-001", endpoint, "An HTTP subresource reference was detected in an HTTPS response body."));
  return findings;
}

function extractSameOriginLinks(body: string, base: URL, maxLinks: number) {
  const links = new Set<string>();
  const expression = /(?:href|src)=["']([^"'#?][^"']*)["']/gi;
  for (const match of Array.from(body.matchAll(expression))) {
    try {
      const candidate = new URL(match[1], base);
      if (candidate.origin === base.origin && (candidate.protocol === "https:" || candidate.protocol === "http:")) {
        candidate.hash = "";
        links.add(candidate.toString());
      }
    } catch {
      // Invalid markup is ignored by the bounded passive crawler.
    }
    if (links.size >= maxLinks) break;
  }
  return Array.from(links);
}

function dedupe(findings: ScannerFinding[]) {
  const result = new Map<string, ScannerFinding>();
  for (const item of findings) result.set(`${item.ruleId}:${item.endpoint}`, item);
  return Array.from(result.values()).sort((a, b) => b.score - a.score || a.ruleId.localeCompare(b.ruleId));
}

function overallSeverity(findings: ScannerFinding[]): Severity {
  return findings[0]?.severity || "informational";
}

export async function runSafePassiveScan(target: string, profile: AssessmentProfile = "safe_passive", limitOverrides: ScannerLimits = {}): Promise<ScanResult> {
  if (profile !== "safe_passive") throw new TargetSafetyError("Active Lab checks are available only in documented local authorized testing.");
  const started = Date.now();
  const limits = { ...DEFAULT_LIMITS, ...limitOverrides };
  const seed = await assertSafeTarget(target);
  const queue = [seed.toString()];
  const visited = new Set<string>();
  const endpoints: DiscoveredEndpoint[] = [];
  const findings: ScannerFinding[] = [];
  const activity: ScanResult["activity"] = [{ at: new Date().toISOString(), label: "Target verified", detail: "URL, hostname, DNS answers, redirect behavior, and profile boundaries were checked." }];

  while (queue.length && visited.size < limits.maxPages) {
    const next = queue.shift()!;
    if (visited.has(next)) continue;
    visited.add(next);
    try {
      const { response, finalUrl } = await safeFetch(new URL(next), limits);
      const body = await readLimitedBody(response, limits.maxResponseBytes);
      endpoints.push({ url: finalUrl.toString(), statusCode: response.status, contentType: response.headers.get("content-type"), discoveredBy: visited.size === 1 ? "seed" : "link" });
      const corsProbe = await safeFetch(finalUrl, limits, "OPTIONS").catch(() => null);
      findings.push(...assessResponse(finalUrl, response, body, corsProbe?.response));
      for (const link of extractSameOriginLinks(body, finalUrl, limits.maxPages - visited.size)) {
        if (!visited.has(link)) queue.push(link);
      }
      activity.push({ at: new Date().toISOString(), label: "Endpoint assessed", detail: `${response.status} ${finalUrl.pathname || "/"}; evidence redacted before persistence.` });
    } catch (error) {
      activity.push({ at: new Date().toISOString(), label: "Endpoint skipped", detail: error instanceof Error ? redactEvidence(error.message) : "Unknown fetch error" });
    }
  }

  if (seed.protocol === "http:" && !endpoints.some(endpoint => endpoint.url.startsWith("https://"))) findings.push(finding("ARS-TRANS-001", seed.toString(), "The seeded HTTP URL did not complete a validated redirect to HTTPS."));
  const normalized = dedupe(findings);
  const score = normalized.length ? Math.round((normalized.reduce((total, item) => total + item.score, 0) / normalized.length) * 10) / 10 : 0;
  activity.push({ at: new Date().toISOString(), label: "Assessment complete", detail: `${normalized.length} deduplicated findings across ${endpoints.length} bounded endpoint(s).` });

  return {
    targetUrl: seed.toString(),
    profile,
    summary: { score, severity: overallSeverity(normalized), scannedEndpoints: endpoints.length, findingCount: normalized.length, durationMs: Date.now() - started },
    endpoints,
    findings: normalized,
    activity,
  };
}

export const scannerLimits = DEFAULT_LIMITS;
