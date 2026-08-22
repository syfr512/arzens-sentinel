import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import type { AssessmentProfile, DiscoveredEndpoint, ScanResult, ScannerFinding, Severity } from "@shared/security";
import { RULES, scoreFromFactors, severityFromScore } from "./rules";

const DEFAULT_LIMITS = { maxPages: 4, maxRedirects: 3, maxResponseBytes: 350_000, timeoutMs: 8_000, maxTotalMs: 45_000 };
const HARD_LIMITS = { maxPages: 10, maxRedirects: 5, maxResponseBytes: 1_000_000, timeoutMs: 15_000, maxTotalMs: 90_000 };
const sensitiveHeaderNames = new Set(["authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"]);
const sensitiveBodyPatterns = [/(bearer\s+)[a-z0-9._~+\-/=]+/gi, /(api[_-]?key\s*[=:]\s*)[^\s"'&]+/gi, /(password\s*[=:]\s*)[^\s"'&]+/gi, /(token\s*[=:]\s*)[^\s"'&]+/gi];

export type ScannerLimits = Partial<typeof DEFAULT_LIMITS>;
export type AuthorizedScope = { origin: string; scopePath: string };
export type ScanExecutionOptions = { scope?: AuthorizedScope; shouldCancel?: () => Promise<boolean> | boolean };

type ResolvedAddress = { address: string; family: 4 | 6 };
type ScannerResponse = { status: number; headers: Headers; body: string; finalUrl: URL; resolvedAddress: string };

export class TargetSafetyError extends Error { constructor(message: string) { super(message); this.name = "TargetSafetyError"; } }
export class ScanCancelledError extends Error { constructor() { super("The scan was cancelled by the operator."); this.name = "ScanCancelledError"; } }

function isBlockedIpv4(address: string) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return true;
  const [a, b, c] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 0 || b === 168)) || (a === 192 && b === 88 && c === 99) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0);
}

function isBlockedIpv6(address: string) {
  const value = address.toLowerCase();
  return value === "::" || value === "::1" || value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe80") || value.startsWith("ff") || value.startsWith("::ffff:") || value.startsWith("2001:db8");
}

function hostnameBlocked(hostname: string) {
  const value = hostname.toLowerCase().replace(/\.$/, "");
  return value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local") || value === "metadata.google.internal" || value === "metadata" || value === "169.254.169.254" || value === "instance-data";
}

function normalizeScopePath(value: string) { const path = value.startsWith("/") ? value : `/${value}`; return path.endsWith("/") ? path : `${path}/`; }

function ensureScope(url: URL, scope?: AuthorizedScope) {
  if (!scope) return;
  if (url.origin !== scope.origin) throw new TargetSafetyError("The request left the verified origin and was blocked by the authorization scope.");
  const normalizedScope = normalizeScopePath(scope.scopePath);
  const normalizedPath = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
  if (!normalizedPath.startsWith(normalizedScope)) throw new TargetSafetyError("The request left the verified path scope and was blocked.");
}

async function resolvePublicHost(hostname: string): Promise<ResolvedAddress> {
  if (hostnameBlocked(hostname)) throw new TargetSafetyError("This target is not permitted by the safety policy.");
  const directVersion = isIP(hostname);
  if (directVersion) {
    const blocked = directVersion === 4 ? isBlockedIpv4(hostname) : isBlockedIpv6(hostname);
    if (blocked) throw new TargetSafetyError("Private, reserved, multicast, and loopback network targets are blocked.");
    return { address: hostname, family: directVersion as 4 | 6 };
  }
  let answers: Array<{ address: string; family: number }>;
  try { answers = await lookup(hostname, { all: true, verbatim: true }); } catch { throw new TargetSafetyError("The target hostname could not be resolved safely."); }
  const publicAnswers = answers.filter(item => (item.family === 4 ? !isBlockedIpv4(item.address) : !isBlockedIpv6(item.address)));
  if (!answers.length || publicAnswers.length !== answers.length) throw new TargetSafetyError("The target resolves to a private, reserved, or loopback network address.");
  const chosen = publicAnswers[0];
  if (!chosen || (chosen.family !== 4 && chosen.family !== 6)) throw new TargetSafetyError("The target returned an unsupported DNS address family.");
  return { address: chosen.address, family: chosen.family as 4 | 6 };
}

export async function assertSafeTarget(input: string, scope?: AuthorizedScope): Promise<URL> {
  let url: URL;
  try { url = new URL(input); } catch { throw new TargetSafetyError("Enter a valid absolute HTTP(S) URL."); }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new TargetSafetyError("Only HTTP(S) targets are supported.");
  if (url.username || url.password) throw new TargetSafetyError("Embedded URL credentials are not permitted.");
  ensureScope(url, scope);
  await resolvePublicHost(url.hostname);
  url.hash = "";
  return url;
}

function boundedLimits(overrides: ScannerLimits) {
  const clamp = (value: number | undefined, fallback: number, ceiling: number) => Number.isFinite(value) ? Math.min(Math.max(Math.floor(value as number), 1), ceiling) : fallback;
  return {
    maxPages: clamp(overrides.maxPages, DEFAULT_LIMITS.maxPages, HARD_LIMITS.maxPages),
    maxRedirects: clamp(overrides.maxRedirects, DEFAULT_LIMITS.maxRedirects, HARD_LIMITS.maxRedirects),
    maxResponseBytes: clamp(overrides.maxResponseBytes, DEFAULT_LIMITS.maxResponseBytes, HARD_LIMITS.maxResponseBytes),
    timeoutMs: clamp(overrides.timeoutMs, DEFAULT_LIMITS.timeoutMs, HARD_LIMITS.timeoutMs),
    maxTotalMs: DEFAULT_LIMITS.maxTotalMs,
  };
}

export function redactEvidence(value: string): string {
  let redacted = value;
  for (const pattern of sensitiveBodyPatterns) redacted = redacted.replace(pattern, "$1[REDACTED]");
  return redacted.replace(/[A-Za-z0-9+/_-]{36,}/g, "[REDACTED_TOKEN]");
}

function redactHeaders(headers: Headers): string { return Array.from(headers.entries()).map(([name, value]) => `${name}: ${sensitiveHeaderNames.has(name.toLowerCase()) ? "[REDACTED]" : redactEvidence(value)}`).join("\n"); }

function toHeaders(input: http.IncomingHttpHeaders) {
  const headers = new Headers();
  Object.entries(input).forEach(([name, value]) => { if (Array.isArray(value)) value.forEach(item => headers.append(name, item)); else if (value !== undefined) headers.set(name, value); });
  return headers;
}

async function requestPinned(url: URL, method: "GET" | "OPTIONS", resolved: ResolvedAddress, limits: ReturnType<typeof boundedLimits>): Promise<Omit<ScannerResponse, "finalUrl">> {
  const transport = url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const request = transport.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || undefined,
      path: `${url.pathname}${url.search}`,
      method,
      servername: url.protocol === "https:" ? url.hostname : undefined,
      headers: { "User-Agent": "Arzens-Sentinel/1.1 (authorized safe-passive assessment)", Accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.4", "Accept-Encoding": "identity" },
      lookup: (_host, _options, callback) => callback(null, resolved.address, resolved.family),
    }, response => {
      const contentLength = Number(response.headers["content-length"] || 0);
      if (contentLength > limits.maxResponseBytes) { response.resume(); resolve({ status: response.statusCode || 0, headers: toHeaders(response.headers), body: "[Response body omitted: advertised size exceeds configured limit]", resolvedAddress: resolved.address }); return; }
      const chunks: Buffer[] = [];
      let total = 0;
      response.on("data", chunk => {
        total += chunk.length;
        if (total > limits.maxResponseBytes) { request.destroy(new TargetSafetyError("Response exceeded the configured size limit.")); return; }
        chunks.push(Buffer.from(chunk));
      });
      response.on("end", () => resolve({ status: response.statusCode || 0, headers: toHeaders(response.headers), body: Buffer.concat(chunks).toString("utf8"), resolvedAddress: resolved.address }));
      response.on("error", reject);
    });
    request.setTimeout(limits.timeoutMs, () => request.destroy(new TargetSafetyError("The target exceeded the configured response timeout.")));
    request.once("error", reject);
    request.end();
  });
}

async function safeFetch(input: URL, limits: ReturnType<typeof boundedLimits>, method: "GET" | "OPTIONS" = "GET", scope?: AuthorizedScope): Promise<ScannerResponse> {
  let current = input;
  for (let redirectCount = 0; redirectCount <= limits.maxRedirects; redirectCount += 1) {
    const checked = await assertSafeTarget(current.toString(), scope);
    const resolved = await resolvePublicHost(checked.hostname);
    const response = await requestPinned(checked, method, resolved, limits);
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      current = new URL(response.headers.get("location")!, checked);
      continue;
    }
    return { ...response, finalUrl: checked };
  }
  throw new TargetSafetyError("The target exceeded the configured redirect limit.");
}

function finding(ruleId: string, endpoint: string, evidence: string, source: ScannerFinding["source"] = "native"): ScannerFinding {
  const rule = RULES[ruleId]; const score = scoreFromFactors(rule.impact, rule.exploitability);
  return { id: `${rule.id}-${createHash("sha256").update(`${endpoint}:${rule.id}`).digest("hex").slice(0, 10)}`, ruleId: rule.id, title: rule.title, category: rule.category, severity: severityFromScore(score), originalSeverity: severityFromScore(score), score, confidence: rule.confidence, endpoint, evidence: redactEvidence(evidence), rationale: { impact: rule.impact, exploitability: rule.exploitability, score, explanation: `Impact ${rule.impact}/10 and exploitability ${rule.exploitability}/10 produce the documented ${score}/10 assessment score.` }, reference: rule.reference, remediation: rule.remediation, status: "open", source };
}

function assessResponse(url: URL, response: ScannerResponse, corsResponse?: ScannerResponse | null): ScannerFinding[] {
  const findings: ScannerFinding[] = []; const headers = response.headers; const endpoint = url.toString(); const headerEvidence = redactHeaders(headers);
  if (!headers.get("content-security-policy")) findings.push(finding("ARS-HEAD-001", endpoint, `Content-Security-Policy absent.\n${headerEvidence}`));
  if (url.protocol === "https:" && !headers.get("strict-transport-security")) findings.push(finding("ARS-HEAD-002", endpoint, `Strict-Transport-Security absent.\n${headerEvidence}`));
  if (headers.get("x-content-type-options")?.toLowerCase() !== "nosniff") findings.push(finding("ARS-HEAD-003", endpoint, `X-Content-Type-Options is not nosniff.\n${headerEvidence}`));
  if (!headers.get("referrer-policy")) findings.push(finding("ARS-HEAD-004", endpoint, `Referrer-Policy absent.\n${headerEvidence}`));
  if (!headers.get("x-frame-options") && !headers.get("content-security-policy")?.includes("frame-ancestors")) findings.push(finding("ARS-HEAD-005", endpoint, `Neither X-Frame-Options nor CSP frame-ancestors was detected.\n${headerEvidence}`));
  const cookies = headers.get("set-cookie") || "";
  if (cookies && !/;\s*secure\b/i.test(cookies)) findings.push(finding("ARS-COOKIE-001", endpoint, "Set-Cookie was observed without a Secure attribute. Cookie values have been redacted."));
  if (cookies && !/;\s*httponly\b/i.test(cookies)) findings.push(finding("ARS-COOKIE-002", endpoint, "Set-Cookie was observed without an HttpOnly attribute. Cookie values have been redacted."));
  const corsOrigin = corsResponse?.headers.get("access-control-allow-origin") || headers.get("access-control-allow-origin");
  if (corsOrigin === "*") findings.push(finding("ARS-CORS-001", endpoint, `Safe OPTIONS/response check observed Access-Control-Allow-Origin: *.\n${corsResponse ? redactHeaders(corsResponse.headers) : headerEvidence}`));
  if (headers.get("server") || headers.get("x-powered-by")) findings.push(finding("ARS-DISC-001", endpoint, `Technology disclosure header observed.\n${headerEvidence}`));
  if (url.protocol === "https:" && /(?:src|href)=["']http:\/\//i.test(response.body)) findings.push(finding("ARS-MIXED-001", endpoint, "An HTTP subresource reference was detected in an HTTPS response body."));
  return findings;
}

function extractSameOriginLinks(body: string, base: URL, maxLinks: number, scope?: AuthorizedScope) {
  const links = new Set<string>(); const expression = /(?:href|src)=["']([^"'#?][^"']*)["']/gi;
  for (const match of Array.from(body.matchAll(expression))) {
    try { const candidate = new URL(match[1], base); if (candidate.origin === base.origin && (candidate.protocol === "https:" || candidate.protocol === "http:")) { ensureScope(candidate, scope); candidate.hash = ""; links.add(candidate.toString()); } } catch { /* out-of-scope and malformed markup are not crawled */ }
    if (links.size >= maxLinks) break;
  }
  return Array.from(links);
}

function dedupe(findings: ScannerFinding[]) { const result = new Map<string, ScannerFinding>(); for (const item of findings) result.set(`${item.ruleId}:${item.endpoint}`, item); return Array.from(result.values()).sort((a, b) => b.score - a.score || a.ruleId.localeCompare(b.ruleId)); }
function overallSeverity(findings: ScannerFinding[]): Severity { return findings[0]?.severity || "informational"; }

export async function verifyWellKnownProof(origin: string, token: string): Promise<void> {
  const base = await assertSafeTarget(origin);
  if (base.protocol !== "https:") throw new TargetSafetyError("Live target verification requires HTTPS.");
  const proofUrl = new URL("/.well-known/arzens-sentinel-verification.txt", base);
  const response = await safeFetch(proofUrl, boundedLimits({ maxPages: 1, maxRedirects: 2, maxResponseBytes: 8_192, timeoutMs: 8_000 }), "GET", { origin: base.origin, scopePath: "/" });
  const expected = `arzens-sentinel-verification=${token}`;
  if (response.status !== 200 || response.body.trim() !== expected) throw new TargetSafetyError("The verification file was not found or did not contain the expected proof token.");
}

export async function runSafePassiveScan(target: string, profile: AssessmentProfile = "safe_passive", limitOverrides: ScannerLimits = {}, execution: ScanExecutionOptions = {}): Promise<ScanResult> {
  if (profile !== "safe_passive") throw new TargetSafetyError("Active Lab checks are available only in documented local authorized testing.");
  const started = Date.now(); const limits = boundedLimits(limitOverrides); const seed = await assertSafeTarget(target, execution.scope); const queue = [seed.toString()]; const visited = new Set<string>(); const endpoints: DiscoveredEndpoint[] = []; const findings: ScannerFinding[] = [];
  const activity: ScanResult["activity"] = [{ at: new Date().toISOString(), label: "Target verified", detail: "URL, DNS answers, pinned outbound connection, redirect behavior, and profile boundaries were checked." }];
  while (queue.length && visited.size < limits.maxPages) {
    if (await execution.shouldCancel?.()) throw new ScanCancelledError();
    if (Date.now() - started >= limits.maxTotalMs) { activity.push({ at: new Date().toISOString(), label: "Assessment time budget reached", detail: `The hosted scan stopped after ${(limits.maxTotalMs / 1000).toFixed(0)} seconds to preserve the managed request-timeout envelope. Findings reflect only assessed endpoints.` }); break; }
    const next = queue.shift()!; if (visited.has(next)) continue; visited.add(next);
    try {
      const response = await safeFetch(new URL(next), limits, "GET", execution.scope);
      endpoints.push({ url: response.finalUrl.toString(), statusCode: response.status, contentType: response.headers.get("content-type"), discoveredBy: visited.size === 1 ? "seed" : "link" });
      const corsProbe = await safeFetch(response.finalUrl, limits, "OPTIONS", execution.scope).catch(() => null);
      findings.push(...assessResponse(response.finalUrl, response, corsProbe));
      for (const link of extractSameOriginLinks(response.body, response.finalUrl, limits.maxPages - visited.size, execution.scope)) if (!visited.has(link)) queue.push(link);
      activity.push({ at: new Date().toISOString(), label: "Endpoint assessed", detail: `${response.status} ${response.finalUrl.pathname || "/"}; pinned IP ${response.resolvedAddress}; evidence redacted before persistence.` });
    } catch (error) { if (error instanceof ScanCancelledError) throw error; activity.push({ at: new Date().toISOString(), label: "Endpoint skipped", detail: error instanceof Error ? redactEvidence(error.message) : "Unknown fetch error" }); }
  }
  if (seed.protocol === "http:" && !endpoints.some(endpoint => endpoint.url.startsWith("https://"))) findings.push(finding("ARS-TRANS-001", seed.toString(), "The seeded HTTP URL did not complete a validated redirect to HTTPS."));
  const normalized = dedupe(findings); const score = normalized.length ? Math.round((normalized.reduce((total, item) => total + item.score, 0) / normalized.length) * 10) / 10 : 0;
  activity.push({ at: new Date().toISOString(), label: "Assessment complete", detail: `${normalized.length} deduplicated findings across ${endpoints.length} bounded endpoint(s).` });
  return { targetUrl: seed.toString(), profile, summary: { score, severity: overallSeverity(normalized), scannedEndpoints: endpoints.length, findingCount: normalized.length, durationMs: Date.now() - started }, endpoints, findings: normalized, activity };
}

export const scannerLimits = DEFAULT_LIMITS;
export const scannerHardLimits = HARD_LIMITS;
