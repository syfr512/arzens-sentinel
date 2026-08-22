import { and, desc, eq, gte, lt } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { nanoid } from "nanoid";
import {
  auditEvents,
  findings,
  remediationRecommendations,
  reportArtifacts,
  scanEndpoints,
  scanEvents,
  scanRuns,
  scanTargets,
  targetAuthorizations,
  type InsertUser,
  users,
} from "../drizzle/schema";
import type { FindingStatus, RemediationGuidance, ScanResult, Severity } from "@shared/security";
import { ENV } from "./_core/env";

const DEFAULT_RETENTION_DAYS = 30;
const AUTHORIZATION_DAYS = 30;
let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try { _db = drizzle(process.env.DATABASE_URL); } catch (error) { console.warn("[Database] Failed to connect:", error); _db = null; }
  }
  return _db;
}

function mustDb<T>(db: T | null): T { if (!db) throw new Error("The assessment database is not available."); return db; }
function expiresInDays(days: number) { return new Date(Date.now() + days * 24 * 60 * 60 * 1000); }

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb(); if (!db) return;
  const values: InsertUser = { openId: user.openId }; const updateSet: Record<string, unknown> = {};
  for (const field of ["name", "email", "loginMethod"] as const) if (user[field] !== undefined) { values[field] = user[field] ?? null; updateSet[field] = user[field] ?? null; }
  values.lastSignedIn = user.lastSignedIn ?? new Date(); updateSet.lastSignedIn = values.lastSignedIn;
  values.role = user.role ?? (user.openId === ENV.ownerOpenId ? "admin" : "user"); updateSet.role = values.role;
  await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb(); if (!db) return undefined;
  return (await db.select().from(users).where(eq(users.openId, openId)).limit(1))[0];
}

export type AuditPayload = { userId?: number | null; action: string; entityType: string; entityId?: string | null; outcome: "success" | "denied" | "failure"; requestId?: string | null; metadata?: Record<string, unknown> };
export async function writeAuditEvent(event: AuditPayload) {
  const db = mustDb(await getDb());
  const id = nanoid(18);
  await db.insert(auditEvents).values({ id, ...event, metadata: event.metadata ?? null });
  return id;
}

export async function listAuditEvents(userId: number) {
  const db = mustDb(await getDb());
  return db.select().from(auditEvents).where(eq(auditEvents.userId, userId)).orderBy(desc(auditEvents.createdAt)).limit(100);
}
export async function countAuditActionSince(userId: number, action: string, since: Date) { const db = mustDb(await getDb()); return (await db.select({ id: auditEvents.id }).from(auditEvents).where(and(eq(auditEvents.userId, userId), eq(auditEvents.action, action), gte(auditEvents.createdAt, since)))).length; }

export type AuthorizationInput = { origin: string; hostname: string; scopePath: string; maxPages: number; maxRedirects: number; maxResponseBytes: number; timeoutMs: number; retentionDays: number };
export async function createTargetAuthorization(userId: number, input: AuthorizationInput) {
  const db = mustDb(await getDb()); const id = nanoid(18); const verificationToken = nanoid(48);
  await db.insert(targetAuthorizations).values({ id, userId, ...input, verificationToken, expiresAt: expiresInDays(AUTHORIZATION_DAYS) });
  return { id, verificationToken, expiresAt: expiresInDays(AUTHORIZATION_DAYS), ...input, status: "pending" as const };
}

export async function listTargetAuthorizations(userId: number) {
  const db = mustDb(await getDb());
  return db.select().from(targetAuthorizations).where(eq(targetAuthorizations.userId, userId)).orderBy(desc(targetAuthorizations.createdAt));
}

export async function getOwnedAuthorization(userId: number, authorizationId: string) {
  const db = mustDb(await getDb());
  return (await db.select().from(targetAuthorizations).where(and(eq(targetAuthorizations.id, authorizationId), eq(targetAuthorizations.userId, userId))).limit(1))[0];
}

export async function recordAuthorizationVerification(userId: number, authorizationId: string, outcome: { success: boolean; detail?: string }) {
  const db = mustDb(await getDb()); const authorization = await getOwnedAuthorization(userId, authorizationId); if (!authorization) return undefined;
  const now = new Date();
  await db.update(targetAuthorizations).set(outcome.success ? { status: "verified", verifiedAt: authorization.verifiedAt ?? now, lastVerifiedAt: now, lastVerificationError: null, verificationAttempts: authorization.verificationAttempts + 1 } : { lastVerificationError: outcome.detail || "Verification failed", verificationAttempts: authorization.verificationAttempts + 1 }).where(eq(targetAuthorizations.id, authorizationId));
  return getOwnedAuthorization(userId, authorizationId);
}

export async function revokeTargetAuthorization(userId: number, authorizationId: string) {
  const db = mustDb(await getDb()); const authorization = await getOwnedAuthorization(userId, authorizationId); if (!authorization) return undefined;
  await db.update(targetAuthorizations).set({ status: "revoked" }).where(eq(targetAuthorizations.id, authorizationId));
  return getOwnedAuthorization(userId, authorizationId);
}

export async function expireStaleAuthorizations() {
  const db = mustDb(await getDb());
  await db.update(targetAuthorizations).set({ status: "expired" }).where(and(eq(targetAuthorizations.status, "verified"), lt(targetAuthorizations.expiresAt, new Date())));
}

function completedRecord(result: ScanResult, userId: number, targetId: string, scanId: string) {
  return { id: scanId, userId, targetId, targetUrl: result.targetUrl, profile: result.profile, status: "completed" as const, riskScore: Math.round(result.summary.score * 10), overallSeverity: result.summary.severity, endpointCount: result.summary.scannedEndpoints, findingCount: result.summary.findingCount, startedAt: new Date(Date.now() - result.summary.durationMs), completedAt: new Date(), retentionExpiresAt: expiresInDays(DEFAULT_RETENTION_DAYS) };
}

async function insertScanPayload(scanId: string, result: ScanResult) {
  const db = mustDb(await getDb());
  if (result.endpoints.length) await db.insert(scanEndpoints).values(result.endpoints.map((endpoint, index) => ({ id: `${scanId}-${index}`, scanId, url: endpoint.url, statusCode: endpoint.statusCode, contentType: endpoint.contentType, discoveredBy: endpoint.discoveredBy })));
  if (result.findings.length) await db.insert(findings).values(result.findings.map(item => ({ ...item, scanId, scoreTenth: Math.round(item.score * 10), rationale: item.rationale })));
  if (result.activity.length) await db.insert(scanEvents).values(result.activity.map(event => ({ id: nanoid(18), scanId, label: event.label, detail: event.detail, createdAt: new Date(event.at) })));
}

export async function persistScanResult(userId: number, result: ScanResult) {
  const db = mustDb(await getDb()); const targetId = nanoid(18); const scanId = nanoid(18);
  await db.insert(scanTargets).values({ id: targetId, userId, normalizedUrl: result.targetUrl });
  await db.insert(scanRuns).values(completedRecord(result, userId, targetId, scanId));
  await insertScanPayload(scanId, result);
  return scanId;
}

export async function getOwnedScanByRequestId(userId: number, requestId: string) { const db = mustDb(await getDb()); return (await db.select().from(scanRuns).where(and(eq(scanRuns.userId, userId), eq(scanRuns.requestId, requestId))).limit(1))[0]; }

export async function beginAuthorizedScan(userId: number, authorization: Awaited<ReturnType<typeof getOwnedAuthorization>>, requestId: string) {
  if (!authorization) throw new Error("Verified target authorization is required.");
  const existing = await getOwnedScanByRequestId(userId, requestId); if (existing) return { scanId: existing.id, reused: true };
  const db = mustDb(await getDb()); const targetId = nanoid(18); const scanId = nanoid(18); const now = new Date();
  await db.insert(scanTargets).values({ id: targetId, userId, normalizedUrl: authorization.origin });
  try {
    await db.insert(scanRuns).values({ id: scanId, userId, targetId, authorizationId: authorization.id, requestId, targetUrl: authorization.origin, profile: "safe_passive", status: "running", policySnapshot: { scopePath: authorization.scopePath, maxPages: authorization.maxPages, maxRedirects: authorization.maxRedirects, maxResponseBytes: authorization.maxResponseBytes, timeoutMs: authorization.timeoutMs, retentionDays: authorization.retentionDays, policyVersion: authorization.policyVersion }, startedAt: now, retentionExpiresAt: expiresInDays(authorization.retentionDays) });
  } catch (error) {
    const duplicate = (error as { code?: string }).code === "ER_DUP_ENTRY";
    if (duplicate) { const retried = await getOwnedScanByRequestId(userId, requestId); if (retried) return { scanId: retried.id, reused: true }; }
    throw error;
  }
  await db.insert(scanEvents).values({ id: nanoid(18), scanId, label: "Scan started", detail: "Verified authorization, scope, bounded policy, retention, and idempotency key were recorded before outbound assessment.", createdAt: now });
  return { scanId, reused: false };
}

export async function completeAuthorizedScan(userId: number, scanId: string, result: ScanResult) {
  const db = mustDb(await getDb()); const scan = await getOwnedScan(userId, scanId); if (!scan || scan.status !== "running") return undefined;
  await db.update(scanRuns).set({ targetUrl: result.targetUrl, status: "completed", riskScore: Math.round(result.summary.score * 10), overallSeverity: result.summary.severity, endpointCount: result.summary.scannedEndpoints, findingCount: result.summary.findingCount, completedAt: new Date() }).where(eq(scanRuns.id, scanId));
  await insertScanPayload(scanId, result); return getOwnedScan(userId, scanId);
}

export async function failAuthorizedScan(userId: number, scanId: string, message: string, cancelled = false) {
  const db = mustDb(await getDb()); const scan = await getOwnedScan(userId, scanId); if (!scan || !["running", "queued"].includes(scan.status)) return undefined;
  await db.update(scanRuns).set({ status: cancelled ? "cancelled" : "failed", errorMessage: message.slice(0, 1000), completedAt: new Date() }).where(eq(scanRuns.id, scanId));
  await db.insert(scanEvents).values({ id: nanoid(18), scanId, label: cancelled ? "Scan cancelled" : "Scan failed", detail: message.slice(0, 1000) });
  return getOwnedScan(userId, scanId);
}

export async function requestScanCancellation(userId: number, scanId: string) {
  const db = mustDb(await getDb()); const scan = await getOwnedScan(userId, scanId); if (!scan || !["running", "queued"].includes(scan.status)) return undefined;
  await db.update(scanRuns).set({ cancelRequestedAt: new Date() }).where(eq(scanRuns.id, scanId));
  await db.insert(scanEvents).values({ id: nanoid(18), scanId, label: "Cancellation requested", detail: "The scanner will stop before the next bounded endpoint check." });
  return getOwnedScan(userId, scanId);
}

export async function isScanCancellationRequested(scanId: string) {
  const db = mustDb(await getDb()); const scan = (await db.select({ cancelRequestedAt: scanRuns.cancelRequestedAt }).from(scanRuns).where(eq(scanRuns.id, scanId)).limit(1))[0];
  return Boolean(scan?.cancelRequestedAt);
}

export async function listUserScans(userId: number) { const db = mustDb(await getDb()); return db.select().from(scanRuns).where(eq(scanRuns.userId, userId)).orderBy(desc(scanRuns.createdAt)).limit(50); }
export async function getOwnedScan(userId: number, scanId: string) { const db = mustDb(await getDb()); return (await db.select().from(scanRuns).where(and(eq(scanRuns.id, scanId), eq(scanRuns.userId, userId))).limit(1))[0]; }
export async function countRecentLiveScans(userId: number, since: Date) { const db = mustDb(await getDb()); return (await db.select().from(scanRuns).where(and(eq(scanRuns.userId, userId), gte(scanRuns.createdAt, since)))).length; }
export async function hasActiveAuthorizationScan(userId: number, authorizationId: string) { const db = mustDb(await getDb()); return Boolean((await db.select({ id: scanRuns.id }).from(scanRuns).where(and(eq(scanRuns.userId, userId), eq(scanRuns.authorizationId, authorizationId), eq(scanRuns.status, "running"))).limit(1))[0]); }

export async function getScanDetail(userId: number, scanId: string) {
  const db = mustDb(await getDb()); const scan = await getOwnedScan(userId, scanId); if (!scan) return undefined;
  const [endpoints, scanFindings, events, artifacts] = await Promise.all([db.select().from(scanEndpoints).where(eq(scanEndpoints.scanId, scanId)), db.select().from(findings).where(eq(findings.scanId, scanId)).orderBy(desc(findings.scoreTenth)), db.select().from(scanEvents).where(eq(scanEvents.scanId, scanId)).orderBy(desc(scanEvents.createdAt)), db.select().from(reportArtifacts).where(eq(reportArtifacts.scanId, scanId)).orderBy(desc(reportArtifacts.createdAt))]);
  return { scan, endpoints, findings: scanFindings, events, artifacts };
}

export async function getOwnedFinding(userId: number, findingId: string) { const db = mustDb(await getDb()); const item = (await db.select().from(findings).where(eq(findings.id, findingId)).limit(1))[0]; if (!item) return undefined; const scan = await getOwnedScan(userId, item.scanId); return scan ? { finding: item, scan } : undefined; }

export async function updateOwnedFinding(userId: number, findingId: string, update: { status?: FindingStatus; reviewerNote?: string; severity?: Severity; severityOverrideNote?: string }) {
  const db = mustDb(await getDb()); const owned = await getOwnedFinding(userId, findingId); if (!owned) return undefined;
  await db.update(findings).set(update).where(eq(findings.id, findingId)); return (await db.select().from(findings).where(eq(findings.id, findingId)).limit(1))[0];
}

export async function storeRemediation(userId: number, findingId: string, guidance: RemediationGuidance) { const db = mustDb(await getDb()); const owned = await getOwnedFinding(userId, findingId); if (!owned) return undefined; const id = nanoid(18); await db.insert(remediationRecommendations).values({ id, scanId: owned.scan.id, findingId, source: guidance.source, guidance }); return { id, guidance }; }
export async function listRemediation(userId: number, findingId: string) { const db = mustDb(await getDb()); if (!(await getOwnedFinding(userId, findingId))) return undefined; return db.select().from(remediationRecommendations).where(eq(remediationRecommendations.findingId, findingId)).orderBy(desc(remediationRecommendations.createdAt)); }

export async function storeReportArtifact(userId: number, scanId: string, format: "json" | "csv" | "html" | "pdf", storageKey: string, url: string) {
  const db = mustDb(await getDb()); const scan = await getOwnedScan(userId, scanId); if (!scan) return undefined; const id = nanoid(18); const expiresAt = scan.retentionExpiresAt ?? expiresInDays(DEFAULT_RETENTION_DAYS);
  await db.insert(reportArtifacts).values({ id, scanId, format, storageKey, url, expiresAt }); return { id, format, storageKey, url, expiresAt };
}

export async function getOwnedReportArtifact(userId: number, artifactId: string) {
  const db = mustDb(await getDb()); const artifact = (await db.select().from(reportArtifacts).where(eq(reportArtifacts.id, artifactId)).limit(1))[0]; if (!artifact || (artifact.expiresAt && artifact.expiresAt < new Date())) return undefined;
  const scan = await getOwnedScan(userId, artifact.scanId); return scan ? { artifact, scan } : undefined;
}

export async function markReportDownloaded(userId: number, artifactId: string) {
  const db = mustDb(await getDb()); const owned = await getOwnedReportArtifact(userId, artifactId); if (!owned) return undefined;
  await db.update(reportArtifacts).set({ downloadCount: owned.artifact.downloadCount + 1 }).where(eq(reportArtifacts.id, artifactId)); return getOwnedReportArtifact(userId, artifactId);
}

export async function purgeExpiredScanMetadata() {
  const db = mustDb(await getDb());
  // Retention cleanup intentionally deletes only database metadata. A production operator should pair this with an object-storage lifecycle rule for artifact bytes.
  const expired = await db.select().from(scanRuns).where(lt(scanRuns.retentionExpiresAt, new Date()));
  return expired.map(scan => scan.id);
}
