import { and, desc, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { nanoid } from "nanoid";
import {
  findings,
  remediationRecommendations,
  reportArtifacts,
  scanEndpoints,
  scanEvents,
  scanRuns,
  scanTargets,
  type InsertUser,
  users,
} from "../drizzle/schema";
import type { FindingStatus, RemediationGuidance, ScanResult, Severity } from "@shared/security";
import { ENV } from "./_core/env";

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

function mustDb<T>(db: T | null): T {
  if (!db) throw new Error("The assessment database is not available.");
  return db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb();
  if (!db) return;
  const values: InsertUser = { openId: user.openId };
  const updateSet: Record<string, unknown> = {};
  for (const field of ["name", "email", "loginMethod"] as const) {
    if (user[field] !== undefined) {
      values[field] = user[field] ?? null;
      updateSet[field] = user[field] ?? null;
    }
  }
  values.lastSignedIn = user.lastSignedIn ?? new Date();
  updateSet.lastSignedIn = values.lastSignedIn;
  values.role = user.role ?? (user.openId === ENV.ownerOpenId ? "admin" : "user");
  updateSet.role = values.role;
  await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result[0];
}

function scanRecord(result: ScanResult, userId: number, targetId: string, scanId: string) {
  return {
    id: scanId,
    userId,
    targetId,
    targetUrl: result.targetUrl,
    profile: result.profile,
    status: "completed" as const,
    riskScore: Math.round(result.summary.score * 10),
    overallSeverity: result.summary.severity,
    endpointCount: result.summary.scannedEndpoints,
    findingCount: result.summary.findingCount,
    startedAt: new Date(Date.now() - result.summary.durationMs),
    completedAt: new Date(),
  };
}

export async function persistScanResult(userId: number, result: ScanResult) {
  const db = mustDb(await getDb());
  const targetId = nanoid(18);
  const scanId = nanoid(18);
  await db.insert(scanTargets).values({ id: targetId, userId, normalizedUrl: result.targetUrl });
  await db.insert(scanRuns).values(scanRecord(result, userId, targetId, scanId));
  if (result.endpoints.length) {
    await db.insert(scanEndpoints).values(result.endpoints.map((endpoint, index) => ({
      id: `${scanId}-${index}`,
      scanId,
      url: endpoint.url,
      statusCode: endpoint.statusCode,
      contentType: endpoint.contentType,
      discoveredBy: endpoint.discoveredBy,
    })));
  }
  if (result.findings.length) {
    await db.insert(findings).values(result.findings.map(item => ({
      ...item,
      scanId,
      scoreTenth: Math.round(item.score * 10),
      rationale: item.rationale,
    })));
  }
  if (result.activity.length) {
    await db.insert(scanEvents).values(result.activity.map(event => ({
      id: nanoid(18),
      scanId,
      label: event.label,
      detail: event.detail,
      createdAt: new Date(event.at),
    })));
  }
  return scanId;
}

export async function listUserScans(userId: number) {
  const db = mustDb(await getDb());
  return db.select().from(scanRuns).where(eq(scanRuns.userId, userId)).orderBy(desc(scanRuns.createdAt)).limit(50);
}

export async function getOwnedScan(userId: number, scanId: string) {
  const db = mustDb(await getDb());
  const scan = await db.select().from(scanRuns).where(and(eq(scanRuns.id, scanId), eq(scanRuns.userId, userId))).limit(1);
  return scan[0];
}

export async function getScanDetail(userId: number, scanId: string) {
  const db = mustDb(await getDb());
  const scan = await getOwnedScan(userId, scanId);
  if (!scan) return undefined;
  const [endpoints, scanFindings, events, artifacts] = await Promise.all([
    db.select().from(scanEndpoints).where(eq(scanEndpoints.scanId, scanId)),
    db.select().from(findings).where(eq(findings.scanId, scanId)).orderBy(desc(findings.scoreTenth)),
    db.select().from(scanEvents).where(eq(scanEvents.scanId, scanId)).orderBy(desc(scanEvents.createdAt)),
    db.select().from(reportArtifacts).where(eq(reportArtifacts.scanId, scanId)).orderBy(desc(reportArtifacts.createdAt)),
  ]);
  return { scan, endpoints, findings: scanFindings, events, artifacts };
}

export async function getOwnedFinding(userId: number, findingId: string) {
  const db = mustDb(await getDb());
  const item = await db.select().from(findings).where(eq(findings.id, findingId)).limit(1);
  if (!item[0]) return undefined;
  const scan = await getOwnedScan(userId, item[0].scanId);
  return scan ? { finding: item[0], scan } : undefined;
}

export async function updateOwnedFinding(
  userId: number,
  findingId: string,
  update: { status?: FindingStatus; reviewerNote?: string; severity?: Severity; severityOverrideNote?: string },
) {
  const db = mustDb(await getDb());
  const owned = await getOwnedFinding(userId, findingId);
  if (!owned) return undefined;
  await db.update(findings).set(update).where(eq(findings.id, findingId));
  const result = await db.select().from(findings).where(eq(findings.id, findingId)).limit(1);
  return result[0];
}

export async function storeRemediation(userId: number, findingId: string, guidance: RemediationGuidance) {
  const db = mustDb(await getDb());
  const owned = await getOwnedFinding(userId, findingId);
  if (!owned) return undefined;
  const id = nanoid(18);
  await db.insert(remediationRecommendations).values({ id, scanId: owned.scan.id, findingId, source: guidance.source, guidance });
  return { id, guidance };
}

export async function listRemediation(userId: number, findingId: string) {
  const db = mustDb(await getDb());
  const owned = await getOwnedFinding(userId, findingId);
  if (!owned) return undefined;
  return db.select().from(remediationRecommendations).where(eq(remediationRecommendations.findingId, findingId)).orderBy(desc(remediationRecommendations.createdAt));
}

export async function storeReportArtifact(userId: number, scanId: string, format: "json" | "html" | "pdf", storageKey: string, url: string) {
  const db = mustDb(await getDb());
  const scan = await getOwnedScan(userId, scanId);
  if (!scan) return undefined;
  const id = nanoid(18);
  await db.insert(reportArtifacts).values({ id, scanId, format, storageKey, url });
  return { id, format, storageKey, url };
}
