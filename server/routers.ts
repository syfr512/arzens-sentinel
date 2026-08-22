import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { COOKIE_NAME } from "@shared/const";
import type { ScannerFinding } from "@shared/security";
import { findings as findingsTable } from "../drizzle/schema";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import {
  beginAuthorizedScan,
  completeAuthorizedScan,
  countAuditActionSince,
  countRecentLiveScans,
  createTargetAuthorization,
  expireStaleAuthorizations,
  failAuthorizedScan,
  getOwnedAuthorization,
  getOwnedFinding,
  getOwnedReportArtifact,
  getScanDetail,
  getOwnedScanByRequestId,
  hasActiveAuthorizationScan,
  isScanCancellationRequested,
  listAuditEvents,
  listRemediation,
  listTargetAuthorizations,
  listUserScans,
  markReportDownloaded,
  persistScanResult,
  recordAuthorizationVerification,
  requestScanCancellation,
  revokeTargetAuthorization,
  storeRemediation,
  storeReportArtifact,
  updateOwnedFinding,
  writeAuditEvent,
} from "./db";
import { createCsvReport, createHtmlReport, createJsonReport, createPdfReport } from "./reports/render";
import { getDemoScanResult } from "./scanner/demo";
import { generateRemediation } from "./scanner/remediation";
import { assertSafeTarget, runSafePassiveScan, ScanCancelledError, TargetSafetyError, verifyWellKnownProof } from "./scanner/core";
import { storageGetSignedUrl, storagePut } from "./storage";

const scanIdInput = z.object({ scanId: z.string().min(8).max(32) });
const findingIdInput = z.object({ findingId: z.string().min(8).max(90) });
const liveLimitsInput = z.object({ maxPages: z.number().int().min(1).max(10).default(4), maxRedirects: z.number().int().min(0).max(5).default(3), maxResponseBytes: z.number().int().min(16_384).max(1_000_000).default(350_000), timeoutMs: z.number().int().min(1_000).max(15_000).default(8_000) });
const authorizationInput = z.object({ targetUrl: z.string().min(8).max(2048), scopePath: z.string().min(1).max(1024).default("/").refine(value => value.startsWith("/"), "Scope path must begin with '/'."), limits: liveLimitsInput.default({ maxPages: 4, maxRedirects: 3, maxResponseBytes: 350_000, timeoutMs: 8_000 }), retentionDays: z.union([z.literal(7), z.literal(30), z.literal(90)]).default(30) });

function requestId(headers: Record<string, string | string[] | undefined>) { const value = headers["x-request-id"]; return typeof value === "string" && value.length <= 48 ? value : undefined; }
async function enforceScanBudget(userId: number) { if (await countRecentLiveScans(userId, new Date(Date.now() - 60 * 60 * 1000)) >= 6) throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Live assessments are limited to six starts per hour per workspace." }); }
function toScannerFinding(item: typeof findingsTable.$inferSelect): ScannerFinding { const { scoreTenth, rationale, ...rest } = item; return { ...rest, score: scoreTenth / 10, rationale: rationale as ScannerFinding["rationale"] }; }
function operatorError(error: unknown) { if (error instanceof TargetSafetyError) return new TRPCError({ code: "BAD_REQUEST", message: error.message }); if (error instanceof ScanCancelledError) return new TRPCError({ code: "CONFLICT", message: "The scan was cancelled before completion." }); return new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "The bounded assessment could not complete. No unredacted response content was persisted." }); }

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => { const cookieOptions = getSessionCookieOptions(ctx.req); ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 }); return { success: true } as const; }),
  }),
  targets: router({
    list: protectedProcedure.query(async ({ ctx }) => listTargetAuthorizations(ctx.user.id)),
    create: protectedProcedure.input(authorizationInput).mutation(async ({ ctx, input }) => {
      const checked = await assertSafeTarget(input.targetUrl);
      if (checked.protocol !== "https:") throw new TRPCError({ code: "BAD_REQUEST", message: "Live target authorization requires an HTTPS origin." });
      const authorization = await createTargetAuthorization(ctx.user.id, { origin: checked.origin, hostname: checked.hostname, scopePath: input.scopePath, ...input.limits, retentionDays: input.retentionDays });
      await writeAuditEvent({ userId: ctx.user.id, action: "target.authorization.created", entityType: "target_authorization", entityId: authorization.id, outcome: "success", requestId: requestId(ctx.req.headers), metadata: { origin: checked.origin, scopePath: input.scopePath, retentionDays: input.retentionDays } });
      return { ...authorization, proofPath: "/.well-known/arzens-sentinel-verification.txt", proofValue: `arzens-sentinel-verification=${authorization.verificationToken}` };
    }),
    verify: protectedProcedure.input(z.object({ authorizationId: z.string().min(8).max(32) })).mutation(async ({ ctx, input }) => {
      const authorization = await getOwnedAuthorization(ctx.user.id, input.authorizationId);
      if (!authorization) throw new TRPCError({ code: "NOT_FOUND", message: "This target authorization was not found in your workspace." });
      try {
        await verifyWellKnownProof(authorization.origin, authorization.verificationToken);
        const updated = await recordAuthorizationVerification(ctx.user.id, authorization.id, { success: true });
        await writeAuditEvent({ userId: ctx.user.id, action: "target.authorization.verified", entityType: "target_authorization", entityId: authorization.id, outcome: "success", requestId: requestId(ctx.req.headers), metadata: { origin: authorization.origin } });
        return updated;
      } catch (error) {
        const detail = error instanceof Error ? error.message : "Verification failed";
        await recordAuthorizationVerification(ctx.user.id, authorization.id, { success: false, detail });
        await writeAuditEvent({ userId: ctx.user.id, action: "target.authorization.verified", entityType: "target_authorization", entityId: authorization.id, outcome: "failure", requestId: requestId(ctx.req.headers), metadata: { origin: authorization.origin } });
        throw operatorError(error);
      }
    }),
    revoke: protectedProcedure.input(z.object({ authorizationId: z.string().min(8).max(32) })).mutation(async ({ ctx, input }) => {
      const updated = await revokeTargetAuthorization(ctx.user.id, input.authorizationId);
      if (!updated) throw new TRPCError({ code: "NOT_FOUND", message: "This target authorization was not found in your workspace." });
      await writeAuditEvent({ userId: ctx.user.id, action: "target.authorization.revoked", entityType: "target_authorization", entityId: input.authorizationId, outcome: "success", requestId: requestId(ctx.req.headers), metadata: { origin: updated.origin } });
      return updated;
    }),
  }),
  scans: router({
    list: protectedProcedure.query(async ({ ctx }) => listUserScans(ctx.user.id)),
    detail: protectedProcedure.input(scanIdInput).query(async ({ ctx, input }) => { const detail = await getScanDetail(ctx.user.id, input.scanId); if (!detail) throw new TRPCError({ code: "NOT_FOUND", message: "This scan was not found in your workspace." }); return { ...detail, findings: detail.findings.map(item => ({ ...item, score: item.scoreTenth / 10 })) }; }),
    runDemo: protectedProcedure.mutation(async ({ ctx }) => { const scanId = await persistScanResult(ctx.user.id, getDemoScanResult()); await writeAuditEvent({ userId: ctx.user.id, action: "scan.demo.completed", entityType: "scan", entityId: scanId, outcome: "success", requestId: requestId(ctx.req.headers), metadata: { fixture: true } }); return { scanId }; }),
    run: protectedProcedure.input(z.object({ authorizationId: z.string().min(8).max(32), idempotencyKey: z.string().min(16).max(48).regex(/^[A-Za-z0-9_-]+$/, "Idempotency key contains unsupported characters."), profile: z.literal("safe_passive").default("safe_passive") })).mutation(async ({ ctx, input }) => {
      const previous = await getOwnedScanByRequestId(ctx.user.id, input.idempotencyKey);
      if (previous) return { scanId: previous.id, reused: true };
      await enforceScanBudget(ctx.user.id); await expireStaleAuthorizations(); const authorization = await getOwnedAuthorization(ctx.user.id, input.authorizationId);
      if (!authorization || authorization.status !== "verified" || authorization.expiresAt < new Date()) {
        await writeAuditEvent({ userId: ctx.user.id, action: "scan.live.started", entityType: "target_authorization", entityId: input.authorizationId, outcome: "denied", requestId: requestId(ctx.req.headers), metadata: { reason: "verified authorization required" } });
        throw new TRPCError({ code: "FORBIDDEN", message: "A current verified target authorization is required before a live assessment can start." });
      }
      if (await hasActiveAuthorizationScan(ctx.user.id, authorization.id)) throw new TRPCError({ code: "CONFLICT", message: "A live assessment for this verified target is already running." });
      const id = input.idempotencyKey; const started = await beginAuthorizedScan(ctx.user.id, authorization, id); if (started.reused) return { scanId: started.scanId, reused: true }; const scanId = started.scanId;
      await writeAuditEvent({ userId: ctx.user.id, action: "scan.live.started", entityType: "scan", entityId: scanId, outcome: "success", requestId: id, metadata: { authorizationId: authorization.id, origin: authorization.origin, scopePath: authorization.scopePath, retentionDays: authorization.retentionDays } });
      try {
        const seed = new URL(authorization.scopePath, authorization.origin).toString();
        const result = await runSafePassiveScan(seed, input.profile, { maxPages: authorization.maxPages, maxRedirects: authorization.maxRedirects, maxResponseBytes: authorization.maxResponseBytes, timeoutMs: authorization.timeoutMs }, { scope: { origin: authorization.origin, scopePath: authorization.scopePath }, shouldCancel: () => isScanCancellationRequested(scanId) });
        await completeAuthorizedScan(ctx.user.id, scanId, result);
        await writeAuditEvent({ userId: ctx.user.id, action: "scan.live.completed", entityType: "scan", entityId: scanId, outcome: "success", requestId: id, metadata: { endpoints: result.summary.scannedEndpoints, findings: result.summary.findingCount } });
        return { scanId, reused: false };
      } catch (error) {
        const cancelled = error instanceof ScanCancelledError; const message = error instanceof Error ? error.message : "The scan failed unexpectedly.";
        await failAuthorizedScan(ctx.user.id, scanId, message, cancelled);
        await writeAuditEvent({ userId: ctx.user.id, action: "scan.live.completed", entityType: "scan", entityId: scanId, outcome: "failure", requestId: id, metadata: { cancelled } });
        throw operatorError(error);
      }
    }),
    cancel: protectedProcedure.input(scanIdInput).mutation(async ({ ctx, input }) => { const updated = await requestScanCancellation(ctx.user.id, input.scanId); if (!updated) throw new TRPCError({ code: "NOT_FOUND", message: "No cancellable scan was found in your workspace." }); await writeAuditEvent({ userId: ctx.user.id, action: "scan.cancellation.requested", entityType: "scan", entityId: input.scanId, outcome: "success", requestId: requestId(ctx.req.headers) }); return updated; }),
  }),
  findings: router({
    update: protectedProcedure.input(z.object({ findingId: z.string().min(8).max(90), status: z.enum(["open", "in_review", "accepted_risk", "remediated"]).optional(), reviewerNote: z.string().max(2000).optional(), severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional(), severityOverrideNote: z.string().max(1000).optional() })).mutation(async ({ ctx, input }) => {
      if (input.severity && !input.severityOverrideNote) throw new TRPCError({ code: "BAD_REQUEST", message: "A severity override requires an audit note; the original score will be preserved." });
      const { findingId, ...changes } = input; const updated = await updateOwnedFinding(ctx.user.id, findingId, changes); if (!updated) throw new TRPCError({ code: "NOT_FOUND", message: "This finding was not found in your workspace." });
      await writeAuditEvent({ userId: ctx.user.id, action: "finding.review.updated", entityType: "finding", entityId: findingId, outcome: "success", requestId: requestId(ctx.req.headers), metadata: { status: changes.status, severityOverride: changes.severity } }); return { ...updated, score: updated.scoreTenth / 10 };
    }),
    remediation: router({
      list: protectedProcedure.input(findingIdInput).query(async ({ ctx, input }) => { const result = await listRemediation(ctx.user.id, input.findingId); if (!result) throw new TRPCError({ code: "NOT_FOUND", message: "This finding was not found in your workspace." }); return result; }),
      generate: protectedProcedure.input(findingIdInput).mutation(async ({ ctx, input }) => { const owned = await getOwnedFinding(ctx.user.id, input.findingId); if (!owned) throw new TRPCError({ code: "NOT_FOUND", message: "This finding was not found in your workspace." }); const aiEnabled = process.env.ENABLE_AI_REMEDIATION === "true"; const dailyAiCount = aiEnabled ? await countAuditActionSince(ctx.user.id, "remediation.ai.generated", new Date(Date.now() - 24 * 60 * 60 * 1000)) : 0; const guidance = await generateRemediation(toScannerFinding(owned.finding), { allowAi: dailyAiCount < 10 }); const stored = await storeRemediation(ctx.user.id, input.findingId, guidance); await writeAuditEvent({ userId: ctx.user.id, action: guidance.source === "ai" ? "remediation.ai.generated" : "remediation.generated", entityType: "finding", entityId: input.findingId, outcome: "success", requestId: requestId(ctx.req.headers), metadata: { source: guidance.source, budgetFallback: aiEnabled && dailyAiCount >= 10 } }); return stored; }),
    }),
  }),
  reports: router({
    generate: protectedProcedure.input(scanIdInput.extend({ format: z.enum(["json", "csv", "html", "pdf"]) })).mutation(async ({ ctx, input }) => {
      const detail = await getScanDetail(ctx.user.id, input.scanId); if (!detail) throw new TRPCError({ code: "NOT_FOUND", message: "This scan was not found in your workspace." });
      const payload = input.format === "json" ? createJsonReport(detail) : input.format === "csv" ? createCsvReport(detail) : input.format === "html" ? createHtmlReport(detail) : createPdfReport(detail); const contentType = input.format === "json" ? "application/json" : input.format === "csv" ? "text/csv; charset=utf-8" : input.format === "html" ? "text/html; charset=utf-8" : "application/pdf";
      const stored = await storagePut(`reports/${ctx.user.id}/${input.scanId}/arzens-sentinel-${input.scanId}.${input.format}`, payload, contentType); const artifact = await storeReportArtifact(ctx.user.id, input.scanId, input.format, stored.key, stored.url);
      await writeAuditEvent({ userId: ctx.user.id, action: "report.generated", entityType: "scan", entityId: input.scanId, outcome: "success", requestId: requestId(ctx.req.headers), metadata: { format: input.format } }); return artifact;
    }),
    download: protectedProcedure.input(z.object({ artifactId: z.string().min(8).max(32) })).mutation(async ({ ctx, input }) => {
      const owned = await getOwnedReportArtifact(ctx.user.id, input.artifactId); if (!owned) throw new TRPCError({ code: "NOT_FOUND", message: "This report is unavailable in your workspace." });
      const signedUrl = await storageGetSignedUrl(owned.artifact.storageKey); await markReportDownloaded(ctx.user.id, input.artifactId); await writeAuditEvent({ userId: ctx.user.id, action: "report.downloaded", entityType: "report_artifact", entityId: input.artifactId, outcome: "success", requestId: requestId(ctx.req.headers), metadata: { format: owned.artifact.format } }); return { url: signedUrl, format: owned.artifact.format, expiresAt: owned.artifact.expiresAt };
    }),
  }),
  audit: router({ list: protectedProcedure.query(async ({ ctx }) => listAuditEvents(ctx.user.id)) }),
  ai: router({ status: protectedProcedure.query(() => ({ mode: process.env.ENABLE_AI_REMEDIATION === "true" ? "built_in_schema_validated" : "deterministic_fallback", dailyGuidanceLimit: 10, externalKeyRequired: false })) }),
});

export type AppRouter = typeof appRouter;
