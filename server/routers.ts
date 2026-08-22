import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { COOKIE_NAME } from "@shared/const";
import type { ScannerFinding } from "@shared/security";
import { findings as findingsTable } from "../drizzle/schema";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import {
  getOwnedFinding,
  getScanDetail,
  listRemediation,
  listUserScans,
  persistScanResult,
  storeRemediation,
  storeReportArtifact,
  updateOwnedFinding,
} from "./db";
import { createHtmlReport, createJsonReport, createPdfReport } from "./reports/render";
import { getDemoScanResult } from "./scanner/demo";
import { generateRemediation } from "./scanner/remediation";
import { runSafePassiveScan, TargetSafetyError } from "./scanner/core";
import { storagePut } from "./storage";

const scanIdInput = z.object({ scanId: z.string().min(8).max(32) });
const findingIdInput = z.object({ findingId: z.string().min(8).max(90) });

function toScannerFinding(item: typeof findingsTable.$inferSelect): ScannerFinding {
  const { scoreTenth, rationale, ...rest } = item;
  return {
    ...rest,
    score: scoreTenth / 10,
    rationale: rationale as ScannerFinding["rationale"],
  };
}

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),
  scans: router({
    list: protectedProcedure.query(async ({ ctx }) => listUserScans(ctx.user.id)),
    detail: protectedProcedure.input(scanIdInput).query(async ({ ctx, input }) => {
      const detail = await getScanDetail(ctx.user.id, input.scanId);
      if (!detail) throw new TRPCError({ code: "NOT_FOUND", message: "This scan was not found in your workspace." });
      return { ...detail, findings: detail.findings.map(item => ({ ...item, score: item.scoreTenth / 10 })) };
    }),
    runDemo: protectedProcedure.mutation(async ({ ctx }) => {
      const scanId = await persistScanResult(ctx.user.id, getDemoScanResult());
      return { scanId };
    }),
    run: protectedProcedure.input(z.object({ targetUrl: z.string().min(8).max(2048), profile: z.literal("safe_passive").default("safe_passive"), authorized: z.literal(true) })).mutation(async ({ ctx, input }) => {
      try {
        const result = await runSafePassiveScan(input.targetUrl, input.profile);
        const scanId = await persistScanResult(ctx.user.id, result);
        return { scanId };
      } catch (error) {
        if (error instanceof TargetSafetyError) throw new TRPCError({ code: "BAD_REQUEST", message: error.message });
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "The bounded assessment could not complete. No unredacted response content was persisted." });
      }
    }),
  }),
  findings: router({
    update: protectedProcedure.input(z.object({ findingId: z.string().min(8).max(90), status: z.enum(["open", "in_review", "accepted_risk", "remediated"]).optional(), reviewerNote: z.string().max(2000).optional(), severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional(), severityOverrideNote: z.string().max(1000).optional() })).mutation(async ({ ctx, input }) => {
      if (input.severity && !input.severityOverrideNote) throw new TRPCError({ code: "BAD_REQUEST", message: "A severity override requires an audit note; the original score will be preserved." });
      const { findingId, ...changes } = input;
      const updated = await updateOwnedFinding(ctx.user.id, findingId, changes);
      if (!updated) throw new TRPCError({ code: "NOT_FOUND", message: "This finding was not found in your workspace." });
      return { ...updated, score: updated.scoreTenth / 10 };
    }),
    remediation: router({
      list: protectedProcedure.input(findingIdInput).query(async ({ ctx, input }) => {
        const result = await listRemediation(ctx.user.id, input.findingId);
        if (!result) throw new TRPCError({ code: "NOT_FOUND", message: "This finding was not found in your workspace." });
        return result;
      }),
      generate: protectedProcedure.input(findingIdInput).mutation(async ({ ctx, input }) => {
        const owned = await getOwnedFinding(ctx.user.id, input.findingId);
        if (!owned) throw new TRPCError({ code: "NOT_FOUND", message: "This finding was not found in your workspace." });
        const guidance = await generateRemediation(toScannerFinding(owned.finding));
        return storeRemediation(ctx.user.id, input.findingId, guidance);
      }),
    }),
  }),
  reports: router({
    generate: protectedProcedure.input(scanIdInput.extend({ format: z.enum(["json", "html", "pdf"]) })).mutation(async ({ ctx, input }) => {
      const detail = await getScanDetail(ctx.user.id, input.scanId);
      if (!detail) throw new TRPCError({ code: "NOT_FOUND", message: "This scan was not found in your workspace." });
      const reportDetail = { ...detail, findings: detail.findings.map(item => ({ ...item, scoreTenth: item.scoreTenth })) };
      const payload = input.format === "json" ? createJsonReport(reportDetail) : input.format === "html" ? createHtmlReport(reportDetail) : createPdfReport(reportDetail);
      const contentType = input.format === "json" ? "application/json" : input.format === "html" ? "text/html; charset=utf-8" : "application/pdf";
      const fileName = `reports/${ctx.user.id}/${input.scanId}/arzens-sentinel-${input.scanId}.${input.format}`;
      const stored = await storagePut(fileName, payload, contentType);
      return storeReportArtifact(ctx.user.id, input.scanId, input.format, stored.key, stored.url);
    }),
  }),
});

export type AppRouter = typeof appRouter;
