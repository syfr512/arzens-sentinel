import { TRPCError } from "@trpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getOwnedReportArtifact: vi.fn(), markReportDownloaded: vi.fn(), requestScanCancellation: vi.fn(), writeAuditEvent: vi.fn(),
  countRecentLiveScans: vi.fn(), expireStaleAuthorizations: vi.fn(), getOwnedScanByRequestId: vi.fn(), getOwnedAuthorization: vi.fn(), hasActiveAuthorizationScan: vi.fn(), beginAuthorizedScan: vi.fn(), completeAuthorizedScan: vi.fn(), failAuthorizedScan: vi.fn(), isScanCancellationRequested: vi.fn(),
  getOwnedFinding: vi.fn(), countAuditActionSince: vi.fn(), storeRemediation: vi.fn(), generateRemediation: vi.fn(), runSafePassiveScan: vi.fn(), storageGetSignedUrl: vi.fn(),
}));

vi.mock("./db", () => ({
  getOwnedReportArtifact: mocks.getOwnedReportArtifact, markReportDownloaded: mocks.markReportDownloaded, requestScanCancellation: mocks.requestScanCancellation, writeAuditEvent: mocks.writeAuditEvent,
  countRecentLiveScans: mocks.countRecentLiveScans, expireStaleAuthorizations: mocks.expireStaleAuthorizations, getOwnedScanByRequestId: mocks.getOwnedScanByRequestId, getOwnedAuthorization: mocks.getOwnedAuthorization, hasActiveAuthorizationScan: mocks.hasActiveAuthorizationScan, beginAuthorizedScan: mocks.beginAuthorizedScan, completeAuthorizedScan: mocks.completeAuthorizedScan, failAuthorizedScan: mocks.failAuthorizedScan, isScanCancellationRequested: mocks.isScanCancellationRequested,
  getOwnedFinding: mocks.getOwnedFinding, countAuditActionSince: mocks.countAuditActionSince, storeRemediation: mocks.storeRemediation,
  listTargetAuthorizations: vi.fn(), createTargetAuthorization: vi.fn(), recordAuthorizationVerification: vi.fn(), revokeTargetAuthorization: vi.fn(), listUserScans: vi.fn(), getScanDetail: vi.fn(), persistScanResult: vi.fn(), listRemediation: vi.fn(), updateOwnedFinding: vi.fn(), storeReportArtifact: vi.fn(), listAuditEvents: vi.fn(),
}));
vi.mock("./scanner/core", () => ({
  TargetSafetyError: class TargetSafetyError extends Error {}, ScanCancelledError: class ScanCancelledError extends Error {}, runSafePassiveScan: mocks.runSafePassiveScan, assertSafeTarget: vi.fn(), verifyWellKnownProof: vi.fn(),
}));
vi.mock("./scanner/remediation", () => ({ generateRemediation: mocks.generateRemediation }));
vi.mock("./storage", () => ({ storageGetSignedUrl: mocks.storageGetSignedUrl, storagePut: vi.fn() }));

import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function context(): TrpcContext { return { user: { id: 22, openId: "hardening-owner", name: "Hardening Owner", email: "owner@example.com", loginMethod: "manus", role: "user", createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date() }, req: { protocol: "https", headers: {} } as TrpcContext["req"], res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"] }; }
function authorization() { return { id: "auth-hardening-123", userId: 22, origin: "https://staging.example.com", hostname: "staging.example.com", scopePath: "/", status: "verified", expiresAt: new Date(Date.now() + 86400000), maxPages: 2, maxRedirects: 2, maxResponseBytes: 100000, timeoutMs: 4000, retentionDays: 7 }; }
function finding() { return { id: "finding-hardening-123", scanId: "scan-hardening-123", scoreTenth: 60, rationale: { impact: 6, exploitability: 6, score: 6, explanation: "test" }, ruleId: "ARS-HEAD-001", title: "Missing CSP", category: "headers", severity: "medium", originalSeverity: "medium", confidence: "high", endpoint: "https://staging.example.com/", evidence: "redacted", reference: "https://example.com", remediation: "Add CSP", status: "open", source: "native" }; }

describe("hardening lifecycle and retention controls", () => {
  beforeEach(() => { vi.clearAllMocks(); mocks.writeAuditEvent.mockResolvedValue("audit"); mocks.getOwnedScanByRequestId.mockResolvedValue(undefined); mocks.countRecentLiveScans.mockResolvedValue(0); mocks.expireStaleAuthorizations.mockResolvedValue(undefined); mocks.getOwnedAuthorization.mockResolvedValue(authorization()); mocks.hasActiveAuthorizationScan.mockResolvedValue(false); mocks.beginAuthorizedScan.mockResolvedValue({ scanId: "scan-hardening-123", reused: false }); mocks.isScanCancellationRequested.mockResolvedValue(false); });

  it("hides expired report artifacts by treating the owner lookup as unavailable", async () => {
    mocks.getOwnedReportArtifact.mockResolvedValue(undefined);
    const error = await appRouter.createCaller(context()).reports.download({ artifactId: "artifact-hardening-123" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError); expect((error as TRPCError).code).toBe("NOT_FOUND"); expect(mocks.storageGetSignedUrl).not.toHaveBeenCalled();
  });

  it("records cancellation requests only for owner-visible active scans", async () => {
    mocks.requestScanCancellation.mockResolvedValue({ id: "scan-hardening-123", status: "running" });
    const result = await appRouter.createCaller(context()).scans.cancel({ scanId: "scan-hardening-123" });
    expect(result).toMatchObject({ id: "scan-hardening-123" }); expect(mocks.writeAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: "scan.cancellation.requested", outcome: "success" }));
  });

  it("records a failed scan lifecycle transition when scanner execution throws", async () => {
    mocks.runSafePassiveScan.mockRejectedValue(new Error("bounded transport failed"));
    const error = await appRouter.createCaller(context()).scans.run({ authorizationId: "auth-hardening-123", idempotencyKey: "hardening-idempotency-0001", profile: "safe_passive" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError); expect((error as TRPCError).code).toBe("INTERNAL_SERVER_ERROR"); expect(mocks.failAuthorizedScan).toHaveBeenCalledWith(22, "scan-hardening-123", "bounded transport failed", false);
  });

  it("uses deterministic guidance when the daily AI budget is already exhausted", async () => {
    const prior = process.env.ENABLE_AI_REMEDIATION; process.env.ENABLE_AI_REMEDIATION = "true";
    mocks.getOwnedFinding.mockResolvedValue({ finding: finding(), scan: { id: "scan-hardening-123" } }); mocks.countAuditActionSince.mockResolvedValue(10); mocks.generateRemediation.mockResolvedValue({ source: "deterministic", summary: "Fallback", steps: ["Add CSP"], validation: ["Verify header"], limitations: ["Review manually"] }); mocks.storeRemediation.mockResolvedValue({ id: "remediation-hardening", guidance: { source: "deterministic" } });
    const result = await appRouter.createCaller(context()).findings.remediation.generate({ findingId: "finding-hardening-123" });
    expect(result).toMatchObject({ id: "remediation-hardening" }); expect(mocks.generateRemediation).toHaveBeenCalledWith(expect.anything(), { allowAi: false }); expect(mocks.writeAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: "remediation.generated", metadata: expect.objectContaining({ budgetFallback: true }) })); process.env.ENABLE_AI_REMEDIATION = prior;
  });
});
