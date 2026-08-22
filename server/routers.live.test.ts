import { TRPCError } from "@trpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getDemoScanResult } from "./scanner/demo";

const mocks = vi.hoisted(() => ({
  countRecentLiveScans: vi.fn(), expireStaleAuthorizations: vi.fn(), getOwnedAuthorization: vi.fn(), getOwnedScanByRequestId: vi.fn(), hasActiveAuthorizationScan: vi.fn(), beginAuthorizedScan: vi.fn(), completeAuthorizedScan: vi.fn(), failAuthorizedScan: vi.fn(), isScanCancellationRequested: vi.fn(), writeAuditEvent: vi.fn(), createTargetAuthorization: vi.fn(), recordAuthorizationVerification: vi.fn(), getOwnedReportArtifact: vi.fn(), markReportDownloaded: vi.fn(),
  runSafePassiveScan: vi.fn(), assertSafeTarget: vi.fn(), verifyWellKnownProof: vi.fn(), storageGetSignedUrl: vi.fn(),
}));

vi.mock("./db", () => ({
  countRecentLiveScans: mocks.countRecentLiveScans, expireStaleAuthorizations: mocks.expireStaleAuthorizations, getOwnedAuthorization: mocks.getOwnedAuthorization, getOwnedScanByRequestId: mocks.getOwnedScanByRequestId, hasActiveAuthorizationScan: mocks.hasActiveAuthorizationScan, beginAuthorizedScan: mocks.beginAuthorizedScan, completeAuthorizedScan: mocks.completeAuthorizedScan, failAuthorizedScan: mocks.failAuthorizedScan, isScanCancellationRequested: mocks.isScanCancellationRequested, writeAuditEvent: mocks.writeAuditEvent, createTargetAuthorization: mocks.createTargetAuthorization, recordAuthorizationVerification: mocks.recordAuthorizationVerification, getOwnedReportArtifact: mocks.getOwnedReportArtifact, markReportDownloaded: mocks.markReportDownloaded,
  listTargetAuthorizations: vi.fn(), listUserScans: vi.fn(), getScanDetail: vi.fn(), persistScanResult: vi.fn(), requestScanCancellation: vi.fn(), getOwnedFinding: vi.fn(), listRemediation: vi.fn(), updateOwnedFinding: vi.fn(), storeRemediation: vi.fn(), storeReportArtifact: vi.fn(), listAuditEvents: vi.fn(), revokeTargetAuthorization: vi.fn(), countAuditActionSince: vi.fn(),
}));
vi.mock("./scanner/core", () => ({ TargetSafetyError: class TargetSafetyError extends Error {}, ScanCancelledError: class ScanCancelledError extends Error {}, runSafePassiveScan: mocks.runSafePassiveScan, assertSafeTarget: mocks.assertSafeTarget, verifyWellKnownProof: mocks.verifyWellKnownProof }));
vi.mock("./storage", () => ({ storageGetSignedUrl: mocks.storageGetSignedUrl, storagePut: vi.fn() }));

import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function context(): TrpcContext { return { user: { id: 19, openId: "live-owner", name: "Live Owner", email: "owner@example.com", loginMethod: "manus", role: "user", createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date() }, req: { protocol: "https", headers: { "x-request-id": "test-live-request" } } as TrpcContext["req"], res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"] }; }
function authorization(status: "verified" | "pending" = "verified") { return { id: "auth-live-123", userId: 19, origin: "https://staging.example.com", hostname: "staging.example.com", scopePath: "/app/", status, verificationMethod: "well_known_file", verificationToken: "token-123", verificationAttempts: 1, lastVerificationError: null, verifiedAt: new Date(), lastVerifiedAt: new Date(), expiresAt: new Date(Date.now() + 86400000), maxPages: 3, maxRedirects: 2, maxResponseBytes: 100000, timeoutMs: 4000, retentionDays: 30, policyVersion: 1, createdAt: new Date(), updatedAt: new Date() }; }
const key = (value: number) => `test-idempotency-${String(value).padStart(4, "0")}`;

describe("live verified-target controls", () => {
  beforeEach(() => { vi.clearAllMocks(); mocks.countRecentLiveScans.mockResolvedValue(0); mocks.expireStaleAuthorizations.mockResolvedValue(undefined); mocks.getOwnedScanByRequestId.mockResolvedValue(undefined); mocks.hasActiveAuthorizationScan.mockResolvedValue(false); mocks.beginAuthorizedScan.mockResolvedValue({ scanId: "scan-live-123", reused: false }); mocks.completeAuthorizedScan.mockResolvedValue({ id: "scan-live-123" }); mocks.isScanCancellationRequested.mockResolvedValue(false); mocks.writeAuditEvent.mockResolvedValue("audit-1"); mocks.runSafePassiveScan.mockResolvedValue(getDemoScanResult()); });

  it("denies a live assessment until the user has a verified target authorization", async () => {
    mocks.getOwnedAuthorization.mockResolvedValue(authorization("pending"));
    const error = await appRouter.createCaller(context()).scans.run({ authorizationId: "auth-live-123", idempotencyKey: key(1), profile: "safe_passive" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError); expect((error as TRPCError).code).toBe("FORBIDDEN"); expect(mocks.beginAuthorizedScan).not.toHaveBeenCalled();
  });

  it("records a verified policy before executing an origin- and path-scoped safe assessment", async () => {
    mocks.getOwnedAuthorization.mockResolvedValue(authorization());
    const result = await appRouter.createCaller(context()).scans.run({ authorizationId: "auth-live-123", idempotencyKey: key(2), profile: "safe_passive" });
    expect(result).toEqual({ scanId: "scan-live-123", reused: false });
    expect(mocks.beginAuthorizedScan).toHaveBeenCalledWith(19, expect.objectContaining({ id: "auth-live-123", retentionDays: 30 }), key(2));
    expect(mocks.runSafePassiveScan).toHaveBeenCalledWith("https://staging.example.com/app/", "safe_passive", expect.objectContaining({ maxPages: 3, maxRedirects: 2 }), expect.objectContaining({ scope: { origin: "https://staging.example.com", scopePath: "/app/" } }));
    expect(mocks.completeAuthorizedScan).toHaveBeenCalledWith(19, "scan-live-123", expect.anything());
  });

  it("prevents duplicate concurrent assessments for the same authorization", async () => {
    mocks.getOwnedAuthorization.mockResolvedValue(authorization()); mocks.hasActiveAuthorizationScan.mockResolvedValue(true);
    const error = await appRouter.createCaller(context()).scans.run({ authorizationId: "auth-live-123", idempotencyKey: key(3), profile: "safe_passive" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError); expect((error as TRPCError).code).toBe("CONFLICT"); expect(mocks.beginAuthorizedScan).not.toHaveBeenCalled();
  });

  it("enforces the database-backed hourly scan budget before outbound work", async () => {
    mocks.countRecentLiveScans.mockResolvedValue(6);
    const error = await appRouter.createCaller(context()).scans.run({ authorizationId: "auth-live-123", idempotencyKey: key(4), profile: "safe_passive" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError); expect((error as TRPCError).code).toBe("TOO_MANY_REQUESTS");
  });

  it("returns the existing scan for a repeated idempotency key without starting a duplicate", async () => {
    mocks.getOwnedScanByRequestId.mockResolvedValue({ id: "scan-existing-123" });
    const result = await appRouter.createCaller(context()).scans.run({ authorizationId: "auth-live-123", idempotencyKey: key(5), profile: "safe_passive" });
    expect(result).toEqual({ scanId: "scan-existing-123", reused: true });
    expect(mocks.beginAuthorizedScan).not.toHaveBeenCalled(); expect(mocks.runSafePassiveScan).not.toHaveBeenCalled();
  });

  it("returns a signed report link only after artifact ownership is checked", async () => {
    mocks.getOwnedReportArtifact.mockResolvedValue({ artifact: { id: "artifact-123", scanId: "scan-live-123", format: "pdf", storageKey: "reports/19/scan-live-123/report.pdf", expiresAt: new Date(Date.now() + 60000) }, scan: { id: "scan-live-123" } }); mocks.storageGetSignedUrl.mockResolvedValue("https://signed.example/report.pdf"); mocks.markReportDownloaded.mockResolvedValue({});
    const result = await appRouter.createCaller(context()).reports.download({ artifactId: "artifact-123" });
    expect(result.url).toBe("https://signed.example/report.pdf"); expect(mocks.markReportDownloaded).toHaveBeenCalledWith(19, "artifact-123");
  });
});
