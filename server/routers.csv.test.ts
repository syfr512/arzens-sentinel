import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getScanDetail: vi.fn(), storeReportArtifact: vi.fn(), getOwnedReportArtifact: vi.fn(), markReportDownloaded: vi.fn(), writeAuditEvent: vi.fn(), storagePut: vi.fn(), storageGetSignedUrl: vi.fn(),
}));

vi.mock("./db", () => ({
  getScanDetail: mocks.getScanDetail, storeReportArtifact: mocks.storeReportArtifact, getOwnedReportArtifact: mocks.getOwnedReportArtifact, markReportDownloaded: mocks.markReportDownloaded, writeAuditEvent: mocks.writeAuditEvent,
  countRecentLiveScans: vi.fn(), expireStaleAuthorizations: vi.fn(), getOwnedAuthorization: vi.fn(), getOwnedScanByRequestId: vi.fn(), hasActiveAuthorizationScan: vi.fn(), beginAuthorizedScan: vi.fn(), completeAuthorizedScan: vi.fn(), failAuthorizedScan: vi.fn(), isScanCancellationRequested: vi.fn(), persistScanResult: vi.fn(), requestScanCancellation: vi.fn(), listUserScans: vi.fn(), listTargetAuthorizations: vi.fn(), createTargetAuthorization: vi.fn(), recordAuthorizationVerification: vi.fn(), revokeTargetAuthorization: vi.fn(), getOwnedFinding: vi.fn(), listRemediation: vi.fn(), updateOwnedFinding: vi.fn(), storeRemediation: vi.fn(), listAuditEvents: vi.fn(), countAuditActionSince: vi.fn(),
}));
vi.mock("./scanner/core", () => ({ TargetSafetyError: class TargetSafetyError extends Error {}, ScanCancelledError: class ScanCancelledError extends Error {}, assertSafeTarget: vi.fn(), runSafePassiveScan: vi.fn(), verifyWellKnownProof: vi.fn() }));
vi.mock("./scanner/demo", () => ({ getDemoScanResult: vi.fn() }));
vi.mock("./scanner/remediation", () => ({ generateRemediation: vi.fn() }));
vi.mock("./storage", () => ({ storagePut: mocks.storagePut, storageGetSignedUrl: mocks.storageGetSignedUrl }));

import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function context(): TrpcContext { return { user: { id: 41, openId: "csv-owner", name: "CSV Owner", email: "csv@example.com", loginMethod: "manus", role: "user", createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date() }, req: { protocol: "https", headers: { "x-request-id": "csv-request-123" } } as TrpcContext["req"], res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"] }; }
function detail() { return { scan: { id: "scan-csv-123", targetUrl: "https://controlled.example.test/", profile: "safe_passive", status: "completed", riskScore: 48, overallSeverity: "medium", endpointCount: 1, findingCount: 1, createdAt: new Date(), completedAt: new Date() }, endpoints: [], findings: [{ id: "finding-csv-123", ruleId: "ARS-HEAD-001", title: "Missing CSP", category: "Security Headers", severity: "medium", originalSeverity: "medium", scoreTenth: 55, confidence: "high", endpoint: "https://controlled.example.test/", evidence: "token=[REDACTED]", remediation: "Set CSP", status: "open", reviewerNote: null, reference: "https://example.test/reference" }], events: [], artifacts: [] }; }

describe("CSV report artifact workflow", () => {
  beforeEach(() => { vi.clearAllMocks(); mocks.getScanDetail.mockResolvedValue(detail()); mocks.storagePut.mockResolvedValue({ key: "reports/41/scan-csv-123/report.csv", url: "s3://reports/report.csv" }); mocks.storeReportArtifact.mockResolvedValue({ id: "artifact-csv-123", format: "csv", storageKey: "reports/41/scan-csv-123/report.csv", url: "s3://reports/report.csv", expiresAt: new Date(Date.now() + 86400000) }); mocks.writeAuditEvent.mockResolvedValue("audit-csv-123"); });

  it("stores a redacted CSV artifact then retrieves it through an owner-checked signed link", async () => {
    const caller = appRouter.createCaller(context());
    const artifact = await caller.reports.generate({ scanId: "scan-csv-123", format: "csv" });
    expect(artifact).toMatchObject({ id: "artifact-csv-123", format: "csv" });
    expect(mocks.storagePut).toHaveBeenCalledWith(expect.stringContaining(".csv"), expect.stringContaining("[REDACTED]"), "text/csv; charset=utf-8");
    expect(mocks.storeReportArtifact).toHaveBeenCalledWith(41, "scan-csv-123", "csv", expect.any(String), expect.any(String));
    mocks.getOwnedReportArtifact.mockResolvedValue({ artifact, scan: { id: "scan-csv-123" } }); mocks.storageGetSignedUrl.mockResolvedValue("https://signed.example.test/report.csv"); mocks.markReportDownloaded.mockResolvedValue(artifact);
    const download = await caller.reports.download({ artifactId: "artifact-csv-123" });
    expect(download).toMatchObject({ url: "https://signed.example.test/report.csv", format: "csv" });
    expect(mocks.markReportDownloaded).toHaveBeenCalledWith(41, "artifact-csv-123");
    expect(mocks.writeAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: "report.downloaded", metadata: { format: "csv" } }));
  });
});
