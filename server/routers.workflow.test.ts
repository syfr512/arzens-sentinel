import { beforeEach, describe, expect, it, vi } from "vitest";
import { getDemoScanResult } from "./scanner/demo";

const mocks = vi.hoisted(() => ({
  persistScanResult: vi.fn(),
  getScanDetail: vi.fn(),
  getOwnedFinding: vi.fn(),
  storeRemediation: vi.fn(),
  storagePut: vi.fn(),
  storeReportArtifact: vi.fn(),
}));

vi.mock("./db", () => ({
  listUserScans: vi.fn(),
  getScanDetail: mocks.getScanDetail,
  getOwnedFinding: mocks.getOwnedFinding,
  persistScanResult: mocks.persistScanResult,
  storeRemediation: mocks.storeRemediation,
  storeReportArtifact: mocks.storeReportArtifact,
  updateOwnedFinding: vi.fn(),
  listRemediation: vi.fn(),
}));

vi.mock("./storage", () => ({ storagePut: mocks.storagePut }));

import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function context(): TrpcContext {
  return {
    user: { id: 7, openId: "workflow-owner", name: "Workflow Owner", email: "owner@example.com", loginMethod: "manus", role: "user", createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date() },
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"],
  };
}

function detailFixture() {
  const demo = getDemoScanResult();
  return {
    scan: { id: "demo-scan-123", userId: 7, targetId: "demo-target", targetUrl: demo.targetUrl, profile: "safe_passive" as const, status: "completed" as const, riskScore: Math.round(demo.summary.score * 10), overallSeverity: demo.summary.severity, endpointCount: demo.summary.scannedEndpoints, findingCount: demo.summary.findingCount, errorMessage: null, startedAt: new Date(), completedAt: new Date(), createdAt: new Date() },
    endpoints: demo.endpoints.map((item, index) => ({ ...item, id: `endpoint-${index}`, scanId: "demo-scan-123", createdAt: new Date() })),
    findings: demo.findings.map(item => ({ ...item, scanId: "demo-scan-123", scoreTenth: Math.round(item.score * 10), reviewerNote: null, severityOverrideNote: null, createdAt: new Date(), updatedAt: new Date() })),
    events: demo.activity.map((item, index) => ({ id: `event-${index}`, scanId: "demo-scan-123", label: item.label, detail: item.detail, createdAt: new Date(item.at) })),
    artifacts: [],
  };
}

describe("authenticated demo workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    const detail = detailFixture();
    mocks.persistScanResult.mockResolvedValue("demo-scan-123");
    mocks.getScanDetail.mockResolvedValue(detail);
    mocks.getOwnedFinding.mockResolvedValue({ finding: detail.findings[0], scan: detail.scan });
    mocks.storeRemediation.mockResolvedValue({ id: "remediation-123", guidance: { source: "deterministic", advisory: true } });
    mocks.storagePut.mockResolvedValue({ key: "reports/7/demo-scan-123/report.pdf", url: "/manus-storage/reports/7/demo-scan-123/report.pdf" });
    mocks.storeReportArtifact.mockResolvedValue({ id: "artifact-123", format: "pdf", storageKey: "reports/7/demo-scan-123/report.pdf", url: "/manus-storage/reports/7/demo-scan-123/report.pdf" });
  });

  it("runs a fixture-backed demo through persistence, review, deterministic remediation, and secure report artifact metadata", async () => {
    const caller = appRouter.createCaller(context());
    const demo = await caller.scans.runDemo();
    expect(demo.scanId).toBe("demo-scan-123");
    expect(mocks.persistScanResult).toHaveBeenCalledWith(7, expect.objectContaining({ targetUrl: "https://demo.arzens.example", profile: "safe_passive" }));

    const detail = await caller.scans.detail({ scanId: demo.scanId });
    expect(detail.findings).toHaveLength(5);
    expect(detail.findings[0]?.evidence).toContain("Access-Control-Allow-Origin");

    const remediation = await caller.findings.remediation.generate({ findingId: detail.findings[0]!.id });
    expect(remediation).toEqual(expect.objectContaining({ id: "remediation-123" }));
    expect(mocks.storeRemediation).toHaveBeenCalledWith(7, detail.findings[0]!.id, expect.objectContaining({ advisory: true, source: "deterministic" }));

    const report = await caller.reports.generate({ scanId: demo.scanId, format: "pdf" });
    expect(report).toEqual(expect.objectContaining({ format: "pdf", url: "/manus-storage/reports/7/demo-scan-123/report.pdf" }));
    expect(mocks.storagePut).toHaveBeenCalledWith(expect.stringContaining("reports/7/demo-scan-123"), expect.any(Buffer), "application/pdf");
    expect(mocks.storeReportArtifact).toHaveBeenCalledWith(7, demo.scanId, "pdf", expect.any(String), expect.any(String));
  });
});
