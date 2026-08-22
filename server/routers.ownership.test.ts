import { TRPCError } from "@trpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  listUserScans: vi.fn(),
  getScanDetail: vi.fn(),
  updateOwnedFinding: vi.fn(),
  getOwnedFinding: vi.fn(),
  listRemediation: vi.fn(),
}));

vi.mock("./db", () => ({
  listUserScans: mocks.listUserScans,
  getScanDetail: mocks.getScanDetail,
  updateOwnedFinding: mocks.updateOwnedFinding,
  getOwnedFinding: mocks.getOwnedFinding,
  listRemediation: mocks.listRemediation,
  persistScanResult: vi.fn(),
  storeRemediation: vi.fn(),
  storeReportArtifact: vi.fn(),
}));

import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function context(userId = 42): TrpcContext {
  return {
    user: { id: userId, openId: `user-${userId}`, name: "Owner", email: "owner@example.com", loginMethod: "manus", role: "user", createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date() },
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"],
  };
}

describe("protected assessment procedures", () => {
  beforeEach(() => vi.clearAllMocks());

  it("scopes scan history to the authenticated user", async () => {
    mocks.listUserScans.mockResolvedValue([]);
    const result = await appRouter.createCaller(context(42)).scans.list();
    expect(result).toEqual([]);
    expect(mocks.listUserScans).toHaveBeenCalledWith(42);
  });

  it("does not reveal another user’s scan when ownership lookup is empty", async () => {
    mocks.getScanDetail.mockResolvedValue(undefined);
    const error = await appRouter.createCaller(context(42)).scans.detail({ scanId: "foreign-scan-123" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError);
    expect((error as TRPCError).code).toBe("NOT_FOUND");
    expect(mocks.getScanDetail).toHaveBeenCalledWith(42, "foreign-scan-123");
  });

  it("requires an audit note when an authorized reviewer changes severity", async () => {
    const error = await appRouter.createCaller(context(42)).findings.update({ findingId: "ARS-CORS-001-demo-api", severity: "low" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError);
    expect((error as TRPCError).code).toBe("BAD_REQUEST");
    expect(mocks.updateOwnedFinding).not.toHaveBeenCalled();
  });

  it("does not return remediation records when a finding is outside the workspace", async () => {
    mocks.listRemediation.mockResolvedValue(undefined);
    const error = await appRouter.createCaller(context(42)).findings.remediation.list({ findingId: "foreign-finding-123" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError);
    expect((error as TRPCError).code).toBe("NOT_FOUND");
    expect(mocks.listRemediation).toHaveBeenCalledWith(42, "foreign-finding-123");
  });

  it("rejects a reviewer update when the requested finding is outside the workspace", async () => {
    mocks.updateOwnedFinding.mockResolvedValue(undefined);
    const error = await appRouter.createCaller(context(42)).findings.update({ findingId: "foreign-finding-123", status: "in_review", reviewerNote: "Attempted foreign update" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError);
    expect((error as TRPCError).code).toBe("NOT_FOUND");
    expect(mocks.updateOwnedFinding).toHaveBeenCalledWith(42, "foreign-finding-123", expect.objectContaining({ status: "in_review" }));
  });

  it("rejects remediation generation for a finding outside the workspace", async () => {
    mocks.getOwnedFinding.mockResolvedValue(undefined);
    const error = await appRouter.createCaller(context(42)).findings.remediation.generate({ findingId: "foreign-finding-123" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError);
    expect((error as TRPCError).code).toBe("NOT_FOUND");
    expect(mocks.getOwnedFinding).toHaveBeenCalledWith(42, "foreign-finding-123");
  });

  it("rejects report artifact generation for a scan outside the workspace", async () => {
    mocks.getScanDetail.mockResolvedValue(undefined);
    const error = await appRouter.createCaller(context(42)).reports.generate({ scanId: "foreign-scan-123", format: "pdf" }).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError);
    expect((error as TRPCError).code).toBe("NOT_FOUND");
    expect(mocks.getScanDetail).toHaveBeenCalledWith(42, "foreign-scan-123");
  });

  it("requires an explicit authorization attestation before a real target can reach scanner orchestration", async () => {
    const error = await appRouter.createCaller(context(42)).scans.run({
      targetUrl: "https://example.com",
      profile: "safe_passive",
      authorized: false,
    } as never).catch(item => item);
    expect(error).toBeInstanceOf(TRPCError);
    expect((error as TRPCError).code).toBe("BAD_REQUEST");
  });
});
