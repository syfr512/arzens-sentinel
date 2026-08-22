import { describe, expect, it } from "vitest";
import { assertSafeTarget, redactEvidence, runSafePassiveScan, TargetSafetyError } from "./core";
import { getDemoScanResult } from "./demo";
import { scoreFromFactors, severityFromScore } from "./rules";

describe("scanner safety boundaries", () => {
  it("rejects localhost, loopback, private, link-local, and non-HTTP targets", async () => {
    await expect(assertSafeTarget("http://localhost:3000")).rejects.toBeInstanceOf(TargetSafetyError);
    await expect(assertSafeTarget("http://127.0.0.1/admin")).rejects.toBeInstanceOf(TargetSafetyError);
    await expect(assertSafeTarget("http://10.0.0.5")).rejects.toBeInstanceOf(TargetSafetyError);
    await expect(assertSafeTarget("http://169.254.169.254/latest/meta-data")).rejects.toBeInstanceOf(TargetSafetyError);
    await expect(assertSafeTarget("file:///etc/passwd")).rejects.toBeInstanceOf(TargetSafetyError);
  });

  it("enforces Safe Passive as the hosted profile", async () => {
    await expect(runSafePassiveScan("https://example.com", "active_lab")).rejects.toThrow("Active Lab checks");
  });

  it("redacts bearer tokens, named secrets, and token-like values before evidence persists", () => {
    const evidence = "authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEF\napi_key=private-value\npassword: never-store-this";
    const redacted = redactEvidence(evidence);
    expect(redacted).toContain("Bearer [REDACTED]");
    expect(redacted).toContain("api_key=[REDACTED]");
    expect(redacted).toContain("password: [REDACTED]");
    expect(redacted).not.toContain("private-value");
  });
});

describe("scoring and demo fixture", () => {
  it("maps documented impact and exploitability factors to explainable severity bands", () => {
    expect(scoreFromFactors(7, 6)).toBe(6.6);
    expect(severityFromScore(9)).toBe("critical");
    expect(severityFromScore(7)).toBe("high");
    expect(severityFromScore(4)).toBe("medium");
    expect(severityFromScore(2)).toBe("low");
  });

  it("provides a fixture-backed demo without a network target", () => {
    const result = getDemoScanResult();
    expect(result.targetUrl).toBe("https://demo.arzens.example");
    expect(result.profile).toBe("safe_passive");
    expect(result.endpoints).toHaveLength(5);
    expect(result.findings.map(item => item.source)).toEqual(Array(5).fill("demo"));
    expect(result.activity[0]?.detail).toContain("No third-party system was contacted");
  });
});
