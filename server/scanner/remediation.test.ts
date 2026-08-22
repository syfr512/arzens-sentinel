import { describe, expect, it } from "vitest";
import { getDemoScanResult } from "./demo";
import { deterministicRemediation, generateRemediation } from "./remediation";

describe("remediation guidance", () => {
  it("provides a complete deterministic fallback that is explicitly advisory", () => {
    const finding = getDemoScanResult().findings[0]!;
    const guidance = deterministicRemediation(finding);
    expect(guidance.source).toBe("deterministic");
    expect(guidance.advisory).toBe(true);
    expect(guidance.steps.length).toBeGreaterThanOrEqual(2);
    expect(guidance.references).toContain(finding.reference);
    expect(guidance.patch).toBeNull();
  });

  it("does not make an AI request unless the feature is explicitly enabled", async () => {
    const previous = process.env.ENABLE_AI_REMEDIATION;
    delete process.env.ENABLE_AI_REMEDIATION;
    const guidance = await generateRemediation(getDemoScanResult().findings[0]!);
    expect(guidance.source).toBe("deterministic");
    process.env.ENABLE_AI_REMEDIATION = previous;
  });
});
