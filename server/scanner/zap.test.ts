import { describe, expect, it } from "vitest";
import { normalizeZapAlert } from "./zap";

describe("local ZAP adapter normalization", () => {
  it("maps local ZAP alert fixtures into stable scanner rules without changing source metadata", () => {
    const finding = normalizeZapAlert({
      alert: "Content Security Policy (CSP) Header Not Set",
      riskcode: "2",
      confidence: "High",
      url: "https://lab.example.test/",
      evidence: "content-security-policy header absent",
    });
    expect(finding.ruleId).toBe("ARS-HEAD-001");
    expect(finding.source).toBe("zap");
    expect(finding.confidence).toBe("high");
    expect(finding.id).toMatch(/^ARS-HEAD-001-zap-/);
  });
});
