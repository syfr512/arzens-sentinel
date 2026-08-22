import { describe, expect, it } from "vitest";
import { evaluatePassiveFixture } from "./core";

describe("controlled vulnerability-lab fixtures", () => {
  it("detects the expected safe-passive signals from a controlled response without issuing network traffic", () => {
    const findings = evaluatePassiveFixture("https://lab.example.test/headers-missing", {
      headers: {
        "set-cookie": "session=secret-token-value; Path=/",
        "access-control-allow-origin": "*",
        server: "FixtureServer/1.0",
      },
      body: '<img src="http://cdn.example.test/logo.png">',
    });
    const ids = findings.map(item => item.ruleId);
    expect(ids).toEqual(expect.arrayContaining([
      "ARS-HEAD-001", "ARS-HEAD-002", "ARS-HEAD-003", "ARS-HEAD-004", "ARS-HEAD-005", "ARS-HEAD-006",
      "ARS-COOKIE-001", "ARS-COOKIE-002", "ARS-COOKIE-003", "ARS-CORS-001", "ARS-DISC-001", "ARS-MIXED-001",
    ]));
    expect(findings.every(item => !item.evidence.includes("secret-token-value"))).toBe(true);
  });

  it("flags unsafe inline scripts while accepting a strict cookie and header baseline", () => {
    const findings = evaluatePassiveFixture("https://lab.example.test/csp", {
      headers: {
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
        "set-cookie": "session=value; Secure; HttpOnly; SameSite=Lax",
      },
    });
    const ids = findings.map(item => item.ruleId);
    expect(ids).toContain("ARS-HEAD-007");
    expect(ids).not.toEqual(expect.arrayContaining(["ARS-COOKIE-001", "ARS-COOKIE-002", "ARS-COOKIE-003", "ARS-HEAD-006"]));
  });
});
