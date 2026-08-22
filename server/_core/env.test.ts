import { describe, expect, it } from "vitest";
import { validateRuntimeEnvironment, type RuntimeEnvironment } from "./env";

const validProduction: RuntimeEnvironment = {
  appId: "app-123", cookieSecret: "a-secure-production-secret-with-32-chars", databaseUrl: "mysql://user:pass@db.example.com/app", oAuthServerUrl: "https://oauth.example.com", ownerOpenId: "owner", isProduction: true, forgeApiUrl: "https://forge.example.com", forgeApiKey: "forge-key",
};

describe("validateRuntimeEnvironment", () => {
  it("accepts a complete production configuration and an opaque managed session secret", () => {
    expect(() => validateRuntimeEnvironment(validProduction)).not.toThrow();
    expect(() => validateRuntimeEnvironment({ ...validProduction, cookieSecret: "managed-secret" })).not.toThrow();
  });
  it("fails fast for missing settings or insecure service endpoints", () => {
    expect(() => validateRuntimeEnvironment({ ...validProduction, databaseUrl: "" })).toThrow("DATABASE_URL");
    expect(() => validateRuntimeEnvironment({ ...validProduction, cookieSecret: "" })).toThrow("JWT_SECRET");
    expect(() => validateRuntimeEnvironment({ ...validProduction, forgeApiUrl: "http://forge.example.com" })).toThrow("must use HTTPS");
  });
});
