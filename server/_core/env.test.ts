import { describe, expect, it } from "vitest";
import { validateRuntimeEnvironment, type RuntimeEnvironment } from "./env";

const validProduction: RuntimeEnvironment = {
  appId: "app-123", cookieSecret: "a-secure-production-secret-with-32-chars", databaseUrl: "mysql://user:pass@db.example.com/app", oAuthServerUrl: "https://oauth.example.com", ownerOpenId: "owner", isProduction: true, forgeApiUrl: "https://forge.example.com", forgeApiKey: "forge-key",
};

describe("validateRuntimeEnvironment", () => {
  it("accepts a complete production configuration", () => expect(() => validateRuntimeEnvironment(validProduction)).not.toThrow());
  it("fails fast for missing settings, short secrets, or insecure service endpoints", () => {
    expect(() => validateRuntimeEnvironment({ ...validProduction, databaseUrl: "" })).toThrow("DATABASE_URL");
    expect(() => validateRuntimeEnvironment({ ...validProduction, cookieSecret: "too-short" })).toThrow("at least 32");
    expect(() => validateRuntimeEnvironment({ ...validProduction, forgeApiUrl: "http://forge.example.com" })).toThrow("must use HTTPS");
  });
});
