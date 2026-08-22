export type RuntimeEnvironment = {
  appId: string;
  cookieSecret: string;
  databaseUrl: string;
  oAuthServerUrl: string;
  ownerOpenId: string;
  isProduction: boolean;
  forgeApiUrl: string;
  forgeApiKey: string;
};

export const ENV: RuntimeEnvironment = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? "",
};

export function validateRuntimeEnvironment(runtime: RuntimeEnvironment = ENV) {
  if (!runtime.isProduction) return;
  const required: Array<[string, string]> = [
    ["VITE_APP_ID", runtime.appId],
    ["JWT_SECRET", runtime.cookieSecret],
    ["DATABASE_URL", runtime.databaseUrl],
    ["OAUTH_SERVER_URL", runtime.oAuthServerUrl],
    ["BUILT_IN_FORGE_API_URL", runtime.forgeApiUrl],
    ["BUILT_IN_FORGE_API_KEY", runtime.forgeApiKey],
  ];
  const missing = required.filter(([, value]) => !value.trim()).map(([key]) => key);
  if (missing.length) throw new Error(`Production environment validation failed: missing ${missing.join(", ")}.`);
  if (runtime.cookieSecret.length < 32) throw new Error("Production environment validation failed: JWT_SECRET must be at least 32 characters.");
  if (!/^https:\/\//.test(runtime.oAuthServerUrl) || !/^https:\/\//.test(runtime.forgeApiUrl)) throw new Error("Production environment validation failed: OAuth and Forge endpoints must use HTTPS.");
}
