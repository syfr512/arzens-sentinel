import { index, int, json, mysqlEnum, mysqlTable, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export const scanTargets = mysqlTable("scan_targets", {
  id: varchar("id", { length: 32 }).primaryKey(),
  userId: int("userId").notNull(),
  normalizedUrl: varchar("normalizedUrl", { length: 2048 }).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => [index("scan_targets_user_url_idx").on(table.userId, table.normalizedUrl)]);

export const targetAuthorizations = mysqlTable("target_authorizations", {
  id: varchar("id", { length: 32 }).primaryKey(),
  userId: int("userId").notNull(),
  origin: varchar("origin", { length: 512 }).notNull(),
  hostname: varchar("hostname", { length: 255 }).notNull(),
  scopePath: varchar("scopePath", { length: 1024 }).default("/").notNull(),
  status: mysqlEnum("status", ["pending", "verified", "revoked", "expired"]).default("pending").notNull(),
  verificationMethod: mysqlEnum("verificationMethod", ["well_known_file"]).default("well_known_file").notNull(),
  verificationToken: varchar("verificationToken", { length: 96 }).notNull().unique(),
  verificationAttempts: int("verificationAttempts").default(0).notNull(),
  lastVerificationError: text("lastVerificationError"),
  verifiedAt: timestamp("verifiedAt"),
  lastVerifiedAt: timestamp("lastVerifiedAt"),
  expiresAt: timestamp("expiresAt").notNull(),
  maxPages: int("maxPages").default(4).notNull(),
  maxRedirects: int("maxRedirects").default(3).notNull(),
  maxResponseBytes: int("maxResponseBytes").default(350000).notNull(),
  timeoutMs: int("timeoutMs").default(8000).notNull(),
  retentionDays: int("retentionDays").default(30).notNull(),
  policyVersion: int("policyVersion").default(1).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => [
  index("target_authorizations_user_origin_idx").on(table.userId, table.origin),
  index("target_authorizations_user_status_idx").on(table.userId, table.status),
]);

export const scanRuns = mysqlTable("scan_runs", {
  id: varchar("id", { length: 32 }).primaryKey(),
  userId: int("userId").notNull(),
  targetId: varchar("targetId", { length: 32 }).notNull(),
  targetUrl: varchar("targetUrl", { length: 2048 }).notNull(),
  profile: mysqlEnum("profile", ["safe_passive", "active_lab"]).default("safe_passive").notNull(),
  authorizationId: varchar("authorizationId", { length: 32 }),
  requestId: varchar("requestId", { length: 48 }),
  policySnapshot: json("policySnapshot"),
  status: mysqlEnum("status", ["queued", "running", "completed", "failed", "cancelled"]).default("queued").notNull(),
  riskScore: int("riskScore").default(0).notNull(),
  overallSeverity: mysqlEnum("overallSeverity", ["critical", "high", "medium", "low", "informational"]).default("informational").notNull(),
  endpointCount: int("endpointCount").default(0).notNull(),
  findingCount: int("findingCount").default(0).notNull(),
  errorMessage: text("errorMessage"),
  startedAt: timestamp("startedAt"),
  completedAt: timestamp("completedAt"),
  cancelRequestedAt: timestamp("cancelRequestedAt"),
  retentionExpiresAt: timestamp("retentionExpiresAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [
  index("scan_runs_user_created_idx").on(table.userId, table.createdAt),
  index("scan_runs_authorization_status_idx").on(table.authorizationId, table.status),
  uniqueIndex("scan_runs_user_request_unique").on(table.userId, table.requestId),
]);

export const scanEndpoints = mysqlTable("scan_endpoints", {
  id: varchar("id", { length: 40 }).primaryKey(),
  scanId: varchar("scanId", { length: 32 }).notNull(),
  url: varchar("url", { length: 2048 }).notNull(),
  statusCode: int("statusCode").notNull(),
  contentType: varchar("contentType", { length: 255 }),
  discoveredBy: varchar("discoveredBy", { length: 32 }).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [index("scan_endpoints_scan_idx").on(table.scanId)]);

export const findings = mysqlTable("findings", {
  id: varchar("id", { length: 80 }).primaryKey(),
  scanId: varchar("scanId", { length: 32 }).notNull(),
  ruleId: varchar("ruleId", { length: 32 }).notNull(),
  title: varchar("title", { length: 512 }).notNull(),
  category: varchar("category", { length: 128 }).notNull(),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low", "informational"]).notNull(),
  originalSeverity: mysqlEnum("originalSeverity", ["critical", "high", "medium", "low", "informational"]).notNull(),
  scoreTenth: int("scoreTenth").notNull(),
  confidence: mysqlEnum("confidence", ["high", "medium", "low"]).notNull(),
  endpoint: varchar("endpoint", { length: 2048 }).notNull(),
  evidence: text("evidence").notNull(),
  rationale: json("rationale").notNull(),
  reference: varchar("reference", { length: 1024 }).notNull(),
  remediation: text("remediation").notNull(),
  status: mysqlEnum("status", ["open", "in_review", "accepted_risk", "remediated"]).default("open").notNull(),
  reviewerNote: text("reviewerNote"),
  severityOverrideNote: text("severityOverrideNote"),
  source: mysqlEnum("source", ["native", "zap", "demo"]).default("native").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => [index("findings_scan_idx").on(table.scanId), index("findings_rule_endpoint_idx").on(table.scanId, table.ruleId)]);

export const remediationRecommendations = mysqlTable("remediation_recommendations", {
  id: varchar("id", { length: 32 }).primaryKey(),
  scanId: varchar("scanId", { length: 32 }).notNull(),
  findingId: varchar("findingId", { length: 80 }).notNull(),
  source: mysqlEnum("source", ["deterministic", "ai"]).notNull(),
  guidance: json("guidance").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [index("remediation_finding_idx").on(table.findingId)]);

export const scanEvents = mysqlTable("scan_events", {
  id: varchar("id", { length: 32 }).primaryKey(),
  scanId: varchar("scanId", { length: 32 }).notNull(),
  label: varchar("label", { length: 128 }).notNull(),
  detail: text("detail").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [index("scan_events_scan_idx").on(table.scanId)]);

export const reportArtifacts = mysqlTable("report_artifacts", {
  id: varchar("id", { length: 32 }).primaryKey(),
  scanId: varchar("scanId", { length: 32 }).notNull(),
  format: mysqlEnum("format", ["json", "csv", "html", "pdf"]).notNull(),
  storageKey: varchar("storageKey", { length: 512 }).notNull(),
  url: varchar("url", { length: 1024 }).notNull(),
  expiresAt: timestamp("expiresAt"),
  downloadCount: int("downloadCount").default(0).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [index("report_artifacts_scan_idx").on(table.scanId)]);

export const auditEvents = mysqlTable("audit_events", {
  id: varchar("id", { length: 32 }).primaryKey(),
  userId: int("userId"),
  action: varchar("action", { length: 128 }).notNull(),
  entityType: varchar("entityType", { length: 64 }).notNull(),
  entityId: varchar("entityId", { length: 96 }),
  outcome: mysqlEnum("outcome", ["success", "denied", "failure"]).notNull(),
  requestId: varchar("requestId", { length: 48 }),
  metadata: json("metadata"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [
  index("audit_events_user_created_idx").on(table.userId, table.createdAt),
  index("audit_events_entity_idx").on(table.entityType, table.entityId),
]);

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
