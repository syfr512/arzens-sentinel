#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { getDemoScanResult } from "../server/scanner/demo.ts";
import { runSafePassiveScan } from "../server/scanner/core.ts";
import { createCsvReport, createHtmlReport, createJsonReport, createPdfReport } from "../server/reports/render.ts";

const args = process.argv.slice(2);
const value = flag => {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
};
const has = flag => args.includes(flag);

function help() {
  console.log(`
Arzens Sentinel CLI — authorized, bounded web-security assessment

Usage:
  pnpm cli -- --demo [--format json|csv|html|pdf] [--output ./reports]
  pnpm cli -- --target https://app.example.com --authorized [--format json|csv|html|pdf] [--max-pages 4] [--timeout-ms 8000] [--fail-on high]

Safety:
  Only Safe Passive assessment is available. Private, reserved, loopback,
  link-local, metadata, and redirect-bypass targets are rejected. Use only
  systems that you own or are explicitly authorized to assess.
`);
}

if (has("--help") || has("-h")) {
  help();
  process.exit(0);
}

const target = value("--target");
const demo = has("--demo");
const authorized = has("--authorized");
const format = value("--format") || "json";
const outputDir = resolve(value("--output") || "./reports");
const failOn = value("--fail-on");
const maxPages = Number(value("--max-pages") || 4);
const timeoutMs = Number(value("--timeout-ms") || 8000);

if ((!target && !demo) || (target && demo) || !["json", "csv", "html", "pdf"].includes(format)) {
  help();
  process.exit(2);
}

if (target && !authorized) {
  console.error("A real target requires --authorized to confirm you own it or have explicit permission to assess it.");
  process.exit(2);
}

try {
  const result = demo ? getDemoScanResult() : await runSafePassiveScan(target, "safe_passive", { maxPages, timeoutMs });
  const detail = {
    scan: {
      id: demo ? "demo-cli-scan" : "local-cli-scan",
      targetUrl: result.targetUrl,
      profile: result.profile,
      status: "completed",
      riskScore: Math.round(result.summary.score * 10),
      overallSeverity: result.summary.severity,
      endpointCount: result.summary.scannedEndpoints,
      findingCount: result.summary.findingCount,
      createdAt: new Date(Date.now() - result.summary.durationMs),
      completedAt: new Date(),
    },
    endpoints: result.endpoints,
    findings: result.findings.map(item => ({ ...item, scoreTenth: Math.round(item.score * 10), reviewerNote: null })),
    events: result.activity.map(item => ({ ...item, createdAt: new Date(item.at) })),
  };
  mkdirSync(outputDir, { recursive: true });
  const extension = format;
  const filePath = join(outputDir, `arzens-sentinel-${Date.now()}.${extension}`);
  const payload = format === "json" ? createJsonReport(detail) : format === "csv" ? createCsvReport(detail) : format === "html" ? createHtmlReport(detail) : createPdfReport(detail);
  writeFileSync(filePath, payload);
  console.log(`Assessment completed safely. ${result.summary.findingCount} finding(s), score ${result.summary.score.toFixed(1)}/10.`);
  console.log(`Report written to ${filePath}`);
  if (failOn) {
    const ranks = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const threshold = ranks[failOn];
    if (threshold === undefined) throw new Error("--fail-on must be one of informational, low, medium, high, or critical.");
    if (result.findings.some(item => ranks[item.severity] >= threshold)) process.exitCode = 1;
  }
} catch (error) {
  console.error(`Assessment not completed: ${error instanceof Error ? error.message : "unknown error"}`);
  process.exitCode = 2;
}
