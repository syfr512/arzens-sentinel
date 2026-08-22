import { describe, expect, it } from "vitest";
import { getDemoScanResult } from "../scanner/demo";
import { createCsvReport, createHtmlReport, createJsonReport, createPdfReport } from "./render";

function demoDetail() {
  const demo = getDemoScanResult();
  return {
    scan: {
      id: "demo-scan-id",
      targetUrl: demo.targetUrl,
      profile: demo.profile,
      status: "completed",
      riskScore: Math.round(demo.summary.score * 10),
      overallSeverity: demo.summary.severity,
      endpointCount: demo.summary.scannedEndpoints,
      findingCount: demo.summary.findingCount,
      createdAt: new Date("2026-08-22T08:32:11.000Z"),
      completedAt: new Date("2026-08-22T08:32:13.840Z"),
    },
    endpoints: demo.endpoints,
    findings: demo.findings.map(item => ({ ...item, scoreTenth: Math.round(item.score * 10), reviewerNote: null })),
    events: demo.activity.map(item => ({ ...item, createdAt: new Date(item.at) })),
  };
}

describe("redacted report exports", () => {
  it("includes methodology, limitations, and normalized evidence in JSON", () => {
    const output = createJsonReport(demoDetail());
    expect(output).toContain("responsibleUse");
    expect(output).toContain("methodology");
    expect(output).toContain("limitations");
    expect(output).toContain("[REDACTED]");
  });

  it("creates print-ready HTML and a valid PDF header", () => {
    const detail = demoDetail();
    expect(createHtmlReport(detail)).toContain("Bounded Web Security Assessment");
    expect(createHtmlReport(detail)).toContain("Limitations & responsible use");
    expect(createPdfReport(detail).subarray(0, 8).toString()).toBe("%PDF-1.4");
  });

  it("creates a redacted CSV finding export and neutralizes spreadsheet formulas", () => {
    const detail = demoDetail();
    detail.findings[0] = { ...detail.findings[0], reviewerNote: "=HYPERLINK(\"https://untrusted.example\")" };
    const output = createCsvReport(detail);
    expect(output).toContain('"Finding ID","Rule ID","Title"');
    expect(output).toContain("[REDACTED]");
    expect(output).toContain("'=HYPERLINK");
    expect(output.split("\r\n")).toHaveLength(detail.findings.length + 1);
  });
});
