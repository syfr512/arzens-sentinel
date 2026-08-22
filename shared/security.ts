export const severityLevels = ["critical", "high", "medium", "low", "informational"] as const;
export type Severity = (typeof severityLevels)[number];

export const assessmentProfiles = ["safe_passive", "active_lab"] as const;
export type AssessmentProfile = (typeof assessmentProfiles)[number];

export const findingStatuses = ["open", "in_review", "accepted_risk", "remediated"] as const;
export type FindingStatus = (typeof findingStatuses)[number];

export type SeverityRationale = {
  impact: number;
  exploitability: number;
  score: number;
  explanation: string;
};

export type ScannerFinding = {
  id: string;
  ruleId: string;
  title: string;
  category: string;
  severity: Severity;
  originalSeverity: Severity;
  score: number;
  confidence: "high" | "medium" | "low";
  endpoint: string;
  evidence: string;
  rationale: SeverityRationale;
  reference: string;
  remediation: string;
  status: FindingStatus;
  source: "native" | "zap" | "demo";
};

export type DiscoveredEndpoint = {
  url: string;
  statusCode: number;
  contentType: string | null;
  discoveredBy: "seed" | "link" | "robots" | "sitemap" | "response";
};

export type ScanResult = {
  targetUrl: string;
  profile: AssessmentProfile;
  summary: {
    score: number;
    severity: Severity;
    scannedEndpoints: number;
    findingCount: number;
    durationMs: number;
  };
  endpoints: DiscoveredEndpoint[];
  findings: ScannerFinding[];
  activity: Array<{ at: string; label: string; detail: string }>;
};

export type RemediationGuidance = {
  summary: string;
  businessImpact: string;
  steps: string[];
  patch: string | null;
  validation: string[];
  rollback: string[];
  assumptions: string[];
  references: string[];
  advisory: true;
  source: "deterministic" | "ai";
};
