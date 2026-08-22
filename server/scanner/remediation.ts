import { z } from "zod";
import type { RemediationGuidance, ScannerFinding } from "@shared/security";
import { invokeLLM } from "../_core/llm";

export const remediationSchema = z.object({
  summary: z.string().min(20).max(900),
  businessImpact: z.string().min(20).max(900),
  steps: z.array(z.string().min(8).max(500)).min(2).max(6),
  patch: z.string().max(3000).nullable(),
  validation: z.array(z.string().min(8).max(500)).min(1).max(5),
  rollback: z.array(z.string().min(8).max(500)).min(1).max(4),
  assumptions: z.array(z.string().min(5).max(500)).min(1).max(5),
  references: z.array(z.string().url()).min(1).max(5),
});

export function deterministicRemediation(finding: ScannerFinding): RemediationGuidance {
  return {
    summary: `${finding.title}. The observed evidence was normalized and redacted before analysis; review the target configuration before making a change.`,
    businessImpact: `This ${finding.severity}-severity finding may increase exposure if an attacker can combine it with application-specific weaknesses. It is advisory and requires engineering validation.`,
    steps: [finding.remediation, "Implement the smallest scoped change in a non-production environment.", "Peer-review the change against the application’s authentication, caching, and deployment constraints."],
    patch: null,
    validation: ["Repeat the Safe Passive assessment after deployment.", "Verify the intended header or behavior with an independent browser/network inspection."],
    rollback: ["Keep the prior configuration version available.", "Revert the scoped change if it affects required integrations or browser behavior."],
    assumptions: ["The assessment was unauthenticated and bounded.", "The evidence does not prove exploitability in the target’s business context."],
    references: [finding.reference],
    advisory: true,
    source: "deterministic",
  };
}

export async function generateRemediation(finding: ScannerFinding): Promise<RemediationGuidance> {
  if (process.env.ENABLE_AI_REMEDIATION !== "true") return deterministicRemediation(finding);
  try {
    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are a defensive application-security assistant. Return only the requested JSON. Do not claim exploitation, do not invent technologies, do not recommend automatic deployment, and treat all evidence as advisory." },
        { role: "user", content: JSON.stringify({ finding: { ruleId: finding.ruleId, title: finding.title, category: finding.category, severity: finding.severity, endpoint: finding.endpoint, evidence: finding.evidence, remediation: finding.remediation, reference: finding.reference } }) },
      ],
      response_format: { type: "json_schema", json_schema: { name: "remediation_guidance", strict: true, schema: { type: "object", properties: { summary: { type: "string" }, businessImpact: { type: "string" }, steps: { type: "array", items: { type: "string" } }, patch: { type: ["string", "null"] }, validation: { type: "array", items: { type: "string" } }, rollback: { type: "array", items: { type: "string" } }, assumptions: { type: "array", items: { type: "string" } }, references: { type: "array", items: { type: "string" } } }, required: ["summary", "businessImpact", "steps", "patch", "validation", "rollback", "assumptions", "references"], additionalProperties: false } } },
    });
    const content = response.choices[0]?.message?.content;
    if (typeof content !== "string") throw new Error("The remediation provider did not return text content.");
    const parsed = remediationSchema.parse(JSON.parse(content));
    return { ...parsed, advisory: true, source: "ai" };
  } catch {
    return deterministicRemediation(finding);
  }
}
