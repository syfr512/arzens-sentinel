import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState, LoadingState, PageHeader, RiskRing, SectionTitle, SeverityBadge } from "@/components/security-ui";
import { trpc } from "@/lib/trpc";
import { ArrowLeft, ChevronRight, Download, ExternalLink, FileCode2, FileSpreadsheet, FileText, Loader2, MessageSquareText, ShieldCheck } from "lucide-react";
import type { RemediationGuidance } from "@shared/security";
import { useMemo, useState } from "react";
import { useLocation, useRoute } from "wouter";

type DetailFinding = {
  id: string;
  ruleId: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  originalSeverity: "critical" | "high" | "medium" | "low" | "informational";
  score: number;
  confidence: string;
  endpoint: string;
  evidence: string;
  rationale: { impact: number; exploitability: number; score: number; explanation: string };
  reference: string;
  remediation: string;
  status: "open" | "in_review" | "accepted_risk" | "remediated";
  reviewerNote: string | null;
  severityOverrideNote: string | null;
};

export default function ScanDetail() {
  const [, params] = useRoute("/scans/:scanId");
  const scanId = params?.scanId || "";
  const detail = trpc.scans.detail.useQuery({ scanId }, { enabled: Boolean(scanId) });
  const [, setLocation] = useLocation();
  const [selected, setSelected] = useState<DetailFinding | null>(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [endpointQuery, setEndpointQuery] = useState("");
  const reports = trpc.reports.generate.useMutation();
  const update = trpc.findings.update.useMutation();
  const guidance = trpc.findings.remediation.generate.useMutation();
  const savedGuidance = trpc.findings.remediation.list.useQuery(
    { findingId: selected?.id || "unselected" },
    { enabled: Boolean(selected?.id) },
  );
  const utils = trpc.useUtils();
  const data = detail.data;
  const scan = data?.scan;
  const allFindings = (data?.findings || []) as DetailFinding[];
  const categories = useMemo(() => Array.from(new Set(allFindings.map(item => item.category))).sort(), [allFindings]);
  const filtered = useMemo(() => allFindings.filter(item => (
    (severityFilter === "all" || item.severity === severityFilter) &&
    (statusFilter === "all" || item.status === statusFilter) &&
    (confidenceFilter === "all" || item.confidence === confidenceFilter) &&
    (categoryFilter === "all" || item.category === categoryFilter) &&
    (!endpointQuery || item.endpoint.toLowerCase().includes(endpointQuery.toLowerCase()))
  )), [allFindings, severityFilter, statusFilter, confidenceFilter, categoryFilter, endpointQuery]);

  const exportReport = (format: "json" | "csv" | "html" | "pdf") => {
    reports.mutate({ scanId, format }, {
      onSuccess: artifact => {
        if (artifact?.url) window.open(artifact.url, "_blank", "noopener,noreferrer");
        utils.scans.detail.invalidate({ scanId });
      },
    });
  };

  const saveFinding = (input: {
    status?: DetailFinding["status"];
    reviewerNote?: string;
    severity?: DetailFinding["severity"];
    severityOverrideNote?: string;
  }) => {
    if (!selected) return;
    update.mutate({ findingId: selected.id, ...input }, {
      onSuccess: next => {
        setSelected(next as DetailFinding);
        utils.scans.detail.invalidate({ scanId });
      },
    });
  };

  if (detail.isLoading) return <LoadingState label="Loading assessment record" />;
  if (detail.error || !data || !scan) {
    return <ErrorState message={detail.error?.message || "This assessment is unavailable."} retry={() => detail.refetch()} />;
  }

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Security operations / Assessment detail"
        title={scan.targetUrl}
        description={`Completed ${new Date(scan.completedAt || scan.createdAt).toLocaleString()} · ${scan.profile.replace("_", " ")} profile · redacted evidence`}
        action={
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => setLocation("/history")}><ArrowLeft className="h-4 w-4" />History</Button>
            <Button variant="outline" onClick={() => exportReport("json")} disabled={reports.isPending}><FileCode2 className="h-4 w-4" />JSON</Button>
            <Button variant="outline" onClick={() => exportReport("csv")} disabled={reports.isPending}><FileSpreadsheet className="h-4 w-4" />CSV</Button>
            <Button variant="outline" onClick={() => exportReport("html")} disabled={reports.isPending}><FileText className="h-4 w-4" />HTML</Button>
            <Button className="btn-amber" onClick={() => exportReport("pdf")} disabled={reports.isPending}><Download className="h-4 w-4" />{reports.isPending ? "Preparing" : "PDF"}</Button>
          </div>
        }
      />

      <section className="detail-summary">
        <Card className="posture-card"><CardContent className="p-7">
          <RiskRing score={scan.riskScore / 10} />
          <div>
            <p className="eyebrow">Assessment posture</p>
            <h2>{scan.overallSeverity === "informational" ? "No material signal detected" : `${scan.overallSeverity} priority review`}</h2>
            <p>{scan.findingCount} deduplicated finding{scan.findingCount === 1 ? "" : "s"} across {scan.endpointCount} bounded endpoint{scan.endpointCount === 1 ? "" : "s"}. The original score remains visible if reviewers apply an override.</p>
            <div className="summary-chips"><SeverityBadge severity={scan.overallSeverity} /><span>{scan.status}</span><span>{scan.profile.replace("_", " ")}</span></div>
          </div>
        </CardContent></Card>
        <Card className="summary-side"><CardContent className="p-6">
          <p className="eyebrow">Report integrity</p>
          <div className="integrity-list">
            <p><ShieldCheck className="h-4 w-4 text-[#8dc483]" />Evidence redaction enabled</p>
            <p><ShieldCheck className="h-4 w-4 text-[#8dc483]" />Same-origin boundary applied</p>
            <p><ShieldCheck className="h-4 w-4 text-[#8dc483]" />No exploit payloads used</p>
          </div>
          {data.artifacts.length ? <p className="artifact-note">{data.artifacts.length} stored report artifact{data.artifacts.length === 1 ? "" : "s"} linked to this assessment.</p> : null}
        </CardContent></Card>
      </section>

      <Tabs defaultValue="findings" className="space-y-5">
        <TabsList className="detail-tabs">
          <TabsTrigger value="findings">Findings <span>{allFindings.length}</span></TabsTrigger>
          <TabsTrigger value="endpoints">Endpoints <span>{data.endpoints.length}</span></TabsTrigger>
          <TabsTrigger value="activity">Activity <span>{data.events.length}</span></TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-4">
          <div className="finding-toolbar">
            <SectionTitle title="Review queue" description="Select a finding to inspect evidence, record a decision, set an accountable note, or request advisory guidance." />
            <div className="finding-filters">
              <Input value={endpointQuery} onChange={event => setEndpointQuery(event.target.value)} placeholder="Filter endpoint" className="h-8 min-w-[155px] text-xs" />
              <Select value={severityFilter} onValueChange={setSeverityFilter}><SelectTrigger className="h-8 w-[104px] text-xs"><SelectValue placeholder="Severity" /></SelectTrigger><SelectContent>{["all", "high", "medium", "low", "informational"].map(item => <SelectItem key={item} value={item}>{item === "all" ? "All severity" : item}</SelectItem>)}</SelectContent></Select>
              <Select value={statusFilter} onValueChange={setStatusFilter}><SelectTrigger className="h-8 w-[112px] text-xs"><SelectValue placeholder="Status" /></SelectTrigger><SelectContent>{["all", "open", "in_review", "accepted_risk", "remediated"].map(item => <SelectItem key={item} value={item}>{item === "all" ? "All status" : item.replace("_", " ")}</SelectItem>)}</SelectContent></Select>
              <Select value={confidenceFilter} onValueChange={setConfidenceFilter}><SelectTrigger className="h-8 w-[124px] text-xs"><SelectValue placeholder="Confidence" /></SelectTrigger><SelectContent>{["all", "high", "medium", "low"].map(item => <SelectItem key={item} value={item}>{item === "all" ? "All confidence" : item}</SelectItem>)}</SelectContent></Select>
              <Select value={categoryFilter} onValueChange={setCategoryFilter}><SelectTrigger className="h-8 w-[128px] text-xs"><SelectValue placeholder="Category" /></SelectTrigger><SelectContent><SelectItem value="all">All categories</SelectItem>{categories.map(item => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent></Select>
            </div>
          </div>
          <Card className="data-card"><CardContent className="p-0"><div className="findings-list">
            {filtered.map(item => <button key={item.id} className="finding-row" onClick={() => setSelected(item)}>
              <div className="finding-main"><SeverityBadge severity={item.severity} /><div><div className="finding-title-line"><strong>{item.title}</strong>{item.severity !== item.originalSeverity ? <span className="override-note">overridden from {item.originalSeverity}</span> : null}</div><p>{item.ruleId} · {item.category} · <span className="font-mono">{item.endpoint}</span></p></div></div>
              <div className="finding-meta"><span>{item.score.toFixed(1)} / 10</span><span className="status-tag">{item.status.replace("_", " ")}</span><ChevronRight className="h-4 w-4 text-muted-foreground" /></div>
            </button>)}
            {!filtered.length ? <div className="empty-table">No findings match this review filter.</div> : null}
          </div></CardContent></Card>
        </TabsContent>

        <TabsContent value="endpoints"><Card className="data-card"><CardContent className="p-0"><div className="endpoint-list">
          {data.endpoints.map(endpoint => <div key={endpoint.id} className="endpoint-row"><div><strong className="font-mono">{endpoint.url}</strong><p>{endpoint.contentType || "unknown content type"} · discovered by {endpoint.discoveredBy}</p></div><span className="http-status">{endpoint.statusCode}</span></div>)}
        </div></CardContent></Card></TabsContent>

        <TabsContent value="activity"><Card className="data-card"><CardContent className="p-0"><div className="activity-list">
          {data.events.map(event => <div key={event.id} className="activity-row"><span className="activity-dot" /><div><strong>{event.label}</strong><p>{event.detail}</p></div><time>{new Date(event.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time></div>)}
        </div></CardContent></Card></TabsContent>
      </Tabs>

      <Dialog open={Boolean(selected)} onOpenChange={open => !open && setSelected(null)}>
        <DialogContent className="finding-dialog">
          <DialogHeader>
            <div className="flex items-center gap-2"><SeverityBadge severity={selected?.severity || "informational"} /><span className="font-mono text-xs text-muted-foreground">{selected?.ruleId}</span></div>
            <DialogTitle>{selected?.title}</DialogTitle>
            <DialogDescription>{selected?.category} · Score {selected?.score.toFixed(1)} / 10 · confidence {selected?.confidence}</DialogDescription>
          </DialogHeader>
          {selected ? <FindingReview key={selected.id} finding={selected} saving={update.isPending} generating={guidance.isPending} savedGuidance={savedGuidance.data} onSave={saveFinding} onGuidance={() => guidance.mutate({ findingId: selected.id }, { onSuccess: () => savedGuidance.refetch() })} /> : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function FindingReview({
  finding, onSave, onGuidance, saving, generating, savedGuidance,
}: {
  finding: DetailFinding;
  onSave: (data: { status?: DetailFinding["status"]; reviewerNote?: string; severity?: DetailFinding["severity"]; severityOverrideNote?: string }) => void;
  onGuidance: () => void;
  saving: boolean;
  generating: boolean;
  savedGuidance?: Array<{ guidance: unknown }>;
}) {
  const [status, setStatus] = useState<DetailFinding["status"]>(finding.status);
  const [note, setNote] = useState(finding.reviewerNote || "");
  const [severity, setSeverity] = useState<DetailFinding["severity"]>(finding.severity);
  const [overrideNote, setOverrideNote] = useState(finding.severityOverrideNote || "");
  const latest = (savedGuidance?.[0]?.guidance || null) as RemediationGuidance | null;
  const hasOverride = severity !== finding.severity;

  return <div className="finding-review-content">
    <section><p className="dialog-label">Endpoint</p><p className="font-mono text-xs break-all">{finding.endpoint}</p></section>
    <section><p className="dialog-label">Redacted evidence</p><pre className="evidence-box">{finding.evidence}</pre></section>
    <section className="rationale-box"><p className="dialog-label">Why this score</p><p>{finding.rationale.explanation}</p><div><span>Impact {finding.rationale.impact}/10</span><span>Exploitability {finding.rationale.exploitability}/10</span><span>Original severity: {finding.originalSeverity}</span></div></section>
    <section><p className="dialog-label">Deterministic remediation</p><p>{finding.remediation}</p><a href={finding.reference} target="_blank" rel="noreferrer" className="reference-link">Open reference <ExternalLink className="h-3.5 w-3.5" /></a></section>
    <section className="review-form">
      <div className="form-row">
        <div><Label>Status</Label><Select value={status} onValueChange={value => setStatus(value as DetailFinding["status"])}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{["open", "in_review", "accepted_risk", "remediated"].map(value => <SelectItem key={value} value={value}>{value.replace("_", " ")}</SelectItem>)}</SelectContent></Select></div>
        <div><Label>Reviewer severity</Label><Select value={severity} onValueChange={value => setSeverity(value as DetailFinding["severity"])}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{["critical", "high", "medium", "low", "informational"].map(value => <SelectItem key={value} value={value}>{value}</SelectItem>)}</SelectContent></Select></div>
      </div>
      <div className="space-y-2"><Label>Reviewer note</Label><Textarea value={note} onChange={event => setNote(event.target.value)} placeholder="Record scope, owner, validation, or acceptance context." /></div>
      {hasOverride ? <div className="space-y-2"><Label>Override audit note</Label><Input value={overrideNote} onChange={event => setOverrideNote(event.target.value)} placeholder="Why is the reviewer severity different?" /><p className="form-hint">The original severity and score are retained for traceability.</p></div> : null}
      <Button className="w-full" disabled={saving || (hasOverride && !overrideNote)} onClick={() => onSave({ status, reviewerNote: note, ...(hasOverride ? { severity, severityOverrideNote: overrideNote } : {}) })}>{saving ? "Saving review…" : "Save reviewer decision"}</Button>
    </section>
    <section className="ai-guidance">
      <div><p className="dialog-label">Advisory remediation guidance</p><p>Structured guidance is evidence-bounded, schema-validated, and never applied automatically.</p></div>
      <Button variant="outline" onClick={onGuidance} disabled={generating}>{generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <MessageSquareText className="h-4 w-4" />}{generating ? "Generating" : "Generate guidance"}</Button>
      {latest ? <div className="guidance-card"><span>{latest.source === "ai" ? "AI-generated · verify before applying" : "Deterministic fallback guidance"}</span><strong>{latest.summary}</strong><p>{latest.businessImpact}</p><ul>{latest.steps.map(step => <li key={step}>{step}</li>)}</ul><p className="form-hint">Validation: {latest.validation.join(" · ")}</p></div> : null}
    </section>
  </div>;
}
