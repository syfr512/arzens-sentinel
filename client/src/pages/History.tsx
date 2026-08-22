import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState, PageHeader, SeverityBadge } from "@/components/security-ui";
import { trpc } from "@/lib/trpc";
import { ArrowRight, CalendarDays, Plus, ScanLine, SlidersHorizontal } from "lucide-react";
import { useMemo, useState } from "react";
import { useLocation } from "wouter";

export default function History() {
  const scans = trpc.scans.list.useQuery();
  const [filter, setFilter] = useState("all");
  const [, setLocation] = useLocation();
  const rows = useMemo(() => (scans.data || []).filter(scan => filter === "all" || scan.overallSeverity === filter), [scans.data, filter]);
  if (scans.isLoading) return <LoadingState label="Loading assessment history"/>;
  if (scans.error) return <ErrorState message={scans.error.message} retry={() => scans.refetch()}/>;
  return <div className="space-y-7"><PageHeader eyebrow="Security operations / History" title="Assessments with an audit trail." description="Findings, reviewer decisions, generated guidance, and export references remain scoped to the user who created the assessment." action={<Button onClick={() => setLocation("/new-scan")}><Plus className="h-4 w-4"/>New assessment</Button>}/><div className="filter-bar"><div className="flex items-center gap-2 text-sm text-muted-foreground"><SlidersHorizontal className="h-4 w-4"/>Severity</div><div className="filter-pills">{["all", "high", "medium", "low", "informational"].map(item => <button key={item} onClick={() => setFilter(item)} className={filter === item ? "active" : ""}>{item === "all" ? "All" : item}</button>)}</div></div>{rows.length ? <Card className="data-card"><CardContent className="p-0"><div className="history-table"><div className="history-head"><span>Assessment</span><span>Posture</span><span>Findings</span><span>Completed</span><span/></div>{rows.map(scan => <button key={scan.id} className="history-row" onClick={() => setLocation(`/scans/${scan.id}`)}><div className="history-target"><span className="recent-icon"><ScanLine className="h-4 w-4"/></span><div><strong>{scan.targetUrl}</strong><p>{scan.profile.replace("_", " ")} · {scan.endpointCount} endpoints</p></div></div><div><SeverityBadge severity={scan.overallSeverity}/><p className="score-line">{(scan.riskScore / 10).toFixed(1)} / 10</p></div><span>{scan.findingCount}</span><span className="date-cell"><CalendarDays className="h-3.5 w-3.5"/>{new Date(scan.completedAt || scan.createdAt).toLocaleDateString()}</span><ArrowRight className="h-4 w-4 text-muted-foreground"/></button>)}</div></CardContent></Card> : <EmptyState title={filter === "all" ? "No assessments yet" : "No assessments match this filter"} description="Create an authorized assessment or use the fixture-backed Demo Scan to populate the workspace." action={{ label: "New assessment", onClick: () => setLocation("/new-scan") }}/>}</div>;
}
