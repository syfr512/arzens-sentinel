import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

const severityLabel: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Info" };

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const normalized = (severity || "informational") as Severity;
  return <Badge className={`severity-badge severity-${normalized}`}>{severityLabel[normalized] || severity}</Badge>;
}

export function MetricCard({ label, value, helper, icon: Icon, accent = "amber" }: { label: string; value: ReactNode; helper: string; icon: LucideIcon; accent?: "amber" | "cyan" | "red" | "lime" }) {
  return <Card className="metric-card"><CardContent className="p-5"><div className="flex items-start justify-between gap-4"><div><p className="metric-label">{label}</p><p className="metric-value">{value}</p><p className="metric-helper">{helper}</p></div><span className={`metric-icon metric-icon-${accent}`}><Icon className="h-4 w-4" /></span></div></CardContent></Card>;
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <header className="page-header"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="page-description">{description}</p></div>{action ? <div className="page-action">{action}</div> : null}</header>;
}

export function SectionTitle({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return <div className="section-title"><div><h2>{title}</h2>{description ? <p>{description}</p> : null}</div>{action}</div>;
}

export function LoadingState({ label = "Loading workspace" }: { label?: string }) {
  return <div className="state-card"><Loader2 className="h-5 w-5 animate-spin text-primary" /><span>{label}</span></div>;
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: { label: string; onClick: () => void } }) {
  return <div className="empty-state"><div className="empty-orb"/><h3>{title}</h3><p>{description}</p>{action ? <Button onClick={action.onClick}>{action.label}</Button> : null}</div>;
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="state-card state-error"><div><strong>Unable to load this view.</strong><p>{message}</p></div>{retry ? <Button variant="outline" onClick={retry}>Retry</Button> : null}</div>;
}

export function RiskRing({ score }: { score: number }) {
  const safeScore = Math.min(Math.max(score, 0), 10);
  return <div className="risk-ring" style={{ "--risk": `${safeScore * 10}%` } as React.CSSProperties}><div><strong>{safeScore.toFixed(1)}</strong><span>/10</span></div></div>;
}
