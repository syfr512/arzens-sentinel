import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/security-ui";
import { BookOpen, CheckCircle2, FileLock2, LogOut, ShieldCheck, UserRound } from "lucide-react";
import { useLocation } from "wouter";

export default function Account() {
  const { user, logout } = useAuth();
  const [, setLocation] = useLocation();
  return <div className="space-y-7"><PageHeader eyebrow="Security operations / Account" title="Workspace identity & safeguards." description="Your assessment records are scoped to your authenticated workspace. This page makes the stored-data and operating boundaries explicit for review."/><section className="account-grid"><Card className="identity-card"><CardContent className="p-7"><div className="identity-mark"><UserRound className="h-5 w-5" /></div><p className="eyebrow">Authenticated workspace</p><h2>{user?.name || "Authorized user"}</h2><p>{user?.email || "No email supplied by identity provider"}</p><div className="identity-meta"><span>Role</span><strong>{user?.role || "user"}</strong><span>Access</span><strong>Owned assessments only</strong></div><Button variant="outline" onClick={logout}><LogOut className="h-4 w-4"/>Sign out</Button></CardContent></Card><Card className="account-boundary"><CardContent className="p-7"><p className="eyebrow">Data boundary</p><h3>Your records remain reviewable and contained.</h3><div className="account-checks"><p><FileLock2 className="h-4 w-4"/>Scan data, findings, notes, and remediation are read with ownership checks.</p><p><ShieldCheck className="h-4 w-4"/>Evidence is redacted before database, report, or guidance processing.</p><p><CheckCircle2 className="h-4 w-4"/>Report bytes are stored outside the database with linked metadata.</p></div><Button variant="ghost" onClick={() => setLocation("/methodology")}>Read methodology <BookOpen className="h-4 w-4"/></Button></CardContent></Card></section><section className="responsible-note"><ShieldCheck className="h-5 w-5"/><p><strong>Authorized use remains required.</strong> A signed-in user can only create or view assessments for systems they own or are explicitly authorized to assess. Safe Passive is the hosted default; Active Lab remains local-only.</p></section></div>;
}
