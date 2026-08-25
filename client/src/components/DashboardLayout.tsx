import { useAuth } from "@/_core/hooks/useAuth";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarTrigger, useSidebar } from "@/components/ui/sidebar";
import { startLogin } from "@/const";
import { useIsMobile } from "@/hooks/useMobile";
import { resolveQueryViewState } from "@/lib/queryState";
import { BookOpen, ChevronRight, FileText, Gauge, History, LogOut, Plus, ScanLine, Settings2, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { DashboardLayoutSkeleton } from "./DashboardLayoutSkeleton";

const menuItems = [
  { icon: Gauge, label: "Overview", path: "/" },
  { icon: Plus, label: "New assessment", path: "/new-scan" },
  { icon: History, label: "Assessment history", path: "/history" },
  { icon: FileText, label: "Reports", path: "/history" },
  { icon: BookOpen, label: "Methodology", path: "/methodology" },
  { icon: Settings2, label: "Account", path: "/settings" },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { loading, user, error, refresh } = useAuth();
  const [authTimedOut, setAuthTimedOut] = useState(false);
  useEffect(() => {
    if (!loading) { setAuthTimedOut(false); return; }
    const timer = window.setTimeout(() => setAuthTimedOut(true), 8_000);
    return () => window.clearTimeout(timer);
  }, [loading]);
  const authState = resolveQueryViewState({ isLoading: loading, hasData: Boolean(user), hasError: Boolean(error), timedOut: authTimedOut });
  if (authState === "loading") return <DashboardLayoutSkeleton />;
  if (authState === "timeout" || authState === "error") return <div className="auth-shell"><div className="auth-grid"/><div className="auth-card"><div className="brand-mark"><ShieldCheck className="h-6 w-6" /></div><p className="eyebrow">Arzens Sentinel</p><h1>Workspace check needs a retry.</h1><p>{authState === "timeout" ? "The secure session check is taking longer than expected. No assessment request has been started." : "The secure session check could not be completed. Retry to reconnect."}</p><Button onClick={() => { setAuthTimedOut(false); refresh(); }} size="lg" className="w-full">Retry secure check <ChevronRight className="h-4 w-4" /></Button></div></div>;
  if (!user) return <div className="auth-shell"><div className="auth-grid"/><div className="auth-card"><div className="brand-mark"><ShieldCheck className="h-6 w-6" /></div><p className="eyebrow">Arzens Sentinel</p><h1>Authorized assessment, made legible.</h1><p>Sign in to run bounded web-security assessments, review redacted evidence, and export advisory remediation reports.</p><Button onClick={() => startLogin()} size="lg" className="w-full">Sign in to workspace <ChevronRight className="h-4 w-4" /></Button><p className="auth-note">Safe Passive is enforced by default. Demo scans use fixtures only.</p></div></div>;
  return <SidebarProvider defaultOpen><DashboardChrome>{children}</DashboardChrome></SidebarProvider>;
}

function DashboardChrome({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const [location, setLocation] = useLocation();
  const { state, toggleSidebar } = useSidebar();
  const isMobile = useIsMobile();
  const [now, setNow] = useState(new Date());
  useEffect(() => { const timer = window.setInterval(() => setNow(new Date()), 30_000); return () => window.clearInterval(timer); }, []);
  const active = menuItems.find(item => item.path === location || (item.path === "/history" && location.startsWith("/scans/")))?.label || "Workspace";
  return <><Sidebar collapsible="icon" className="sentinel-sidebar"><SidebarHeader className="h-[76px] px-3"><div className="flex items-center gap-3"><button onClick={toggleSidebar} aria-label="Toggle navigation" className="brand-mark brand-mark-small"><ShieldCheck className="h-4 w-4" /><span className="emblem-trace" /></button><div className="min-w-0 group-data-[collapsible=icon]:hidden"><p className="font-semibold tracking-tight text-sidebar-foreground">Arzens Sentinel</p><p className="text-[10px] uppercase tracking-[0.16em] text-sidebar-foreground/45">Security operations</p></div></div></SidebarHeader><SidebarContent className="px-2 py-3"><p className="sidebar-label group-data-[collapsible=icon]:hidden">Workspace</p><SidebarMenu>{menuItems.map(item => { const isActive = location === item.path || (item.path === "/history" && location.startsWith("/scans/")); return <SidebarMenuItem key={item.label}><SidebarMenuButton isActive={isActive} onClick={() => setLocation(item.path)} tooltip={item.label} className="nav-item"><item.icon className="h-4 w-4"/><span>{item.label}</span></SidebarMenuButton></SidebarMenuItem>; })}</SidebarMenu><div className="scope-card group-data-[collapsible=icon]:hidden"><div className="flex items-center gap-2"><ScanLine className="h-3.5 w-3.5 text-primary"/><span>Assessment profile</span></div><strong>Safe Passive</strong><p>Bounded, redacted, no exploit payloads.</p></div></SidebarContent><SidebarFooter className="p-3"><DropdownMenu><DropdownMenuTrigger asChild><button className="user-panel"><Avatar className="h-8 w-8"><AvatarFallback>{user?.name?.charAt(0).toUpperCase() || "A"}</AvatarFallback></Avatar><div className="min-w-0 text-left group-data-[collapsible=icon]:hidden"><p className="truncate text-xs font-medium">{user?.name || "Authorized user"}</p><p className="truncate text-[10px] text-muted-foreground">{user?.email || "Signed in"}</p></div></button></DropdownMenuTrigger><DropdownMenuContent align="end" className="w-52"><DropdownMenuItem onClick={logout} className="text-destructive focus:text-destructive"><LogOut className="mr-2 h-4 w-4"/>Sign out</DropdownMenuItem></DropdownMenuContent></DropdownMenu></SidebarFooter></Sidebar><SidebarInset className="min-h-screen overflow-x-hidden"><header className="topbar"><div className="flex items-center gap-3">{isMobile ? <SidebarTrigger className="h-9 w-9"/> : null}<div><p className="topbar-title">{active}</p><p className="topbar-date">{now.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })} · Authorized workspace</p></div></div><div className="topbar-status"><span className="status-dot"/>All safeguards active</div></header><main className="workspace-main">{children}</main></SidebarInset></>;
}
