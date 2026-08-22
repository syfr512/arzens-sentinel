import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import DashboardLayout from "@/components/DashboardLayout";
import ErrorBoundary from "@/components/ErrorBoundary";
import { ThemeProvider } from "@/contexts/ThemeContext";
import History from "@/pages/History";
import Home from "@/pages/Home";
import Methodology from "@/pages/Methodology";
import NewScan from "@/pages/NewScan";
import NotFound from "@/pages/NotFound";
import ScanDetail from "@/pages/ScanDetail";
import Account from "@/pages/Account";
import { Route, Switch } from "wouter";

function WorkspaceRoute({ component: Component }: { component: React.ComponentType }) {
  return <DashboardLayout><Component/></DashboardLayout>;
}

function Router() {
  return <Switch><Route path="/" component={() => <WorkspaceRoute component={Home}/>}/><Route path="/new-scan" component={() => <WorkspaceRoute component={NewScan}/>}/><Route path="/history" component={() => <WorkspaceRoute component={History}/>}/><Route path="/methodology" component={() => <WorkspaceRoute component={Methodology}/>}/><Route path="/settings" component={() => <WorkspaceRoute component={Account}/>}/><Route path="/scans/:scanId" component={() => <WorkspaceRoute component={ScanDetail}/>}/><Route path="/404" component={NotFound}/><Route component={NotFound}/></Switch>;
}

export default function App() {
  return <ErrorBoundary><ThemeProvider defaultTheme="dark"><TooltipProvider><Toaster richColors position="top-right"/><Router/></TooltipProvider></ThemeProvider></ErrorBoundary>;
}
