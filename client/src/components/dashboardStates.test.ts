import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.stubGlobal("React", React);

const mocked = vi.hoisted(() => ({
  auth: {} as any,
  scans: {} as any,
  runDemo: {} as any,
  setLocation: vi.fn(),
  startLogin: vi.fn(),
}));

vi.mock("@/_core/hooks/useAuth", () => ({
  useAuth: () => mocked.auth,
}));

vi.mock("@/const", () => ({
  startLogin: mocked.startLogin,
}));

vi.mock("@/lib/trpc", () => ({
  trpc: {
    scans: {
      list: { useQuery: () => mocked.scans },
      runDemo: { useMutation: () => mocked.runDemo },
    },
  },
}));

vi.mock("wouter", () => ({
  useLocation: () => ["/", mocked.setLocation],
}));

import DashboardLayout from "./DashboardLayout";
import Home from "@/pages/Home";

describe("dashboard resolved query states", () => {
  beforeEach(() => {
    mocked.auth = { loading: false, user: null, error: null, refresh: vi.fn() };
    mocked.scans = { data: [], isLoading: false, error: null, refetch: vi.fn() };
    mocked.runDemo = { mutate: vi.fn(), isPending: false };
    mocked.setLocation.mockReset();
    mocked.startLogin.mockReset();
  });

  it("renders a clear sign-in shell when an unauthenticated session has resolved", () => {
    const html = renderToStaticMarkup(React.createElement(DashboardLayout, null, "protected content"));

    expect(html).toContain("Authorized assessment, made legible.");
    expect(html).toContain("Sign in to workspace");
    expect(html).not.toContain("protected content");
  });

  it("renders the ready empty-workspace view after an empty completed scan query", () => {
    const html = renderToStaticMarkup(React.createElement(Home));

    expect(html).toContain("Your workspace is ready.");
    expect(html).toContain("No assessments yet");
    expect(html).toContain("Run Demo Scan");
  });
});
