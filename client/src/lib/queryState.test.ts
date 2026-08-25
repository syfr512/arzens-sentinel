import { describe, expect, it } from "vitest";
import { resolveQueryViewState } from "./queryState";

describe("resolveQueryViewState", () => {
  it("keeps a fresh query loading but turns a stalled empty query into a retry state", () => {
    expect(resolveQueryViewState({ isLoading: true, hasData: false, hasError: false, timedOut: false })).toBe("loading");
    expect(resolveQueryViewState({ isLoading: true, hasData: false, hasError: false, timedOut: true })).toBe("timeout");
  });

  it("prioritizes errors and treats completed empty or populated queries as ready", () => {
    expect(resolveQueryViewState({ isLoading: true, hasData: false, hasError: true, timedOut: true })).toBe("error");
    expect(resolveQueryViewState({ isLoading: false, hasData: false, hasError: false, timedOut: false })).toBe("ready");
    expect(resolveQueryViewState({ isLoading: false, hasData: true, hasError: false, timedOut: false })).toBe("ready");
  });
});
