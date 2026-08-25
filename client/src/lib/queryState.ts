export type QueryViewState = "loading" | "timeout" | "error" | "ready";

export function resolveQueryViewState(input: { isLoading: boolean; hasData: boolean; hasError: boolean; timedOut: boolean }): QueryViewState {
  if (input.hasError) return "error";
  if (input.isLoading && !input.hasData) return input.timedOut ? "timeout" : "loading";
  return "ready";
}
