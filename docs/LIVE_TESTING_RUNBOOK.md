# Authorized Live-Testing Runbook

This runbook governs real target use of Arzens Sentinel. It is designed for an operator assessing an HTTPS staging or production system that they own or are explicitly authorized to test.

## Preconditions

| Requirement | Operator confirmation |
|---|---|
| Written ownership or authorization exists for the exact origin and path scope. | Confirm before creating an authorization record. |
| The target is reachable over public HTTPS. | The hosted scanner blocks private, local, and metadata destinations. |
| The owner accepts non-destructive Safe Passive checks. | No credentialed crawling, exploitation, fuzzing, mutation, brute force, or automatic remediation occurs. |
| A change contact and rollback plan are known. | Stop the scan if unexpected target instability or traffic is observed. |
| Deployment egress policy is configured. | Block private/control-plane addresses and monitor outbound HTTP(S). |

## Operator procedure

1. Sign in and open **New assessment**. Enter only the HTTPS origin and the narrowest required path scope, such as `/staging/`.
2. Select **Issue verification proof**. This action does not contact the target beyond initial safe URL/DNS validation.
3. Publish the displayed exact value to `/.well-known/arzens-sentinel-verification.txt` on the target origin. The file must contain only the issued value.
4. Select **Verify proof**. A single bounded HTTPS request checks the fixed proof path. Review the resulting verified authorization, scope, expiry, and policy limits.
5. Choose the verified target and select **Start verified assessment**. The product persists the authorization and policy snapshot before any bounded scan request.
6. Review the scan timeline. Use **Cancel** if a maintenance window changes, the target becomes unstable, or authorization is withdrawn. Cancellation is observed between endpoint checks.
7. Triage only the redacted evidence. Preserve the original score when overriding severity and provide a reviewer note for every override.
8. Generate remediation only as advisory text. Review the deterministic or optional schema-validated guidance before making a separate, approved change in the target environment.
9. Generate a report and retrieve it through the workspace. Reports are owner-scoped; distribute them according to the organization’s security-data policy.
10. Revoke the target authorization when the assessment engagement ends. Re-issue and re-verify a proof for later work.

## Boundaries and stop conditions

> **Stop immediately** if you no longer have authorization, see unexpected target impact, encounter sensitive data outside agreed scope, or receive a legal/security escalation. Record the observation in the review workflow and revoke the target authorization.

The hosted service stops discovery at the recorded page, redirect, response-size, per-request-timeout, and wall-clock limits. A “time budget reached” timeline event means the result is **partial** and only assessed endpoints support the reported conclusions.

## AI guidance operation

The product does not require an OpenAI API key for live use. Its default remediation path is deterministic. The built-in server-side AI mode is optional, schema-validated, advisory-only, and capped at 10 generations per workspace per day. If the model is disabled, errors, returns invalid output, or the budget is exhausted, the deterministic rule recommendation is returned instead.

If a future external OpenAI-compatible provider is approved, obtain and store its credential only through the deployment secret manager. Do not place it in client code, source control, report evidence, browser storage, or audit metadata.

## Deployment checklist

- [ ] Enforce HTTPS at the edge and validate the published domain.
- [ ] Restrict outbound network egress and enable a WAF/gateway rate limit for API calls.
- [ ] Configure a 30-day object-storage lifecycle rule for `reports/` and a controlled metadata cleanup process.
- [ ] Monitor `http.request`, `scan.live.*`, target authorization, report, and remediation audit events.
- [ ] Run `pnpm check`, `pnpm test`, `pnpm build`, and `pnpm audit --prod --audit-level high` before each release.
- [ ] Exercise a staging target proof, bounded scan, report download, and authorization revocation during release validation.
