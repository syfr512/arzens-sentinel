# Arzens Sentinel Live-Readiness Security Review

**Review scope:** application code, scanner transport, API authorization, data persistence, reporting, AI guidance, dependency posture, and managed-runtime deployment assumptions. This is an engineering security review, not a penetration-test attestation or a guarantee that target systems are secure.

## Executive assessment

Arzens Sentinel is now suitable for **authorized, bounded Safe Passive assessments of HTTPS staging or production systems** when the deployment prerequisites in the companion runbook are followed. The implementation deliberately keeps assessment scope narrow: it does not authenticate to target systems, mutate state, brute-force credentials, test exploitability, or apply patches.

The hardening work replaced the former checkbox-only live-scan workflow with a verified-target model. A user must publish a random proof value at a fixed HTTPS `/.well-known/` location before a live scan can begin. Each run records the verified origin, allowed path prefix, response and crawl limits, and request correlation identifier. Every object-specific API operation remains owner-checked.

| Review area | Result | Implemented control |
|---|---|---|
| Target authorization | **Pass with operator prerequisite** | HTTPS proof-file verification, expiry, revocation, scope path, immutable policy snapshot, and authorization audit events. |
| SSRF and redirects | **Pass for application layer** | HTTP(S)-only parsing, blocked local/private/reserved/metadata destinations, DNS resolution validation, pinned connection lookup, per-hop redirect validation, origin/path enforcement, and no credentials in URLs. |
| Resource safety | **Pass with bounded synchronous model** | Hard page, redirect, response-size, per-request timeout, wall-clock scan budget, one active scan per target check, per-workspace hourly budget, and cancellation polling. |
| Evidence and reports | **Pass** | Redaction before persistence, owner-checked detail reads, artifact metadata outside report bytes, expiry metadata, download audit records, and signed report retrieval. |
| API authorization | **Pass** | Protected procedures, ownership checks for scans/findings/remediation/reports, foreign-access regression tests, and audit records for sensitive state changes. |
| AI guidance | **Pass with deterministic default** | Server-only provider, strict output schema, no automatic changes, daily per-workspace budget, advisory labelling, and deterministic fallback. |
| Web deployment | **Pass baseline** | CSP, nosniff, frame protection, referrer and permissions policies, structured request IDs/logs, health/readiness probes, body-size limits, and production HSTS. |
| Supply chain | **Pass at high/critical threshold** | Focused upgrades for Express, tRPC, Drizzle, Axios, NanoID, AWS SDK, Recharts, and Streamdown; production audit returns no high or critical finding. |

## Security rationale

The scanner follows defense-in-depth rather than relying on a single URL string check. It validates the protocol and hostname, rejects unsafe address classes, ensures every discovered link and redirect remains within the verified origin and path scope, then forces the outbound socket lookup to the previously inspected DNS answer. This approach responds directly to the risks described in OWASP SSRF prevention guidance, while the deployment should still deny private and metadata egress at the network boundary.[1]

The API is designed around per-object authorization. Scan, finding, remediation, target-authorization, and report operations all derive ownership from the authenticated workspace before data is read, altered, generated, or downloaded. This follows the principle that APIs receiving object identifiers need explicit object-level authorization.[2]

## Tests and verification evidence

The hardening verification completed the following checks in the project workspace.

| Verification | Outcome |
|---|---|
| TypeScript validation | Passed with `pnpm check`. |
| Automated test suite | Passed: **26 tests** across 8 files. |
| Production build | Passed with `pnpm build`. |
| Runtime health | `/healthz` returned `200`; `/readyz` returned a ready database state. |
| Header probe | CSP, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and request IDs were observed. |
| Dependency audit | `pnpm audit --prod --audit-level high` completed with no high or critical production finding after upgrades. |
| Live-operation tests | Verified authorization denial, scoped-policy handoff, duplicate scan rejection, database-backed hourly budget, and owner-checked signed report retrieval. |

## Remaining risks and production conditions

The following items are intentionally visible rather than hidden. They should be accepted by the deployment owner before exposing the service to a broader user base.

| Residual condition | Why it matters | Required production treatment |
|---|---|---|
| Egress policy is not enforceable purely in application code. | DNS and address controls reduce SSRF risk but cannot replace network segmentation. | Deny RFC1918, link-local, metadata, localhost, and control-plane egress at the cloud network/firewall layer; allow only required public HTTP(S) egress.[1] |
| Hosted scans are synchronous and deliberately limited to 90 seconds. | This protects the autoscaled request timeout but limits deep crawling. | Use the local CLI or a separately approved queued worker environment for larger authorized assessments; do not increase hosted limits casually. |
| Database count-based rate limits are advisory under simultaneous cross-instance races. | A burst can theoretically pass concurrent read checks before records commit. | Put a gateway/WAF rate limit in front of `/api/trpc` and monitor `scan.live.started` events; use an atomic distributed limiter when scaling beyond a small trusted team. |
| Artifact expiry metadata does not delete object bytes by itself. | Retention claims require storage and database cleanup to agree. | Configure object-storage lifecycle rules for the `reports/` prefix that match each selected 7-, 30-, or 90-day retention policy and periodically remove matching expired metadata under a controlled maintenance process. |
| Built-in AI guidance can be enabled operationally. | Generated text can be wrong, incomplete, or prompt-influenced. | Keep deterministic fallback as the default; enable AI only for trained reviewers, keep the 10/day budget, and never copy raw target secrets into prompts.[3] |

## References

[1] [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

[2] [OWASP API Security Project](https://owasp.org/www-project-api-security/)

[3] [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

[4] [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
