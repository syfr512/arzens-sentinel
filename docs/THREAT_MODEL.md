# Threat Model and Limitations

## Assets and security objectives

The principal assets are user-owned assessment records, redacted evidence, report artifacts, and the integrity of the assessment workflow. The primary objectives are to prevent the scanner from becoming an SSRF primitive, keep secrets out of stored evidence and AI prompts, enforce tenant ownership, and prevent advisory remediation from becoming an unauthorized deployment mechanism.

| Threat | Mitigation in this release | Residual limitation |
|---|---|---|
| SSRF via a supplied URL | Live scans require verified HTTPS target ownership, HTTP(S)-only input, private/reserved/loopback/link-local/metadata and mixed-DNS blocking, DNS validation, pinned connection lookup, per-hop redirect validation, and origin/path scope enforcement | Egress firewalls must still block private/control-plane ranges; application controls cannot replace network segmentation. |
| Crawl amplification or request-timeout exhaustion | Same-origin, in-scope discovery with strict page, redirect, response-size, per-request timeout, and 90-second wall-clock limits | The hosted scanner is deliberately shallow and synchronous; larger authorized scans belong in the local CLI or an approved queued worker design. |
| Secret disclosure | Redaction of authorization, cookies, named tokens, API keys, and token-like strings before persistence, reporting, or remediation | Pattern redaction cannot guarantee recognition of every proprietary secret format. |
| Cross-user access or report leakage | Protected procedures and ownership checks on every scan, finding, remediation, target authorization, and report action; report retrieval requires owner validation and produces a signed link | Defense in depth should add database foreign keys and central audit-log monitoring in a larger production tenancy. |
| Unauthorised or stale target assessments | Random `/.well-known/` proof, verified status, expiry, revocation, authorization scope, immutable run policy snapshot, and per-target duplicate-run check | A malicious user can only be constrained by the authenticity of the proof and organizational authorization controls; legal authorization remains an operator obligation. |
| AI hallucination, prompt influence, or cost abuse | Strict JSON schema, minimal normalized evidence, server-only provider, advisory label, deterministic fallback, daily per-workspace generation budget, and no patch execution | Generated advice still requires human review, testing, and change control; external model use requires separately approved secret and privacy handling. |
| Audit-event tampering or sensitive log leakage | Separate audit-event table, request IDs, structured metadata limited to action/outcome context, and no raw scanner response or prompt logging | For regulated deployments, export append-only logs to a centralized integrity-protected platform. |
| Dependency supply-chain exposure | Production dependency upgrades and release-time `pnpm audit --prod --audit-level high` verification | New advisories can emerge after release; a regular dependency review cadence remains required. |
| Unsafe active testing | Hosted profile enforces Safe Passive; Active Lab is local-only documentation and does not ship as a public action | A local operator remains responsible for authorization and environment isolation. |

> **Limitation.** This application makes repeatable, bounded observations. It does not prove a vulnerability is exploitable, does not establish that a target is secure, and does not replace a professional penetration test.

## Data handling

The database stores metadata, redacted evidence, reviewer decisions, target-authorization state, audit events, retention timestamps, and references to report artifacts. It does not store report file bytes. Report bytes are placed in managed object storage and are linked back to the assessment record using a storage key and URL. Object-storage lifecycle rules must be configured to match the 30-day database retention record.
