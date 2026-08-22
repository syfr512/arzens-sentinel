# Security Audit Sources

The live-readiness audit uses the following authoritative guidance as an external benchmark.

| Area | Key guidance applied | Source |
|---|---|---|
| SSRF defenses | Prefer narrow destination allowlists where feasible; validate protocol, hostname, DNS/IP resolution, and redirects; apply network-layer egress restrictions as defense in depth. | [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) |
| Object authorization | Every operation that receives a user-controlled object identifier must enforce object-level authorization. | [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/) |
| Resource consumption | Network, CPU, memory, storage, and paid provider calls need explicit limits to prevent denial of service and cost abuse. | [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/) |
| Unsafe outbound calls | User-supplied URIs require strong validation because backend requests can reach unexpected destinations. | [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/) |
| Configuration and inventory | Deployment configuration and the inventory of exposed endpoints need continuous review. | [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/) |

These sources inform defensive controls only. They are not used to broaden active scanning behavior.

## Current implementation audit observations

The first code review found that the project already blocks many unsafe targets and re-validates manual redirects. However, a live-testing release requires additional defenses and operations controls: DNS answers should be pinned or otherwise enforced at connection time to reduce rebinding exposure; real target assessments need a durable authorization/scope record rather than a checkbox alone; per-user rate/concurrency limits and scan budgets are absent; scans execute synchronously without durable queued/running/cancelled state; report retrieval needs an explicit owner-checked operation; and API actions need structured audit events, request correlation, and security telemetry. These findings are tracked in `todo.md` and will be addressed during hardening.

The entry point currently accepts 50 MB JSON and form bodies even though the product does not ingest large uploads, and it lacks application-level security headers, request identifiers, structured request logs, health/readiness probes, explicit production error handling, and a restrictive request policy. The persistence layer owns scan rows correctly for normal reads but needs explicit target authorization records, audit-event separation from scanner timeline events, stronger report-download controls, idempotency support, scan-state transitions, and data-retention support. These are priority hardening items for live operation.

The remediation path correctly validates structured output and falls back deterministically, but live use needs per-user generation budgets, operator-configured model selection, minimal prompt logging with no evidence payloads, a time-bound enablement switch, and a documented key-management path. The current built-in server-side provider avoids requiring an external key. An OpenAI API key will be requested only if the operator explicitly selects the external OpenAI-compatible provider in the new settings workflow.

| Area | Key guidance applied | Source |
|---|---|---|
| Browser response hardening | Apply a maintained response-header baseline with CSP, framing restrictions, referrer controls, MIME-sniffing prevention, and transport protection in production. | [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) |
| Security logging | Keep application security events distinct from scanner evidence, include identity/action/outcome/correlation context, minimize sensitive data, and avoid exposing log records as web content. | [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |

The hardening work now adds request IDs, structured stdout telemetry without request bodies, and a separate operator audit-event table. It intentionally does not store raw target responses, authentication material, or model prompts in audit metadata.
