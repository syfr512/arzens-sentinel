# Arzens Sentinel: AI-Powered Vulnerability Scanner & Remediation Engine

**Project submission report**  
**Prepared for:** The Arzens internship project  
**Prepared by:** Internship candidate  
**Version:** Live-readiness release

## Executive summary

Arzens Sentinel is an authenticated security-operations platform for **authorized, bounded web-security assessments**. The project converts the original scanner proposal into a full-stack product: users verify target control with a one-time HTTPS proof, run a constrained Safe Passive assessment, review redacted evidence, preserve explainable scoring and reviewer decisions, request advisory remediation, and export auditable reports.

The project deliberately does not act as a broad exploitation tool. It contains no credential attacks, payload-based exploitation, brute-force functionality, patch execution, or public scan endpoint. This design responds to the principle that vulnerability testing must occur with permission and in a safe environment.[1]

| Outcome | Delivered capability |
|---|---|
| Safe live operation | HTTPS ownership proof, verified origin/path scope, DNS-pinned outbound connection, redirect re-validation, strict response/page/time budgets, and cancellation. |
| Reviewable findings | Stable rule identifiers, CVSS-inspired factors, original-score preservation, severity overrides with notes, ownership checks, and audit events. |
| Actionable remediation | Deterministic recommendations by default, optional server-side structured AI guidance, daily budget, schema validation, and no automatic changes. |
| Reporting | Redacted JSON, CSV, print-ready HTML, and PDF artifacts, stored separately from database metadata and retrieved through owner-checked signed links. |
| Portfolio quality | Responsive dashboard, local CLI, ZAP normalization boundary, controlled-lab tests, security documentation, CI pipeline, and deployment runbook. |

## Problem and objectives

Web teams often need early visibility into passive security gaps—such as missing browser headers, unsafe cookies, permissive CORS, mixed content, or product disclosure—but full penetration testing is not always appropriate in every release cycle. The project objective was to provide a responsible layer of **repeatable observation**, not a replacement for professional offensive testing.

The following objectives were met: authentication and tenant separation; authorized target verification; bounded scanning; redacted evidence; explainable prioritization; reviewer decision tracking; advisory remediation; exportable reporting; local command-line use; and clear responsible-use boundaries.

## Architecture and methodology

The application uses a React and TypeScript dashboard with an Express/tRPC server, MySQL-compatible data layer, managed artifact storage, and a shared scanner core used by both the web experience and local CLI. The scanner treats user-supplied URLs as security-sensitive input. It permits only HTTP(S), rejects embedded credentials and unsafe destination classes, resolves DNS before connection, pins the selected validated address, validates every redirect, and limits crawling to the verified origin and path.

| Layer | Responsibilities |
|---|---|
| Dashboard | Authenticated target proof workflow, review queue, findings filters, remediation, reports, audit trail, and policy visibility. |
| API and persistence | Owner-scoped procedures, scan lifecycle, idempotency, authorization expiry/revocation, policy snapshots, report metadata, and audit events. |
| Scanner core | Bounded safe-passive checks for headers, cookies, CORS, mixed content, redirect/transport behavior, disclosure, and controlled same-origin discovery. |
| Reporting | Redacts evidence, neutralizes CSV spreadsheet formulas, generates JSON/CSV/HTML/PDF, and stores artifact bytes outside the database. |
| Validation | Unit, protected-procedure, loopback-controlled-lab, export, build, header, readiness, and dependency-audit checks. |

The security controls align with OWASP guidance on SSRF prevention, API object authorization, secure headers, and privacy-aware logging.[2] [3] [4] [5]

## Implementation results

The final release exposes a one-click zero-network Demo Scan for reviewers and a separate live workflow that requires publication of `/.well-known/arzens-sentinel-verification.txt` on the target. Before every assessment, the system records the verified authorization, scope, limits, retention selection, and retry-safe idempotency key. Public hosting never permits the Active Lab profile.

The rule catalog now covers CSP absence and unsafe inline scripts, HSTS, MIME-sniffing protection, referrer policy, clickjacking controls, permissions policy, `Secure`/`HttpOnly`/`SameSite` cookies, permissive CORS, technology disclosure, mixed content, and HTTP-to-HTTPS behavior. Findings remain advisory signals, not evidence of exploitability.

## Validation and evidence

The completed validation suite contains **38 passing tests across 13 files**. It validates scanner safety, redaction, score mapping, ownership boundaries, target authorization, lifecycle states, retry-safe starts, cancellation, error handling, report access, structured remediation fallback, ZAP normalization, CSV protection, and environment validation.

A real ephemeral HTTP server bound to `127.0.0.1` is created only during the automated test lifecycle. The shared scanner’s loopback exception is enabled only when the test process explicitly requests the controlled-lab mode; the hosted scanner and CLI still block loopback targets. This validated known safe-passive response signals without contacting a public vulnerable application.

All four report types were generated through the zero-network CLI path. JSON contained methodology and responsible-use data; CSV contained redacted evidence and normalized columns; HTML included report sections; and PDF began with a valid `%PDF-1.4` signature. The CSV report test also verified persisted artifact metadata, owner-checked signed retrieval, and download auditing.

## Professional limitations

Arzens Sentinel is intentionally bounded. It does not authenticate to a target, prove exploitability, perform destructive testing, scan private networks, or replace a penetration test. Network egress policy, gateway rate limiting, storage lifecycle configuration, secrets management, and centralized log monitoring remain deployment-owner responsibilities. These limitations are documented rather than concealed so the project can be evaluated honestly.

## Future roadmap

The next appropriate enhancements are a separately approved queued-worker execution environment for deep scans, an organization-level role model, encrypted external AI-provider configuration if required, report retention cleanup automation, target-change monitoring, and integration with a centralized SIEM. None should weaken the current authorization or passive-testing boundaries.

## References

[1] [OWASP WebGoat](https://owasp.org/www-project-webgoat/)

[2] [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

[3] [OWASP API Security Project](https://owasp.org/www-project-api-security/)

[4] [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

[5] [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
