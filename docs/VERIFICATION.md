# Verification Record

## Post-hardening live-readiness verification

The live-readiness hardening release completed successfully with the following reproducible command sequence:

```bash
pnpm check
pnpm test
pnpm build
pnpm audit --prod --audit-level high
```

## Final deployed-release evidence

The production release is publicly available at **https://arzenscan-gvtdnrjn.manus.space**. The authenticated workspace overview and an existing fixture-backed Demo Scan detail were opened in the deployed application on 25 August 2026. The overview rendered one completed assessment, five deduplicated findings, a 4.8/10 posture score, Safe Passive safeguards, and the one-click Demo Scan control. The detail view rendered five redacted findings and the JSON, CSV, HTML, and PDF report actions.

External probes returned HTTP 200 with `{"status":"ok"}` from `/api/health`, HTTP 200 with `{"status":"ready","database":true}` from `/readyz`, and HTTP 200 from the application root without a maintenance page. The production response included HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and a request correlation ID. The managed platform reserves the public `/healthz` path; `/api/health` is the documented application-owned monitoring endpoint.

The deployment evidence set includes an authenticated overview capture and a Demo Scan detail capture showing the reviewer queue, safe-passive profile, finding controls, and all four report formats. Screenshots contain only fixture-backed, redacted assessment data and are retained as submission evidence rather than application assets.

![Deployed overview evidence](https://arzenscan-gvtdnrjn.manus.space/manus-storage/arzens-sentinel-overview_fc994c71.png)

![Fixture-backed Demo Scan detail evidence](https://arzenscan-gvtdnrjn.manus.space/manus-storage/arzens-sentinel-demo-scan-detail_d4f7c09d.png)

The evaluator-facing procedure is available in the [Live Testing Guide](LIVE_TESTING_GUIDE.md). It covers the zero-network Demo Scan, authorized target proof, bounded Safe Passive policy, reviewer workflow, advisory remediation, report exports, cancellation, audit trail review, and monitoring checks.

The final deployed browser check confirmed both the resolved authenticated overview and the explicit unauthenticated sign-in shell; the temporary sign-out was immediately restored through the existing Manus OAuth account. To avoid altering production assessment data solely to fabricate an empty workspace, the completed empty-workspace branch is verified by a deterministic server-rendered component test, while the deployed account continues to display its legitimate fixture-backed Demo Scan record.

The suite now contains **42 passing tests** across fifteen files. In addition to verified target authorization, per-origin/path policy handoff, hourly budget enforcement, active-scan conflict rejection, idempotent retry reuse, expired-report denial, cancellation requests, scan failure lifecycle recording, AI-budget deterministic fallback, production environment validation failures, browser and cookie policy rules, CSV formula neutralization, and the secured CSV report artifact lifecycle, it now covers the resolved unauthenticated sign-in shell, completed empty-workspace view, and loading/timeout/error/ready state mapping used by the dashboard.

The loopback-only controlled-lab test starts an ephemeral HTTP server on `127.0.0.1` and invokes the shared scanner with its test-only local harness option. It confirms expected passive findings for absent headers, unsafe cookie attributes, wildcard CORS, server disclosure, and absent HTTP-to-HTTPS redirect behavior, while asserting that the test cookie value is redacted. The local server is closed after the test and the hosted scanner continues to reject loopback targets.

On 25 August 2026, the isolated controlled-lab validation and complete regression suite were re-run successfully: **42 tests across 15 files passed**, including the loopback fixture. A fresh production build completed successfully, and `pnpm audit --prod --audit-level high` reported no known production vulnerabilities. No public deliberately vulnerable site was contacted; validation remained limited to fixture data and the ephemeral `127.0.0.1` test server.

The CSV report verification includes three layers: renderer-level schema, redaction, and spreadsheet-formula neutralization checks; CLI generation and artifact-content checks; and a protected API-level test that verifies a CSV artifact’s storage metadata, owner-checked signed URL retrieval, download counter call, and audit event.

The reviewed non-destructive migration `0003_futuristic_power_man.sql` was applied successfully. It adds a persisted `retentionDays` target-policy field and a per-user unique request ID constraint that prevents duplicate live starts from a retried launch request.

Runtime probes confirmed `GET /healthz` and `GET /readyz` return successfully. The response baseline includes a correlation request ID, CSP, MIME-sniffing protection, referrer policy, frame denial, permissions policy, and cross-origin opener policy. The final production dependency audit completed with **no high or critical production finding**.

Desktop and 390 px mobile screenshots were captured for the verified-target workflow and account console. They confirm the responsive policy selectors, ownership-proof sequence, idempotency-aware start language, target registry, audit timeline state, AI mode visibility, and safe-passive boundary copy.

## Automated verification

The final local verification command completed successfully:

```bash
pnpm check
pnpm test
pnpm build
```

The initial test suite contained **20 passing tests** across seven files. It covered the scanner’s SSRF boundaries, redaction, score mapping, fixture-backed Demo Scan, deterministic remediation fallback, local ZAP normalization, report rendering, logout behavior, protected scan/finding/remediation/report ownership checks, explicit authorization attestation, and an authenticated protected-procedure workflow that runs Demo Scan → scan detail → remediation → secure PDF artifact metadata without inserting test records into the live database.

The CLI was also verified using the zero-network fixture path. It generated JSON, HTML, and a valid PDF 1.4 document. The `--fail-on` threshold produced the expected non-zero exit code, and a non-demo target without `--authorized` was rejected before scan orchestration.

## Database and build verification

The reviewed migration was applied successfully. A non-destructive schema query confirmed the presence of `scan_targets`, `scan_runs`, `scan_endpoints`, `findings`, `remediation_recommendations`, `scan_events`, and `report_artifacts`. The final production build completed successfully.

## Visual and responsive verification

Authenticated preview screenshots were captured for the Overview, New Assessment, History, Methodology, and Account views in desktop and mobile viewports. The interface was checked for navigation, empty states, visible focus-compatible controls, responsive single-column mobile transformations, the account route, and the safe-passive authorization control.

## Interactive browser limitation

The connected personal browser session reached the sign-in gate but did not have an authenticated project session. To avoid asking the user to log in to an account or creating live database test records, the interaction sequence was verified at the protected-procedure level with mocked storage/database boundaries instead of clicking through the live account. The live authenticated preview screenshots confirm the protected dashboard routes render for an authorized session. Before a public demonstration, sign in and exercise the same documented Demo Scan workflow manually; it remains fixture-backed and does not contact a third-party system.
