# Arzens Sentinel

> **A portfolio-ready, AI-assisted vulnerability scanner and remediation workspace for authorized web-security assessments.**

Arzens Sentinel turns the internship proposal into a polished end-to-end security-operations product: an authenticated dashboard, bounded safe-passive scanner, explainable finding model, review workflow, structured remediation guidance, professional reports, shared-core CLI, and local-only OWASP ZAP adapter boundary.

## Why this implementation is stronger than the original proposal

The proposal’s Python/Streamlit/ZAP direction was valuable as a starting point, but a single-process Python UI tightly couples interface and scanner responsibilities. This implementation uses a typed React + TypeScript application with a separate scanner-core so the dashboard, server procedures, CLI, scoring, reports, and future ZAP adapter share one predictable security model.

| Proposal goal | Production-minded implementation |
|---|---|
| Automated web/API crawler | Bounded same-origin HTTP(S) scanner with strict URL/DNS/redirect SSRF checks and page/response/time limits. |
| Risk scoring | Stable rule IDs with transparent impact/exploitability factors and preserved original severity. |
| LLM remediation | Server-side strict-schema guidance, evidence grounding, advisory labels, deterministic fallback, and no automatic patch application. |
| PDF reporting | Redacted JSON, print-ready HTML, and server-generated PDF artifacts stored outside the database. |
| OWASP ZAP | Local-only alert-normalization boundary with fixture tests and lab documentation. |

## Core workflow

```mermaid
flowchart LR
  A[Run fixture Demo Scan or authorized Safe Passive assessment] --> B[Review redacted findings]
  B --> C[Record status, notes, or severity override]
  C --> D[Generate advisory remediation]
  D --> E[Export JSON, HTML, or PDF report]
```

## Feature highlights

The dashboard provides overview metrics, assessment history, a safe scan-creation flow, detailed findings review, severity filters, endpoint coverage, activity trail, report controls, methodology, and responsive accessible states. The Demo Scan is fixture-backed and does **not** target an external system.

The scanner defaults to **Safe Passive**. It validates protocols, blocks private/loopback/link-local/reserved/metadata targets, re-validates redirects, bounds crawling, observes same-origin links, inspects headers/transport/cookies/CORS/mixed content/disclosure signals, and redacts sensitive-looking evidence before database, report, or AI use.

## Local quick start

```bash
pnpm install
pnpm check
pnpm test
pnpm dev
```

The managed web project supplies authentication, database credentials, and secure object storage. For the reviewer path, sign in and click **Run Demo Scan**.

## CLI

The CLI uses the same scanner-core and report renderer as the web application.

```bash
# Zero-network fixture demonstration
pnpm cli -- --demo --format json --output ./reports

# Authorized target only; non-zero exit code if high+ findings occur
pnpm cli -- --target https://app.example.com --authorized --format pdf --max-pages 4 --timeout-ms 8000 --fail-on high
```

| Option | Purpose |
|---|---|
| `--demo` | Uses a controlled fixture only; no third-party network target. |
| `--target <url>` | Runs the bounded Safe Passive scanner against an authorized HTTP(S) target. |
| `--format json|html|pdf` | Chooses the report artifact type. |
| `--output <directory>` | Writes the local report directory. |
| `--max-pages`, `--timeout-ms` | Tightens bounded scanner limits. |
| `--fail-on <severity>` | Returns exit code `1` when a finding meets/exceeds the threshold, useful in CI. |

## Security and AI boundaries

The original assessment score remains visible if a reviewer applies a severity override, and every override requires an audit note. Findings, remediation guidance, reports, and target data are always queried with ownership checks.

AI guidance is server-side and schema-validated. It is labeled **AI-generated / verify before applying** when enabled, returns to deterministic guidance if unavailable or invalid, and can never automatically apply a patch. The initial build uses deterministic fallback by default to keep demos reproducible and avoid unnecessary model cost.

## Documentation

Read the [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [responsible-use policy](docs/RESPONSIBLE_USE.md), [local ZAP adapter notes](docs/ZAP_LOCAL_LAB.md), and [verification record](docs/VERIFICATION.md) for the portfolio narrative, operational boundaries, and test evidence.

## Verification status

The Vitest suite covers scanner safety boundaries, redaction, score mapping, fixture-backed demo behavior, deterministic remediation, AI-off fallback, ZAP normalization, HTML/JSON/PDF report generation, and the template authentication logout behavior.

## Professional limitations

Arzens Sentinel performs bounded, unauthenticated, evidence-led checks. It does not prove exploitability, does not guarantee that a system is secure, and does not replace a professional penetration test. Use it only on targets you are authorized to assess.
