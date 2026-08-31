# Arzens Sentinel

> **An AI-assisted, safety-bounded security operations workspace for authorized web assessments.**

Arzens Sentinel is the internship implementation of an AI-powered vulnerability assessment and remediation engine. It combines an authenticated React dashboard, Express/tRPC API, MySQL-compatible persistence, managed report storage, a shared Safe Passive scanner core, explainable findings, advisory remediation, exportable reports, and a local CLI.

**Live application:** [arzenscan-gvtdnrjn.manus.space](https://arzenscan-gvtdnrjn.manus.space)
**Safe review path:** Sign in, select **Run Demo Scan**, then review the fixture-backed findings and exports. The Demo Scan never contacts a third-party target.

## What it does

| Area | Delivered capability |
|---|---|
| Authorized assessment | HTTPS target-control proof, persisted origin/path scope, expiry/revocation controls, idempotent scan starts, cancellation, and audit events. |
| Bounded scanner | Safe Passive HTTP(S) observations only, same-origin discovery, DNS-pinned connections, redirect re-validation, strict page/byte/time limits, SSRF controls, and evidence redaction. |
| Explainable review | Stable rule identifiers, CVSS-inspired scoring factors, severity rationale, filters, notes, non-destructive overrides, and preserved original risk scores. |
| Remediation | Deterministic guidance by default, optional server-only structured AI assistance, schema validation, daily limits, advisory labels, and no automatic patching. |
| Reports | Owner-protected redacted JSON, CSV, HTML, and PDF exports, with signed retrieval and audit metadata. |
| Engineering quality | Typed React/TypeScript codebase, Vitest regression suite, CI workflow, Dependabot, controlled loopback lab, local CLI, security documentation, and GitHub handoff material. |

## Safety model

Arzens Sentinel is intentionally **not** a general exploitation platform. Hosted assessments are limited to Safe Passive checks and require the target controller to publish a one-time `/.well-known/arzens-sentinel-verification.txt` proof file. The scanner rejects private, loopback, link-local, metadata, mixed-DNS, and redirect-bypass destinations. It does not run credential attacks, brute-force campaigns, exploit payloads, authenticated target actions, destructive testing, or automatic remediation.

> Use the live-target workflow only for systems you own or have explicit written authorization to assess. For demonstrations, use the built-in Demo Scan or the isolated controlled lab.

## Download and local installation

### Prerequisites

| Requirement | Recommended version | Purpose |
|---|---:|---|
| Node.js | 22 or later | Application runtime and build tooling. |
| pnpm | 10.4 or later | Locked dependency installation. |
| MySQL-compatible database | MySQL 8 / TiDB-compatible | Persistent user, assessment, finding, report-metadata, and audit data. |
| OAuth and managed storage settings | Deployment-provided | Authentication and protected report artifacts. |

### Get the source

Clone the repository once it is available on GitHub, or use **Code → Download ZIP** on the repository page and extract it locally.

```bash
git clone https://github.com/syfr512/arzens-sentinel.git
cd arzens-sentinel

# Enable the package-manager version declared by the repository.
corepack enable
corepack prepare pnpm@10.4.1 --activate

# Reproducible dependency install.
pnpm install --frozen-lockfile
```

### Configure a local environment

Read [`docs/LOCAL_CONFIG_TEMPLATE.md`](docs/LOCAL_CONFIG_TEMPLATE.md) before creating local environment values. It documents every required configuration key, the responsible source, validation behavior, and the rule that real secrets must never be committed.

For a full self-managed installation, provide a MySQL-compatible `DATABASE_URL`, session/OAuth configuration, and storage/AI settings only where needed. In the managed deployment, authentication, database, and storage credentials are injected by the platform; do not copy those production values into a local `.env` file.

Apply the reviewed database migrations only to a database you control:

```bash
# Inspect migration SQL first, then apply it to the configured local database.
pnpm db:push
```

### Run locally

```bash
# Starts the local development server.
pnpm dev
```

Open the server URL printed in the terminal. The local environment must have its OAuth redirect and database settings aligned with the URL you use for development.

## Quality checks and controlled validation

Run these commands before opening a pull request, tagging a release, or deploying a change:

```bash
pnpm check
pnpm test
pnpm build
pnpm audit --prod --audit-level high
```

The release suite currently contains **42 passing tests across 15 files**. It includes a real, ephemeral loopback-only test server that verifies passive findings such as missing headers, unsafe cookies, permissive CORS, disclosure headers, and absent redirects. The test server is created only inside Vitest and is shut down immediately; it is not a public target and does not expand the hosted scanner’s permissions.

## Demo, live proof workflow, and reports

### Zero-network demonstration

1. Sign in to the dashboard.
2. Select **Run Demo Scan**.
3. Open the created assessment to review the five fixture-backed findings, evidence redaction indicators, scoring, and reviewer controls.
4. Use the **JSON**, **CSV**, **HTML**, and **PDF** controls to verify protected report generation.

### Authorized Safe Passive assessment

1. Open **New assessment** and enter only an HTTPS origin and path scope that you are authorized to assess.
2. Copy the generated verification value into `/.well-known/arzens-sentinel-verification.txt` on that target.
3. Verify the proof in the dashboard, choose conservative page/time/retention limits, and start the assessment.
4. Review redacted findings, reviewer status, advisory remediation, and reports. Revoke the authorization or cancel the assessment whenever needed.

The complete evaluator procedure is in [`docs/LIVE_TESTING_GUIDE.md`](docs/LIVE_TESTING_GUIDE.md). The detailed operator controls and limitations are in [`docs/LIVE_TESTING_RUNBOOK.md`](docs/LIVE_TESTING_RUNBOOK.md).

## CLI

The local CLI uses the same Safe Passive scanner core and report renderer as the application.

```bash
# Zero-network fixture demonstration; no external site is contacted.
pnpm cli -- --demo --format json --output ./reports

# Authorized target only. Returns exit code 1 when a high-or-worse signal is found.
pnpm cli -- --target https://app.example.com --authorized \
  --format pdf --max-pages 4 --timeout-ms 8000 --fail-on high
```

| Option | Use |
|---|---|
| `--demo` | Uses the controlled fixture path without contacting a third-party system. |
| `--target <url>` | Supplies an authorized HTTP(S) target for the bounded scanner. |
| `--format json|html|pdf` | Selects a local report format. |
| `--output <directory>` | Sets the report output directory. |
| `--max-pages`, `--timeout-ms` | Tighten scanner limits for cautious local use. |
| `--fail-on <severity>` | Makes CI fail when a finding meets or exceeds the selected severity. |

## Deployment

The recommended production path is the managed application deployment, with the source retained in a **private GitHub repository** and CI enabled. Before deployment, follow [`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md) and verify:

1. Production secrets and OAuth/database URLs are set through the deployment secret manager rather than source control.
2. Storage retention, gateway/WAF rate limits, and outbound network controls are configured by the deployment owner.
3. The controlled Demo Scan, authorization proof, bounded assessment, report retrieval, cancellation, and authorization revocation are tested in a permitted environment.
4. External monitoring uses **`/api/health`** and **`/readyz`**. The managed platform reserves `/healthz`.

## Project documentation

| Document | Purpose |
|---|---|
| [`docs/SUBMISSION_REPORT.md`](docs/SUBMISSION_REPORT.md) | Internship-ready executive report, architecture, results, limitations, deployment evidence, and screenshots. |
| [`docs/VERIFICATION.md`](docs/VERIFICATION.md) | Reproducible validation evidence, release checks, controlled-lab record, and public endpoint results. |
| [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md) | Security assessment, controls, residual risks, and operational responsibilities. |
| [`docs/CONTROLLED_LAB.md`](docs/CONTROLLED_LAB.md) | Isolated test-lab policy and loopback validation details. |
| [`docs/LOCAL_CONFIG_TEMPLATE.md`](docs/LOCAL_CONFIG_TEMPLATE.md) | Repository-safe local and production configuration guide. |
| [`docs/GITHUB_RELEASE_CHECKLIST.md`](docs/GITHUB_RELEASE_CHECKLIST.md) | Repository export, CI, review, deployment, and release handoff checklist. |
| [`SECURITY.md`](SECURITY.md) | Private security-reporting and responsible-disclosure expectations. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution safety and quality requirements. |

## Release status

The current release has been type-checked, built for production, audited for high-severity production dependency vulnerabilities, verified through the authenticated dashboard and fixture-backed Demo Scan, and exercised through its isolated loopback controlled lab. The public deployment exposes application-owned health monitoring at [`/api/health`](https://arzenscan-gvtdnrjn.manus.space/api/health) and dependency readiness at [`/readyz`](https://arzenscan-gvtdnrjn.manus.space/readyz).

## Contributing and security reporting

Review [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting changes, especially changes to scanner networking, target authorization, report rendering, storage, migrations, or workflows. Do not publish target evidence, credentials, signed report links, or security reports in public issues. Use [`SECURITY.md`](SECURITY.md) for responsible private reporting.
