# Threat Model and Limitations

## Assets and security objectives

The principal assets are user-owned assessment records, redacted evidence, report artifacts, and the integrity of the assessment workflow. The primary objectives are to prevent the scanner from becoming an SSRF primitive, keep secrets out of stored evidence and AI prompts, enforce tenant ownership, and prevent advisory remediation from becoming an unauthorized deployment mechanism.

| Threat | Mitigation in this release | Residual limitation |
|---|---|---|
| SSRF via a supplied URL | HTTP(S)-only input, private/reserved/loopback/link-local/metadata blocking, DNS validation, and redirect re-validation | DNS rebinding and distributed proxy defenses require infrastructure-level controls in a production-scale scanner. |
| Crawl amplification | Same-origin discovery with strict page, redirect, response-size, and timeout limits | The scanner is intentionally not designed for broad crawling. |
| Secret disclosure | Redaction of authorization, cookies, named tokens, API keys, and token-like strings before persistence, reporting, or remediation | Pattern redaction cannot guarantee recognition of every proprietary secret format. |
| Cross-user access | Protected procedures and ownership checks on every scan, finding, remediation, and report action | Defense in depth should add database foreign keys and audit monitoring in a production tenancy. |
| AI hallucination | Strict JSON schema, evidence-bounded prompt, advisory label, deterministic fallback, and no patch execution | Generated advice still requires human review, testing, and change control. |
| Unsafe active testing | Hosted profile enforces Safe Passive; Active Lab is local-only documentation and does not ship as a public action | A local operator remains responsible for authorization and environment isolation. |

> **Limitation.** This application makes repeatable, bounded observations. It does not prove a vulnerability is exploitable, does not establish that a target is secure, and does not replace a professional penetration test.

## Data handling

The database stores metadata, redacted evidence, reviewer decisions, and references to report artifacts. It does not store report file bytes. Report bytes are placed in managed object storage and are linked back to the assessment record using a storage key and URL.
