# Live Testing Guide

Use the deployed application at **https://arzenscan-gvtdnrjn.manus.space**. This guide demonstrates the project without scanning an unapproved public system. Begin with the built-in Demo Scan, then use a target only when you control it or have written authorization from its owner.

## Reviewer demonstration: zero-network Demo Scan

After signing in, open **Overview** and select **Run Demo Scan**. The application creates a seeded assessment from local fixtures only; it makes no request to a third-party target. Open the generated assessment to review the bounded endpoints, redacted evidence, stable rule IDs, CVSS-inspired score rationale, severity/status/category filters, and activity history.

Open a finding to add a reviewer decision or note, then request advisory remediation. The recommendation is advisory only; no configuration change is applied. Use the report controls to generate JSON, CSV, HTML, and PDF. CSV cells that could be interpreted as spreadsheet formulas are neutralized, and every report artifact is governed by owner-checked retrieval and audit logging.

## Authorized live Safe Passive assessment

Choose **New assessment** and enter only an HTTPS origin that you control or are formally authorized to assess. Set a small initial policy, such as 10 pages, 2 redirects, 256 KB responses, and a 15-second timeout. Choose an appropriate 7-, 30-, or 90-day retention policy, then create the authorization request.

Publish the generated one-time token at the exact required path on the controlled origin: `/.well-known/arzens-sentinel-verification.txt`. Return to the authorization record and verify the proof. The scanner only permits the verified origin/path scope and Safe Passive profile; it rejects loopback, private, link-local, metadata, unsafe redirect, and out-of-scope destinations.

Start the assessment using the generated retry-safe request. The scan records queued, running, completed, failed, or cancelled lifecycle events. To demonstrate cancellation safely, start a controlled staging scan and select **Cancel** before completion. Do not use this control to scan production systems without an agreed maintenance window.

## What to show the evaluator

| Demonstration step | Evidence to point out |
|---|---|
| Scope proof | HTTPS token verification, selected path, limits, and retention setting. |
| Assessment safety | Safe Passive label, no exploit payloads, DNS/redirect scope controls, and evidence redaction. |
| Review | Original score preservation, severity override, reviewer note, and audit event. |
| Remediation | Deterministic or budgeted advisory guidance with no automatic patching. |
| Reporting | Redacted JSON/CSV/HTML/PDF artifacts, download audit, and retention metadata. |
| Monitoring | `GET /api/health` for application status and `GET /readyz` for application plus database status. |

> Stop immediately if the target proof cannot be verified, an unexpected redirect leaves the approved scope, or you are uncertain about authorization. The appropriate next action is to revoke the target authorization and review the audit record.
