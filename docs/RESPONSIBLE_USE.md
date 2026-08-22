# Responsible Use Policy

Arzens Sentinel is designed for **authorized defensive assessment**. By using the hosted workflow or the CLI, the operator confirms that they own the target or have explicit permission to assess it.

The hosted application enforces Safe Passive checks. It does not brute force credentials, mutate data, submit exploit payloads, authenticate as a user, apply code changes, or scan private/reserved infrastructure. The fixture-backed Demo Scan does not contact a third-party system.

The local OWASP ZAP adapter is an integration boundary for a developer-controlled laboratory only. Any active local work remains the operator’s responsibility and must be isolated, authorized, rate-limited, and validated against an agreed rules of engagement.

If a target is not yours, or you cannot demonstrate authorization, do not scan it.
