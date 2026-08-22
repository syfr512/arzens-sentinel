# Configuration Reference

This document identifies the configuration keys used by Arzens Sentinel without creating a local environment file or exposing secret values. In managed hosting, configure these values through the secure project settings interface. In self-hosted development, use your organization’s secret manager and keep any local secret file outside version control.

| Key | Required in production | Purpose |
|---|---:|---|
| `VITE_APP_ID` | Yes | OAuth application identity. |
| `JWT_SECRET` | Yes | Server session signing; must be at least 32 characters. |
| `DATABASE_URL` | Yes | MySQL-compatible persistence connection. |
| `OAUTH_SERVER_URL` | Yes | HTTPS OAuth provider endpoint. |
| `OWNER_OPEN_ID` | Yes | Initial project owner identity. |
| `BUILT_IN_FORGE_API_URL` | Yes | Managed server-side platform API endpoint. |
| `BUILT_IN_FORGE_API_KEY` | Yes | Managed server-side platform API credential. |
| `ENABLE_AI_REMEDIATION` | No | Enables optional built-in advisory remediation. Keep disabled for deterministic-only operation. |

Never put real credentials in Git, client-side code, report evidence, issue trackers, screenshots, or exported artifacts. The production startup validator rejects missing required values, secrets shorter than the session-security minimum, and non-HTTPS service endpoints.
