# Local and Production Configuration Template

This template is intentionally a **documentation artifact**, not an environment file. It maps required keys and expected values without creating, copying, or exposing any secret. Use your managed hosting secret interface or organization secret manager to provide real values.

## Configuration map

| Key | Local development expectation | Production source | Startup validation |
|---|---|---|---|
| `NODE_ENV` | `development` | Runtime-provided `production` | Enables fail-fast production checks. |
| `VITE_APP_ID` | Local OAuth app identifier | Managed OAuth project setting | Required, non-empty. |
| `JWT_SECRET` | Random development-only string, never committed | Managed secret | Required; at least 32 characters. |
| `DATABASE_URL` | Local MySQL-compatible test database | Managed database connection | Required, non-empty. |
| `OAUTH_SERVER_URL` | HTTPS local/staging OAuth endpoint | Managed OAuth endpoint | Required and HTTPS. |
| `OWNER_OPEN_ID` | Development owner identity | Managed project owner mapping | Used for initial administrative role mapping. |
| `BUILT_IN_FORGE_API_URL` | Managed development value | Managed platform value | Required and HTTPS. |
| `BUILT_IN_FORGE_API_KEY` | Managed development secret | Managed platform secret | Required and server-side only. |
| `ENABLE_AI_REMEDIATION` | `false` by default | Explicit operator choice | Optional; deterministic guidance remains available when false. |

## Local startup sequence

1. Obtain approved **development-only** OAuth, database, and managed-service configuration through the team’s secret manager.
2. Keep local secret values in an ignored developer-specific file or injected shell session. Never create or commit a repository `.env` file.
3. Run `pnpm install --frozen-lockfile`, `pnpm check`, `pnpm test`, and `pnpm dev`.
4. Use the Demo Scan or controlled test harness. Do not point local development at a production target unless the written authorization workflow has been completed.

## Production handoff

Before release, the deployment owner configures the production values through the managed settings interface. The server validates that required values exist, that `JWT_SECRET` meets the minimum length, and that OAuth/managed API endpoints use HTTPS. The deployment must also apply the controls in `DEPLOYMENT_GUIDE.md`: network egress restrictions, gateway rate limiting, audit monitoring, and report-object lifecycle rules.

> Never share a key in GitHub issues, pull requests, submission documents, screenshots, CSV files, reports, browser storage, or chat messages.
