# Deployment Decision and Release Guide

## Recommended approach

**Use Manus managed hosting for the live application and GitHub for source control, CI, issue tracking, and portfolio review.** GitHub Pages is not appropriate because Arzens Sentinel requires a Node server, authenticated tRPC procedures, database access, managed storage, and secure server-side environment variables. A static host would remove the controls that make the product safe.

| Option | Recommendation | Reason |
|---|---|---|
| Manus managed hosting | **Recommended for the application** | The project already has managed OAuth, database, storage, runtime configuration, preview, release checkpointing, and custom-domain support. |
| GitHub repository | **Recommended for source control** | It provides version history, code review, CI, issue tracking, a portfolio landing page, and reproducible local setup. |
| GitHub Pages | Not recommended | It cannot run the required server, protected procedures, scanner, database, or secure artifact path. |
| Self-managed container platform | Later option | Use only if an organization needs private networking, SIEM/egress controls, or dedicated queued workers beyond the managed request envelope. |

## Pre-deployment controls

> Publish only after the deployment owner confirms authorization policy, egress restrictions, rate limiting, and retention configuration.

| Control | Required deployment action |
|---|---|
| Network egress | Block private, loopback, link-local, metadata, and control-plane destinations at the cloud firewall layer. |
| Rate limit | Add an edge or WAF rate limit for `/api/trpc`, especially assessment-start requests. |
| Artifact retention | Configure object-storage lifecycle rules matching allowed 7-, 30-, and 90-day policy selections. |
| Secrets | Use the managed secret interface only; never commit `.env` files or API keys. |
| Identity | Confirm the production OAuth callback domain and administrator ownership mapping. |
| Monitoring | Forward structured request and audit logs to the organization’s approved monitoring platform. |
| Release gate | Run `pnpm check`, `pnpm test`, `pnpm build`, and `pnpm audit --prod --audit-level high`. |

## GitHub handoff

The repository contains a GitHub Actions workflow, Dependabot updates, issue template, contribution guide, security reporting guidance, a [configuration reference](CONFIGURATION_REFERENCE.md), a [local and production configuration template](LOCAL_CONFIG_TEMPLATE.md), a [GitHub release checklist](GITHUB_RELEASE_CHECKLIST.md), and project documentation. Create a **private repository first** if the internship proposal, internal references, or screenshots are not public.

1. In the project management interface, open **Settings → GitHub** and choose the intended owner and repository name, such as `arzens-sentinel`.
2. Export the code to a new private repository. Review the generated repository, branch protection, and collaborators before changing visibility.
3. In GitHub, require the CI workflow for the default branch and enable Dependabot security updates.
4. Add repository topics such as `typescript`, `application-security`, `secure-coding`, `owasp`, and `portfolio` only if public release is approved.
5. Create a release tag after the first successful deployed smoke test. Do not store user data, report artifacts, or secrets in Git history.

## Publishing the application

After the project checkpoint is reviewed, use the **Publish** control in the management interface to deploy. Publishing is intentionally left to the deployment owner because it exposes a live application. Start with a restricted/internal audience, complete the pre-deployment controls above, then attach a custom domain only after the staging smoke test passes.
