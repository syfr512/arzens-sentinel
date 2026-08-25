# GitHub Release and Handoff Checklist

This checklist prepares the repository for a controlled internship submission and later production publication. It does **not** authorize pushing code, changing repository visibility, or publishing the application automatically.

## Repository preparation

- [ ] Create a **private** GitHub repository under the approved owner, such as `arzens-sentinel`.
- [ ] Export the reviewed project through the project management interface’s GitHub integration.
- [ ] Confirm that `.env`, report directories, build output, local database files, credentials, customer evidence, and signed artifact links are excluded.
- [ ] Review the generated first commit and confirm that migration `0004_soft_synch.sql`, documentation, CI, issue template, security policy, and contribution guide are included.
- [ ] Add the project supervisor and required collaborators with least-privilege repository roles.

## Continuous integration gate

- [ ] Enable the included **Quality Gate** workflow on pull requests and the default branch.
- [ ] Require successful type checking, 42-test suite, production build, production dependency audit, and zero-network CSV fixture export before merge.
- [ ] Enable Dependabot version and security updates.
- [ ] Require code review for changes to scanner networking, authorization, report rendering, storage, database schema, or workflows.

## Deployment gate

- [ ] Review `docs/DEPLOYMENT_GUIDE.md`, `docs/LOCAL_CONFIG_TEMPLATE.md`, `docs/SECURITY_REVIEW.md`, and `docs/LIVE_TESTING_RUNBOOK.md` with the deployment owner.
- [ ] Configure managed secrets and production OAuth/database settings without committing values.
- [ ] Enforce private/control-plane egress blocks and an API gateway/WAF rate limit.
- [ ] Configure object-storage retention rules matching 7-, 30-, and 90-day target policy selections.
- [ ] Publish first to a restricted/internal audience and complete a staging target proof, bounded scan, report retrieval, revocation, and cancellation smoke test.

## Release notes and portfolio handoff

- [ ] Create a GitHub release from the reviewed commit using a descriptive tag such as `v1.0.0-live-ready`.
- [ ] Link the submission report, verification record, responsible-use policy, controlled-lab protocol, and deployment guide from the release notes.
- [ ] State clearly that Safe Passive scans require authorization, findings are advisory, and external AI guidance remains optional.
- [ ] Do not publish a public demo with real target data, credentials, raw evidence, or stored report artifacts.
