# Contributing

Contributions must preserve the project’s responsible-use boundaries. New scanner behavior must be non-destructive by default, backed by deterministic tests, and reviewed for authorization, SSRF, redaction, ownership, and resource-limit impact.

## Local quality gate

Run the following before opening a pull request:

```bash
pnpm check
pnpm test
pnpm build
pnpm audit --prod --audit-level high
```

Use the fixture Demo Scan and the isolated test harness for validation. Do not include real target evidence, secrets, download links, or production data in commits, issues, or pull requests.
