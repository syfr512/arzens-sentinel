# Verification Record

## Automated verification

The final local verification command completed successfully:

```bash
pnpm check
pnpm test
pnpm build
```

The test suite contains **20 passing tests** across seven files. It covers the scanner’s SSRF boundaries, redaction, score mapping, fixture-backed Demo Scan, deterministic remediation fallback, local ZAP normalization, report rendering, logout behavior, protected scan/finding/remediation/report ownership checks, explicit authorization attestation, and an authenticated protected-procedure workflow that runs Demo Scan → scan detail → remediation → secure PDF artifact metadata without inserting test records into the live database.

The CLI was also verified using the zero-network fixture path. It generated JSON, HTML, and a valid PDF 1.4 document. The `--fail-on` threshold produced the expected non-zero exit code, and a non-demo target without `--authorized` was rejected before scan orchestration.

## Database and build verification

The reviewed migration was applied successfully. A non-destructive schema query confirmed the presence of `scan_targets`, `scan_runs`, `scan_endpoints`, `findings`, `remediation_recommendations`, `scan_events`, and `report_artifacts`. The final production build completed successfully.

## Visual and responsive verification

Authenticated preview screenshots were captured for the Overview, New Assessment, History, Methodology, and Account views in desktop and mobile viewports. The interface was checked for navigation, empty states, visible focus-compatible controls, responsive single-column mobile transformations, the account route, and the safe-passive authorization control.

## Interactive browser limitation

The connected personal browser session reached the sign-in gate but did not have an authenticated project session. To avoid asking the user to log in to an account or creating live database test records, the interaction sequence was verified at the protected-procedure level with mocked storage/database boundaries instead of clicking through the live account. The live authenticated preview screenshots confirm the protected dashboard routes render for an authorized session. Before a public demonstration, sign in and exercise the same documented Demo Scan workflow manually; it remains fixture-backed and does not contact a third-party system.
