# Local OWASP ZAP Adapter

The application contains a local-only adapter in `server/scanner/zap.ts`. It maps selected ZAP alert names into the same stable Arzens Sentinel rule IDs used by the native safe-passive core. The fixture `zap-fixtures/csp-header-not-set.json` is covered by a unit test, so the hosted application never needs ZAP installed to verify this boundary.

For a local lab, start a developer-controlled HTTP service on loopback and run:

```bash
docker compose -f docker-compose.zap.yml up --abort-on-container-exit
```

The compose file targets `http://127.0.0.1:3000` deliberately. Do not replace that address with an external system unless you have explicit written authorization. Import the resulting JSON into the adapter only after applying the same evidence-redaction policy used by native findings.

ZAP output is an additional signal, not an automatic severity authority. The normalization layer preserves source metadata, assigns a documented rule ID, and allows the dashboard’s deduplication/review process to make the final triage decision.
