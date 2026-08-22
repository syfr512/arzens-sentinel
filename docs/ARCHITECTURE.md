# Architecture

Arzens Sentinel separates **interface**, **assessment orchestration**, **deterministic scanning**, **advisory remediation**, and **artifact storage** so that the web dashboard does not become the scanner and AI never becomes the source of truth.

```mermaid
flowchart LR
  U[Authorized user] --> UI[React security-operations dashboard]
  UI --> API[tRPC protected procedures]
  API --> OWN[Ownership & authorization checks]
  OWN --> DB[(MySQL: metadata, status, evidence)]
  API --> CORE[Safe scanner core]
  CORE --> SAFE[URL/DNS/redirect SSRF policy]
  SAFE --> HTTP[Bounded same-origin HTTP client]
  HTTP --> RULES[Deterministic rule catalog & scoring]
  RULES --> DB
  API --> REM[Structured remediation service]
  REM --> FALLBACK[Deterministic guidance]
  REM -. optional .-> LLM[Server-side model]
  API --> REPORT[JSON / HTML / PDF renderer]
  REPORT --> S3[(Managed object storage)]
  DB --> UI
```

The scanner-core is intentionally shared between the server workflow and the local CLI. This keeps URL-safety enforcement, response limits, evidence redaction, rule IDs, and scoring consistent across user experiences.

## Trust boundaries

| Boundary | Design response |
|---|---|
| User supplied target | URL protocol, DNS resolution, IP category, and every redirect are checked before use. |
| Remote response | Response size, redirect count, timeout, page count, and same-origin discovery are bounded; credential-like values are redacted. |
| AI provider | Receives only normalized/redacted finding evidence and returns a strict schema; deterministic guidance is used if the provider is unavailable or invalid. |
| Database | Stores metadata and redacted evidence only; user ownership is verified before every target-specific operation. |
| Artifact storage | Stores report bytes outside the database; database retains only the storage key and retrievable URL metadata. |

## Extension path

The hosted profile remains Safe Passive. A separate local-only adapter normalizes OWASP ZAP output into the same stable finding model. Future authenticated crawling or active lab testing must remain local, require explicit authorization, and be isolated from the hosted service.
