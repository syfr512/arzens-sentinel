# Controlled Vulnerability-Lab Validation

Arzens Sentinel will not scan public “vulnerable sites.” All accuracy checks use either deterministic in-process fixtures or an intentionally vulnerable application that is **locally isolated, explicitly authorized, and never exposed to the public Internet**.

## Validation approach

The automated suite uses both deterministic response fixtures and a real ephemeral **loopback-only HTTP server** with known response patterns. The server is bound to `127.0.0.1` on an operating-system-assigned port, exists only for the test lifecycle, and is closed after the assertion. It supplies only the signals that the Safe Passive scanner is designed to observe: omitted or weak headers, unsafe cookie attributes, wildcard CORS, mixed-content references, and server disclosure. This creates reproducible expected findings without running exploit payloads or targeting a third-party host.

For an optional manual demonstration, OWASP WebGoat or Juice Shop may be bound to loopback only in a disposable environment. WebGoat explicitly warns that it is deliberately insecure and should be isolated; Juice Shop describes itself as a security-tools “guinea pig.” [1] [2]

> The hosted application blocks local, private, link-local, metadata, and mixed-DNS targets by design. Local lab testing therefore belongs to the test harness or shared-core CLI in a separately approved isolated environment—not the public dashboard.

The loopback exception is not available to the hosted route or CLI. It is accepted only when the scanner is called from the automated test process with the explicit `controlledLab` execution option, so it cannot widen the live application’s SSRF boundary.

## Known-signal test matrix

| Fixture route | Expected Safe Passive signal | Expected rule family |
|---|---|---|
| `/headers-missing` | No CSP, HSTS, clickjacking, or MIME-sniffing response headers | Response hardening |
| `/unsafe-cookie` | Session cookie missing `Secure`, `HttpOnly`, or `SameSite` | Cookie security |
| `/cors-wildcard` | Wildcard `Access-Control-Allow-Origin` observed | Cross-origin policy |
| `/redirect-http` | HTTP redirect response retained as evidence | Redirect / transport |
| `/mixed-content` | HTTPS page references an HTTP asset | Mixed content |
| `/server-banner` | Verbose server technology header | Information disclosure |

## References

[1] [OWASP WebGoat](https://owasp.org/www-project-webgoat/)

[2] [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
