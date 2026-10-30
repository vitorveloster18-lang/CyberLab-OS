# Network Evidence Format Guidelines

- Use `kind: "network_observation"` or `kind: "http_exchange"` for raw protocol responses.
- Record exact target endpoint, timestamp (`observedAt`), tool version, and raw payload hash (`sha256`).
- Redact session tokens, `Authorization` headers, and cookies before sharing context with external partner runtimes.
