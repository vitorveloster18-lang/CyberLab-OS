# Static Code Audit Checklist

- **Secrets & Keys**: hardcoded API keys, PEM private keys, JWT secrets, cloud credentials.
- **Cryptography & Transport**: `rejectUnauthorized: false`, weak hashes for passwords, hardcoded IVs.
- **Execution Sinks**: shell string interpolation (`sh -c`), `eval()`, `new Function()`, unsafe deserialization.
- **Filesystem & Network**: unvalidated path joins (`..`), SSRF to `169.254.169.254` or internal services.
