---
name: web-appsec
description: Use when assessing web application security (OWASP Top 10, API security, authentication flaws). Covers testing methodology for injection, broken access control, and API vulnerabilities under CyberLab scope.
---

# Web Application Security

Web application and API security assessment methodology, aligned with OWASP Top 10 and CyberLab evidence capture.

## When To Use

- Use when the user requests web app testing, API security review, or OWASP assessment.
- Use when analyzing authentication, authorization, or input handling flaws.
- Confirm the web target is in authorized scope before any active testing.

## Workflow

### 1. Reconnaissance
- Map the application surface: endpoints, parameters, authentication flows.
- `cyberlab exec -- ffuf -u <url>/FUZZ -w <wordlist>` — content discovery.
- `cyberlab exec -- curl -s -i <url>` — inspect headers and behavior.

### 2. OWASP Top 10 Testing

**A01 Broken Access Control**
- Test IDOR: swap object IDs in requests, verify authorization.
- Check vertical privilege escalation (user → admin endpoints).

**A02 Cryptographic Failures**
- Verify TLS config, sensitive data in transit/at rest.
- Check for secrets in client-side code or error messages.

**A03 Injection**
- SQLi, NoSQLi, command injection, SSTI — test inputs with payloads.
- `cyberlab exec -- sqlmap -u "<url>?id=1" --batch` — automated SQLi.

**A07 Authentication Failures**
- Brute-force protection, session management, credential stuffing resistance.

**A08 Software/Data Integrity**
- Deserialization, unsigned updates, CDN integrity.

**A10 SSRF**
- Test URL parameters, webhooks, and fetch functionality for internal access.

### 3. API Security
- Broken Object Level Authorization (BOLA) — the #1 API risk.
- Excessive data exposure — APIs returning more than the client needs.
- Rate limiting and resource consumption.

### 4. Evidence & Reporting
- Capture request/response pairs as SHA-256 evidence.
- Classify each finding by confirmed severity, not theoretical impact.
- Provide remediation: parameterized queries, least-privilege, output encoding.

## Tool Reference (Kali native)

| Goal | Command |
|---|---|
| Content discovery | `ffuf`, `gobuster` |
| SQL injection | `sqlmap` |
| XSS testing | `dalfox` |
| HTTP inspection | `curl`, `httpie` |
| TLS analysis | `testssl.sh`, `sslyze` |

## Guardrails

- Active testing only against in-scope targets with authorization.
- Avoid destructive payloads; prefer proof-of-concept.
- Respect rate limits; aggressive fuzzing needs explicit approval.
