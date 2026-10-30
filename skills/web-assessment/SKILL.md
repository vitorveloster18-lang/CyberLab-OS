---
name: web-assessment
description: Conduct scoped web application security checks, HTTP header audits, and evidence-backed validation without unverified claims.
---

# Web Assessment

## Purpose

Provide a structured methodology for evaluating web applications and HTTP APIs within an authorized CyberLab OS project scope.

## Preconditions

- Confirm the target URL origin or domain is listed in `ProjectScope.allowedTargets` and not excluded by `blockedTargets`.
- Prefer passive HTTP header, TLS, cookie-flag, and configuration inspection before any active fuzzing.
- Ensure authentication headers and session cookies are handled through redaction-safe evidence storage.

## Workflow

1. Inspect passive HTTP exchanges (`http_exchange`) for transport security (`Strict-Transport-Security`), framing (`Content-Security-Policy`, `X-Frame-Options`), MIME sniffing (`X-Content-Type-Options`), CORS misconfigurations, and cookie attributes (`HttpOnly`, `Secure`, `SameSite`).
2. Record raw HTTP status and response headers in `EvidenceStore` before interpretation.
3. Evaluate potential findings with explicit `severity` (impact) and `confidence` (certainty `0.0..1.0`).
4. Request human approval (`ask`) before any active template scan or fuzzing capability (`moderate` / `high` risk).

## Safety

Skills do not authorize network requests. Every HTTP check is validated by `ScopeController` and `PolicyEngine` at submission and execution time.
