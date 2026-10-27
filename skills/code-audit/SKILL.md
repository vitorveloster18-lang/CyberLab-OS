---
name: code-audit
description: Perform read-only static security audits of source code and configuration files with reproducible file/line evidence.
---

# Code Audit

## Purpose

Guide systematic static security auditing of authorized workspace source trees and infrastructure configurations.

## Workflow

1. Run read-only workspace capabilities (such as `code-analysis.workspace-audit` or `code-analysis.secret-config-scan`) scoped inside `workspaceRoot`.
2. Inspect flagged `code_location` and `json` evidence items in context to eliminate false positives (e.g., test fixtures vs. live credentials).
3. Trace untrusted input sources to sensitive sinks (command execution, SQL queries, deserialization, SSRF, path traversal, TLS verification bypass).
4. Propose minimal, idiomatic remediations and record findings with exact file paths, line numbers, and linked `evidenceIds`.

## Safety

Static audit skills are read-only guides; they never authorize arbitrary code execution or reading outside `workspaceRoot`.
