---
name: mobile-forensics
description: Guide authorized mobile backup, indicator and artifact inspection with strict chain-of-custody and privacy redaction.
---

# Mobile Forensics

## Purpose

Provide forensically sound procedures for inspecting authorized mobile diagnostic exports and indicator checks (e.g., MVT-compatible workflows) while preserving chain of custody.

## Preconditions

- Confirm explicit legal/owner authorization and retention policy (`retentionClass: "forensic"`).
- Store all imported artifacts with SHA-256 verification before running parsers.
- Apply strict PII and credential redaction before sharing summaries with models or external partners.

## Output Requirements

- Distinguish benign system telemetry from high-confidence compromise indicators.
- Record collector identity, acquisition timestamp, tool version, and full `CustodyEvent` trail.
- Mark ambiguous IoC matches as `inconclusive` until corroborated by independent artifacts.
