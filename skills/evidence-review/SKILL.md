---
name: evidence-review
description: Audit collected evidence integrity, challenge AI or partner hypotheses, and govern finding status transitions.
---

# Evidence Review

## Purpose

Enforce rigorous verification of `EvidenceRecord` integrity and `SecurityFinding` quality before reporting or remediation sign-off.

## Review Protocol

1. Run `verifyIntegrity(evidenceId)` on every referenced artifact to confirm SHA-256 immutability.
2. Verify provenance (`toolId`, `executorId`, `executionId`, `observedAt`) and inspect raw output directly rather than relying solely on AI summaries.
3. Check whether `severity` (potential impact) and `confidence` (strength of proof) are calibrated independently.
4. Reject or mark `needs_more_evidence` (`inconclusive`) any finding that lacks reproducible raw evidence or ignores plausible benign explanations.
5. Ensure sensitive tokens, cookies, and credentials are redacted (`readRedactedForSharing`) before exporting bundles.
