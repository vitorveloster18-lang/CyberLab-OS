---
name: network-assessment
description: Plan, scope, execute and review authorized network assessments using CyberLab capabilities and SHA-256 evidence tracking.
---

# Network Assessment

## Purpose

Guide the operator through an authorized, strictly scoped network assessment in CyberLab OS.

## Preconditions

- Identify the active `projectId` and verify its `ProjectScope` (`allowedTargets`, `blockedTargets`, `allowExternalTargets`).
- Confirm every target IP, CIDR, or hostname belongs to the authorized scope before proposing a check.
- Verify executor availability and tool version via the CyberLab registry.
- Explain the planned check, its `CapabilityRisk` level, and expected network footprint.

## Workflow

1. Inspect existing project evidence and scope boundaries.
2. Propose the smallest, lowest-risk capability that answers the current question.
3. Explain the selected capability ID and structured parameters (never construct raw shell strings).
4. Obtain explicit operator approval whenever required by policy (`ask`).
5. Execute exclusively through the CyberLab `ExecutionController`.
6. Preserve raw output (`EvidenceRecord`) before summarizing or interpreting results.
7. Separate observed facts from inferred hypotheses (`severity` vs `confidence`).
8. Recommend independent verification and concrete remediation steps.

## Output Requirements

- Summarize verified observations with explicit `evidenceId` and `sha256` references.
- Explicitly list limitations, uninspected ports/protocols, and potential false-positive sources.
- Never mark a `SecurityFinding` as `confirmed` without at least one verified `evidenceId`.
- Explain how the operator can reproduce or challenge every conclusion.

## Safety

Skills provide operational methodology only; they never grant execution permissions or expand `ProjectScope`. The `PolicyEngine` and `ScopeController` remain authoritative at both submission and execution time.
