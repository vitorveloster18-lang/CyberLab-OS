---
name: reverse-engineering
description: Structure static and assisted binary reverse-engineering workflows in WSL2/Linux environments with provenance tracking.
---

# Reverse Engineering

## Purpose

Guide static binary inspection, symbol/string triage, and decompilation review in Linux/WSL2 lab environments (including Ghidra / REA workflows when installed locally).

## Preconditions

- Never execute untrusted binaries directly on the host WSL2 environment; restrict dynamic analysis to isolated, network-disabled containers or VMs.
- Record the exact binary SHA-256 in `EvidenceStore` before beginning static analysis.
- Verify Linux/WSL2 runtime availability (`detectRuntimeEnvironment`) before invoking native decompiler adapters.

## Output Requirements

- Cite exact binary SHA-256, section/offset or function address, and decompiler version for every claim.
- Distinguish heuristic decompiler pseudocode artifacts from verified control-flow behavior.
