---
name: incident-response
description: Use when responding to security incidents (containment, eradication, recovery, lessons learned). Covers the NIST incident handling lifecycle adapted to CyberLab evidence and scope controls.
---

# Incident Response

Incident response lifecycle (NIST SP 800-61) executed under CyberLab scope and evidence controls.

## When To Use

- Use when the user reports a security incident, breach, or compromise.
- Use when planning containment, eradication, or recovery actions.
- Coordinate with the operator — destructive response actions need approval.

## Workflow

### Phase 1 — Preparation
- Confirm incident scope and authorization for response actions.
- Ensure evidence collection tooling is ready (hashing, imaging, logging).
- Establish communication channel and decision authority.

### Phase 2 — Detection & Analysis
- Triage alerts: true positive vs. false positive.
- Scope the incident: affected hosts, accounts, data, timeframe.
- Collect volatile evidence first (memory, network connections, running processes).

### Phase 3 — Containment
- **Short-term:** isolate affected systems without destroying evidence.
- **Long-term:** apply patches, block IOCs, disable compromised accounts.
- Balance containment against business impact — coordinate with operator.

### Phase 4 — Eradication
- Remove malicious artifacts, persistence mechanisms, and backdoors.
- Patch the root cause vulnerability.
- Verify eradication with follow-up scans (`cyberlab exec -- nmap`, `nuclei`).

### Phase 5 — Recovery
- Restore systems from known-good backups.
- Enhanced monitoring for the recovery period.
- Gradual return to production with heightened alertness.

### Phase 6 — Lessons Learned
- Document timeline, root cause, and response effectiveness.
- Update detection rules and playbooks.
- Feed findings back into the knowledge library (`propose_document_update`).

## Evidence Requirements

- Every response action is captured as SHA-256 evidence.
- Timeline is reconstructed from sealed artifacts, not memory.
- Chain of custody maintained throughout.

## Guardrails

- Containment actions that disrupt operations need operator approval.
- Never eradicate before evidence collection is complete.
- Legal obligations (notification, preservation) take precedence.
