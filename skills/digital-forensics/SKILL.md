---
name: digital-forensics
description: Use when conducting digital forensics and incident investigation (artifact collection, timeline analysis, malware triage). Covers evidence integrity, chain of custody, and analysis methodology under CyberLab.
---

# Digital Forensics

Digital forensics and incident investigation methodology with strict evidence integrity and chain of custody.

## When To Use

- Use when the user requests forensic analysis, incident investigation, or artifact examination.
- Use when analyzing disk images, memory dumps, logs, or suspicious files.
- Maintain chain of custody — every artifact is hashed and sealed.

## Workflow

### 1. Evidence Acquisition
- Hash everything on collection: `cyberlab exec -- sha256sum <artifact>`.
- Work on copies, never originals. Originals stay sealed.
- Document acquisition method, tool, and timestamp in the evidence record.

### 2. Timeline Analysis
- Correlate timestamps across sources (filesystem, logs, network, registry).
- Build a unified timeline to establish sequence of events.
- Use `tshark` for network capture analysis: `cyberlab exec -- tshark -r <capture>`.

### 3. Artifact Analysis
- **Filesystem:** deleted file recovery, alternate data streams, timestomping.
- **Memory:** process injection, credential extraction, rootkit detection.
- **Logs:** authentication anomalies, lateral movement indicators, exfiltration.
- **Malware:** static analysis (`ghidra`, `jadx`), behavioral analysis, IOC extraction.

### 4. Indicator Correlation
- Extract IOCs (hashes, IPs, domains, mutexes, registry keys).
- Correlate with the knowledge library for known threat patterns.
- Distinguish confirmed malicious activity from benign anomalies.

### 5. Reporting
- Present findings with evidence chain intact (SHA-256 at each step).
- Separate facts (artifact-derived) from inference (analyst conclusion).
- Recommend containment and eradication steps.

## Tool Reference (Kali native)

| Goal | Command |
|---|---|
| Disk imaging | `dd`, `dc3dd`, `ftkimager` |
| Network forensics | `tshark`, `wireshark` |
| Reverse engineering | `ghidra`, `jadx`, `radare2` |
| String extraction | `strings`, `binwalk` |
| Filesystem | `sleuthkit` (`fls`, `icat`) |

## Guardrails

- Chain of custody is non-negotiable — hash at every transfer.
- Never run unknown samples on the analysis workstation without isolation.
- Legal/authorization basis must be documented before acquisition.
