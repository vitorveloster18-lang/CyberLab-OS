---
name: network-recon
description: Use when performing network reconnaissance and enumeration (port scanning, service discovery, banner analysis) against authorized targets. Covers nmap usage, scope compliance, and evidence capture via CyberLab.
---

# Network Reconnaissance

Authorized network reconnaissance techniques using the operator's own Kali tools, executed under CyberLab scope guard.

## When To Use

- Use when the user requests network scanning, port enumeration, or service discovery.
- Use when mapping attack surface of an in-scope network.
- Do not use against out-of-scope targets — confirm scope first.

## Workflow

### 1. Confirm Scope
- Verify target is within `.cyberlab/scope.json` allowed targets.
- For external targets, `allowExternalTargets` must be true and the target explicitly listed.

### 2. Host Discovery
- `cyberlab exec -- nmap -sn <target>` — ping sweep to find live hosts.
- `cyberlab exec -- nmap -sn <target>/24` — subnet discovery.

### 3. Port Scanning
- `cyberlab exec -- nmap -sV -p- <target>` — full port scan with service versions.
- `cyberlab exec -- nmap -sV -p 80,443,22,3306 <target>` — targeted common ports.
- `cyberlab exec -- nmap -sU --top-ports 20 <target>` — UDP scan (top ports).

### 4. Banner & Service Analysis
- Correlate service versions with known vulnerabilities via `search_knowledge`.
- Flag outdated services, default credentials, and exposed management interfaces.
- Beware false positives: backported patches make banners lie.

### 5. Evidence
- Every scan is captured as SHA-256 evidence automatically by `cyberlab exec`.
- Reference evidence IDs in findings; never report a port/service without evidence.

## Tool Reference (Kali native)

| Goal | Command |
|---|---|
| Host discovery | `nmap -sn` |
| Port + version | `nmap -sV -p-` |
| OS fingerprint | `nmap -O` |
| Vuln scripts | `nmap --script vuln` |
| Slow/stealth | `nmap -T2 -sS` |

## Guardrails

- Aggressive scans (`-A`, `-T4`, `--script vuln`) only with explicit authorization.
- Rate limiting and IDS evasion are out of scope unless the engagement authorizes them.
- Document scan parameters in the evidence for reproducibility.
