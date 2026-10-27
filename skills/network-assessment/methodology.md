# Network Assessment Methodology

1. **Passive & Local Inventory First**: inspect configuration files, architecture diagrams, and prior `EvidenceRecord` entries before sending network packets.
2. **Incremental Probing**: prefer targeted service/header checks on known ports over broad subnet sweeps.
3. **Lab Containment**: in Windows + WSL2 + Docker setups, ensure lab containers reside on isolated Docker networks and `allowExternalTargets` remains `false` unless explicitly authorized.
4. **Rate & Timeout Discipline**: respect executor timeouts and abort immediately if unexpected production traffic or gateway addresses are encountered.
