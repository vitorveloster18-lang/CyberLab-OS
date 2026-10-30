# Inventário Inicial de Ferramentas — CyberLab OS

Nenhum componente externo passa para incorporação (`vendor/`) ou execução integrada sem registro explícito de origem, versão/commit fixado, licença SPDX, dependências e modo de integração aprovado.

---

## 1. Máquina de Estados do Inventário

| Estado | Significado operacional | Permitido em build de distribuição? |
| --- | --- | --- |
| `candidate` | Ferramenta identificada, ainda sem análise técnica/licença | Não |
| `license_review` | Código, licença e dependências em revisão | Não |
| `approved_embed` | Incorporação de código aprovada para versão e commit documentados | Sim (com aviso em `THIRD_PARTY_NOTICES.md`) |
| `approved_internal_process` | Execução local como processo externo/container com adaptador próprio | Sim (adaptador próprio; binário externo sujeito à licença dele) |
| `plugin_only` | Integração apenas via API/plugin/documentação; proibido embutir código | Sim (somente adaptador desacoplado) |
| `blocked` | Incompatibilidade de licença ou segurança não resolvida | Não (bloqueia pipeline) |
| `revalidation_required` | Mudança de versão, commit ou dependência exige nova revisão | Não até revalidação |

---

## 2. Triagem Inicial de Engenharia

| Componente | Categoria | Estado Inicial | Modo Pretendido | Observações Críticas |
| --- | --- | --- | --- | --- |
| **OpenCode V2 (`2.1.4`)** | Plataforma base | `approved_embed` | Base do monorepo | Licença MIT confirmada no commit `dae4077a96243257ea0a2086068504b791629f10`; avisos preservados. |
| **CyberLab Native Security Suite (10 Executores)** | Web / Rede / `.pcap` / Reversa / Mobile | `approved_embed` | Embutido (`integrations/*`) | Suíte própria `MIT` em TypeScript/Bun cobrindo Workspace Audit, HTTP Security Headers, HTTP Repeater & Comparer, Decoder/JWT/Sequencer, Surface Discovery, TCP Probe, TLS/X.509 Inspector, PCAP Analyzer, Binary ELF/PE/Mach-O Triage e Mobile APK/Backup Forensics. |
| **OpenTRAP (`opentrap/opentrap`)** | Avaliação web (Proxy/Repeater GUI) | `plugin_only` | `plugin_only` (`.cyberlab/bin`) | Repositório auditado: Java 17 + OWASP ZAP sob **AGPL-3.0** (incompatível com incorporação de código em projeto MIT). O CyberLab OS já traz equivalentes nativos `MIT` (`http-repeater`, `decoder-sequencer`, `surface-discovery`) e oferece download opcional do AppImage local via `script/bootstrap-local-tools.sh --with-agpl`. |
| **Nmap** | Avaliação de rede | `license_review` | `internal_process` | A *Nmap Public Source License (NPSL)* restringe incorporação e redistribuição em produtos; usar apenas binário instalado localmente pelo usuário após revisão. |
| **Burp Suite Community** | Avaliação web | `plugin_only` | `plugin_only` | Software proprietário PortSwigger; proibido incorporar código ou redistribuir binários. |
| **OWASP ZAP** | Avaliação web | `license_review` | `internal_process` | Verificar Apache-2.0 da versão alvo e licenças de add-ons antes de qualquer empacotamento. |
| **Wireshark / tshark** | Análise de tráfego | `license_review` | `internal_process` | GPL-2.0+; manter como processo CLI separado (`tshark`) sem linkar código GPL ao core MIT. |
| **Nuclei** | Varredura baseada em templates | `license_review` | `internal_process` | Avaliar separadamente o binário (MIT) e os repositórios de templates/dependências. |
| **ffuf** | Fuzzing web | `license_review` | `internal_process` | Conferir licença MIT da tag fixada e dependências Go transitivas. |
| **Metasploit Framework** | Validação de exploração | `approved_internal_process` | Slot Oficial `metasploit` (WSL2 / Win) | Roda `msfconsole` oficial externamente sob governança de escopo e custódia SHA-256. |
| **Strix (`usestrix/strix`)** | Agente / automação ofensiva | `approved_internal_process` | Slot Oficial `strix` | Apache-2.0; executa `strix-agent` externamente com validação dinâmica de PoCs. |
| **Shannon (`KeygraphHQ/shannon`)** | Automação Web/API | `plugin_only` | Slot Oficial `shannon` | AGPL-3.0; zero código embutido — executa `@keygraph/shannon` como ferramenta externa isolada. |
| **PentAGI (`vxcontrol/pentagi`)** | Agente autônomo | `approved_internal_process` | Slot Oficial `pentagi` (Web Embed) | MIT; stack Docker externo incorporável no palco central (`:8443`). |
| **PentestGPT & CAI** | Assistente / Framework cyber | `approved_internal_process` | Slot Oficial `pentestgpt-cai` | Executa em `venv` isolado no Kali WSL2 (`/opt/cyberlab-ai-pentest`). |
| **HexStrike AI (`0x4m4/hexstrike-ai`)** | MCP de 150+ ferramentas | `approved_internal_process` | Slot Oficial `hexstrike-ai` | MIT; ponte MCP/API local em `/opt/hexstrike-ai` conectada às ferramentas do Kali. |
| **MVT (`mvt-project/mvt`)** | Forense mobile (Android/iOS) | `approved_internal_process` | Slot Oficial `mvt` (WSL2) | Amnesty International Tech (`mvt-android` / `mvt-ios`) em ambiente isolado `/opt/mvt`. |
| **Mullvad / Signal / GrapheneOS** | OpSec, Privacidade & Mobile | `plugin_only` | Slot Oficial `mullvad-opsec` | Consulta local de túnel Mullvad VPN e auditoria de hardening/Verified Boot via `adb`. |
| **Tor + Torsocks + OnionShare** | Transporte anônimo & entrega | `approved_internal_process` | Slot Oficial `tor-onionshare` | BSD-3-Clause / GPL-3.0 externos; SOCKS5 `:9050` e compartilhamento seguro OnionShare. |
| **VeraCrypt** | Cofres criptografados | `approved_internal_process` | Slot Oficial `veracrypt` (GUI) | Abre nativamente no Windows ou dentro do Canvas X11/noVNC para montar cofres de evidências. |
| **REA (`morluto/rea`)** | Engenharia reversa assistida | `approved_internal_process` | Slot Oficial `rea` (Win / WSL2 + MCP) | MIT (`rea-agents`); conecta Ghidra, JADX e reconstrução JS/Electron/ASAR direto ao MCP nativo do OpenCode V2 (`rea setup --client opencode`). |

---

## 3. Localização dos Manifestos Individuais

Os manifestos JSON por componente residem em `vendor/manifests/<tool-id>.json` e são validados automaticamente por `script/check-cyberlab-licenses.ts` contra o schema `ToolComponentManifest` (`cyberlab/config/tool-manifest.ts`).
