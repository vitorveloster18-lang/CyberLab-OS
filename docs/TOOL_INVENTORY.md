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
| **CyberLab Passive HTTP & Secret Audit** | Rede / Código (nativo) | `approved_embed` | Embutido (`integrations/`) | Implementação própria MIT em TypeScript/Bun sem dependências restritivas. |
| **Nmap** | Avaliação de rede | `license_review` | `internal_process` | A *Nmap Public Source License (NPSL)* restringe incorporação e redistribuição em produtos; usar apenas binário instalado localmente pelo usuário após revisão. |
| **Burp Suite Community** | Avaliação web | `plugin_only` | `plugin_only` | Software proprietário PortSwigger; proibido incorporar código ou redistribuir binários. |
| **OWASP ZAP** | Avaliação web | `license_review` | `internal_process` | Verificar Apache-2.0 da versão alvo e licenças de add-ons antes de qualquer empacotamento. |
| **Wireshark / tshark** | Análise de tráfego | `license_review` | `internal_process` | GPL-2.0+; manter como processo CLI separado (`tshark`) sem linkar código GPL ao core MIT. |
| **Nuclei** | Varredura baseada em templates | `license_review` | `internal_process` | Avaliar separadamente o binário (MIT) e os repositórios de templates/dependências. |
| **ffuf** | Fuzzing web | `license_review` | `internal_process` | Conferir licença MIT da tag fixada e dependências Go transitivas. |
| **Metasploit Framework** | Validação de exploração | `license_review` | `internal_process` | Licença BSD-3-Clause com particularidades Rapid7; avaliar módulos e dependências individualmente; alto risco operacional (`high`/`destructive`). |
| **Strix** | Agente / automação ofensiva | `license_review` | `plugin_only` / `partner` | Fixar repositório exato, licença e dependências antes de integrar via ponte. |
| **Shannon** | Automação de segurança | `license_review` | `plugin_only` | Declara **AGPL-3.0**; não incorporar nem derivar código dentro do CyberLab OS sem revisão jurídica explícita das obrigações AGPL. |
| **PentAGI** | Agente autônomo | `license_review` | `partner` / `internal_process` | Declara MIT no repositório principal; revisar imagens Docker e dependências transitivas. |
| **PentestGPT** | Assistente de pentest | `license_review` | `partner` | Declara MIT; auditar dependências Python e avisos de licença antes de uso. |
| **CAI** | Framework de agentes cyber | `license_review` | `partner` | Verificar cobertura exata da licença por subpacote/arquivo. |
| **HexStrike AI** | Automação ofensiva | `candidate` | `plugin_only` | Identificar repositório canônico, tag e licença antes de iniciar avaliação. |
| **MVT (Mobile Verification Toolkit)** | Forense mobile | `license_review` | `internal_process` | Verificar termos da licença própria do MVT (restrições éticas/não-abuso) antes de integrar. |
| **Mullvad** | Privacidade / rede | `plugin_only` | `plugin_only` | Distinguir cliente local, daemon do sistema e serviço; apenas verificação de estado local. |
| **OnionShare** | Compartilhamento seguro | `license_review` | `internal_process` | GPL-3.0; manter desacoplado como ferramenta externa opcional. |
| **VeraCrypt** | Criptografia de volumes | `license_review` | `internal_process` | Licença Apache-2.0 + termos históricos TrueCrypt License 3.0; não incorporar código-fonte sem revisão completa. |
| **Tor** | Transporte anônimo | `license_review` | `internal_process` | BSD-3-Clause no daemon principal, mas avaliar binários específicos do sistema operacional. |
| **GrapheneOS** | Hardening mobile | `plugin_only` | `plugin_only` | Uso restrito a checklists, skills de auditoria e verificação de atestação; SO separado. |
| **Signal** | Comunicação segura | `plugin_only` | `plugin_only` | AGPL-3.0; não incorporar clientes ou servidores; tratar apenas como canal externo se aplicável. |
| **REA (Reverse Engineering Assistant)** | Engenharia reversa | `license_review` | `internal_process` (WSL2) | Repositório declara MIT, mas **Hopper** é proprietário (não incluído) e **Ghidra** (Apache-2.0) é instalação separada com limitações conhecidas no Windows — validar exclusivamente via Linux/WSL2. |

---

## 3. Localização dos Manifestos Individuais

Os manifestos JSON por componente residem em `vendor/manifests/<tool-id>.json` e são validados automaticamente por `script/check-cyberlab-licenses.ts` contra o schema `ToolComponentManifest` (`cyberlab/config/tool-manifest.ts`).
