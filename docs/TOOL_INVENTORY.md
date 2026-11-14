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

## 2. Triagem de Engenharia

**O CyberLab OS não distribui, não instala e não embute ferramenta de terceiros.**
Todo binário é do operador, resolvido pelo `PATH` do Kali dele. A tabela abaixo existe
para registrar *o que o CyberLab espera encontrar* e *por que não pode empacotar*.

| Componente | Categoria | Estado | Modo | Observações Críticas |
| --- | --- | --- | --- | --- |
| **OpenCode V2 (`2.1.4`)** | Plataforma base | `approved_embed` | Base do monorepo | Licença MIT confirmada no commit `dae4077a96243257ea0a2086068504b791629f10`; avisos preservados. |
| **CyberLab Core (`cyberlab/`)** | Domínio próprio | `approved_embed` | Embutido | Escopo, execução, evidência `SHA-256`, redação, CDIs e biblioteca curada — todo `MIT`, código próprio. |
| **Nmap** | Avaliação de rede | `plugin_only` | `PATH` do operador | *NPSL* restringe incorporação e redistribuição. O CyberLab só o invoca por `cyberlab exec`. |
| **Nuclei / ffuf / sqlmap / dirsearch** | Varredura web | `plugin_only` | `PATH` do operador | Binários do operador; o CyberLab nunca baixa templates nem agenda instalação. |
| **Wireshark / tshark** | Análise de tráfego | `plugin_only` | `PATH` do operador | GPL-2.0+; mantido como processo externo, sem qualquer link com o core MIT. |
| **Ghidra / JADX / Rizin** | Engenharia reversa | `plugin_only` | `PATH` do operador | Apache-2.0; usados pelo operador, inclusive por caminho absoluto quando o pacote não publica o binário no `PATH`. |
| **Burp Suite Community** | Avaliação web | `plugin_only` | `PATH` do operador | Proprietário PortSwigger; o operador aponta o proxy dele para o alvo do laboratório. |
| **Metasploit / Hashcat / John** | Validação & quebra | `plugin_only` | `PATH` do operador | Executados sob trava de escopo e custódia `SHA-256`. |

---

## 3. Localização dos Manifestos Individuais

Os manifestos JSON por componente residem em `vendor/manifests/<tool-id>.json` e são validados automaticamente por `script/check-cyberlab-licenses.ts` contra o schema `ToolComponentManifest` (`cyberlab/config/tool-manifest.ts`).
