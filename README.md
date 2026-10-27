# CyberLab OS

**CyberLab OS** é um workspace unificado de avaliação de segurança autorizada, análise defensiva, auditoria estática, resposta a incidentes e revisão forense construído sobre o núcleo real do **OpenCode V2** (`anomalyco/opencode` v2.1.4, licença `MIT`).

O projeto preserva integralmente o motor nativo de sessões, agentes, modelos de IA, TUI, servidor HTTP, suporte a **MCP (Model Context Protocol)** e interface gráfica **SolidJS** do OpenCode V2, adicionando uma camada de governança e engenharia de segurança própria (`cyberlab/` + `integrations/` + `skills/`):

- **Catálogo controlado de capacidades** (`ControlledCapabilityRegistry`) com níveis formais de risco (`read_only`, `low`, `moderate`, `high`, `destructive`) — agentes remotos nunca podem auto-registrar capacidades executáveis.
- **Motor de políticas em duas fases e confinamento de escopo** (`PolicyEngine` + `ScopeController` + `ApprovalManager`) — revalida o escopo no momento exato da execução (anti-TOCTOU), bloqueia alvos fora de escopo/SSRF (`169.254.169.254`) e exige tickets humanos de uso único para ações propostas ou de maior risco.
- **Cadeia de custódia criptográfica e persistência de evidências** (`EvidenceStore` em `bun:sqlite` com `WAL` e permissões `0600` + artefatos `artifacts/<sha256>`) — separa **Execução**, **Evidência Bruta** e **Finding Analítico** (`severity` separado de `confidence`), com redação automática de credenciais/tokens/cookies.
- **Executores estruturados sem shell livre** (`CyberLabExecutor`) — recebem parâmetros validados via `Effect Schema`, honram `AbortSignal`, aplicam timeouts/limites de bytes e preservam a saída bruta antes de qualquer resumo por IA.
- **6 Skills operacionais nativas (`skills/*/SKILL.md`)** — descobertas automaticamente pelo `Skill.Service` do OpenCode V2, fornecendo metodologia sem jamais conceder privilégios de execução.
- **Ponte autenticada para Agentes Externos (`PartnerBridge` v1.0 + `chat_py_bridge.py`)** — comunicação assinada com `HMAC-SHA256` (`timingSafeEqual`), anti-replay, redação pré-envio de contexto e conector pronto em Python (`integrations/partners/chat_py_bridge.py`) para integrar runtimes externos baseados em `chat.py`.

---

## 1. Como Baixar Direto do Shell e Instalar Localmente

### Pré-requisitos recomendados
- **Linux nativo** ou **Windows 11 + WSL2 (Ubuntu 22.04/24.04)**  
  *(Se estiver no WSL2, clone sempre dentro do filesystem Linux, ex.: `~/projetos/CyberLab-OS`, **nunca** em `/mnt/c/...`, para máxima performance e permissões POSIX `0600` corretas no SQLite).*
- **Git**, **Python 3.10+** (caso use a ponte `chat_py_bridge.py` com seu `chat.py`) e **Bun `1.4.4`**.

### Passo a passo no terminal (Shell)

```bash
# 1. Instalar o Bun 1.4.4 (caso ainda não tenha instalado)
curl -fsSL https://bun.sh/install | bash -s "bun-v1.4.4"
export PATH="$HOME/.bun/bin:$PATH"
bun --version   # deve exibir 1.4.4

# 2. Clonar o repositório
# Enquanto o PR #1 estiver aberto, baixe direto da branch de implementação:
git clone -b arena/ce70b843-cyberlab-os https://github.com/vitorveloster18-lang/CyberLab-OS.git
# (Após aprovar/fazer merge do PR #1 na main no GitHub, basta: git clone https://github.com/vitorveloster18-lang/CyberLab-OS.git)

cd CyberLab-OS

# 3. Instalar dependências do monorepo (pula download binário pesado do Electron caso use CLI/TUI/Web)
ELECTRON_SKIP_BINARY_DOWNLOAD=1 bun install --ignore-scripts
bun run --cwd packages/core fix-node-pty

# 4. Validar licenças, tipagem e todas as suítes de testes localmente
bun run cyberlab:check-licenses
bun run cyberlab:typecheck
bun run cyberlab:test
```

---

## 2. Configurações do Sistema

O CyberLab OS utiliza três pontos simples de configuração (há arquivos de modelo prontos em [`.env.example`](.env.example) e [`config/cyberlab.example.json`](config/cyberlab.example.json)):

### 2.1. Variáveis de Ambiente (`.env` ou shell)

```bash
cp .env.example .env
```

Principais variáveis:
| Variável | Função | Padrão |
|---|---|---|
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_GENERATIVE_AI_API_KEY` / `OPENROUTER_API_KEY` | Chaves de API dos modelos LLM usados nas sessões do OpenCode V2 (ou faça login interativo com `bun packages/cli/src/index.ts auth login`) | — |
| `CYBERLAB_PARTNER_ID` | Identificador do seu runtime externo de agentes | `chat-py-agent` |
| `CYBERLAB_PARTNER_SECRET` | Segredo compartilhado `HMAC-SHA256` (mínimo 16 caracteres, recomendado 32+) entre o CyberLab OS e o `chat_py_bridge.py` | — |
| `CYBERLAB_PARTNER_URL` | Endpoint HTTP local do conector `chat_py_bridge.py` | `http://127.0.0.1:8788/cyberlab/partner` |

### 2.2. Armazenamento e Escopo por Projeto (`.cyberlab/`)

Ao operar em qualquer diretório de projeto, o CyberLab OS cria automaticamente `<projeto>/.cyberlab/` (ignorado pelo Git):
- `.cyberlab/cyberlab-evidence.sqlite` — banco SQLite em modo `WAL` (`chmod 0600`) com execuções, evidências, cadeia de custódia e revisões de findings.
- `.cyberlab/artifacts/<sha256>` — blobs forenses imutáveis endereçados por hash `SHA-256`.
- **Escopo padrão seguro (`allowExternalTargets: false`)**: por padrão, apenas o próprio `workspaceRoot` (protegendo `.git`) e `127.0.0.1` / `localhost` estão liberados. Alvos de laboratório adicionais (como uma sub-rede Docker `172.28.0.0/16`) podem ser liberados via API (`PUT /api/cyberlab/scope`) ou programaticamente via `ScopeController`.

### 2.3. Configuração de MCP e Plugins no OpenCode (`opencode.jsonc`)

Para conectar ferramentas externas via **MCP (Model Context Protocol)** nativo do OpenCode V2, adicione na raiz do projeto ou em `~/.config/opencode/opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "meu-servidor-mcp": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "."],
      "enabled": true
    }
  }
}
```

---

## 3. Como Usar o Sistema (4 Modos de Operação)

### Modo 1 — Linha de Comando Direta (`cyberlab` CLI)

Você pode executar auditorias, verificar integridade `SHA-256` e gerar relatórios Markdown sem sequer precisar de chave de IA:

```bash
# Ver status do workspace, plataforma (Linux/WSL2), escopo ativo, skills e contadores
bun packages/cli/src/index.ts cyberlab status

# Listar capacidades locais registradas e seus níveis de risco
bun packages/cli/src/index.ts cyberlab capabilities

# 1) Executar auditoria estática somente leitura de código/segredos no workspace
bun packages/cli/src/index.ts cyberlab run \
  -c code-analysis.workspace-audit \
  -i '{"subpath":"cyberlab","maxFiles":50}'

# 2) Executar inspeção passiva de cabeçalhos HTTP de segurança em um alvo local autorizado
bun packages/cli/src/index.ts cyberlab run \
  -c web-assessment.http-security-headers \
  -i '{"url":"http://127.0.0.1:8080/","method":"GET"}'

# 3) Executar sonda controlada de porta TCP e banner em laboratório local
bun packages/cli/src/index.ts cyberlab run \
  -c network-assessment.tcp-surface-probe \
  -i '{"host":"127.0.0.1","port":8080}'

# Listar evidências gravadas e verificar integridade criptográfica SHA-256 de uma evidência
bun packages/cli/src/index.ts cyberlab evidence
bun packages/cli/src/index.ts cyberlab evidence --verify <EVIDENCE_ID>

# Listar findings e gerar relatório técnico reproduzível em Markdown
bun packages/cli/src/index.ts cyberlab findings
bun packages/cli/src/index.ts cyberlab report > relatorio-cyberlab.md
```

### Modo 2 — Interface Interativa TUI + Agente de IA + Skills Nativas

```bash
# Autenticar seu provedor de modelo preferido (Anthropic, OpenAI, Google, OpenRouter, etc.)
bun packages/cli/src/index.ts auth login

# Iniciar a interface interativa do OpenCode V2 + CyberLab OS no projeto atual
bun packages/cli/src/index.ts
```

Dentro da sessão interativa, o agente já dispõe automaticamente:
- Das **6 Skills metodológicas** (`network-assessment`, `web-assessment`, `code-audit`, `mobile-forensics`, `reverse-engineering`, `evidence-review`).
- Das **5 Tools estruturadas do CyberLab** (`cyberlab_status`, `cyberlab_execute`, `cyberlab_evidence_list`, `cyberlab_finding_propose`, `cyberlab_partner_delegate`), todas passando obrigatoriamente pelo `PolicyEngine` e `ScopeController`.

### Modo 3 — Servidor API HTTP + Painel Visual Web/Desktop

```bash
# Iniciar o servidor OpenCode V2 + rotas /api/cyberlab/*
bun packages/cli/src/index.ts serve --hostname 127.0.0.1 --port 4096
```

- Endpoints REST disponíveis em `http://127.0.0.1:4096/api/cyberlab/*` (`status`, `capabilities`, `scope`, `executions`, `approvals`, `evidence`, `evidence/verify`, `findings`, `findings/review`, `report`).
- Na interface gráfica SolidJS (`packages/app` / `packages/gui-plugins/src/cyberlab`), abra o painel lateral **CyberLab** pelo menu da sessão ou pelo atalho **`Ctrl+Alt+L`** (`Ctrl+Cmd+L` no macOS) para disparar auditorias, verificar hashes `SHA-256` e confirmar/rejeitar findings.

---

## 4. Como Conectar os Agentes do Seu Runtime Externo (`chat.py`)

**Sim — exatamente como você usa um script conector para o Telegram, o CyberLab OS já inclui pronto o script conector oficial em Python: [`integrations/partners/chat_py_bridge.py`](integrations/partners/chat_py_bridge.py)!**

### Por que usar o conector `chat_py_bridge.py`?
1. Você **não precisa reescrever o seu `chat.py`** nem acoplar código interno dele ao TypeScript/Bun.
2. O `chat_py_bridge.py` sobe um micro-servidor local em `127.0.0.1:8788/cyberlab/partner` usando apenas biblioteca padrão do Python 3 (zero dependências extras).
3. Antes de enviar qualquer evidência ao seu `chat.py`, o CyberLab OS **redige automaticamente tokens, cookies, chaves privadas e credenciais**, assina o envelope com `HMAC-SHA256`, o `chat_py_bridge.py` valida a assinatura, chama o seu `chat.py` e devolve a resposta assinada para o CyberLab OS registrar como `unreviewed` (sem risco de execução arbitrária de comandos).

### Passo a passo em 2 terminais

**Terminal 1 — Subir a ponte conectada ao seu `chat.py`:**

Escolha um dos 3 modos conforme o seu `chat.py` recebe mensagens hoje:

```bash
export CYBERLAB_PARTNER_SECRET="minha-chave-hmac-super-forte-2026-cyberlab"

# Opção A (--mode arg): se você chama `python3 chat.py "mensagem"`
python3 integrations/partners/chat_py_bridge.py \
  --mode arg \
  --script /caminho/para/seu/chat.py \
  --port 8788

# Opção B (--mode stdin): se o seu chat.py lê a pergunta pelo input()/stdin
python3 integrations/partners/chat_py_bridge.py \
  --mode stdin \
  --script /caminho/para/seu/chat.py \
  --port 8788

# Opção C (--mode import): se você quer importar direto uma função Python do seu chat.py (ex.: def responder(msg): ...)
python3 integrations/partners/chat_py_bridge.py \
  --mode import \
  --callable /caminho/para/seu/chat.py:responder \
  --port 8788
```

**Terminal 2 — Delegar tarefa do CyberLab OS para o seu `chat.py`:**

```bash
export CYBERLAB_PARTNER_SECRET="minha-chave-hmac-super-forte-2026-cyberlab"
export CYBERLAB_PARTNER_URL="http://127.0.0.1:8788/cyberlab/partner"

# Via CLI direta (opcionalmente anexando IDs de evidências já coletadas com -e):
bun packages/cli/src/index.ts cyberlab partner \
  -o "Analise as evidências coletadas e sugira hipóteses de validação defensiva" \
  -e ev-1234
```
*(E nas sessões de IA do OpenCode V2, basta pedir ao assistente para consultar o parceiro `chat-py-agent`: ele usará automaticamente a tool `cyberlab_partner_delegate`!).*

---

## 5. Matriz Completa dos Softwares: Implementados vs. Plug-in / MCP vs. Parceiros

Conforme auditado em [`docs/TOOL_INVENTORY.md`](docs/TOOL_INVENTORY.md) e [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md):

### A. Já Implementados e Embutidos no Repositório (`approved_embed` — prontos para uso)
| Software / Componente | Licença | Status Atual no Repositório |
|---|---|---|
| **OpenCode V2 (`2.1.4`)** | `MIT` | **Implementado e fixado** (`packages/*`, TUI, CLI, Server, MCP client, GUI SolidJS) |
| **CyberLab Core (`@cyberlab/core`)** | `MIT` | **Implementado** (`PolicyEngine`, `ScopeController`, `ApprovalManager`, `EvidenceStore` SQLite+SHA256, `PartnerBridge`) |
| **Workspace Audit (`code-analysis.workspace-audit`)** | `MIT` | **Implementado** (`integrations/code-analysis/workspace-audit-executor.ts`) |
| **HTTP Security Inspector (`web-assessment.http-security-headers`)** | `MIT` | **Implementado** (`integrations/web-security/http-security-inspector.ts`) |
| **TCP Surface Probe (`network-assessment.tcp-surface-probe`)** | `MIT` | **Implementado** (`integrations/network-observation/tcp-banner-inspector.ts`) |
| **6 Skills Nativas (`SKILL.md`)** | `MIT` | **Implementadas** (`skills/{network-assessment,web-assessment,code-audit,mobile-forensics,reverse-engineering,evidence-review}`) |
| **Conector `chat_py_bridge.py`** | `MIT` | **Implementado** (`integrations/partners/chat_py_bridge.py` + `opencode cyberlab partner`) |

### B. Adicionados via Plug-in Externo ou Servidor MCP (`plugin_only` / `approved_internal_process`)
Ferramentas instaladas localmente pelo operador no Linux/WSL2 (nunca embutidas no código distribuído quando possuem licenças restritivas/copyleft):
| Software | Licença | Forma de Integração no CyberLab OS |
|---|---|---|
| **Nuclei** | `MIT` | Processo interno estruturado (`approved_internal_process`) ou servidor MCP local |
| **ffuf** | `MIT` | Processo interno estruturado (`approved_internal_process`) com aprovação humana obrigatória |
| **Ghidra (Headless)** | `Apache-2.0` | Processo interno / MCP local em Linux/WSL2 consumindo binários do workspace |
| **OWASP ZAP** | `Apache-2.0` | `plugin_only` / MCP via API daemon local do ZAP |
| **Nmap** | `NPSL-0.95` | **Exclusivamente `plugin_only` / MCP** chamando `/usr/bin/nmap` instalado pelo usuário (jamais embutido devido à licença NPSL) |
| **Wireshark / `tshark`** | `GPL-2.0+` | **Exclusivamente `plugin_only` / MCP** lendo arquivos `.pcap` via CLI externa sem linkar código GPL |
| **Burp Suite** | Proprietária | **Exclusivamente `plugin_only` / MCP** conectado à instância licenciada do analista |
| **MVT (Mobile Verification Toolkit)** | MVT License | **Exclusivamente `plugin_only`** para triagem forense autorizada de backups/logs móveis |

### C. Conectados via `PartnerBridge` (`partner` — Agentes Externos Isolados)
| Software / Agente | Licença | Como Conecta |
|---|---|---|
| **Seu Runtime Externo (`chat.py`)** | Própria | **Pronto** via `integrations/partners/chat_py_bridge.py` (`HMAC-SHA256`) |
| **Strix / CAI / PentestGPT / REA** | `Apache-2.0` / `MIT` | Como serviços parceiros isolados falando `cyberlab-partner` v1.0 |

### D. Bloqueados para Incorporação ou Camada de Sistema Operacional (`blocked` / `host_infra`)
- **Bloqueados para embed (`blocked`)**: **Shannon** (`AGPL-3.0`), **PentAGI** (`AGPL/GPL`), **HexStrike AI** (licença/segurança não auditadas) e **Metasploit Framework** (alto risco de exploração intrusiva + módulos com restrições comerciais).
- **Infraestrutura de host/operação do analista (fora da camada de plugins da aplicação)**: **Mullvad VPN**, **Tor**, **VeraCrypt**, **OnionShare**, **Signal** e **GrapheneOS** (operam no nível do sistema operacional/rede/dispositivo físico do operador).

---

## 6. O Que Mais Falta Implementar? (Status do Projeto)

- **Arquitetura base completa (Commits 01 a 11 + Ponte `chat.py` + CI)**: **100% implementada, testada e pronta para uso local.**
- **Evoluções opcionais sob demanda (Fase 2)**:
  1. **Merge do Pull Request #1 na `main`** no GitHub para tornar a branch principal padrão.
  2. **Adaptadores específicos `plugin_only` / MCP** para ferramentas de CLI que você já tenha instaladas na sua máquina Linux/WSL2 (por exemplo: `nmap`, `nuclei`, `ffuf`, `tshark` ou `ghidra-headless`), seguindo exatamente o mesmo contrato `CyberLabExecutor` já pronto em `integrations/`.

---

## Documentação Arquitetural Detalhada

- [`docs/UPSTREAM_AUDIT.md`](docs/UPSTREAM_AUDIT.md) — Auditoria linha a linha do OpenCode V2 (`2.1.4`).
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Arquitetura em 3 níveis e fluxo de execução/evidência.
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — Modelo de ameaças, anti-TOCTOU, redação e isolamento de parceiros.
- [`docs/TOOL_INVENTORY.md`](docs/TOOL_INVENTORY.md) — Triagem completa das 23 ferramentas analisadas.
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — Regras jurídicas para `approved_embed`, `plugin_only` e `blocked`.
