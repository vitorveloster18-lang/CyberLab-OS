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
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_GENERATIVE_AI_API_KEY` / `OPENROUTER_API_KEY` | Chaves de API dos modelos LLM usados nas sessões do OpenCode V2 (ou faça login interativo com `bun run dev auth login`) | — |
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

## 3. Como Usar o Sistema (Security Studio Visual + CLI + TUI + IA)

### Modo Principal — Security Studio Visual Completo (7 Abas Manuais Interativas, sem sair do CyberLab OS)

Você **não precisa sair do CyberLab OS** para abrir a UI do Burp Suite, Wireshark, Zenmap ou digitar JSON cru na mão. Todas as ferramentas — **tanto os motores internos `MIT` quanto os binários externos (`nmap`, `nuclei`, `ffuf`, `tshark`)** — possuem **controles visuais dedicados, presets, seletores, tabelas e comparadores** dentro do próprio CyberLab OS:

1. **Aba `1. Proxy & Repeater`**:
   - **Proxy HTTP Local de Captura (`127.0.0.1:8899`)** com botão *Start/Stop*, filtro de escopo (`ScopeController`), bloqueio anti-SSRF (`169.254.169.254`), tabela de histórico ao vivo e botões de 1 clique **`→ Repeater`**, **`→ Baseline`** e **`Save SHA-256`**.
   - **HTTP Repeater & Comparer** estilo Burp/OpenTRAP: seletor de método (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`/`HEAD`/`OPTIONS`), editor chave-valor de cabeçalhos com checkboxes e presets (`+ JSON`, `+ Bearer`, `+ XFF`), editor de body e diff visual contra URL de baseline.
2. **Aba `2. Decoder & JWT`**: pipeline visual encadeado em 1 clique (`URL`, `Base64`, `Base64URL`, `Hex`, `HTML`, `SHA-256`), auditoria de segurança JWT (`alg:none`, ausência de `exp`, injeção `jku`/`x5u`) e Sequencer de entropia de tokens de sessão.
3. **Aba `3. Web Scanner & Fuzzer`**: formulários visuais, sliders de concorrência/rate-limit e tags para disparar tanto o **Scanner Nativo `MIT`** e o **Inspetor de Headers/CORS** quanto **`nuclei`** e **`ffuf`** externos.
4. **Aba `4. Network & TLS`**: perfis rápidos de portas (*Web*, *Infra*, *Database*), toggle `-sV`, campo TLS SNI e visualização estruturada de certificados `X.509` e banners TCP/Nmap.
5. **Aba `5. Packets (.pcap)`**: seletor visual entre o dissecador nativo Pure-TS e o `tshark` (Wireshark CLI), slider de pacotes e visualização de fluxos, queries DNS, SNI TLS e requisições HTTP.
6. **Aba `6. Reverse & Mobile`**: controles visuais para triagem estática de binários `ELF`/`PE`/`Mach-O` (NX, PIE/ASLR, Canary, entropia de packers, imports suspeitos) e pacotes mobile `.apk`/`.ipa`/backups (permissões críticas e caça a domínios IoC).
7. **Aba `7. Scope & Custody`**: construtor visual de regras de escopo (`ip`, `cidr`, `domain`, `url_origin`, `workspace_path`), fila de aprovações humanas, *Kill-Switch* em tempo real de processos, radar de ferramentas externas, `.cyberlab/inbox/`, inspetor de evidências `SHA-256` e gerador de relatório Markdown.

Você pode abrir o **Security Studio Visual** de duas formas:

```bash
# Opção A: Workbench Visual em Tela Cheia no navegador (porta 4180)
bun run cyberlab:studio

# Ou com laboratório local de demonstração integrado (alvo HTTP + TLS + .pcap + .elf + .apk prontos para testar em 1 clique):
bun run cyberlab studio --demo-lab --port 4180
```

```bash
# Opção B: Integrado dentro do OpenCode V2 Web/Desktop (atalho Ctrl+Alt+L / Ctrl+Cmd+L)
bun run dev serve --hostname 127.0.0.1 --port 4096
```

### Modo CLI — Linha de Comando Direta (`cyberlab` CLI)

Você pode executar auditorias, verificar integridade `SHA-256` e gerar relatórios Markdown sem sequer precisar de chave de IA:

```bash
# Ver status do workspace, plataforma (Linux/WSL2), escopo ativo, skills e as 10 capacidades nativas
bun run cyberlab status

# Listar todas as 10 capacidades locais registradas e seus níveis de risco
bun run cyberlab capabilities

# 1) Auditoria estática somente leitura de código/segredos no workspace
bun run cyberlab run \
  -c code-analysis.workspace-audit \
  -i '{"subpath":"cyberlab","maxFiles":50}'

# 2) HTTP Repeater & Comparer nativo (estilo OpenTRAP/Burp) com redação automática de segredos
bun run cyberlab run \
  -c web-assessment.http-repeater \
  -i '{"url":"http://127.0.0.1:8080/api/admin","baselineUrl":"http://127.0.0.1:8080/api/guest"}'

# 3) Decoder encadeado + Inspetor JWT + Sequencer de entropia de tokens
bun run cyberlab run \
  -c web-assessment.decoder-sequencer \
  -i '{"tokenSamples":["a9f18c7d4e20b11983fa9012bc7788e1","f4029d81bc77201948ea661209bc4410"]}'

# 4) Scanner de superfície web / templates (estilo Nuclei/ffuf) + TLS/X.509 + PCAP + Binários + APK
bun run cyberlab run -c web-assessment.surface-discovery -i '{"baseUrl":"http://127.0.0.1:8080"}'
bun run cyberlab run -c network-assessment.tls-inspector -i '{"host":"127.0.0.1","port":8443}'
bun run cyberlab run -c network-assessment.pcap-analyzer -i '{"pcapPath":"captura.pcap"}'
bun run cyberlab run -c reverse-engineering.binary-triage -i '{"binaryPath":"amostra.elf"}'
bun run cyberlab run -c mobile-forensics.artifact-triage -i '{"artifactPath":"app.apk"}'

# Listar evidências gravadas e verificar integridade criptográfica SHA-256 de uma evidência
bun run cyberlab evidence
bun run cyberlab evidence --verify <EVIDENCE_ID>

# Listar findings e gerar relatório técnico reproduzível em Markdown
bun run cyberlab findings
bun run cyberlab report > relatorio-cyberlab.md
```

### Modo 2 — Interface Interativa TUI + Agente de IA + Skills Nativas

```bash
# Autenticar seu provedor de modelo preferido (Anthropic, OpenAI, Google, OpenRouter, etc.)
bun run dev auth login

# Iniciar a interface interativa do OpenCode V2 + CyberLab OS no projeto atual
bun run dev
```

Dentro da sessão interativa, o agente já dispõe automaticamente:
- Das **6 Skills metodológicas** (`network-assessment`, `web-assessment`, `code-audit`, `mobile-forensics`, `reverse-engineering`, `evidence-review`).
- Das **5 Tools estruturadas do CyberLab** (`cyberlab_status`, `cyberlab_execute`, `cyberlab_evidence_list`, `cyberlab_finding_propose`, `cyberlab_partner_delegate`), todas passando obrigatoriamente pelo `PolicyEngine` e `ScopeController`.

### Modo 3 — Servidor API HTTP + Painel Visual Web/Desktop

```bash
# Iniciar o servidor OpenCode V2 + rotas /api/cyberlab/*
bun run dev serve --hostname 127.0.0.1 --port 4096
```

- Endpoints REST disponíveis em `http://127.0.0.1:4096/api/cyberlab/*` (`status`, `capabilities`, `scope`, `executions`, `executions/approve`, `executions/cancel`, `approvals`, `evidence`, `evidence/verify`, `findings`, `findings/review`, `report`, `external/tools`, `external/ingest`, `external/sync`).
- Na interface gráfica SolidJS (`packages/app` / `packages/gui-plugins/src/cyberlab`), abra o **Cockpit Unificado CyberLab** pelo menu da sessão ou pelo atalho **`Ctrl+Alt+L`** (`Ctrl+Cmd+L` no macOS) para controlar de um único lugar: **escopo ativo, aprovações pendentes, disparador unificado (capacidades internas + plugins externos), botão Kill/Cancel em tempo real, radar de ferramentas externas, sincronização da `.cyberlab/inbox`, ingestão de sessões manuais externas, verificação `SHA-256` e revisão de findings**.

---

### Modo 4 — Plano de Controle Único para Ferramentas e Ações Externas (`cyberlab external`)

Mesmo quando um motor roda **fora** do CyberLab OS (via binário externo como `nmap`, `nuclei`, `ffuf`, `tshark`, `mvt-android`, `ghidra`, desktop GUI como **OpenTRAP**/**Burp**/**Wireshark**, ou servidor **MCP**), **todos os controles de escopo, supervisão, kill-switch e custódia `SHA-256` ficam centralizados em um só lugar** (`cyberlab/external/control-plane.ts`):

```bash
# 1) Radar de Ferramentas Externas: verifica o que está instalado em .cyberlab/bin, PATH ou config/external-tools.json
bun run cyberlab external

# 2) Disparar ferramentas externas governadas direto pelo CyberLab OS (shell=false + ScopeController + Kill-Switch)
bun run cyberlab run -c external.nmap-service-probe -i '{"host":"127.0.0.1","ports":"80,443,8080","serviceVersion":true}'
bun run cyberlab run -c external.nuclei-template-scan -i '{"url":"http://127.0.0.1:8080","rateLimit":10}'
bun run cyberlab run -c external.ffuf-endpoint-probe -i '{"baseUrl":"http://127.0.0.1:8080","wordlistPath":"wordlist.txt"}'
bun run cyberlab run -c external.tshark-pcap-summary -i '{"pcapPath":"captura.pcap","maxPackets":250}'

# 3) Wrapper Supervisionado (você roda manualmente no terminal, mas o CyberLab valida o escopo ANTES de abrir o processo e grava SHA-256 com redação de segredos)
bun run cyberlab external \
  --action wrap \
  --tool nmap \
  --target 127.0.0.1 \
  --binary nmap \
  --args '["-Pn","-sV","-p","8080","127.0.0.1"]'

# 4) Drop-Folder Universal (.cyberlab/inbox/) e Ingestão Manual (OpenTRAP, Burp, Wireshark, Ghidra, MVT):
# Basta salvar qualquer exportação externa em .cyberlab/inbox/ e sincronizar com 1 comando (ou botão no painel GUI):
bun run cyberlab external --action sync

# Ou ingerir um arquivo específico auditando automaticamente se o alvo estava dentro do ProjectScope:
bun run cyberlab external \
  --action ingest \
  --tool opentrap \
  --target http://127.0.0.1:8080/login \
  --file sessao-opentrap.http
```
*(Na sessão interativa de IA, o assistente também enxerga esse mesmo plano de controle pela tool `cyberlab_external_control`, mantendo você e a IA sincronizados sobre o mesmo banco de evidências e o mesmo escopo).*

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
bun run cyberlab partner \
  -o "Analise as evidências coletadas e sugira hipóteses de validação defensiva" \
  -e ev-1234
```
*(E nas sessões de IA do OpenCode V2, basta pedir ao assistente para consultar o parceiro `chat-py-agent`: ele usará automaticamente a tool `cyberlab_partner_delegate`!).*

---

## 5. Matriz Completa dos Softwares: Implementados vs. Plug-in / MCP vs. Parceiros

Conforme auditado em [`docs/TOOL_INVENTORY.md`](docs/TOOL_INVENTORY.md) e [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md):

### A. Suíte Nativa Embutida Diretamente no Projeto (`approved_embed` — 100% `MIT`, zero dependências externas)
Para máxima produtividade e integração unificada com `PolicyEngine`, `ScopeController` e `EvidenceStore` (`SHA-256`), o CyberLab OS traz **10 capacidades nativas prontas para uso imediato dentro de `integrations/`**:

| Capacidade (`capabilityId`) | Substituto / Inspiração Open-Source | Arquivo no Repositório (`MIT`) |
|---|---|---|
| **`code-analysis.workspace-audit`** | Auditoria estática de segredos e configs | `integrations/code-analysis/workspace-audit-executor.ts` |
| **`web-assessment.http-security-headers`** | Inspetor passivo HSTS/CSP/CORS/Cookies | `integrations/web-security/http-security-inspector.ts` |
| **`web-assessment.http-repeater`** | **OpenTRAP / Burp Repeater + Comparer** | `integrations/web-security/http-repeater-comparer.ts` |
| **`web-assessment.decoder-sequencer`** | **OpenTRAP / Burp Decoder + JWT + Sequencer** | `integrations/web-security/decoder-sequencer.ts` |
| **`web-assessment.surface-discovery`** | **Nuclei / ffuf** (templates anti-soft-404) | `integrations/web-security/surface-discovery.ts` |
| **`network-assessment.tcp-surface-probe`** | **Nmap** (sonda TCP controlada + banners) | `integrations/network-observation/tcp-banner-inspector.ts` |
| **`network-assessment.tls-inspector`** | **testssl / sslscan** (TLS + cadeia X.509/SAN) | `integrations/network-observation/tls-certificate-inspector.ts` |
| **`network-assessment.pcap-analyzer`** | **Wireshark / `tshark`** (parser binário `.pcap`) | `integrations/network-observation/pcap-packet-analyzer.ts` |
| **`reverse-engineering.binary-triage`** | **REA / radare2** (`ELF`/`PE`/`Mach-O` + entropia) | `integrations/reverse-forensics/binary-static-triage.ts` |
| **`mobile-forensics.artifact-triage`** | **MVT / MobSF** (`.apk`/`.ipa`/backups + IoCs) | `integrations/reverse-forensics/mobile-artifact-triage.ts` |

Além dos 10 executores nativos, também já estão embutidos:
- **OpenCode V2 (`2.1.4`, `MIT`)**: TUI, CLI, Server Hono, MCP Client e GUI SolidJS (`Ctrl+Alt+L`).
- **6 Skills Nativas (`SKILL.md`)** + **Conector Python `integrations/partners/chat_py_bridge.py`** (`HMAC-SHA256`).

### B. Bootstrap Local Autossuficiente (`.cyberlab/bin`) + Plug-ins / MCP (`plugin_only`)
Quando você também quiser motores binários pesados rodando localmente **dentro da própria pasta do seu projeto** (em `.cyberlab/bin/`, ignorado pelo Git para manter o repositório enxuto e 100% `MIT`), basta rodar:

```bash
# Baixa binários standalone MIT (Nuclei + ffuf) direto para .cyberlab/bin/
./script/bootstrap-local-tools.sh

# Opcional: inclui também o OpenTRAP Desktop AppImage (Java 17 + ZAP, AGPL-3.0) em Linux x86_64
./script/bootstrap-local-tools.sh --with-agpl
```

| Software | Licença | Como Opera com o CyberLab OS |
|---|---|---|
| **OpenTRAP (`opentrap/opentrap`)** | `AGPL-3.0` | Auditado: desktop Java 17 sobre OWASP ZAP sem IA. Como é `AGPL-3.0`, seu código Java não é copiado para o repo `MIT`; você já tem Repeater/Comparer/Decoder/Sequencer nativos embutidos e pode baixar o `.AppImage` em `.cyberlab/bin/` com `--with-agpl` |
| **Nuclei / ffuf** | `MIT` | Já contam com scanner nativo leve (`web-assessment.surface-discovery`) + download automático dos binários Go completos em `.cyberlab/bin/` |
| **Ghidra (Headless)** | `Apache-2.0` | Complementa o `reverse-engineering.binary-triage` nativo para descompilação profunda via Linux/WSL2 |
| **OWASP ZAP** | `Apache-2.0` | `plugin_only` / MCP via API daemon local do ZAP |
| **Nmap** | `NPSL-0.95` | **Exclusivamente `plugin_only` / MCP** chamando `/usr/bin/nmap` (complementando `tcp-surface-probe` e `tls-inspector` nativos) |
| **Wireshark / `tshark`** | `GPL-2.0+` | **Exclusivamente `plugin_only` / MCP** (enquanto `network-assessment.pcap-analyzer` já analisa `.pcap` nativamente em TypeScript `MIT`) |
| **Burp Suite** | Proprietária | **Exclusivamente `plugin_only` / MCP** (substituído nativamente no dia a dia por `http-repeater` e `decoder-sequencer`) |
| **MVT (Mobile Verification Toolkit)** | MVT License | **Exclusivamente `plugin_only`** (substituído nativamente na triagem inicial por `mobile-forensics.artifact-triage`) |

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
