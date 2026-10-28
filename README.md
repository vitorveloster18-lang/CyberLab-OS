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

## 3. Como Usar o Sistema (Aplicação Única Unificada — OpenCode V2 + CyberLab OS)

Tudo vive em **uma única aplicação integrada** (construída diretamente sobre o OpenCode V2, na porta `4096`), sem separar o OpenCode de páginas externas de ferramentas:

```bash
# Inicia a aplicação completa (OpenCode V2 + Chat + Configurações + CyberLab OS + Gateway CDI) em http://localhost:4096
bun run start
```

Dentro dessa **única interface (`http://localhost:4096`)**, você tem acesso imediato a:
1. **Todas as funções nativas do OpenCode V2**: Sessões de Chat com IA, Provedores e Modelos (`Settings → Providers / Models`), Servidores MCP, Plugins, Atalhos, Árvore de Arquivos, Visualizador de Diffs e Terminal integrado.
2. **Configurações Nativas do CyberLab OS (`Settings → CyberLab OS` ou `/settings?tab=cyberlab`)**:
   - **Escopo & Proteção de Alvos**: toggle de alvos externos e cadastro visual de IPs, domínios, CIDRs e URLs autorizados.
   - **Agentes Externos CDI (`Salem`, `Kairós`, `Naia`, `CDI-04` — Portas `8788–8791`)**: botão de 1 clique **"Preset 4 CDIs"**, geração/edição do `CYBERLAB_PARTNER_SECRET`, botão **"Copiar Comandos PowerShell"**, teste de Ping e nível de autonomia de cada CDI.
   - **Motores Externos Opcionais**: status de `nmap`, `nuclei`, `ffuf`, `tshark` e botão de sincronização da pasta `.cyberlab/inbox`.
3. **Painel Lateral Limpo do CyberLab dentro de qualquer Sessão** (clique no botão **`CyberLab`** no topo da sessão, digite **`/cyberlab`** no chat, ou use `Ctrl+Alt+L`):
   - **Aba `Web & API`**: HTTP Repeater & Comparer, Proxy Local de Captura (`127.0.0.1:8899`), Scanner Web (Nativo, Nuclei ou ffuf) e Decoder/JWT/Entropia.
   - **Aba `Rede & Arquivos`**: Inspetor de Certificado TLS/X.509, Teste de Portas TCP / Nmap, Dissecador `.pcap` e Triagem Estática de Binários (`ELF`/`PE`) ou `.apk`.
   - **Aba `Agentes CDI`**: Despacho individual ou paralelo para Salem, Kairós, Naia e CDI-04, visualização das respostas e anexo em 1 clique direto no Chat da IA (**"Anexar ao Chat"**).
   - **Aba `Evidências`**: Aprovações humanas pendentes em 1 clique, cadeia de custódia `SHA-256`, registo de Findings e exportação de Relatório Markdown (`.md`).

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

## 4. Hub Multi-CDI & Bridge Bidirecional (`Salem`, `Kairós`, `Naia`, `CDI-04` — Portas `8788–8791`)

O CyberLab OS implementa um **Bridge Bidirecional v2.0** completo (`cyberlab/partners/cdi-hub.ts` + [`integrations/partners/chat_py_bridge.py`](integrations/partners/chat_py_bridge.py) + modelo em [`config/partners.example.json`](config/partners.example.json)):

### Respostas diretas para a configuração do seu CDI Runtime
1. **Como o CyberLab OS regista parceiros?**
   - Direto em **`Settings → CyberLab OS` (`http://localhost:4096/settings?tab=cyberlab`)**, pela CLI (`bun run cyberlab partner --preset-4`) ou editando `.cyberlab/partners.json` (modelo pronto em `config/partners.example.json`). Com 1 clique no botão **"Preset 4 CDIs (8788–8791)"**, o sistema regista automaticamente `salem` (`8788`), `kairos` (`8789`), `naia` (`8790`) e `cdi-4` (`8791`).
2. **O `CYBERLAB_PARTNER_SECRET` — o OS gera ou você define?**
   - **Suporta ambos!** Você pode clicar em **"Gerar Novo Secret (256-bit)"** (`bun run cyberlab partner --generate-secret`) para o CyberLab OS gerar e salvar um segredo criptográfico de 64 caracteres hex em `.cyberlab/partners.json`, **ou** definir o seu próprio segredo (`bun run cyberlab partner --set-secret "seu-segredo..."` ou variável `CYBERLAB_PARTNER_SECRET`). Todos os 4 CDIs podem compartilhar o mesmo `CYBERLAB_PARTNER_SECRET` (ou ter `secretOverride` individual).
3. **Os CDIs são chamados em paralelo ou 1 por tarefa?**
   - **Suporta ambos nativamente!**
     - **Especialista único**: escolher apenas 1 CDI (ex.: `--partner-id salem`).
     - **Colaboração em paralelo (`Promise.all`)**: selecionar múltiplos CDIs na Aba 8 ou rodar `--partners salem,kairos,naia` (ou `partnerIds: ["salem", "kairos", "naia"]` na tool de IA `cyberlab_partner_delegate`).

### O que os CDIs agora fazem autonomamente de dentro do Python (`CyberLabOSClient`)
Importando `CyberLabOSClient` de `integrations/partners/chat_py_bridge.py` dentro do seu `chat.py` / `process_message()`, qualquer CDI pode enviar mensagens assinadas **do CDI → para o CyberLab OS** (`POST http://127.0.0.1:4096/api/cyberlab/partner-gateway`):

```python
from chat_py_bridge import CyberLabOSClient, build_cyberlab_cdi_tools

# Lê automaticamente CYBERLAB_PARTNER_ID, CYBERLAB_PARTNER_SECRET e CYBERLAB_CALLBACK_URL
cyberlab = CyberLabOSClient.from_env(default_partner_id="salem")

# 1. Ver o estado dos projetos em tempo real (escopo, capabilities, findings, aprovações)
estado = cyberlab.get_project_state()

# 2. Aceder diretamente às evidências e ficheiros em escopo do OS (segredos já saem redigidos)
evidencias = cyberlab.list_evidence()
conteudo_ev = cyberlab.read_evidence(evidencias[0]["evidenceId"])
ficheiro_log = cyberlab.read_workspace_file("logs/security.log")

# 3. Criar artifacts SHA-256 e findings diretamente no CyberLab OS
artifact = cyberlab.create_artifact(
    title="Parse Estruturado de Log pelo Salem",
    content={"alertas_criticos": 3, "cve": "CVE-2024-9999"},
    kind="json",
)
cyberlab.propose_finding(
    title="CVE-2024-9999 correlacionada pelo Salem",
    description="Identificada a partir do log e confirmada via pesquisa CVE.",
    severity="high",
    confidence=0.85,
    evidence_ids=[artifact["evidenceId"]],
)

# 4. Iniciar ações/ferramentas no CyberLab OS por conta própria!
# - Capabilities read_only executam na hora; capabilities ativas entram na fila de aprovação humana.
execucao = cyberlab.initiate_action("code-analysis.workspace-audit", {"maxFiles": 25})

# Opcional: obter lista pronta de tools para plugar direto no loop de tools do chat.py:
tools_cyberlab = build_cyberlab_cdi_tools(cyberlab)
```

### Subindo as pontes dos 4 CDIs (Portas `8788–8791`) e despachando em paralelo

```bash
# Gerar segredo + registar os 4 CDIs (Salem 8788, Kairós 8789, Naia 8790, CDI-04 8791):
bun run cyberlab partner --generate-secret --preset-4

# Em cada CDI (ex.: --mode import apontando para process_message do seu chat.py):
python3 integrations/partners/chat_py_bridge.py --partner-id salem  --port 8788 --mode import --callable /caminho/salem/chat.py:process_message
python3 integrations/partners/chat_py_bridge.py --partner-id kairos --port 8789 --mode import --callable /caminho/kairos/chat.py:process_message
python3 integrations/partners/chat_py_bridge.py --partner-id naia   --port 8790 --mode import --callable /caminho/naia/chat.py:process_message
python3 integrations/partners/chat_py_bridge.py --partner-id cdi-4  --port 8791 --mode import --callable /caminho/cdi4/chat.py:process_message

# Chamar apenas 1 especialista (ex.: Salem):
bun run cyberlab partner --partner-id salem -o "Analisar este log de segurança"

# Ou chamar Kairós + Naia + Salem EM PARALELO na mesma tarefa:
bun run cyberlab partner --partners salem,kairos,naia -o "Analisar arquitetura, logs e inteligência de ameaças em paralelo"
```

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
