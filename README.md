# CyberLab OS — Investigative Security & Real Arsenal Edition (v6.5)

Plataforma unificada de **Engenharia de Segurança Ofensiva/Defensiva, Investigação Orientada por Hipóteses, Bug Bounty Autorizado, Engenharia Reversa, DFIR e Laboratórios de Treinamento**, construída sobre o **OpenCode V2 (`2.1.4`)** e projetada nativamente para **Windows 11 (PowerShell) + WSL2 (`kali-linux` 2026.x)** ou Linux nativo.

> **Filosofia Central (v6.2)**: O CyberLab OS combina em **uma única janela (`http://127.0.0.1:4096`)**:
> 1. **Investigative Security Orchestrator (`Orchestrator`)**: agente principal em `pt-BR` orientado por hipóteses científicas (Ciclo **Fases A–I**), validação rigorosa de evidências e **6 subagentes especializados sob demanda** com guardrails rígidos de profundidade (`1`), concorrência (`3`) e orçamento por sessão (`12`).
> 2. **Biblioteca Curada `CyberLab-Knowledge/` no Cofre Obsidian + Memória Investigativa Isolada**: **35** documentos técnicos revisados com metadados verificáveis (fontes primárias, versão, data de revisão, limitações e grafo `[[WikiLinks]]`) servidos via MCP com separação epistemológica estrita em **3 camadas** (Conhecimento Curado vs. Contexto da Sessão vs. Conhecimento Externo).
> 3. **Hub MCP Unificado (`cyberlab-arsenal`) + 48 Slots Oficiais de Ferramentas Reais**: 1 único processo `stdio` ultraleve conectando **45 ferramentas com `🟢 MCP`** (incluindo pontes ao vivo para **Burp Suite `:9876` SSE**, **GhidraMCP `:8080`** e **JADX-AI-MCP `:8650`**), **Cofre Obsidian Flutuante (`Alt+N`)**, **Topo Retrátil (`28px`)**, **4 Parceiros Cognitivos CDI (`8788–8791`)** e **5 Laboratórios Internos de Treino**.

---

## Sumário

1. [Inicialização Rápida (Windows PowerShell + WSL2 Kali)](#1-inicialização-rápida-windows-powershell--wsl2-kali)
2. [Primeira Tarefa Recomendada (Calibração do Orquestrador)](#2-primeira-tarefa-recomendada-calibração-do-orquestrador)
3. [Investigative Security Orchestrator & 6 Subagentes Especializados (v6.2)](#3-investigative-security-orchestrator--6-subagentes-especializados-v62)
4. [Biblioteca Curada `CyberLab-Knowledge/` & Cofre Obsidian (`Alt+N`)](#4-biblioteca-curada-cyberlab-knowledge--cofre-obsidian-altn)
5. [Hub MCP Unificado (`cyberlab-arsenal`), Pontes GUI em Tempo Real & Modelos Gratuitos](#5-hub-mcp-unificado-cyberlab-arsenal-pontes-gui-em-tempo-real--modelos-gratuitos)
6. [Layout Antigravity de 3 Colunas, Topo Retrátil (`28px`) & `noVNC` Nitidez Real](#6-layout-antigravity-de-3-colunas-topo-retrátil-28px--novnc-nitidez-real)
7. [Catálogo Completo dos 48 Slots Oficiais + Slots Personalizados](#7-catálogo-completo-dos-48-slots-oficiais--slots-personalizados)
8. [Laboratórios de Treino Prontos para Investigação (v6.4–v6.5)](#8-laboratórios-de-treino-prontos-para-investigação-v64v65)
---

## 8. Laboratórios de Treino Prontos para Investigação (v6.4–v6.5)

A Fase A de calibração apontou que **nenhuma capacidade havia sido validada com evidência real** porque o
servidor do lab estava inativo e a memória investigativa estava vazia. Agora o laboratório sobe **com as
Fases B (Modelagem), D (Hipóteses) e F (Experimentação) já prontas**:

```powershell
# TUDO EM 1 UNICO TERMINAL (--daemon deixa o servidor vivo em segundo plano)
bun run cyberlab lab start lab-owasp-api-bola --daemon
bun run cyberlab lab seed   lab-owasp-api-bola
bun run cyberlab lab model  lab-owasp-api-bola
bun run cyberlab lab status lab-owasp-api-bola

# Para encerrar (funciona de qualquer terminal)
bun run cyberlab lab stop   lab-owasp-api-bola
```

> ℹ️ **Portas**: `http://127.0.0.1:19081` = **alvo de treino** (API REST, sem interface — é isso que você
> ataca com Burp/curl/scanners). `http://127.0.0.1:4096` = **interface do CyberLab OS** (3 colunas), aberta
> por `bun run cyberlab`. Abrir a `/` do lab no navegador mostra uma página de orientação com os controles,
> os endpoints e o comando de teste; o JSON de diagnóstico fica em `/health`.

> ✅ **Se aparecer "JÁ ESTÁ NO AR", está tudo certo** — não é erro: o lab já está rodando e
> respondendo. O comando mostra o painel e os próximos passos. Para recomeçar do zero use
> `bun run cyberlab lab restart lab-owasp-api-bola`.

> ⚠️ **Sem `--daemon` o servidor morre com o terminal.** O comando `start` sem a flag mantém o processo
> em primeiro plano e exibe `Servidor ativo neste processo. Pressione Ctrl+C para encerrar.` — ao
> pressionar `Ctrl+C` (ou fechar a janela) o lab é desligado. `seed` e `model` continuam funcionando
> (eles só leem o Kit em disco), mas o alvo fica fora do ar para execução de experimentos.

Também é possível subir junto da interface: `bun run cyberlab --rebuild --lab lab-owasp-api-bola`.

### 8.1 Arquivos gerados em `<labs>/lab-owasp-api-bola/`

| Arquivo | Conteúdo |
|---|---|
| `LAB_SYSTEM_MODEL.md` + `lab-system-model.json` | **Fase B** — componentes, tecnologias, fluxos de dados, fronteiras de confiança, identidades (A/B/admin/anon) e invariante de autorização por endpoint |
| `HYPOTHESES.md` + `lab-hypotheses.json` | **Fase D** — H1–H4 com os 6 elementos obrigatórios (esperado, suspeito, pressuposto frágil, racional técnico, evidência necessária, explicações alternativas) |
| `EXPERIMENTS.md` + `lab-experiments.json` | **Fase F** — 6 experimentos com **uma única variável** cada, critério de parada, comandos `curl` prontos e matriz de remediação |
| `investigation-memory-seed.json` | Patch pronto para `investigation_memory_update` (missão + escopo em loopback + modelo + hipóteses + referências externas) |

### 8.2 Matriz de Remediação comprovada (Fase G)

| Hipótese | Comando PoC | Controle OFF | Controle ON |
|---|---|---|---|
| H1 BOLA | `GET /api/v1/accounts/1002` c/ token A | 200 + `bob@corp.lab` + `bolaFlag` | **403** |
| H2 JWT `alg:none` | `GET /api/v1/admin/debug` c/ JWT forjado | 200 + flag admin | **401** |
| H3 Erro SQL | `GET /api/v1/search?q=%27` | 500 + `SQLITE_ERROR` | **200** sem erro |
| H4 Headers | `curl -D -` em qualquer rota | 0 headers | **CSP + HSTS + nosniff + XFO** |

> ⚠️ **Porta desatualizada**: notas antigas do cofre citam `127.0.0.1:4101`. A porta real é resolvida
> dinamicamente (padrão `19081`) — confirme sempre com `bun run cyberlab lab status`.

---

9. [Os 4 Parceiros Cognitivos CDI (`8788–8791`) & 5 Laboratórios de Treino](#8-os-4-parceiros-cognitivos-cdi-87888791--5-laboratórios-de-treino)
10. [Governança de Escopo Bug Bounty, Custódia `SHA-256` & Segurança Anti-Prompt-Injection](#9-governança-de-escopo-bug-bounty-custódia-sha-256--segurança-anti-prompt-injection)
11. [Histórico Completo de Versões (`v1.0` → `v6.5`), Verificação CI & Licenciamento MIT](#11-histórico-completo-de-versões-v10--v65-verificação-ci--licenciamento-mit)

---

### 8.3 Evidência arquivada com SHA-256 (`lab evidence`)

```powershell
bun run cyberlab lab evidence lab-owasp-api-bola
bun run cyberlab lab evidence lab-owasp-api-bola --out evidence\rodada-01
```

Reexecuta **E1–E7** contra um servidor real e grava, para cada requisição, um `.txt` com o
comando, a requisição e a resposta completa — mais `manifest.json`, `REPORT.md` e `SEAL.txt`.

| Arquivo | Papel |
| --- | --- |
| `E1-01-...txt` … `E7-04-...txt` | 19 pares comando/resposta + a expectativa declarada antes de rodar |
| `manifest.json` | metadados de todas as requisições + SHA-256 de cada `.txt` |
| `SEAL.txt` | SHA-256 do `manifest.json` (selo do lote) |
| `REPORT.md` | veredito por hipótese com o critério usado |

Conferência (o selo bate com o arquivo gravado — sem paradoxo ovo/galinha):

```powershell
(Get-FileHash .\manifest.json -Algorithm SHA256).Hash.ToLower()   # deve igualar SEAL.txt
```

> O lab **volta ao estado vulnerável** ao final (E7 comprova a restauração), então o treino continua.

### 8.4 Alvo externo autorizado (`lab targets` / `lab scope`)

```powershell
bun run cyberlab lab targets                      # lista alvos com AUTORIZAÇÃO declarada
bun run cyberlab lab scope portswigger-wsa        # grava SCOPE.md + RULES-OF-ENGAGEMENT.md
```

Perfil disponível: **`portswigger-wsa`** (PortSwigger Web Security Academy) — gratuita, mantida
pelos autores do Burp Suite, e **autoriza ataques somente contra as instâncias de laboratório que
ela cria para você**. Hosts permitidos: `*.web-security-academy.net` e
`*.h1-web-security-academy.net`.

A ponte com o método já calibrado no laboratório local:

| Hipótese local | Tópico equivalente na Academy |
| --- | --- |
| H1 — BOLA/IDOR | Access control vulnerabilities |
| H2 — JWT `alg:none` | JWT attacks |
| H3 — erro SQL com estrutura da consulta | SQL injection |
| H4 — headers de segurança ausentes | transversal (melhor observado no lab local) |

Regras que o `RULES-OF-ENGAGEMENT.md` deixa explícitas: **não** varrer o domínio da plataforma
(só o hostname do SEU laboratório está no escopo), **não** reutilizar a técnica em site vivo, sem
DoS/força bruta volumosa. E uma limitação honesta: laboratórios que dependem de interação fora de
banda exigem Burp Collaborator (Burp Pro) e o firewall de saída do laboratório bloqueia servidores
externos arbitrários — sem licença, marque `FORA DE ESCOPO` em vez de tentar um substituto.

### 8.5 `cyberlab up` — atualizar e subir tudo com 1 comando

```powershell
bun run cyberlab up
```

1. `git pull --ff-only` (pule com `--no-pull`; não roda se houver alterações locais)
2. `bun install` se `node_modules` estiver ausente (`--install` força, `--no-install` nunca roda)
3. sobe o **laboratório em segundo plano** (`--daemon` — sobrevive ao fechar o terminal)
4. sobe a **interface** em primeiro plano em `http://127.0.0.1:4096`

Opções: `--lab <labId>`, `--port <n>` (interface), `--lab-port <n>` (alvo), `--no-open`.
`Ctrl+C` derruba **só a interface**; o laboratório continua no ar até `lab stop`.

## 1. Inicialização Rápida (Windows PowerShell + WSL2 Kali)

### 1.1 Iniciar o CyberLab OS Unificado (1 Único Comando)

No **Windows PowerShell**, dentro da pasta do repositório:

```powershell
bun run cyberlab up          # atualiza (git pull) + sobe interface E laboratório
```

Equivalente em passos explícitos, se preferir ver cada etapa:

```powershell
git pull
bun run cyberlab --rebuild
```

- Na inicialização, o lançador `script/start-cyberlab.ts` automaticamente:
  1. Semeia de forma idempotente os **36 documentos curados** de `<workspace>/vault/CyberLab-Knowledge/` sem sobrescrever notas existentes;
  2. Consolida qualquer entrada legada de `opencode.json` em **1 único servidor MCP unificado** (`"cyberlab-arsenal"`, `--slot __hub__`);
  3. Define `"default_agent": "cyberlab-orchestrator"` caso você ainda não tenha personalizado seu agente padrão;
  4. Recompila o frontend (`--rebuild`) e sobe o servidor unificado em **`http://127.0.0.1:4096`**.

### 1.2 Instalação Automática de Todas as Ferramentas Reais no Kali WSL2

Você pode instalar qualquer ferramenta individualmente clicando em **`⬇ Instalar Automaticamente`** dentro do próprio CyberLab OS, ou provisionar o arsenal completo de uma vez pelo **Windows PowerShell** (removendo `\r` para compatibilidade total com `bash` no WSL2):

```powershell
$installCmd = @'
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo apt-get install -y -qq xvfb x11vnc websockify novnc openbox xterm dbus-x11 libgtk-3-0 libgbm1 libnss3 libasound2t64 kali-desktop-xfce nmap ncat sqlmap ffuf dirsearch wireshark tshark mitmproxy zaproxy ghidra jadx rizin python3-frida apktool tor torsocks onionshare-cli gitleaks metasploit-framework impacket-scripts hashcat john netexec curl unzip jq python3-pip python3-venv pipx golang-go cargo
'@.Replace("`r", "")
$installCmd | wsl -d kali-linux -u root -- bash -s
```

---

## 2. Primeira Tarefa Recomendada (Calibração do Orquestrador)

Assim que abrir o CyberLab OS em **`http://127.0.0.1:4096`**, com o agente **`Orchestrator`** selecionado no painel direito, envie este prompt inicial para calibrar o inventário real de ferramentas e conhecimento do seu ambiente sem tocar em nenhum alvo externo:

> **Prompt inicial recomendado:**
> *"Mapeie o conhecimento técnico e as ferramentas MCP disponíveis. Identifique quais capacidades estão comprovadas, quais ainda não foram validadas e quais lacunas de conhecimento limitam uma investigação orientada por hipóteses."*

O `Orchestrator` irá:
1. Consultar o catálogo curado em `CyberLab-Knowledge/` (`search_knowledge`, `read_document("00-Index")`, `read_document("tools/mcp-tool-catalog")`);
2. Auditar em tempo real todas as ferramentas conectadas via `arsenal_mcp_status` (distinguindo binários instalados no Windows/WSL2, servidores GUI ativos em `:9876`/`:8080`/`:8650` e ferramentas ainda não instaladas ou desconectadas);
3. Entregar um diagnóstico estruturado separando **capacidades comprovadas**, **capacidades pendentes de validação** e **lacunas de conhecimento**, registrando o baseline na memória investigativa (`investigation_memory_update`).

---

## 3. Investigative Security Orchestrator & 6 Subagentes Especializados (v6.2)

### 3.1 Agente Principal: `Orchestrator` (`cyberlab-orchestrator`)

Registrado nativamente no núcleo do OpenCode V2 (`packages/core/src/plugin/agent.ts`), o **Investigative Security Orchestrator** substitui a execução cega de scanners por engenharia investigativa em português brasileiro:

- **10 Princípios Fundamentais**: compreender antes de testar; formular uma pergunta investigativa antes de escolher uma ferramenta; modelar sistemas como componentes interdependentes; mapear fronteiras de confiança e transformações de dados; diferenciar fatos observados, hipóteses, inferências e incertezas; preferir experimentos diferenciadores; tratar saídas de scanners/modelos como evidências preliminares; buscar explicações alternativas; preservar resultados negativos; e jamais declarar vulnerabilidade confirmada sem evidência reproduzível.
- **Ciclo Metodológico Completo (Fases A–I)**:
  - **Fase A — Contextualização** (missão, escopo autorizado `.cyberlab/scope.json`, ativos e restrições)
  - **Fase B — Modelagem** (componentes, fluxos, identidades, fronteiras de confiança e transformações)
  - **Fase C — Pesquisa** (`CyberLab-Knowledge/`, RFCs, advisories primários, commits e patches)
  - **Fase D — Formulação de Hipóteses** (comportamento esperado vs. suspeito, pressuposto frágil, evidência necessária e explicações alternativas)
  - **Fase E — Priorização** (plausibilidade, impacto, custo, risco e poder diferenciador)
  - **Fase F — Experimentação Controlada** (baseline + modificação de **1 única variável independente** + critério de parada)
  - **Fase G — Avaliação Crítica** (comparação observado vs. esperado sem forçar confirmação)
  - **Fase H — Validação em 5 Níveis**: *(1) Comportamento inesperado*, *(2) Falha funcional*, *(3) Configuração insegura*, *(4) Vulnerabilidade potencial* ou *(5) Vulnerabilidade confirmada*
  - **Fase I — Documentação Reproduzível**

### 3.2 Os 6 Subagentes Especializados Sob Demanda & Guardrails de Runtime

O `Orchestrator` cria subagentes **somente quando há ganho investigativo concreto** (paralelismo independente, especialização profunda ou revisão cética):

| ID do Subagente | Especialidade | Permissões de Segurança |
|---|---|---|
| `research-agent` | Pesquisa em `CyberLab-Knowledge/`, RFCs, advisories, CVEs, commits e patches com checagem de alcançabilidade (*reachability*) | Sem edição de arquivos, sem `subagent` recursivo |
| `system-architect-agent` | Modelagem de componentes, proxies/CDNs, fluxos de dados, serializações, identidades e fronteiras de confiança | Sem edição de arquivos, sem `subagent` recursivo |
| `hypothesis-agent` | Formulação de hipóteses testáveis, pressupostos frágeis e explicações concorrentes | Somente raciocínio/leitura (sem `shell`, sem `edit`, sem `subagent`) |
| `tool-specialist-agent` | Seleção cirúrgica e minimamente intrusiva de ferramentas MCP (`arsenal_mcp_status`, `mcp-tool-catalog`, `arsenal_tool_help`) | Sem edição de arquivos, sem `subagent` recursivo |
| `experiment-agent` | Desenho de experimentos controlados (condições iniciais, 1 variável modificada, resultado esperado e *stop condition*) | Sem edição de arquivos, sem `subagent` recursivo |
| `evidence-reviewer-agent` | Revisão cética independente: caça falsos positivos (*soft-200*, cache/WAF, banners com *backport*) e aponta lacunas probatórias | Somente análise crítica (sem `shell`, sem `edit`, sem `subagent`) |

**Guardrails Rígidos de Infraestrutura (`packages/core/src/tool/plugin/subagent.ts` + `subagent-guardrails.ts`)**:
- **Limite de Profundidade (`maxDepth = 1`)**: nenhum subagente pode criar outros subagentes (bloqueado simultaneamente por `depth >= 1` e pela política `subagent: deny`).
- **Limite de Concorrência (`maxConcurrentPerSession = 3`)**: no máximo `3` subagentes simultâneos (foreground + background) por sessão investigativa (ajustável via `CYBERLAB_MAX_CONCURRENT_SUBAGENTS`).
- **Limite de Quantidade por Sessão (`maxTotalPerSession = 12`)**: teto de `12` novas sessões filhas por investigação (ajustável via `CYBERLAB_MAX_SESSION_SUBAGENTS`), incentivando a reutilização de `sessionID` de especialistas já iniciados.

---

## 4. Biblioteca Curada `CyberLab-Knowledge/` & Cofre Obsidian (`Alt+N`)

### 4.1 Estrutura Curada (`<workspace>/vault/CyberLab-Knowledge/` — 36 documentos)

Todos os **36 documentos curados** possuem frontmatter YAML auditável (`id`, `title`, `tier: curated`, `version`, `last_reviewed`, `status: validated`, `sources`, `limitations` e `related`) e links `[[WikiLinks]]` navegáveis tanto pelo agente quanto pelo operador humano no Cofre Obsidian:

```text
vault/CyberLab-Knowledge/
├── 00-Index.md
├── fundamentals/
│   ├── http.md                     # RFC 9110/9112/9113, framing CL/TE, normalização de paths e proxies
│   ├── authentication.md           # Sessões vs. JWT/JWKS, OAuth2/OIDC PKCE, WebAuthn e mTLS
│   ├── authorization.md            # Matriz Sujeito × Ação × Objeto × Contexto, RBAC/ABAC/ReBAC e multi-tenant
│   ├── sessions.md                 # Ciclo de vida de cookies, entropia, rotação, revogação e CSRF/SameSite
│   └── networking.md               # DNS, TCP/TLS, SNI/ALPN, proxies reversos, X-Forwarded-For e SSRF
│   ├── jwt-oauth-oidc.md           # alg:none, RS256→HS256, kid/jku/x5u, claim confusion, OAuth2/OIDC, PKCE
│   ├── csrf-cors-samesite.md       # Token anti-CSRF, Origin/Referer, ACAO+credenciais, SameSite Lax/None
│   └── tls-crypto.md               # TLS 1.2/1.3, downgrade, pinning, mTLS e falhas criptográficas aplicadas
├── methodologies/
│   ├── hypothesis-driven-testing.md # Método científico aplicado: hipótese falsificável e 1 variável por teste
│   ├── evidence-validation.md       # Taxonomia em 5 níveis, checklist anti-falso-positivo e reprodutibilidade
│   └── root-cause-analysis.md       # Violação de invariantes, pressupostos implícitos e caça de variantes
├── vulnerabilities/
│   ├── access-control/idor-bola-bfla.md
│   ├── injection/context-aware-injection.md
│   ├── parser-differential/http-url-json-differentials.md
│   └── business-logic/state-race-invariants.md
│   ├── ssrf.md                     # Diferenciais de parser, DNS rebinding, IMDS 169.254.169.254
│   ├── deserialization-xxe-upload.md # CWE-502/611/434: gadgets, XXE cego/OOB e validação de upload
│   ├── graphql-websocket.md        # Autorização por resolver, aliases/batching, CSWSH e canais
│   ├── cache-poisoning-deception.md  # Chave de cache, headers não-chaveados, fat GET, deception
│   ├── race-conditions-toctou.md   # Protocolo de experimento concorrente (N=20, single-packet)
│   └── mass-assignment-rate-limit.md # CWE-915, BOPLA, consumo irrestrito e limites por fluxo
├── domains/                        # (novo na v6.3) Domínios que faltavam para formular hipóteses
│   ├── mobile-android-ios.md       # JADX, Frida, MVT, WebView, armazenamento e deep links
│   ├── binary-reverse-engineering.md # Ghidra/Rizin/CAPA/GEF: pipeline estático→dinâmico
│   ├── cloud-iam-containers.md     # IMDS, escalada IAM, privileged container, Trivy
│   └── logging-forensics-detection.md # Hayabusa/YARA-X/MVT, cadeia de custódia e log injection
├── research/
│   ├── cve-analysis/cve-applicability-methodology.md
│   ├── patch-analysis/patch-diff-methodology.md
│   └── technical-writeups/reproducible-writeup-standard.md
├── tools/
│   ├── burp.md
│   ├── nuclei.md
│   ├── semgrep.md
│   ├── ai-assisted-pentest-workflows.md  # PentAGI/Shannon/Strix/CAI/HexStrike: IA = geradora de hipóteses
│   └── mcp-tool-catalog.md
├── targets/                        # (novo na v6.5) Alvos externos com autorização declarada
│   └── portswigger-web-security-academy.md  # Escopo, proibições, limites e ponte H1→H4
├── _drafts/                        # Rascunhos criados pelo agente (tier: draft — nunca misturados ao curado)
└── _proposals/                     # Propostas de revisão aguardando curadoria humana (pending_human_review)
```

### 4.2 Separação Epistemológica em 3 Camadas & Tools MCP de Conhecimento

O Hub MCP expõe **8 ferramentas dedicadas de Conhecimento e Memória Investigativa** (sempre ativas, mesmo quando nenhum scanner externo está habilitado):

| Tool MCP | Camada | Função |
|---|---|---|
| `search_knowledge` | 1. Conhecimento Curado | Pesquisa por conceito, falha, CVE, metodologia ou ferramenta (exclui `_drafts/` por padrão) |
| `read_document` | 1. Conhecimento Curado | Lê documento completo com cabeçalho de proveniência (fontes primárias, versão, revisão e limitações) |
| `get_document_metadata` | 1. Conhecimento Curado | Inspeciona metadados e seções sem consumir contexto com o texto completo |
| `get_related_documents` | 1. Conhecimento Curado | Navega o grafo `related` / `[[WikiLinks]]` / backlinks (falha → causa raiz → validação → ferramenta) |
| `create_draft_note` | Rascunho Isolado (`_drafts/`) | Registra descobertas separando **fatos observados**, **hipóteses**, **inferências** e **incertezas** |
| `propose_document_update` | Proposta (`_proposals/`) | Sugere atualização com fontes primárias obrigatórias **sem jamais alterar o documento curado original** |
| `investigation_memory_read` | 2. Contexto da Sessão | Lê missão, escopo, modelo arquitetural, hipóteses, testes e **resultados negativos** da investigação atual |
| `investigation_memory_update` | 2. Contexto da Sessão | Atualiza `.cyberlab/investigations/<id>.json` e sincroniza espelho legível em `vault/Investigacoes/<id>.md` |

### 4.3 Cofre Nativo Flutuante & Acoplável Compatível com Obsidian (`📓 Notas & Comandos` / `Alt+N`)

- Pressione **`Alt+N`** ou clique em **`📓 Notas & Comandos`** na barra superior para abrir o Cofre sobreposto (com fundo sólido opaco de alto contraste `#090d16`, redimensionável, arrastável ou acoplável à direita/rodapé **sem encolher nem deslocar a ferramenta do palco central**).
- Totalmente compatível com **Obsidian Desktop**: aponte o mesmo diretório `<workspace>/vault/` (ou qualquer pasta externa do Windows) e edite simultaneamente notas `.md`, `#tags`, `[[WikiLinks]]`, Backlinks, checklists interativos e blocos de comandos copiáveis/executáveis em 1 clique.

---

## 5. Hub MCP Unificado (`cyberlab-arsenal`), Pontes GUI em Tempo Real & Modelos Gratuitos

### 5.1 Arquitetura Hub MCP de Processo Único (`v6.1`–`v6.2`)

Em vez de iniciar dezenas de processos `bun.exe` separados no Windows (que causavam timeouts de inicialização e consumo elevado de RAM), o CyberLab OS consolida **todas as 45 ferramentas compatíveis com MCP** em **1 único servidor multiplexado ultrarrápido** (`cyberlab/mcp/arsenal-mcp-stdio.ts --slot __hub__`):

- **Hot-Reload Instantâneo**: clicar em **`🔌 MCP` / `🟢 MCP`** na barra lateral atualiza `.cyberlab/mcp-enabled-slots.json` e emite `notifications/tools/list_changed` imediatamente para o OpenCode sem reiniciar processos.
- **Resolução Automática Windows + WSL2 Kali**: localiza executáveis automaticamente em `C:\Program Files\...`, `WinGet`, `Scoop`, `PATH` do Windows ou dentro da distro `kali-linux` no WSL2, sempre com `shell=false`, Trava de Escopo Bug Bounty e redação `SHA-256` de segredos.
- **Tools Centrais do Arsenal**: `arsenal_mcp_status`, `arsenal_tool_help` e `arsenal_run_tool`.

### 5.2 Pontes MCP Nativas em Tempo Real para Suítes Gráficas (GUI)

Quando os slots abaixo estão com **`🟢 MCP`** ativo, o Hub expõe ferramentas dedicadas conectadas diretamente às instâncias gráficas abertas:

1. **Burp Suite (`127.0.0.1:9876` — Ponte Nativa HTTP+SSE `PortSwigger/mcp-server`)**:
   - Botão de **1 clique** no painel do Burp baixa `burp-mcp-all.jar` em `/opt/cyberlab-burp/` (fora do repositório MIT).
   - Tools expostas: `burp_suite_status`, `burp_suite_get_proxy_history`, `burp_suite_get_proxy_http_history_regex`, `burp_suite_send_http1_request`, `burp_suite_send_http2_request`, `burp_suite_create_repeater_tab`, `burp_suite_send_to_intruder`, `burp_suite_set_intercept`, `burp_suite_url_encode`, `burp_suite_base64_encode` e `burp_suite_call_tool` (com fallback automático Windows ↔ WSL2).
2. **NSA Ghidra (`127.0.0.1:8080` — `LaurieWired/GhidraMCP` v2.0)**:
   - Botão **`🔌 Instalar GhidraMCP (:8080)`** instala automaticamente a release oficial `Apache-2.0`.
   - Tools expostas: `ghidra_mcp_status`, `ghidra_mcp_decompile` e `ghidra_mcp_call` (funções, strings, imports/exports, xrefs, renomeação de símbolos e modo headless).
3. **JADX-GUI (`127.0.0.1:8650` — `zinja-coder/jadx-ai-mcp`)**:
   - Botão **`🔌 Instalar JADX-AI-MCP (:8650)`** instala o plugin oficial via `jadx plugins --install "github:zinja-coder:jadx-ai-mcp"`.
   - Tools expostas: `jadx_mcp_status`, `jadx_mcp_get_class_source` e `jadx_mcp_call` (`AndroidManifest.xml`, busca de métodos, recursos e xrefs).

### 5.3 Paridade de Runtime WSL2 para Capabilities `external.*` (`v6.3`)

A Fase A de calibração revelou que **7 capabilities `external.*`** (`nuclei`, `tshark`, `ghidra`, `jadx`, `yarax`,
`dalfox`, `keyhunter`) reportavam `not installed` enquanto os slots MCP correspondentes diziam `INSTALLED`. A causa
era uma divergência de detecção: o `ArsenalSlotManager` fazia probe dentro do WSL2 Kali, mas o control plane externo
resolvia binários apenas em `.cyberlab/bin` e no `PATH` do Windows.

Agora a resolução acontece em **4 camadas**, na mesma ordem para slots e capabilities:

| # | Camada | Exemplo |
|---|---|---|
| 1 | `config/external-tools.json` → `binaryPaths` | override manual do operador |
| 2 | `<workspace>/.cyberlab/bin` | bootstrap local (`./script/bootstrap-local-tools.sh`) |
| 3 | `PATH` do host (Windows / Linux nativo / macOS) | `winget install skylot.jadx` |
| 4 | **WSL2** (`kali-linux` por padrão) | `sudo apt install -y nuclei` |

- **Probe batido único**: um só `wsl.exe -d kali-linux -u root -- bash -s` (script via **stdin**, com retry
  automático quando a VM do Hyper-V está fria) resolve **todos** os candidatos de uma vez — sem um processo por binário.
- **Tradução automática de caminhos**: `C:\ws\out.json` → `/mnt/c/ws/out.json`; flags, URLs e números passam intactos.
- **Encapsulamento transparente**: `wsl.exe -d kali-linux -u root -- /usr/bin/nuclei <args>`, mantendo `shell=false`,
  Trava de Escopo Bug Bounty, `AbortSignal` e custódia `SHA-256` da evidência.
- **Diagnóstico honesto**: `bun run cyberlab external list` agora mostra a origem real
  (`READY via wsl_distro:kali-linux (/usr/bin/nuclei)`) e a dica de instalação no Kali quando o binário falta.

### 5.4 9 Modelos de IA Gratuitos Nativos do OpenCode Zen

Prontos para uso imediato sem chave paga (`apiKey: "public"`, configurados automaticamente com `--use-system-ca`):
`Big Pickle`, `DeepSeek V4.1 Flash Free`, `GLM-5.3 Flash Free`, `Nemotron 3.5 Super VL Free`, `Nemotron 3.5 Lightning Free`, `Nemotron 3 Ultra Free`, `MiMo V2.6 Flash Free`, `Flint 40B Free` e `Beam Free` — além de suporte total a qualquer provedor Anthropic, OpenAI, Gemini, OpenRouter, Ollama ou LM Studio local.

---

## 6. Layout Antigravity de 3 Colunas, Topo Retrátil (`28px`) & `noVNC` Nitidez Real

```text
┌───────────────────┬──────────────────────────────────────────────────────┬────────────────────┐
│ COLUNA ESQUERDA   │                PALCO CENTRAL (100% REAL)             │  COLUNA DIREITA    │
│ (Retrátil ~230px) │  [▲ Recolher Topo -> fita compacta de 28px (v5.9)]   │ (Retrátil ~330px)  │
│                   │                                                      │                    │
│ 📁 Arquivos       │  • GUI Linux Real via Xvfb + noVNC 110 DPI           │ 🤖 Orchestrator    │
│ 🛠 48 Slots       │    (Burp, OpenTRAP, ZAP, Wireshark, Ghidra, JADX,    │    (v6.2 Hipóteses │
│    + Custom       │     VeraCrypt, Kali XFCE Desktop Completo)           │     + Subagentes   │
│    [🔌/🟢 MCP]    │  • Web UIs Reais (Caido, mitmweb, CyberChef,         │     + Knowledge)   │
│                   │     PentAGI TLS :8443, Pentest Copilot)              │                    │
│ [📓 Alt+N Cofre]  │  • Scanners CLI Reais + Escopo + Custódia SHA-256    │                    │
└───────────────────┴──────────────────────────────────────────────────────┴────────────────────┘
```

- **Topo Horizontal Retrátil na Vertical (`v5.9`)**: recolhe automaticamente todas as barras superiores em uma fita enxuta de **`28px`** ao abrir ferramentas gráficas ou Web, entregando quase 100% da altura vertical da tela para a ferramenta e redimensionando o desktop X11 instantaneamente.
- **Zoom `60%–160%` com Zero Deslocamento do Mouse (`v5.8`)**: usa `Display._scale` + `ExtendedDesktopSize` nativos do `noVNC` (`110 DPI`), mantendo clique cirúrgico em cada botão/menu de Burp, Ghidra, Wireshark e JADX.
- **Navegador Isolado Pré-Configurado no Proxy em 1 Clique**: abre Microsoft Edge ou Chrome com perfil temporário apontando automaticamente para `127.0.0.1:8080` (ou porta ativa do proxy).

---

## 7. Catálogo Completo dos 48 Slots Oficiais + Slots Personalizados

Todas as ferramentas abaixo residem **fora** do repositório `MIT` do CyberLab OS (instaladas no sistema do operador):

1. **Proxies, Interceptação & Suítes Web (`5 slots`)**: `burp-suite` (Burp Suite Community + MCP `:9876`), `opentrap`, `mitmweb` (`:8081`), `caido` (`:7000`), `owasp-zap`.
2. **Auditoria Web, Bug Bounty, Fuzzing & OAST (`9 slots`)**: `nuclei`, `ffuf`, `dirsearch`, `katana`, `httpx`, `interactsh`, `dalfox`, `sqlmap`, `wpprobe`.
3. **Reconhecimento, Rede, PCAP & Infraestrutura (`8 slots`)**: `subfinder`, `nmap`, `netcat-ncat`, `naabu-dnsx-tlsx`, `wireshark` (GUI + `tshark`), `netexec`, `metasploit`, `impacket-hashcat`.
4. **Engenharia Reversa, REA, Depuração & Mobile Forensics (`8 slots`)**: `rea` (`morluto/rea` MCP), `ghidra` (+ `GhidraMCP :8080`), `jadx` (+ `JADX-AI-MCP :8650`), `rizin-cutter`, `gef`, `frida-apktool`, `capa`, `mvt`.
5. **Caça de Segredos, SAST, SCA & Cloud (`5 slots`)**: `keyhunter`, `betterleaks`, `gitleaks-trufflehog`, `semgrep` (OpenGrep), `trivy`.
6. **Agentes de IA Externos & Metodologia (`6 slots`)**: `strix`, `shannon`, `hexstrike-ai`, `pentagi` (proxy TLS `:8443`), `pentestgpt-cai`, `pentest-copilot`.
7. **OpSec, Privacidade & Criptografia (`3 slots`)**: `tor-onionshare`, `veracrypt` (GUI/CLI), `mullvad-opsec` *(isolados sem MCP por segurança operacional)*.
8. **CyberChef, DFIR (Sigma), Purple Team & Kali Desktop (`4 slots`)**: `cyberchef`, `hayabusa-yarax`, `atomic-operator`, `kali-desktop-stream`.
9. **Slots Personalizados (`+ Slot`)**: adicione qualquer binário CLI, aplicação Web (`iframe`) ou ferramenta Desktop do Windows/WSL2.

---

## 9. Os 4 Parceiros Cognitivos CDI (`8788–8791`) & 5 Laboratórios de Treino

### 8.1 Gateway Bidirecional `HMAC-SHA256` dos 4 CDIs
**Kairós (`:8788`)**, **Naia (`:8789`)**, **Salem (`:8790`)** e **Nova (`:8791`)** operam em autonomia horizontal (`hierarchy: "none"`, `humanRole: "curator"`) via `/api/cyberlab/partner-gateway` e SDK Python `integrations/partners/chat_py_bridge.py`.

### 8.2 Os 5 Laboratórios Internos Seguros (`5 Labs de Treino`)
1. `lab-owasp-api-bola` (BOLA `API1:2023`, JWT `alg:none` e headers)
2. `lab-graphql-oauth-sso` (Introspecção GraphQL, batching e OAuth2 PKCE `S256`)
3. `lab-keyhunter-supply-chain` (Segredos sintéticos, SCA e IaC Terraform/Docker)
4. `lab-dfir-soc-incident` (Triagem de logs `JSONL`/`CEF` com regras Sigma)
5. `lab-reversing-crypto-mobile` (Artefatos benignos `ELF64`, `.pcap` e `.apk`)

---

## 10. Governança de Escopo Bug Bounty, Custódia `SHA-256` & Segurança Anti-Prompt-Injection

- **Trava de Escopo Bug Bounty (`.cyberlab/scope.json`)**: importa escopos HackerOne/Bugcrowd, injeta cabeçalhos de identificação do pesquisador, bloqueia alvos fora de escopo antes da criação do processo (`shell=false`) e mantém bloqueio anti-SSRF permanente contra metadados de nuvem (`169.254.169.254`).
- **Defesa contra Conteúdo Não Confiável (*Prompt Injection*)**: respostas HTTP, páginas analisadas, artefatos de engenharia reversa e saídas de ferramentas são tratados pelo `Orchestrator` e pelos 6 subagentes estritamente como **dados não confiáveis**, incapazes de alterar escopo, permissões ou instruções da missão.
- **Cofre Criptográfico `SHA-256` & Redação Automática**: todas as evidências salvas passam por redação automática de tokens/chaves sensíveis (`Bearer`, `Cookie`, AWS, GitHub, JWT, `PEM`) com verificação de integridade `SHA-256` e exportação de relatório Markdown reproduzível.

---

## 11. Histórico Completo de Versões (`v1.0` → `v6.5`), Verificação CI & Licenciamento MIT

- **v1.0 – v4.0**: Base OpenCode V2 (`2.1.4`), governança anti-TOCTOU, cofre `SHA-256`, 4 CDIs (`8788–8791`), 5 Labs de Treino e 9 modelos gratuitos OpenCode Zen.
- **v5.0 – v5.8**: Arquitetura **Real Arsenal Edition** (3 colunas Antigravity, motor `X11/noVNC` 110 DPI sem deslocamento de mouse no zoom, navegador proxy em 1 clique, Burp oficial, REA MCP, PentAGI TLS `:8443` e ferramentas Kali 2026.1).
- **v5.9**: Topo horizontal retrátil na vertical (`28px`) + resiliência a boot frio do WSL2 `kali-linux`.
- **v6.0 – v6.0.2**: Cofre nativo flutuante/acoplável compatível com Obsidian (`Alt+N`) com fundo sólido opaco, slots `netcat-ncat` e `dirsearch` (**48 slots oficiais**) e ponte nativa `stdio <-> SSE` para o **Burp Suite MCP (`:9876`)**.
- **v6.1**: **Hub MCP Unificado (`cyberlab-arsenal` `--slot __hub__`)** consolidando todos os slots em 1 único processo (~3,5 GB de RAM economizados no Windows), resolução completa de caminhos Windows (`Program Files`/WinGet/Scoop) + WSL2 e instaladores/pontes de 1 clique para **`GhidraMCP (:8080)`** e **`JADX-AI-MCP (:8650)`**.
- **v6.2**: **Investigative Security Orchestrator** em `pt-BR` (Ciclo Fases A–I + validação em 5 níveis), **6 Subagentes Especializados sob demanda** com limites rígidos de profundidade (`1`), concorrência (`3`) e quantidade por sessão (`12`), biblioteca curada **`CyberLab-Knowledge/`** integrada ao Cofre Obsidian com **8 tools MCP de Conhecimento e Memória Investigativa** (preservando resultados negativos e imutabilidade dos documentos curados) e atualização integral da documentação.
- **v6.3**: **Paridade de Runtime WSL2 + Expansão da Biblioteca Curada (34 docs)** — correção da divergência crítica reportada na Fase A: as 7 capabilities `external.*` (`nuclei`, `tshark`, `ghidra`, `jadx`, `yarax`, `dalfox`, `keyhunter`) que diziam `not installed` enquanto os slots MCP diziam `INSTALLED`. O control plane agora resolve binários em **4 camadas** (`external-tools.json` → `.cyberlab/bin` → `PATH` Windows → **WSL2**), com probe batido único (`wsl.exe -d kali-linux -u root -- bash -s`, retry para VM fria), tradução automática de caminhos Windows → `/mnt/...` e encapsulamento transparente em `wsl.exe`. Biblioteca curada expandida de 20 → **34 documentos** cobrindo JWT/OAuth, CSRF/CORS/SameSite, TLS & cripto, SSRF, desserialização/XXE/upload, GraphQL/WebSocket, cache poisoning/deception, race conditions (protocolo concorrente N=20), mass assignment/BOPLA/rate limiting, mobile, engenharia reversa, cloud/IAM/contêineres, logging/forense e fluxos com IA orientados por hipótese.

- **v6.3.1**: **Higiene de Slots Personalizados** — resolve os 3 slots ativos sem binário encontrados pela Fase A
  (`custom-metasploit-framework-c421`, `custom-metasploit-framework-ce52`, `custom-ssti-advanced-payload-list-9b27`).
  Novo diagnóstico `health` no overview do Arsenal detecta **slot fantasma** (executável configurado ausente no
  Windows/PATH/WSL2), **duplicata** (mesmo nome normalizado de outro slot já instalado — nunca sugere remover
  oficial), **alvo não-executável** (aponta para lista de payload/JSON em vez de binário) e **slot sem
  configuração**. Exposição em 3 superfícies: banner âmbar na barra Slots com botão
  **🧹 Limpar Fantasmas & Duplicatas**, tool MCP `arsenal_slot_health` no Hub e endpoint
  `POST /api/cyberlab/arsenal/prune` (nunca remove slots oficiais).

- **v6.4**: **Laboratório pronto para investigação (Fases B/D/F)** — resolve o item "servidor do lab inativo /
  memória investigativa vazia" do relatório de calibração. Novo `cyberlab/labs/investigation-kit.ts` gera
  automaticamente, na porta real do servidor: `LAB_SYSTEM_MODEL.md` (Fase B — componentes, tecnologias, fluxos,
  fronteiras de confiança, identidades e invariantes por endpoint), `HYPOTHESES.md` (Fase D — H1 BOLA, H2 JWT
  `alg:none`, H3 erro SQL, H4 headers, cada uma com os 6 elementos obrigatórios) e `EXPERIMENTS.md` (Fase F —
  6 experimentos com variável única, critério de parada, comandos `curl` prontos e **matriz de remediação**
  antes/depois). Novo CLI `bun run cyberlab lab <list|start|stop|status|kit|seed|model>` e flag
  `--lab <labId>` no launcher unificado. Observação: a porta citada em notas antigas (`4101`) estava
  **desatualizada** — a porta real é confirmada por `bun run cyberlab lab status`.

- **v6.4.1**: **Modo daemon para os laboratórios** — corrige a armadilha de UX do v6.4: sem
  `--daemon`, o servidor do lab vivia dentro do processo do terminal e morria no `Ctrl+C` (ou ao fechar a
  janela), deixando o orquestrador sem alvo. Agora `bun run cyberlab lab start <labId> --daemon` sobe o
  servidor em **segundo plano** (processo desanexado + arquivo de PID + log em disco), ele sobrevive ao
  fechamento do terminal, e `lab stop <labId>` encerra o daemon **mesmo de outro terminal**. `lab status`
  detecta o daemon por PID + sonda TCP e imprime a URL confirmada.

- **v6.4.2**: **Porta do lab vs. porta da aplicação** — `http://127.0.0.1:19081` é o **alvo** da investigação
  (uma API REST sem interface), não o CyberLab OS. Abrir essa URL devolvia JSON cru e dava a impressão de que
  "não abria como antes". Agora `GET /` exibe uma página HTML legível: avisa que esta porta é apenas o alvo,
  aponta para a interface em `http://127.0.0.1:4096`, mostra o estado real dos 4 controles de
  `server-config.json`, lista os endpoints clicáveis com o invariante esperado e traz o comando `curl.exe`
  pronto. `GET /health` continua JSON (usado por scripts e pela sonda TCP do `lab status`).

- **v6.4.3**: **`lab start` quando o lab já está no ar** — rodar `lab start ... --daemon` duas vezes
  devolvia apenas "Já existe um daemon ativo" + "use `lab stop`", o que parecia um erro e não dizia
  onde o lab estava. Agora o comando **confirma por sonda TCP** e, se estiver tudo certo, responde
  `✔ ... JÁ ESTÁ NO AR` com o painel, o smoke test e a lista de próximos passos (`status`, `seed`).
  Se o PID estiver vivo mas a porta não responder (**daemon zumbi**), ele encerra o órfão e sobe um
  novo sozinho. Novo comando `lab restart <labId>` (e flag `--restart`/`--force`) para recomeçar do
  zero. Corrigido também um **ENOENT** quando a raiz `.cyberlab/labs` ainda não existia (primeiro uso).

- **v6.5**: **Evidência arquivada, alvo externo autorizado e `cyberlab up`.**
  - `lab evidence <labId>`: reexecuta **E1–E7** e grava 19 pares comando/resposta com a
    expectativa declarada *antes* de rodar, mais `manifest.json`, `REPORT.md` e `SEAL.txt`
    (selo = SHA-256 do manifesto, conferível com `sha256sum`/`Get-FileHash`). O lab volta ao
    estado vulnerável ao fim, comprovado pela fase `E7`.
  - `lab targets` / `lab scope <perfil>`: perfis de alvo externo **com base de autorização
    declarada** (nenhum perfil entra na lista sem ela). Perfil `portswigger-wsa` cobre
    `*.web-security-academy.net` e `*.h1-web-security-academy.net`, com hosts permitidos,
    proibições, limites de taxa, regras de evidência e a ponte H1–H4 → tópicos da Academy.
  - `bun run cyberlab up`: um comando para atualizar (`git pull --ff-only`), instalar se
    preciso, subir o laboratório em segundo plano e abrir a interface. `Ctrl+C` derruba só
    a interface — o laboratório continua no ar.
  - Biblioteca curada: **36 documentos** (novo `targets/portswigger-web-security-academy.md`).

### Verificação Local Completa (Idêntica ao GitHub Actions Linux + Windows)

```bash
# 1. Auditoria automática de licenças MIT (0 código GPL/AGPL embutido no repositório)
bun run script/check-cyberlab-licenses.ts

# 2. Typecheck completo por pacote
bun --cwd packages/schema typecheck
bun --cwd packages/core typecheck
bun --cwd packages/server typecheck
bun --cwd packages/cli typecheck
bun --cwd packages/gui-plugins typecheck
bun --cwd cyberlab typecheck

# 3. Suíte automatizada de testes (85 testes / 1.344+ asserções)
bun --cwd cyberlab test
```

### Documentação Complementar
- [`docs/PLAYBOOK_POWERSHELL_WSL2_ARSENAL.md`](docs/PLAYBOOK_POWERSHELL_WSL2_ARSENAL.md) — Operação híbrida Windows PowerShell + WSL2 Kali Linux.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Arquitetura de governança, execução e custódia criptográfica.
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — Modelo de ameaças, anti-TOCTOU, redação e protocolo `HMAC-SHA256`.
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — Política de conformidade `MIT` e isolamento de ferramentas externas.
- [`docs/UPSTREAM_AUDIT.md`](docs/UPSTREAM_AUDIT.md) — Auditoria técnica da base OpenCode V2 (`2.1.4`).
