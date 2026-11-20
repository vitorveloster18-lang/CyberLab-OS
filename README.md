# CyberLab OS — Investigative Security Edition (v7.0)

Plataforma de **Engenharia de Segurança Ofensiva/Defensiva, Investigação Orientada por Hipóteses, Bug Bounty Autorizado, Engenharia Reversa, DFIR e Laboratórios de Treinamento**, construída sobre o **OpenCode V2 (`2.1.4`)** e feita para rodar **no terminal do seu Kali** — nativo, sem VM convidada, sem ponte de Windows e sem reempacotar ferramenta.

> **Filosofia Central (v7.0)**: o CyberLab OS é a **camada de método, escopo e custódia**. As ferramentas são as que você já tem instaladas.
> 1. **Investigative Security Orchestrator (`Orchestrator`)**: agente principal em `pt-BR` orientado por hipóteses científicas (Ciclo **Fases A–I**), validação rigorosa de evidências e **6 subagentes especializados sob demanda** com guardrails rígidos de profundidade (`1`), concorrência (`3`) e orçamento por sessão (`12`).
> 2. **Biblioteca Curada `CyberLab-Knowledge/` no Cofre Obsidian + Memória Investigativa Isolada**: **40** documentos técnicos revisados com metadados verificáveis (fontes primárias, versão, data de revisão, limitações e grafo `[[WikiLinks]]`), servidos via **MCP** (`cyberlab-knowledge`) com separação epistemológica estrita em **3 camadas**.
> 3. **`cyberlab exec` + Trava de Escopo + Custódia `SHA-256`**: você roda o binário; o CyberLab garante que o alvo está no escopo autorizado, redige segredos da saída e arquiva tudo como evidência reproduzível.

---

---

## Sumário

1. [Inicialização Rápida (terminal do Kali)](#1-inicialização-rápida-terminal-do-kali)
2. [Primeira Tarefa Recomendada (Calibração do Orquestrador)](#2-primeira-tarefa-recomendada-calibração-do-orquestrador)
3. [Investigative Security Orchestrator & 6 Subagentes Especializados](#3-investigative-security-orchestrator--6-subagentes-especializados-v62)
4. [Biblioteca Curada `CyberLab-Knowledge/` & Cofre Obsidian](#4-biblioteca-curada-cyberlab-knowledge--cofre-obsidian)
5. [Servidor MCP da Biblioteca de Conhecimento (`cyberlab-knowledge`)](#5-servidor-mcp-da-biblioteca-de-conhecimento-cyberlab-knowledge)
6. [Laboratórios de Treino Prontos para Investigação](#8-laboratórios-de-treino-prontos-para-investigação-v64v65)
7. [Os 4 Parceiros Cognitivos CDI (`8788–8791`)](#9-os-4-parceiros-cognitivos-cdi-87888791--5-laboratórios-de-treino)
8. [Governança de Escopo Bug Bounty, Custódia `SHA-256` & Segurança Anti-Prompt-Injection](#10-governança-de-escopo-bug-bounty-custódia-sha-256--segurança-anti-prompt-injection)
9. [Histórico de Versões, Verificação CI & Licenciamento MIT](#11-histórico-completo-de-versões-v10--v67-verificação-ci--licenciamento-mit)

> ℹ️ **Sumário detalhado dos laboratórios**: veja a seção [6](#8-laboratórios-de-treino-prontos-para-investigação-v64v65).

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

> ℹ️ **Porta**: `http://127.0.0.1:19081` = **alvo de treino** (API REST, sem interface — é isso que você
> ataca com Burp/curl/scanners). A porta real é sempre confirmada por `bun run cyberlab lab status`.
> Abrir a `/` do lab no navegador mostra uma página de orientação com os controles, os endpoints e o
> comando de teste; o JSON de diagnóstico fica em `/health`.

> ✅ **Se aparecer "JÁ ESTÁ NO AR", está tudo certo** — não é erro: o lab já está rodando e
> respondendo. O comando mostra o painel e os próximos passos. Para recomeçar do zero use
> `bun run cyberlab lab restart lab-owasp-api-bola`.

> ⚠️ **Sem `--daemon` o servidor morre com o terminal.** O comando `start` sem a flag mantém o processo
> em primeiro plano e exibe `Servidor ativo neste processo. Pressione Ctrl+C para encerrar.` — ao
> pressionar `Ctrl+C` (ou fechar a janela) o lab é desligado. `seed` e `model` continuam funcionando
> (eles só leem o Kit em disco), mas o alvo fica fora do ar para execução de experimentos.

O CyberLab OS em si não abre porta: ele é o terminal. O alvo é o único processo de rede.

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
9. [Histórico de Versões, Verificação CI & Licenciamento MIT](#11-histórico-de-versões-v10--v70-verificação-ci--licenciamento-mit)

---

### 8.3 Evidência arquivada com SHA-256 (`lab evidence`)

```powershell
bun run cyberlab lab evidence lab-owasp-api-bola
bun run cyberlab lab evidence lab-owasp-api-bola --out evidence\rodada-01
bun run cyberlab lab slots --health
bun run cyberlab lab tools --missing
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

### 8.6 Guarda de ações destrutivas — o agente NÃO destrói sem perguntar (v6.7)

Regra do projeto, agora **no código** (não só no prompt): `cyberlab/safety/destructive-guard.ts`.

| Operação | Risco | O que exige |
| --- | --- | --- |
| `cyberlab.arsenal.prune` | destrutivo | `confirm: true` |
| `cyberlab.arsenal.custom.remove` | destrutivo | `confirm: true` |
| `cyberlab.labs.control` (`reset` / `stop`) | destrutivo | `confirm: true` |
| `cyberlab.vault.delete` | **irreversível** | `confirm: true` **+** `confirmPhrase` digitada exata |
| `cyberlab.knowledge.sync` | destrutivo | `confirm: true` |

Sem a confirmação, a operação **falha fechada** e responde `HTTP 400` com o plano completo
(o que seria afetado, o que tem volta e o que não tem) — para o agente conseguir **mostrar
o plano ao operador** e pedir autorização. Erro sem corpo não ensina nada a ninguém.

O humano clicando num botão da interface **já é** a confirmação: a UI envia `confirm: true`.
O agente não tem como obter esse token, então sempre recebe o plano primeiro.

### 8.7 Sincronização do cofre curado — `cyberlab knowledge` (v6.7)

A semeadura da biblioteca só escrevia quando o arquivo **não** existia
(`if (!existsSync(dest))`). Na prática: documentos novos entravam, mas qualquer doc que já
estivesse no cofre ficava preso na versão do dia em que você rodou o CyberLab pela primeira
vez — foi exatamente por isso que o `00-Index.md` continuava sendo o da v6.2.

```powershell
bun run cyberlab knowledge            # PLANO: não escreve nada
bun run cyberlab knowledge --apply    # aplica, com .bak antes de cada troca
```

- Compara `version` + `last_reviewed` do frontmatter — status, não palpite.
- Só toca em documento com `tier: curated`. `_drafts/`, `Investigacoes/` e notas suas são
  preservadas (e aparecem como **protegidas** no plano).
- Cada arquivo substituído ganha um `.bak` ao lado. Se não conseguir fazer o backup, **não
  escreve**.
- O `00-Index.md` foi corrigido: 35 documentos + o índice (vulnerabilidades eram 10, o texto
  dizia 9).

### 8.8 Evidência visível para o agente — `lab evidence --register` (v6.7)

O `lab evidence` gravava em arquivos; o agente consulta o `EvidenceStore` (SQLite). Eram
dois mundos separados, e por isso a calibração dizia "0 registros" mesmo com 19 requisições
arquivadas. Agora:

```powershell
bun run cyberlab lab evidence lab-owasp-api-bola --register
bun run cyberlab lab evidence lab-owasp-api-bola --out evidence\rodada-02 --register
```

Grava os arquivos **e** registra cada requisição no `EvidenceStore` (projeto = `labId`), de
onde `cyberlab_evidence_list` passa a enxergá-las.

### 8.9 Diagnóstico das ferramentas do seu Kali — `lab tools` (v6.7)

A pergunta *"quais ferramentas faltam instalar?"* não tinha resposta verificável.
O CyberLab responde perguntando ao **seu** `PATH`, sem inventar inventário:

```bash
# cada binário que o laboratório espera, com o status real
for t in nmap nuclei ffuf tshark sqlmap jadx ghidra; do
  bun run cyberlab exec -- which $t || echo "$t: AUSENTE"
done
```

Ou, para um retrato completo de uma vez:

```bash
bun run cyberlab exec -- bash -lc 'command -v nmap nuclei ffuf tshark sqlmap jadx ghidra'
```

A distinção que importa: **pacote instalado ≠ binário no `PATH`**. O Ghidra do Kali, por
exemplo, põe o launcher gráfico em `/usr/bin/ghidra`, mas o `analyzeHeadless` (o que um
agente invocaria) fica em `/usr/share/ghidra/support/analyzeHeadless`. Quando isso
acontece, chame pelo caminho absoluto — o `cyberlab exec` aceita qualquer binário:

```bash
bun run cyberlab exec -- /usr/share/ghidra/support/analyzeHeadless /tmp/projeto -import /tmp/alvo.elf
```

> **Host de escuta do lab**: por padrão o alvo escuta **somente em `127.0.0.1`** — ele é um
> *alvo de treino* e o escopo autorizado declarado no Kit de Investigação é loopback. Quando o
> navegador do operador **não** está na mesma máquina (preview remoto, container, sandbox), use
> `CYBERLAB_LAB_HOST=0.0.0.0 bun run cyberlab lab start lab-owasp-api-bola --port 19081`.


### 8.10 Fase C — Pesquisa: `lab research` (v6.7)

A **Fase C** do ciclo metodológico (A–I) era a única que existia só no prompt do agente:
*"consulte `CyberLab-Knowledge/` e fontes primárias sobre mecanismos, histórico de falhas,
patches anteriores e pressupostos de segurança"* — sem ferramenta, cada operador montava a
pesquisa à mão e nada ficava arquivado. Agora é um artefato versionado:

```powershell
bun run cyberlab lab research lab-owasp-api-bola
bun run cyberlab lab research lab-owasp-api-bola --register   # também entra no EvidenceStore
bun run cyberlab lab research lab-owasp-api-bola --offline    # não toca a rede (usa o cache)
bun run cyberlab lab research lab-owasp-api-bola --refresh    # ignora o cache (TTL 12h)
bun run cyberlab lab research lab-owasp-api-bola --json
```

Duas fontes, como manda a metodologia:

1. **`CyberLab-Knowledge/`** — busca local na biblioteca curada do cofre (sem rede).
2. **GitHub Advisory Database** (`GET api.github.com/advisories`) — histórico real de
   falhas das tecnologias que o lab emula. Cada resposta é arquivada **bruta** em
   `research-raw/` com SHA-256, para o relatório ser auditável.

Gera `RESEARCH.md`, `research.json`, `research-raw/*.json` e `research-manifest.json`
(lacre SHA-256 do lote). Autenticação opcional via `GITHUB_TOKEN`/`GH_TOKEN`: sem token o
limite é 60 req/h, com token 5.000 req/h.

> **A Fase C não declara vulnerabilidade — ela produz contexto para a Fase D.** O lab é um
> alvo sintético em `node:http` puro, **sem dependências de terceiros**: os advisories
> listados referem-se às tecnologias que ele *emula*, **não são CVEs do próprio lab**.
> Isso está escrito explicitamente na seção "Limitações declaradas" do relatório.

O perfil de pesquisa é curado por lab (`cyberlab/labs/research-profile.ts`): pacotes a
consultar, classes de fraqueza (CWE/OWASP) e fontes primárias (RFC 8725 para JWT
`alg:none`, OWASP API1:2023 para BOLA, CWE-639/347/209/693). Lab sem curadoria recebe um
perfil **derivado** do modelo de Fase B — e esse perfil derivado deliberadamente **não
consulta nenhum pacote**, para não inventar falso positivo.

Dois ajustes que vieram de dados reais:

- Um advisory pode listar vários pacotes; a normalização gera um registro por pacote
  afetado **e depois colapsa para 1 linha por advisory**. Sem isso, `affects=jose`
  devolvia 17 linhas (3 advisories) por causa de faixas repetidas e pacotes irmãos.
- `pyjwt` aparece em três grafias (`pyjwt`, `PyJWT`, `pyJWT`); o colapso casa ignorando
  caixa.

### 8.11 Fase D — Hipóteses ancoradas na Fase C + priorização (Fase E)

As sementes de hipótese já existiam (com os 6 elementos obrigatórios), mas tinham dois
furos metodológicos: **nenhuma hipótese consumia a Fase C**, e **não havia Fase E** — a
ordem de investigação era simplesmente a ordem em que as sementes foram digitadas.

```powershell
bun run cyberlab lab hypothesize lab-owasp-api-bola
bun run cyberlab lab hypothesize lab-owasp-api-bola --register
bun run cyberlab lab hypothesize lab-owasp-api-bola --json
```

- **Ancoragem**: cada hipótese é ligada aos achados **reais** da Fase C — advisories
  (GHSA/CVE), classificação CWE e fontes primárias (RFC/OWASP/MITRE). Só entra o que a
  consulta realmente retornou; nada é citado de memória.
- **Priorização (Fase E)** com rubrica explícita e determinística, impressa no relatório:

  | Critério | Peso | De onde vem |
  |---|---|---|
  | Plausibilidade | 0.25 | controle reparador DESLIGADO + existência de âncora |
  | Impacto | 0.25 | severidade declarada na semente (teto, se for faixa) |
  | Poder diferenciador | 0.15 | nº de experimentos independentes |
  | Evidência disponível | 0.15 | cruza Fase C (âncoras) com Fase F (experimentos) |
  | Custo (5 = barato) | 0.10 | proxy pelos comandos já prontos |
  | Risco de execução | −0.10 | 1 (alvo é loopback, nenhum alvo externo) |

- **Lacunas declaradas**: hipótese sem âncora não é escondida — recebe
  `Sem nenhuma âncora na Fase C`. E a que só tem CWE/fonte primária recebe
  `sem advisory: esperado para falhas de lógica de aplicação`.

Resultado real no `lab-owasp-api-bola`:

```
#  Hipótese                                  Score  Ancoras
1  H2  Bypass de assinatura JWT (alg:none)    4.05    36   (32 advisories + CWE-347 + RFC 8725)
2  H1  BOLA/IDOR (token do User A lê User B)  3.95     3   (CWE-639 + OWASP API1:2023)
3  H3  Vazamento de erro SQL                  3.9      2   (CWE-209 + MITRE)
4  H4  Ausência de headers de segurança       3.25     0   (sem âncora — lacuna declarada)
```

O H2 fica em primeiro porque é o único com histórico real de falha documentado
(**CVE-2015-9235**, `critical`, bypass de verificação de assinatura) **e** com o controle
reparador desligado. H1 e H3 são falhas de lógica de aplicação: não têm CVE de biblioteca,
e o relatório diz isso em vez de inventar.

> **Âncora falsa é pior que âncora faltando.** Na primeira versão, a keyword `token` fez o
> H1 (BOLA) puxar os 32 advisories de JWT — o operador leria que uma falha de lógica tem
> CVE de biblioteca. O casamento agora é por **palavra** (`\b`), não por substring, e as
> keywords são específicas (`jwt`, `alg:none`, `assinatura` — não `alg`, que casaria com
> "algum"; não `token`, que casa com qualquer Bearer). Há teste de regressão para isso.

### 8.12 Fase F — Experimentação controlada: `lab experiment` (v6.7)

As sementes de experimento (E1–E6) já vinham com os comandos prontos — mas **ninguém os
executava**. A Fase F executa, com duas regras que valem mais que a conveniência:

```powershell
# Plano (padrão): mostra o que faria, não toca no alvo
bun run cyberlab lab experiment lab-owasp-api-bola

# Execução: só com --run explícito
bun run cyberlab lab experiment lab-owasp-api-bola --run --port 19081

# Filtros e integração
bun run cyberlab lab experiment lab-owasp-api-bola --run --only E1,E3
bun run cyberlab lab experiment lab-owasp-api-bola --run --json
bun run cyberlab lab experiment lab-owasp-api-bola --run --register
```

| Opção | Efeito |
|---|---|
| *(nenhuma)* | **Plano**: imprime cada `$ comando` e o que ficaria manual. Zero requisições. |
| `--run` | Executa de verdade e arquiva o bruto. |
| `--port N` | Redireciona o alvo (o comando registrado continua o original, para você reexecutar). |
| `--only E1,E3` | Restringe os experimentos. |
| `--json` | Máquina: `indicator`, `httpStatus`, `sha256`, `rawFile` por requisição. |
| `--register` | Guarda no EvidenceStore, inclusive uma evidência `http_exchange` por captura. |

**1. Nunca passa por shell.** Cada comando das sementes é *parseado* em uma requisição
estruturada (método, URL, headers, corpo). O subconjunto aceito é deliberadamente pequeno:
`-s -S -sS -i -k -v -L -g` (sem argumento) e `-H -X -d -A --data --data-raw --request`
(com um). Qualquer outra coisa — `Set-Content` do PowerShell, `printf` com redireção,
`-o`, `-w`, `-D` — **não é executada**: aparece como `manual` com
`Comando fora do subconjunto suportado: execute manualmente.`

> Isso é intencional. O E6 do `lab-owasp-api-bola` **aplica a remediação** no alvo
> (escreve `.server-config.json` e reinicia o servidor). Executá-lo "porque o comando
> estava ali" destruiria o laboratório vulnerável no meio do treino.

**2. Ordem vem da Fase D**, não da ordem em que as sementes foram digitadas. Sem Fase D
disponível, cai na ordem das sementes — e o relatório diz qual das duas usou.

**Arquivamento bruto.** Cada requisição executada grava
`raw/<E-id>-NN.txt` com status, headers e corpo **exatamente como vieram**, mais o
SHA-256 e o tamanho em bytes. O relatório cita o arquivo e o hash:

```
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8

{
  "accountId": "1002",
  "owner": "bob@corp.lab",
  "balanceUsd": 94500,
  "bolaFlag": "LAB{BOLA_CROSS_ACCOUNT_EXPOSED}"
}
```

**Indicador ≠ veredito.** Para cada experimento o relatório cruza a resposta com os
`observationMarkers` que a hipótese declara no perfil de pesquisa:

| Indicador | Significado |
|---|---|
| `sustenta` | Um marcador esperado apareceu numa resposta. |
| `nao_observado` | Rodou, mas nenhum marcador apareceu. |
| `sem_marcador` | A hipótese não declara marcador observável (ex.: H4 — ausência de headers) e exige leitura humana. |
| `nao_executado` | Plano, erro de rede, ou nenhum comando executável. |

Resultado real no `lab-owasp-api-bola` (target no ar, `--run`):

| # | Exp. | Hip. | Req. | Executadas | Indicador | Marcadores |
|---|---|---|---|---|---|---|
| 1 | `E3` | H2 | 4 | 4 | sustenta | `LAB{JWT_ALG_NONE_ACCEPTED}` |
| 2 | `E1` | H1 | 3 | 3 | sustenta | `LAB{BOLA_CROSS_ACCOUNT_EXPOSED}` |
| 3 | `E2` | H1 | 2 | 2 | sustenta | `LAB{BOLA_CROSS_ACCOUNT_EXPOSED}` |
| 4 | `E6` | H1 | 7 | 0 (+7 manual) | nao_executado | — |
| 5 | `E4` | H3 | 2 | 2 | sustenta | `SQLITE_ERROR` |
| 6 | `E5` | H4 | 2 | 0 (+2 manual) | nao_executado | — |

> **Bug que os testes pegaram na revisão:** o E6 saía como `nao_observado`. Tecnicamente
> "nenhum marcador apareceu" — e praticamente uma mentira, porque sugeria que a hipótese
> H1 *não se sustentou*, quando nada havia rodado. Agora, sem nenhuma requisição
> executada, o indicador é `nao_executado`. Há teste de regressão para isso.

Saídas em `research/<labId>/fase-f/<data-hora>/`: `EXPERIMENTS.md`, `experiments-f.json`,
`experiments-manifest.json` e `raw/`. O lacre SHA-256 (`experiments-f.json` sem
`files`/`seal`/`outputDir`) é o mesmo critério das Fases C e D.

### 8.13 Fases G/H/I — Avaliação, Validação e Relatório Reproduzível (v6.7)

A Fase F entrega um **indicador** ("o marcador apareceu"). Indicador não é decisão.
Estas três fases fecham o ciclo A–I:

```powershell
bun run cyberlab lab evaluate lab-owasp-api-bola   # FASE G: observado vs. esperado
bun run cyberlab lab validate lab-owasp-api-bola   # FASE H: taxonomia de 5 níveis
bun run cyberlab lab report lab-owasp-api-bola     # FASE I: writeup reproduzível
```

Cada uma consome o artefato da anterior (`fase-d` → `fase-f` → `fase-g` → `fase-h` →
`fase-i`) e **falha com o comando que falta** se você pular uma etapa. Todas aceitam
`--json`, `--out <dir>` e `--register`; `evaluate` também aceita `--only H1,H2`.

**Fase G — o diferencial é o que elimina o falso positivo.** A metodologia exige
experimento *diferenciador*: muda-se uma variável entre uma requisição de controle
(`# BASELINE`) e a experimental (`# PoC`). Se as duas voltam **idênticas** — mesmo
status e mesmo corpo — não há diferencial, e um marcador que aparece nos dois lados
não prova nada:

| Situação | Veredito |
|---|---|
| Marcador + diferencial confirmado | `sustenta` |
| Marcador sem par baseline/PoC verificável | `sustenta_com_ressalva` |
| **Baseline e PoC idênticos** | `indeterminado` (falha o achado, não o promove) |
| Nada executado | `nao_testada` |

A confiança parte de uma priori **neutra (0,50)** e cresce com **retorno decrescente**:
o 2º experimento vale metade do 1º. Dois experimentos da mesma hipótese medem quase
sempre a mesma coisa por caminhos diferentes — somá-los linearmente fingiria
independência que não existe.

> Erro que os testes pegaram: eu estava usando o **score de prioridade da Fase E** como
> probabilidade a priori. Ele responde *"vale a pena investigar?"*, não *"chance de ser
> verdade?"* — o resultado era toda hipótese saturando em 0,95 antes de qualquer
> evidência.

Nenhuma **explicação alternativa** é descartada automaticamente: elas são listadas como
pendências, porque "se a evidência contradisser a hipótese, não force a interpretação".

**Fase H — taxonomia obrigatória** (`methodologies/evidence-validation.md`), com viés
conservador: na dúvida, cai na categoria mais fraca. Cada linha cita a regra que disparou.

| Categoria | Quando |
|---|---|
| **Vulnerabilidade confirmada** | `sustenta` + par baseline↔PoC verificado + impacto em C/I/A |
| **Vulnerabilidade potencial** | Há indício forte, mas sem par verificável |
| **Configuração insegura** | Mecanismo de proteção ausente/desligado, sem vetor direto |
| **Falha funcional** | 5xx sem impacto em C/I/A (bug de produto) |
| **Comportamento inesperado** | Resposta atípica com diferencial, sem violação demonstrada |
| **Não classificado** | Sem evidência suficiente — o relatório diz isso, não inventa |

O impacto por hipótese é **declarado** no perfil de pesquisa (`impactByHypothesis`),
não deduzido do texto: inferir "é vulnerabilidade ou é hardening" por casamento de
palavras faria a classificação mudar quando alguém reescreve uma frase.

**Fase I — writeup com as 6 seções do padrão**, preenchido só com o que as fases
anteriores registraram. E com redação obrigatória: tokens e segredos são redigidos
antes da publicação.

> **Vazamento real encontrado por teste:** o padrão de redação exigia `Authorization:`
> com dois-pontos limpos, mas dentro de um corpo JSON o header vem como
> `"authorization":"Bearer …"` — as aspas quebravam o casamento e **o token vazava
> inteiro no relatório**. Corrigido em `cyberlab/evidence/provenance.ts`, com padrão
> novo para token solto no corpo. O writeup agora sai com 0 tokens e 5 redações.

Resultado real encadeado no `lab-owasp-api-bola` (target no ar):

| Hip. | G — veredito | Confiança | H — classificação |
|---|---|---|---|
| H1 BOLA | sustenta | 0,95 | **Vulnerabilidade confirmada** |
| H2 JWT `alg:none` | sustenta | 0,80 | **Vulnerabilidade confirmada** |
| H3 Erro SQL | sustenta | 0,80 | **Vulnerabilidade confirmada** |
| H4 Headers | nao_testada | 0,50 | Configuração insegura (hardening) |

**As fases do ciclo não aparecem na interface web**: o workbench cobre labs, arsenal,
escopo e evidências, e o ciclo C→I é todo via CLI. Não é ponta solta — nunca esteve lá.

## 1. Inicialização Rápida (terminal do Kali)

### 1.1 Requisitos

| Requisito | Versão | Observação |
|---|---|---|
| **Kali Linux** (ou qualquer Debian/Ubuntu) | 2024.x+ | nativo — **sem WSL2, sem VM convidada, sem Windows** |
| **Bun** | `1.4.4` | `curl -fsSL https://bun.sh/install | bash` |
| **Git** | 2.x | para clonar e atualizar |

As ferramentas de segurança (`nmap`, `nuclei`, `ffuf`, `tshark`, `sqlmap`, `ghidra`,
`jadx`, …) **não são instaladas pelo CyberLab**: use as que você já tem. Se faltar
alguma, instale você mesmo com o `apt` do Kali:

```bash
sudo apt update && sudo apt install -y nmap nuclei ffuf tshark sqlmap ghidra jadx
```

### 1.2 Clonar e instalar

```bash
git clone https://github.com/vitorveloster18-lang/CyberLab-OS.git
cd CyberLab-OS
bun install --ignore-scripts
bun run --cwd packages/core fix-node-pty
```

### 1.3 Os comandos do dia a dia

```bash
# Estado do workspace (escopo, capacidades, evidências)
bun run cyberlab status

# Declarar o escopo autorizado ANTES de qualquer execução (tudo ou nada)
bun run cyberlab scope 10.0.0.0/24 exemplo.com        # alvos internos
bun run cyberlab scope --external exemplo.com         # libera alvo público/roteável
bun run cyberlab scope                                # mostra o escopo vigente
bun run cyberlab scope --clear                        # encerra a autorização

# Rodar uma ferramenta do seu Kali sob guarda do CyberLab
bun run cyberlab exec -- nmap -sV -p 80,443 10.0.0.10
bun run cyberlab exec -- nuclei -u https://exemplo.com -t exposures/
bun run cyberlab exec --timeout 120 -- curl -s -i https://exemplo.com/login

# Evidências, achados e relatório
bun run cyberlab evidence                             # lista com SHA-256
bun run cyberlab evidence --verify <id da evidência>  # reconfere a custódia
bun run cyberlab findings
bun run cyberlab report > relatorio.md
```

`cyberlab exec` faz três coisas que o terminal puro não faz:

1. **Trava de escopo** — recusa o comando se o alvo não estiver no escopo declarado;
2. **Redação de segredos** — tokens, senhas e chaves na saída são mascarados antes de
   irem para o contexto do agente;
3. **Custódia `SHA-256`** — cada execução vira um registro de evidência com id próprio,
   referenciado depois no relatório.

Saída crua é repassada integralmente no `stdout`; no `stderr` você recebe um rodapé:

```text
— cyberlab exec · exit=0 · 3.2s · (saída redigida) · evidência=evt_01J...
```

### 1.3.1 Interface do OpenCode no terminal (TUI)

O CyberLab OS é o **OpenCode com as customizações do CyberLab** — a mesma interface
interativa de terminal do OpenCode original, com o agente `Orchestrator`, as ferramentas
do workspace e a identidade visual do CyberLab. Para abrir:

```bash
bun run cyberlab:tui
```

Isso sobe o TUI (terminal UI) do OpenCode dentro da pasta do projeto — a **interface
original do OpenCode**, com as funcionalidades do CyberLab disponíveis por baixo:

- **Interface original do OpenCode** — logo, tema e comandos padrão do OpenCode,
  sem alterações visuais;
- **Agentes do CyberLab disponíveis** — aperte `Tab` para alternar para o
  `Orchestrator` (investigação orientada por hipóteses, biblioteca
  `CyberLab-Knowledge`, validação de evidências) ou outro subagente;
- **Ferramentas do workspace** — o agente enxerga as capacidades registradas
  (`cyberlab_status`, `cyberlab_execute`, `cyberlab_evidence`, …) e o escopo
  declarado em `.cyberlab/scope.json`;
- **Modelo gratuito padrão** — o config do projeto (`.opencode/opencode.jsonc`) já
  define um modelo free, então o TUI funciona logo após o clone, sem API key.

> Não existe mais servidor web nem `cyberlab up`/`studio`: a interface é o próprio
> terminal. Feche com `Ctrl+C` ou `/exit`.

### 1.4 Subir um laboratório de treino

```bash
bun run cyberlab lab list
bun run cyberlab lab start lab-owasp-api-bola --daemon
bun run cyberlab lab status lab-owasp-api-bola
bun run cyberlab lab stop   lab-owasp-api-bola
```

### 1.5 Biblioteca de conhecimento

```bash
bun run cyberlab knowledge            # mostra o plano de sincronização
bun run cyberlab knowledge --apply    # aplica (cria o cofre se não existir)
```

O cofre é criado em `<workspace>/vault/CyberLab-Knowledge/` na primeira execução,
sem sobrescrever nada que você tenha escrito.

---

## 2. Primeira Tarefa Recomendada (Calibração do Orquestrador)

Com o agente **`Orchestrator`** selecionado, envie este prompt inicial para calibrar o
inventário de conhecimento do seu ambiente **sem tocar em nenhum alvo**:

> **Prompt inicial recomendado:**
> *"Mapeie o conhecimento técnico disponível. Identifique quais capacidades estão comprovadas, quais ainda não foram validadas e quais lacunas de conhecimento limitam uma investigação orientada por hipóteses."*

O `Orchestrator` irá:
1. Consultar o catálogo curado em `CyberLab-Knowledge/` (`search_knowledge`,
   `read_document("00-Index")`);
2. Listar os binários realmente disponíveis no `PATH` — ele faz isso pedindo para você
   rodar `cyberlab exec -- which <ferramenta>`, nunca chutando;
3. Entregar um diagnóstico estruturado separando **capacidades comprovadas**,
   **capacidades pendentes de validação** e **lacunas de conhecimento**, registrando o
   baseline na memória investigativa.

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

## 5. Servidor MCP da Biblioteca de Conhecimento (`cyberlab-knowledge`)

O CyberLab OS **não reempacota ferramenta nenhuma**: quem executa `nmap`, `nuclei`,
`ffuf`, `tshark`, `ghidra`, `jadx`, `sqlmap` ou qualquer outro binário é você, no
terminal do seu Kali. O que o CyberLab publica via MCP é a **Biblioteca de
Conhecimento** — `cyberlab/mcp/knowledge-mcp-stdio.ts`, um servidor `stdio` de
processo único, sem arsenal, sem ponte GUI e sem probe de WSL.

```bash
bun run cyberlab/mcp/knowledge-mcp-stdio.ts --workspace /caminho/do/projeto
```

| Ferramenta MCP | O que faz |
|---|---|
| `search_knowledge` | Busca full-text na biblioteca curada (título, resumo, corpo e tags) |
| `read_document` | Lê um documento por `id`/caminho, com frontmatter e `[[WikiLinks]]` |
| `list_documents` | Lista a árvore curada por categoria |
| `get_related_documents` | Navega o grafo `[[WikiLinks]]` a partir de um documento |
| `record_investigation_note` | Grava nota da sessão na **Camada 2** (contexto da sessão) |
| `search_investigation_notes` | Recupera notas da sessão por texto/período/projeto |
| `promote_note_to_curated` | Promove uma nota validada para a **Camada 1** (curada) — exige revisão |
| `get_knowledge_status` | Estado da biblioteca, contagens por camada e versão do índice |

**Separação epistemológica em 3 camadas (mantida do v6.2)**: *Camada 1* = conhecimento
curado e versionado; *Camada 2* = contexto da sessão (notas descartáveis); *Camada 3* =
conhecimento externo (tudo que vem de fora, marcado como não confiável até virar
evidência).

### 5.1 9 Modelos de IA Gratuitos Nativos do OpenCode Zen

Prontos para uso imediato sem chave paga (`apiKey: "public"`, configurados
automaticamente com `--use-system-ca`): `Big Pickle`, `DeepSeek V4.1 Flash Free`,
`GLM-5.3 Flash Free`, `Nemotron 3.5 Super VL Free`, `Nemotron 3.5 Lightning Free`,
`Nemotron 3 Ultra Free`, `MiMo V2.6 Flash Free`, `Flint 40B Free` e `Beam Free` — além
de suporte total a qualquer provedor Anthropic, OpenAI, Gemini, OpenRouter, Ollama ou
LM Studio local.

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

## 11. Histórico de Versões (`v1.0` → `v7.0`), Verificação CI & Licenciamento MIT

- **v1.0 – v4.0**: Base OpenCode V2 (`2.1.4`), governança anti-TOCTOU, cofre `SHA-256`, 4 CDIs (`8788–8791`), 5 Labs de Treino e 9 modelos gratuitos OpenCode Zen.
- **v5.0 – v5.8**: Arquitetura **Real Arsenal Edition** (3 colunas Antigravity, motor `X11/noVNC` 110 DPI, navegador proxy em 1 clique e empacotamento de ferramentas).
- **v5.9**: Topo horizontal retrátil na vertical (`28px`) + resiliência a boot frio do WSL2 `kali-linux`.
- **v6.0 – v6.1**: Cofre nativo flutuante/acoplável compatível com Obsidian (`Alt+N`) e **Hub MCP Unificado (`cyberlab-arsenal`)** consolidando os slots num único processo.
- **v6.2**: **Investigative Security Orchestrator** em `pt-BR` (Ciclo Fases A–I + validação em 5 níveis), **6 Subagentes Especializados sob demanda** com limites rígidos de profundidade (`1`), concorrência (`3`) e quantidade por sessão (`12`), biblioteca curada **`CyberLab-Knowledge/`** integrada ao Cofre Obsidian com **8 tools MCP de Conhecimento e Memória Investigativa** (preservando resultados negativos e imutabilidade dos documentos curados) e atualização integral da documentação.
- **v6.3**: **Paridade de Runtime WSL2 + Expansão da Biblioteca Curada (34 docs)** — correção da divergência entre o status dos slots MCP e o das capabilities `external.*`. Biblioteca curada expandida de 20 → **34 documentos** cobrindo JWT/OAuth, CSRF/CORS/SameSite, TLS & cripto, SSRF, desserialização/XXE/upload, GraphQL/WebSocket, cache poisoning/deception, race conditions (protocolo concorrente N=20), mass assignment/BOPLA/rate limiting, mobile, engenharia reversa, cloud/IAM/contêineres, logging/forense e fluxos com IA orientados por hipótese.

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
  aponta para o fluxo de terminal (`lab status` / `cyberlab exec`), mostra o estado real dos 4
  controles de `server-config.json`, lista os endpoints clicáveis com o invariante esperado e traz o
  comando `curl` pronto. `GET /health` continua JSON (usado por scripts e pela sonda TCP do
  `lab status`). *(A referência à porta `4096` vale só até a v6.7; na v7.0 não há interface web.)*

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
    preciso e subir o laboratório em segundo plano. *(Removido na v7.0 — veja abaixo.)*
  - Biblioteca curada: **36 documentos** (novo `targets/portswigger-web-security-academy.md`).

- **v6.6**: **Processo único + navegador do alvo embutido (estilo Burp Suite).**
  - O laboratório passa a ser hospedado pelo **próprio servidor da interface**, não pelo
    processo lançador. Antes eram dois `TrainingLabManager` distintos e a UI nem mostrava
    o lab como "rodando". `bun run cyberlab up` agora sobe **um único processo**.
  - Visão `5 Labs de Treino` ganha o **🌐 Navegador do alvo (embutido)**: iframe do alvo com
    recarregar, fechar e `↗ Abrir no navegador do sistema` — o equivalente ao Chromium do
    Burp. Avisa explicitamente quando `enableSecurityHeaders` bloqueia o iframe.
  - Interface e CLI passam a usar a **mesma raiz** (`.cyberlab/training-labs/`, respeitando
    `CYBERLAB_LABS_ROOT`), e `lab status` detecta o lab rodando na interface via sonda
    `/health`, reportando `RODANDO em OUTRO processo` em vez de "parado".
  - `cyberlab up --daemon` mantém o modo antigo (alvo em processo separado).

- **v6.7**: **O agente não destrói nada sem perguntar + cofre sincronizado + evidência visível.**
  - Nova `cyberlab/safety/destructive-guard.ts`: catálogo de operações destrutivas com risco,
    consequências e requisito de liberação. Sem confirmação, **falha fechada** e responde
    `HTTP 400` com o plano completo (usa `InvalidRequestError`, que é erro declarado no
    contrato — lançar genérico virava 500 com corpo vazio e o agente ficava sem o plano).
    `vault.delete` é `irreversível` e exige `confirmPhrase` digitada exata.
    A interface envia `confirm: true` (o clique do operador é a confirmação).
  - `cyberlab knowledge` / `library-sync.ts`: corrige a causa raiz do índice desatualizado —
    a semeadura nunca sobrescrevia. Plano por padrão, `--apply` para escrever, backup `.bak`
    antes de cada troca e arquivo do operador (`tier != curated`) intocado.
  - `00-Index.md` corrigido (35 docs + índice; vulnerabilidades 10, não 9) com `version`
    bumpada para `1.1.0`, para a sincronização detectar a mudança no cofre.
  - `lab evidence --register` grava cada requisição também no `EvidenceStore` (SQLite),
    acabando com o "0 registros" da calibração.
  - CI passa a rodar `tests/cyberlab/safety` e `tests/cyberlab/knowledge`.
  - **Correção da tela vermelha**: a guarda exigia `confirm`, mas a interface chamava
    `labs/control` (stop/reset) e `vault/delete` sem ele → `HTTP 400` em cascata.
    `state.tsx` agora envia `confirm: true` (menos em `start`, que não é destrutivo) e
    `vault/delete` avisa no `window.confirm` que **não há lixeira**. Coberto por
    `tests/cyberlab/safety/ui-confirmation-wiring-v67.test.ts`, que varre
    `packages/app/src` e falha se qualquer chamada a rota protegida esquecer o `confirm`.
  - **`cyberlab lab tools`**: mostra as ferramentas do catálogo (✔/✘), a origem
    esperada e a dica de instalação; `--missing`, `--json` e `--script`.
  - **`cyberlab lab slots`**: lista os slots, separa catálogo de personalizados,
    aponta duplicatas por nome normalizado e mostra os problemas de higiene
    (`--health`, `--json`). *(Ambos removidos na v7.0.)*

### v7.0 — Kali nativo: método, escopo e custódia sem reempacotar ferramenta

A v7.0 remove tudo o que existia só para **embutir ou alcançar** ferramentas de outro
sistema operacional. O CyberLab passa a ser a camada de método, escopo e custódia — as
ferramentas são as que você já tem no Kali.

- **Removidos**: workbench web do CyberLab (`packages/app/src/cyberlab-workbench/`),
  Arsenal de 48 slots (`cyberlab/arsenal/`), ponte de VM e runtime WSL2
  (`cyberlab/external/`), servidor MCP do arsenal, proxy embutido e CA local
  (`cyberlab/proxy/`), e os comandos `cyberlab up`, `cyberlab studio`, `cyberlab
  external` e `cyberlab app/start/serve`.
- **Mantidos**: Orquestrador Investigativo e os 6 subagentes, trava de escopo, pipeline
  de evidência `SHA-256`, redação de segredos, guarda de operações destrutivas, hub dos
  4 CDIs, biblioteca curada e o pacote `reporting/`.
- **Novo transporte MCP da biblioteca**: `cyberlab/mcp/knowledge-mcp-stdio.ts`
  (`cyberlab-knowledge`, 8 ferramentas) substitui o hub do arsenal, para que a
  `CyberLab-Knowledge/` continue acessível via MCP sem carregar nenhuma ponte de
  ferramenta.
- **`cyberlab exec`**: roda qualquer binário do seu Kali sob trava de escopo, redação e
  custódia de evidência — o comando é seu, a governança é do CyberLab.
- **`cyberlab knowledge`** passa a semear o cofre sozinho (antes isso só acontecia
  quando a interface subia).
- **Nada de servidor escondido**: `bun run cyberlab` sem argumentos mostra a ajuda no
  terminal, em vez de subir uma aplicação web.

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

# 3. Suíte automatizada de testes (193+ testes)
bun --cwd cyberlab test
```

> **Falha aqui pode ser da sua máquina, não do código.** Alguns testes dependem de
> pré-requisitos que nem todo Windows tem: **Python no PATH** (parceiros CDI e
> `chat_py_bridge.py`) e **permissão de criar symlink** (Developer Mode ou
> administrador). Quando o pré-requisito falta, o teste é **PULADO com o motivo
> explícito** — nunca aprovado calado, nunca falho por ambiente:
>
> ```
>  171 pass
>  4 skip     # sem Python no PATH
>  0 fail
> ```
>
> Para manter a cobertura completa, instale o interpretador:
> `winget install Python.Python.3.12` (e reabra o PowerShell).

### Documentação Complementar
- [`docs/PLAYBOOK_KALI_NATIVO.md`](docs/PLAYBOOK_KALI_NATIVO.md) — **Playbook oficial**: todos os comandos prontos para o terminal do Kali.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Arquitetura de governança, execução e custódia criptográfica.
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — Modelo de ameaças, anti-TOCTOU, redação e protocolo `HMAC-SHA256`.
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — Política de conformidade `MIT` e isolamento de ferramentas externas.
- [`docs/UPSTREAM_AUDIT.md`](docs/UPSTREAM_AUDIT.md) — Auditoria técnica da base OpenCode V2 (`2.1.4`).
