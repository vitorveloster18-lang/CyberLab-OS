# Auditoria Técnica Automatizada do Upstream — OpenCode V2 (`2.1.4`)

Esta auditoria resolve todos os pontos em aberto da **Seção 2 ("Onde ainda não vou afirmar um caminho exato")** e da **Seção 13 ("Próxima ação recomendada")** do plano técnico, utilizando exclusivamente caminhos, símbolos e números de linha extraídos do commit fixado.

---

## 1. Identificação do Commit Fixado e Linha de Base

- **Repositório upstream**: `https://github.com/anomalyco/opencode`
- **Commit SHA fixado**: `dae4077a96243257ea0a2086068504b791629f10`
- **Versão (`package.json:5`)**: `2.1.4`
- **Licença (`package.json:144`, `LICENSE`)**: `MIT`
- **Gerenciador / Runtime (`package.json:8`)**: `bun@1.4.4`
- **Stack arquitetural real confirmada**:
  - `effect@4.0.1` (`Context.Service`, `Layer`, `Effect.fn`, `Schema`, `HttpApi`, `effect/cli`)
  - `drizzle-orm@1.0.0-rc.5-169397b` + `@effect/sql-sqlite-bun@4.0.1` (`bun:sqlite` com WAL + `chmod 0600`)
  - `solid-js@1.9.15` + `@opentui/solid@0.7.0` + sistema modular de GUI plugins (`packages/gui-plugins`)

### Resultados da Verificação da Linha de Base

| Comando executado | Resultado verificado |
| --- | --- |
| `bun --cwd packages/schema typecheck` | `0` erros em 123 arquivos (`~0.4s`) |
| `bun --cwd packages/core typecheck` | `0` erros em 1.717 arquivos (`~7.4s`) |
| `bun --cwd packages/server typecheck` | `0` erros em 1.337 arquivos (`~4.9s`) |
| `bun --cwd packages/cli typecheck` | `0` erros em 1.907 arquivos (`~6.1s`) |
| `bun --cwd packages/gui-plugins typecheck` | `0` erros em 1.171 arquivos (`~2.8s`) |
| `bun --cwd packages/schema test` | `89 pass / 0 fail` |
| `bun --cwd packages/util test` | `135 pass / 0 fail` |
| `bun --cwd packages/core test test/database.test.ts test/bus.test.ts` | `56 pass / 0 fail` (54 migrações SQLite aplicadas em ~5ms) |

> **Observação operacional crítica**: no OpenCode V2 (`2.1.4`), o script `typecheck` usa `bun check --no-script` (verificador nativo do Bun 1.4.4), enquanto `typecheck:tsc` invoca o compilador JS `tsc -b`, que pode exceder 4 GB de RAM ao inferir grafos profundos do Effect 4 em `packages/core`. Sempre prefira `bun --cwd <pacote> typecheck`.

---

## 2. Resolução dos Pontos Exatos de Integração no Código Real

### 2.1. Registro de Ferramentas no Núcleo (`packages/core`)

- **Serviço central**: `packages/core/src/tool.ts`
  - `Tool.Service` (`Context.Service` `@opencode/Tool`, linha `67`) expõe `transform(editor => ...)` (`State.Transformable<Editor>`, linhas `26-46`), `list()` e `snapshot(permissions?)`.
  - `executeTool` (`packages/core/src/tool.ts:115-158`) dispara `PluginHooks` (`execute.before` e `execute.after`), normaliza conteúdo (`normalizeContent`, `normalizeImages`) e captura `Tool.Error`.
- **Como ferramentas internas são registradas**: `packages/core/src/plugin/internal.ts`
  - As ferramentas nativas (`ReadTool`, `ShellTool`, `SkillTool`, `OpenCodeTools`, `WebFetchTool`, etc.) são plugins internos Effect listados no array `pre` (`packages/core/src/plugin/internal.ts:217-252`).
  - Exemplo real: `packages/core/src/tool/plugin/read.ts:29-47` registra a ferramenta chamando `yield* ctx.tool.transform((editor) => editor.add({ name, description, input, output, execute }))`.
- **Decisão para o CyberLab**: criar `packages/core/src/plugin/cyberlab.ts` registrado em `PluginInternal` (`pre`), expondo ferramentas estruturadas do CyberLab (`cyberlab_capabilities`, `cyberlab_execute`, `cyberlab_evidence`, `cyberlab_findings`) que delegam obrigatoriamente ao `ExecutionController` e ao `PolicyEngine` de `@cyberlab/core`.

### 2.2. Ciclo de Execução e Cancelamento de Tarefas

- **Coordenação de execução de sessão**: `packages/core/src/session/execution.ts`
  - `SessionExecution.Service` (`@opencode/SessionExecution`, linhas `17-43`) gerencia `active`, `isActive`, `resume`, `wake`, `interrupt(sessionID, options)` e `awaitIdle(sessionID)`.
  - Usa interrupção estruturada de fibras Effect (`Cause.hasInterrupts(exit.cause)`, linhas `47-51`) e *write-ahead claim* transacional no SQLite (`claimOnCommit`, linhas `78-80`).
- **Contexto de ferramenta**: `@opencode/schema/tool` (`packages/schema/src/tool.ts`) fornece `Tool.Context` com `sessionID`, `messageID`, `agent` e suporte a interrupção via Effect / `AbortSignal`.
- **Decisão para o CyberLab**: o `ExecutionController` (`cyberlab/execution/`) mantém registros explícitos (`ExecutionRecord` com status `draft`, `awaiting_approval`, `queued`, `running`, `succeeded`, `failed`, `cancelled`, `blocked`, `timed_out`) e propaga `AbortSignal` tanto do cancelamento manual (`cancel(executionId)`) quanto da interrupção de fibra da sessão OpenCode.

### 2.3. Motor de Permissões e Políticas Existente

- **Serviço de permissões**: `packages/core/src/permission.ts`
  - `Permission.Service` (`@opencode/Permission`, linha `100`) expõe `evaluate(action, resource, ...rulesets)` (linhas `74-84`), `ask`, `assert` e `reply`.
  - Regras seguem `{ action, resource, effect: "allow" | "deny" | "ask" }` com correspondência `Wildcard.match`.
  - Regras negadas disparam `Permission.BlockedError` (`linhas 57-66`); aprovações pendentes usam `Deferred` e publicam `Permission.Event.Replied` no `Bus.Service` (`linhas 102-131`).
  - Políticas gerenciadas adicionais residem em `packages/core/src/managed-policy.ts` e `packages/core/src/config/plugin/policy.ts` (protegido em `PluginInternal.guarded`, `packages/core/src/plugin/internal.ts:276`).
- **Decisão para o CyberLab**: reutilizar a semântica `allow | deny | ask`, adicionando em `cyberlab/policy/` o confinamento de escopo de rede/ativos (`CIDR`, IPv4/IPv6, domínios, URLs, workspace) e a **reautorização obrigatória no instante da execução** (mesmo após aprovação prévia), bloqueando qualquer expansão acidental para redes externas.

### 2.4. Descoberta e Preparação Nativa de Skills

- **Serviço e formato nativo**:
  - `packages/core/src/skill.ts`: `Skill.Service` (`@opencode/Skill`, linha `93`), `Skill.available` (`linhas 33-34`, filtrando por `Permission.evaluate("skill", skill.id, permissions)`), e `Skill.prepare` (`linhas 55-74`), que automaticamente escaneia até 10 arquivos auxiliares irmãos quando o arquivo principal chama-se `SKILL.md`!
  - `packages/core/src/config/plugin/skill-scan.ts` (`linhas 11-46`): escaneia diretórios de skills até `MAX_DEPTH = 6` procurando `SKILL.md`.
  - `packages/core/src/plugin/skill.ts` (`linhas 23-48`): demonstra como skills embutidas no produto são registradas via `ctx.skill.transform((editor) => editor.add(Skill.Info.make({ ... })))`.
- **Decisão para o CyberLab**: versionar as skills em `skills/<skill-name>/SKILL.md` com arquivos metodológicos auxiliares (`methodology.md`, `evidence-format.md`, `validation-checklist.md`) e registrá-las nativamente no `Skill.Service` pelo plugin interno do CyberLab, sem criar um sistema paralelo de skills.

### 2.5. Persistência Existente vs. Armazenamento de Evidências

- **Infraestrutura existente**:
  - `packages/core/src/database/database.ts`: SQLite via Drizzle + Effect (`@opencode/storage/Database`, linha `26`), `PRAGMA journal_mode = WAL`, `PRAGMA foreign_keys = ON` e permissões restritas ao dono (`chmod 0o600` no banco e nos sidecars `-wal`/`-shm`, `linhas 85-98`).
  - `packages/core/src/session/blob.ts`: armazena anexos/blobs de mensagens de sessão codificados em base64 na tabela `blob`/`blob_ref`.
  - `packages/core/src/kv/sql.ts`: tabela simples `kv (key, value JSON, time_created, time_updated)`.
- **Análise arquitetural e decisão**:
  - Alterar as 54 migrações geradas (`packages/core/src/database/migration.gen.ts`) do banco de sessões do upstream criaria conflitos diretos a cada atualização do OpenCode V2.
  - Em vez disso, o `EvidenceStore` do CyberLab (`cyberlab/evidence/store.ts`) utiliza o **mesmo motor `bun:sqlite` com WAL e `chmod 0o600`** em um arquivo dedicado por workspace/ambiente (`cyberlab-evidence.sqlite` dentro do diretório de dados do projeto/CyberLab) aliado a um **armazenamento local endereçado por conteúdo (`artifacts/<sha256>`)** para artefatos grandes, mantendo zero conflito de migração com o upstream e cadeia de custódia forense isolada e exportável!

### 2.6. Contratos Públicos (`packages/schema`, `packages/protocol`, `packages/server`)

- **Schemas compartilhados**: `packages/schema/src/*.ts` usa `Schema` do `effect` (`Schema.Struct`, `Schema.Class`, `Schema.Literals`, `Schema.TaggedError`).
- **Protocolo HTTP tipado**: `packages/protocol/src/api.ts` compõe grupos `HttpApiGroup.make("server.<grupo>")` (`packages/protocol/src/groups/*.ts`, ex.: `groups/skill.ts:7-27`).
- **Servidor HTTP**: `packages/server/src/handlers.ts:36-69` combina handlers `HttpApiBuilder.group(Api, "server.<grupo>", ...)` com `Layer.mergeAll(...)`, montados em `packages/server/src/routes.ts`.
- **Decisão para o CyberLab**: adicionar `packages/schema/src/cyberlab.ts`, `packages/protocol/src/groups/cyberlab.ts` (`/api/cyberlab/*`) e `packages/server/src/handlers/cyberlab.ts`, preservando 100% os contratos existentes de sessão e mensagens.

### 2.7. CLI (`packages/cli`) e Interface Gráfica (`packages/gui-plugins` + `packages/app`)

- **CLI**: `packages/cli/src/commands/commands.ts:48-70` declara a árvore de subcomandos usando `Spec.make(...)` sobre `effect/cli`, com handlers em `packages/cli/src/commands/handlers/`. Adicionaremos o grupo `opencode cyberlab` (`status`, `capabilities`, `scope`, `run`, `evidence`, `findings`, `inventory`).
- **Aplicação Web / Desktop**: `packages/app/src/runtime/plugin/builtins.ts` carrega `builtins` de `packages/gui-plugins/src/renderer.ts` (`linhas 37-52`) e `packages/gui-plugins/src/main.ts` (`linhas 18-33`). Painéis laterais nativos (`review`, `details`, `terminal`, `btw`) usam `Plugin.define` + `ctx.add(Panel, ...)` + SolidJS. Adicionaremos o plugin GUI nativo `packages/gui-plugins/src/cyberlab/` para operação manual, aprovação, inspeção de evidências SHA-256 e revisão de achados no mesmo workspace!

---

## 3. Mapa Consolidado: Existente no Upstream vs. Novo no CyberLab OS

| Caminho | Origem | Ação no CyberLab OS |
| --- | --- | --- |
| `packages/schema/src/cyberlab.ts` | **Novo** | Schemas Effect compartilhados para API/UI do CyberLab |
| `packages/protocol/src/groups/cyberlab.ts` | **Novo** | Grupo `HttpApiGroup` `/api/cyberlab/*` |
| `packages/protocol/src/api.ts` | Upstream existente | Registrar `CyberLabGroup` sem alterar rotas existentes |
| `packages/server/src/handlers/cyberlab.ts` | **Novo** | Handlers HTTP ligados ao workspace CyberLab |
| `packages/server/src/handlers.ts` | Upstream existente | Incluir `CyberLabHandler` em `Layer.mergeAll` |
| `packages/core/src/plugin/cyberlab.ts` | **Novo** | Plugin interno que registra skills e tools do CyberLab |
| `packages/core/src/plugin/internal.ts` | Upstream existente | Adicionar `CyberLabInternalPlugin` em `pre` |
| `packages/cli/src/commands/handlers/cyberlab.ts` | **Novo** | Subcomandos CLI `cyberlab` |
| `packages/cli/src/commands/commands.ts` | Upstream existente | Registrar especificação `Spec.make("cyberlab", ...)` |
| `packages/gui-plugins/src/cyberlab/*` | **Novo** | Painel visual unificado de escopo, execuções, evidências e achados |
| `packages/gui-plugins/src/{main,renderer}.ts` | Upstream existente | Registrar o plugin GUI `cyberlab` em `builtins` |
| `cyberlab/**` | **Novo** | Pacote `@cyberlab/core`: contratos, políticas, evidências, execução, parceiros e relatórios |
| `integrations/**` | **Novo** | Executores estruturados de leitura e ferramentas aprovadas |
| `skills/**` | **Novo** | Skills metodológicas `SKILL.md` compatíveis com OpenCode V2 |
| `vendor/**` | **Novo** | Baseline upstream, manifestos de licenças e avisos de terceiros |
| `tests/cyberlab/**` | **Novo** | Suíte completa de testes unitários, segurança e integração |
