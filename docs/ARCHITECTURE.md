# Arquitetura do CyberLab OS

## 1. Visão Geral

O **CyberLab OS** é uma distribuição personalizada do **OpenCode V2** (`anomalyco/opencode` v2.1.4) voltada para avaliações de segurança autorizadas, auditoria de código e configuração, engenharia reversa assistida e revisão forense de evidências.

A arquitetura segue o princípio central: **reconstruir o produto como experiência integrada, preservando o núcleo do OpenCode V2 sempre que possível**.

---

## 2. Estratégia em Três Níveis

### Nível A — Alterações Mínimas no Núcleo (`packages/*`)
- Reutiliza integralmente sessões, mensagens, modelos, provedores, terminal PTY, banco SQLite de sessões e motor de permissões do OpenCode V2.
- Conecta o CyberLab por pontos de extensão cirúrgicos já previstos pela arquitetura V2:
  - `packages/core/src/plugin/internal.ts` (tools e skills embutidas via Effect);
  - `packages/schema/src/cyberlab.ts` + `packages/protocol/src/groups/cyberlab.ts` + `packages/server/src/handlers/cyberlab.ts` (rotas HTTP tipadas `/api/cyberlab/*`);
  - `packages/cli/src/commands/commands.ts` (subcomando `opencode cyberlab`).

### Nível B — Domínio Próprio (`cyberlab/` — `@cyberlab/core`)
Concentra toda a inteligência operacional e de segurança que não existe no upstream:
- `cyberlab/contracts/`: contratos TypeScript + validação em runtime (`effect/Schema`) para capacidades, execuções, evidências, achados, políticas, manifestos e protocolo de parceiros.
- `cyberlab/registry/`: registro controlado de capacidades, executores e skills (impedindo auto-registro arbitrário por agentes remotos).
- `cyberlab/policy/`: avaliação de risco, escopo ativo (`CIDR`, IP, domínio, URL, workspace), aprovação humana (`ask`) e reautorização obrigatória no momento exato da execução.
- `cyberlab/execution/`: `ExecutionController`, cancelamento estruturado (`AbortSignal`), timeouts, limites de bytes de saída e normalização preservando a saída bruta antes de qualquer síntese de IA.
- `cyberlab/evidence/`: persistência SQLite (`WAL` + `0o600`) + armazenamento local de artefatos por SHA-256, proveniência, cadeia de custódia e redação automática de segredos.
- `cyberlab/partners/`: ponte `cyberlab-partner` v1.0 com assinatura HMAC-SHA256, deduplicação/anti-replay, contexto mínimo redigido e isolamento de respostas não confiáveis.
- `cyberlab/reporting/`: geração de relatórios técnicos e pacotes exportáveis de evidências com manifesto de integridade SHA-256.

### Nível C — Experiência Unificada (`integrations/`, `skills/`, CLI e UI)
- Operações manuais (via CLI `opencode cyberlab run` ou painel visual CyberLab) e operações assistidas pela IA compartilham **exatamente o mesmo projeto, escopo, histórico de execuções, banco de evidências e fila de revisão de achados**.

---

## 3. Fronteiras Estritas entre Diretórios

```text
CyberLab-OS/
├── packages/         # Pacotes do produto OpenCode V2 (modificações mínimas e rastreáveis)
├── cyberlab/         # Domínio próprio (@cyberlab/core) — contratos, política, execução, evidências, parceiros
├── integrations/     # Adaptadores estruturados para executores internos e ferramentas aprovadas
├── skills/           # Skills metodológicas (SKILL.md + guias auxiliares; nunca concedem privilégio)
├── vendor/           # Baseline upstream, manifestos de licenças e avisos de terceiros
├── docs/             # Auditoria upstream, arquitetura, modelo de segurança, inventário e licenças
└── tests/cyberlab/   # Suíte de testes de contratos, políticas, evidências, execução, parceiros e hardening
```

Regras invariantes:
1. `cyberlab/` nunca duplica o motor de sessões/LLM do OpenCode V2.
2. `integrations/` contém **adaptadores tipados**, nunca concatenação de strings livres em shell.
3. `skills/` contém metodologia operacional e critérios de validação; o `PolicyEngine` permanece a única autoridade de execução.
4. `vendor/` só admite componentes com origem, commit, licença e avisos documentados e aprovados.

---

## 4. Topologia Local: Kali nativo

```text
┌──────────────────────────────────────────────────────────────────┐
│ Kali Linux (nativo — sem WSL2, sem VM convidada, sem Windows)    │
│  • Bun 1.4.4 + OpenCode V2 + @cyberlab/core                      │
│  • EvidenceStore (SQLite 0600 + artefatos SHA-256)               │
│  • cyberlab exec  →  binários que VOCÊ já tem no PATH            │
└───────────────┬───────────────────────────────┬──────────────────┘
                │ Rede Docker isolada de lab    │ Ponte autenticada HMAC
┌───────────────▼──────────────────┐ ┌──────────▼──────────────────┐
│ Containers Docker Isolados       │ │ Runtimes de Agentes         │
│  • Aplicações/alvos de teste     │ │ Parceiros Externos          │
└──────────────────────────────────┘ └─────────────────────────────┘
```

**O CyberLab OS não embute, não instala e não alcança ferramentas de outro sistema
operacional.** O binário é resolvido pelo `PATH` do seu próprio Kali; o CyberLab
contribui com trava de escopo, redação de segredos e custódia `SHA-256`.

Práticas recomendadas para o ambiente local:
- Manter o repositório em sistema de arquivos `ext4` nativo (`~/src/cyberlab-os`) para máximo desempenho de I/O com Bun e SQLite WAL.
- Isolar laboratórios vulneráveis em redes Docker internas (`--internal` ou bridge dedicada sem bind público `0.0.0.0` na interface física).
- Declarar o escopo (`cyberlab scope --set ...`) **antes** de qualquer `cyberlab exec`.
