# Modelo de Segurança — CyberLab OS

## 1. Princípios Fundamentais

1. **Negação por padrão fora do escopo**: nenhuma capacidade de rede, web ou inspeção ativa executa contra um alvo que não pertença explicitamente ao escopo ativo do projeto (`ProjectScope`).
2. **Separação entre proposta, autorização e execução**: a IA ou um agente parceiro podem propor uma operação (`ExecutionRequest`), mas somente o `PolicyEngine` + aprovação humana (quando exigida) autorizam o despacho ao `CyberLabExecutor`.
3. **Dupla verificação temporal (Submissão + Pré-Execução)**: mesmo após uma tarefa ser aprovada na fila (`awaiting_approval` → `queued`), o controlador reexecuta a verificação de escopo, estado de habilitação da capacidade e validade da aprovação imediatamente antes de chamar `executor.execute()`.
4. **Executores sem shell livre**: parâmetros de entrada (`unknown`) são validados contra o schema formal da capacidade antes de chegar ao executor; argumentos de processo são sempre passados como vetores estruturados (`argv[]`), jamais interpolados em `/bin/sh -c`.
5. **Evidência bruta imutável antes da interpretação**: toda saída observada é gravada com hash SHA-256 antes de qualquer resumo ou hipótese gerada por modelo de linguagem.
6. **Gravidade ≠ Confiança**: achados (`SecurityFinding`) separam impacto potencial (`severity`) de grau de certeza (`confidence` `0.0..1.0`) e exigem evidências vinculadas (`evidenceIds`) para sair de `unreviewed`/`inconclusive` para `confirmed`.

---

## 2. Classificação de Risco e Modos de Execução

| Nível de Risco (`CapabilityRisk`) | Exemplos | Política Padrão |
| --- | --- | --- |
| `read_only` | Auditoria estática de workspace, leitura de configuração local, verificação de hashes | `allow` dentro do workspace/escopo autorizado |
| `low` | Inspeção passiva de cabeçalhos HTTP em escopo local/lab | `allow` em modo `manual`/`approved`; `ask` se proposto por assistente em escopo externo |
| `moderate` | Enumeração ativa de portas/serviços, varredura de templates controlados | Exige escopo explícito + aprovação (`ask`) salvo automação de laboratório restrita a loopback/rede privada de lab |
| `high` | Fuzzing intensivo, testes ativos com carga ou mutação de estado | Sempre exige aprovação humana explícita (`ask`); bloqueado para disparo direto por parceiros |
| `destructive` | Exploração ativa com impacto de disponibilidade/integridade | Bloqueado por padrão (`deny`) para IA e parceiros; exige habilitação explícita e aprovação humana individual |

---

## 3. Confinamento de Escopo (`ScopeController`)

Cada projeto mantém um `ProjectScope` com:
- **Alvos permitidos (`allowedTargets`)**: sub-redes CIDR IPv4 (`10.240.0.0/24`, `127.0.0.1/32`), IPs exatos, domínios/subdomínios (`lab.internal`, `*.lab.local`), origens URL e raízes de diretório do workspace.
- **Alvos explicitamente bloqueados (`blockedTargets`)**: precedem qualquer regra `allow` (ex.: gateway doméstico, metadados de nuvem `169.254.169.254/32`, redes de produção).
- **Proteção contra expansão acidental**: se `allowExternalTargets` for `false` (padrão), endereços IP públicos roteáveis na internet são bloqueados mesmo que uma regra ampla seja configurada por engano.

---

## 4. Integridade, Proveniência e Redação de Evidências

- **Integridade**: todo `EvidenceRecord` registra `sha256` calculado sobre os bytes exatos observados e `immutable: true`. Qualquer divergência futura em `verifyEvidenceIntegrity` sinaliza violação de integridade.
- **Cadeia de custódia**: eventos de criação, leitura para exportação, redação e revisão de achados são registrados em trilha de auditoria append-only com timestamp ISO-8601 e identificador do ator.
- **Redação obrigatória antes de compartilhamento externo**: antes de incluir evidências em `contextBundle` para agentes parceiros ou prompts externos, o redator (`redactSensitiveContent`) mascara:
  - Cabeçalhos `Authorization: Bearer ...`, `Cookie`, `Set-Cookie`, `X-Api-Key`;
  - Chaves privadas PEM, tokens JWT, chaves AWS (`AKIA...`), GitHub tokens (`ghp_...`, `github_pat_...`), segredos em query strings e credenciais em URLs.

---

## 5. Segurança da Ponte com Agentes Parceiros (`cyberlab-partner` v1.0)

Os agentes parceiros operam em runtime externo próprio e são tratados como **fronteira de confiança distinta (não confiável)**:
1. **Autenticação mútua**: envelopes assinados com HMAC-SHA256 por chave específica de cada parceiro + janela máxima de clock skew (`±300s`).
2. **Anti-replay e deduplicação**: cache de `messageId` + validação de `correlationId` vinculado a tarefas ativas.
3. **Limites rígidos**: tamanho máximo de envelope configurável (padrão `256 KiB`) e validação estrita de schema antes do processamento.
4. **Proibição de execução remota direta**: mensagens de parceiros nunca invocam executores diretamente; pedidos de ação adicional geram no máximo uma proposta `awaiting_approval` sujeita ao `PolicyEngine` e à aprovação do usuário.
5. **Skills nunca concedem permissão**: carregar uma `SKILL.md` instrui o modelo sobre metodologia, mas não altera `Permission.Ruleset` nem `ProjectScope`.
