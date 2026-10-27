# CyberLab OS

**CyberLab OS** é uma distribuição reconstruída de segurança ofensiva, auditoria técnica, resposta a incidentes e revisão forense construída sobre o núcleo do **OpenCode V2** (`anomalyco/opencode` v2.1.4, licença MIT).

A plataforma preserva o motor nativo de sessões, agentes, modelos, permissões, skills e interface do OpenCode V2, adicionando uma camada de domínio própria (`cyberlab/`) para:

- **Catálogo controlado de capacidades** (`CapabilityRegistry`) com níveis explícitos de risco (`read_only` a `destructive`).
- **Motor de políticas e confinamento de escopo** (`PolicyEngine` + `ScopeController`) com dupla verificação (submissão e pré-execução) e bloqueio de alvos fora do escopo autorizado.
- **Executores estruturados** (`CyberLabExecutor`) sem interpolação livre de shell, com cancelamento (`AbortSignal`), timeouts, limites de bytes e menor privilégio.
- **Cadeia de custódia e persistência de evidências** (`EvidenceStore` + `FindingStore`) com integridade SHA-256, redação automática de segredos/credenciais e separação rigorosa entre observação bruta e conclusão analítica (`severity` vs `confidence`).
- **Skills operacionais nativas** (`skills/*/SKILL.md`) compatíveis com o mecanismo nativo do OpenCode V2, sem conceder privilégios executáveis por conta própria.
- **Ponte autenticada com agentes parceiros externos** (`cyberlab-partner` v1.0) com HMAC-SHA256, proteção contra replay, contexto mínimo redigido e validação de respostas não confiáveis.
- **Governança de licenças e inventário de ferramentas** (`vendor/manifests/`, `THIRD_PARTY_NOTICES.md`) com verificação automatizada no pipeline.

---

## Linha de Base Upstream Fixada

- **Repositório upstream**: [`anomalyco/opencode`](https://github.com/anomalyco/opencode)
- **Versão de referência**: `2.1.4`
- **Commit fixado**: `dae4077a96243257ea0a2086068504b791629f10` (registrado em [`vendor/UPSTREAM_BASELINE.json`](vendor/UPSTREAM_BASELINE.json))
- **Runtime / Gerenciador de pacotes**: `bun@1.4.4`
- **Perfil de distribuição**: Pacotes reais do produto (`packages/cli`, `packages/core`, `packages/server`, `packages/protocol`, `packages/schema`, `packages/plugin`, `packages/gui-plugins`, `packages/app`, `packages/tui`, `packages/ui`, `packages/desktop`, etc.), excluindo serviços proprietários de nuvem/marketing SaaS (`packages/console`, `packages/web`, `packages/stats`, `services/*`).

---

## Ambiente Recomendado (Windows + WSL2 + Docker)

1. **WSL2 (Linux)** como ambiente primário para o repositório (`~/src/cyberlab-os` no filesystem ext4 nativo do WSL2, evitando `/mnt/c`), `bun@1.4.4`, compilação e execução das ferramentas Linux.
2. **Windows** para acesso do usuário ao navegador, cliente web/desktop e revisão visual.
3. **Docker (redes isoladas de laboratório)** para executores conteinerizados e alvos vulneráveis de teste, sem exposição para a rede externa.

---

## Instalação, Verificação de Tipos e Testes

```bash
# Instalar dependências com Bun 1.4.4
ELECTRON_SKIP_BINARY_DOWNLOAD=1 bun install --ignore-scripts
bun run --cwd packages/core fix-node-pty

# Verificação rápida de tipos (typecheck nativo do Bun 1.4.4)
bun --cwd packages/schema typecheck
bun --cwd packages/core typecheck
bun --cwd packages/server typecheck
bun --cwd packages/cli typecheck
bun --cwd packages/gui-plugins typecheck

# Testes de linha de base e da camada CyberLab
bun --cwd packages/schema test
bun --cwd packages/util test
bun test tests/cyberlab
```

> **Nota sobre memória no typecheck**: utilize sempre `bun --cwd <pkg> typecheck` (`bun check --no-script`) em vez de `tsc -b` nos pacotes com Effect 4 (`packages/core`, `packages/server`), garantindo verificação completa em poucos segundos e baixo consumo de RAM.

---

## Documentação Técnica

- [`docs/UPSTREAM_AUDIT.md`](docs/UPSTREAM_AUDIT.md) — Auditoria detalhada do commit fixado `2.1.4` com arquivos, linhas e símbolos reais.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Arquitetura em 3 níveis, fronteiras de módulos e integração com OpenCode V2.
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — Modelo de ameaças, autorização em duas fases, escopo, redação e isolamento de parceiros.
- [`docs/TOOL_INVENTORY.md`](docs/TOOL_INVENTORY.md) — Inventário inicial e triagem técnica/jurídica das ferramentas candidatas.
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — Política de conformidade de licenças e regras para `vendor/` vs `integrations/`.
