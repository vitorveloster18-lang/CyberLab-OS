import { describe, expect, test } from "bun:test"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  CURATED_KNOWLEDGE_FILES,
  CyberLabKnowledgeEngine,
  ensureKnowledgeLibrarySeeded,
} from "../../../cyberlab/knowledge/curated-library.js"
import { CyberLabObsidianVault } from "../../../cyberlab/vault/obsidian-vault.js"
import {
  SUBAGENT_GUARDRAIL_DEFAULTS,
  checkSubagentGuardrails,
} from "../../../packages/core/src/tool/plugin/subagent-guardrails.js"

describe("CyberLab OS v6.2 — Investigative Security Orchestrator, Subagent Guardrails & CyberLab-Knowledge Vault MCP", () => {
  test("1. Seeds all 20 curated CyberLab-Knowledge/ documents with verified provenance metadata and Obsidian WikiLinks", () => {
    const tmpWorkspace = mkdtempSync(path.join(tmpdir(), "cyberlab-know-v62-"))
    try {
      const vault = new CyberLabObsidianVault({ projectId: "proj-v62", workspaceRoot: tmpWorkspace })
      const listing = vault.getOverview()

      expect(CURATED_KNOWLEDGE_FILES.length).toBe(40)

      const requiredDocIds = [
        "00-Index",
        "fundamentals/http",
        "fundamentals/authentication",
        "fundamentals/authorization",
        "fundamentals/sessions",
        "fundamentals/networking",
        "methodologies/hypothesis-driven-testing",
        "methodologies/evidence-validation",
        "methodologies/root-cause-analysis",
        "vulnerabilities/access-control/idor-bola-bfla",
        "vulnerabilities/access-control",
        "vulnerabilities/injection/context-aware-injection",
        "vulnerabilities/parser-differential/http-url-json-differentials",
        "vulnerabilities/business-logic/state-race-invariants",
        "research/cve-analysis/cve-applicability-methodology",
        "research/cve-analysis",
        "research/patch-analysis/patch-diff-methodology",
        "research/technical-writeups/reproducible-writeup-standard",
        "tools/burp",
        "tools/nuclei",
        "tools/semgrep",
        "tools/mcp-tool-catalog",
      ]

      const engine = new CyberLabKnowledgeEngine({ workspaceRoot: tmpWorkspace })
      for (const seed of CURATED_KNOWLEDGE_FILES) {
        const meta = engine.getDocumentMetadata(seed.relativePath)
        expect(meta.tier).toBe("curated")
        expect(meta.status).toBe("validated")
        expect(meta.version.length).toBeGreaterThan(0)
        expect(meta.last_reviewed).toMatch(/^\d{4}-\d{2}-\d{2}$/)
        expect(meta.sources.length).toBeGreaterThan(0)
        expect(meta.limitations.length).toBeGreaterThan(0)
      }

      for (const docId of requiredDocIds) {
        const doc = engine.readDocument(docId)
        expect(doc.body.length).toBeGreaterThan(150)
      }

      // Verify CyberLabObsidianVault indexes CyberLab-Knowledge notes and resolves related graph
      const knowledgeNotesInVault = listing.notes.filter((n) =>
        n.relativePath.startsWith("CyberLab-Knowledge/"),
      )
      expect(knowledgeNotesInVault.length).toBe(CURATED_KNOWLEDGE_FILES.length)

      const rel = engine.getRelatedDocuments("vulnerabilities/parser-differential/http-url-json-differentials")
      expect(rel.related.length).toBeGreaterThanOrEqual(2)
      expect(rel.related.some((r) => r.docPath.includes("fundamentals/http"))).toBe(true)
    } finally {
      rmSync(tmpWorkspace, { recursive: true, force: true })
    }
  })

  test("2. Enforces 3-tier epistemic separation: drafts, update proposals, and negative-result session memory never mutate curated docs", () => {
    const tmpWorkspace = mkdtempSync(path.join(tmpdir(), "cyberlab-epistemic-v62-"))
    try {
      const vaultDir = path.join(tmpWorkspace, "vault")
      ensureKnowledgeLibrarySeeded(vaultDir)
      const targetAbs = path.join(vaultDir, "CyberLab-Knowledge", "fundamentals", "http.md")
      const originalHttpBytes = readFileSync(targetAbs, "utf8")

      const engine = new CyberLabKnowledgeEngine({ workspaceRoot: tmpWorkspace })

      // 1) Create draft note -> must land in _drafts/ and separate facts vs hypotheses
      const draft = engine.createDraftNote({
        slug: "Proxy Matrix Path Test",
        title: "Diferencial de Matriz ;jsessionid entre Proxy e Backend",
        factsObserved: ["GET /api/admin;v=1 retornou HTTP 200 no ambiente de homologação autorizado"],
        hypotheses: ["O proxy trata ;v=1 como sufixo estático enquanto o roteador Java remove path params"],
        inferences: ["A regra de ACL está acoplada apenas à string bruta da URI no proxy"],
        uncertainties: ["Falta verificar se o resultado HTTP 200 depende de sessão autenticada prévia"],
        sources: ["Experimento controlado EXP-01 na sessão atual"],
        relatedDocs: ["fundamentals/http"],
      })
      expect(draft.draftDocPath).toContain("CyberLab-Knowledge/_drafts/")

      // Default curated search excludes unreviewed drafts unless includeDrafts: true
      const curatedOnlyHits = engine.searchKnowledge({ query: "Diferencial de Matriz" })
      expect(curatedOnlyHits.some((h) => h.tier === "draft")).toBe(false)

      const withDraftsHits = engine.searchKnowledge({ query: "Diferencial de Matriz", includeDrafts: true })
      expect(withDraftsHits.some((h) => h.docPath === draft.draftDocPath && h.tier === "draft")).toBe(true)

      // 2) Propose update -> requires primarySources and writes to _proposals/, never mutating fundamentals/http.md
      expect(() =>
        engine.proposeDocumentUpdate({
          targetDocPath: "fundamentals/http",
          targetSection: "Diferenciais",
          rationale: "Sem fonte primária",
          proposedContent: "Texto sem fonte",
          primarySources: [],
        }),
      ).toThrow(/primarySources/)

      const proposal = engine.proposeDocumentUpdate({
        targetDocPath: "fundamentals/http",
        targetSection: "3. Diferenciais Clássicos entre Componentes",
        rationale: "Documentar comportamento de HTTP/2 pseudo-headers :authority vs Host",
        proposedContent: "Em conversões H2->H1, divergências entre `:authority` e `Host` causam roteamento ambíguo.",
        primarySources: ["RFC 9113 Section 8.3.1"],
      })
      expect(proposal.proposalDocPath).toContain("CyberLab-Knowledge/_proposals/")
      expect(readFileSync(targetAbs, "utf8")).toBe(originalHttpBytes)

      // 3) Investigation session memory preserves negative results & syncs readable mirror to vault/Investigacoes/
      const memUpdate = engine.updateInvestigationMemory({
        investigationId: "api-portal-v2",
        mission: "Avaliar isolamento multi-tenant na API de faturas",
        authorizedScope: "https://sandbox.exemplo.interno/*",
        systemModel: {
          components: ["CDN Envoy", "API Node/Fastify", "PostgreSQL RLS"],
          technologies: ["HTTP/2", "JWT RS256"],
          dataFlows: ["Cliente -> Envoy -> Fastify -> Postgres"],
          trustBoundaries: ["Internet -> Envoy", "Fastify -> Tenant RLS"],
          identitiesAndPermissions: ["role:member", "role:billing_admin"],
        },
        hypotheses: [
          {
            id: "H1",
            title: "BOLA em GET /v2/invoices/:id entre tenants distintos",
            expectedBehavior: "Tenant A recebe HTTP 403/404 ao consultar fatura do Tenant B",
            suspectedBehavior: "Endpoint filtra apenas por id numérico sem restringir org_id",
            fragileAssumption: "Middleware assume que UUID/ID não é enumerável",
            technicalRationale: "Rotas legadas v1 não aplicavam filtro org_id",
            evidenceNeeded: "Comparar baseline Tenant B->B (200) vs Tenant A->B",
            alternativeExplanations: ["Row-Level Security no PostgreSQL bloqueia na camada de banco"],
            status: "refuted",
            updatedAt: new Date().toISOString(),
          },
        ],
        negativeResults: [
          "H1 refutada: Tenant A -> fatura do Tenant B retornou HTTP 404 consistente; RLS ativa confirmada.",
        ],
        nextSteps: ["Investigar endpoint de exportação assíncrona POST /v2/invoices/export"],
      })

      expect(memUpdate.memory.negativeResults.length).toBe(1)
      expect(memUpdate.vaultMirrorPath).toBe("Investigacoes/api-portal-v2.md")
      const mirrorContent = readFileSync(path.join(vaultDir, memUpdate.vaultMirrorPath), "utf8")
      expect(mirrorContent).toContain("Resultados Negativos")
      expect(mirrorContent).toContain("H1 refutada")
      expect(readFileSync(targetAbs, "utf8")).toBe(originalHttpBytes)
    } finally {
      rmSync(tmpWorkspace, { recursive: true, force: true })
    }
  })

  test("4. Registers Investigative Security Orchestrator, all 6 specialized subagents, and enforces hard depth/concurrency/quantity guardrails", () => {
    const agentPluginSource = readFileSync(
      path.resolve(import.meta.dir, "../../../packages/core/src/plugin/agent.ts"),
      "utf8",
    )

    // Verify Orchestrator prompt includes all 11 specification sections & core principles
    for (const marker of [
      "CYBERLAB OS — INVESTIGATIVE SECURITY ORCHESTRATOR",
      "## 1. Identidade e missão",
      "## 2. Princípios fundamentais",
      "## 3. Responsabilidade do agente principal",
      "## 4. Orquestração dinâmica de subagentes",
      "## 5. Metodologia de investigação",
      "## 6. Seleção de ferramentas MCP",
      "## 7. Conhecimento técnico",
      "## 8. Segurança e autorização",
      "## 9. Memória investigativa",
      "## 10. Critério de sucesso",
      "## 11. Estilo de interação",
    ]) {
      expect(agentPluginSource).toContain(marker)
    }

    // Verify primary orchestrator + all 6 subagents are registered
    expect(agentPluginSource).toContain('Agent.ID.make("cyberlab-orchestrator")')
    for (const subId of [
      "research-agent",
      "system-architect-agent",
      "hypothesis-agent",
      "tool-specialist-agent",
      "experiment-agent",
      "evidence-reviewer-agent",
    ]) {
      expect(agentPluginSource).toContain(`Agent.ID.make("${subId}")`)
    }

    // Verify hard runtime subagent guardrails (depth = 1, concurrency = 3, session budget = 12)
    expect(SUBAGENT_GUARDRAIL_DEFAULTS).toEqual({
      maxDepth: 1,
      maxConcurrentPerSession: 3,
      maxTotalPerSession: 12,
    })

    // Allowed normal spawn
    expect(
      checkSubagentGuardrails({
        depth: 0,
        activeConcurrentCount: 2,
        totalSpawnedInSession: 11,
        isExistingChildSession: false,
      }),
    ).toEqual({ allowed: true })

    // Depth limit blocks nested subagent (depth >= 1)
    const depthBlocked = checkSubagentGuardrails({
      depth: 1,
      activeConcurrentCount: 0,
      totalSpawnedInSession: 1,
      isExistingChildSession: false,
    })
    expect(depthBlocked.allowed).toBe(false)
    if (!depthBlocked.allowed) expect(depthBlocked.reason).toContain("depth limit reached")

    // Concurrency limit blocks 4th simultaneous subagent
    const concurrencyBlocked = checkSubagentGuardrails({
      depth: 0,
      activeConcurrentCount: 3,
      totalSpawnedInSession: 3,
      isExistingChildSession: false,
    })
    expect(concurrencyBlocked.allowed).toBe(false)
    if (!concurrencyBlocked.allowed) expect(concurrencyBlocked.reason).toContain("concurrency limit reached")

    // Session budget blocks 13th new child subagent, but ALLOWS continuing an existing child sessionID
    const budgetBlocked = checkSubagentGuardrails({
      depth: 0,
      activeConcurrentCount: 0,
      totalSpawnedInSession: 12,
      isExistingChildSession: false,
    })
    expect(budgetBlocked.allowed).toBe(false)
    if (!budgetBlocked.allowed) expect(budgetBlocked.reason).toContain("session budget reached")

    const reuseAllowed = checkSubagentGuardrails({
      depth: 0,
      activeConcurrentCount: 0,
      totalSpawnedInSession: 12,
      isExistingChildSession: true,
    })
    expect(reuseAllowed).toEqual({ allowed: true })
  })
})
