import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  CURATED_KNOWLEDGE_FILES,
  CyberLabKnowledgeEngine,
  ensureKnowledgeLibrarySeeded,
} from "../../../cyberlab/knowledge/curated-library.js"

/**
 * v6.3 — Fecha as lacunas de conhecimento apontadas no relatório de calibração da Fase A:
 * CSRF/CORS, SSRF dedicado, JWT/OAuth, desserialização/XXE/upload, GraphQL/WebSocket,
 * cache poisoning, race conditions, cripto/TLS, mobile, RE, cloud/IAM, mass assignment
 * e uso orientado por hipótese das ferramentas de IA.
 */
describe("CyberLab OS v6.3 — Cobertura de domínios da biblioteca curada", () => {
  test("biblioteca expandida cobre todos os domínios ausentes apontados na Fase A", () => {
    const tmpWorkspace = mkdtempSync(path.join(tmpdir(), "cyberlab-know-v63-"))
    try {
      ensureKnowledgeLibrarySeeded(tmpWorkspace)
      const engine = new CyberLabKnowledgeEngine({ workspaceRoot: tmpWorkspace })

      const expected = [
        "fundamentals/jwt-oauth-oidc",
        "fundamentals/csrf-cors-samesite",
        "fundamentals/tls-crypto",
        "vulnerabilities/ssrf",
        "vulnerabilities/deserialization-xxe-upload",
        "vulnerabilities/graphql-websocket",
        "vulnerabilities/cache-poisoning-deception",
        "vulnerabilities/race-conditions-toctou",
        "vulnerabilities/mass-assignment-rate-limit",
        "domains/mobile-android-ios",
        "domains/binary-reverse-engineering",
        "domains/cloud-iam-containers",
        "domains/logging-forensics-detection",
        "tools/ai-assisted-pentest-workflows",
      ]

      for (const docId of expected) {
        const doc = engine.readDocument(docId)
        expect(doc.metadata.tier).toBe("curated")
        expect(doc.metadata.status).toBe("validated")
        expect(doc.metadata.sources.length).toBeGreaterThan(0)
        expect(doc.metadata.limitations.length).toBeGreaterThan(0)
        // Documentos curados precisam ter corpo útil, não só frontmatter
        expect(doc.body.length).toBeGreaterThan(400)
      }

      // A biblioteca inteira continua íntegra (34 docs: 20 do v6.2 + 14 do v6.3)
      expect(CURATED_KNOWLEDGE_FILES.length).toBe(36)
    } finally {
      rmSync(tmpWorkspace, { recursive: true, force: true })
    }
  })

  test("search_knowledge recupera os novos domínios por termo investigativo", () => {
    const tmpWorkspace = mkdtempSync(path.join(tmpdir(), "cyberlab-know-v63-search-"))
    try {
      ensureKnowledgeLibrarySeeded(tmpWorkspace)
      const engine = new CyberLabKnowledgeEngine({ workspaceRoot: tmpWorkspace })

      const queries: Array<[string, string]> = [
        ["ssrf metadata", "vulnerabilities/ssrf"],
        ["jwt alg none kid", "fundamentals/jwt-oauth-oidc"],
        ["csrf samesite cors", "fundamentals/csrf-cors-samesite"],
        ["race condition toctou", "vulnerabilities/race-conditions-toctou"],
        ["cache poisoning deception", "vulnerabilities/cache-poisoning-deception"],
        ["graphql websocket", "vulnerabilities/graphql-websocket"],
        ["xxe deserialization upload", "vulnerabilities/deserialization-xxe-upload"],
        ["mass assignment bopla rate limit", "vulnerabilities/mass-assignment-rate-limit"],
        ["ghidra reverse engineering", "domains/binary-reverse-engineering"],
        ["android jadx frida", "domains/mobile-android-ios"],
        ["cloud iam container trivy", "domains/cloud-iam-containers"],
        ["hayabusa yara forensics", "domains/logging-forensics-detection"],
        ["pentagi shannon strix ia", "tools/ai-assisted-pentest-workflows"],
      ]

      for (const [query, expectedPath] of queries) {
        const hits = engine.searchKnowledge({ query, limit: 10 })
        expect(hits.length).toBeGreaterThan(0)
        expect(hits.some((h) => h.docPath.includes(expectedPath))).toBe(true)
      }
    } finally {
      rmSync(tmpWorkspace, { recursive: true, force: true })
    }
  })

  test("novos documentos são navegáveis por WikiLink a partir dos fundamentos existentes", () => {
    const tmpWorkspace = mkdtempSync(path.join(tmpdir(), "cyberlab-know-v63-graph-"))
    try {
      ensureKnowledgeLibrarySeeded(tmpWorkspace)
      const engine = new CyberLabKnowledgeEngine({ workspaceRoot: tmpWorkspace })

      const ssrfRel = engine.getRelatedDocuments("vulnerabilities/ssrf")
      expect(ssrfRel.related.length).toBeGreaterThanOrEqual(2)
      expect(ssrfRel.related.some((r) => r.docPath.includes("fundamentals/networking"))).toBe(true)

      const jwtRel = engine.getRelatedDocuments("fundamentals/jwt-oauth-oidc")
      expect(jwtRel.related.some((r) => r.docPath.includes("fundamentals/authentication"))).toBe(true)
    } finally {
      rmSync(tmpWorkspace, { recursive: true, force: true })
    }
  })
})
