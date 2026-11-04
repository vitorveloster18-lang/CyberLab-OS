import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { CURATED_KNOWLEDGE_FILES } from "../../../cyberlab/knowledge/curated-library.js"
import {
  applyKnowledgeLibrarySync,
  parseFrontmatterFields,
  planKnowledgeLibrarySync,
  renderSyncPlan,
} from "../../../cyberlab/knowledge/library-sync.js"

const tempDirs: string[] = []
afterEach(() => {
  for (const d of tempDirs.splice(0)) {
    try {
      rmSync(d, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 })
    } catch {
      // Windows pode prender o arquivo; limpeza não pode derrubar o teste
    }
  }
})

describe("CyberLab OS v6.7 — Sincronização do Cofre Curado", () => {
  test("parseFrontmatterFields extrai tier/version/last_reviewed/status", () => {
    const fm = parseFrontmatterFields(
      ["---", 'id: x', 'tier: "curated"', 'version: "1.2.3"', 'last_reviewed: "2026-11-04"', "status: validated", "---", "", "# Doc"].join("\n"),
    )
    expect(fm.tier).toBe("curated")
    expect(fm.version).toBe("1.2.3")
    expect(fm.last_reviewed).toBe("2026-11-04")
    expect(fm.status).toBe("validated")
  })

  test("cofre vazio: todos os documentos entram como 'create'", () => {
    const vault = mkdtempSync(path.join(os.tmpdir(), "cyberlab-vault-"))
    tempDirs.push(vault)
    const plan = planKnowledgeLibrarySync(vault)
    expect(plan.counts.create).toBe(CURATED_KNOWLEDGE_FILES.length)
    expect(plan.counts.update).toBe(0)
  })

  test("cofre já sincronizado não gera trabalho (idempotente)", () => {
    const vault = mkdtempSync(path.join(os.tmpdir(), "cyberlab-vault-"))
    tempDirs.push(vault)
    applyKnowledgeLibrarySync(planKnowledgeLibrarySync(vault))

    const again = planKnowledgeLibrarySync(vault)
    expect(again.counts.update).toBe(0)
    expect(again.counts.create).toBe(0)
    expect(again.counts.skip).toBe(CURATED_KNOWLEDGE_FILES.length)
  })

  test("o bug real: documento antigo no cofre é detectado como 'update' com motivo", () => {
    const vault = mkdtempSync(path.join(os.tmpdir(), "cyberlab-vault-"))
    tempDirs.push(vault)
    applyKnowledgeLibrarySync(planKnowledgeLibrarySync(vault))

    // Simula o 00-Index.md da v6.2 que ficou preso no cofre do operador
    const stale = path.join(vault, "CyberLab-Knowledge", "00-Index.md")
    const original = readFileSync(stale, "utf8")
    writeFileSync(
      stale,
      original
        .replace('version: "1.1.0"', 'version: "0.9.0"')
        .replace('last_reviewed: "2026-11-04"', 'last_reviewed: "2026-10-01"'),
      "utf8",
    )

    const plan = planKnowledgeLibrarySync(vault)
    const item = plan.items.find((i) => i.relativePath === "00-Index.md")
    expect(item?.action).toBe("update")
    expect(item?.currentVersion).toBe("0.9.0")
    expect(item?.incomingVersion).toBe("1.1.0")
    expect(item?.reason).toContain("Desatualizado")
    expect(item?.backupPath).toContain("00-Index.md.bak")
    expect(plan.counts.update).toBe(1)
  })

  test("apply faz backup antes de substituir e restaura o conteúdo novo", () => {
    const vault = mkdtempSync(path.join(os.tmpdir(), "cyberlab-vault-"))
    tempDirs.push(vault)
    applyKnowledgeLibrarySync(planKnowledgeLibrarySync(vault))

    const target = path.join(vault, "CyberLab-Knowledge", "00-Index.md")
    const expected = CURATED_KNOWLEDGE_FILES.find((d) => d.relativePath.endsWith("00-Index.md"))!.content
    writeFileSync(target, expected.replace('version: "1.1.0"', 'version: "0.1.0"'), "utf8")

    const result = applyKnowledgeLibrarySync(planKnowledgeLibrarySync(vault))

    expect(result.applied).toContain("00-Index.md")
    expect(result.backups).toContain("00-Index.md.bak")
    expect(existsSync(`${target}.bak`)).toBe(true)
    expect(readFileSync(`${target}.bak`, "utf8")).toContain('version: "0.1.0"')
    expect(readFileSync(target, "utf8")).toContain('version: "1.1.0"')
  })

  test("arquivo do OPERADOR (tier diferente de curated) é classificado como protegido", () => {
    const vault = mkdtempSync(path.join(os.tmpdir(), "cyberlab-vault-"))
    tempDirs.push(vault)
    applyKnowledgeLibrarySync(planKnowledgeLibrarySync(vault))

    // Um doc curado que o operador reescreveu à mão como nota pessoal
    const target = path.join(vault, "CyberLab-Knowledge", "fundamentals", "http.md")
    writeFileSync(
      target,
      ["---", "tier: note", "status: unreviewed", "---", "", "# Minha anotação sobre HTTP"].join("\n"),
      "utf8",
    )

    const plan = planKnowledgeLibrarySync(vault)
    const item = plan.items.find((i) => i.relativePath === "fundamentals/http.md")
    expect(item?.action).toBe("protected")

    const result = applyKnowledgeLibrarySync(plan)
    expect(result.blocked).toContain("fundamentals/http.md")
    // O conteúdo do operador continua intacto
    expect(readFileSync(target, "utf8")).toContain("Minha anotação sobre HTTP")
  })

  test("plano sem --apply não escreve nada", () => {
    const vault = mkdtempSync(path.join(os.tmpdir(), "cyberlab-vault-"))
    tempDirs.push(vault)
    const plan = planKnowledgeLibrarySync(vault)
    const rendered = renderSyncPlan(plan)

    expect(rendered).toContain("PLANO (nada foi escrito)")
    expect(rendered).toContain("bun run cyberlab knowledge --apply")
    expect(existsSync(path.join(vault, "CyberLab-Knowledge"))).toBe(false)
  })

  test("notas soltas do operador nunca aparecem no plano", () => {
    const vault = mkdtempSync(path.join(os.tmpdir(), "cyberlab-vault-"))
    tempDirs.push(vault)
    mkdirSync(path.join(vault, "CyberLab-Knowledge", "_drafts"), { recursive: true })
    writeFileSync(path.join(vault, "CyberLab-Knowledge", "_drafts", "calibracao-v2.md"), "# rascunho\n")

    const plan = planKnowledgeLibrarySync(vault)
    expect(plan.items.some((i) => i.relativePath.startsWith("_drafts/"))).toBe(false)
  })
})
