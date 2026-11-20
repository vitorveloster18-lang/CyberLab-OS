import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { CyberLabKnowledgeEngine } from "../../../cyberlab/knowledge/curated-library.js"
import {
  buildLabInvestigationKit,
  buildMemorySeed,
  getSupportedKitLabIds,
  labInvestigationKitExists,
  writeLabInvestigationKit,
} from "../../../cyberlab/labs/investigation-kit.js"
import { BUILTIN_TRAINING_LABS, TrainingLabManager } from "../../../cyberlab/labs/training-labs.js"

const tempDirs: string[] = []
const managers: TrainingLabManager[] = []

afterEach(async () => {
  for (const m of managers.splice(0)) await m.stopAll().catch(() => {})
  // No Windows o SO costuma manter o arquivo preso por alguns ms depois de parar o
  // servidor; falhar a limpeza NÃO pode derrubar o teste (é sujeira em %TEMP%).
  for (const d of tempDirs.splice(0)) {
    try {
      rmSync(d, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 })
    } catch {
      // ignore
    }
  }
})

describe("CyberLab OS v6.4 — Kit de Investigação do Laboratório (Fases B/D/F prontas)", () => {
  test("kit do lab-owasp-api-bola traz modelo do sistema, 4 hipóteses e 6 experimentos", () => {
    const kit = buildLabInvestigationKit("lab-owasp-api-bola", 19081)
    expect(kit).not.toBeNull()
    expect(kit!.baseUrl).toBe("http://127.0.0.1:19081")

    // Fase B — modelagem
    expect(kit!.systemModel.components.length).toBeGreaterThanOrEqual(4)
    expect(kit!.systemModel.trustBoundaries.length).toBeGreaterThanOrEqual(3)
    expect(kit!.systemModel.endpoints.length).toBe(5)
    expect(kit!.systemModel.endpoints.map((e) => e.id)).toContain("ep-accounts")
    expect(kit!.systemModel.identities.map((i) => i.id)).toEqual(["user-a", "user-b", "admin", "anon"])

    // Fase D — hipóteses com os 6 elementos obrigatórios
    expect(kit!.hypotheses.map((h) => h.id)).toEqual(["H1", "H2", "H3", "H4"])
    for (const h of kit!.hypotheses) {
      expect(h.expectedBehavior.length).toBeGreaterThan(10)
      expect(h.suspectedBehavior.length).toBeGreaterThan(10)
      expect(h.fragileAssumption.length).toBeGreaterThan(10)
      expect(h.technicalRationale.length).toBeGreaterThan(10)
      expect(h.evidenceNeeded.length).toBeGreaterThan(10)
      expect(h.alternativeExplanations.length).toBeGreaterThanOrEqual(2)
      expect(h.status).toBe("proposed")
    }

    // Fase F — experimentos com variável única e critério de parada
    expect(kit!.experiments.map((e) => e.id)).toEqual(["E1", "E2", "E3", "E4", "E5", "E6"])
    for (const e of kit!.experiments) {
      expect(kit!.hypotheses.some((h) => h.id === e.hypothesisId)).toBe(true)
      expect(e.modifiedVariable.length).toBeGreaterThan(5)
      expect(e.stopCriterion.length).toBeGreaterThan(5)
      expect(e.commands.length).toBeGreaterThan(0)
      expect(e.verdict).toBe("inconclusive")
    }
  })

  test("cada hipótese aponta para o controle que a repara e cada experimento cita a URL real", () => {
    const kit = buildLabInvestigationKit("lab-owasp-api-bola", 19555)!
    const flags = new Set(kit.hypotheses.map((h) => h.relatedControlFlag))
    expect(flags).toEqual(
      new Set(["enforceAccountOwnership", "rejectAlgNoneJwt", "sanitizeSqlQuery", "enableSecurityHeaders"]),
    )
    for (const e of kit.experiments) {
      expect(e.commands.join("\n")).toContain("http://127.0.0.1:19555")
    }
  })

  test("writeLabInvestigationKit grava os 7 arquivos e o detector os reconhece", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "cyberlab-kit-"))
    tempDirs.push(root)

    expect(labInvestigationKitExists(root)).toBe(false)
    const files = writeLabInvestigationKit("lab-owasp-api-bola", root, 19081)
    expect(files).not.toBeNull()
    for (const f of Object.values(files!)) expect(existsSync(f)).toBe(true)
    expect(labInvestigationKitExists(root)).toBe(true)

    const modelMd = readFileSync(files!.systemModelMd, "utf8")
    expect(modelMd).toContain("Modelo do Sistema")
    expect(modelMd).toContain("Fronteiras de Confiança")
    expect(modelMd).toContain("api/v1/accounts/:accountId")

    const hypMd = readFileSync(files!.hypothesesMd, "utf8")
    expect(hypMd).toContain("H1")
    expect(hypMd).toContain("Pressuposto frágil")

    const expMd = readFileSync(files!.experimentsMd, "utf8")
    expect(expMd).toContain("Matriz de Remediação")
    expect(expMd).toContain("403")
    expect(expMd).toContain("401")
  })

  test("seed de memória é compatível com updateInvestigationMemory e isola o escopo no loopback", () => {
    const kit = buildLabInvestigationKit("lab-owasp-api-bola", 19081)!
    const seed = buildMemorySeed(kit)

    expect(seed.investigationId).toBe("lab-owasp-api-bola")
    expect(seed.authorizedScope).toContain("127.0.0.1:19081")
    expect(seed.authorizedScope.toLowerCase()).toContain("nenhum alvo externo")
    expect(seed.hypotheses.length).toBe(4)
    expect(seed.experiments.length).toBe(6)
    expect(seed.externalReferences.length).toBeGreaterThanOrEqual(4)
    expect(seed.nextSteps.length).toBeGreaterThanOrEqual(3)

    const root = mkdtempSync(path.join(os.tmpdir(), "cyberlab-mem-"))
    tempDirs.push(root)
    const engine = new CyberLabKnowledgeEngine({ workspaceRoot: root })
    const res = engine.updateInvestigationMemory(seed)

    expect(res.memory.investigationId).toBe("lab-owasp-api-bola")
    expect(res.memory.hypotheses.map((h) => h.id)).toEqual(["H1", "H2", "H3", "H4"])
    expect(res.memory.experiments.every((e) => e.verdict === "inconclusive")).toBe(true)
    expect(res.vaultMirrorPath).toContain("Investigacoes/")
  })

  test(
    "startLab gera o kit automaticamente com a porta REAL e resetLab o regenera",
    async () => {
    const labsRoot = mkdtempSync(path.join(os.tmpdir(), "cyberlab-labs-"))
    tempDirs.push(labsRoot)
    const manager = new TrainingLabManager(labsRoot)
    managers.push(manager)

    const status = await manager.startLab({ labId: "lab-owasp-api-bola", preferredPort: 0 })
    expect(status.running).toBe(true)
    expect(status.port).toBeGreaterThan(0)

    const wsRoot = manager.getLabWorkspacePath("lab-owasp-api-bola")
    expect(manager.hasInvestigationKit("lab-owasp-api-bola")).toBe(true)

    const modelJson = JSON.parse(
      readFileSync(path.join(wsRoot, "lab-system-model.json"), "utf8"),
    ) as { baseUrl: string }
    expect(modelJson.baseUrl).toBe(`http://127.0.0.1:${status.port}`)

    const expMd = readFileSync(path.join(wsRoot, "EXPERIMENTS.md"), "utf8")
    expect(expMd).toContain(`http://127.0.0.1:${status.port}`)

    // O modelo gerado pelo manager usa exatamente a porta em uso
    const seed = manager.buildInvestigationMemorySeed("lab-owasp-api-bola")
    expect(seed?.authorizedScope).toContain(`:${status.port}`)
    },
    60_000, // Windows CI lento: sobe servidor do lab
  )

  test("seed e model funcionam SEM o servidor no ar (usam a porta do kit/do catálogo)", () => {
    const labsRoot = mkdtempSync(path.join(os.tmpdir(), "cyberlab-labs-offline-"))
    tempDirs.push(labsRoot)
    const manager = new TrainingLabManager(labsRoot)
    // Nenhum startLab(): apenas o kit, exatamente como `lab seed`/`lab model` operam
    const files = manager.ensureInvestigationKit("lab-owasp-api-bola")
    expect(files).not.toBeNull()

    const seed = manager.buildInvestigationMemorySeed("lab-owasp-api-bola")
    expect(seed).not.toBeNull()
    expect(seed!.authorizedScope).toContain("127.0.0.1:19081")
    expect(seed!.hypotheses.length).toBe(4)

    const status = manager.getLabStatus("lab-owasp-api-bola")
    expect(status.running).toBe(false)
    expect(status.provisioned).toBe(false) // kit não marca "provisionado" (isso é LAB_BRIEFING.md)
  })

  test(
    "GET / devolve página HTML legível e GET /health continua JSON (v6.4.2)",
    async () => {
    const labsRoot = mkdtempSync(path.join(os.tmpdir(), "cyberlab-labs-html-"))
    tempDirs.push(labsRoot)
    const manager = new TrainingLabManager(labsRoot)
    managers.push(manager)

    const status = await manager.startLab({ labId: "lab-owasp-api-bola", preferredPort: 0 })
    const base = status.baseUrl!

    // `/health` permanece JSON (usado por scripts e pela sonda TCP do `lab status`)
    const healthRes = await fetch(`${base}/health`)
    expect(healthRes.status).toBe(200)
    expect(healthRes.headers.get("content-type")).toContain("application/json")
    const health = (await healthRes.json()) as { status: string; labId: string }
    expect(health.status).toBe("online")
    expect(health.labId).toBe("lab-owasp-api-bola")

    // `/` agora abre uma página HTML no navegador (antes devolvia JSON cru)
    const indexRes = await fetch(`${base}/`)
    expect(indexRes.status).toBe(200)
    expect(indexRes.headers.get("content-type")).toContain("text/html")
    const html = await indexRes.text()
    expect(html).toContain("<!doctype html>")
    expect(html).toContain("Laboratório OWASP API Security")
    // Deixa claro que esta porta é o ALVO e aponta para o fluxo de terminal
    expect(html).toContain("bun run cyberlab lab status")
    expect(html).toContain("cyberlab exec")
    // Mostra o estado real dos 4 controles
    expect(html).toContain("enforceAccountOwnership")
    expect(html).toContain("DESLIGADO (vulnerável)")
    // Endpoints clicáveis + comando pronto para o terminal
    expect(html).toContain("/api/v1/accounts/1002")
    expect(html).toContain("curl -s -i")
    },
    60_000, // Windows CI lento: sobe servidor do lab
  )

  test("labs sem kit retornam null sem quebrar (degradação graciosa)", () => {
    const other = BUILTIN_TRAINING_LABS.find((l) => !getSupportedKitLabIds().includes(l.labId))
    expect(other).toBeDefined()
    expect(buildLabInvestigationKit(other!.labId, 19081)).toBeNull()
    expect(buildLabInvestigationKit("lab-inexistente", 19081)).toBeNull()
  })
})
