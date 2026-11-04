import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import { createHash } from "node:crypto"
import os from "node:os"
import path from "node:path"
import {
  buildBolaEvidenceCases,
  buildRemediationCases,
  renderEvidenceText,
  runBolaEvidenceSuite,
  sha256Hex,
  SECURITY_HEADERS,
  VULNERABLE_CONFIG,
} from "../../../cyberlab/labs/evidence-recorder.js"
import { TrainingLabManager } from "../../../cyberlab/labs/training-labs.js"

const tempDirs: string[] = []
const managers: TrainingLabManager[] = []
const sha = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex")

afterEach(async () => {
  for (const m of managers.splice(0)) await m.stopAll().catch(() => {})
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 })
})

describe("CyberLab OS v6.5 — Gravador de Evidência (E1–E7 + SHA-256)", () => {
  test("suíte vulnerável tem 11 casos nas hipóteses H1–H4, sempre com baseline + PoC", () => {
    const cases = buildBolaEvidenceCases("http://127.0.0.1:19081")
    expect(cases.length).toBe(11)
    expect(cases.map((c) => c.experimentId)).toEqual([
      "E1", "E1", "E1", "E2", "E2", "E3", "E3", "E3", "E4", "E4", "E5",
    ])
    for (const c of cases) {
      // Sem expectativa declarada não há experimento, só curiosidade.
      expect(c.expectation.length).toBeGreaterThan(15)
      expect(c.command.startsWith("curl")).toBe(true)
      expect(c.command).toContain("127.0.0.1:19081")
    }
    // E1 isola a variável: mesmo token, IDs diferentes; e mesmo ID, tokens diferentes
    expect(cases[1]!.url).toContain("/accounts/1002")
    expect(cases[2]!.headers?.Authorization).toBe("Bearer token-user-b-1002")
  })

  test("fases de remediação repetem os mesmos 4 casos (E6 remediado, E7 restaurado)", () => {
    const remediado = buildRemediationCases("http://127.0.0.1:19081", "remediado")
    const restaurado = buildRemediationCases("http://127.0.0.1:19081", "restaurado")
    expect(remediado.length).toBe(4)
    expect(restaurado.length).toBe(4)
    // Mesmos-alvos, nomes distintos: a comparação tem de ser maçã com maçã.
    expect(remediado.map((c) => c.url)).toEqual(restaurado.map((c) => c.url))
    expect(remediado.map((c) => c.id)).toEqual(["E6-01-bola", "E6-02-alg-none", "E6-03-sql-error", "E6-04-headers"])
    expect(restaurado.map((c) => c.id)).toEqual(["E7-01-bola", "E7-02-alg-none", "E7-03-sql-error", "E7-04-headers"])
  })

  test("texto arquivado traz comando, requisição, resposta e a expectativa declarada", () => {
    const text = renderEvidenceText({
      id: "X-01",
      experimentId: "EX",
      label: "exemplo",
      command: "curl -s -i http://127.0.0.1:19081/x",
      method: "GET",
      url: "http://127.0.0.1:19081/x?q=1",
      requestHeaders: { Authorization: "Bearer t" },
      expectation: "200 esperado",
      status: 200,
      statusText: "OK",
      responseHeaders: { "content-type": "application/json" },
      body: '{"ok":true}',
      durationMs: 3,
      capturedAt: "2026-11-04T00:00:00.000Z",
    })
    expect(text).toContain("$ curl -s -i http://127.0.0.1:19081/x")
    expect(text).toContain(">>> REQUISICAO")
    expect(text).toContain("GET /x?q=1 HTTP/1.1")
    expect(text).toContain("Authorization: Bearer t")
    expect(text).toContain("<<< RESPOSTA")
    expect(text).toContain("HTTP/1.1 200 OK")
    expect(text).toContain("content-type: application/json")
    expect(text).toContain('{"ok":true}')
    expect(text).toContain("expectativa  : 200 esperado")
    expect(sha256Hex(text)).toMatch(/^[0-9a-f]{64}$/)
  })

  test("execução real: arquiva 19 requisições, sela o lote e NÃO deixa o lab remediado", async () => {
    const labsRoot = mkdtempSync(path.join(os.tmpdir(), "cyberlab-labs-ev-"))
    tempDirs.push(labsRoot)
    const outDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-evidence-"))
    tempDirs.push(outDir)

    const manager = new TrainingLabManager(labsRoot)
    managers.push(manager)
    const status = await manager.startLab({ labId: "lab-owasp-api-bola", preferredPort: 0 })
    expect(status.baseUrl).toBeTruthy()

    const result = await runBolaEvidenceSuite({
      baseUrl: status.baseUrl!,
      outDir,
      workspaceRoot: manager.getLabWorkspacePath("lab-owasp-api-bola"),
    })

    // 11 (vulnerável) + 4 (remediado) + 4 (restaurado)
    expect(result.manifest.cases.length).toBe(19)
    expect(result.manifest.files.length).toBe(19)

    // Vereditos: vulnerável antes, remediado depois — é o ciclo completo (Fases D→G)
    expect(result.manifest.verdicts.H1!.verdict).toBe("vulneravel")
    expect(result.manifest.verdicts.H2!.verdict).toBe("vulneravel")
    expect(result.manifest.verdicts.H3!.verdict).toBe("vulneravel")
    expect(result.manifest.verdicts.H4!.verdict).toBe("vulneravel")
    for (const h of ["H1", "H2", "H3", "H4"]) {
      expect(result.manifest.verdicts[`${h}@remediado`]!.verdict).toBe("remediado")
    }

    // Selo confere com o hash do arquivo gravado (sem paradoxo ovo/galinha)
    expect(result.seal).toMatch(/^[0-9a-f]{64}$/)
    expect(sha(result.manifestPath)).toBe(result.seal)
    expect(readFileSync(result.sealPath, "utf8")).toContain(result.seal)
    // O manifesto em disco mantém seal=null: o valor vive em SEAL.txt
    expect(JSON.parse(readFileSync(result.manifestPath, "utf8")).seal).toBeNull()

    // Cada arquivo bate com o SHA-256 registrado
    for (const f of result.manifest.files) {
      expect(sha(path.join(outDir, f.path))).toBe(f.sha256)
      expect(existsSync(path.join(outDir, f.path))).toBe(true)
    }

    // Relatório legível
    const report = readFileSync(result.reportPath, "utf8")
    expect(report).toContain(result.seal)
    expect(report).toContain("VULNERÁVEL")
    expect(report).toContain("REMEDIADO")

    // O lab voltou ao estado vulnerável (senão o treino acabou sem querer)
    expect(result.manifest.configAtEnd).toEqual(VULNERABLE_CONFIG)
    const restored = JSON.parse(
      readFileSync(path.join(manager.getLabWorkspacePath("lab-owasp-api-bola"), "server-config.json"), "utf8"),
    )
    expect(restored).toEqual(VULNERABLE_CONFIG)

    // E7 prova que os 4 comportamentos inseguros voltaram
    for (const id of ["E7-01-bola", "E7-02-alg-none", "E7-03-sql-error", "E7-04-headers"]) {
      const rec = result.manifest.cases.find((c) => c.id === id)
      expect(rec).toBeDefined()
    }
    expect(result.manifest.cases.find((c) => c.id === "E7-01-bola")!.status).toBe(200)
    expect(result.manifest.cases.find((c) => c.id === "E7-02-alg-none")!.status).toBe(200)
  })

  test("headers de segurança monitorados são os 4 esperados", () => {
    expect(SECURITY_HEADERS).toEqual([
      "content-security-policy",
      "strict-transport-security",
      "x-frame-options",
      "x-content-type-options",
    ])
  })
})
