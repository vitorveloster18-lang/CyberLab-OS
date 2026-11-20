import { afterEach, describe, expect, it } from "bun:test"
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { orderExperiments, parseCurlCommand, runExperimentPhase, tokenize } from "../../../cyberlab/labs/experiment-phase.js"
import { buildLabInvestigationKit } from "../../../cyberlab/labs/investigation-kit.js"
import { getLabResearchProfile } from "../../../cyberlab/labs/research-profile.js"

/**
 * Fase F — Experimentação Controlada.
 *
 * Duas coisas podem dar muito errado aqui, e nenhuma quebra o build:
 *   1. **Executar o que não deveria.** Os comandos das sementes incluem PowerShell
 *      (`Set-Content`) e `printf` — passar isso por um shell seria executar
 *      remediação no alvo sem o operador pedir.
 *   2. **Mentir no indicador.** Um experimento que não rodou nada (todos manuais)
 *      saindo como "nao_observado" sugere que a hipótese caiu, quando nada foi testado.
 */

const LAB_ID = "lab-owasp-api-bola"

const dirs: string[] = []
function tmpDir(): string {
  const d = mkdtempSync(path.join(os.tmpdir(), "cyberlab-fase-f-"))
  dirs.push(d)
  return d
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    for (let i = 0; i < 5; i++) {
      try {
        rmSync(d, { recursive: true, force: true })
        break
      } catch {
        Bun.sleepSync(30)
      }
    }
  }
})

function kit() {
  const k = buildLabInvestigationKit(LAB_ID, null)
  if (!k) throw new Error("kit não encontrado")
  return k
}

describe("Fase F — parse do comando curl (v6.7)", () => {
  it("converte o `curl -s -i -H` das sementes em requisição estruturada", () => {
    const parsed = parseCurlCommand(
      'curl -s -i -H "Authorization: Bearer token-user-a-1001" http://127.0.0.1:19081/api/v1/accounts/1001',
    )
    expect(parsed).not.toBeNull()
    expect(parsed!.method).toBe("GET")
    expect(parsed!.url).toBe("http://127.0.0.1:19081/api/v1/accounts/1001")
    expect(parsed!.headers["Authorization"]).toBe("Bearer token-user-a-1001")
    expect(parsed!.body).toBeNull()
  })

  it("suporta -X, -d e aspas simples", () => {
    const parsed = parseCurlCommand(
      "curl -s -X POST -d 'a=1&b=2' -H 'Content-Type: application/x-www-form-urlencoded' http://x/y",
    )
    expect(parsed!.method).toBe("POST")
    expect(parsed!.body).toBe("a=1&b=2")
    expect(parsed!.headers["Content-Type"]).toBe("application/x-www-form-urlencoded")
  })

  it("-d sem -X vira POST (comportamento do curl)", () => {
    expect(parseCurlCommand("curl -s -d 'x=1' http://x/y")!.method).toBe("POST")
  })

  it("recusa tudo que não seja o subconjunto suportado", () => {
    // `-o` e `-w` descartam/formatam a saída: executar produziria captura enganosa.
    expect(parseCurlCommand('curl -s -o /dev/null -w "%{http_code}" http://x/y')).toBeNull()
    expect(parseCurlCommand("curl -s -D - -o /dev/null http://x/y")).toBeNull()
    // Não é curl.
    expect(parseCurlCommand("Set-Content -Encoding utf8 x.json '{}'")).toBeNull()
    expect(parseCurlCommand("printf '%s\\n' '{}' > x.json")).toBeNull()
    // Comentário e vazio.
    expect(parseCurlCommand("# apenas um comentário")).toBeNull()
    expect(parseCurlCommand("   ")).toBeNull()
    // Header malformado, URL faltando, URL relativa, flag sem valor.
    expect(parseCurlCommand('curl -s -H "SemDoisPontos" http://x/y')).toBeNull()
    expect(parseCurlCommand("curl -s -H 'A: b'")).toBeNull()
    expect(parseCurlCommand("curl -s /api/v1/x")).toBeNull()
    expect(parseCurlCommand("curl -s -H")).toBeNull()
  })

  it("aceita `curl.exe` do Windows", () => {
    expect(parseCurlCommand("curl.exe -s http://x/y")).not.toBeNull()
  })

  it("tokenize respeita aspas simples e duplas", () => {
    expect(tokenize(`-H "Authorization: Bearer a b" -H 'X: y'`)).toEqual([
      "-H",
      "Authorization: Bearer a b",
      "-H",
      "X: y",
    ])
  })
})

describe("Fase F — ordem dos experimentos (v6.7)", () => {
  it("segue a prioridade da Fase D quando existe", () => {
    const k = kit()
    const ordered = orderExperiments(k, ["H2", "H1", "H3", "H4"])
    expect(ordered[0]!.hypothesisId).toBe("H2")
    // Dentro da mesma hipótese, ordem alfabética estável.
    const h1 = ordered.filter((e) => e.hypothesisId === "H1").map((e) => e.id)
    expect(h1).toEqual([...h1].sort())
  })

  it("sem Fase D, preserva a ordem das sementes", () => {
    const k = kit()
    expect(orderExperiments(k, null).map((e) => e.id)).toEqual(k.experiments.map((e) => e.id))
  })

  it("--only filtra sem quebrar a ordem relativa", () => {
    const k = kit()
    const ordered = orderExperiments(k, ["H2", "H1"], ["E1", "E3"])
    expect(ordered.map((e) => e.id).sort()).toEqual(["E1", "E3"])
  })
})

describe("Fase F — execução (v6.7)", () => {
  const fakeFetch = (
    handler: (url: string, init: RequestInit) => { status: number; body: string },
  ) =>
    (async (input: unknown, init: RequestInit) => {
      const url = typeof input === "string" ? input : String((input as Request).url)
      const r = handler(url, init)
      return new Response(r.body, {
        status: r.status,
        headers: { "content-type": "application/json" },
      })
    }) as unknown as typeof fetch

  const BOLA_BODY = '{"owner":"bob@corp.lab","bolaFlag":"LAB{BOLA_CROSS_ACCOUNT_EXPOSED}"}'

  it("no modo plano NÃO toca a rede e marca tudo como planejado/manual", async () => {
    const ws = tmpDir()
    let calls = 0
    const board = await runExperimentPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "plano"),
      fetchImpl: (async () => {
        calls += 1
        return new Response("{}")
      }) as unknown as typeof fetch,
    })
    expect(calls).toBe(0)
    expect(board.mode).toBe("plan")
    for (const e of board.experiments) {
      expect(e.indicator).toBe("nao_executado")
      for (const r of e.requests) {
        expect(["planned", "manual"]).toContain(r.outcome)
        expect(r.raw).toBeNull()
      }
    }
  })

  it("no modo --run executa, arquiva o bruto com SHA-256 e acha o marcador", async () => {
    const ws = tmpDir()
    const board = await runExperimentPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "run"),
      run: true,
      only: ["E1"],
      fetchImpl: fakeFetch((url) => ({
        status: url.endsWith("1002") ? 200 : 200,
        body: BOLA_BODY,
      })),
    })
    expect(board.mode).toBe("run")
    const e1 = board.experiments.find((e) => e.seed.id === "E1")!
    expect(e1.requests.every((r) => r.outcome === "executed")).toBe(true)
    expect(e1.markersFound).toContain("LAB{BOLA_CROSS_ACCOUNT_EXPOSED}")
    expect(e1.indicator).toBe("sustenta")

    for (const r of e1.requests) {
      expect(r.rawFile).toBeTruthy()
      expect(r.sha256).toMatch(/^[0-9a-f]{64}$/)
      const onDisk = readFileSync(path.join(board.outputDir, r.rawFile!), "utf8")
      expect(onDisk).toContain("HTTP/1.1 200")
      expect(onDisk).toContain("LAB{BOLA_CROSS_ACCOUNT_EXPOSED}")
    }
    expect(existsSync(path.join(board.outputDir, "EXPERIMENTS.md"))).toBe(true)
    expect(board.seal).toMatch(/^[0-9a-f]{64}$/)
  })

  it("REGRESSÃO: experimento sem nenhuma requisição executada é 'nao_executado', não 'nao_observado'", async () => {
    // E6 aplica remediação via PowerShell/printf: nenhum comando é executável.
    // Dizer "nao_observado" sugeriria que a hipótese caiu — nada foi testado.
    const ws = tmpDir()
    const board = await runExperimentPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "e6"),
      run: true,
      only: ["E6"],
      fetchImpl: fakeFetch(() => ({ status: 200, body: "{}" })),
    })
    const e6 = board.experiments.find((e) => e.seed.id === "E6")!
    expect(e6.requests.every((r) => r.outcome === "manual")).toBe(true)
    expect(e6.indicator).toBe("nao_executado")
  })

  it("marcador ausente => 'nao_observado' (não inventa sustentação)", async () => {
    const ws = tmpDir()
    const board = await runExperimentPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "sem-marcador"),
      run: true,
      only: ["E1"],
      fetchImpl: fakeFetch(() => ({ status: 403, body: '{"error":"forbidden"}' })),
    })
    const e1 = board.experiments.find((e) => e.seed.id === "E1")!
    expect(e1.markersFound).toEqual([])
    expect(e1.indicator).toBe("nao_observado")
  })

  it("hipótese sem marcador declarado => 'sem_marcador' (avaliação manual)", async () => {
    const profile = getLabResearchProfile(LAB_ID)
    expect(profile.observationMarkers["H4"]).toEqual([])
    const ws = tmpDir()
    const board = await runExperimentPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "h4"),
      run: true,
      only: ["E5"],
      fetchImpl: fakeFetch(() => ({ status: 200, body: "{}" })),
    })
    const e5 = board.experiments.find((e) => e.seed.id === "E5")
    if (e5 && e5.requests.some((r) => r.outcome === "executed")) {
      expect(e5.indicator).toBe("sem_marcador")
    }
  })

  it("erro de rede vira registro, não exceção", async () => {
    const ws = tmpDir()
    const board = await runExperimentPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "erro"),
      run: true,
      only: ["E1"],
      fetchImpl: (async () => {
        throw new Error("ECONNREFUSED")
      }) as unknown as typeof fetch,
    })
    const e1 = board.experiments.find((e) => e.seed.id === "E1")!
    expect(e1.requests.every((r) => r.outcome === "error")).toBe(true)
    expect(e1.requests[0]!.error).toContain("ECONNREFUSED")
    expect(e1.indicator).toBe("nao_executado")
  })

  it("--port redireciona o alvo sem alterar o comando registrado", async () => {
    const ws = tmpDir()
    const seen: string[] = []
    const board = await runExperimentPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "porta"),
      run: true,
      baseUrl: "http://127.0.0.1:19999",
      only: ["E1"],
      fetchImpl: fakeFetch((url) => {
        seen.push(url)
        return { status: 200, body: BOLA_BODY }
      }),
    })
    expect(seen.length).toBeGreaterThan(0)
    for (const u of seen) expect(u.startsWith("http://127.0.0.1:19999/")).toBe(true)
    // O comando original segue registrado: é o que o operador precisa poder reexecutar.
    expect(board.experiments[0]!.requests[0]!.command).toContain("19081")
  })

  it("lab sem Kit de Investigação falha com mensagem acionável", async () => {
    expect(
      runExperimentPhase({ labId: "lab-que-nao-existe", workspaceRoot: tmpDir() }),
    ).rejects.toThrow(/não tem Kit de Investigação/)
  })
})
