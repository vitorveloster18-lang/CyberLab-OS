import { afterEach, describe, expect, it } from "bun:test"
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs"
import { mkdtempSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
  collectAnchors,
  keywordMatches,
  loadLatestResearch,
  parseImpact,
  priorityScore,
  runHypothesisPhase,
  scoreHypothesis,
} from "../../../cyberlab/labs/hypothesis-phase.js"
import { buildLabInvestigationKit } from "../../../cyberlab/labs/investigation-kit.js"
import { getLabResearchProfile } from "../../../cyberlab/labs/research-profile.js"

/**
 * Fase D — Hipóteses ancoradas na Fase C + priorização (Fase E).
 *
 * O risco real deste módulo não é quebrar: é **ancorar errado**. Uma âncora falsa
 * faz o operador crer que uma falha de lógica de aplicação tem CVE de biblioteca —
 * e foi exatamente o que aconteceu na primeira versão (ver teste do H1 abaixo).
 */

const LAB_ID = "lab-owasp-api-bola"

const dirs: string[] = []
function tmpDir(): string {
  const d = mkdtempSync(path.join(os.tmpdir(), "cyberlab-fase-d-"))
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

function writeFakeResearch(ws: string, stamp: string, advisories: unknown[]): string {
  const dir = path.join(ws, "research", LAB_ID, stamp)
  mkdirSync(dir, { recursive: true })
  writeFileSync(
    path.join(dir, "research.json"),
    JSON.stringify(
      {
        labId: LAB_ID,
        generatedAt: "2026-11-04T00:00:00.000Z",
        advisories: [
          {
            target: {
              ecosystem: "npm",
              package: "jsonwebtoken",
              rationale: "r",
              anchorKeywords: ["jwt", "alg:none", "assinatura", "signature"],
            },
            status: "ok",
            httpStatus: 200,
            error: null,
            advisories,
            rawFile: null,
            rawSha256: null,
            fetchedAt: "2026-11-04T00:00:00.000Z",
          },
        ],
      },
      null,
      2,
    ),
    "utf8",
  )
  return dir
}

const ONE_ADVISORY = [
  {
    ghsaId: "GHSA-c7hr-j4mj-j2w6",
    cveId: "CVE-2015-9235",
    summary: "jsonwebtoken signature validation bypass (alg:none)",
    severity: "critical",
    cvssScore: null,
    cvssVector: null,
    ecosystem: "npm",
    packageName: "jsonwebtoken",
    vulnerableVersionRange: "< 4.2.2",
    firstPatchedVersion: "4.2.2",
    publishedAt: "2018-10-09T00:00:00Z",
    updatedAt: "2018-10-09T00:00:00Z",
    withdrawnAt: null,
    url: "https://github.com/advisories/GHSA-c7hr-j4mj-j2w6",
    references: [],
  },
]

describe("Fase D — casamento de keywords (v6.7)", () => {
  it("casa por palavra, não por substring", () => {
    expect(keywordMatches("bypass de assinatura jwt", "jwt")).toBe(true)
    // `alg` como substring casaria com "algum"/"alguma" em português.
    expect(keywordMatches("isso não tem a ver com algum token", "alg")).toBe(false)
    expect(keywordMatches("header alg:none aceito", "alg:none")).toBe(true)
    // "BOLA/IDOR": a barra é separador de palavra.
    expect(keywordMatches("bola/idor: token do user a", "bola")).toBe(true)
  })

  it("ignora keyword vazia em vez de casar com tudo", () => {
    expect(keywordMatches("qualquer coisa", "")).toBe(false)
    expect(keywordMatches("qualquer coisa", "   ")).toBe(false)
  })
})

describe("Fase D — ancoragem Fase C -> Fase D (v6.7)", () => {
  it("a hipótese de JWT recebe os advisories de JWT", () => {
    const k = kit()
    const h2 = k.hypotheses.find((h) => h.id === "H2")!
    const research = loadLatestResearch(
      (() => {
        const ws = tmpDir()
        writeFakeResearch(ws, "2026-11-04T00-00-00-000Z", ONE_ADVISORY)
        return ws
      })(),
      LAB_ID,
    )
    const anchors = collectAnchors(h2, getLabResearchProfile(LAB_ID), research)
    const advisories = anchors.filter((a) => a.kind === "advisory")
    expect(advisories.length).toBe(1)
    expect(advisories[0]!.ref).toBe("CVE-2015-9235")
    // CWE-347 aparece no próprio racional técnico da H2.
    expect(anchors.some((a) => a.ref === "CWE-347")).toBe(true)
    // RFC 8725 é a fonte primária do alg:none.
    expect(anchors.some((a) => a.kind === "primary_source" && a.ref.includes("RFC 8725"))).toBe(
      true,
    )
  })

  it("REGRESSÃO: a hipótese de BOLA NÃO puxa os advisories de JWT", () => {
    // Bug real da primeira versão: com `token` na lista de keywords, o H1
    // ("o token do User A...") puxava os 32 advisories de JWT. BOLA é falha de
    // lógica de aplicação — não tem CVE de biblioteca.
    const k = kit()
    const h1 = k.hypotheses.find((h) => h.id === "H1")!
    const research = loadLatestResearch(
      (() => {
        const ws = tmpDir()
        writeFakeResearch(ws, "2026-11-04T00-00-00-000Z", ONE_ADVISORY)
        return ws
      })(),
      LAB_ID,
    )
    const anchors = collectAnchors(h1, getLabResearchProfile(LAB_ID), research)
    expect(anchors.filter((a) => a.kind === "advisory")).toEqual([])
    // Mas continua ancorada na classificação e na fonte primária corretas.
    expect(anchors.some((a) => a.ref === "CWE-639")).toBe(true)
    expect(anchors.some((a) => a.kind === "primary_source" && a.ref.includes("BOLA"))).toBe(true)
  })

  it("sem Fase C, a hipótese fica ancorada só no que é estrutural", () => {
    const k = kit()
    const h2 = k.hypotheses.find((h) => h.id === "H2")!
    const anchors = collectAnchors(h2, getLabResearchProfile(LAB_ID), null)
    expect(anchors.filter((a) => a.kind === "advisory")).toEqual([])
    expect(anchors.some((a) => a.ref === "CWE-347")).toBe(true)
  })
})

describe("Fase D — priorização (Fase E)", () => {
  it("converte a severidade declarada em impacto", () => {
    expect(parseImpact("Crítica — escalada de privilégio")).toBe(5)
    expect(parseImpact("Alta — exposição de dados")).toBe(4)
    // Numa faixa ("Média/Alta", "Baixa/Média") vale o TETO: subestimar impacto
    // rebaixaria a prioridade de uma hipótese real.
    expect(parseImpact("Média/Alta — informação sensível")).toBe(4)
    expect(parseImpact("Baixa/Média — defesa em profundidade")).toBe(3)
    expect(parseImpact("sem severidade declarada")).toBe(3)
  })

  it("controle desligado + âncora é o máximo de plausibilidade", () => {
    const h = kit().hypotheses[0]!
    const base = { hypothesis: h, experiments: [], anchors: [] }
    expect(scoreHypothesis({ ...base, controlCurrentlyOff: false }).plausibility).toBe(2)
    expect(scoreHypothesis({ ...base, controlCurrentlyOff: true }).plausibility).toBe(4)
    expect(
      scoreHypothesis({
        ...base,
        controlCurrentlyOff: true,
        anchors: [{ kind: "weakness", ref: "CWE-1", detail: "d" }],
      }).plausibility,
    ).toBe(5)
  })

  it("mais experimentos independentes = mais poder diferenciador", () => {
    const k = kit()
    const h = k.hypotheses[0]!
    const exps = k.experiments.filter((e) => e.hypothesisId === h.id)
    expect(
      scoreHypothesis({ hypothesis: h, experiments: [], anchors: [], controlCurrentlyOff: false })
        .discriminatingPower,
    ).toBe(2)
    expect(
      scoreHypothesis({
        hypothesis: h,
        experiments: exps.slice(0, 1),
        anchors: [],
        controlCurrentlyOff: false,
      }).discriminatingPower,
    ).toBe(4)
    expect(
      scoreHypothesis({ hypothesis: h, experiments: exps, anchors: [], controlCurrentlyOff: false })
        .discriminatingPower,
    ).toBe(5)
  })

  it("o score é determinístico e o risco subtrai", () => {
    const scores = {
      plausibility: 5,
      impact: 5,
      discriminatingPower: 5,
      evidenceAvailable: 5,
      cost: 5,
      executionRisk: 1,
    }
    const low = priorityScore(scores)
    expect(low).toBe(priorityScore(scores))
    expect(priorityScore({ ...scores, executionRisk: 5 })).toBeLessThan(low)
    expect(priorityScore({ ...scores, plausibility: 1 })).toBeLessThan(low)
  })
})

describe("Fase D — execução ponta a ponta (v6.7)", () => {
  it("grava HYPOTHESES-D.md, hypotheses-d.json e o manifesto", () => {
    const ws = tmpDir()
    writeFakeResearch(ws, "2026-11-04T00-00-00-000Z", ONE_ADVISORY)
    const out = path.join(ws, "saida")
    const board = runHypothesisPhase({ labId: LAB_ID, workspaceRoot: ws, outDir: out })

    expect(board.hypotheses.length).toBe(kit().hypotheses.length)
    expect(board.researchDir).toBeTruthy()
    for (const name of ["HYPOTHESES-D.md", "hypotheses-d.json", "hypotheses-manifest.json"]) {
      expect(existsSync(path.join(out, name))).toBe(true)
    }
    for (const f of board.files) expect(f.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(board.seal).toMatch(/^[0-9a-f]{64}$/)

    const md = readFileSync(path.join(out, "HYPOTHESES-D.md"), "utf8")
    expect(md).toContain("# Fase D")
    expect(md).toContain("Critério de priorização")
    expect(md).toContain("CVE-2015-9235")
    expect(md).toContain("Ordem de investigação")
  })

  it("ordena por score decrescente sem perder hipótese", () => {
    const ws = tmpDir()
    writeFakeResearch(ws, "2026-11-04T00-00-00-000Z", ONE_ADVISORY)
    const board = runHypothesisPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "o"),
    })
    const scores = board.hypotheses.map((h) => h.priorityScore)
    expect(scores).toEqual([...scores].sort((a, b) => b - a))
    expect(new Set(board.hypotheses.map((h) => h.id)).size).toBe(kit().hypotheses.length)
    // A mais bem ancorada (JWT) fica em primeiro.
    expect(board.hypotheses[0]!.id).toBe("H2")
  })

  it("sem Fase C avisa em vez de ancorar no escuro", () => {
    const ws = tmpDir()
    const board = runHypothesisPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "sem-pesquisa"),
    })
    expect(board.researchDir).toBeNull()
    const md = readFileSync(path.join(board.outputDir, "HYPOTHESES-D.md"), "utf8")
    // Sem negrito na asserção: o markdown enfatiza o "NÃO" e quebraria o toContain.
    expect(md).toContain("NÃO")
    expect(md).toContain("bun run cyberlab lab research")
  })

  it("marca a lacuna de cada hipótese (sem esconder o que não foi ancorado)", () => {
    const ws = tmpDir()
    writeFakeResearch(ws, "2026-11-04T00-00-00-000Z", ONE_ADVISORY)
    const board = runHypothesisPhase({
      labId: LAB_ID,
      workspaceRoot: ws,
      outDir: path.join(ws, "lacunas"),
    })
    const byId = new Map(board.hypotheses.map((h) => [h.id, h]))
    // H4 (headers) não tem CWE nem advisory no perfil: precisa ser declarada.
    expect(byId.get("H4")!.anchors).toEqual([])
    expect(byId.get("H4")!.gap).toContain("Sem nenhuma âncora")
    // H1 é ancorada, mas sem advisory — e isso é esperado, não um defeito.
    expect(byId.get("H1")!.gap).toContain("sem advisory")
  })

  it("lab sem Kit de Investigação falha com mensagem acionável", () => {
    expect(() =>
      runHypothesisPhase({
        labId: "lab-que-nao-existe",
        workspaceRoot: tmpDir(),
      }),
    ).toThrow(/não tem Kit de Investigação/)
  })
})
