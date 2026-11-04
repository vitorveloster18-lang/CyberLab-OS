import { afterEach, describe, expect, it } from "bun:test"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
  NEUTRAL_PRIOR,
  assessDifferential,
  assessExperiment,
  bodyOf,
  classifyRole,
  evaluateHypothesis,
  runEvaluationPhase,
  updateConfidence,
  type ExperimentAssessment,
  type HypothesisAssessment,
} from "../../../cyberlab/labs/evaluation-phase.js"
import {
  classifyFinding,
  runValidationPhase,
} from "../../../cyberlab/labs/validation-phase.js"
import { runDocumentationPhase } from "../../../cyberlab/labs/documentation-phase.js"

/**
 * Fases G (Avaliação), H (Validação) e I (Documentação).
 *
 * O ciclo A–I está definido em `packages/core/src/plugin/agent.ts` §5, a taxonomia de
 * 5 níveis em `vault/CyberLab-Knowledge/methodologies/evidence-validation.md` e o
 * padrão de writeup em `.../research/technical-writeups/reproducible-writeup-standard.md`.
 *
 * O que mais pode dar errado aqui é justamente o que não quebra o build:
 *   1. **Promover achado sem diferencial.** Um marcador que aparece igual em baseline
 *      e PoC não prova nada — é o falso positivo clássico.
 *   2. **Descartar explicação alternativa automaticamente.** A metodologia manda o
 *      oposto ("se a evidência contradisser, não force a interpretação").
 *   3. **Vazar o segredo que prova o achado.** O writeup da Fase I carrega o token
 *      que ele mesmo usou; sem redação, o relatório é um incidente.
 */

const dirs: string[] = []
function tmpDir(): string {
  const d = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ghi-"))
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

const LAB = "lab-teste-ghi"

/** Uma captura crua mínima no formato que a Fase F arquiva. */
function raw(status: number, body: string): string {
  return `HTTP/1.1 ${status} OK\r\ncontent-type: application/json\r\n\r\n${body}`
}

function req(opts: {
  id?: string
  intent?: string
  status?: number
  body?: string
  outcome?: "executed" | "manual" | "error" | "planned"
  command?: string
  rawFile?: string
}) {
  return {
    experimentId: opts.id ?? "E1",
    intent: opts.intent ?? null,
    command: opts.command ?? "curl -s http://127.0.0.1/x",
    outcome: opts.outcome ?? "executed",
    httpStatus: opts.status ?? 200,
    raw: raw(opts.status ?? 200, opts.body ?? "{}"),
    sha256: "0".repeat(64),
    rawFile: opts.rawFile ?? "raw/E1-01.txt",
    error: null,
  }
}

function exp(opts: {
  id: string
  hypothesisId: string
  markers?: string[]
  indicator?: string
  requests?: ReturnType<typeof req>[]
}): Record<string, unknown> {
  return {
    seed: {
      id: opts.id,
      hypothesisId: opts.hypothesisId,
      question: `${opts.id}?`,
      expectedOutcome: "esperado",
    },
    hypothesisId: opts.hypothesisId,
    markersFound: opts.markers ?? [],
    indicator: opts.indicator ?? "sustenta",
    requests: opts.requests ?? [],
  }
}

function hyp(id: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    title: `Hipótese ${id}`,
    expectedBehavior: "comportamento esperado",
    suspectedBehavior: "comportamento suspeito",
    evidenceNeeded: "observação X",
    alternativeExplanations: ["Explicação alternativa A", "Explicação alternativa B"],
    priorityScore: 4,
    ...extra,
  }
}

function writePhase(root: string, fase: string, file: string, data: unknown): string {
  const dir = path.join(root, "research", LAB, fase, "2026-01-01T00-00-00-000Z")
  mkdirSync(dir, { recursive: true })
  writeFileSync(path.join(dir, file), JSON.stringify(data, null, 2), "utf8")
  return dir
}

// ---------------------------------------------------------------------------

describe("Fase G — papel da requisição e corpo bruto (v6.7)", () => {
  it("classifica o papel pelo comentário de intenção das sementes", () => {
    expect(classifyRole("BASELINE — sem token (esperado: 401)")).toBe("baseline")
    expect(classifyRole("PoC — JWT forjado (alg:none)")).toBe("poc")
    expect(classifyRole("CONTROLE — User B lendo a própria conta")).toBe("controle")
    expect(classifyRole("DICA: o token também é devolvido em")).toBe("outro")
    expect(classifyRole(null)).toBe("outro")
  })

  it("separa o corpo dos headers na captura crua", () => {
    expect(bodyOf("HTTP/1.1 200 OK\r\nx: y\r\n\r\n{\"a\":1}")).toBe('{"a":1}')
    expect(bodyOf("")).toBe("")
    expect(bodyOf(null)).toBe("")
  })
})

describe("Fase G — diferencial baseline ↔ PoC (v6.7)", () => {
  it("status diferente é diferencial confirmado", () => {
    const d = assessDifferential([
      req({ intent: "BASELINE", status: 401, body: '{"error":"no"}' }),
      req({ intent: "PoC", status: 200, body: '{"ok":true}' }),
    ])
    expect(d.state).toBe("confirmado")
    expect(d.statusChanged).toBe(true)
    expect(d.identicalBaselineAndPoc).toBe(false)
  })

  it("mesmo status mas corpo diferente também é diferencial", () => {
    // É o caso real do BOLA: 200 -> 200, mas o corpo traz outro titular.
    const d = assessDifferential([
      req({ intent: "BASELINE", body: '{"owner":"alice"}' }),
      req({ intent: "PoC", body: '{"owner":"bob"}' }),
    ])
    expect(d.state).toBe("confirmado")
    expect(d.statusChanged).toBe(false)
    expect(d.bodyChanged).toBe(true)
  })

  it("REGRESSÃO: baseline e PoC idênticos NÃO sustentam achado", () => {
    // O marcador aparecer nos dois lados não prova nada — é o falso positivo
    // que a taxonomia manda eliminar antes de classificar.
    const d = assessDifferential([
      req({ intent: "BASELINE", body: '{"owner":"alice"}' }),
      req({ intent: "PoC", body: '{"owner":"alice"}' }),
    ])
    expect(d.state).toBe("ausente")
    expect(d.identicalBaselineAndPoc).toBe(true)
    expect(d.note).toContain("idênticos")
  })

  it("sem baseline ou sem PoC o par fica incompleto", () => {
    const semBaseline = assessDifferential([req({ intent: "PoC", body: "{}" })])
    expect(semBaseline.state).toBe("incompleto")
    expect(semBaseline.note).toContain("controle")

    const semPoc = assessDifferential([req({ intent: "BASELINE", body: "{}" })])
    expect(semPoc.state).toBe("incompleto")
    expect(semPoc.note).toContain("experimental")
  })

  it("nada executado é par incompleto", () => {
    const d = assessDifferential([req({ outcome: "manual" }), req({ outcome: "planned" })])
    expect(d.state).toBe("incompleto")
    expect(d.baselineCount).toBe(0)
    expect(d.pocCount).toBe(0)
  })

  it("requisição de CONTROLE conta como linha de base", () => {
    const d = assessDifferential([
      req({ intent: "BASELINE", status: 401, body: "a" }),
      req({ intent: "CONTROLE", status: 401, body: "b" }),
      req({ intent: "PoC", status: 200, body: "c" }),
    ])
    expect(d.baselineCount).toBe(2)
    expect(d.pocCount).toBe(1)
    expect(d.state).toBe("confirmado")
  })
})

describe("Fase G — veredito por experimento (v6.7)", () => {
  it("marcador com diferencial sustenta", () => {
    const a = assessExperiment(
      exp({
        id: "E1",
        hypothesisId: "H1",
        markers: ["LAB{X}"],
        requests: [
          req({ intent: "BASELINE", status: 401, body: "a" }),
          req({ intent: "PoC", status: 200, body: "b" }),
        ],
      }) as never,
    )
    expect(a.verdict).toBe("sustenta")
    expect(a.markersFound).toEqual(["LAB{X}"])
  })

  it("REGRESSÃO: marcador SEM diferencial não sustenta", () => {
    // Marcador presente, mas baseline == PoC: o achado não demonstra diferença.
    const a = assessExperiment(
      exp({
        id: "E1",
        hypothesisId: "H1",
        markers: ["LAB{X}"],
        requests: [
          req({ intent: "BASELINE", body: "igual" }),
          req({ intent: "PoC", body: "igual" }),
        ],
      }) as never,
    )
    expect(a.verdict).toBe("indeterminado")
    expect(a.reason).toContain("idênticos")
  })

  it("marcador sem par verificável sustenta com ressalva", () => {
    const a = assessExperiment(
      exp({
        id: "E1",
        hypothesisId: "H1",
        markers: ["LAB{X}"],
        requests: [req({ intent: "PoC", status: 200, body: "b" })],
      }) as never,
    )
    expect(a.verdict).toBe("sustenta_com_ressalva")
  })

  it("mudança de status sem marcador sustenta com ressalva", () => {
    const a = assessExperiment(
      exp({
        id: "E1",
        hypothesisId: "H1",
        markers: [],
        requests: [
          req({ intent: "BASELINE", status: 200, body: "a" }),
          req({ intent: "PoC", status: 500, body: "b" }),
        ],
      }) as never,
    )
    expect(a.verdict).toBe("sustenta_com_ressalva")
    expect(a.reason).toContain("status mudou")
  })

  it("nada executado => nao_testada (e não 'refuta')", () => {
    const a = assessExperiment(
      exp({
        id: "E6",
        hypothesisId: "H1",
        requests: [req({ outcome: "manual" }), req({ outcome: "error" })],
      }) as never,
    )
    expect(a.verdict).toBe("nao_testada")
    expect(a.executedCount).toBe(0)
  })
})

describe("Fase G — confiança (v6.7)", () => {
  const sustenta = { verdict: "sustenta" } as ExperimentAssessment

  it("a priori é neutra, não o score de prioridade da Fase E", () => {
    // O score da Fase E responde "vale a pena investigar?", não "chance de ser
    // verdade?" — usá-lo como probabilidade saturava tudo em 0.95.
    expect(NEUTRAL_PRIOR).toBe(0.5)
  })

  it("retorno decrescente: o 2º experimento acrescenta menos que o 1º", () => {
    const um = updateConfidence(NEUTRAL_PRIOR, [sustenta])
    const dois = updateConfidence(NEUTRAL_PRIOR, [sustenta, sustenta])
    expect(um).toBe(0.8)
    expect(dois).toBe(0.95)
    expect(dois - um).toBeLessThan(um - NEUTRAL_PRIOR)
  })

  it("nunca afirma certeza absoluta", () => {
    const muitos = updateConfidence(NEUTRAL_PRIOR, Array.from({ length: 10 }, () => sustenta))
    expect(muitos).toBeLessThan(1)
    expect(muitos).toBe(0.95)
  })

  it("evidência contrária derruba a confiança", () => {
    const c = updateConfidence(NEUTRAL_PRIOR, [
      { verdict: "refuta" } as ExperimentAssessment,
      { verdict: "indeterminado" } as ExperimentAssessment,
    ])
    expect(c).toBeLessThan(NEUTRAL_PRIOR)
  })

  it("nada testado não altera a confiança", () => {
    expect(updateConfidence(NEUTRAL_PRIOR, [{ verdict: "nao_testada" } as ExperimentAssessment])).toBe(NEUTRAL_PRIOR)
  })
})

describe("Fase G — veredito por hipótese (v6.7)", () => {
  it("explicação alternativa NUNCA é descartada automaticamente", () => {
    const h = evaluateHypothesis(hyp("H1"), [], null)
    expect(h.alternativeExplanations.length).toBe(2)
    for (const alt of h.alternativeExplanations) {
      expect(alt.status).toBe("nao_descartada")
      expect(alt.wouldRuleOut).toContain("observação X")
    }
  })

  it("conflito entre experimentos gera ressalva, não veredito limpo", () => {
    const h = evaluateHypothesis(
      hyp("H1"),
      [
        exp({
          id: "E1",
          hypothesisId: "H1",
          markers: ["LAB{X}"],
          requests: [
            req({ intent: "BASELINE", status: 401, body: "a" }),
            req({ intent: "PoC", status: 200, body: "b" }),
          ],
        }),
        exp({
          id: "E2",
          hypothesisId: "H1",
          markers: [],
          requests: [
            req({ intent: "BASELINE", body: "m" }),
            req({ intent: "PoC", body: "m" }),
          ],
        }),
      ] as never,
      null,
    )
    expect(h.verdict).toBe("sustenta_com_ressalva")
    expect(h.reason).toContain("Conflito")
  })

  it("sinal de falso positivo é registrado quando o par é idêntico", () => {
    const h = evaluateHypothesis(
      hyp("H1"),
      [
        exp({
          id: "E1",
          hypothesisId: "H1",
          requests: [
            req({ intent: "BASELINE", body: "igual" }),
            req({ intent: "PoC", body: "igual" }),
          ],
        }),
      ] as never,
      null,
    )
    expect(h.falsePositiveFlags.some((f) => f.includes("idênticos"))).toBe(true)
  })

  it("sem experimento nenhum a hipótese fica 'nao_testada'", () => {
    const h = evaluateHypothesis(hyp("H1"), [], null)
    expect(h.verdict).toBe("nao_testada")
    expect(h.confidence).toBe(NEUTRAL_PRIOR)
  })
})

describe("Fase G — execução ponta a ponta (v6.7)", () => {
  it("sem Fase D falha com mensagem acionável", () => {
    expect(() => runEvaluationPhase({ labId: LAB, workspaceRoot: tmpDir() })).toThrow(/bun run cyberlab lab hypothesize/)
  })

  it("consome Fase D + Fase F e grava o relatório com lacre", () => {
    const ws = tmpDir()
    writePhase(ws, "fase-d", "hypotheses-d.json", { labId: LAB, hypotheses: [hyp("H1")] })
    writePhase(ws, "fase-f", "experiments-f.json", {
      labId: LAB,
      mode: "run",
      baseUrl: "http://127.0.0.1:19081",
      experiments: [
        exp({
          id: "E1",
          hypothesisId: "H1",
          markers: ["LAB{X}"],
          requests: [
            req({ intent: "BASELINE", status: 401, body: "a" }),
            req({ intent: "PoC", status: 200, body: "b" }),
          ],
        }),
      ],
    })

    const board = runEvaluationPhase({ labId: LAB, workspaceRoot: ws })
    expect(board.hypotheses[0]?.verdict).toBe("sustenta")
    expect(board.sources.faseF).toContain("fase-f")
    expect(board.seal).toMatch(/^[0-9a-f]{64}$/)
    expect(readFileSync(path.join(board.outputDir, "EVALUATION.md"), "utf8")).toContain("Fase G")
  })

  it("Fase F ausente não quebra: avalia sem evidência e declara a lacuna", () => {
    const ws = tmpDir()
    writePhase(ws, "fase-d", "hypotheses-d.json", { labId: LAB, hypotheses: [hyp("H1")] })
    const board = runEvaluationPhase({ labId: LAB, workspaceRoot: ws })
    expect(board.sources.faseF).toBeNull()
    expect(board.openQuestions.some((q) => q.includes("Fase F"))).toBe(true)
    expect(board.hypotheses[0]?.verdict).toBe("nao_testada")
  })
})

// ---------------------------------------------------------------------------

function assessed(over: Partial<HypothesisAssessment>): HypothesisAssessment {
  return {
    hypothesisId: "H1",
    title: "Hipótese H1",
    expectedBehavior: "",
    suspectedBehavior: "",
    priorityScore: 4,
    priorConfidence: NEUTRAL_PRIOR,
    confidence: 0.8,
    experiments: [],
    supporting: 1,
    contradicting: 0,
    untested: 0,
    verdict: "sustenta",
    reason: "",
    alternativeExplanations: [],
    falsePositiveFlags: [],
    impact: null,
    ...over,
  }
}

const diffConfirmado = {
  state: "confirmado" as const,
  baselineCount: 1,
  pocCount: 1,
  baselineStatuses: [401],
  pocStatuses: [200],
  statusChanged: true,
  bodyChanged: true,
  identicalBaselineAndPoc: false,
  note: "",
}

const executedExp = {
  experimentId: "E1",
  hypothesisId: "H1",
  question: "",
  expectedOutcome: "",
  indicator: "sustenta",
  markersFound: ["LAB{X}"],
  executedCount: 2,
  manualCount: 0,
  errorCount: 0,
  pairs: [],
  differential: diffConfirmado,
  verdict: "sustenta" as const,
  reason: "",
}

describe("Fase H — taxonomia obrigatória (v6.7)", () => {
  it("sustenta + par verificável + vetor direto => vulnerabilidade confirmada", () => {
    const { classification } = classifyFinding(
      assessed({
        verdict: "sustenta",
        experiments: [executedExp],
        impact: { dimension: "confidentiality", vector: "direct", rationale: "r" },
      }),
    )
    expect(classification).toBe("vulnerabilidade_confirmada")
  })

  it("REGRESSÃO: sustenta SEM par verificável é potencial, nunca confirmada", () => {
    const { classification, rule } = classifyFinding(
      assessed({
        verdict: "sustenta",
        experiments: [{ ...executedExp, differential: { ...diffConfirmado, state: "incompleto" } }],
        impact: { dimension: "confidentiality", vector: "direct", rationale: "r" },
      }),
    )
    expect(classification).toBe("vulnerabilidade_potencial")
    expect(rule).toContain("prova determinística")
  })

  it("diferencial provado mas impacto declarado ausente => configuração insegura", () => {
    const { classification } = classifyFinding(
      assessed({
        verdict: "sustenta",
        experiments: [executedExp],
        impact: { dimension: "none", vector: "none", rationale: "headers ausentes" },
      }),
    )
    expect(classification).toBe("configuracao_insegura")
  })

  it("sem execução e impacto declarado ausente => configuração insegura (hardening)", () => {
    const { classification } = classifyFinding(
      assessed({
        experiments: [],
        impact: { dimension: "none", vector: "none", rationale: "headers ausentes" },
      }),
    )
    expect(classification).toBe("configuracao_insegura")
  })

  it("sem execução e impacto desconhecido => não classificado (não inventa)", () => {
    const { classification, rule } = classifyFinding(assessed({ experiments: [], impact: null }))
    expect(classification).toBe("nao_classificado")
    expect(rule).toContain("Nenhum experimento executado")
  })

  it("5xx sem impacto em C/I/A => falha funcional", () => {
    const { classification } = classifyFinding(
      assessed({
        experiments: [
          {
            ...executedExp,
            differential: { ...diffConfirmado, pocStatuses: [500], statusChanged: true },
          },
        ],
        impact: { dimension: "none", vector: "none", rationale: "r" },
      }),
    )
    expect(classification).toBe("falha_funcional")
  })

  it("diferencial sem sustentar => comportamento inesperado", () => {
    const { classification } = classifyFinding(
      assessed({
        verdict: "indeterminado",
        experiments: [executedExp],
        impact: { dimension: "confidentiality", vector: "direct", rationale: "r" },
      }),
    )
    expect(classification).toBe("comportamento_inesperado")
  })

  it("hipótese refutada não vira achado", () => {
    const { classification } = classifyFinding(
      assessed({ verdict: "refuta", experiments: [executedExp], impact: null }),
    )
    expect(classification).toBe("nao_classificado")
  })

  it("sem Fase G falha com mensagem acionável", () => {
    expect(() => runValidationPhase({ labId: LAB, workspaceRoot: tmpDir() })).toThrow(/bun run cyberlab lab evaluate/)
  })
})

// ---------------------------------------------------------------------------

describe("Fase I — relatório reproduzível (v6.7)", () => {
  it("sem Fase H falha com mensagem acionável", () => {
    expect(() => runDocumentationPhase({ labId: LAB, workspaceRoot: tmpDir() })).toThrow(
      /bun run cyberlab lab validate/,
    )
  })

  it("REGRESSÃO: o token que prova o achado NÃO aparece no relatório", () => {
    const ws = tmpDir()
    const token = "Bearer token-user-a-1001"
    const fDir = writePhase(ws, "fase-f", "experiments-f.json", {
      labId: LAB,
      mode: "run",
      baseUrl: "http://127.0.0.1:19081",
      experiments: [
        {
          seed: { id: "E1", hypothesisId: "H1", question: "q", expectedOutcome: "e" },
          hypothesisId: "H1",
          markersFound: ["LAB{X}"],
          indicator: "sustenta",
          requests: [
            {
              experimentId: "E1",
              intent: "BASELINE",
              command: `curl -s -i -H "Authorization: ${token}" http://127.0.0.1:19081/api/v1/accounts/1001`,
              outcome: "executed",
              httpStatus: 200,
              raw: raw(200, '{"owner":"alice"}'),
              sha256: "a".repeat(64),
              rawFile: "raw/E1-01.txt",
            },
            {
              experimentId: "E1",
              intent: "PoC",
              command: `curl -s -i -H "Authorization: ${token}" http://127.0.0.1:19081/api/v1/accounts/1002`,
              outcome: "executed",
              httpStatus: 200,
              raw: raw(200, `{"owner":"bob","authorization":"${token}"}`),
              sha256: "b".repeat(64),
              rawFile: "raw/E1-02.txt",
            },
          ],
        },
      ],
    })
    // Arquivo cru no disco, igual à Fase F.
    mkdirSync(path.join(fDir, "raw"), { recursive: true })
    writeFileSync(path.join(fDir, "raw", "E1-01.txt"), raw(200, '{"owner":"alice"}'), "utf8")
    writeFileSync(
      path.join(fDir, "raw", "E1-02.txt"),
      raw(200, `{"owner":"bob","authorization":"${token}"}`),
      "utf8",
    )

    writePhase(ws, "fase-d", "hypotheses-d.json", {
      labId: LAB,
      hypotheses: [
        hyp("H1", {
          technicalRationale: "mecanismo",
          fragileAssumption: "pressuposto",
          severityIfConfirmed: "Alta",
          relatedControlFlag: "enforceAccountOwnership",
        }),
      ],
    })

    const g = runEvaluationPhase({ labId: LAB, workspaceRoot: ws })
    expect(g.hypotheses[0]?.verdict).toBe("sustenta")
    runValidationPhase({ labId: LAB, workspaceRoot: ws })
    const board = runDocumentationPhase({ labId: LAB, workspaceRoot: ws })

    const md = readFileSync(path.join(board.outputDir, "WRITEUP.md"), "utf8")
    // O segredo não pode vazar — nem no comando, nem na resposta custodiada.
    expect(md).not.toContain("token-user-a-1001")
    expect(md).toContain("[REDACTED")
    // Mas a prova continua lá: o par baseline/PoC e o corpo que diferencia.
    expect(md).toContain("alice")
    expect(md).toContain("bob")
    // E as 6 seções do padrão.
    expect(md).toContain("## 1. Resumo Executivo")
    expect(md).toContain("## 2. Ativo, Escopo e Condições de Teste")
    expect(md).toContain("item 3 do padrão")
    expect(md).toContain("item 4 do padrão")
    expect(md).toContain("item 5 do padrão")
    expect(md).toContain("item 6 do padrão")
    // Recomendação aponta o CONTROLE que faltou, não "corrija o bug".
    expect(md).toContain("enforceAccountOwnership")
  })
})
