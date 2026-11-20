/**
 * Fase G — Avaliação Crítica.
 *
 * Definição metodológica (`packages/core/src/plugin/agent.ts`, Ciclo A–I):
 *   "compare observado vs. esperado e atualize a confiança. Se a evidência
 *    contradisser a hipótese, não force a interpretação: descarte-a, refine-a ou
 *    investigue explicação alternativa."
 *
 * A Fase F entrega um **indicador** — "o marcador apareceu". A Fase G transforma isso
 * em **decisão**, e faz três coisas que a Fase F não faz:
 *
 * 1. **Diferencial baseline ↔ PoC.** A metodologia (`hypothesis-driven-testing.md`)
 *    exige experimento diferenciador: muda-se UMA variável entre uma requisição de
 *    controle e a experimental. Se baseline e PoC voltam idênticos (mesmo status e
 *    mesmo corpo), não há diferencial — o "marcador encontrado" é suspeita de falso
 *    positivo, não evidência. Isso é verificável comparando os SHA-256 capturados.
 * 2. **Confiança atualizada.** Parte do score da Fase D como priori e sobe/desce
 *    conforme a evidência, em vez de tratar todo achado como igualmente certo.
 * 3. **Explicações alternativas.** Nenhuma é dada como descartada automaticamente:
 *    elas são listadas como pendências que someone precisa descartar antes de
 *    confirmar. É a regra "não force a interpretação" virando comportamento do código.
 */

import { createHash } from "node:crypto"
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs"
import path from "node:path"
import { getLabResearchProfile, type ImpactDeclaration } from "./research-profile.js"

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------

export type Role = "baseline" | "poc" | "controle" | "outro"

export type DifferentialState = "confirmado" | "ausente" | "incompleto"

/** Resultado da comparação baseline ↔ PoC — o coração da eliminação de falso positivo. */
export interface DifferentialCheck {
  state: DifferentialState
  /** Requisições de controle executadas (papel `baseline` ou `controle`). */
  baselineCount: number
  /** Requisições experimentais executadas (papel `poc`). */
  pocCount: number
  /** Status HTTP distintos entre baseline e PoC. */
  baselineStatuses: number[]
  pocStatuses: number[]
  /** O status mudou entre baseline e PoC? */
  statusChanged: boolean
  /** O corpo mudou entre baseline e PoC? (comparação por SHA-256) */
  bodyChanged: boolean
  /**
   * `true` quando baseline e PoC voltaram EXATAMENTE iguais. É o sinal clássico de
   * falso positivo: o achado não demonstra diferença nenhuma, então "encontrar o
   * marcador" nos dois lados não prova nada.
   */
  identicalBaselineAndPoc: boolean
  note: string
}

export type ExperimentVerdict = "sustenta" | "sustenta_com_ressalva" | "indeterminado" | "refuta" | "nao_testada"

export interface ExperimentAssessment {
  experimentId: string
  hypothesisId: string
  question: string
  /** O que a semente dizia que deveria acontecer. */
  expectedOutcome: string
  /** Indicador vindo da Fase F. */
  indicator: string
  markersFound: string[]
  executedCount: number
  manualCount: number
  errorCount: number
  /** Requisições executadas, com papel e custódia — base da reprodução na Fase I. */
  pairs: RequestPair[]
  differential: DifferentialCheck
  verdict: ExperimentVerdict
  /** Por que este veredito — a regra que disparou. */
  reason: string
}

export type HypothesisVerdict = "sustenta" | "sustenta_com_ressalva" | "refuta" | "indeterminado" | "nao_testada"

export interface AlternativeExplanation {
  text: string
  /** Sempre `nao_descartada`: descartar é trabalho de quem analisa, não do código. */
  status: "nao_descartada"
  /** O que seria preciso observar para descartá-la. */
  wouldRuleOut: string
}

export interface HypothesisAssessment {
  hypothesisId: string
  title: string
  expectedBehavior: string
  suspectedBehavior: string
  /** Score de prioridade da Fase E (0–5), quando existir. Só para exibição. */
  priorityScore: number | null
  /** Confiança antes da evidência (0–1). */
  priorConfidence: number
  /** Confiança depois da evidência (0–1). */
  confidence: number
  experiments: ExperimentAssessment[]
  supporting: number
  contradicting: number
  untested: number
  verdict: HypothesisVerdict
  /** Justificativa do veredito, citando os números que a produziram. */
  reason: string
  alternativeExplanations: AlternativeExplanation[]
  /** Sinais de falso positivo detectados mecanicamente. */
  falsePositiveFlags: string[]
  /** Impacto declarado no perfil — consumido pela Fase H. */
  impact: ImpactDeclaration | null
}

export interface EvaluationBoard {
  labId: string
  generatedAt: string
  outputDir: string
  /** De onde vieram os artefatos consumidos. */
  sources: { faseD: string | null; faseF: string | null }
  hypotheses: HypothesisAssessment[]
  /** Contagem por veredito, para o resumo. */
  summary: Record<HypothesisVerdict, number>
  openQuestions: string[]
  files: string[]
  seal: string
}

export interface RunEvaluationPhaseParams {
  labId: string
  workspaceRoot: string
  outDir?: string
  now?: Date
  /** Restringe a avaliação a estas hipóteses (ex.: `["H1","H2"]`). */
  only?: string[]
}

// ---------------------------------------------------------------------------
// Carregamento dos artefatos das fases anteriores
// ---------------------------------------------------------------------------

interface LoadedArtifact<T> {
  data: T
  dir: string
  generatedAt: string | null
}

/**
 * Lê o artefato mais recente de uma fase (`fase-d`, `fase-f`, ...).
 * Retorna `null` quando a fase ainda não foi executada — a Fase G degrada
 * explicitamente em vez de quebrar.
 */
export function loadLatestArtifact<T>(
  workspaceRoot: string,
  labId: string,
  fase: string,
  file: string,
): LoadedArtifact<T> | null {
  const base = path.join(workspaceRoot, "research", labId, fase)
  let stamps: string[]
  try {
    stamps = readdirSync(base)
  } catch {
    return null
  }
  for (const stamp of [...stamps].sort().reverse()) {
    const dir = path.join(base, stamp)
    try {
      const raw = readFileSync(path.join(dir, file), "utf8")
      const data = JSON.parse(raw) as T
      const generatedAt = (data as { generatedAt?: unknown }).generatedAt
      return { data, dir, generatedAt: typeof generatedAt === "string" ? generatedAt : null }
    } catch {
      continue
    }
  }
  return null
}

interface FaseDHypothesis {
  id: string
  title: string
  expectedBehavior?: string
  suspectedBehavior?: string
  evidenceNeeded?: string
  alternativeExplanations?: string[]
  /** Score de PRIORIDADE da Fase E (0–5). Não é probabilidade — ver `NEUTRAL_PRIOR`. */
  priorityScore?: number
  severityIfConfirmed?: string
}

interface FaseDData {
  hypotheses?: FaseDHypothesis[]
}

interface FaseFRequest {
  experimentId?: string
  index?: number
  intent?: string | null
  command?: string | null
  outcome?: string
  httpStatus?: number | null
  raw?: string | null
  sha256?: string | null
  rawFile?: string | null
  error?: string | null
}

/**
 * Uma requisição executada, com o papel que exerce no experimento e o arquivo cru
 * que a custodia. Vai para o relatório da Fase H e para a reprodução da Fase I.
 */
export interface RequestPair {
  role: Role
  status: number | null
  command: string | null
  rawFile: string | null
  sha256: string | null
}

interface FaseFExperiment {
  seed?: {
    id?: string
    hypothesisId?: string
    question?: string
    expectedOutcome?: string
    toolUsed?: string
  }
  hypothesisId?: string
  markersFound?: string[]
  indicator?: string
  requests?: FaseFRequest[]
}

interface FaseFData {
  mode?: string
  experiments?: FaseFExperiment[]
}

// ---------------------------------------------------------------------------
// Classificação de papel e diferencial
// ---------------------------------------------------------------------------

const ROLE_PATTERNS: Array<[Role, RegExp]> = [
  ["baseline", /\bBASELINE\b/i],
  ["poc", /\bPoC\b/i],
  ["controle", /\bCONTROLE\b|\bCONTROL\b/i],
]

/**
 * Descobre o papel de cada requisição pelo comentário de intenção das sementes
 * (`# BASELINE — ...`, `# PoC — ...`, `# CONTROLE — ...`).
 */
export function classifyRole(intent: string | null | undefined): Role {
  if (!intent) return "outro"
  for (const [role, re] of ROLE_PATTERNS) {
    if (re.test(intent)) return role
  }
  return "outro"
}

/** Corpo de uma captura crua (tudo depois do primeiro `\r\n\r\n`). */
export function bodyOf(raw: string | null | undefined): string {
  if (!raw) return ""
  const idx = raw.indexOf("\r\n\r\n")
  return idx >= 0 ? raw.slice(idx + 4) : ""
}

function bodyHash(raw: string | null | undefined): string | null {
  const body = bodyOf(raw)
  if (!body) return null
  return createHash("sha256").update(body, "utf8").digest("hex")
}

/**
 * Compara baseline e PoC.
 *
 * O ponto que importa: **igualdade entre baseline e PoC derruba o achado**. Se as duas
 * respostas têm o mesmo status e o mesmo corpo, o experimento não demonstrou uma
 * diferença — qualquer marcador encontrado aparece nos dois lados e não prova nada.
 */
export function assessDifferential(requests: FaseFRequest[]): DifferentialCheck {
  const executed = requests.filter((r) => r.outcome === "executed")
  const baselineReqs = executed.filter((r) => {
    const role = classifyRole(r.intent)
    return role === "baseline" || role === "controle"
  })
  const pocReqs = executed.filter((r) => classifyRole(r.intent) === "poc")

  const baselineStatuses = Array.from(new Set(baselineReqs.map((r) => r.httpStatus).filter((s): s is number => typeof s === "number")))
  const pocStatuses = Array.from(new Set(pocReqs.map((r) => r.httpStatus).filter((s): s is number => typeof s === "number")))

  const baselineHashes = new Set(baselineReqs.map((r) => bodyHash(r.raw)).filter((h): h is string => h !== null))
  const pocHashes = new Set(pocReqs.map((r) => bodyHash(r.raw)).filter((h): h is string => h !== null))

  const statusChanged = pocStatuses.length > 0 && pocStatuses.every((s) => !baselineStatuses.includes(s))
  const statusAndBodySame =
    baselineStatuses.length > 0 &&
    pocStatuses.length > 0 &&
    baselineStatuses.length === pocStatuses.length &&
    baselineStatuses.every((s) => pocStatuses.includes(s)) &&
    baselineHashes.size > 0 &&
    pocHashes.size > 0 &&
    [...baselineHashes].every((h) => pocHashes.has(h))

  const bodyChanged =
    pocHashes.size > 0 && ![...pocHashes].every((h) => baselineHashes.has(h))

  const base: Omit<DifferentialCheck, "state" | "note"> = {
    baselineCount: baselineReqs.length,
    pocCount: pocReqs.length,
    baselineStatuses,
    pocStatuses,
    statusChanged,
    bodyChanged,
    identicalBaselineAndPoc: statusAndBodySame,
  }

  if (baselineReqs.length === 0 || pocReqs.length === 0) {
    return {
      ...base,
      state: "incompleto",
      note:
        baselineReqs.length === 0 && pocReqs.length === 0
          ? "Sem requisições baseline nem PoC executadas: não há par para comparar."
          : baselineReqs.length === 0
            ? "Falta a requisição de controle (baseline): sem ela não se prova que a diferença vem da variável modificada."
            : "Falta a requisição experimental (PoC): sem ela não há o que comparar com o baseline.",
    }
  }

  if (statusAndBodySame) {
    return {
      ...base,
      state: "ausente",
      note: `Baseline e PoC voltaram idênticos (status ${baselineStatuses.join("/")}, mesmo corpo). Não há diferencial: o achado não demonstra diferença de comportamento.`,
    }
  }

  return {
    ...base,
    state: "confirmado",
    note: `Baseline ${baselineStatuses.join("/")} vs. PoC ${pocStatuses.join("/")}${
      statusChanged ? " — status mudou" : ""
    }${bodyChanged ? " — corpo mudou" : ""}.`,
  }
}

// ---------------------------------------------------------------------------
// Avaliação por experimento e por hipótese
// ---------------------------------------------------------------------------

/**
 * Veredito de UM experimento.
 *
 * Ordem importa: o diferencial vem antes do indicador, porque um marcador sem
 * diferencial é justamente o falso positivo que a metodologia manda eliminar.
 */
export function assessExperiment(exp: FaseFExperiment): ExperimentAssessment {
  const seed = exp.seed ?? {}
  const requests = exp.requests ?? []
  const markers = exp.markersFound ?? []
  const indicator = exp.indicator ?? "nao_executado"
  const differential = assessDifferential(requests)

  const executed = requests.filter((r) => r.outcome === "executed")
  const executedCount = executed.length
  const manualCount = requests.filter((r) => r.outcome === "manual").length
  const errorCount = requests.filter((r) => r.outcome === "error").length

  let verdict: ExperimentVerdict
  let reason: string

  if (executedCount === 0) {
    verdict = "nao_testada"
    reason =
      errorCount > 0
        ? `${errorCount} requisição(ões) falharam por erro de rede — nada observado.`
        : `Nenhum comando executável (${manualCount} manual(is)): o experimento não rodou.`
  } else if (differential.state === "ausente") {
    verdict = "indeterminado"
    reason = "Baseline e PoC idênticos: mesmo com marcador, não há diferencial que sustente o achado."
  } else if (markers.length > 0 && differential.state === "confirmado") {
    verdict = "sustenta"
    reason = `Marcador(es) ${markers.join(", ")} presente(s) com diferencial confirmado.`
  } else if (markers.length > 0) {
    verdict = "sustenta_com_ressalva"
    reason = `Marcador(es) ${markers.join(", ")} presente(s), mas sem par baseline/PoC verificável.`
  } else if (differential.statusChanged) {
    verdict = "sustenta_com_ressalva"
    reason = `Sem marcador, mas o status mudou entre baseline e PoC (${differential.baselineStatuses.join("/")} → ${differential.pocStatuses.join("/")}).`
  } else if (differential.bodyChanged) {
    verdict = "sustenta_com_ressalva"
    reason = "Sem marcador, mas o corpo da resposta mudou entre baseline e PoC."
  } else {
    verdict = "indeterminado"
    reason = "Executado, sem marcador e sem diferencial observável — nada sustenta nem refuta."
  }

  const pairs: RequestPair[] = executed.map((r) => ({
    role: classifyRole(r.intent),
    status: typeof r.httpStatus === "number" ? r.httpStatus : null,
    command: r.command ?? null,
    rawFile: r.rawFile ?? null,
    sha256: r.sha256 ?? null,
  }))

  return {
    experimentId: seed.id ?? "?",
    hypothesisId: exp.hypothesisId ?? seed.hypothesisId ?? "?",
    question: seed.question ?? "",
    expectedOutcome: seed.expectedOutcome ?? "",
    indicator,
    markersFound: markers,
    executedCount,
    manualCount,
    errorCount,
    pairs,
    differential,
    verdict,
    reason,
  }
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n))
}

/**
 * Confiança a priori.
 *
 * Deliberadamente NEUTRA, e não derivada do score da Fase E. Aquele score mistura
 * plausibilidade, impacto, custo, risco e poder diferenciador — ele responde "vale a
 * pena investigar?", não "qual a chance de ser verdade?". Importar uma decisão de
 * alocação de tempo como probabilidade inflaria a confiança antes de qualquer
 * evidência, e era exatamente isso que fazia toda hipótese saturar em 0.95.
 */
export const NEUTRAL_PRIOR = 0.5

/**
 * Confiança posterior.
 *
 * Retorno DECRESCENTE por design: o 2º experimento que sustenta acrescenta metade do
 * 1º, o 3º um terço. Dois experimentos da mesma hipótese medem quase sempre a mesma
 * coisa por caminhos diferentes — somá-los linearmente fingiria independência que não
 * existe. Nunca chega a 1.0: confiança absoluta não é conclusão científica.
 */
export function updateConfidence(prior: number, assessments: ExperimentAssessment[]): number {
  const gains = assessments.filter((a) => a.verdict === "sustenta" || a.verdict === "sustenta_com_ressalva").length
  const losses = assessments.filter((a) => a.verdict === "refuta" || a.verdict === "indeterminado").length

  let c = prior
  for (let i = 0; i < gains; i++) c += 0.3 / (i + 1)
  for (let i = 0; i < losses; i++) c -= 0.25 / (i + 1)

  return Math.round(clamp(c, 0.05, 0.95) * 100) / 100
}

export function evaluateHypothesis(
  hypothesis: FaseDHypothesis,
  experiments: FaseFExperiment[],
  impact: ImpactDeclaration | null,
): HypothesisAssessment {
  const assessments = experiments.map(assessExperiment)
  const supporting = assessments.filter((a) => a.verdict === "sustenta" || a.verdict === "sustenta_com_ressalva").length
  const contradicting = assessments.filter((a) => a.verdict === "refuta" || a.verdict === "indeterminado").length
  const untested = assessments.filter((a) => a.verdict === "nao_testada").length

  const priorityScore = typeof hypothesis.priorityScore === "number" ? hypothesis.priorityScore : null
  const priorConfidence = NEUTRAL_PRIOR
  const confidence = updateConfidence(priorConfidence, assessments)

  let verdict: HypothesisVerdict
  let reason: string
  if (assessments.length === 0) {
    verdict = "nao_testada"
    reason = "Nenhum experimento da Fase F cobre esta hipótese."
  } else if (supporting > 0 && contradicting === 0) {
    verdict = "sustenta"
    reason = `${supporting} experimento(s) sustenta(m) e nenhum contradiz.`
  } else if (supporting > 0 && contradicting > 0) {
    verdict = "sustenta_com_ressalva"
    reason = `Conflito: ${supporting} sustenta(m) e ${contradicting} não sustenta(m)/contradiz(em). Não force a interpretação — refine a hipótese ou investigue a explicação alternativa.`
  } else if (untested === assessments.length) {
    verdict = "nao_testada"
    reason = `Nenhum dos ${untested} experimento(s) chegou a executar.`
  } else if (contradicting > 0) {
    verdict = "refuta"
    reason = `${contradicting} experimento(s) não sustenta(m) a hipótese e nenhum a sustenta.`
  } else {
    verdict = "indeterminado"
    reason = "Evidência insuficiente para sustentar ou refutar."
  }

  const falsePositiveFlags: string[] = []
  for (const a of assessments) {
    if (a.differential.state === "ausente") {
      falsePositiveFlags.push(
        `${a.experimentId}: baseline e PoC idênticos — sem diferencial, o achado pode ser falso positivo.`,
      )
    }
    if (a.differential.state === "incompleto" && a.executedCount > 0) {
      falsePositiveFlags.push(
        `${a.experimentId}: par baseline/PoC incompleto (${a.differential.baselineCount} baseline / ${a.differential.pocCount} PoC) — não dá para atribuir a diferença à variável modificada.`,
      )
    }
    if (a.errorCount > 0) {
      falsePositiveFlags.push(`${a.experimentId}: ${a.errorCount} requisição(ões) com erro de execução.`)
    }
  }

  const wouldRuleOut = hypothesis.evidenceNeeded?.trim()
    ? `Evidência necessária declarada na Fase D: ${hypothesis.evidenceNeeded.trim()}`
    : "Declarar explicitamente qual observação descartaria esta explicação e repetir o experimento."

  const alternatives: AlternativeExplanation[] = (hypothesis.alternativeExplanations ?? []).map((text) => ({
    text,
    status: "nao_descartada" as const,
    wouldRuleOut,
  }))

  return {
    hypothesisId: hypothesis.id,
    title: hypothesis.title ?? hypothesis.id,
    expectedBehavior: hypothesis.expectedBehavior ?? "",
    suspectedBehavior: hypothesis.suspectedBehavior ?? "",
    priorityScore,
    priorConfidence,
    confidence,
    experiments: assessments,
    supporting,
    contradicting,
    untested,
    verdict,
    reason,
    alternativeExplanations: alternatives,
    falsePositiveFlags,
    impact,
  }
}

// ---------------------------------------------------------------------------
// Execução da fase
// ---------------------------------------------------------------------------

function verdictsSummary(list: HypothesisAssessment[]): Record<HypothesisVerdict, number> {
  const out: Record<HypothesisVerdict, number> = {
    sustenta: 0,
    sustenta_com_ressalva: 0,
    refuta: 0,
    indeterminado: 0,
    nao_testada: 0,
  }
  for (const h of list) out[h.verdict] += 1
  return out
}

function sha256Of(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex")
}

const VERDICT_LABEL: Record<HypothesisVerdict, string> = {
  sustenta: "SUSTENTA",
  sustenta_com_ressalva: "SUSTENTA (COM RESSALVA)",
  refuta: "REFUTA",
  indeterminado: "INDETERMINADO",
  nao_testada: "NÃO TESTADA",
}

export const EXPERIMENT_VERDICT_LABEL: Record<ExperimentVerdict, string> = {
  sustenta: "sustenta",
  sustenta_com_ressalva: "sustenta c/ ressalva",
  indeterminado: "indeterminado",
  refuta: "refuta",
  nao_testada: "nao testada",
}

export function runEvaluationPhase(params: RunEvaluationPhaseParams): EvaluationBoard {
  const now = params.now ?? new Date()
  const generatedAt = now.toISOString()
  const stamp = generatedAt.replace(/[:.]/g, "-")
  const outDir = params.outDir ?? path.join(params.workspaceRoot, "research", params.labId, "fase-g", stamp)

  const profile = getLabResearchProfile(params.labId)

  const faseD = loadLatestArtifact<FaseDData>(params.workspaceRoot, params.labId, "fase-d", "hypotheses-d.json")
  const faseF = loadLatestArtifact<FaseFData>(params.workspaceRoot, params.labId, "fase-f", "experiments-f.json")

  if (!faseD) {
    throw new Error(
      `Não há Fase D para "${params.labId}". A Fase G avalia hipóteses — rode antes: bun run cyberlab lab hypothesize ${params.labId}`,
    )
  }

  const hypotheses = (faseD.data.hypotheses ?? []).filter(
    (h) => !params.only || params.only.length === 0 || params.only.includes(h.id),
  )
  const experiments = faseF?.data.experiments ?? []

  const assessed = hypotheses.map((h) =>
    evaluateHypothesis(
      h,
      experiments.filter((e) => (e.hypothesisId ?? e.seed?.hypothesisId) === h.id),
      profile.impactByHypothesis[h.id] ?? null,
    ),
  )

  // Hipóteses avaliadas por ordem de confiança decrescente.
  assessed.sort((a, b) => b.confidence - a.confidence || a.hypothesisId.localeCompare(b.hypothesisId))

  const openQuestions: string[] = []
  for (const h of assessed) {
    if (h.verdict === "nao_testada") {
      openQuestions.push(`${h.hypothesisId}: nenhum experimento executado — a hipótese segue em aberto.`)
    }
    for (const alt of h.alternativeExplanations) {
      openQuestions.push(`${h.hypothesisId}: explicação alternativa não descartada — ${alt.text}`)
    }
  }
  if (!faseF) {
    openQuestions.push("Fase F não encontrada: a avaliação foi feita sem dados de experimento.")
  }

  mkdirSync(outDir, { recursive: true })

  const board: EvaluationBoard = {
    labId: params.labId,
    generatedAt,
    outputDir: outDir,
    sources: {
      faseD: faseD.dir,
      faseF: faseF?.dir ?? null,
    },
    hypotheses: assessed,
    summary: verdictsSummary(assessed),
    openQuestions,
    files: [],
    seal: "",
  }

  const md = renderEvaluationMarkdown(board)
  const json = renderEvaluationJson(board)

  const mdPath = path.join(outDir, "EVALUATION.md")
  const jsonPath = path.join(outDir, "evaluation-g.json")
  writeFileSync(mdPath, md, "utf8")
  writeFileSync(jsonPath, `${JSON.stringify(json, null, 2)}\n`, "utf8")

  board.seal = sha256Of(`${JSON.stringify(json, null, 2)}\n`)
  board.files = ["EVALUATION.md", "evaluation-g.json"]

  const manifest = {
    labId: board.labId,
    phase: "G",
    generatedAt: board.generatedAt,
    sources: board.sources,
    files: board.files,
    seal: board.seal,
    summary: board.summary,
  }
  writeFileSync(path.join(outDir, "evaluation-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8")
  board.files.push("evaluation-manifest.json")

  writeFileSync(jsonPath, `${JSON.stringify(renderEvaluationJson(board), null, 2)}\n`, "utf8")

  return board
}

/** JSON estável: sem `files`, `seal` nem `outputDir` (mesmo critério das Fases C/D/F). */
function renderEvaluationJson(board: EvaluationBoard): Record<string, unknown> {
  return {
    labId: board.labId,
    generatedAt: board.generatedAt,
    sources: board.sources,
    summary: board.summary,
    hypotheses: board.hypotheses,
    openQuestions: board.openQuestions,
  }
}

function renderEvaluationMarkdown(board: EvaluationBoard): string {
  const L: string[] = []
  L.push(`# Fase G — Avaliação Crítica: ${board.labId}`)
  L.push("")
  L.push(`- **Gerado em**: ${board.generatedAt}`)
  L.push(`- **Fase D consumida**: ${board.sources.faseD ?? "—"}`)
  L.push(`- **Fase F consumida**: ${board.sources.faseF ?? "NÃO ENCONTRADA"}`)
  L.push(`- **Hipóteses**: ${board.hypotheses.length}`)
  L.push("")
  L.push(
    "> A Fase G compara **observado vs. esperado** e atualiza a confiança. Ela NÃO emite",
  )
  L.push(
    "> laudo: a classificação final (comportamento inesperado → vulnerabilidade confirmada)",
  )
  L.push("> é da Fase H.")
  L.push("")

  L.push("## Resumo")
  L.push("")
  L.push("| Hipótese | Título | Veredito | Antes | Depois | Exp. (sust/contr/não test.) |")
  L.push("|---|---|---|---|---|---|")
  for (const h of board.hypotheses) {
    L.push(
      `| \`${h.hypothesisId}\` | ${h.title} | **${VERDICT_LABEL[h.verdict]}** | ${h.priorConfidence.toFixed(2)} | ${h.confidence.toFixed(2)} | ${h.experiments.length} (${h.supporting}/${h.contradicting}/${h.untested}) |`,
    )
  }
  L.push("")

  for (const h of board.hypotheses) {
    L.push(`## ${h.hypothesisId} — ${h.title}`)
    L.push("")
    L.push(`- **Veredito**: \`${h.verdict}\` — ${h.reason}`)
    L.push(`- **Confiança**: ${h.priorConfidence.toFixed(2)} → **${h.confidence.toFixed(2)}** (priori neutra de ${NEUTRAL_PRIOR.toFixed(2)}; retorno decrescente por experimento)`)
    if (h.expectedBehavior) L.push(`- **Comportamento esperado**: ${h.expectedBehavior}`)
    if (h.suspectedBehavior) L.push(`- **Comportamento suspeito**: ${h.suspectedBehavior}`)
    L.push("")
    if (h.experiments.length > 0) {
      L.push("| Exp. | Diferencial (baseline → PoC) | Marcadores | Veredito | Motivo |")
      L.push("|---|---|---|---|---|")
      for (const e of h.experiments) {
        const diff =
          e.differential.state === "confirmado"
            ? `${e.differential.baselineStatuses.join("/")} → ${e.differential.pocStatuses.join("/")}`
            : e.differential.state === "ausente"
              ? "idênticos"
              : `incompleto (${e.differential.baselineCount} base / ${e.differential.pocCount} poc)`
        L.push(
          `| \`${e.experimentId}\` | ${diff} | ${e.markersFound.length ? e.markersFound.map((m) => `\`${m}\``).join(", ") : "—"} | ${EXPERIMENT_VERDICT_LABEL[e.verdict]} | ${e.reason} |`,
        )
      }
      L.push("")
    }
    if (h.falsePositiveFlags.length > 0) {
      L.push("**Sinais de falso positivo**")
      L.push("")
      for (const f of h.falsePositiveFlags) L.push(`- ${f}`)
      L.push("")
    }
    if (h.alternativeExplanations.length > 0) {
      L.push("**Explicações alternativas — NENHUMA descartada automaticamente**")
      L.push("")
      for (const alt of h.alternativeExplanations) {
        L.push(`- ${alt.text}`)
        L.push(`  - Como descartar: ${alt.wouldRuleOut}`)
      }
      L.push("")
    }
  }

  if (board.openQuestions.length > 0) {
    L.push("## Pendências antes de qualquer confirmação")
    L.push("")
    for (const q of board.openQuestions) L.push(`- ${q}`)
    L.push("")
  }

  return L.join("\n")
}
