/**
 * Fase I — Documentação Reproduzível.
 *
 * Definição metodológica (`research/technical-writeups/reproducible-writeup-standard.md`):
 *
 *   1. Resumo Executivo & Classificação Honesta
 *   2. Ativo, Escopo e Condições de Teste
 *   3. Modelo do Mecanismo e Causa Raiz
 *   4. Passos Exatos de Reprodução (baseline vs. PoC mínimo benigno)
 *   5. Evidências Custodiadas (SHA-256, pares HTTP com segredos redigidos)
 *   6. Impacto Real, Limitações Conhecidas e Recomendação Estrutural de Correção
 *
 * Duas decisões que valem mais que o resto do arquivo:
 *
 * - **Redação antes de escrever.** Tokens, chaves e segredos são redigidos com o
 *   `redactSensitiveContent` do próprio CyberLab antes de irem para o relatório. Um
 *   writeup que vaza o Bearer token que ele mesmo usou para provar o achado é um
 *   incidente, não uma evidência.
 * - **O relatório não inventa.** Cada seção é preenchida com o que as fases
 *   anteriores registraram. Se a Fase H não classificou, o relatório diz
 *   "não classificado" — não preenche lacuna com suposição.
 */

import { createHash } from "node:crypto"
import { mkdirSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import { redactSensitiveContent } from "../evidence/provenance.js"
import { loadLatestArtifact } from "./evaluation-phase.js"
import type { HypothesisAssessment } from "./evaluation-phase.js"
import { getLabResearchProfile } from "./research-profile.js"
import type { ValidationBoard, ValidatedFinding } from "./validation-phase.js"

export interface WriteupFinding {
  hypothesisId: string
  title: string
  classification: string
  classificationLabel: string
  classificationRule: string
  confidence: number
  /** Causa raiz conforme a Fase D. */
  rootCause: string
  /** Mecanismo conforme a Fase D (justificativa técnica). */
  mechanism: string
  severityIfConfirmed: string | null
  /** Passos: baseline e PoC com comando e custódia. */
  steps: Array<{ experimentId: string; role: string; status: number | null; command: string; rawFile: string | null; sha256: string | null }>
  /** Corpo das respostas, redigido, para provar o diferencial. */
  redactedEvidence: Array<{ experimentId: string; role: string; status: number | null; rawFile: string | null; sha256: string | null; body: string }>
  openAlternatives: string[]
  falsePositiveFlags: string[]
  /** Recomendação estrutural: o controle que faltou. */
  recommendation: string | null
}

export interface WriteupBoard {
  labId: string
  generatedAt: string
  outputDir: string
  sources: { faseD: string | null; faseF: string | null; faseG: string | null; faseH: string | null }
  /** Condições de teste: alvo, controles e contas usadas (seção 2). */
  conditions: {
    baseUrl: string | null
    mode: string | null
    controls: Record<string, unknown> | null
  }
  findings: WriteupFinding[]
  limitations: string[]
  files: string[]
  seal: string
}

export interface RunDocumentationPhaseParams {
  labId: string
  workspaceRoot: string
  outDir?: string
  now?: Date
  /** Diretório com os arquivos `raw/` da Fase F (para ler os corpos). */
  rawDir?: string
}

function sha256Of(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex")
}

interface FaseDHypothesis {
  id: string
  title?: string
  technicalRationale?: string
  fragileAssumption?: string
  severityIfConfirmed?: string
  relatedControlFlag?: string
  alternativeExplanations?: string[]
}

interface FaseDData {
  hypotheses?: FaseDHypothesis[]
  researchDir?: string | null
}

interface FaseFRequest {
  experimentId?: string
  intent?: string | null
  command?: string | null
  outcome?: string
  httpStatus?: number | null
  raw?: string | null
  sha256?: string | null
  rawFile?: string | null
}

interface FaseFExperiment {
  seed?: { id?: string; hypothesisId?: string; question?: string; initialConditions?: string; modifiedVariable?: string }
  hypothesisId?: string
  requests?: FaseFRequest[]
}

interface FaseFData {
  mode?: string
  baseUrl?: string
  experiments?: FaseFExperiment[]
}

/**
 * Recomendação estrutural: em vez de "corrija o bug", aponta o CONTROLE que estava
 * desligado — é o que a Fase D já declarou em `relatedControlFlag`.
 */
function recommendationFor(flag: string | null | undefined): string | null {
  if (!flag) return null
  return `Reativar/implementar o controle \`${flag}\` e impedir que ele volte a ser desligado por configuração (o mesmo mecanismo que falhou aqui falhará em qualquer endpoint que repita o padrão).`
}

function pickSteps(
  experiments: FaseFExperiment[],
  hypothesisId: string,
): Array<{ experimentId: string; role: string; status: number | null; command: string; rawFile: string | null; sha256: string | null }> {
  const steps: Array<{ experimentId: string; role: string; status: number | null; command: string; rawFile: string | null; sha256: string | null }> = []
  for (const e of experiments) {
    if ((e.hypothesisId ?? e.seed?.hypothesisId) !== hypothesisId) continue
    for (const r of e.requests ?? []) {
      if (r.outcome !== "executed") continue
      const intent = (r.intent ?? "").toUpperCase()
      const role = intent.includes("BASELINE")
        ? "baseline"
        : intent.includes("POC")
          ? "PoC"
          : intent.includes("CONTROLE")
            ? "controle"
            : "outro"
      if (role === "outro") continue
      steps.push({
        experimentId: e.seed?.id ?? r.experimentId ?? "?",
        role,
        status: typeof r.httpStatus === "number" ? r.httpStatus : null,
        command: r.command ?? "",
        rawFile: r.rawFile ?? null,
        sha256: r.sha256 ?? null,
      })
    }
  }
  return steps
}

/** Corpo da resposta, redigido. Preserva a prova sem preservar o segredo. */
function redactedBody(raw: string | null | undefined): string {
  if (!raw) return ""
  const idx = raw.indexOf("\r\n\r\n")
  const body = idx >= 0 ? raw.slice(idx + 4) : raw
  return redactSensitiveContent(body).text
}

export function runDocumentationPhase(params: RunDocumentationPhaseParams): WriteupBoard {
  const now = params.now ?? new Date()
  const generatedAt = now.toISOString()
  const stamp = generatedAt.replace(/[:.]/g, "-")
  const outDir = params.outDir ?? path.join(params.workspaceRoot, "research", params.labId, "fase-i", stamp)

  const profile = getLabResearchProfile(params.labId)

  const faseD = loadLatestArtifact<FaseDData>(params.workspaceRoot, params.labId, "fase-d", "hypotheses-d.json")
  const faseF = loadLatestArtifact<FaseFData>(params.workspaceRoot, params.labId, "fase-f", "experiments-f.json")
  const faseG = loadLatestArtifact<{ hypotheses?: HypothesisAssessment[] }>(
    params.workspaceRoot,
    params.labId,
    "fase-g",
    "evaluation-g.json",
  )
  const faseH = loadLatestArtifact<ValidationBoard>(params.workspaceRoot, params.labId, "fase-h", "validation-h.json")

  if (!faseH) {
    throw new Error(
      `Não há Fase H para "${params.labId}". A Fase I documenta achados classificados — rode antes: bun run cyberlab lab validate ${params.labId}`,
    )
  }

  const validated = (faseH.data.findings ?? []) as ValidatedFinding[]
  const evaluated = new Map((faseG?.data.hypotheses ?? []).map((h) => [h.hypothesisId, h]))
  const dHypotheses = new Map((faseD?.data.hypotheses ?? []).map((h) => [h.id, h]))

  const rawDir = params.rawDir ?? (faseF ? path.join(faseF.dir, "raw") : null)

  const findings: WriteupFinding[] = validated.map((f) => {
    const g = evaluated.get(f.hypothesisId)
    const d = dHypotheses.get(f.hypothesisId)

    const steps = pickSteps(faseF?.data.experiments ?? [], f.hypothesisId)

    // Evidência custodiada: lê o arquivo cru da Fase F e redige antes de publicar.
    const redactedEvidence: WriteupFinding["redactedEvidence"] = []
    for (const s of steps) {
      if (!s.rawFile || !rawDir) continue
      try {
        const raw = readFileSync(path.join(rawDir, path.basename(s.rawFile)), "utf8")
        redactedEvidence.push({
          experimentId: s.experimentId,
          role: s.role,
          status: s.status,
          rawFile: s.rawFile,
          sha256: s.sha256,
          body: redactedBody(raw),
        })
      } catch {
        // Arquivo cru ausente: o relatório segue sem ele, sem quebrar.
      }
    }

    return {
      hypothesisId: f.hypothesisId,
      title: f.title,
      classification: f.classification,
      classificationLabel: f.classification,
      classificationRule: f.rule,
      confidence: f.confidence,
      rootCause: d?.fragileAssumption ?? "",
      mechanism: d?.technicalRationale ?? "",
      severityIfConfirmed: d?.severityIfConfirmed ?? null,
      steps,
      redactedEvidence,
      openAlternatives: g?.alternativeExplanations.map((a) => a.text) ?? f.openAlternatives,
      falsePositiveFlags: g?.falsePositiveFlags ?? f.falsePositiveFlags,
      recommendation: recommendationFor(d?.relatedControlFlag),
    }
  })

  mkdirSync(outDir, { recursive: true })

  const board: WriteupBoard = {
    labId: params.labId,
    generatedAt,
    outputDir: outDir,
    sources: {
      faseD: faseD?.dir ?? null,
      faseF: faseF?.dir ?? null,
      faseG: faseG?.dir ?? null,
      faseH: faseH.dir,
    },
    conditions: {
      baseUrl: faseF?.data.baseUrl ?? null,
      mode: faseF?.data.mode ?? null,
      controls: null,
    },
    findings,
    limitations: [
      ...profile.limitations,
      ...(faseG?.data.hypotheses?.flatMap((h) =>
        h.alternativeExplanations.map((a) => `${h.hypothesisId}: explicação alternativa NÃO descartada — ${a.text}`),
      ) ?? []),
    ],
    files: [],
    seal: "",
  }

  const json = renderWriteupJson(board)
  writeFileSync(path.join(outDir, "report-i.json"), `${JSON.stringify(json, null, 2)}\n`, "utf8")
  board.seal = sha256Of(`${JSON.stringify(json, null, 2)}\n`)
  board.files = ["WRITEUP.md", "report-i.json"]

  const manifest = {
    labId: board.labId,
    phase: "I",
    generatedAt: board.generatedAt,
    sources: board.sources,
    files: board.files,
    seal: board.seal,
  }
  writeFileSync(path.join(outDir, "report-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8")
  board.files.push("report-manifest.json")

  writeFileSync(path.join(outDir, "report-i.json"), `${JSON.stringify(renderWriteupJson(board), null, 2)}\n`, "utf8")
  writeFileSync(path.join(outDir, "WRITEUP.md"), renderWriteupMarkdown(board), "utf8")

  return board
}

function renderWriteupJson(board: WriteupBoard): Record<string, unknown> {
  return {
    labId: board.labId,
    generatedAt: board.generatedAt,
    sources: board.sources,
    conditions: board.conditions,
    findings: board.findings,
    limitations: board.limitations,
  }
}

function renderWriteupMarkdown(board: WriteupBoard): string {
  const L: string[] = []
  const confirmed = board.findings.filter((f) => f.classification === "vulnerabilidade_confirmada").length
  const potential = board.findings.filter((f) => f.classification === "vulnerabilidade_potencial").length

  L.push(`# Relatório Técnico Reproduzível — ${board.labId}`)
  L.push("")
  L.push(`- **Gerado em**: ${board.generatedAt}`)
  L.push(`- **Ciclo**: Fase C (pesquisa) → D (hipóteses) → E (priorização) → F (experimentação) → G (avaliação) → H (validação) → I (documentação)`)
  L.push("")

  // 1. Resumo executivo
  L.push("## 1. Resumo Executivo & Classificação Honesta")
  L.push("")
  L.push(
    `${confirmed} vulnerabilidade(s) confirmada(s) e ${potential} potencial(is) em ${board.findings.length} hipótese(s) avaliada(s).`,
  )
  L.push("")
  L.push("| Hipótese | Achado | Classificação | Confiança |")
  L.push("|---|---|---|---|")
  for (const f of board.findings) {
    L.push(`| \`${f.hypothesisId}\` | ${f.title} | ${f.classificationLabel} | ${f.confidence.toFixed(2)} |`)
  }
  L.push("")
  L.push(
    "> Classificação honesta: nenhum achado foi promovido a \"confirmado\" sem par baseline↔PoC",
  )
  L.push("> verificado. Onde a prova é indireta, a categoria é `vulnerabilidade_potencial`.")
  L.push("")

  // 2. Ativo, escopo e condições
  L.push("## 2. Ativo, Escopo e Condições de Teste")
  L.push("")
  L.push(`- **Alvo**: \`${board.conditions.baseUrl ?? "—"}\``)
  L.push(`- **Modo de execução da Fase F**: \`${board.conditions.mode ?? "—"}\``)
  L.push("- **Escopo**: alvo de treino em loopback, executado localmente pelo operador.")
  L.push("")

  // 3..6 por achado
  for (const f of board.findings) {
    L.push(`## ${f.hypothesisId} — ${f.title}`)
    L.push("")
    L.push(`**Classificação**: ${f.classificationLabel}`)
    L.push("")
    L.push(`**Regra que produziu a classificação**: ${f.classificationRule}`)
    L.push("")

    L.push("### Modelo do Mecanismo e Causa Raiz (item 3 do padrão)")
    L.push("")
    if (f.mechanism) L.push(`Mecanismo: ${f.mechanism}`)
    if (f.rootCause) L.push("")
    if (f.rootCause) L.push(`Pressuposto frágil (causa raiz): ${f.rootCause}`)
    L.push("")

    L.push("### Passos Exatos de Reprodução (item 4 do padrão)")
    L.push("")
    if (f.steps.length === 0) {
      L.push("_Nenhuma requisição baseline/PoC executada para esta hipótese._")
    } else {
      L.push("| Exp. | Papel | Status | Comando |")
      L.push("|---|---|---|---|")
      for (const s of f.steps) {
        const cmd = redactSensitiveContent(s.command).text
        L.push(`| \`${s.experimentId}\` | ${s.role} | ${s.status ?? "—"} | \`${cmd.replace(/`/g, "'")}\` |`)
      }
    }
    L.push("")

    L.push("### Evidências Custodiadas (item 5 do padrão)")
    L.push("")
    if (f.redactedEvidence.length === 0) {
      L.push("_Sem captura bruta arquivada para esta hipótese._")
    }
    for (const ev of f.redactedEvidence) {
      L.push(`**${ev.experimentId} · ${ev.role}** — HTTP ${ev.status ?? "—"} · \`${ev.rawFile}\``)
      L.push("")
      if (ev.sha256) L.push(`SHA-256: \`${ev.sha256}\``)
      L.push("")
      L.push("```http")
      L.push(ev.body.trim())
      L.push("```")
      L.push("")
    }
    L.push("> Segredos redigidos com o padrão do CyberLab OS antes da publicação.")
    L.push("")

    L.push("### Impacto, Limitações e Recomendação (item 6 do padrão)")
    L.push("")
    if (f.severityIfConfirmed) L.push(`**Impacto declarado**: ${f.severityIfConfirmed}`)
    if (f.recommendation) L.push("")
    if (f.recommendation) L.push(`**Recomendação estrutural**: ${f.recommendation}`)
    if (f.openAlternatives.length > 0) {
      L.push("")
      L.push("**Explicações alternativas NÃO descartadas** (devem ser eliminadas antes de tratar o achado como definitivo):")
      L.push("")
      for (const a of f.openAlternatives) L.push(`- ${a}`)
    }
    if (f.falsePositiveFlags.length > 0) {
      L.push("")
      L.push("**Ressalvas de evidência:**")
      L.push("")
      for (const s of f.falsePositiveFlags) L.push(`- ${s}`)
    }
    L.push("")
  }

  L.push("## Limitações Conhecidas")
  L.push("")
  for (const l of board.limitations) L.push(`- ${l}`)
  L.push("")

  return L.join("\n")
}
