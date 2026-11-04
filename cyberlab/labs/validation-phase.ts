/**
 * Fase H — Validação (taxonomia obrigatória de classificação).
 *
 * Definição metodológica (`methodologies/evidence-validation.md` e
 * `packages/core/src/plugin/agent.ts`): determinar se há violação demonstrável de
 * propriedade de segurança, diferenciando ESTRITAMENTE:
 *
 *   1. Comportamento inesperado     — resposta atípica, sem violação demonstrada
 *   2. Falha funcional              — bug de produto (ex.: 500) sem impacto em C/I/A
 *   3. Configuração insegura        — header ausente / versão exposta, sem vetor direto
 *   4. Vulnerabilidade potencial    — indício forte, pendente de prova determinística
 *   5. Vulnerabilidade confirmada   — violação reproduzível com par baseline vs. PoC
 *
 * A classificação é por REGRA, não por impressão: cada linha do relatório cita a regra
 * que disparou. E o viés é conservador — na dúvida, cai na categoria mais fraca
 * (`vulnerabilidade_potencial`, não `confirmada`). Inflar achado é o erro mais caro
 * aqui, e a taxonomia existe justamente para impedi-lo.
 */

import { createHash } from "node:crypto"
import { mkdirSync, writeFileSync } from "node:fs"
import path from "node:path"
import { loadLatestArtifact } from "./evaluation-phase.js"
import type { HypothesisAssessment } from "./evaluation-phase.js"

export type ValidationClass =
  | "vulnerabilidade_confirmada"
  | "vulnerabilidade_potencial"
  | "configuracao_insegura"
  | "falha_funcional"
  | "comportamento_inesperado"
  | "nao_classificado"

export const VALIDATION_CLASS_LABEL: Record<ValidationClass, string> = {
  vulnerabilidade_confirmada: "Vulnerabilidade confirmada",
  vulnerabilidade_potencial: "Vulnerabilidade potencial",
  configuracao_insegura: "Configuração insegura (Hardening)",
  falha_funcional: "Falha funcional",
  comportamento_inesperado: "Comportamento inesperado",
  nao_classificado: "Não classificado",
}

/** Uma requisição custodiada que sustenta o achado. */
export type EvidenceEntry = {
  experimentId: string
  role: "baseline" | "poc"
  status: number
  rawFile: string | null
}

export interface ValidatedFinding {
  hypothesisId: string
  title: string
  /** Veredito da Fase G que originou esta classificação. */
  evaluationVerdict: string
  confidence: number
  classification: ValidationClass
  /** Regra exata que produziu a classificação — auditável. */
  rule: string
  /** O impacto declarado no perfil (ou ausência dele). */
  declaredImpact: { dimension: string; vector: string; rationale: string } | null
  /** Sinais de falso positivo herdados da Fase G. */
  falsePositiveFlags: string[]
  /** Explicações alternativas ainda não descartadas. */
  openAlternatives: string[]
  /** Requisições que sustentam o achado (baseline e PoC), para o relatório da Fase I. */
  evidence: EvidenceEntry[]
}

export interface ValidationBoard {
  labId: string
  generatedAt: string
  outputDir: string
  source: string | null
  findings: ValidatedFinding[]
  /** Contagem por categoria. */
  summary: Record<ValidationClass, number>
  files: string[]
  seal: string
}

export interface RunValidationPhaseParams {
  labId: string
  workspaceRoot: string
  outDir?: string
  now?: Date
}

function sha256Of(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex")
}

function collectEvidence(h: HypothesisAssessment): EvidenceEntry[] {
  // A Fase G já classificou o papel de cada requisição; aqui só reaproveitamos,
  // mantendo o arquivo cru que custodia cada uma — é ele que a Fase I cita.
  const out: EvidenceEntry[] = []
  for (const e of h.experiments) {
    for (const pair of e.pairs) {
      if (pair.role !== "baseline" && pair.role !== "poc") continue
      if (pair.status === null) continue
      out.push({
        experimentId: e.experimentId,
        role: pair.role,
        status: pair.status,
        rawFile: pair.rawFile,
      })
    }
  }
  return out
}

/**
 * Aplica a taxonomia de 5 níveis a uma hipótese avaliada pela Fase G.
 *
 * Ordem das regras importa: as categorias mais fracas são testadas primeiro para que
 * um achado nunca receba classificação mais forte do que a evidência suporta.
 */
export function classifyFinding(h: HypothesisAssessment): { classification: ValidationClass; rule: string } {
  const decl = h.impact
  const dimension = decl?.dimension ?? "unknown"
  const vector = decl?.vector ?? "unknown"

  const executed = h.experiments.some((e) => e.executedCount > 0)
  const anyDiff = h.experiments.some((e) => e.differential.state === "confirmado")
  const pocStatuses = h.experiments.flatMap((e) => e.differential.pocStatuses)
  const allPocServerError = pocStatuses.length > 0 && pocStatuses.every((s) => s >= 500)

  if (!executed) {
    return dimension === "none"
      ? {
          classification: "configuracao_insegura",
          rule:
            "Nenhum experimento executado, mas o impacto declarado é `none`: o achado é de hardening por declaração (mecanismo disponível e desligado).",
        }
      : {
          classification: "nao_classificado",
          rule: "Nenhum experimento executado: não há evidência para enquadrar em qualquer categoria.",
        }
  }

  if (h.verdict === "refuta") {
    return {
      classification: "nao_classificado",
      rule: "Hipótese refutada na Fase G: não há achado a classificar.",
    }
  }

  if (allPocServerError && vector === "none") {
    return {
      classification: "falha_funcional",
      rule: `Todas as requisições PoC retornaram 5xx (${pocStatuses.join(", ")}) e o impacto declarado é \`none\`: bug de produto sem impacto em confidencialidade, integridade ou disponibilidade.`,
    }
  }

  if (h.verdict === "sustenta" && anyDiff) {
    return vector === "none"
      ? {
          classification: "configuracao_insegura",
          rule:
            "Diferencial baseline↔PoC provado, mas o impacto declarado é `none`: mecanismo de proteção ausente/desligado, sem vetor de exploração direto.",
        }
      : {
          classification: "vulnerabilidade_confirmada",
          rule: `Veredito \`sustenta\` com par baseline↔PoC verificado: violação reproduzível e inequívoca (vetor \`${vector}\`).`,
        }
  }

  if (h.verdict === "sustenta" || h.verdict === "sustenta_com_ressalva") {
    return {
      classification: "vulnerabilidade_potencial",
      rule:
        "Há indício forte (marcador e/ou mudança de status/corpo), mas sem par baseline↔PoC verificável: falta prova determinística.",
    }
  }

  if (anyDiff) {
    return {
      classification: "comportamento_inesperado",
      rule:
        "Resposta atípica com diferencial observado, mas sem violação de propriedade de segurança demonstrada.",
    }
  }

  return {
    classification: "nao_classificado",
    rule: "Evidência insuficiente: não sustenta, não refuta e não há diferencial observável.",
  }
}

function emptySummary(): Record<ValidationClass, number> {
  return {
    vulnerabilidade_confirmada: 0,
    vulnerabilidade_potencial: 0,
    configuracao_insegura: 0,
    falha_funcional: 0,
    comportamento_inesperado: 0,
    nao_classificado: 0,
  }
}

/** Ordem do mais grave para o menos grave, usada no relatório. */
const SEVERITY_ORDER: ValidationClass[] = [
  "vulnerabilidade_confirmada",
  "vulnerabilidade_potencial",
  "configuracao_insegura",
  "falha_funcional",
  "comportamento_inesperado",
  "nao_classificado",
]

export function runValidationPhase(params: RunValidationPhaseParams): ValidationBoard {
  const now = params.now ?? new Date()
  const generatedAt = now.toISOString()
  const stamp = generatedAt.replace(/[:.]/g, "-")
  const outDir = params.outDir ?? path.join(params.workspaceRoot, "research", params.labId, "fase-h", stamp)

  const evaluation = loadLatestArtifact<{ hypotheses?: HypothesisAssessment[] }>(
    params.workspaceRoot,
    params.labId,
    "fase-g",
    "evaluation-g.json",
  )

  if (!evaluation) {
    throw new Error(
      `Não há Fase G para "${params.labId}". A Fase H classifica o que a Fase G avaliou — rode antes: bun run cyberlab lab evaluate ${params.labId}`,
    )
  }

  const hypotheses = evaluation.data.hypotheses ?? []

  const findings: ValidatedFinding[] = hypotheses.map((h) => {
    const { classification, rule } = classifyFinding(h)
    return {
      hypothesisId: h.hypothesisId,
      title: h.title,
      evaluationVerdict: h.verdict,
      confidence: h.confidence,
      classification,
      rule,
      declaredImpact: h.impact
        ? { dimension: h.impact.dimension, vector: h.impact.vector, rationale: h.impact.rationale }
        : null,
      falsePositiveFlags: h.falsePositiveFlags,
      openAlternatives: h.alternativeExplanations.map((a) => a.text),
      evidence: collectEvidence(h),
    }
  })

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.classification) - SEVERITY_ORDER.indexOf(b.classification) ||
      b.confidence - a.confidence,
  )

  const summary = emptySummary()
  for (const f of findings) summary[f.classification] += 1

  mkdirSync(outDir, { recursive: true })

  const board: ValidationBoard = {
    labId: params.labId,
    generatedAt,
    outputDir: outDir,
    source: evaluation.dir,
    findings,
    summary,
    files: [],
    seal: "",
  }

  const json = renderValidationJson(board)
  writeFileSync(path.join(outDir, "validation-h.json"), `${JSON.stringify(json, null, 2)}\n`, "utf8")
  board.seal = sha256Of(`${JSON.stringify(json, null, 2)}\n`)
  board.files = ["VALIDATION.md", "validation-h.json"]

  const manifest = {
    labId: board.labId,
    phase: "H",
    generatedAt: board.generatedAt,
    source: board.source,
    files: board.files,
    seal: board.seal,
    summary: board.summary,
  }
  writeFileSync(path.join(outDir, "validation-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8")
  board.files.push("validation-manifest.json")

  // Reescreve o JSON já com o lacre (mesmo critério das Fases C/D/F/G).
  writeFileSync(path.join(outDir, "validation-h.json"), `${JSON.stringify(renderValidationJson(board), null, 2)}\n`, "utf8")
  writeFileSync(path.join(outDir, "VALIDATION.md"), renderValidationMarkdown(board), "utf8")

  return board
}

function renderValidationJson(board: ValidationBoard): Record<string, unknown> {
  return {
    labId: board.labId,
    generatedAt: board.generatedAt,
    source: board.source,
    summary: board.summary,
    findings: board.findings,
  }
}

function renderValidationMarkdown(board: ValidationBoard): string {
  const L: string[] = []
  L.push(`# Fase H — Validação: ${board.labId}`)
  L.push("")
  L.push(`- **Gerado em**: ${board.generatedAt}`)
  L.push(`- **Fase G consumida**: ${board.source ?? "—"}`)
  L.push(`- **Achados**: ${board.findings.length}`)
  L.push("")
  L.push("> Taxonomia obrigatória (`methodologies/evidence-validation.md`). Cada linha cita a")
  L.push("> **regra que disparou**, e o viés é conservador: na dúvida, a classificação cai na")
  L.push("> categoria mais fraca. Nada aqui é laudo automático — é enquadramento auditável.")
  L.push("")

  L.push("## Resumo")
  L.push("")
  L.push("| Categoria | Quantidade |")
  L.push("|---|---|")
  for (const cls of SEVERITY_ORDER) {
    if (board.summary[cls] > 0) L.push(`| ${VALIDATION_CLASS_LABEL[cls]} | ${board.summary[cls]} |`)
  }
  L.push("")

  for (const f of board.findings) {
    L.push(`## ${f.hypothesisId} — ${f.title}`)
    L.push("")
    L.push(`- **Classificação**: **${VALIDATION_CLASS_LABEL[f.classification]}**`)
    L.push(`- **Confiança (Fase G)**: ${f.confidence.toFixed(2)}`)
    L.push(`- **Regra aplicada**: ${f.rule}`)
    if (f.declaredImpact) {
      L.push(
        `- **Impacto declarado**: dimensão \`${f.declaredImpact.dimension}\`, vetor \`${f.declaredImpact.vector}\` — ${f.declaredImpact.rationale}`,
      )
    } else {
      L.push("- **Impacto declarado**: nenhum (perfil sem curadoria para esta hipótese)")
    }
    L.push("")
    if (f.evidence.length > 0) {
      L.push("| Experimento | Papel | Status HTTP |")
      L.push("|---|---|---|")
      for (const e of f.evidence) {
        L.push(`| \`${e.experimentId}\` | ${e.role} | ${e.status} |`)
      }
      L.push("")
    }
    if (f.falsePositiveFlags.length > 0) {
      L.push("**Sinais de falso positivo**")
      L.push("")
      for (const s of f.falsePositiveFlags) L.push(`- ${s}`)
      L.push("")
    }
    if (f.openAlternatives.length > 0) {
      L.push("**Explicações alternativas não descartadas**")
      L.push("")
      for (const a of f.openAlternatives) L.push(`- ${a}`)
      L.push("")
    }
  }

  return L.join("\n")
}
