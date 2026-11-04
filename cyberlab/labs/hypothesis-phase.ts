/**
 * Fase D — Formulação de Hipóteses (com priorização da Fase E).
 *
 * O que já existia: `investigation-kit.ts` grava sementes de hipótese com os 6
 * elementos obrigatórios. O que faltava:
 *
 *   1. **Nenhuma hipótese consumia a Fase C.** O operador rodava `lab research`,
 *      recebia CVEs e fontes primárias, e as hipóteses seguiam sem citar nada
 *      disso. Pesquisa e hipótese viviam em arquivos separados que nunca se
 *      encontravam — a Fase C virava decoração.
 *   2. **Não havia Fase E.** A metodologia pede priorização por plausibilidade,
 *      impacto, evidência disponível, custo, risco e poder diferenciador. Sem
 *      critério explícito, a ordem de investigação era a ordem em que as sementes
 *      foram digitadas.
 *
 * Então este módulo:
 *   - ancora cada hipótese nos achados REAIS da Fase C (advisories, CWE, fontes);
 *   - pontua cada uma com uma rubrica documentada e determinística;
 *   - grava `HYPOTHESES-D.md` + `hypotheses-d.json` com custódia SHA-256.
 *
 * Nada aqui executa teste nem declara achado: Fase D formula, Fase F experimenta.
 */

import { createHash } from "node:crypto"
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs"
import path from "node:path"
import { buildLabInvestigationKit, labInvestigationKitExists } from "./investigation-kit.js"
import type {
  LabExperimentSeed,
  LabHypothesisSeed,
  LabInvestigationKit,
  LabSystemModel,
} from "./investigation-kit.js"
import { getLabResearchProfile } from "./research-profile.js"

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------

export type ResearchAnchorKind = "advisory" | "weakness" | "primary_source"

export interface ResearchAnchor {
  kind: ResearchAnchorKind
  /** Identificador curto: `CVE-2015-9235`, `CWE-347`, `RFC 8725`, caminho do doc. */
  ref: string
  /** Por que este achado sustenta a hipótese. */
  detail: string
}

export interface HypothesisScores {
  /** 1–5: chance de a hipótese ser verdadeira, dado o estado atual do alvo. */
  plausibility: number
  /** 1–5: severidade declarada na semente. */
  impact: number
  /** 1–5: quantos experimentos independentes testam a hipótese. */
  discriminatingPower: number
  /** 1–5: o quanto já temos em mãos (Fase C + Fase F) para decidir. */
  evidenceAvailable: number
  /** 1–5 (5 = barato): proxy pelos comandos já prontos nos experimentos. */
  cost: number
  /** 1–5 (5 = arriscado): risco de executar o experimento. */
  executionRisk: number
}

/** Pesos documentados no relatório — sem número mágico escondido. */
export const PRIORITY_WEIGHTS = {
  plausibility: 0.25,
  impact: 0.25,
  discriminatingPower: 0.15,
  evidenceAvailable: 0.15,
  cost: 0.1,
  executionRisk: 0.1,
} as const

export interface PrioritizedHypothesis extends LabHypothesisSeed {
  anchors: ResearchAnchor[]
  scores: HypothesisScores
  priorityScore: number
  experimentIds: string[]
  /** O controle que repararia a falha está DESLIGADO agora (alvo configurado vulnerável). */
  controlCurrentlyOff: boolean
  /** Lacuna metodológica detectada (ex.: hipótese sem ancoragem na Fase C). */
  gap: string | null
}

export interface HypothesisArtifact {
  name: string
  sha256: string
  bytes: number
}

export interface HypothesisBoard {
  labId: string
  generatedAt: string
  /** De qual relatório da Fase C as âncoras vieram — `null` se ele não existir. */
  researchDir: string | null
  researchGeneratedAt: string | null
  hypotheses: PrioritizedHypothesis[]
  weights: typeof PRIORITY_WEIGHTS
  files: HypothesisArtifact[]
  seal: string
  outputDir: string
}

export interface RunHypothesisPhaseParams {
  labId: string
  workspaceRoot: string
  outDir?: string
  now?: Date
}

// ---------------------------------------------------------------------------
// Leitura do kit e do relatório da Fase C
// ---------------------------------------------------------------------------

export function loadLabKit(labId: string, workspaceRoot: string): LabInvestigationKit | null {
  return buildLabInvestigationKit(labId, null) ?? null
}

/** Estado atual dos controles (o kit embutido já traz os valores do `server-config.json`). */
export function loadCurrentControls(
  labId: string,
  workspaceRoot: string,
): Record<string, boolean> {
  const fromDisk = path.join(workspaceRoot, "lab-system-model.json")
  if (labInvestigationKitExists(workspaceRoot) || existsSync(fromDisk)) {
    try {
      const model = JSON.parse(readFileSync(fromDisk, "utf8")) as LabSystemModel
      if (model?.labId === labId && model.controls) return model.controls
    } catch {
      // cai para o kit embutido
    }
  }
  return loadLabKit(labId, workspaceRoot)?.systemModel.controls ?? {}
}

export interface LoadedResearch {
  dir: string
  generatedAt: string
  advisories: Array<{
    target: { ecosystem: string; package: string; anchorKeywords: string[] }
    advisories: Array<{ ghsaId: string; cveId: string | null; summary: string; severity: string }>
  }>
}

/**
 * Procura o relatório da Fase C mais recente do lab.
 * Os diretórios são ISO-8601 com `:`/`.` trocados por `-`, então ordenam por data.
 */
export function loadLatestResearch(workspaceRoot: string, labId: string): LoadedResearch | null {
  const base = path.join(workspaceRoot, "research", labId)
  if (!existsSync(base)) return null
  const dirs = readdirSync(base)
    .filter((d) => !d.startsWith("."))
    .sort()
    .reverse()
  for (const d of dirs) {
    const file = path.join(base, d, "research.json")
    if (!existsSync(file)) continue
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as {
        generatedAt?: string
        advisories?: LoadedResearch["advisories"]
      }
      return {
        dir: path.join(base, d),
        generatedAt: parsed.generatedAt ?? "—",
        advisories: parsed.advisories ?? [],
      }
    } catch {
      continue
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// Ancoragem (Fase C -> Fase D)
// ---------------------------------------------------------------------------

function hypothesisText(h: LabHypothesisSeed): string {
  return [
    h.id,
    h.title,
    h.expectedBehavior,
    h.suspectedBehavior,
    h.fragileAssumption,
    h.technicalRationale,
    h.evidenceNeeded,
    ...(h.alternativeExplanations ?? []),
  ]
    .join(" \n ")
    .toLowerCase()
}

/**
 * Casa a keyword como PALAVRA, não como substring.
 *
 * Isso importa: `alg` como substring casa com "algum"/"alguma" em português, e
 * `token` casa com "o token do User A" de uma hipótese de BOLA que nada tem a ver
 * com JWT. Falso positivo em âncora é pior que âncora faltando — ele faz o
 * operador acreditar que uma falha de lógica tem CVE de biblioteca.
 */
export function keywordMatches(haystack: string, keyword: string): boolean {
  const needle = keyword.trim().toLowerCase()
  if (!needle) return false
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  const useBoundary = /^[a-z0-9]/i.test(needle)
  const re = new RegExp(`${useBoundary ? "\\b" : ""}${escaped}${useBoundary ? "\\b" : ""}`, "i")
  return re.test(haystack)
}

export function collectAnchors(
  hypothesis: LabHypothesisSeed,
  profile: ReturnType<typeof getLabResearchProfile>,
  research: LoadedResearch | null,
): ResearchAnchor[] {
  const text = hypothesisText(hypothesis)
  const anchors: ResearchAnchor[] = []
  const seen = new Set<string>()

  const push = (kind: ResearchAnchorKind, ref: string, detail: string) => {
    const key = `${kind}:${ref}`
    if (seen.has(key)) return
    seen.add(key)
    anchors.push({ kind, ref, detail })
  }

  // 1. CWE citado no próprio texto da hipótese (ex.: "(CWE-347)").
  for (const w of profile.weaknesses) {
    if (text.includes(w.cwe.toLowerCase())) {
      push("weakness", w.cwe, `${w.name}${w.owasp ? ` — ${w.owasp}` : ""}. ${w.why}`)
    }
    // 2. Referência OWASP (ex.: "API1:2023") citada no texto.
    if (w.owasp) {
      const apiRef = /API\d+:\d{4}/.exec(w.owasp)?.[0]
      if (apiRef && text.includes(apiRef.toLowerCase())) {
        push("weakness", w.cwe, `${w.name}${w.owasp ? ` — ${w.owasp}` : ""}. ${w.why}`)
      }
    }
  }

  // 3. Fontes primárias: pela keyword declarada, ou pelo CWE/API ref já citado no texto.
  for (const s of profile.primarySources) {
    const byKeyword = (s.anchorKeywords ?? []).some((k) => keywordMatches(text, k))
    const sourceCwe = /CWE-\d+/.exec(s.url)?.[0]
    const byCwe = sourceCwe ? text.includes(sourceCwe.toLowerCase()) : false
    const apiRef = /API\d+:\d{4}/.exec(s.title)?.[0]
    const byApi = apiRef ? text.includes(apiRef.toLowerCase()) : false
    if (byKeyword || byCwe || byApi) push("primary_source", s.title, s.note)
  }

  // 4. Advisories REAIS da Fase C, ligados por `anchorKeywords`.
  //    Só entram advisories que a consulta realmente retornou — nada é citado de memória.
  if (research) {
    for (const entry of research.advisories) {
      const keywords = entry.target.anchorKeywords ?? []
      if (keywords.length === 0) continue
      if (!keywords.some((k) => keywordMatches(text, k))) continue
      for (const adv of entry.advisories) {
        const ref = adv.cveId ?? adv.ghsaId
        push(
          "advisory",
          ref,
          `${adv.severity} — ${adv.summary} (${entry.target.ecosystem}/${entry.target.package})`,
        )
      }
    }
  }

  return anchors
}

// ---------------------------------------------------------------------------
// Priorização (Fase E)
// ---------------------------------------------------------------------------

/**
 * Mapa da severidade declarada na semente para 1–5.
 * Numa faixa ("Média/Alta") vale o TETO: subestimar impacto rebaixaria a
 * prioridade de uma hipótese que pode ser grave.
 */
export function parseImpact(severityIfConfirmed: string): number {
  const head = severityIfConfirmed.split("—")[0] ?? ""
  const s = head.toLowerCase()
  if (s.includes("crítica") || s.includes("critica")) return 5
  if (s.includes("alta")) return 4
  if (s.includes("média") || s.includes("media")) return 3
  if (s.includes("baixa")) return 2
  return 3
}

export function scoreHypothesis(params: {
  hypothesis: LabHypothesisSeed
  anchors: ResearchAnchor[]
  experiments: LabExperimentSeed[]
  controlCurrentlyOff: boolean
  /** Risco de execução: labs de loopback são 1 (nenhum alvo externo envolvido). */
  executionRisk?: number
}): HypothesisScores {
  const { hypothesis, anchors, experiments, controlCurrentlyOff } = params
  const executionRisk = params.executionRisk ?? 1

  let plausibility: number
  if (controlCurrentlyOff && anchors.length > 0) plausibility = 5
  else if (controlCurrentlyOff) plausibility = 4
  else if (anchors.length > 0) plausibility = 3
  else plausibility = 2

  const discriminatingPower = experiments.length >= 2 ? 5 : experiments.length === 1 ? 4 : 2

  const totalCommands = experiments.reduce((n, e) => n + (e.commands?.length ?? 0), 0)
  const evidenceAvailable =
    anchors.length > 0 && experiments.length > 0
      ? 5
      : experiments.length > 0
        ? 4
        : anchors.length > 0
          ? 3
          : 2
  const cost = totalCommands === 0 ? 2 : totalCommands <= 4 ? 5 : totalCommands <= 9 ? 4 : 3

  return {
    plausibility,
    impact: parseImpact(hypothesis.severityIfConfirmed),
    discriminatingPower,
    evidenceAvailable,
    cost,
    executionRisk,
  }
}

export function priorityScore(scores: HypothesisScores): number {
  const raw =
    PRIORITY_WEIGHTS.plausibility * scores.plausibility +
    PRIORITY_WEIGHTS.impact * scores.impact +
    PRIORITY_WEIGHTS.discriminatingPower * scores.discriminatingPower +
    PRIORITY_WEIGHTS.evidenceAvailable * scores.evidenceAvailable +
    PRIORITY_WEIGHTS.cost * scores.cost -
    PRIORITY_WEIGHTS.executionRisk * scores.executionRisk
  return Math.round(raw * 100) / 100
}

// ---------------------------------------------------------------------------
// Relatório
// ---------------------------------------------------------------------------

function renderBoard(
  board: Omit<HypothesisBoard, "files" | "seal" | "outputDir">,
  files: HypothesisArtifact[],
): string {
  const L: string[] = []
  L.push(`# Fase D — Hipóteses & Priorização (Fase E): ${board.labId}`)
  L.push("")
  L.push(`- **Gerado em**: ${board.generatedAt}`)
  L.push(
    board.researchDir
      ? `- **Ancorado na Fase C**: \`${board.researchDir}\` (gerado em ${board.researchGeneratedAt})`
      : `- **Ancorado na Fase C**: **NÃO** — nenhum \`research/<labId>/*/research.json\` encontrado. Rode \`bun run cyberlab lab research ${board.labId}\` para ancorar as hipóteses.`,
  )
  L.push(`- **Hipóteses**: ${board.hypotheses.length}`)
  L.push("")
  L.push("## Critério de priorização (Fase E)")
  L.push("")
  L.push("| Critério | Peso | Faixa |")
  L.push("|---|---|---|")
  L.push(`| Plausibilidade | ${board.weights.plausibility} | 1–5 |`)
  L.push(`| Impacto | ${board.weights.impact} | 1–5 |`)
  L.push(`| Poder diferenciador | ${board.weights.discriminatingPower} | 1–5 |`)
  L.push(`| Evidência disponível | ${board.weights.evidenceAvailable} | 1–5 |`)
  L.push(`| Custo (5 = barato) | ${board.weights.cost} | 1–5 |`)
  L.push(`| Risco de execução (subtrai) | -${board.weights.executionRisk} | 1–5 |`)
  L.push("")
  L.push(
    "Cada critério é derivado de dados, não de palpite: plausibilidade vem do estado atual do",
  )
  L.push("controle somado à existência de âncora na Fase C; impacto vem da severidade declarada na")
  L.push("semente; poder diferenciador conta experimentos independentes; evidência disponível cruza")
  L.push("Fase C e Fase F; custo é um proxy pelos comandos já prontos; risco é 1 porque o alvo é")
  L.push("loopback e nenhum alvo externo é tocado.")
  L.push("")

  L.push("## Ordem de investigação")
  L.push("")
  L.push("| # | Hipótese | Score | Plaus. | Imp. | Dif. | Evid. | Custo | Risco | Âncoras |")
  L.push("|---|---|---|---|---|---|---|---|---|---|")
  for (const [i, h] of board.hypotheses.entries()) {
    const s = h.scores
    L.push(
      `| ${i + 1} | \`${h.id}\` — ${h.title} | **${h.priorityScore}** | ${s.plausibility} | ${s.impact} | ${s.discriminatingPower} | ${s.evidenceAvailable} | ${s.cost} | ${s.executionRisk} | ${h.anchors.length} |`,
    )
  }
  L.push("")

  for (const h of board.hypotheses) {
    L.push(`## ${h.id} — ${h.title}`)
    L.push("")
    L.push(`- **Prioridade**: ${h.priorityScore} · **Status**: \`${h.status}\``)
    L.push(
      `- **Controle reparador**: ${h.relatedControlFlag ?? "—"} (atualmente **${
        h.controlCurrentlyOff ? "DESLIGADO — alvo configurado vulnerável" : "ligado"
      }**)`,
    )
    if (h.gap) L.push(`- **Lacuna**: ${h.gap}`)
    L.push("")
    L.push(`- **Comportamento esperado (se seguro)**: ${h.expectedBehavior}`)
    L.push(`- **Comportamento suspeito (a testar)**: ${h.suspectedBehavior}`)
    L.push(`- **Pressuposto frágil**: ${h.fragileAssumption}`)
    L.push(`- **Racional técnico**: ${h.technicalRationale}`)
    L.push(`- **Evidência necessária (critério de parada)**: ${h.evidenceNeeded}`)
    L.push(`- **Severidade se confirmada**: ${h.severityIfConfirmed}`)
    L.push("")
    L.push("**Âncoras na Fase C**")
    L.push("")
    if (h.anchors.length === 0) {
      L.push("_Nenhuma. Esta hipótese não é sustentada por pesquisa — investigue por que, ou rode a Fase C._")
    } else {
      L.push("| Tipo | Referência | Detalhe |")
      L.push("|---|---|---|")
      for (const a of h.anchors) {
        L.push(`| ${a.kind} | \`${a.ref}\` | ${a.detail.replace(/\|/g, "\\|")} |`)
      }
    }
    L.push("")
    L.push(`**Experimentos vinculados**: ${h.experimentIds.join(", ") || "—"}`)
    L.push("")
    L.push("**Explicações alternativas**")
    L.push("")
    for (const alt of h.alternativeExplanations) L.push(`- ${alt}`)
    L.push("")
  }

  L.push("## Custódia")
  L.push("")
  L.push("| Arquivo | Bytes | SHA-256 |")
  L.push("|---|---|---|")
  for (const f of files) L.push(`| \`${f.name}\` | ${f.bytes} | \`${f.sha256}\` |`)
  L.push("")
  return L.join("\n")
}

// ---------------------------------------------------------------------------
// Execução
// ---------------------------------------------------------------------------

function sha256Of(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex")
}

export function runHypothesisPhase(params: RunHypothesisPhaseParams): HypothesisBoard {
  const now = params.now ?? new Date()
  const stamp = now.toISOString().replace(/[:.]/g, "-")
  const outDir = params.outDir ?? path.join(params.workspaceRoot, "research", params.labId, "fase-d", stamp)
  mkdirSync(outDir, { recursive: true })

  const kit = loadLabKit(params.labId, params.workspaceRoot)
  if (!kit) {
    throw new Error(
      `O lab "${params.labId}" não tem Kit de Investigação (Fases B/D/F). Labs suportados: ${"lab-owasp-api-bola"}.`,
    )
  }
  const controls = loadCurrentControls(params.labId, params.workspaceRoot)
  const profile = getLabResearchProfile(params.labId)
  const research = loadLatestResearch(params.workspaceRoot, params.labId)

  const hypotheses: PrioritizedHypothesis[] = kit.hypotheses.map((h) => {
    const anchors = collectAnchors(h, profile, research)
    const experiments = kit.experiments.filter((e) => e.hypothesisId === h.id)
    const flag = h.relatedControlFlag
    const controlCurrentlyOff = Boolean(flag) && controls[flag!] === false
    const scores = scoreHypothesis({ hypothesis: h, anchors, experiments, controlCurrentlyOff })
    const hasAdvisory = anchors.some((a) => a.kind === "advisory")
    let gap: string | null = null
    if (anchors.length === 0) {
      gap = "Sem nenhuma âncora na Fase C: a hipótese não é sustentada por pesquisa primária."
    } else if (!hasAdvisory) {
      gap =
        "Ancorada apenas em CWE/fonte primária, sem advisory: esperado para falhas de lógica de aplicação (não há pacote vulnerável)."
    }
    return {
      ...h,
      anchors,
      scores,
      priorityScore: priorityScore(scores),
      experimentIds: experiments.map((e) => e.id),
      controlCurrentlyOff,
      gap,
    }
  })

  // Maior score primeiro; empate preserva a ordem original das sementes.
  hypotheses.sort((a, b) => b.priorityScore - a.priorityScore)

  const base: Omit<HypothesisBoard, "files" | "seal" | "outputDir"> = {
    labId: params.labId,
    generatedAt: now.toISOString(),
    researchDir: research?.dir ?? null,
    researchGeneratedAt: research?.generatedAt ?? null,
    hypotheses,
    weights: PRIORITY_WEIGHTS,
  }

  const jsonText = JSON.stringify(base, null, 2)
  writeFileSync(path.join(outDir, "hypotheses-d.json"), jsonText, "utf8")
  const artifact = (name: string, text: string): HypothesisArtifact => ({
    name,
    sha256: sha256Of(text),
    bytes: Buffer.byteLength(text, "utf8"),
  })
  const jsonArtifact = artifact("hypotheses-d.json", jsonText)

  const md = renderBoard(base, [jsonArtifact])
  writeFileSync(path.join(outDir, "HYPOTHESES-D.md"), md, "utf8")
  const mdArtifact = artifact("HYPOTHESES-D.md", md)

  const files = [mdArtifact, jsonArtifact]
  const seal = sha256Of(files.map((f) => `${f.name}  ${f.sha256}`).join("\n"))
  writeFileSync(
    path.join(outDir, "hypotheses-manifest.json"),
    JSON.stringify({ labId: params.labId, generatedAt: base.generatedAt, files, seal }, null, 2),
    "utf8",
  )

  return { ...base, files, seal, outputDir: outDir }
}
