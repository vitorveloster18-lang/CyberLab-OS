/**
 * Fase F — Experimentação Controlada.
 *
 * As sementes de experimento já existiam (baseline, variável única, critério de
 * parada, comandos prontos). O que faltava:
 *
 *   1. **Nada executava.** Os comandos ficavam no markdown para o operador copiar
 *      e colar à mão — e o resultado nunca voltava para o processo.
 *   2. **Nenhum vínculo com a priorização da Fase D.** A ordem de execução era a
 *      ordem das sementes, não a ordem de prioridade.
 *
 * Execução é **opt-in** (`--run`): o padrão é planejar e mostrar, porque experimento
 * que toca um alvo não deve rodar por acidente.
 *
 * Segurança: os comandos NÃO vão para um shell. São parseados para uma requisição
 * estruturada e executados com `fetch`. Comando que não casa com o subconjunto
 * suportado vira `manual` e é exibido para execução humana — nunca é executado às cegas.
 */

import { createHash } from "node:crypto"
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import { buildLabInvestigationKit } from "./investigation-kit.js"
import type { LabExperimentSeed, LabInvestigationKit } from "./investigation-kit.js"
import { getLabResearchProfile } from "./research-profile.js"

// ---------------------------------------------------------------------------
// Parse do comando curl
// ---------------------------------------------------------------------------

export interface ParsedRequest {
  method: string
  url: string
  headers: Record<string, string>
  body: string | null
}

/**
 * Converte um `curl` do kit em uma requisição estruturada.
 * Retorna `null` quando o comando usa algo fora do subconjunto suportado — aí ele
 * vira execução manual, em vez de ser executado às cegas.
 */
export function parseCurlCommand(command: string): ParsedRequest | null {
  let line = command.trim()
  if (line.startsWith("#")) return null
  if (line.length === 0) return null

  const tokens = tokenize(line)
  if (tokens.length === 0) return null
  if (basenameOfToken(tokens[0]!) !== "curl") return null

  let method = "GET"
  const headers: Record<string, string> = {}
  let body: string | null = null
  const urls: string[] = []

  const SUPPORTED_NO_ARG = new Set(["-s", "-S", "-sS", "-i", "-k", "-v", "-L", "-g"])
  const SUPPORTED_ONE_ARG = new Set(["-H", "-X", "-d", "-A", "--data", "--data-raw", "--request"])

  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!
    if (SUPPORTED_NO_ARG.has(t)) continue
    if (SUPPORTED_ONE_ARG.has(t)) {
      const value = tokens[i + 1]
      if (value === undefined) return null
      i += 1
      if (t === "-H") {
        const sep = value.indexOf(":")
        if (sep === -1) return null
        headers[value.slice(0, sep).trim()] = value.slice(sep + 1).trim()
      } else if (t === "-X" || t === "--request") {
        method = value.toUpperCase()
      } else if (t === "-A") {
        headers["User-Agent"] = value
      } else {
        body = body === null ? value : `${body}&${value}`
      }
      continue
    }
    // Qualquer outra flag é desconhecida: não executa.
    if (t.startsWith("-")) return null
    urls.push(t)
  }

  if (urls.length !== 1) return null
  const url = urls[0]!
  if (!/^https?:\/\//i.test(url)) return null
  if (body !== null && method === "GET") method = "POST"
  return { method, url, headers, body }
}

/** Separa respeitando aspas simples e duplas. */
export function tokenize(line: string): string[] {
  const out: string[] = []
  let cur = ""
  let quote: '"' | "'" | null = null
  let has = false
  for (const ch of line) {
    if (quote) {
      if (ch === quote) {
        quote = null
        continue
      }
      cur += ch
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      has = true
      continue
    }
    if (/\s/.test(ch)) {
      if (has) {
        out.push(cur)
        cur = ""
        has = false
      }
      continue
    }
    cur += ch
    has = true
  }
  if (has) out.push(cur)
  return out
}

function basenameOfToken(token: string): string {
  const base = token.replace(/\\/g, "/").split("/").pop() ?? token
  return base.replace(/\.exe$/i, "").toLowerCase()
}

// ---------------------------------------------------------------------------
// Execução
// ---------------------------------------------------------------------------

export type RequestOutcome = "executed" | "manual" | "error" | "planned"

export interface RequestResult {
  experimentId: string
  index: number
  /** Linha do comentário que precede o comando, quando houver. */
  intent: string | null
  command: string
  outcome: RequestOutcome
  request: ParsedRequest | null
  httpStatus: number | null
  durationMs: number | null
  /** Captura bruta (linha de status + headers + corpo), espelho do `curl -i`. */
  raw: string | null
  sha256: string | null
  bytes: number
  error: string | null
  rawFile: string | null
}

export interface ExperimentResult {
  seed: LabExperimentSeed
  hypothesisId: string
  requests: RequestResult[]
  /** Marcadores da hipótese encontrados em QUALQUER resposta do experimento. */
  markersFound: string[]
  /**
   * Indicador preliminar para a Fase G. **Não é veredito**: só diz se o marcador
   * esperado apareceu. Quem decide é a Fase G (avaliação crítica).
   */
  indicator: "sustenta" | "nao_observado" | "sem_marcador" | "nao_executado"
}

function sha256Of(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex")
}

function retarget(url: string, baseUrl: string | null): string {
  if (!baseUrl) return url
  try {
    const u = new URL(url)
    const b = new URL(baseUrl)
    u.protocol = b.protocol
    u.host = b.host
    return u.toString()
  } catch {
    return url
  }
}

async function executeRequest(
  req: ParsedRequest,
  timeoutMs: number,
  fetchImpl?: typeof fetch,
): Promise<{ status: number; raw: string; durationMs: number }> {
  const doFetch = fetchImpl ?? fetch
  const started = Date.now()
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await doFetch(req.url, {
      method: req.method,
      headers: req.headers,
      ...(req.body !== null ? { body: req.body } : {}),
      redirect: "manual",
      signal: controller.signal,
    })
    const text = await res.text()
    const headerLines: string[] = []
    res.headers.forEach((value, key) => headerLines.push(`${key}: ${value}`))
    const raw = [`HTTP/1.1 ${res.status} ${res.statusText || ""}`.trim(), ...headerLines, "", text].join(
      "\r\n",
    )
    return { status: res.status, raw, durationMs: Date.now() - started }
  } finally {
    clearTimeout(timer)
  }
}

// ---------------------------------------------------------------------------
// Plano / execução
// ---------------------------------------------------------------------------

export interface ExperimentArtifact {
  name: string
  sha256: string
  bytes: number
}

export interface ExperimentBoard {
  labId: string
  generatedAt: string
  /** `plan` = nada foi executado; `run` = requisições foram ao alvo. */
  mode: "plan" | "run"
  baseUrl: string | null
  /** Ordem seguida: a da Fase D quando existe, senão a das sementes. */
  orderSource: "fase-d" | "sementes"
  experiments: ExperimentResult[]
  files: ExperimentArtifact[]
  seal: string
  outputDir: string
}

export interface RunExperimentPhaseParams {
  labId: string
  workspaceRoot: string
  /** Executa as requisições. Sem isso, só planeja. */
  run?: boolean
  /** Redireciona as requisições para outro host:porta (padrão: o `baseUrl` do modelo). */
  baseUrl?: string | null
  /** IDs de experimento a incluir (ex.: `E1,E3`). */
  only?: string[]
  timeoutMs?: number
  outDir?: string
  now?: Date
  /** Injeta o fetch — usado pelos testes para não tocar a rede. */
  fetchImpl?: typeof fetch
}

/** Lê a ordem priorizada da Fase D, se existir. */
export function loadPriorityOrder(workspaceRoot: string, labId: string): string[] | null {
  const dir = path.join(workspaceRoot, "research", labId, "fase-d")
  let stamps: string[] = []
  try {
    stamps = readdirSafe(dir)
  } catch {
    return null
  }
  for (const stamp of stamps.sort().reverse()) {
    try {
      const parsed = JSON.parse(
        readFileSync(path.join(dir, stamp, "hypotheses-d.json"), "utf8"),
      ) as { hypotheses?: Array<{ id: string }> }
      const ids = (parsed.hypotheses ?? []).map((h) => h.id)
      if (ids.length > 0) return ids
    } catch {
      continue
    }
  }
  return null
}

function readdirSafe(dir: string): string[] {
  return readdirSync(dir)
}

export async function runExperimentPhase(
  params: RunExperimentPhaseParams,
): Promise<ExperimentBoard> {
  const now = params.now ?? new Date()
  const stamp = now.toISOString().replace(/[:.]/g, "-")
  const outDir =
    params.outDir ?? path.join(params.workspaceRoot, "research", params.labId, "fase-f", stamp)
  mkdirSync(path.join(outDir, "raw"), { recursive: true })

  const kit = buildLabInvestigationKit(params.labId, null)
  if (!kit) {
    throw new Error(
      `O lab "${params.labId}" não tem Kit de Investigação (Fases B/D/F). Labs suportados: lab-owasp-api-bola.`,
    )
  }

  const baseUrl = params.baseUrl ?? kit.systemModel.baseUrl ?? null
  const profile = getLabResearchProfile(params.labId)
  const priority = loadPriorityOrder(params.workspaceRoot, params.labId)
  const ordered = orderExperiments(kit, priority, params.only)

  const experiments: ExperimentResult[] = []
  for (const seed of ordered) {
    const markers = profile.observationMarkers[seed.hypothesisId] ?? []
    const requests: RequestResult[] = []

    let intent: string | null = null
    let idx = 0
    for (const command of seed.commands) {
      const trimmed = command.trim()
      if (trimmed.startsWith("#")) {
        intent = trimmed.replace(/^#+\s*/, "")
        continue
      }
      if (trimmed.length === 0) continue
      const parsed = parseCurlCommand(trimmed)
      const entry: RequestResult = {
        experimentId: seed.id,
        index: idx,
        intent,
        command: trimmed,
        outcome: "planned",
        request: parsed ? { ...parsed, url: retarget(parsed.url, baseUrl) } : null,
        httpStatus: null,
        durationMs: null,
        raw: null,
        sha256: null,
        bytes: 0,
        error: null,
        rawFile: null,
      }
      intent = null

      if (!params.run) {
        entry.outcome = parsed ? "planned" : "manual"
      } else if (!parsed) {
        entry.outcome = "manual"
        entry.error = "Comando fora do subconjunto suportado: execute manualmente."
      } else {
        try {
          const res = await executeRequest(
            { ...parsed, url: retarget(parsed.url, baseUrl) },
            params.timeoutMs ?? 15_000,
            params.fetchImpl,
          )
          entry.outcome = "executed"
          entry.httpStatus = res.status
          entry.durationMs = res.durationMs
          entry.raw = res.raw
          entry.sha256 = sha256Of(res.raw)
          entry.bytes = Buffer.byteLength(res.raw, "utf8")
          const fileName = `${seed.id}-${String(idx + 1).padStart(2, "0")}.txt`
          writeFileSync(path.join(outDir, "raw", fileName), res.raw, "utf8")
          entry.rawFile = path.posix.join("raw", fileName)
        } catch (err) {
          entry.outcome = "error"
          entry.error =
            err instanceof Error
              ? /abort/i.test(err.message)
                ? `Timeout ao consultar ${retarget(parsed.url, baseUrl)}. O lab está no ar?`
                : err.message
              : String(err)
        }
      }
      requests.push(entry)
      idx += 1
    }

    const haystack = requests.map((r) => r.raw ?? "").join("\n")
    const markersFound = markers.filter((m) => haystack.includes(m))
    // Ordem importa: um experimento cujos comandos são todos manuais (ex.: E6, que
    // aplica remediação via PowerShell) NÃO deve sair como "nao_observado" — isso
    // sugeriria que a hipótese não se sustentou, quando na verdade nada rodou.
    const executedCount = requests.filter((r) => r.outcome === "executed").length
    let indicator: ExperimentResult["indicator"]
    if (!params.run || executedCount === 0) indicator = "nao_executado"
    else if (markers.length === 0) indicator = "sem_marcador"
    else if (markersFound.length > 0) indicator = "sustenta"
    else indicator = "nao_observado"

    experiments.push({ seed, hypothesisId: seed.hypothesisId, requests, markersFound, indicator })
  }

  const boardBase = {
    labId: params.labId,
    generatedAt: now.toISOString(),
    mode: params.run ? ("run" as const) : ("plan" as const),
    baseUrl,
    orderSource: priority ? ("fase-d" as const) : ("sementes" as const),
    experiments,
  }

  const jsonText = JSON.stringify(boardBase, null, 2)
  writeFileSync(path.join(outDir, "experiments-f.json"), jsonText, "utf8")
  const artifact = (name: string, text: string): ExperimentArtifact => ({
    name,
    sha256: sha256Of(text),
    bytes: Buffer.byteLength(text, "utf8"),
  })
  const jsonArtifact = artifact("experiments-f.json", jsonText)

  const md = renderBoard(boardBase, experiments, [jsonArtifact])
  writeFileSync(path.join(outDir, "EXPERIMENTS.md"), md, "utf8")
  const mdArtifact = artifact("EXPERIMENTS.md", md)

  const files = [mdArtifact, jsonArtifact]
  const seal = sha256Of(files.map((f) => `${f.name}  ${f.sha256}`).join("\n"))
  writeFileSync(
    path.join(outDir, "experiments-manifest.json"),
    JSON.stringify({ labId: params.labId, generatedAt: boardBase.generatedAt, files, seal }, null, 2),
    "utf8",
  )

  return { ...boardBase, files, seal, outputDir: outDir }
}

/** Ordena os experimentos pela prioridade da Fase D (H mais prioritário primeiro). */
export function orderExperiments(
  kit: LabInvestigationKit,
  priority: string[] | null,
  only?: string[],
): LabExperimentSeed[] {
  let seeds = kit.experiments.slice()
  if (only && only.length > 0) {
    const wanted = new Set(only.map((s) => s.trim().toUpperCase()))
    seeds = seeds.filter((s) => wanted.has(s.id.toUpperCase()))
  }
  if (!priority) return seeds
  const rank = new Map(priority.map((h, i) => [h, i]))
  return seeds.sort((a, b) => {
    const ra = rank.get(a.hypothesisId) ?? Number.MAX_SAFE_INTEGER
    const rb = rank.get(b.hypothesisId) ?? Number.MAX_SAFE_INTEGER
    if (ra !== rb) return ra - rb
    return a.id.localeCompare(b.id)
  })
}

// ---------------------------------------------------------------------------
// Relatório
// ---------------------------------------------------------------------------

function renderBoard(
  board: Omit<ExperimentBoard, "files" | "seal" | "outputDir">,
  experiments: ExperimentResult[],
  files: ExperimentArtifact[],
): string {
  const L: string[] = []
  L.push(`# Fase F — Experimentação: ${board.labId}`)
  L.push("")
  L.push(`- **Gerado em**: ${board.generatedAt}`)
  L.push(
    `- **Modo**: ${board.mode === "run" ? "EXECUTADO (requisições foram ao alvo)" : "PLANEJADO (nada foi executado)"}`,
  )
  L.push(`- **Alvo**: ${board.baseUrl ?? "—"}`)
  L.push(
    `- **Ordem**: ${board.orderSource === "fase-d" ? "prioridade da Fase D" : "ordem das sementes (rode \`lab hypothesize\` para priorizar)"}`,
  )
  L.push(`- **Experimentos**: ${experiments.length}`)
  L.push("")
  if (board.mode === "plan") {
    L.push("> Nada foi executado. Para rodar: `bun run cyberlab lab experiment <labId> --run`.")
    L.push("")
  }
  L.push(
    "> O **indicador** abaixo NÃO é veredito: diz apenas se o marcador esperado apareceu na",
  )
  L.push("> resposta. Quem decide é a Fase G (avaliação crítica).")
  L.push("")

  L.push("## Resumo")
  L.push("")
  L.push("| # | Experimento | Hipótese | Requisições | Executadas | Indicador | Marcadores |")
  L.push("|---|---|---|---|---|---|---|")
  for (const [i, e] of experiments.entries()) {
    const executed = e.requests.filter((r) => r.outcome === "executed").length
    const manual = e.requests.filter((r) => r.outcome === "manual").length
    L.push(
      `| ${i + 1} | \`${e.seed.id}\` | ${e.hypothesisId} | ${e.requests.length} | ${executed}${
        manual > 0 ? ` (+${manual} manual)` : ""
      } | ${e.indicator} | ${e.markersFound.length > 0 ? e.markersFound.map((m) => `\`${m.slice(0, 40)}\``).join(", ") : "—"} |`,
    )
  }
  L.push("")

  for (const e of experiments) {
    L.push(`## ${e.seed.id} — ${e.seed.question}`)
    L.push("")
    L.push(`- **Hipótese**: ${e.hypothesisId} · **Indicador**: \`${e.indicator}\``)
    L.push(`- **Ferramenta**: ${e.seed.toolUsed}`)
    L.push(`- **Condições iniciais (baseline)**: ${e.seed.initialConditions}`)
    L.push(`- **Variável modificada**: ${e.seed.modifiedVariable}`)
    L.push(`- **Resultado esperado**: ${e.seed.expectedOutcome}`)
    L.push(`- **Critério de interrupção**: ${e.seed.stopCriterion}`)
    if (e.markersFound.length > 0) {
      L.push(`- **Marcadores encontrados**: ${e.markersFound.map((m) => `\`${m}\``).join(", ")}`)
    }
    L.push("")
    L.push("| # | Intenção | Comando | Resultado |")
    L.push("|---|---|---|---|")
    for (const r of e.requests) {
      const result =
        r.outcome === "executed"
          ? `HTTP ${r.httpStatus} · ${r.durationMs}ms · \`${r.rawFile}\` · SHA-256 \`${(r.sha256 ?? "").slice(0, 12)}…\``
          : r.outcome === "manual"
            ? "manual (fora do subconjunto)"
            : r.outcome === "error"
              ? `erro: ${r.error}`
              : "planejado (não executado)"
      L.push(
        `| ${r.index + 1} | ${r.intent ?? "—"} | \`${r.command.replace(/\|/g, "\\|")}\` | ${result} |`,
      )
    }
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
