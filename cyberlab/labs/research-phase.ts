/**
 * Fase C — Pesquisa: executa a pesquisa do laboratório e a transforma em artefato.
 *
 * Duas fontes, como manda a metodologia:
 *   1. `CyberLab-Knowledge/` (biblioteca curada do cofre) — busca local, sempre disponível.
 *   2. GitHub Advisory Database (`api.github.com/advisories`) — histórico real de falhas
 *      das tecnologias que o lab emula.
 *
 * Tudo que vem de rede é arquivado **bruto** (`research-raw/*.json`) com SHA-256, para o
 * relatório ser auditável e reexecutável — o mesmo padrão já usado em `lab evidence`.
 * Nenhum achado é declarado aqui: a Fase C produz contexto, não vulnerabilidade.
 */

import { createHash } from "node:crypto"
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs"
import path from "node:path"
import { CyberLabKnowledgeEngine } from "../knowledge/curated-library.js"
import type { KnowledgeSearchHit } from "../knowledge/curated-library.js"
import { buildLabInvestigationKit, labInvestigationKitExists } from "./investigation-kit.js"
import type { LabSystemModel } from "./investigation-kit.js"
import {
  deriveProfile,
  getLabResearchProfile,
  hasCuratedResearchProfile,
  type AdvisoryTarget,
  type LabResearchProfile,
} from "./research-profile.js"

const ADVISORY_ENDPOINT = "https://api.github.com/advisories"
const CACHE_TTL_MS = 12 * 60 * 60 * 1000
const DEFAULT_TIMEOUT_MS = 20_000

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------

export interface AdvisoryRecord {
  ghsaId: string
  cveId: string | null
  summary: string
  severity: string
  cvssScore: number | null
  cvssVector: string | null
  ecosystem: string
  packageName: string
  vulnerableVersionRange: string
  firstPatchedVersion: string | null
  publishedAt: string
  updatedAt: string
  withdrawnAt: string | null
  url: string
  references: string[]
}

export type AdvisoryQueryStatus = "ok" | "empty" | "error" | "cached" | "offline"

export interface AdvisoryQueryResult {
  target: AdvisoryTarget
  status: AdvisoryQueryStatus
  httpStatus: number | null
  error: string | null
  advisories: AdvisoryRecord[]
  /** Caminho relativo (dentro da pasta do relatório) do JSON bruto arquivado. */
  rawFile: string | null
  rawSha256: string | null
  fetchedAt: string
}

export interface KnowledgeQueryResult {
  query: string
  hits: Array<{
    docPath: string
    title: string
    category: string
    tier: string
    score: number
    matchedSections: string[]
    excerpt: string
  }>
}

export interface ResearchArtifact {
  name: string
  sha256: string
  bytes: number
}

export interface LabResearchReport {
  labId: string
  generatedAt: string
  curated: boolean
  offline: boolean
  outputDir: string
  systemModel: {
    title: string
    baseUrl: string
    components: string[]
    technologies: string[]
    trustBoundaries: string[]
  }
  knowledge: KnowledgeQueryResult[]
  advisories: AdvisoryQueryResult[]
  profile: LabResearchProfile
  files: ResearchArtifact[]
  seal: string
}

export interface RunLabResearchParams {
  labId: string
  workspaceRoot: string
  /** Não toca a rede: usa só o cache em disco (marca `offline`). */
  offline?: boolean
  /** Ignora o cache e consulta a API novamente. */
  refresh?: boolean
  /** Limite de hits por consulta na biblioteca curada. */
  knowledgeLimit?: number
  /** Diretório de saída (padrão: <workspaceRoot>/research/<labId>/<timestamp>). */
  outDir?: string
  /** Injeta o fetch — usado pelos testes para não depender de rede. */
  fetchImpl?: typeof fetch
  now?: Date
}

// ---------------------------------------------------------------------------
// Normalização da resposta da GitHub Advisory Database
// ---------------------------------------------------------------------------

type RawAdvisory = {
  ghsa_id?: unknown
  cve_id?: unknown
  summary?: unknown
  description?: unknown
  severity?: unknown
  cvss?: { score?: unknown; vector_string?: unknown } | null
  vulnerabilities?: Array<{
    package?: { ecosystem?: unknown; name?: unknown }
    vulnerable_version_range?: unknown
    first_patched_version?: unknown
  }> | null
  references?: Array<string | { url?: unknown }> | null
  published_at?: unknown
  updated_at?: unknown
  withdrawn_at?: unknown
  html_url?: unknown
}

function str(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

/**
 * Converte um item da API em `AdvisoryRecord`.
 *
 * Um advisory pode afetar vários pacotes/ecossistemas; a normalização gera **um
 * registro por (advisory, pacote afetado)**, senão o relatório atribuiria a um pacote
 * uma falha que na verdade é de outro.
 */
export function normalizeAdvisories(raw: unknown, target: AdvisoryTarget): AdvisoryRecord[] {
  if (!Array.isArray(raw)) return []
  const out: AdvisoryRecord[] = []
  for (const item of raw) {
    // A API é terceira: um item nulo no array não pode derrubar a Fase C inteira.
    if (!item || typeof item !== "object") continue
    const adv = item as RawAdvisory
    const ghsaId = str(adv.ghsa_id)
    if (!ghsaId) continue
    const vulns = Array.isArray(adv.vulnerabilities) ? adv.vulnerabilities : []
    const pkgs = vulns.length > 0 ? vulns : [undefined]
    for (const vuln of pkgs) {
      out.push({
        ghsaId,
        cveId: str(adv.cve_id),
        summary: str(adv.summary) ?? "(sem resumo)",
        severity: str(adv.severity) ?? "unknown",
        cvssScore: num(adv.cvss?.score),
        cvssVector: str(adv.cvss?.vector_string),
        ecosystem: str(vuln?.package?.ecosystem) ?? target.ecosystem,
        packageName: str(vuln?.package?.name) ?? target.package,
        vulnerableVersionRange: str(vuln?.vulnerable_version_range) ?? "—",
        firstPatchedVersion: str(vuln?.first_patched_version),
        publishedAt: str(adv.published_at) ?? "—",
        updatedAt: str(adv.updated_at) ?? "—",
        withdrawnAt: str(adv.withdrawn_at),
        url: str(adv.html_url) ?? `https://github.com/advisories/${ghsaId}`,
        references: (Array.isArray(adv.references) ? adv.references : [])
          .map((r) => (typeof r === "string" ? str(r) : str(r?.url)))
          .filter((u): u is string => Boolean(u)),
      })
    }
  }
  return out
}

/**
 * Reduz os registros expandidos para **um por advisory**, filtrando pelo pacote
 * consultado.
 *
 * Necessário por dados reais: `GET /advisories?affects=jose` devolve 3 advisories que,
 * expandidos, viram 17 registros — 9 só de faixas de versão repetidas do próprio `jose`
 * e 8 dos pacotes irmãos (`jose-node-cjs-runtime`, `jose-browser-runtime`, ...).
 * E `pyjwt` aparece em três grafias (`pyjwt`, `PyJWT`, `pyJWT`). Uma tabela assim é
 * ilegível e faz o operador crer que há 17 falhas onde há 3.
 */
export function collapseForTarget(
  records: AdvisoryRecord[],
  target: AdvisoryTarget,
): AdvisoryRecord[] {
  const wanted = target.package.toLowerCase()
  const byGhsa = new Map<string, AdvisoryRecord>()
  for (const rec of records) {
    if (rec.packageName.toLowerCase() !== wanted) continue
    const existing = byGhsa.get(rec.ghsaId)
    if (!existing) {
      byGhsa.set(rec.ghsaId, { ...rec, packageName: target.package })
      continue
    }
    const ranges = new Set(
      [existing.vulnerableVersionRange, rec.vulnerableVersionRange]
        .flatMap((r) => r.split(";"))
        .map((r) => r.trim())
        .filter((r) => r && r !== "—"),
    )
    const patches = new Set(
      [existing.firstPatchedVersion, rec.firstPatchedVersion].filter(
        (v): v is string => Boolean(v),
      ),
    )
    existing.vulnerableVersionRange = ranges.size > 0 ? Array.from(ranges).join("; ") : "—"
    existing.firstPatchedVersion = patches.size > 0 ? Array.from(patches).join("; ") : null
    if (rec.withdrawnAt && !existing.withdrawnAt) existing.withdrawnAt = rec.withdrawnAt
  }
  return Array.from(byGhsa.values())
}

// ---------------------------------------------------------------------------
// Cache em disco
// ---------------------------------------------------------------------------

interface CacheFile {
  version: 1
  entries: Record<
    string,
    { at: string; httpStatus: number | null; error: string | null; raw: unknown }
  >
}

function cachePath(workspaceRoot: string): string {
  return path.join(workspaceRoot, ".cyberlab", "research", "advisory-cache.json")
}

function readCache(workspaceRoot: string): CacheFile {
  try {
    const parsed = JSON.parse(readFileSync(cachePath(workspaceRoot), "utf8")) as CacheFile
    return parsed?.version === 1 && parsed.entries ? parsed : { version: 1, entries: {} }
  } catch {
    return { version: 1, entries: {} }
  }
}

function writeCache(workspaceRoot: string, cache: CacheFile): void {
  try {
    mkdirSync(path.dirname(cachePath(workspaceRoot)), { recursive: true })
    writeFileSync(cachePath(workspaceRoot), JSON.stringify(cache, null, 2), "utf8")
  } catch {
    // Cache é otimização: falhar ao gravar não pode derrubar a Fase C.
  }
}

// ---------------------------------------------------------------------------
// Consulta à GitHub Advisory Database
// ---------------------------------------------------------------------------

function githubToken(): string | undefined {
  return process.env.GITHUB_TOKEN || process.env.GH_TOKEN || undefined
}

export interface RawAdvisoryFetch {
  httpStatus: number | null
  error: string | null
  raw: unknown
}

export async function fetchAdvisories(
  target: AdvisoryTarget,
  opts: { timeoutMs?: number; fetchImpl?: typeof fetch } = {},
): Promise<RawAdvisoryFetch> {
  const url = `${ADVISORY_ENDPOINT}?ecosystem=${encodeURIComponent(target.ecosystem)}&affects=${encodeURIComponent(
    target.package,
  )}&per_page=50`
  const doFetch = opts.fetchImpl ?? fetch
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  try {
    const headers: Record<string, string> = { accept: "application/vnd.github+json" }
    const token = githubToken()
    if (token) headers.authorization = `Bearer ${token}`
    const res = await doFetch(url, { headers, signal: controller.signal })
    if (!res.ok) {
      const body = await res.text().catch(() => "")
      const rateLimited = res.status === 403 || res.status === 429
      return {
        httpStatus: res.status,
        error: rateLimited
          ? `Limite de requisições da GitHub Advisory Database (HTTP ${res.status}). Defina GITHUB_TOKEN/GH_TOKEN para 5.000 req/h, ou rode com --offline para reusar o cache.`
          : `HTTP ${res.status} ao consultar ${target.ecosystem}/${target.package}${body ? `: ${body.slice(0, 200)}` : ""}`,
        raw: null,
      }
    }
    return { httpStatus: res.status, error: null, raw: await res.json() }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    const aborted = /abort/i.test(msg)
    return {
      httpStatus: null,
      error: aborted
        ? `Timeout ao consultar a GitHub Advisory Database (${target.ecosystem}/${target.package}).`
        : `Falha de rede ao consultar a GitHub Advisory Database (${target.ecosystem}/${target.package}): ${msg}`,
      raw: null,
    }
  } finally {
    clearTimeout(timer)
  }
}

// ---------------------------------------------------------------------------
// Relatório
// ---------------------------------------------------------------------------

function sha256Of(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex")
}

function loadSystemModel(labId: string, workspaceRoot: string): LabSystemModel | null {
  if (labInvestigationKitExists(workspaceRoot)) {
    try {
      const raw = JSON.parse(
        readFileSync(path.join(workspaceRoot, "lab-system-model.json"), "utf8"),
      ) as LabSystemModel
      if (raw?.labId === labId) return raw
    } catch {
      // cai para o kit embutido
    }
  }
  return buildLabInvestigationKit(labId, null)?.systemModel ?? null
}

function collectKnowledge(
  workspaceRoot: string,
  queries: string[],
  limit: number,
): KnowledgeQueryResult[] {
  if (queries.length === 0) return []
  let engine: CyberLabKnowledgeEngine
  try {
    engine = new CyberLabKnowledgeEngine({ workspaceRoot })
  } catch {
    return []
  }
  const results: KnowledgeQueryResult[] = []
  for (const query of queries) {
    let hits: KnowledgeSearchHit[] = []
    try {
      hits = engine.searchKnowledge({ query, limit })
    } catch {
      hits = []
    }
    results.push({
      query,
      hits: hits.map((h) => ({
        docPath: h.docPath,
        title: h.title,
        category: h.category,
        tier: h.tier,
        score: h.score,
        matchedSections: h.matchedSections,
        excerpt: h.excerpt,
      })),
    })
  }
  return results
}

function renderReport(
  report: Omit<LabResearchReport, "files" | "seal" | "outputDir">,
  files: ResearchArtifact[],
): string {
  const L: string[] = []
  const p = report.profile
  L.push(`# Fase C — Pesquisa: ${report.labId}`)
  L.push("")
  L.push(`- **Gerado em**: ${report.generatedAt}`)
  L.push(`- **Perfil**: ${report.curated ? "curado" : "derivado automaticamente do modelo (Fase B)"}`)
  L.push(`- **Modo**: ${report.offline ? "offline (somente cache em disco)" : "online (GitHub Advisory Database)"}`)
  L.push(`- **Alvo modelado**: ${report.systemModel.title} — ${report.systemModel.baseUrl}`)
  L.push("")

  L.push("## 1. Escopo e método")
  L.push("")
  L.push("A Fase C do ciclo A–I pesquisa **mecanismos, histórico de falhas, patches anteriores e")
  L.push("pressupostos de segurança**. Este relatório não declara vulnerabilidade: produz contexto")
  L.push("para as hipóteses da Fase D.")
  L.push("")
  L.push("Fontes consultadas:")
  L.push("")
  L.push("1. `CyberLab-Knowledge/` — biblioteca curada do cofre (busca local, sem rede).")
  L.push("2. GitHub Advisory Database — `GET https://api.github.com/advisories` (resposta bruta arquivada com SHA-256).")
  L.push("")

  L.push("## 2. Sistema modelado (Fase B)")
  L.push("")
  L.push("**Tecnologias**")
  for (const t of report.systemModel.technologies) L.push(`- ${t}`)
  L.push("")
  L.push("**Componentes**")
  for (const c of report.systemModel.components) L.push(`- ${c}`)
  L.push("")
  L.push("**Fronteiras de confiança**")
  for (const b of report.systemModel.trustBoundaries) L.push(`- ${b}`)
  L.push("")

  L.push("## 3. Biblioteca curada (`CyberLab-Knowledge/`)")
  L.push("")
  if (report.knowledge.length === 0) {
    L.push("_Nenhuma consulta configurada._")
  } else {
    for (const k of report.knowledge) {
      L.push(`### \`${k.query}\``)
      L.push("")
      if (k.hits.length === 0) {
        L.push("_Nenhum documento encontrado._")
        L.push("")
        continue
      }
      L.push("| Documento | Categoria | Tier | Score |")
      L.push("|---|---|---|---|")
      for (const h of k.hits) {
        L.push(`| \`${h.docPath}\` | ${h.category} | ${h.tier} | ${h.score} |`)
      }
      L.push("")
    }
  }

  L.push("## 4. Advisories (GitHub Advisory Database)")
  L.push("")
  if (report.advisories.length === 0) {
    L.push("_Nenhum pacote configurado para consulta._")
    L.push("")
  } else {
    for (const a of report.advisories) {
      L.push(`### \`${a.target.ecosystem}/${a.target.package}\``)
      L.push("")
      L.push(`> ${a.target.rationale}`)
      L.push("")
      L.push(
        `- **Consulta**: \`${a.status}\` · HTTP ${a.httpStatus ?? "—"} · ${a.fetchedAt}${
          a.rawFile ? ` · bruto: \`${a.rawFile}\` · SHA-256 \`${a.rawSha256}\`` : ""
        }`,
      )
      if (a.error) {
        L.push("")
        L.push(`**Erro:** ${a.error}`)
        L.push("")
        continue
      }
      if (a.advisories.length === 0) {
        L.push("")
        L.push("_Nenhum advisory retornado (resultado negativo registrado)._")
        L.push("")
        continue
      }
      L.push("")
      L.push("| GHSA | CVE | Severidade | CVSS | Faixa afetada | Corrigido em | Publicado |")
      L.push("|---|---|---|---|---|---|---|")
      for (const adv of a.advisories) {
        L.push(
          `| [${adv.ghsaId}](${adv.url}) | ${adv.cveId ?? "—"} | ${adv.severity} | ${
            adv.cvssScore ?? "—"
          } | \`${adv.vulnerableVersionRange}\` | ${adv.firstPatchedVersion ?? "—"} | ${adv.publishedAt.slice(0, 10)} |`,
        )
      }
      L.push("")
    }
  }

  L.push("## 5. Classes de fraqueza exercitadas")
  L.push("")
  if (p.weaknesses.length === 0) {
    L.push("_Nenhuma classe mapeada neste perfil._")
  } else {
    for (const w of p.weaknesses) {
      L.push(`- **${w.cwe} — ${w.name}**${w.owasp ? ` (${w.owasp})` : ""}`)
      L.push(`  - ${w.why}`)
    }
  }
  L.push("")

  L.push("## 6. Fontes primárias")
  L.push("")
  if (p.primarySources.length === 0) {
    L.push("_Nenhuma fonte primária mapeada neste perfil._")
  } else {
    for (const s of p.primarySources) {
      L.push(`- [${s.title}](${s.url}) _(${s.kind})_`)
      L.push(`  - ${s.note}`)
    }
  }
  L.push("")

  L.push("## 7. Limitações declaradas")
  L.push("")
  for (const l of p.limitations) L.push(`- ${l}`)
  L.push("")
  L.push("## 8. Artefatos e custódia")
  L.push("")
  L.push("| Arquivo | Bytes | SHA-256 |")
  L.push("|---|---|---|")
  for (const f of files) L.push(`| \`${f.name}\` | ${f.bytes} | \`${f.sha256}\` |`)
  L.push("")
  L.push(
    "O hash **deste** `RESEARCH.md` e o lacre do lote ficam em `research-manifest.json` — um arquivo",
  )
  L.push("não pode conter o próprio hash sem invalidá-lo.")
  L.push("")
  L.push("Verificação (PowerShell): `(Get-FileHash .\\RESEARCH.md -Algorithm SHA256).Hash.ToLower()`")
  L.push("Verificação (WSL2/Linux): `sha256sum RESEARCH.md`")
  L.push("")
  return L.join("\n")
}

// ---------------------------------------------------------------------------
// Execução
// ---------------------------------------------------------------------------

export async function runLabResearch(params: RunLabResearchParams): Promise<LabResearchReport> {
  const now = params.now ?? new Date()
  const stamp = now.toISOString().replace(/[:.]/g, "-")
  const outDir = params.outDir ?? path.join(params.workspaceRoot, "research", params.labId, stamp)
  mkdirSync(path.join(outDir, "research-raw"), { recursive: true })

  const model = loadSystemModel(params.labId, params.workspaceRoot)
  const curated = hasCuratedResearchProfile(params.labId)
  const profile = curated ? getLabResearchProfile(params.labId) : deriveProfile(params.labId, model)

  const knowledge = collectKnowledge(
    params.workspaceRoot,
    profile.knowledgeQueries,
    params.knowledgeLimit ?? 5,
  )

  const cache = readCache(params.workspaceRoot)
  let cacheDirty = false
  const advisories: AdvisoryQueryResult[] = []

  for (const target of profile.advisoryTargets) {
    const key = `${target.ecosystem}:${target.package}`
    const cached = cache.entries[key]
    const cacheFresh =
      cached && !params.refresh && Date.now() - Date.parse(cached.at) < CACHE_TTL_MS

    let status: AdvisoryQueryStatus
    let httpStatus: number | null = null
    let error: string | null = null
    let raw: unknown = null

    if (cacheFresh && cached) {
      status = params.offline ? "offline" : "cached"
      httpStatus = cached.httpStatus
      error = cached.error
      raw = cached.raw
    } else if (params.offline) {
      status = "offline"
      error = "Sem entrada fresca em cache e a execução está em modo --offline."
    } else {
      const res = await fetchAdvisories(target, { fetchImpl: params.fetchImpl })
      httpStatus = res.httpStatus
      error = res.error
      raw = res.raw
      status = error ? "error" : "ok"
      if (!error) {
        cache.entries[key] = { at: new Date().toISOString(), httpStatus, error, raw }
        cacheDirty = true
      }
    }

    const records = raw ? collapseForTarget(normalizeAdvisories(raw, target), target) : []
    if (!error && records.length === 0) status = "empty"

    let rawFile: string | null = null
    let rawSha256: string | null = null
    if (raw !== null) {
      const fileName = `${target.ecosystem}-${target.package.replace(/[^a-zA-Z0-9._-]/g, "_")}.json`
      const serialized = JSON.stringify(raw, null, 2)
      writeFileSync(path.join(outDir, "research-raw", fileName), serialized, "utf8")
      rawFile = path.posix.join("research-raw", fileName)
      rawSha256 = sha256Of(serialized)
    }

    advisories.push({
      target,
      status,
      httpStatus,
      error,
      advisories: records,
      rawFile,
      rawSha256,
      fetchedAt: now.toISOString(),
    })
  }

  if (cacheDirty) writeCache(params.workspaceRoot, cache)

  // `outputDir` NÃO entra aqui (ver comentário no return): o JSON serializado precisa
  // ser independente do caminho para o lacre ser comparável entre execuções.
  const base: Omit<LabResearchReport, "files" | "seal" | "outputDir"> = {
    labId: params.labId,
    generatedAt: now.toISOString(),
    curated,
    offline: Boolean(params.offline),
    systemModel: {
      title: model?.title ?? params.labId,
      baseUrl: model?.baseUrl ?? "—",
      components: model?.components ?? [],
      technologies: model?.technologies ?? [],
      trustBoundaries: model?.trustBoundaries ?? [],
    },
    knowledge,
    advisories,
    profile,
  }

  // Ordem importa para a custódia não ficar circular:
  //   1. research.json guarda só o relatório estruturado (hash estável, sem files/seal).
  //   2. RESEARCH.md lista os artefatos brutos + research.json (não lista a si próprio).
  //   3. research-manifest.json fecha o lacre com o hash de todos — inclusive do RESEARCH.md.
  const jsonText = JSON.stringify(base, null, 2)
  writeFileSync(path.join(outDir, "research.json"), jsonText, "utf8")

  const artifact = (name: string, text: string): ResearchArtifact => ({
    name,
    sha256: sha256Of(text),
    bytes: Buffer.byteLength(text, "utf8"),
  })

  const jsonArtifact = artifact("research.json", jsonText)
  const rawArtifacts: ResearchArtifact[] = readdirSync(path.join(outDir, "research-raw"))
    .sort()
    .map((name) => {
      const text = readFileSync(path.join(outDir, "research-raw", name), "utf8")
      return artifact(path.posix.join("research-raw", name), text)
    })

  const md = renderReport(base, [jsonArtifact, ...rawArtifacts])
  writeFileSync(path.join(outDir, "RESEARCH.md"), md, "utf8")
  const mdArtifact = artifact("RESEARCH.md", md)

  const files: ResearchArtifact[] = [mdArtifact, jsonArtifact, ...rawArtifacts]
  const seal = sha256Of(files.map((f) => `${f.name}  ${f.sha256}`).join("\n"))
  writeFileSync(
    path.join(outDir, "research-manifest.json"),
    JSON.stringify({ labId: params.labId, generatedAt: base.generatedAt, files, seal }, null, 2),
    "utf8",
  )

  // `outputDir` fica fora do JSON serializado de propósito: ele é um ponteiro para
  // onde os arquivos estão, e incluí-lo tornaria o lacre dependente do caminho —
  // dois lotes idênticos gerados em pastas diferentes teriam hashes diferentes.
  return { ...base, outputDir: outDir, files, seal }
}
