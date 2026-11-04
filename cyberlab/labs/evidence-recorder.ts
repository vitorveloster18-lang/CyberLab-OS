/**
 * CyberLab OS — Gravador de Evidência (v6.5).
 *
 * Reexecuta os experimentos E1–E6 do `lab-owasp-api-bola` contra um servidor real e
 * arquiva cada par comando/resposta em disco com SHA-256, para que qualquer auditor
 * possa (a) reler o que foi observado e (b) detectar alteração posterior do arquivo.
 *
 * Por que exists: a memória investigativa guarda a *interpretação*. A evidência guarda
 * o *dado bruto*. Sem o dado bruto, "confirmado" é só uma opinião com data.
 *
 * Garantias do formato:
 *  - Um arquivo `.txt` por requisição: comando executado + requisição + resposta completa.
 *  - `manifest.json`: metadados de todas as requisições + SHA-256 de cada `.txt`.
 *  - `SEAL.txt`: SHA-256 do próprio `manifest.json` (selo do lote) + carimbo de tempo.
 *  - `REPORT.md`: leitura humana (veredito por hipótese, com o critério usado).
 *
 * Nada aqui altera o estado final do lab: a remediação de E6 é revertida e verificada.
 */

import { createHash } from "node:crypto"
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import path from "node:path"

export const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
] as const

export const REMEDIATED_CONFIG = {
  enforceAccountOwnership: true,
  rejectAlgNoneJwt: true,
  sanitizeSqlQuery: true,
  enableSecurityHeaders: true,
} as const

export const VULNERABLE_CONFIG = {
  enforceAccountOwnership: false,
  rejectAlgNoneJwt: false,
  sanitizeSqlQuery: false,
  enableSecurityHeaders: false,
} as const

export type LabSecurityConfig = {
  enforceAccountOwnership: boolean
  rejectAlgNoneJwt: boolean
  sanitizeSqlQuery: boolean
  enableSecurityHeaders: boolean
}

export type EvidenceVerdict = "vulneravel" | "seguro" | "remediado" | "inconclusivo"

export interface EvidenceCase {
  /** Identificador curto e estável — vira o nome do arquivo. */
  id: string
  experimentId: string
  label: string
  /** Comando exatamente como o operador deve reproduzir (PowerShell). */
  command: string
  method: "GET" | "POST"
  url: string
  headers?: Record<string, string>
  /** O que se esperava ANTES de rodar (hipótese em teste). */
  expectation: string
}

export interface EvidenceRecord {
  id: string
  experimentId: string
  label: string
  command: string
  method: string
  url: string
  requestHeaders: Record<string, string>
  expectation: string
  status: number
  statusText: string
  responseHeaders: Record<string, string>
  body: string
  durationMs: number
  capturedAt: string
  file: string
  sha256: string
  bytes: number
}

export interface EvidenceManifest {
  schema: "cyberlab.lab.evidence/1"
  labId: string
  baseUrl: string
  suite: string
  tool: string
  generatedAt: string
  configAtStart: LabSecurityConfig
  configAtEnd: LabSecurityConfig
  cases: EvidenceRecord[]
  verdicts: Record<string, { hypothesisId?: string; verdict: EvidenceVerdict; rationale: string }>
  files: { path: string; sha256: string; bytes: number }[]
  /** Sempre `null` no arquivo: o valor vive em SEAL.txt (ver comentário em `runBolaEvidenceSuite`). */
  seal: string | null
}

const REASON: Record<number, string> = {
  200: "OK",
  201: "Created",
  204: "No Content",
  301: "Moved Permanently",
  302: "Found",
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  418: "I'm a teapot",
  429: "Too Many Requests",
  500: "Internal Server Error",
  502: "Bad Gateway",
  503: "Service Unavailable",
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex")
}

/** Renderiza um par comando/resposta em texto puro — legível por humano e por diff. */
export function renderEvidenceText(record: Omit<EvidenceRecord, "file" | "sha256" | "bytes">): string {
  const u = new URL(record.url)
  const reqLines = [`${record.method} ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`]
  for (const [k, v] of Object.entries(record.requestHeaders)) reqLines.push(`${k}: ${v}`)

  const resLines = [`HTTP/1.1 ${record.status} ${record.statusText}`.trimEnd()]
  for (const [k, v] of Object.entries(record.responseHeaders)) resLines.push(`${k}: ${v}`)

  return [
    `# ${record.experimentId} — ${record.id}: ${record.label}`,
    `capturado_em : ${record.capturedAt}`,
    `duracao_ms   : ${record.durationMs}`,
    `expectativa  : ${record.expectation}`,
    "",
    "$ " + record.command,
    "",
    ">>> REQUISICAO",
    ...reqLines,
    "",
    "<<< RESPOSTA",
    ...resLines,
    "",
    record.body,
    "",
  ].join("\n")
}

export class LabEvidenceRecorder {
  private readonly records: EvidenceRecord[] = []

  constructor(
    readonly baseUrl: string,
    readonly outDir: string,
  ) {
    mkdirSync(outDir, { recursive: true })
  }

  async capture(testCase: EvidenceCase): Promise<EvidenceRecord> {
    const started = Date.now()
    const res = await fetch(testCase.url, {
      method: testCase.method,
      headers: testCase.headers ?? {},
      redirect: "manual",
    })
    const body = await res.text()
    const durationMs = Date.now() - started

    const responseHeaders: Record<string, string> = {}
    res.headers.forEach((value, key) => {
      responseHeaders[key] = value
    })

    const partial = {
      id: testCase.id,
      experimentId: testCase.experimentId,
      label: testCase.label,
      command: testCase.command,
      method: testCase.method,
      url: testCase.url,
      requestHeaders: testCase.headers ?? {},
      expectation: testCase.expectation,
      status: res.status,
      statusText: res.statusText || REASON[res.status] || "",
      responseHeaders,
      body,
      durationMs,
      capturedAt: new Date().toISOString(),
    }

    const text = renderEvidenceText(partial)
    const file = path.join(this.outDir, `${testCase.id}.txt`)
    writeFileSync(file, text, "utf8")

    const record: EvidenceRecord = {
      ...partial,
      file: path.basename(file),
      sha256: sha256Hex(text),
      bytes: Buffer.byteLength(text, "utf8"),
    }
    this.records.push(record)
    return record
  }

  all(): EvidenceRecord[] {
    return [...this.records]
  }

  get(id: string): EvidenceRecord | undefined {
    return this.records.find((r) => r.id === id)
  }
}

// ---------------------------------------------------------------------------
// Suíte E1–E6 do lab-owasp-api-bola
// ---------------------------------------------------------------------------

export interface EvidenceSuiteOptions {
  baseUrl: string
  outDir: string
  /** Diretório do workspace do lab — contém `server-config.json`. */
  workspaceRoot: string
  /** Sobrepõe o relógio (testes determinísticos). */
  now?: () => string
}

export interface EvidenceSuiteResult {
  manifest: EvidenceManifest
  /** SHA-256 do `manifest.json` gravado — confere com `sha256sum manifest.json`. */
  seal: string
  manifestPath: string
  sealPath: string
  reportPath: string
  suiteDir: string
}

const ALG_NONE_TOKEN =
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyLTEwMDEiLCJyb2xlIjoiYWRtaW4ifQ."

function readConfig(workspaceRoot: string): LabSecurityConfig {
  return JSON.parse(readFileSync(path.join(workspaceRoot, "server-config.json"), "utf8")) as LabSecurityConfig
}

function writeConfig(workspaceRoot: string, config: LabSecurityConfig): void {
  writeFileSync(path.join(workspaceRoot, "server-config.json"), `${JSON.stringify(config, null, 2)}\n`, "utf8")
}

function auth(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` }
}

/** Monta os 19 casos: 11 no estado vulnerável, 4 remediados, 4 após restaurar. */
export function buildBolaEvidenceCases(baseUrl: string, curl = "curl.exe"): EvidenceCase[] {
  const u = baseUrl.replace(/\/+$/, "")
  const bearer = (t: string) => `-H "Authorization: Bearer ${t}"`
  return [
    // ---------------- E1 · H1 · BOLA entre contas ----------------
    {
      id: "E1-01-baseline-own-account",
      experimentId: "E1",
      label: "User A lendo a PRÓPRIA conta (baseline positivo)",
      command: `${curl} -s -i ${bearer("token-user-a-1001")} ${u}/api/v1/accounts/1001`,
      method: "GET",
      url: `${u}/api/v1/accounts/1001`,
      headers: auth("token-user-a-1001"),
      expectation: "200 com dados de alice@corp.lab (prova que o endpoint funciona).",
    },
    {
      id: "E1-02-poc-cross-account",
      experimentId: "E1",
      label: "User A lendo a conta do User B (PoC de BOLA)",
      command: `${curl} -s -i ${bearer("token-user-a-1001")} ${u}/api/v1/accounts/1002`,
      method: "GET",
      url: `${u}/api/v1/accounts/1002`,
      headers: auth("token-user-a-1001"),
      expectation: "403 se o controle de titularidade existisse; 200 com bolaFlag se vulnerável.",
    },
    {
      id: "E1-03-control-owner-reads-own",
      experimentId: "E1",
      label: "Controle — User B lendo a PRÓPRIA conta (isola o token como variável)",
      command: `${curl} -s -i ${bearer("token-user-b-1002")} ${u}/api/v1/accounts/1002`,
      method: "GET",
      url: `${u}/api/v1/accounts/1002`,
      headers: auth("token-user-b-1002"),
      expectation: "200 — prova que a diferença em E1-02 vem do token, não do ID.",
    },
    // ---------------- E2 · H1 · acesso anônimo ----------------
    {
      id: "E2-01-anon-own-account",
      experimentId: "E2",
      label: "Baseline — sem credencial na conta 1001",
      command: `${curl} -s -i ${u}/api/v1/accounts/1001`,
      method: "GET",
      url: `${u}/api/v1/accounts/1001`,
      expectation: "401/403 se autenticação fosse obrigatória; 200 com dados se não.",
    },
    {
      id: "E2-02-anon-other-account",
      experimentId: "E2",
      label: "PoC — sem credencial na conta 1002",
      command: `${curl} -s -i ${u}/api/v1/accounts/1002`,
      method: "GET",
      url: `${u}/api/v1/accounts/1002`,
      expectation: "401/403 se autenticação fosse obrigatória; 200 com dados se não.",
    },
    // ---------------- E3 · H2 · JWT alg:none ----------------
    {
      id: "E3-01-no-token",
      experimentId: "E3",
      label: "Baseline — endpoint admin sem token",
      command: `${curl} -s -i ${u}/api/v1/admin/debug`,
      method: "GET",
      url: `${u}/api/v1/admin/debug`,
      expectation: "401 (o endpoint exige alguma credencial).",
    },
    {
      id: "E3-02-opaque-token",
      experimentId: "E3",
      label: "Baseline — token opaco não-JWT",
      command: `${curl} -s -i ${bearer("token-user-a-1001")} ${u}/api/v1/admin/debug`,
      method: "GET",
      url: `${u}/api/v1/admin/debug`,
      headers: auth("token-user-a-1001"),
      expectation: "401 (token sem role=admin não deve bastar).",
    },
    {
      id: "E3-03-poc-alg-none",
      experimentId: "E3",
      label: "PoC — JWT forjado com alg:none e role=admin",
      command: `${curl} -s -i ${bearer(ALG_NONE_TOKEN)} ${u}/api/v1/admin/debug`,
      method: "GET",
      url: `${u}/api/v1/admin/debug`,
      headers: auth(ALG_NONE_TOKEN),
      expectation: "401 se a assinatura fosse verificada; 200 com LAB{JWT_ALG_NONE_ACCEPTED} se não.",
    },
    // ---------------- E4 · H3 · erro SQL ----------------
    {
      id: "E4-01-benign-query",
      experimentId: "E4",
      label: "Baseline — consulta benigna",
      command: `${curl} -s -i "${u}/api/v1/search?q=test"`,
      method: "GET",
      url: `${u}/api/v1/search?q=test`,
      expectation: "200 com resultados.",
    },
    {
      id: "E4-02-poc-single-quote",
      experimentId: "E4",
      label: "PoC — aspa simples (%27) no parâmetro q",
      command: `${curl} -s -i "${u}/api/v1/search?q=%27"`,
      method: "GET",
      url: `${u}/api/v1/search?q=%27`,
      expectation: "Erro genérico SEM estrutura da consulta; 500 com SQLITE_ERROR se vulnerável.",
    },
    // ---------------- E5 · H4 · headers ----------------
    {
      id: "E5-01-header-baseline",
      experimentId: "E5",
      label: "Baseline — headers de segurança na resposta autenticada",
      command: `${curl} -s -D - -o NUL ${bearer("token-user-a-1001")} ${u}/api/v1/accounts/1001`,
      method: "GET",
      url: `${u}/api/v1/accounts/1001`,
      headers: auth("token-user-a-1001"),
      expectation: "CSP, HSTS, X-Frame-Options e X-Content-Type-Options presentes.",
    },
  ]
}

/** Os 4 casos repetidos APÓS a remediação (e novamente após restaurar). */
export function buildRemediationCases(baseUrl: string, phase: "remediado" | "restaurado", curl = "curl.exe"): EvidenceCase[] {
  const u = baseUrl.replace(/\/+$/, "")
  const pfx = phase === "remediado" ? "E6" : "E7"
  const expected =
    phase === "remediado"
      ? "Após ligar os 4 controles: 403 esperado."
      : "Após desligar os 4 controles novamente: volta a 200 (estado vulnerável)."
  return [
    {
      id: `${pfx}-01-bola`,
      experimentId: phase === "remediado" ? "E6" : "E7",
      label: `H1 — BOLA (${phase})`,
      command: `${curl} -s -o NUL -w "%{http_code}" -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/accounts/1002`,
      method: "GET",
      url: `${u}/api/v1/accounts/1002`,
      headers: auth("token-user-a-1001"),
      expectation: expected,
    },
    {
      id: `${pfx}-02-alg-none`,
      experimentId: phase === "remediado" ? "E6" : "E7",
      label: `H2 — JWT alg:none (${phase})`,
      command: `${curl} -s -o NUL -w "%{http_code}" -H "Authorization: Bearer ${ALG_NONE_TOKEN}" ${u}/api/v1/admin/debug`,
      method: "GET",
      url: `${u}/api/v1/admin/debug`,
      headers: auth(ALG_NONE_TOKEN),
      expectation:
        phase === "remediado"
          ? "Após ligar rejectAlgNoneJwt: 401 esperado."
          : "Após desligar rejectAlgNoneJwt: volta a 200 (estado vulnerável).",
    },
    {
      id: `${pfx}-03-sql-error`,
      experimentId: phase === "remediado" ? "E6" : "E7",
      label: `H3 — erro SQL (${phase})`,
      command: `${curl} -s -o NUL -w "%{http_code}" "${u}/api/v1/search?q=%27"`,
      method: "GET",
      url: `${u}/api/v1/search?q=%27`,
      expectation:
        phase === "remediado"
          ? "Após ligar sanitizeSqlQuery: 200 SEM SQLITE_ERROR esperado."
          : "Após desligar sanitizeSqlQuery: volta a 500 com SQLITE_ERROR (estado vulnerável).",
    },
    {
      id: `${pfx}-04-headers`,
      experimentId: phase === "remediado" ? "E6" : "E7",
      label: `H4 — headers de segurança (${phase})`,
      command: `${curl} -s -D - -o NUL -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/accounts/1001`,
      method: "GET",
      url: `${u}/api/v1/accounts/1001`,
      headers: auth("token-user-a-1001"),
      expectation:
        phase === "remediado"
          ? "Após ligar enableSecurityHeaders: os 4 headers presentes."
          : "Após desligar enableSecurityHeaders: os 4 headers ausentes novamente.",
    },
  ]
}

function missingSecurityHeaders(record: EvidenceRecord): string[] {
  const have = new Set(Object.keys(record.responseHeaders).map((h) => h.toLowerCase()))
  return SECURITY_HEADERS.filter((h) => !have.has(h))
}

function classifyVulnerablePhase(get: (id: string) => EvidenceRecord | undefined) {
  const verdicts: EvidenceManifest["verdicts"] = {}
  const rationale = (v: EvidenceVerdict, r: string) => ({ verdict: v, rationale: r })

  // H1 — BOLA
  const poc = get("E1-02-poc-cross-account")
  if (!poc) {
    verdicts.H1 = rationale("inconclusivo", "Caso E1-02 não executado.")
  } else if (poc.status === 200 && poc.body.includes("bolaFlag")) {
    verdicts.H1 = rationale(
      "vulneravel",
      `E1-02 retornou 200 com o corpo de bob@corp.lab e bolaFlag (esperado 403). E1-01 e E1-03 confirmam que o endpoint funciona e que a variável é o token.`,
    )
  } else if (poc.status === 403) {
    verdicts.H1 = rationale("seguro", `E1-02 retornou 403 — titularidade aplicada.`)
  } else {
    verdicts.H1 = rationale("inconclusivo", `E1-02 retornou HTTP ${poc.status}, fora do critério (200 com flag / 403).`)
  }

  // H2 — JWT alg:none
  const jwt = get("E3-03-poc-alg-none")
  if (!jwt) {
    verdicts.H2 = rationale("inconclusivo", "Caso E3-03 não executado.")
  } else if (jwt.status === 200 && jwt.body.includes("JWT_ALG_NONE_ACCEPTED")) {
    verdicts.H2 = rationale(
      "vulneravel",
      `E3-03 retornou 200 com flag LAB{JWT_ALG_NONE_ACCEPTED} (esperado 401). E3-01/E3-02 provam que o endpoint recusa ausência de token e token sem role=admin.`,
    )
  } else if (jwt.status === 401 || jwt.status === 403) {
    verdicts.H2 = rationale("seguro", `E3-03 retornou ${jwt.status} — assinatura verificada.`)
  } else {
    verdicts.H2 = rationale("inconclusivo", `E3-03 retornou HTTP ${jwt.status}, fora do critério.`)
  }

  // H3 — erro SQL
  const sql = get("E4-02-poc-single-quote")
  const benign = get("E4-01-benign-query")
  if (!sql || !benign) {
    verdicts.H3 = rationale("inconclusivo", "Casos E4-01/E4-02 não executados.")
  } else if (sql.status === 500 && /SQLITE_ERROR|syntax error/i.test(sql.body)) {
    verdicts.H3 = rationale(
      "vulneravel",
      `E4-02 retornou 500 ecoando SQLITE_ERROR e a estrutura da consulta (esperado erro genérico). E4-01 confirma 200 com q benigno.`,
    )
  } else if (sql.status === 200 || sql.status === 400) {
    verdicts.H3 = rationale("seguro", `E4-02 retornou ${sql.status} sem eco de erro do SGBD.`)
  } else {
    verdicts.H3 = rationale("inconclusivo", `E4-02 retornou HTTP ${sql.status}, fora do critério.`)
  }

  // H4 — headers
  const hdr = get("E5-01-header-baseline")
  if (!hdr) {
    verdicts.H4 = rationale("inconclusivo", "Caso E5-01 não executado.")
  } else {
    const missing = missingSecurityHeaders(hdr)
    verdicts.H4 = missing.length
      ? rationale("vulneravel", `E5-01: ausentes → ${missing.join(", ")}.`)
      : rationale("seguro", "E5-01: os 4 headers de segurança presentes.")
  }

  // H1/H2/H3/H4 após remediação
  const rem = (id: string) => get(`E6-${id}`)
  const checks: Array<[string, string, (r: EvidenceRecord) => boolean, string]> = [
    ["H1", "01-bola", (r) => r.status === 403, "403"],
    ["H2", "02-alg-none", (r) => r.status === 401 || r.status === 403, "401/403"],
    [
      "H3",
      "03-sql-error",
      (r) => r.status === 200 && !/SQLITE_ERROR|syntax error/i.test(r.body),
      "200 sem SQLITE_ERROR",
    ],
    ["H4", "04-headers", (r) => missingSecurityHeaders(r).length === 0, "os 4 headers"],
  ]
  for (const [h, id, ok, expected] of checks) {
    const r = rem(id)
    if (!r) {
      verdicts[`${h}@remediado`] = rationale("inconclusivo", `Caso E6-${id} não executado.`)
    } else {
      verdicts[`${h}@remediado`] = ok(r)
        ? rationale("remediado", `E6-${id} → HTTP ${r.status}, critério "${expected}" atendido.`)
        : rationale("vulneravel", `E6-${id} → HTTP ${r.status}, mas o critério "${expected}" NÃO foi atendido (lacuna de remediação).`)
    }
  }

  return verdicts
}

function renderReport(manifest: EvidenceManifest, seal: string): string {
  const lines: string[] = []
  lines.push(`# Evidência — ${manifest.labId} (suíte ${manifest.suite})`)
  lines.push("")
  lines.push(`- **Gerado em**: ${manifest.generatedAt}`)
  lines.push(`- **Alvo**: ${manifest.baseUrl}`)
  lines.push(`- **Ferramenta**: ${manifest.tool}`)
  lines.push(`- **Requisições arquivadas**: ${manifest.cases.length}`)
  lines.push(`- **Selo do lote (SHA-256 do manifest.json)**: \`${seal}\``)
  lines.push("")
  lines.push("## Vereditos")
  lines.push("")
  lines.push("| Hipótese | Veredito | Critério |")
  lines.push("| --- | --- | --- |")
  const label: Record<EvidenceVerdict, string> = {
    vulneravel: "🔴 VULNERÁVEL",
    seguro: "🟢 SEGURO",
    remediado: "✅ REMEDIADO",
    inconclusivo: "⚪ INCONCLUSIVO",
  }
  for (const [h, v] of Object.entries(manifest.verdicts)) {
    lines.push(`| ${h} | ${label[v.verdict]} | ${v.rationale.replace(/\|/g, "\\|")} |`)
  }
  lines.push("")
  lines.push("## Arquivos")
  lines.push("")
  lines.push("| Arquivo | Bytes | SHA-256 |")
  lines.push("| --- | --- | --- |")
  for (const f of manifest.files) {
    lines.push(`| \`${f.path}\` | ${f.bytes} | \`${f.sha256}\` |`)
  }
  lines.push("")
  lines.push(
    "> O `manifest.json` é o índice do lote; `SEAL.txt` guarda o SHA-256 dele. Alterar qualquer `.txt` quebra o par `sha256` correspondente em `manifest.json`.",
  )
  lines.push("")
  return lines.join("\n")
}

/**
 * Executa E1–E7 (E1–E5 vulnerável, E6 remediado, E7 restaurado), grava tudo em disco
 * e devolve o manifesto. O `server-config.json` volta ao estado original ao final.
 */
export async function runBolaEvidenceSuite(opts: EvidenceSuiteOptions): Promise<EvidenceSuiteResult> {
  const { baseUrl, outDir, workspaceRoot } = opts
  const now = opts.now ?? (() => new Date().toISOString())
  rmSync(outDir, { recursive: true, force: true })
  mkdirSync(outDir, { recursive: true })

  const configAtStart = readConfig(workspaceRoot)
  const recorder = new LabEvidenceRecorder(baseUrl, outDir)
  const curl = process.platform === "win32" ? "curl.exe" : "curl"

  for (const c of buildBolaEvidenceCases(baseUrl, curl)) await recorder.capture(c)

  // --- Fase G: remediação (todos os controles ligados) ---
  writeConfig(workspaceRoot, REMEDIATED_CONFIG)
  for (const c of buildRemediationCases(baseUrl, "remediado", curl)) await recorder.capture(c)

  // --- Restauração: prova que o lab voltou ao estado vulnerável de treino ---
  writeConfig(workspaceRoot, VULNERABLE_CONFIG)
  for (const c of buildRemediationCases(baseUrl, "restaurado", curl)) await recorder.capture(c)

  const configAtEnd = readConfig(workspaceRoot)

  const files = readdirSync(outDir)
    .filter((f) => f.endsWith(".txt"))
    .sort()
    .map((f) => {
      const full = path.join(outDir, f)
      const raw = readFileSync(full)
      return { path: f, sha256: sha256Hex(raw), bytes: raw.byteLength }
    })

  const manifest: EvidenceManifest = {
    schema: "cyberlab.lab.evidence/1",
    labId: "lab-owasp-api-bola",
    baseUrl,
    suite: "E1-E7",
    tool: `CyberLab OS ${process.platform}/${process.arch} — bun ${process.versions.bun ?? "?"}`,
    generatedAt: now(),
    configAtStart,
    configAtEnd,
    cases: recorder.all(),
    verdicts: classifyVulnerablePhase((id) => recorder.get(id)),
    files,
    seal: null,
  }

  // O manifesto é gravado COM `seal: null` e nunca reescrito: assim o operador pode
  // conferir `sha256sum manifest.json` e comparar direto com SEAL.txt. Se o selo
  // fizesse parte do próprio arquivo, o hash nunca bateria (problema do ovo e da galinha).
  const manifestPath = path.join(outDir, "manifest.json")
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8")
  const seal = sha256Hex(readFileSync(manifestPath))

  const sealPath = path.join(outDir, "SEAL.txt")
  writeFileSync(
    sealPath,
    [
      `selo_do_lote : ${seal}`,
      `algoritmo    : SHA-256(manifest.json)`,
      `gerado_em    : ${manifest.generatedAt}`,
      `lab          : ${manifest.labId} @ ${baseUrl}`,
      `requisicoes  : ${manifest.cases.length}`,
      "",
      "Para verificar:",
      `  sha256sum manifest.json      # Linux/WSL2`,
      `  (Get-FileHash .\\manifest.json -Algorithm SHA256).Hash.ToLower()   # PowerShell`,
      "",
    ].join("\n"),
    "utf8",
  )

  const reportPath = path.join(outDir, "REPORT.md")
  writeFileSync(reportPath, renderReport(manifest, seal), "utf8")

  return { manifest, seal, manifestPath, sealPath, reportPath, suiteDir: outDir }
}
