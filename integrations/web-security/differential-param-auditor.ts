import crypto from "node:crypto"
import { Schema } from "effect"
import {
  capOutputBytes,
  normalizeRawOutputDraft,
  redactSensitiveContent,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const WEB_PARAM_AUDIT_INPUT_SCHEMA_ID = "cyberlab.web-param-audit.input.v1"
export const WEB_PARAM_AUDIT_OUTPUT_SCHEMA_ID = "cyberlab.web-param-audit.output.v1"

export const WebParamAuditInputSchema = Schema.Struct({
  url: Schema.String.check(
    Schema.isMinLength(8),
    Schema.isMaxLength(2048),
    Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
  ),
  method: Schema.optionalKey(Schema.Literals(["GET", "POST"])),
  headers: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
  parameterNames: Schema.optionalKey(
    Schema.Array(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(64))).check(Schema.isMaxLength(20)),
  ),
  checkReflectionContext: Schema.optionalKey(Schema.Boolean),
  checkErrorLeakage: Schema.optionalKey(Schema.Boolean),
  checkRedirectHygiene: Schema.optionalKey(Schema.Boolean),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(250), Schema.isLessThanOrEqualTo(12_000)),
  ),
})

export type WebParamAuditInput = typeof WebParamAuditInputSchema.Type

export const WebParamAuditCapability: CapabilityDefinition = {
  id: "web-assessment.param-audit",
  version: "1.0.0",
  title: "Non-Destructive Differential Parameter & Reflection Auditor",
  description:
    "Audits URL and body parameters using benign alphanumeric canary tokens and safe boundary types to detect unencoded reflection contexts, framework/database stack-trace leaks, and unvalidated redirect parameters without destructive payloads.",
  inputSchemaId: WEB_PARAM_AUDIT_INPUT_SCHEMA_ID,
  outputSchemaId: WEB_PARAM_AUDIT_OUTPUT_SCHEMA_ID,
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["url_origin"],
  executorId: "differential-param-auditor-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

const ERROR_LEAK_SIGNATURES: ReadonlyArray<{ category: string; regex: RegExp }> = [
  { category: "SQL Driver Exception", regex: /\b(SQLSTATE\[|PDOException|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBCDriver|sqlite3\.OperationalError|Unclosed quotation mark)\b/i },
  { category: "NoSQL / ORM Exception", regex: /\b(MongoServerError|CastError: Cast to ObjectId|PrismaClientKnownRequestError|SequelizeDatabaseError)\b/i },
  { category: "Template Engine Error", regex: /\b(jinja2\.exceptions|TemplateSyntaxError|Mustache\.render|Handlebars\.Exception|Twig\\Error)\b/i },
  { category: "Application Stack Trace", regex: /\b(Traceback \(most recent call last\)|at Object\.<anonymous>|java\.lang\.NullPointerException|System\.NullReferenceException)\b/i },
]

const REDIRECT_PARAM_CANDIDATES = new Set([
  "next",
  "redirect",
  "redirect_uri",
  "redirect_url",
  "return",
  "return_to",
  "returnurl",
  "url",
  "dest",
  "continue",
])

export class DifferentialParamAuditorExecutor implements CyberLabExecutor {
  readonly id = "differential-param-auditor-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      Schema.decodeUnknownSync(WebParamAuditInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, context: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(WebParamAuditInputSchema)(req.input)
    const baseUrl = new URL(parsed.url)
    const method = parsed.method ?? "GET"
    const timeoutMs = parsed.timeoutMs ?? 6_000
    const checkReflection = parsed.checkReflectionContext ?? true
    const checkErrors = parsed.checkErrorLeakage ?? true
    const checkRedirects = parsed.checkRedirectHygiene ?? true

    const paramSet = new Set<string>()
    baseUrl.searchParams.forEach((_v, k) => paramSet.add(k))
    for (const p of parsed.parameterNames ?? []) {
      if (p.trim()) paramSet.add(p.trim())
    }
    if (paramSet.size === 0) {
      paramSet.add("q")
      paramSet.add("id")
      paramSet.add("next")
    }
    const targetParams = [...paramSet].slice(0, 12)

    const sendProbe = async (probeUrl: URL, bodyParams?: URLSearchParams) => {
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort(), timeoutMs)
      try {
        const headers: Record<string, string> = { ...(parsed.headers ?? {}) }
        if (method === "POST" && bodyParams) {
          headers["Content-Type"] = "application/x-www-form-urlencoded"
        }
        const t0 = performance.now()
        const res = await fetch(probeUrl.toString(), {
          method,
          headers,
          ...(method === "POST" && bodyParams ? { body: bodyParams.toString() } : {}),
          redirect: "manual",
          signal: ctrl.signal,
        })
        const text = capOutputBytes(await res.text(), 32_768).text
        return {
          status: res.status,
          elapsedMs: Math.round(performance.now() - t0),
          contentType: res.headers.get("content-type") ?? "",
          csp: res.headers.get("content-security-policy") ?? "",
          nosniff: res.headers.get("x-content-type-options") ?? "",
          location: res.headers.get("location") ?? "",
          body: text,
        }
      } finally {
        clearTimeout(timer)
      }
    }

    const baseline = await sendProbe(baseUrl)
    const observations: Array<{
      parameter: string
      check: string
      severityHint: "info" | "low" | "medium" | "high"
      summary: string
      statusCode: number
      lengthDelta: number
    }> = []

    for (const param of targetParams) {
      if (context.signal.aborted) break
      const canary = `clb${crypto.randomBytes(4).toString("hex")}`

      if (checkReflection) {
        const u = new URL(baseUrl.toString())
        const form = new URLSearchParams()
        if (method === "GET") u.searchParams.set(param, canary)
        else form.set(param, canary)

        const resp = await sendProbe(u, method === "POST" ? form : undefined)
        if (resp.body.includes(canary)) {
          const isHtml = /text\/html/i.test(resp.contentType)
          const missingCsp = isHtml && !resp.csp
          observations.push({
            parameter: param,
            check: "canary_reflection",
            severityHint: isHtml ? (missingCsp ? "medium" : "low") : "info",
            summary: isHtml
              ? `Canário alfanumérico refletido diretamente em resposta HTML (${missingCsp ? "sem header CSP" : "com CSP presente"}) — revisar codificação de saída contextual.`
              : `Valor do parâmetro refletido em resposta ${resp.contentType || "não-HTML"}.`,
            statusCode: resp.status,
            lengthDelta: resp.body.length - baseline.body.length,
          })
        }
      }

      if (checkErrors) {
        const u = new URL(baseUrl.toString())
        const form = new URLSearchParams()
        if (method === "GET") u.searchParams.set(`${param}[]`, "0")
        else form.set(`${param}[]`, "0")

        const resp = await sendProbe(u, method === "POST" ? form : undefined)
        for (const sig of ERROR_LEAK_SIGNATURES) {
          if (sig.regex.test(resp.body) && !sig.regex.test(baseline.body)) {
            observations.push({
              parameter: param,
              check: "error_stack_leakage",
              severityHint: "medium",
              summary: `Exposição de erro interno (${sig.category}) ao enviar variação estrutural de tipo (HTTP ${resp.status}).`,
              statusCode: resp.status,
              lengthDelta: resp.body.length - baseline.body.length,
            })
          }
        }
        if (resp.status >= 500 && baseline.status < 500) {
          observations.push({
            parameter: param,
            check: "unhandled_5xx_differential",
            severityHint: "low",
            summary: `Transição de HTTP ${baseline.status} para HTTP ${resp.status} sob variação benigna de tipo — validar tratamento de exceções no parâmetro.`,
            statusCode: resp.status,
            lengthDelta: resp.body.length - baseline.body.length,
          })
        }
      }

      if (checkRedirects && REDIRECT_PARAM_CANDIDATES.has(param.toLowerCase())) {
        const inertRedirectCheck = "//cyberlab-redirect-check.invalid/path"
        const u = new URL(baseUrl.toString())
        u.searchParams.set(param, inertRedirectCheck)
        const resp = await sendProbe(u)
        if (
          resp.status >= 300 &&
          resp.status < 400 &&
          resp.location.includes("cyberlab-redirect-check.invalid")
        ) {
          observations.push({
            parameter: param,
            check: "unvalidated_redirect_target",
            severityHint: "medium",
            summary: `Header Location refletiu destino externo relativo ao protocolo (${resp.location}) com HTTP ${resp.status} — restringir redirecionamentos a caminhos internos permitidos.`,
            statusCode: resp.status,
            lengthDelta: resp.body.length - baseline.body.length,
          })
        }
      }
    }

    const report = {
      url: baseUrl.toString(),
      method,
      baselineStatus: baseline.status,
      baselineContentType: baseline.contentType,
      auditedParameters: targetParams,
      observationsCount: observations.length,
      observations,
    }

    const redacted = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await context.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "http_exchange",
        title: `Differential Parameter Audit ${method} ${baseUrl.host}${baseUrl.pathname}`,
        rawText: redacted.text,
        mediaType: "application/json",
        toolId: "cyberlab-param-auditor",
        toolVersion: this.version,
        executorId: this.id,
        executionId: context.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["param-audit", "non-destructive"],
      }),
      redactionApplied: redacted.redacted || true,
    })

    return {
      status: context.signal.aborted ? "cancelled" : "succeeded",
      evidenceIds: [evId],
      summary: `Auditoria diferencial não-destrutiva avaliou ${targetParams.length} parâmetro(s) em ${baseUrl.host}${baseUrl.pathname}: ${observations.length} observação(ões) registrada(s).`,
      exitCode: 0,
    }
  }
}
