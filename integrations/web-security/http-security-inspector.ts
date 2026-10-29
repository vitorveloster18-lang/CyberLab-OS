import { Schema } from "effect"
import {
  EngagementRuntime,
  capOutputBytes,
  normalizeRawOutputDraft,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const HTTP_SECURITY_INSPECTOR_INPUT_SCHEMA_ID = "cyberlab.http-security-inspector.input.v1"
export const HTTP_SECURITY_INSPECTOR_OUTPUT_SCHEMA_ID = "cyberlab.http-security-inspector.output.v1"

export const HttpSecurityInspectorInputSchema = Schema.Struct({
  url: Schema.String.check(
    Schema.isMinLength(8),
    Schema.isMaxLength(2048),
    Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
  ),
  method: Schema.optionalKey(Schema.Literals(["HEAD", "GET"])),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(100), Schema.isLessThanOrEqualTo(15_000)),
  ),
  maxBodyBytes: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(256), Schema.isLessThanOrEqualTo(65_536)),
  ),
})

export type HttpSecurityInspectorInput = typeof HttpSecurityInspectorInputSchema.Type

export const HttpSecurityInspectorCapability: CapabilityDefinition = {
  id: "web-assessment.http-security-headers",
  version: "1.0.0",
  title: "Passive HTTP Security Headers, Cookie & CORS Inspector",
  description:
    "Performs a single non-destructive HEAD or GET request against an in-scope HTTP/HTTPS endpoint, records the raw HTTP exchange with SHA-256 provenance, and evaluates defensive response headers, Set-Cookie attributes, and CORS policy.",
  inputSchemaId: HTTP_SECURITY_INSPECTOR_INPUT_SCHEMA_ID,
  outputSchemaId: HTTP_SECURITY_INSPECTOR_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-passive"],
  requiredScope: ["url_origin"],
  executorId: "http-security-inspector-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export interface HeaderObservation {
  code: string
  header: string
  status: "present" | "missing" | "misconfigured" | "informational"
  detail: string
}

function analyzeSecurityHeaders(urlObj: URL, headers: Headers, setCookies: string[]): HeaderObservation[] {
  const observations: HeaderObservation[] = []
  const required = [
    { code: "HDR-CSP", name: "content-security-policy", label: "Content-Security-Policy" },
    { code: "HDR-XCTO", name: "x-content-type-options", label: "X-Content-Type-Options" },
    { code: "HDR-XFO", name: "x-frame-options", label: "X-Frame-Options" },
    { code: "HDR-RP", name: "referrer-policy", label: "Referrer-Policy" },
    { code: "HDR-PP", name: "permissions-policy", label: "Permissions-Policy" },
    { code: "HDR-COOP", name: "cross-origin-opener-policy", label: "Cross-Origin-Opener-Policy" },
  ]

  if (urlObj.protocol === "https:") {
    const hsts = headers.get("strict-transport-security")
    observations.push(
      hsts
        ? { code: "HDR-HSTS", header: "Strict-Transport-Security", status: "present", detail: hsts }
        : {
            code: "HDR-HSTS",
            header: "Strict-Transport-Security",
            status: "missing",
            detail: "HTTPS endpoint did not emit Strict-Transport-Security header",
          },
    )
  }

  for (const h of required) {
    const val = headers.get(h.name)
    if (!val) {
      observations.push({
        code: h.code,
        header: h.label,
        status: "missing",
        detail: `${h.label} header is absent`,
      })
    } else if (h.name === "x-content-type-options" && val.trim().toLowerCase() !== "nosniff") {
      observations.push({
        code: h.code,
        header: h.label,
        status: "misconfigured",
        detail: `Expected "nosniff", observed "${val}"`,
      })
    } else {
      observations.push({
        code: h.code,
        header: h.label,
        status: "present",
        detail: val,
      })
    }
  }

  const acao = headers.get("access-control-allow-origin")
  const acac = headers.get("access-control-allow-credentials")
  if (acao === "*" && acac?.toLowerCase() === "true") {
    observations.push({
      code: "HDR-CORS-WILDCARD-CREDS",
      header: "Access-Control-Allow-Origin",
      status: "misconfigured",
      detail: "Wildcard Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials: true",
    })
  }

  for (const bannerHeader of ["server", "x-powered-by"]) {
    const banner = headers.get(bannerHeader)
    if (banner && /\d+\.\d+/.test(banner)) {
      observations.push({
        code: "HDR-VERBOSE-BANNER",
        header: bannerHeader,
        status: "informational",
        detail: `Version-bearing banner observed: ${banner}`,
      })
    }
  }

  for (const rawCookie of setCookies) {
    const cookieName = rawCookie.split("=")[0]?.trim() || "cookie"
    const lower = rawCookie.toLowerCase()
    const missingFlags: string[] = []
    if (!lower.includes("httponly")) missingFlags.push("HttpOnly")
    if (urlObj.protocol === "https:" && !lower.includes("secure")) missingFlags.push("Secure")
    if (!lower.includes("samesite=")) missingFlags.push("SameSite")
    if (missingFlags.length > 0) {
      observations.push({
        code: "COOKIE-FLAGS",
        header: "Set-Cookie",
        status: "misconfigured",
        detail: `Cookie "${cookieName}" missing defensive flags: ${missingFlags.join(", ")}`,
      })
    }
  }

  return observations
}

function redactCookieValue(rawCookie: string): string {
  const eq = rawCookie.indexOf("=")
  if (eq === -1) return rawCookie
  const semi = rawCookie.indexOf(";", eq)
  const name = rawCookie.slice(0, eq)
  const attrs = semi === -1 ? "" : rawCookie.slice(semi)
  return `${name}=[REDACTED:COOKIE_VALUE]${attrs}`
}

export class WebHttpSecurityInspectorExecutor implements CyberLabExecutor {
  readonly id = "http-security-inspector-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    return { available: typeof fetch === "function", version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(HttpSecurityInspectorInputSchema)(input)
      const parsed = new URL(decoded.url)
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return { valid: false, errors: [`Unsupported URL scheme "${parsed.protocol}"`] }
      }
      if (parsed.username || parsed.password) {
        return { valid: false, errors: ["Embedded URL credentials are prohibited"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(HttpSecurityInspectorInputSchema)(execInput.input)
    const parsedUrl = new URL(params.url)

    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      throw new Error(`Unsupported protocol "${parsedUrl.protocol}" — only http: and https: are allowed`)
    }
    if (parsedUrl.username || parsedUrl.password) {
      throw new Error("Embedded credentials in target URL are prohibited")
    }

    const method = params.method ?? "GET"
    const maxBodyBytes = params.maxBodyBytes ?? 8_192
    const timeoutMs = params.timeoutMs ?? 5_000

    const requestAbort = new AbortController()
    const timer = setTimeout(() => requestAbort.abort("HTTP inspector timeout"), timeoutMs)
    const onParentAbort = () => requestAbort.abort("Parent execution aborted")
    ctx.signal.addEventListener("abort", onParentAbort, { once: true })

    try {
      await ctx.log("info", `Performing passive ${method} inspection against ${parsedUrl.origin}${parsedUrl.pathname}`)
      await EngagementRuntime.acquireRateSlot(ctx.projectId)
      const reqHeaders = EngagementRuntime.applyHeaders(ctx.projectId, {
        "User-Agent": "CyberLab-OS-Passive-Inspector/4.0",
        Accept: "text/html,application/json,*/*;q=0.8",
      })
      const startedAt = Date.now()
      const response = await fetch(parsedUrl.toString(), {
        method,
        redirect: "manual",
        headers: reqHeaders,
        signal: requestAbort.signal,
      })
      const elapsedMs = Date.now() - startedAt
      EngagementRuntime.recordTraffic({
        projectId: ctx.projectId,
        sourceTool: "http-inspector",
        method,
        url: parsedUrl.toString(),
        host: parsedUrl.host,
        statusCode: response.status,
        elapsedMs,
        responseBytes: Number(response.headers.get("content-length") ?? 0),
      })

      const setCookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : []

      const headerLines: string[] = []
      response.headers.forEach((value, key) => {
        if (key.toLowerCase() === "set-cookie") return
        headerLines.push(`${key}: ${value}`)
      })
      for (const cookie of setCookies) {
        headerLines.push(`set-cookie: ${redactCookieValue(cookie)}`)
      }

      let bodyPreview = ""
      if (method === "GET" && response.body) {
        const rawBodyText = await response.text()
        bodyPreview = capOutputBytes(rawBodyText, maxBodyBytes).text
      }

      const rawHttpText = [
        `${method} ${parsedUrl.pathname}${parsedUrl.search} -> HTTP ${response.status} ${response.statusText} (${elapsedMs}ms)`,
        ...headerLines,
        "",
        bodyPreview,
      ].join("\n")

      const observations = analyzeSecurityHeaders(parsedUrl, response.headers, setCookies)
      const missingOrMisconfigured = observations.filter(
        (o) => o.status === "missing" || o.status === "misconfigured",
      )

      const rawExchangeEvidenceId = await ctx.emitEvidence({
        kind: "http_exchange",
        title: `Passive HTTP ${method} exchange (${parsedUrl.origin}${parsedUrl.pathname})`,
        source: {
          toolId: "cyberlab-http-security-inspector",
          toolVersion: this.version,
          executorId: this.id,
          executionId: ctx.executionId,
        },
        content: {
          mediaType: "text/plain; charset=utf-8",
          inlineText: rawHttpText,
        },
        observedAt: new Date().toISOString(),
        labels: ["passive", "http-headers"],
        redactionApplied: setCookies.length > 0,
      })

      const reportPayload = {
        targetUrl: parsedUrl.toString(),
        method,
        statusCode: response.status,
        elapsedMs,
        observationCount: observations.length,
        issueCount: missingOrMisconfigured.length,
        observations,
      }

      const jsonEvidenceId = await ctx.emitEvidence(
        normalizeRawOutputDraft({
          kind: "json",
          title: `HTTP Security Header Assessment (${parsedUrl.host})`,
          rawText: JSON.stringify(reportPayload, null, 2),
          mediaType: "application/json",
          toolId: "cyberlab-http-security-inspector",
          toolVersion: this.version,
          executorId: this.id,
          executionId: ctx.executionId,
          maxOutputBytes: 512 * 1024,
          labels: ["passive", "security-headers"],
        }),
      )

      return {
        status: "succeeded",
        evidenceIds: [rawExchangeEvidenceId, jsonEvidenceId],
        summary: `Inspected HTTP ${response.status} from ${parsedUrl.origin}; ${missingOrMisconfigured.length} defensive header/cookie issue(s) observed.`,
        exitCode: 0,
      }
    } finally {
      clearTimeout(timer)
      ctx.signal.removeEventListener("abort", onParentAbort)
    }
  }
}
