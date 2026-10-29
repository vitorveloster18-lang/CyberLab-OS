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

export const HTTP_REPEATER_INPUT_SCHEMA_ID = "cyberlab.http-repeater.input.v1"
export const HTTP_REPEATER_OUTPUT_SCHEMA_ID = "cyberlab.http-repeater.output.v1"

const HttpMethodSchema = Schema.Literals(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])

export const HttpRepeaterInputSchema = Schema.Struct({
  url: Schema.String.check(
    Schema.isMinLength(8),
    Schema.isMaxLength(2048),
    Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
  ),
  method: Schema.optionalKey(HttpMethodSchema),
  headers: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
  body: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(262_144))),
  rawRequest: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(262_144))),
  followRedirects: Schema.optionalKey(Schema.Boolean),
  baselineUrl: Schema.optionalKey(
    Schema.String.check(
      Schema.isMinLength(8),
      Schema.isMaxLength(2048),
      Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
    ),
  ),
  baselineHeaders: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
  baselineBody: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(262_144))),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(100), Schema.isLessThanOrEqualTo(30_000)),
  ),
  maxBodyBytes: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(256), Schema.isLessThanOrEqualTo(262_144)),
  ),
})

export type HttpRepeaterInput = typeof HttpRepeaterInputSchema.Type

export const HttpRepeaterCapability: CapabilityDefinition = {
  id: "web-assessment.http-repeater",
  version: "2.0.0",
  title: "Native HTTP Repeater & Response Comparer (Structured + Raw HTTP / Burp & OpenTRAP Style)",
  description:
    "Replays structured or raw HTTP/1.1 requests against authorized in-scope endpoints (with optional redirect following, engagement X-Bug-Bounty headers, RPS rate-limiting, and A/B baseline comparison), redacting sensitive headers in persisted SHA-256 evidence.",
  inputSchemaId: HTTP_REPEATER_INPUT_SCHEMA_ID,
  outputSchemaId: HTTP_REPEATER_OUTPUT_SCHEMA_ID,
  risk: "low",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["url_origin"],
  executorId: "http-repeater-comparer-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
])

function sanitizeHeadersForEvidence(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_HEADER_NAMES.has(k.toLowerCase()) ? "[REDACTED:SENSITIVE_HEADER]" : v
  }
  return out
}

export function parseRawHttpRequestText(
  rawText: string,
  baseUrlString: string,
): { method: string; url: string; headers: Record<string, string>; body: string } {
  const baseUrl = new URL(baseUrlString)
  const sepMatch = /\r?\n\r?\n/.exec(rawText)
  const headPart = sepMatch ? rawText.slice(0, sepMatch.index) : rawText
  const body = sepMatch ? rawText.slice(sepMatch.index + sepMatch[0].length) : ""

  const lines = headPart.split(/\r?\n/)
  const reqLine = (lines[0] ?? "").trim()
  const m = /^([A-Z]+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/i.exec(reqLine)
  if (!m) {
    throw new Error(`Invalid raw HTTP request line: "${reqLine.slice(0, 80)}"`)
  }
  const method = m[1]!.toUpperCase()
  const reqTarget = m[2]!

  const headers: Record<string, string> = {}
  let hostHeader: string | null = null
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!
    const colon = line.indexOf(":")
    if (colon <= 0) continue
    const k = line.slice(0, colon).trim()
    const v = line.slice(colon + 1).trim()
    if (k.toLowerCase() === "host") {
      hostHeader = v
    } else if (k.toLowerCase() !== "content-length") {
      headers[k] = v
    }
  }

  let resolvedUrl: URL
  if (/^https?:\/\//i.test(reqTarget)) {
    resolvedUrl = new URL(reqTarget)
  } else {
    const authority = hostHeader || baseUrl.host
    const pathPart = reqTarget.startsWith("/") ? reqTarget : `/${reqTarget}`
    resolvedUrl = new URL(`${baseUrl.protocol}//${authority}${pathPart}`)
  }

  return {
    method,
    url: resolvedUrl.toString(),
    headers,
    body,
  }
}

interface CapturedHttpExchange {
  url: string
  finalUrl: string
  redirectChain: string[]
  method: string
  statusCode: number
  statusText: string
  elapsedMs: number
  headers: Record<string, string>
  bodyText: string
  bodyBytes: number
}

async function performSingleExchange(params: {
  projectId: string
  url: string
  method: string
  headers: Record<string, string>
  body?: string
  followRedirects: boolean
  maxBodyBytes: number
  signal: AbortSignal
}): Promise<CapturedHttpExchange> {
  const initialParsed = new URL(params.url)
  if (initialParsed.protocol !== "http:" && initialParsed.protocol !== "https:") {
    throw new Error(`Unsupported protocol "${initialParsed.protocol}"`)
  }
  if (initialParsed.username || initialParsed.password) {
    throw new Error("Embedded URL credentials are prohibited")
  }

  const withEngagement = EngagementRuntime.applyHeaders(params.projectId, {
    "User-Agent": "CyberLab-OS-Repeater/4.0",
    ...params.headers,
  })

  await EngagementRuntime.acquireRateSlot(params.projectId)

  const startedAt = Date.now()
  let currentUrl = initialParsed
  let currentMethod = params.method
  let currentBody = params.body
  const redirectChain: string[] = []
  let res: Response | null = null

  for (let hop = 0; hop <= (params.followRedirects ? 5 : 0); hop++) {
    if (currentUrl.hostname === "169.254.169.254" || currentUrl.hostname === "metadata.google.internal") {
      throw new Error("Blocked redirect to cloud metadata SSRF endpoint")
    }
    res = await fetch(currentUrl.toString(), {
      method: currentMethod,
      headers: new Headers(withEngagement),
      ...(currentBody !== undefined && currentMethod !== "GET" && currentMethod !== "HEAD"
        ? { body: currentBody }
        : {}),
      redirect: "manual",
      signal: params.signal,
    })

    if (
      params.followRedirects &&
      res.status >= 300 &&
      res.status < 400 &&
      res.headers.get("location") &&
      hop < 5
    ) {
      const nextUrl = new URL(res.headers.get("location")!, currentUrl)
      if (nextUrl.origin !== currentUrl.origin) {
        // Stop auto-following cross-origin redirects so session headers never leak out of origin
        break
      }
      redirectChain.push(`${res.status} -> ${nextUrl.toString()}`)
      if (res.status === 301 || res.status === 302 || res.status === 303) {
        if (currentMethod !== "GET" && currentMethod !== "HEAD") {
          currentMethod = "GET"
          currentBody = undefined
        }
      }
      currentUrl = nextUrl
      continue
    }
    break
  }

  if (!res) {
    throw new Error("Repeater request produced no response")
  }

  const elapsedMs = Date.now() - startedAt
  const resHeaders: Record<string, string> = {}
  res.headers.forEach((value, key) => {
    resHeaders[key] = SENSITIVE_HEADER_NAMES.has(key.toLowerCase()) ? "[REDACTED:SENSITIVE_HEADER]" : value
  })

  const rawBuf = currentMethod === "HEAD" ? new Uint8Array(0) : new Uint8Array(await res.arrayBuffer())
  const fullText = new TextDecoder("utf-8", { fatal: false }).decode(rawBuf)
  const capped = capOutputBytes(fullText, params.maxBodyBytes)

  EngagementRuntime.recordTraffic({
    projectId: params.projectId,
    sourceTool: "http-repeater",
    method: params.method,
    url: initialParsed.toString(),
    host: initialParsed.host,
    statusCode: res.status,
    elapsedMs,
    responseBytes: rawBuf.byteLength,
  })

  return {
    url: initialParsed.toString(),
    finalUrl: currentUrl.toString(),
    redirectChain,
    method: params.method,
    statusCode: res.status,
    statusText: res.statusText,
    elapsedMs,
    headers: resHeaders,
    bodyText: capped.text,
    bodyBytes: rawBuf.byteLength,
  }
}

function compareExchanges(primary: CapturedHttpExchange, baseline: CapturedHttpExchange) {
  const primaryHeaderKeys = new Set(Object.keys(primary.headers))
  const baselineHeaderKeys = new Set(Object.keys(baseline.headers))

  const addedHeaders = [...primaryHeaderKeys].filter((k) => !baselineHeaderKeys.has(k))
  const removedHeaders = [...baselineHeaderKeys].filter((k) => !primaryHeaderKeys.has(k))
  const changedHeaders = [...primaryHeaderKeys].filter(
    (k) => baselineHeaderKeys.has(k) && primary.headers[k] !== baseline.headers[k],
  )

  const pLines = primary.bodyText.split(/\r?\n/)
  const bLineList = baseline.bodyText.split(/\r?\n/)
  const bLines = new Set(bLineList)
  const pLineSet = new Set(pLines)
  const uniquePrimaryLines = pLines.filter((l) => l.length > 0 && !bLines.has(l)).slice(0, 30)
  const uniqueBaselineLines = bLineList.filter((l) => l.length > 0 && !pLineSet.has(l)).slice(0, 30)

  const pWords = primary.bodyText.trim().split(/\s+/).filter(Boolean).length
  const bWords = baseline.bodyText.trim().split(/\s+/).filter(Boolean).length

  return {
    statusChanged: primary.statusCode !== baseline.statusCode,
    primaryStatus: primary.statusCode,
    baselineStatus: baseline.statusCode,
    byteLengthDelta: primary.bodyBytes - baseline.bodyBytes,
    wordCountDelta: pWords - bWords,
    lineCountDelta: pLines.length - bLineList.length,
    elapsedMsDelta: primary.elapsedMs - baseline.elapsedMs,
    addedHeaders,
    removedHeaders,
    changedHeaders,
    sampleUniqueLinesInPrimary: uniquePrimaryLines,
    sampleUniqueLinesInBaseline: uniqueBaselineLines,
  }
}

export class HttpRepeaterComparerExecutor implements CyberLabExecutor {
  readonly id = "http-repeater-comparer-executor"
  readonly version = "2.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string }> {
    return { available: typeof fetch === "function", version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(HttpRepeaterInputSchema)(input)
      for (const candidate of [decoded.url, decoded.baselineUrl].filter(Boolean) as string[]) {
        const u = new URL(candidate)
        if (u.protocol !== "http:" && u.protocol !== "https:") {
          return { valid: false, errors: [`Unsupported scheme in ${candidate}`] }
        }
        if (u.username || u.password) {
          return { valid: false, errors: ["Embedded URL credentials are prohibited"] }
        }
      }
      if (decoded.rawRequest?.trim()) {
        const parsedRaw = parseRawHttpRequestText(decoded.rawRequest, decoded.url)
        const baseOrigin = new URL(decoded.url).origin
        const rawOrigin = new URL(parsedRaw.url).origin
        if (rawOrigin !== baseOrigin) {
          return {
            valid: false,
            errors: [
              `Raw HTTP Host origin (${rawOrigin}) must match the authorized base URL origin (${baseOrigin})`,
            ],
          }
        }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(HttpRepeaterInputSchema)(execInput.input)
    let effectiveUrl = params.url
    let effectiveMethod: string = params.method ?? "GET"
    let effectiveHeaders: Record<string, string> = params.headers ? { ...params.headers } : {}
    let effectiveBody: string | undefined = params.body

    if (params.rawRequest?.trim()) {
      const parsedRaw = parseRawHttpRequestText(params.rawRequest, params.url)
      const baseOrigin = new URL(params.url).origin
      const rawOrigin = new URL(parsedRaw.url).origin
      if (rawOrigin !== baseOrigin) {
        throw new Error(`Raw HTTP Host (${rawOrigin}) differs from authorized URL origin (${baseOrigin})`)
      }
      effectiveUrl = parsedRaw.url
      effectiveMethod = parsedRaw.method
      effectiveHeaders = { ...effectiveHeaders, ...parsedRaw.headers }
      effectiveBody = parsedRaw.body
    }

    const timeoutMs = params.timeoutMs ?? 12_000
    const maxBodyBytes = params.maxBodyBytes ?? 65_536
    const followRedirects = params.followRedirects ?? false

    const abortCtrl = new AbortController()
    const timer = setTimeout(() => abortCtrl.abort("HTTP Repeater timeout"), timeoutMs)
    const onParentAbort = () => abortCtrl.abort("Parent execution aborted")
    ctx.signal.addEventListener("abort", onParentAbort, { once: true })

    try {
      const primary = await performSingleExchange({
        projectId: ctx.projectId,
        url: effectiveUrl,
        method: effectiveMethod,
        headers: effectiveHeaders,
        ...(effectiveBody !== undefined ? { body: effectiveBody } : {}),
        followRedirects,
        maxBodyBytes,
        signal: abortCtrl.signal,
      })

      let baseline: CapturedHttpExchange | undefined
      if (params.baselineUrl) {
        baseline = await performSingleExchange({
          projectId: ctx.projectId,
          url: params.baselineUrl,
          method: params.method ?? effectiveMethod,
          headers: params.baselineHeaders
            ? { ...params.baselineHeaders }
            : effectiveHeaders,
          ...(params.baselineBody !== undefined
            ? { body: params.baselineBody }
            : effectiveBody !== undefined
              ? { body: effectiveBody }
              : {}),
          followRedirects,
          maxBodyBytes,
          signal: abortCtrl.signal,
        })
      }

      const comparison = baseline ? compareExchanges(primary, baseline) : undefined

      const transcript = [
        `=== PRIMARY REQUEST: ${primary.method} ${primary.url} ===`,
        ...(primary.redirectChain.length > 0 ? [`Redirects: ${primary.redirectChain.join(" | ")}`] : []),
        `Request Headers: ${JSON.stringify(sanitizeHeadersForEvidence(effectiveHeaders))}`,
        `Response: HTTP ${primary.statusCode} ${primary.statusText} (${primary.elapsedMs}ms, ${primary.bodyBytes} bytes)`,
        ...Object.entries(primary.headers).map(([k, v]) => `${k}: ${v}`),
        "",
        primary.bodyText,
      ].join("\n")

      const rawId = await ctx.emitEvidence({
        kind: "http_exchange",
        title: `HTTP Repeater ${primary.method} ${new URL(primary.url).host} -> ${primary.statusCode}`,
        source: {
          toolId: "cyberlab-http-repeater",
          toolVersion: this.version,
          executorId: this.id,
          executionId: ctx.executionId,
        },
        content: {
          mediaType: "text/plain; charset=utf-8",
          inlineText: transcript,
        },
        observedAt: new Date().toISOString(),
        labels: ["repeater", ...(comparison ? ["comparer"] : [])],
        redactionApplied: true,
      })

      const jsonId = await ctx.emitEvidence(
        normalizeRawOutputDraft({
          kind: "json",
          title: `HTTP Repeater & Comparer Structured Result`,
          rawText: JSON.stringify({ primary, baseline, comparison }, null, 2),
          mediaType: "application/json",
          toolId: "cyberlab-http-repeater",
          toolVersion: this.version,
          executorId: this.id,
          executionId: ctx.executionId,
          maxOutputBytes: 512 * 1024,
          labels: ["repeater", "comparer"],
        }),
      )

      return {
        status: "succeeded",
        evidenceIds: [rawId, jsonId],
        summary: comparison
          ? `Repeated ${effectiveMethod} ${primary.url} -> HTTP ${primary.statusCode} (baseline HTTP ${baseline?.statusCode}, byteDelta=${comparison.byteLengthDelta}, wordDelta=${comparison.wordCountDelta})`
          : `Repeated ${effectiveMethod} ${primary.url} -> HTTP ${primary.statusCode} (${primary.bodyBytes} bytes in ${primary.elapsedMs}ms)`,
        exitCode: 0,
      }
    } finally {
      clearTimeout(timer)
      ctx.signal.removeEventListener("abort", onParentAbort)
    }
  }
}
