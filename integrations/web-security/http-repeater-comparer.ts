import { Schema } from "effect"
import {
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
  body: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(65_536))),
  baselineUrl: Schema.optionalKey(
    Schema.String.check(
      Schema.isMinLength(8),
      Schema.isMaxLength(2048),
      Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
    ),
  ),
  baselineHeaders: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(100), Schema.isLessThanOrEqualTo(15_000)),
  ),
  maxBodyBytes: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(256), Schema.isLessThanOrEqualTo(65_536)),
  ),
})

export type HttpRepeaterInput = typeof HttpRepeaterInputSchema.Type

export const HttpRepeaterCapability: CapabilityDefinition = {
  id: "web-assessment.http-repeater",
  version: "1.0.0",
  title: "Native HTTP Repeater & Response Comparer (OpenTRAP/Burp Style)",
  description:
    "Replays a structured HTTP request against an authorized in-scope endpoint and optionally compares the response (status, headers, byte length, timing, and line diff) against a baseline request, redacting sensitive headers/cookies in persisted SHA-256 evidence.",
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

interface CapturedHttpExchange {
  url: string
  method: string
  statusCode: number
  statusText: string
  elapsedMs: number
  headers: Record<string, string>
  bodyText: string
  bodyBytes: number
}

async function performSingleExchange(params: {
  url: string
  method: string
  headers: Record<string, string>
  body?: string
  maxBodyBytes: number
  signal: AbortSignal
}): Promise<CapturedHttpExchange> {
  const parsed = new URL(params.url)
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported protocol "${parsed.protocol}"`)
  }
  if (parsed.username || parsed.password) {
    throw new Error("Embedded URL credentials are prohibited")
  }

  const reqHeaders = new Headers({
    "User-Agent": "CyberLab-OS-Repeater/1.0",
    ...params.headers,
  })

  const startedAt = Date.now()
  const res = await fetch(parsed.toString(), {
    method: params.method,
    headers: reqHeaders,
    ...(params.body !== undefined && params.method !== "GET" && params.method !== "HEAD"
      ? { body: params.body }
      : {}),
    redirect: "manual",
    signal: params.signal,
  })
  const elapsedMs = Date.now() - startedAt

  const resHeaders: Record<string, string> = {}
  res.headers.forEach((value, key) => {
    resHeaders[key] = SENSITIVE_HEADER_NAMES.has(key.toLowerCase()) ? "[REDACTED:SENSITIVE_HEADER]" : value
  })

  const rawBuf = params.method === "HEAD" ? new Uint8Array(0) : new Uint8Array(await res.arrayBuffer())
  const fullText = new TextDecoder("utf-8", { fatal: false }).decode(rawBuf)
  const capped = capOutputBytes(fullText, params.maxBodyBytes)

  return {
    url: parsed.toString(),
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
  const bLines = new Set(baseline.bodyText.split(/\r?\n/))
  const uniquePrimaryLines = pLines.filter((l) => l.length > 0 && !bLines.has(l)).slice(0, 20)

  return {
    statusChanged: primary.statusCode !== baseline.statusCode,
    primaryStatus: primary.statusCode,
    baselineStatus: baseline.statusCode,
    byteLengthDelta: primary.bodyBytes - baseline.bodyBytes,
    elapsedMsDelta: primary.elapsedMs - baseline.elapsedMs,
    addedHeaders,
    removedHeaders,
    changedHeaders,
    sampleUniqueLinesInPrimary: uniquePrimaryLines,
  }
}

export class HttpRepeaterComparerExecutor implements CyberLabExecutor {
  readonly id = "http-repeater-comparer-executor"
  readonly version = "1.0.0"

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
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(HttpRepeaterInputSchema)(execInput.input)
    const method = params.method ?? "GET"
    const timeoutMs = params.timeoutMs ?? 6_000
    const maxBodyBytes = params.maxBodyBytes ?? 16_384

    const abortCtrl = new AbortController()
    const timer = setTimeout(() => abortCtrl.abort("HTTP Repeater timeout"), timeoutMs)
    const onParentAbort = () => abortCtrl.abort("Parent execution aborted")
    ctx.signal.addEventListener("abort", onParentAbort, { once: true })

    try {
      const primary = await performSingleExchange({
        url: params.url,
        method,
        headers: params.headers ? { ...params.headers } : {},
        ...(params.body !== undefined ? { body: params.body } : {}),
        maxBodyBytes,
        signal: abortCtrl.signal,
      })

      let baseline: CapturedHttpExchange | undefined
      if (params.baselineUrl) {
        baseline = await performSingleExchange({
          url: params.baselineUrl,
          method,
          headers: params.baselineHeaders
            ? { ...params.baselineHeaders }
            : params.headers
              ? { ...params.headers }
              : {},
          ...(params.body !== undefined ? { body: params.body } : {}),
          maxBodyBytes,
          signal: abortCtrl.signal,
        })
      }

      const comparison = baseline ? compareExchanges(primary, baseline) : undefined

      const transcript = [
        `=== PRIMARY REQUEST: ${primary.method} ${primary.url} ===`,
        `Request Headers: ${JSON.stringify(sanitizeHeadersForEvidence(params.headers ?? {}))}`,
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
          ? `Repeated ${method} ${primary.url} -> HTTP ${primary.statusCode} (baseline HTTP ${baseline?.statusCode}, byteDelta=${comparison.byteLengthDelta})`
          : `Repeated ${method} ${primary.url} -> HTTP ${primary.statusCode} (${primary.bodyBytes} bytes in ${primary.elapsedMs}ms)`,
        exitCode: 0,
      }
    } finally {
      clearTimeout(timer)
      ctx.signal.removeEventListener("abort", onParentAbort)
    }
  }
}
