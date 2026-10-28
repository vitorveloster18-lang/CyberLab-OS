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

export const HTTP_INTRUDER_INPUT_SCHEMA_ID = "cyberlab.http-intruder.input.v1"
export const HTTP_INTRUDER_OUTPUT_SCHEMA_ID = "cyberlab.http-intruder.output.v1"

const HttpMethodSchema = Schema.Literals(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
const IntruderAttackModeSchema = Schema.Literals(["sniper", "battering_ram", "pitchfork"])

export const HttpIntruderInputSchema = Schema.Struct({
  url: Schema.String.check(
    Schema.isMinLength(8),
    Schema.isMaxLength(2048),
    Schema.isPattern(/^https?:\/\/[^\s]+$/i),
  ),
  method: Schema.optionalKey(HttpMethodSchema),
  headers: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
  bodyTemplate: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(32_768))),
  attackMode: Schema.optionalKey(IntruderAttackModeSchema),
  payloadSet1: Schema.Array(Schema.String.check(Schema.isMaxLength(512))).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(60),
  ),
  payloadSet2: Schema.optionalKey(
    Schema.Array(Schema.String.check(Schema.isMaxLength(512))).check(Schema.isMaxLength(60)),
  ),
  maxRequests: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(60)),
  ),
  concurrency: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(6)),
  ),
  delayMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(0), Schema.isLessThanOrEqualTo(2_000)),
  ),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(200), Schema.isLessThanOrEqualTo(15_000)),
  ),
  grepMatch: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(256))),
  urlEncodePayloads: Schema.optionalKey(Schema.Boolean),
})

export type HttpIntruderInput = typeof HttpIntruderInputSchema.Type

export const HttpIntruderCapability: CapabilityDefinition = {
  id: "web-assessment.http-intruder",
  version: "1.0.0",
  title: "Native HTTP Intruder & Parametric Request Matrix (Sniper / Battering Ram / Pitchfork)",
  description:
    "Executes rate-limited, scope-governed parametric HTTP template requests using §slot§ markers across URL, headers, and body, computing status, byte-length, timing, and grep differentials with SHA-256 custody.",
  inputSchemaId: HTTP_INTRUDER_INPUT_SCHEMA_ID,
  outputSchemaId: HTTP_INTRUDER_OUTPUT_SCHEMA_ID,
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["url_origin"],
  executorId: "http-intruder-matrix-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

interface MarkerSlot {
  index: number
  defaultVal: string
}

const MARKER_REGEX = /§([^§]*)§/g

function extractSlotsFromTemplate(composite: string): MarkerSlot[] {
  const slots: MarkerSlot[] = []
  let idx = 0
  for (const m of composite.matchAll(MARKER_REGEX)) {
    slots.push({ index: idx++, defaultVal: m[1] ?? "" })
  }
  return slots
}

function replaceMarkersWithValues(text: string, values: readonly string[], startOffset: { current: number }): string {
  return text.replace(MARKER_REGEX, (_full, def: string) => {
    const pos = startOffset.current++
    return values[pos] !== undefined ? values[pos]! : def
  })
}

interface PlannedCase {
  caseIndex: number
  positionLabel: string
  appliedPayloads: string[]
  finalUrl: string
  finalHeaders: Record<string, string>
  finalBody: string
}

function buildPlannedCases(input: HttpIntruderInput): PlannedCase[] {
  const headerEntries = Object.entries(input.headers ?? {})
  const bodyTpl = input.bodyTemplate ?? ""
  const composite = [
    input.url,
    ...headerEntries.map(([k, v]) => `${k}: ${v}`),
    bodyTpl,
  ].join("\n")

  const slots = extractSlotsFromTemplate(composite)
  const encodeIfNeeded = (val: string, inUrl: boolean) =>
    inUrl && (input.urlEncodePayloads ?? true) ? encodeURIComponent(val) : val

  const mode = input.attackMode ?? "sniper"
  const set1 = input.payloadSet1
  const set2 = input.payloadSet2 ?? []
  const maxReq = input.maxRequests ?? 30
  const cases: PlannedCase[] = []

  const materialize = (rawValuesForSlots: string[], positionLabel: string, shownPayloads: string[]) => {
    if (cases.length >= maxReq) return
    if (slots.length === 0) {
      const sep = input.url.includes("?") ? "&" : "?"
      const v = rawValuesForSlots[0] ?? ""
      cases.push({
        caseIndex: cases.length + 1,
        positionLabel,
        appliedPayloads: shownPayloads,
        finalUrl: `${input.url}${sep}cyberlab_param=${encodeIfNeeded(v, true)}`,
        finalHeaders: { ...(input.headers ?? {}) },
        finalBody: bodyTpl,
      })
      return
    }

    const urlSlotCount = (input.url.match(MARKER_REGEX) ?? []).length
    const prepared = rawValuesForSlots.map((v, idx) => encodeIfNeeded(v, idx < urlSlotCount))
    const cursor = { current: 0 }
    const finalUrl = replaceMarkersWithValues(input.url, prepared, cursor)
    const finalHeaders: Record<string, string> = {}
    for (const [hk, hv] of headerEntries) {
      const nextKey = replaceMarkersWithValues(hk, prepared, cursor)
      const nextVal = replaceMarkersWithValues(hv, prepared, cursor)
      finalHeaders[nextKey] = nextVal
    }
    const finalBody = replaceMarkersWithValues(bodyTpl, prepared, cursor)
    cases.push({
      caseIndex: cases.length + 1,
      positionLabel,
      appliedPayloads: shownPayloads,
      finalUrl,
      finalHeaders,
      finalBody,
    })
  }

  if (slots.length === 0 || mode === "battering_ram") {
    for (const p1 of set1) {
      const filled = slots.map(() => p1)
      materialize(filled.length > 0 ? filled : [p1], slots.length > 0 ? `all(${slots.length})` : "query", [p1])
    }
  } else if (mode === "pitchfork") {
    const pairCount = Math.min(set1.length, set2.length > 0 ? set2.length : set1.length)
    for (let i = 0; i < pairCount; i++) {
      const v1 = set1[i]!
      const v2 = set2[i] ?? v1
      const filled = slots.map((s, sIdx) => (sIdx === 0 ? v1 : sIdx === 1 ? v2 : s.defaultVal))
      materialize(filled, "slot#1+slot#2", slots.length > 1 ? [v1, v2] : [v1])
    }
  } else {
    for (let sIdx = 0; sIdx < slots.length; sIdx++) {
      for (const p1 of set1) {
        const filled = slots.map((s, idx) => (idx === sIdx ? p1 : s.defaultVal))
        materialize(filled, `slot#${sIdx + 1}`, [p1])
      }
    }
  }

  return cases
}

export class HttpIntruderMatrixExecutor implements CyberLabExecutor {
  readonly id = "http-intruder-matrix-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      Schema.decodeUnknownSync(HttpIntruderInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, context: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(HttpIntruderInputSchema)(req.input)
    const method = parsed.method ?? "GET"
    const timeoutMs = parsed.timeoutMs ?? 6_000
    const delayMs = parsed.delayMs ?? 25
    const concurrency = parsed.concurrency ?? 2
    const grepNeedle = parsed.grepMatch?.trim() ?? ""

    const baseOrigin = new URL(parsed.url.replace(MARKER_REGEX, "marker")).origin
    const planned = buildPlannedCases(parsed)

    interface RowResult {
      caseIndex: number
      position: string
      payloads: string[]
      url: string
      statusCode: number
      bodyLength: number
      lengthDeltaFromFirst: number
      elapsedMs: number
      grepMatched: boolean
      interestingAnomaly: boolean
      locationHeader?: string
      error?: string
    }

    const results: RowResult[] = new Array(planned.length)
    let nextIdx = 0

    const runOne = async (item: PlannedCase): Promise<RowResult> => {
      if (context.signal.aborted) {
        throw new Error("Execution cancelled by operator")
      }
      let targetUrl: URL
      try {
        targetUrl = new URL(item.finalUrl)
      } catch {
        return {
          caseIndex: item.caseIndex,
          position: item.positionLabel,
          payloads: item.appliedPayloads,
          url: item.finalUrl,
          statusCode: 0,
          bodyLength: 0,
          lengthDeltaFromFirst: 0,
          elapsedMs: 0,
          grepMatched: false,
          interestingAnomaly: false,
          error: "Invalid URL after marker substitution",
        }
      }

      if (targetUrl.origin !== baseOrigin) {
        return {
          caseIndex: item.caseIndex,
          position: item.positionLabel,
          payloads: item.appliedPayloads,
          url: item.finalUrl,
          statusCode: 0,
          bodyLength: 0,
          lengthDeltaFromFirst: 0,
          elapsedMs: 0,
          grepMatched: false,
          interestingAnomaly: false,
          error: `Blocked cross-origin substitution (${targetUrl.origin} !== ${baseOrigin})`,
        }
      }

      if (delayMs > 0 && item.caseIndex > 1) {
        await new Promise((r) => setTimeout(r, delayMs))
      }

      const t0 = performance.now()
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort("Intruder request timeout"), timeoutMs)
      const onOuterAbort = () => ctrl.abort("Cancelled")
      context.signal.addEventListener("abort", onOuterAbort, { once: true })

      try {
        const res = await fetch(targetUrl.toString(), {
          method,
          headers: item.finalHeaders,
          ...(method !== "GET" && method !== "HEAD" && item.finalBody.length > 0
            ? { body: item.finalBody }
            : {}),
          redirect: "manual",
          signal: ctrl.signal,
        })
        const rawText = capOutputBytes(await res.text(), 32_768).text
        const elapsedMs = Math.round(performance.now() - t0)
        const loc = res.headers.get("location") ?? undefined
        const grepMatched = grepNeedle ? rawText.toLowerCase().includes(grepNeedle.toLowerCase()) : false

        return {
          caseIndex: item.caseIndex,
          position: item.positionLabel,
          payloads: item.appliedPayloads,
          url: targetUrl.toString(),
          statusCode: res.status,
          bodyLength: Buffer.byteLength(rawText, "utf8"),
          lengthDeltaFromFirst: 0,
          elapsedMs,
          grepMatched,
          interestingAnomaly: false,
          ...(loc ? { locationHeader: loc } : {}),
        }
      } catch (err) {
        return {
          caseIndex: item.caseIndex,
          position: item.positionLabel,
          payloads: item.appliedPayloads,
          url: targetUrl.toString(),
          statusCode: 0,
          bodyLength: 0,
          lengthDeltaFromFirst: 0,
          elapsedMs: Math.round(performance.now() - t0),
          grepMatched: false,
          interestingAnomaly: false,
          error: err instanceof Error ? err.message : String(err),
        }
      } finally {
        clearTimeout(timer)
        context.signal.removeEventListener("abort", onOuterAbort)
      }
    }

    const workers = Array.from({ length: Math.min(concurrency, Math.max(1, planned.length)) }, async () => {
      while (nextIdx < planned.length) {
        const current = planned[nextIdx++]!
        results[current.caseIndex - 1] = await runOne(current)
      }
    })
    await Promise.all(workers)

    const baselineRow = results[0]
    const baseStatus = baselineRow?.statusCode ?? 0
    const baseLen = baselineRow?.bodyLength ?? 0
    for (const row of results) {
      if (!row) continue
      row.lengthDeltaFromFirst = row.bodyLength - baseLen
      row.interestingAnomaly =
        (row.caseIndex > 1 && row.statusCode !== baseStatus && row.statusCode > 0) ||
        Math.abs(row.lengthDeltaFromFirst) >= 64 ||
        row.grepMatched
    }

    const anomalies = results.filter((r) => r?.interestingAnomaly)
    const report = {
      targetTemplate: parsed.url,
      method,
      attackMode: parsed.attackMode ?? "sniper",
      totalExecuted: results.length,
      anomaliesCount: anomalies.length,
      baseline: baselineRow
        ? { statusCode: baselineRow.statusCode, bodyLength: baselineRow.bodyLength }
        : null,
      rows: results,
    }

    const redactedJson = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await context.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "http_exchange",
        title: `HTTP Intruder (${parsed.attackMode ?? "sniper"}) ${method} ${baseOrigin} [${results.length} cases]`,
        rawText: redactedJson.text,
        mediaType: "application/json",
        toolId: "cyberlab-http-intruder",
        toolVersion: this.version,
        executorId: this.id,
        executionId: context.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["intruder", `mode:${parsed.attackMode ?? "sniper"}`],
      }),
      redactionApplied: redactedJson.redacted || true,
    })

    return {
      status: context.signal.aborted ? "cancelled" : "succeeded",
      evidenceIds: [evId],
      summary: `HTTP Intruder (${parsed.attackMode ?? "sniper"}) executou ${results.length} caso(s) em ${baseOrigin} — ${anomalies.length} diferença(s)/anomalia(s) destacada(s).`,
      exitCode: 0,
    }
  }
}
