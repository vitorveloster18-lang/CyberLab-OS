import { createHash } from "node:crypto"
import { Schema } from "effect"
import {
  normalizeRawOutputDraft,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const DECODER_SEQUENCER_INPUT_SCHEMA_ID = "cyberlab.decoder-sequencer.input.v1"
export const DECODER_SEQUENCER_OUTPUT_SCHEMA_ID = "cyberlab.decoder-sequencer.output.v1"

const TransformStepSchema = Schema.Literals([
  "url_decode",
  "url_encode",
  "base64_decode",
  "base64_encode",
  "base64url_decode",
  "hex_decode",
  "hex_encode",
  "html_decode",
  "sha256",
])

export type TransformStep = typeof TransformStepSchema.Type

export const DecoderSequencerInputSchema = Schema.Struct({
  value: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(65_536))),
  transforms: Schema.optionalKey(Schema.Array(TransformStepSchema).check(Schema.isMaxLength(16))),
  inspectJwt: Schema.optionalKey(Schema.Boolean),
  tokenSamples: Schema.optionalKey(
    Schema.Array(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2048))).check(
      Schema.isMaxLength(500),
    ),
  ),
})

export type DecoderSequencerInput = typeof DecoderSequencerInputSchema.Type

export const DecoderSequencerCapability: CapabilityDefinition = {
  id: "web-assessment.decoder-sequencer",
  version: "1.0.0",
  title: "Native Payload Decoder, JWT Inspector & Token Entropy Sequencer (OpenTRAP/Burp Style)",
  description:
    "Executes chained offline encoding/decoding transforms (URL, Base64, Base64URL, Hex, HTML, SHA-256), inspects JWT headers/claims for insecure configurations (alg:none, missing exp), and computes Shannon entropy and predictability metrics on session tokens.",
  inputSchemaId: DECODER_SEQUENCER_INPUT_SCHEMA_ID,
  outputSchemaId: DECODER_SEQUENCER_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  executorId: "decoder-sequencer-executor",
  skillIds: ["web-assessment", "code-audit", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

function applySingleTransform(input: string, step: TransformStep): string {
  switch (step) {
    case "url_decode":
      return decodeURIComponent(input)
    case "url_encode":
      return encodeURIComponent(input)
    case "base64_decode":
      return Buffer.from(input, "base64").toString("utf8")
    case "base64_encode":
      return Buffer.from(input, "utf8").toString("base64")
    case "base64url_decode": {
      const normalized = input.replace(/-/g, "+").replace(/_/g, "/")
      const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4))
      return Buffer.from(normalized + pad, "base64").toString("utf8")
    }
    case "hex_decode":
      return Buffer.from(input.replace(/\s+/g, ""), "hex").toString("utf8")
    case "hex_encode":
      return Buffer.from(input, "utf8").toString("hex")
    case "html_decode":
      return input
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/gi, "'")
        .replace(/&amp;/gi, "&")
    case "sha256":
      return createHash("sha256").update(input, "utf8").digest("hex")
  }
}

function inspectJwtStructure(raw: string) {
  const parts = raw.trim().split(".")
  if (parts.length !== 3) return null
  try {
    const decodePart = (segment: string) => {
      const norm = segment.replace(/-/g, "+").replace(/_/g, "/")
      const pad = norm.length % 4 === 0 ? "" : "=".repeat(4 - (norm.length % 4))
      return JSON.parse(Buffer.from(norm + pad, "base64").toString("utf8")) as Record<string, unknown>
    }
    const header = decodePart(parts[0]!)
    const payload = decodePart(parts[1]!)
    const sigPresent = (parts[2] ?? "").length > 0

    const warnings: string[] = []
    const alg = String(header.alg ?? "")
    if (!alg || alg.toLowerCase() === "none") {
      warnings.push("CRITICAL: JWT uses unsigned alg='none'")
    }
    if (!sigPresent) {
      warnings.push("CRITICAL: JWT signature segment is empty")
    }
    if (typeof payload.exp !== "number") {
      warnings.push("JWT payload lacks 'exp' expiration claim")
    } else if (payload.exp * 1000 < Date.now()) {
      warnings.push("JWT 'exp' timestamp is already expired")
    }
    if (header.jku || header.x5u) {
      warnings.push("JWT header contains remote key URL (jku/x5u) — verify SSRF/key-confusion pinning")
    }

    return {
      header,
      claimsKeys: Object.keys(payload),
      exp: payload.exp ?? null,
      iss: payload.iss ?? null,
      aud: payload.aud ?? null,
      signatureByteLength: Math.floor(((parts[2] ?? "").length * 3) / 4),
      warnings,
    }
  } catch {
    return null
  }
}

function analyzeTokenEntropy(samples: readonly string[]) {
  const joined = samples.join("")
  const freq = new Map<string, number>()
  for (const ch of joined) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1)
  }

  let shannonBitsPerChar = 0
  const totalLen = joined.length
  if (totalLen > 0) {
    for (const count of freq.values()) {
      const p = count / totalLen
      shannonBitsPerChar -= p * Math.log2(p)
    }
  }

  const avgLength = samples.length > 0 ? totalLen / samples.length : 0
  const estimatedEffectiveBits = Number((shannonBitsPerChar * avgLength).toFixed(2))
  const uniqueSamples = new Set(samples).size
  const duplicateCount = samples.length - uniqueSamples

  let sequentialNumericDetected = false
  if (samples.length >= 3 && samples.every((s) => /^\d+$/.test(s))) {
    const nums = samples.map((s) => BigInt(s))
    const diffs = new Set<bigint>()
    for (let i = 1; i < nums.length; i++) {
      diffs.add(nums[i]! - nums[i - 1]!)
    }
    if (diffs.size === 1) sequentialNumericDetected = true
  }

  const rating =
    duplicateCount > 0 || sequentialNumericDetected || estimatedEffectiveBits < 64
      ? "weak_predictable"
      : estimatedEffectiveBits < 112
        ? "moderate"
        : "strong_cryptographic"

  return {
    sampleCount: samples.length,
    uniqueCount: uniqueSamples,
    duplicateCount,
    averageLength: Number(avgLength.toFixed(2)),
    distinctAlphabetSize: freq.size,
    shannonBitsPerChar: Number(shannonBitsPerChar.toFixed(4)),
    estimatedEffectiveBits,
    sequentialNumericDetected,
    entropyRating: rating,
  }
}

export class DecoderSequencerExecutor implements CyberLabExecutor {
  readonly id = "decoder-sequencer-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string }> {
    return { available: true, version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(DecoderSequencerInputSchema)(input)
      if (!decoded.value && (!decoded.tokenSamples || decoded.tokenSamples.length === 0)) {
        return { valid: false, errors: ["Provide either 'value' or non-empty 'tokenSamples'"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(DecoderSequencerInputSchema)(execInput.input)
    const stepsTrace: Array<{ step: string; preview: string }> = []
    let currentValue = params.value ?? ""

    if (params.value !== undefined && params.transforms) {
      for (const step of params.transforms) {
        currentValue = applySingleTransform(currentValue, step)
        stepsTrace.push({ step, preview: currentValue.slice(0, 512) })
      }
    }

    const jwtInspection =
      params.inspectJwt !== false && (params.value || currentValue)
        ? inspectJwtStructure(currentValue || params.value || "")
        : null

    const sequencerReport =
      params.tokenSamples && params.tokenSamples.length > 0
        ? analyzeTokenEntropy(params.tokenSamples)
        : params.value
          ? analyzeTokenEntropy([currentValue || params.value])
          : null

    const payload = {
      transformCount: stepsTrace.length,
      stepsTrace,
      finalOutputPreview: currentValue ? currentValue.slice(0, 2048) : null,
      jwtInspection,
      sequencerReport,
    }

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "json",
        title: `Decoder & Sequencer Analysis (rating=${sequencerReport?.entropyRating ?? "n/a"})`,
        rawText: JSON.stringify(payload, null, 2),
        mediaType: "application/json",
        toolId: "cyberlab-decoder-sequencer",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 256 * 1024,
        labels: ["decoder", "sequencer", "entropy"],
      }),
    )

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `Executed ${stepsTrace.length} transform(s); entropyRating=${sequencerReport?.entropyRating ?? "n/a"} (${sequencerReport?.estimatedEffectiveBits ?? 0} bits).`,
      exitCode: 0,
    }
  }
}
