import crypto from "node:crypto"
import { existsSync, lstatSync, readFileSync } from "node:fs"
import path from "node:path"
import { gunzipSync, gzipSync, inflateRawSync, inflateSync } from "node:zlib"
import { Schema } from "effect"
import {
  isPathInsideRoot,
  normalizeRawOutputDraft,
  redactSensitiveContent,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const ENTROPY_RECIPE_INPUT_SCHEMA_ID = "cyberlab.entropy-recipe.input.v1"
export const ENTROPY_RECIPE_OUTPUT_SCHEMA_ID = "cyberlab.entropy-recipe.output.v1"

export const RecipeStepSchema = Schema.Struct({
  op: Schema.Literals([
    "from_base64",
    "to_base64",
    "from_hex",
    "to_hex",
    "url_decode",
    "url_encode",
    "gunzip",
    "gzip",
    "zlib_inflate",
    "raw_inflate",
    "xor_key",
    "xor_single_byte_bruteforce",
    "aes_cbc_decrypt",
    "aes_gcm_decrypt",
    "protobuf_raw_decode",
    "extract_strings",
    "sha256",
  ]),
  keyHexOrUtf8: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  ivHex: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
})

export const EntropyRecipeInputSchema = Schema.Struct({
  filePath: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512))),
  bucketCount: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(8), Schema.isLessThanOrEqualTo(256)),
  ),
  inputText: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(262_144))),
  recipeSteps: Schema.optionalKey(Schema.Array(RecipeStepSchema).check(Schema.isMaxLength(16))),
})

export type EntropyRecipeInput = typeof EntropyRecipeInputSchema.Type
export type RecipeStep = typeof RecipeStepSchema.Type

export const EntropyRecipeCapability: CapabilityDefinition = {
  id: "reverse-engineering.entropy-recipe-studio",
  version: "1.0.0",
  title: "Binary Entropy Visualizer & CyberChef-Style Recipe Studio",
  description:
    "Computes sliding-window Shannon entropy curves (byte 0 to EOF) with embedded file-signature carving to locate encrypted/compressed regions, and executes chained CyberChef-style decoding recipes (XOR brute-force/key, AES-CBC/GCM, Gzip/Zlib inflate, Protobuf raw wire decoder).",
  inputSchemaId: ENTROPY_RECIPE_INPUT_SCHEMA_ID,
  outputSchemaId: ENTROPY_RECIPE_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "entropy-recipe-studio-executor",
  skillIds: ["reverse-engineering", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export interface EntropyBucket {
  index: number
  startOffset: number
  endOffset: number
  offsetHex: string
  entropy: number
  printableRatio: number
  nullRatio: number
  classification: "null_padding" | "plaintext_or_code" | "structured_binary" | "compressed_or_encrypted"
}

export function shannonEntropy(slice: Uint8Array): number {
  if (slice.byteLength === 0) return 0
  const freq = new Uint32Array(256)
  for (let i = 0; i < slice.byteLength; i++) {
    freq[slice[i]!]!++
  }
  let ent = 0
  const len = slice.byteLength
  for (let b = 0; b < 256; b++) {
    const c = freq[b]!
    if (c > 0) {
      const p = c / len
      ent -= p * Math.log2(p)
    }
  }
  return Math.round(ent * 1000) / 1000
}

const EMBEDDED_MAGICS: Array<{ label: string; bytes: number[] }> = [
  { label: "ELF Executable", bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { label: "PE / MZ Header", bytes: [0x4d, 0x5a, 0x90, 0x00] },
  { label: "ZIP / APK / JAR Archive", bytes: [0x50, 0x4b, 0x03, 0x04] },
  { label: "GZIP Compressed Stream", bytes: [0x1f, 0x8b, 0x08] },
  { label: "ZLIB Deflate Stream (78 9C)", bytes: [0x78, 0x9c] },
  { label: "ZLIB Best Compression (78 DA)", bytes: [0x78, 0xda] },
  { label: "XZ Compressed Archive", bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { label: "PNG Image", bytes: [0x89, 0x50, 0x4e, 0x47] },
  { label: "SQLite 3 Database", bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66] },
  { label: "Dalvik DEX", bytes: [0x64, 0x65, 0x78, 0x0a, 0x30] },
  { label: "PEM Certificate / Key", bytes: [0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47] },
]

export function computeBinaryEntropyProfile(buf: Buffer, requestedBuckets = 64): {
  overallEntropy: number
  buckets: EntropyBucket[]
  embeddedSignatures: Array<{ offsetHex: string; offsetDec: number; signature: string }>
} {
  const actualBuckets = Math.max(1, Math.min(requestedBuckets, buf.length || 1))
  const windowSize = Math.max(1, Math.ceil(buf.length / actualBuckets))
  const buckets: EntropyBucket[] = []

  for (let idx = 0; idx < actualBuckets; idx++) {
    const start = idx * windowSize
    if (start >= buf.length) break
    const end = Math.min(buf.length, start + windowSize)
    const slice = buf.subarray(start, end)
    const ent = shannonEntropy(slice)
    let printable = 0
    let nulls = 0
    for (let i = 0; i < slice.length; i++) {
      const b = slice[i]!
      if (b === 0) nulls++
      else if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) printable++
    }
    const printableRatio = Math.round((printable / slice.length) * 1000) / 1000
    const nullRatio = Math.round((nulls / slice.length) * 1000) / 1000
    const classification: EntropyBucket["classification"] =
      nullRatio >= 0.75
        ? "null_padding"
        : ent >= 7.2
          ? "compressed_or_encrypted"
          : printableRatio >= 0.65
            ? "plaintext_or_code"
            : "structured_binary"

    buckets.push({
      index: idx,
      startOffset: start,
      endOffset: end,
      offsetHex: `0x${start.toString(16).padStart(6, "0")}`,
      entropy: ent,
      printableRatio,
      nullRatio,
      classification,
    })
  }

  const embeddedSignatures: Array<{ offsetHex: string; offsetDec: number; signature: string }> = []
  const scanLimit = Math.min(buf.length, 4 * 1024 * 1024)
  for (let i = 0; i < scanLimit - 8 && embeddedSignatures.length < 40; i++) {
    for (const sig of EMBEDDED_MAGICS) {
      let ok = true
      for (let k = 0; k < sig.bytes.length; k++) {
        if (buf[i + k] !== sig.bytes[k]) {
          ok = false
          break
        }
      }
      if (ok) {
        embeddedSignatures.push({
          offsetHex: `0x${i.toString(16).padStart(6, "0")}`,
          offsetDec: i,
          signature: sig.label,
        })
      }
    }
  }

  return {
    overallEntropy: shannonEntropy(buf),
    buckets,
    embeddedSignatures,
  }
}

export function decodeProtobufWireRaw(buf: Buffer): Array<{ fieldNumber: number; wireType: number; value: unknown }> {
  const fields: Array<{ fieldNumber: number; wireType: number; value: unknown }> = []
  let pos = 0
  const readVarint = (): bigint | null => {
    let result = 0n
    let shift = 0n
    while (pos < buf.length && shift < 70n) {
      const byte = buf[pos++]!
      result |= BigInt(byte & 0x7f) << shift
      if ((byte & 0x80) === 0) return result
      shift += 7n
    }
    return null
  }

  while (pos < buf.length && fields.length < 100) {
    const tag = readVarint()
    if (tag === null || tag === 0n) break
    const wireType = Number(tag & 0x07n)
    const fieldNumber = Number(tag >> 3n)
    if (fieldNumber <= 0 || fieldNumber > 536_870_911) break

    if (wireType === 0) {
      const v = readVarint()
      if (v === null) break
      fields.push({ fieldNumber, wireType, value: v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString() })
    } else if (wireType === 1) {
      if (pos + 8 > buf.length) break
      const v = buf.readBigUInt64LE(pos)
      pos += 8
      fields.push({ fieldNumber, wireType, value: `0x${v.toString(16).padStart(16, "0")}` })
    } else if (wireType === 2) {
      const lenBig = readVarint()
      if (lenBig === null) break
      const len = Number(lenBig)
      if (len < 0 || pos + len > buf.length) break
      const sub = buf.subarray(pos, pos + len)
      pos += len
      const utf8 = sub.toString("utf8")
      const isPrintable = /^[\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]*$/.test(utf8) && !utf8.includes("\ufffd")
      fields.push({
        fieldNumber,
        wireType,
        value: isPrintable ? utf8 : `hex:${sub.toString("hex")}`,
      })
    } else if (wireType === 5) {
      if (pos + 4 > buf.length) break
      const v = buf.readUInt32LE(pos)
      pos += 4
      fields.push({ fieldNumber, wireType, value: v })
    } else {
      break
    }
  }
  return fields
}

function parseKeyBytes(raw?: string): Buffer {
  const clean = (raw ?? "").trim()
  if (!clean) return Buffer.from([0x42])
  if (/^(0x)?[0-9a-fA-F]+$/.test(clean) && clean.replace(/^0x/i, "").length % 2 === 0) {
    return Buffer.from(clean.replace(/^0x/i, ""), "hex")
  }
  return Buffer.from(clean, "utf8")
}

export function runRecipeSteps(initial: Buffer, steps: readonly RecipeStep[]): {
  finalText: string
  finalHexPreview: string
  stepLogs: Array<{ step: number; op: string; byteLength: number; preview: string }>
} {
  let cur = Buffer.from(initial)
  const stepLogs: Array<{ step: number; op: string; byteLength: number; preview: string }> = []

  steps.forEach((step, idx) => {
    switch (step.op) {
      case "from_base64":
        cur = Buffer.from(cur.toString("utf8").replace(/\s+/g, ""), "base64")
        break
      case "to_base64":
        cur = Buffer.from(cur.toString("base64"), "utf8")
        break
      case "from_hex":
        cur = Buffer.from(cur.toString("utf8").replace(/[^0-9a-fA-F]/g, ""), "hex")
        break
      case "to_hex":
        cur = Buffer.from(cur.toString("hex"), "utf8")
        break
      case "url_decode":
        cur = Buffer.from(decodeURIComponent(cur.toString("utf8")), "utf8")
        break
      case "url_encode":
        cur = Buffer.from(encodeURIComponent(cur.toString("utf8")), "utf8")
        break
      case "gunzip":
        cur = gunzipSync(cur, { maxOutputLength: 2 * 1024 * 1024 })
        break
      case "gzip":
        cur = gzipSync(cur)
        break
      case "zlib_inflate":
        cur = inflateSync(cur, { maxOutputLength: 2 * 1024 * 1024 })
        break
      case "raw_inflate":
        cur = inflateRawSync(cur, { maxOutputLength: 2 * 1024 * 1024 })
        break
      case "xor_key": {
        const key = parseKeyBytes(step.keyHexOrUtf8)
        const out = Buffer.alloc(cur.length)
        for (let i = 0; i < cur.length; i++) {
          out[i] = cur[i]! ^ key[i % key.length]!
        }
        cur = out
        break
      }
      case "xor_single_byte_bruteforce": {
        const sample = cur.subarray(0, 4096)
        const candidates: Array<{ keyHex: string; score: number; decoded: string }> = []
        for (let k = 1; k <= 255; k++) {
          let score = 0
          const out = Buffer.alloc(sample.length)
          for (let i = 0; i < sample.length; i++) {
            const c = sample[i]! ^ k
            out[i] = c
            if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x20) score += 3
            else if (c >= 0x21 && c <= 0x7e) score += 1
            else if (c === 0x0a || c === 0x0d || c === 0x09) score += 1
            else score -= 4
          }
          candidates.push({
            keyHex: `0x${k.toString(16).padStart(2, "0")}`,
            score,
            decoded: out.toString("utf8").slice(0, 160),
          })
        }
        candidates.sort((a, b) => b.score - a.score)
        cur = Buffer.from(JSON.stringify(candidates.slice(0, 5), null, 2), "utf8")
        break
      }
      case "aes_cbc_decrypt": {
        const key = parseKeyBytes(step.keyHexOrUtf8)
        const iv = parseKeyBytes(step.ivHex)
        const alg = key.length === 16 ? "aes-128-cbc" : key.length === 24 ? "aes-192-cbc" : "aes-256-cbc"
        const decipher = crypto.createDecipheriv(alg, key, iv)
        cur = Buffer.concat([decipher.update(cur), decipher.final()])
        break
      }
      case "aes_gcm_decrypt": {
        // Supports detached tag via ivHex="ivHex:tagHex" OR appended 16-byte authentication tag
        const key = parseKeyBytes(step.keyHexOrUtf8)
        const rawIvField = (step.ivHex ?? "").trim()
        const [ivPart, detachedTagHex] = rawIvField.includes(":")
          ? (rawIvField.split(":", 2) as [string, string])
          : [rawIvField, ""]
        const iv = parseKeyBytes(ivPart)
        let tag: Buffer
        let body: Buffer
        if (detachedTagHex) {
          tag = parseKeyBytes(detachedTagHex)
          body = cur
        } else {
          if (cur.length < 16) throw new Error("AES-GCM input requires 16-byte authentication tag appended")
          tag = cur.subarray(cur.length - 16)
          body = cur.subarray(0, cur.length - 16)
        }
        const alg = key.length === 16 ? "aes-128-gcm" : key.length === 24 ? "aes-192-gcm" : "aes-256-gcm"
        const decipher = crypto.createDecipheriv(alg, key, iv)
        decipher.setAuthTag(tag)
        cur = Buffer.concat([decipher.update(body), decipher.final()])
        break
      }
      case "protobuf_raw_decode": {
        const decodedFields = decodeProtobufWireRaw(cur)
        cur = Buffer.from(JSON.stringify(decodedFields, null, 2), "utf8")
        break
      }
      case "extract_strings": {
        const matches = cur.toString("latin1").match(/[\x20-\x7e]{5,}/g) ?? []
        cur = Buffer.from(matches.slice(0, 200).join("\n"), "utf8")
        break
      }
      case "sha256": {
        const digest = crypto.createHash("sha256").update(cur).digest("hex")
        cur = Buffer.from(digest, "utf8")
        break
      }
    }

    stepLogs.push({
      step: idx + 1,
      op: step.op,
      byteLength: cur.length,
      preview: cur.subarray(0, 120).toString("utf8"),
    })
  })

  return {
    finalText: cur.toString("utf8"),
    finalHexPreview: cur.subarray(0, 128).toString("hex"),
    stepLogs,
  }
}

export class EntropyRecipeStudioExecutor implements CyberLabExecutor {
  readonly id = "entropy-recipe-studio-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      const parsed = Schema.decodeUnknownSync(EntropyRecipeInputSchema)(input)
      if (!parsed.filePath && (!parsed.inputText || !parsed.inputText.trim())) {
        return {
          valid: false,
          errors: ["Informe filePath (para Mapa Visual de Entropia) e/ou inputText + recipeSteps (CyberChef Studio)."],
        }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(EntropyRecipeInputSchema)(req.input)

    let entropyProfile: ReturnType<typeof computeBinaryEntropyProfile> | null = null
    let sourceBuf: Buffer | null = null

    if (parsed.filePath) {
      const abs = path.resolve(ctx.workspaceRoot, parsed.filePath)
      if (!isPathInsideRoot(abs, ctx.workspaceRoot) || !existsSync(abs) || lstatSync(abs).isSymbolicLink()) {
        return {
          status: "failed",
          evidenceIds: [],
          summary: `Arquivo fora do escopo ou inexistente: ${parsed.filePath}`,
          exitCode: 2,
        }
      }
      const st = lstatSync(abs)
      if (st.size > 32 * 1024 * 1024) {
        return { status: "failed", evidenceIds: [], summary: "Arquivo excede o limite seguro de 32 MiB", exitCode: 2 }
      }
      sourceBuf = readFileSync(abs)
      entropyProfile = computeBinaryEntropyProfile(sourceBuf, parsed.bucketCount ?? 64)
    }

    let recipeOutput: ReturnType<typeof runRecipeSteps> | null = null
    const steps = parsed.recipeSteps ?? []
    if (steps.length > 0 || (parsed.inputText && parsed.inputText.length > 0)) {
      const recipeInput =
        parsed.inputText && parsed.inputText.length > 0
          ? Buffer.from(parsed.inputText, "utf8")
          : (sourceBuf ?? Buffer.alloc(0))
      recipeOutput = runRecipeSteps(recipeInput, steps)
    }

    const report = {
      analyzedFile: parsed.filePath ?? null,
      fileByteLength: sourceBuf?.length ?? null,
      entropyProfile,
      recipeResult: recipeOutput,
    }

    const redacted = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await ctx.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "json",
        title: `Entropy Map & CyberChef Studio${parsed.filePath ? `: ${path.basename(parsed.filePath)}` : ""}`,
        rawText: redacted.text,
        mediaType: "application/json",
        toolId: "cyberlab-entropy-recipe-studio",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["entropy", "recipe-studio", "reverse-engineering"],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: entropyProfile
        ? `Entropia global ${entropyProfile.overallEntropy} bits/byte (${entropyProfile.buckets.length} janelas, ${entropyProfile.embeddedSignatures.length} assinatura(s) embutida(s)).`
        : `Receita executada com ${steps.length} operação(ões).`,
      exitCode: 0,
    }
  }
}
