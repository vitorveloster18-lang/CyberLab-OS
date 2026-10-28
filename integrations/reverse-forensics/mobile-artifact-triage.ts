import { createHash } from "node:crypto"
import { readFileSync, statSync } from "node:fs"
import path from "node:path"
import { inflateRawSync } from "node:zlib"
import { Schema } from "effect"
import {
  isPathInsideRoot,
  normalizeRawOutputDraft,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const MOBILE_TRIAGE_INPUT_SCHEMA_ID = "cyberlab.mobile-triage.input.v1"
export const MOBILE_TRIAGE_OUTPUT_SCHEMA_ID = "cyberlab.mobile-triage.output.v1"

export const MobileArtifactTriageInputSchema = Schema.Struct({
  artifactPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  iocDomains: Schema.optionalKey(
    Schema.Array(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(253))).check(
      Schema.isMaxLength(200),
    ),
  ),
})

export type MobileArtifactTriageInput = typeof MobileArtifactTriageInputSchema.Type

export const MobileArtifactTriageCapability: CapabilityDefinition = {
  id: "mobile-forensics.artifact-triage",
  version: "1.0.0",
  title: "Native Mobile APK / IPA / Backup Forensics & IoC Triage (MVT Alternative)",
  description:
    "Safely inspects Android APK, iOS IPA, or ZIP mobile backup archives in memory without disk extraction (preventing Zip-Slip), cataloging manifests, DEX bytecode, native JNI libraries, dangerous Android permissions, cleartext HTTP endpoints, and IoC domain matches.",
  inputSchemaId: MOBILE_TRIAGE_INPUT_SCHEMA_ID,
  outputSchemaId: MOBILE_TRIAGE_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "mobile-artifact-triage-executor",
  skillIds: ["mobile-forensics", "reverse-engineering", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

const HIGH_RISK_ANDROID_PERMISSIONS = [
  "android.permission.READ_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.SEND_SMS",
  "android.permission.RECORD_AUDIO",
  "android.permission.CAMERA",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.READ_CALL_LOG",
  "android.permission.READ_CONTACTS",
  "android.permission.BIND_ACCESSIBILITY_SERVICE",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.REQUEST_INSTALL_PACKAGES",
  "android.permission.RECEIVE_BOOT_COMPLETED",
]

function parseZipCentralDirectoryEntries(buf: Uint8Array): Array<{
  name: string
  compressionMethod: number
  compressedSize: number
  uncompressedSize: number
  localHeaderOffset: number
}> {
  // Locate End of Central Directory (EOCD) signature 0x06054b50 within last 65 KiB
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  const minOffset = Math.max(0, buf.byteLength - 65_557)
  let eocdOffset = -1
  for (let i = buf.byteLength - 22; i >= minOffset; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i
      break
    }
  }
  if (eocdOffset === -1) return []

  const totalEntries = view.getUint16(eocdOffset + 10, true)
  const cdOffset = view.getUint32(eocdOffset + 16, true)
  const entries: Array<{
    name: string
    compressionMethod: number
    compressedSize: number
    uncompressedSize: number
    localHeaderOffset: number
  }> = []

  let pos = cdOffset
  for (let idx = 0; idx < Math.min(totalEntries, 5_000) && pos + 46 <= buf.byteLength; idx++) {
    if (view.getUint32(pos, true) !== 0x02014b50) break
    const compMethod = view.getUint16(pos + 10, true)
    const compSize = view.getUint32(pos + 20, true)
    const uncompSize = view.getUint32(pos + 24, true)
    const nameLen = view.getUint16(pos + 28, true)
    const extraLen = view.getUint16(pos + 30, true)
    const commentLen = view.getUint16(pos + 32, true)
    const localHeaderOffset = view.getUint32(pos + 42, true)
    if (pos + 46 + nameLen > buf.byteLength) break
    const name = new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(pos + 46, pos + 46 + nameLen))
    entries.push({
      name,
      compressionMethod: compMethod,
      compressedSize: compSize,
      uncompressedSize: uncompSize,
      localHeaderOffset,
    })
    pos += 46 + nameLen + extraLen + commentLen
  }
  return entries
}

function readZipEntryBytesSafe(
  archive: Uint8Array,
  entry: { compressionMethod: number; compressedSize: number; uncompressedSize: number; localHeaderOffset: number },
  maxBytes = 16 * 1024 * 1024,
): Uint8Array | null {
  if (entry.uncompressedSize > maxBytes || entry.compressedSize > maxBytes) return null
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength)
  const lh = entry.localHeaderOffset
  if (lh + 30 > archive.byteLength || view.getUint32(lh, true) !== 0x04034b50) return null
  const nameLen = view.getUint16(lh + 26, true)
  const extraLen = view.getUint16(lh + 28, true)
  const dataStart = lh + 30 + nameLen + extraLen
  if (dataStart + entry.compressedSize > archive.byteLength) return null
  const rawSlice = archive.subarray(dataStart, dataStart + entry.compressedSize)
  if (entry.compressionMethod === 0) return rawSlice
  if (entry.compressionMethod === 8) {
    try {
      return new Uint8Array(inflateRawSync(rawSlice, { maxOutputLength: maxBytes }))
    } catch {
      return null
    }
  }
  return null
}

function readUleb128(buf: Uint8Array, start: number): { value: number; next: number } {
  let result = 0
  let shift = 0
  let pos = start
  while (pos < buf.byteLength && shift < 35) {
    const byte = buf[pos++]!
    result |= (byte & 0x7f) << shift
    if ((byte & 0x80) === 0) break
    shift += 7
  }
  return { value: result >>> 0, next: pos }
}

function inspectDalvikDexBytes(dex: Uint8Array): {
  dexVersion: string
  stringCount: number
  typeCount: number
  methodCount: number
  classCount: number
  discoveredClasses: string[]
  discoveredMethods: string[]
} | null {
  // Magic: "dex\n035\0" .. "dex\n039\0"
  if (dex.byteLength < 112 || dex[0] !== 0x64 || dex[1] !== 0x65 || dex[2] !== 0x78 || dex[3] !== 0x0a) {
    return null
  }
  const view = new DataView(dex.buffer, dex.byteOffset, dex.byteLength)
  const dexVersion = new TextDecoder("ascii").decode(dex.subarray(4, 7))
  const stringIdsSize = view.getUint32(56, true)
  const stringIdsOff = view.getUint32(60, true)
  const typeIdsSize = view.getUint32(64, true)
  const typeIdsOff = view.getUint32(68, true)
  const methodIdsSize = view.getUint32(88, true)
  const methodIdsOff = view.getUint32(92, true)
  const classDefsSize = view.getUint32(96, true)

  const readDexString = (strIdx: number): string => {
    if (strIdx >= stringIdsSize || stringIdsOff + (strIdx + 1) * 4 > dex.byteLength) return ""
    const dataOff = view.getUint32(stringIdsOff + strIdx * 4, true)
    if (dataOff >= dex.byteLength) return ""
    const { next } = readUleb128(dex, dataOff)
    let end = next
    while (end < dex.byteLength && dex[end] !== 0 && end - next < 256) end++
    return new TextDecoder("utf-8", { fatal: false }).decode(dex.subarray(next, end))
  }

  const readTypeDesc = (typeIdx: number): string => {
    if (typeIdx >= typeIdsSize || typeIdsOff + (typeIdx + 1) * 4 > dex.byteLength) return ""
    const descStrIdx = view.getUint32(typeIdsOff + typeIdx * 4, true)
    return readDexString(descStrIdx)
  }

  const classes: string[] = []
  for (let t = 0; t < Math.min(typeIdsSize, 400) && classes.length < 60; t++) {
    const desc = readTypeDesc(t)
    if (desc.startsWith("L") && desc.endsWith(";") && !desc.startsWith("Ljava/") && !desc.startsWith("Landroid/")) {
      classes.push(desc.slice(1, -1).replace(/\//g, "."))
    }
  }

  const methods: string[] = []
  for (let m = 0; m < Math.min(methodIdsSize, 300) && methods.length < 50; m++) {
    if (methodIdsOff + (m + 1) * 8 > dex.byteLength) break
    const classIdx = view.getUint16(methodIdsOff + m * 8, true)
    const nameIdx = view.getUint32(methodIdsOff + m * 8 + 4, true)
    const cls = readTypeDesc(classIdx)
    const mName = readDexString(nameIdx)
    if (cls && mName && !cls.startsWith("Ljava/")) {
      const prettyCls = cls.startsWith("L") && cls.endsWith(";") ? cls.slice(1, -1).replace(/\//g, ".") : cls
      methods.push(`${prettyCls}#${mName}()`)
    }
  }

  return {
    dexVersion,
    stringCount: stringIdsSize,
    typeCount: typeIdsSize,
    methodCount: methodIdsSize,
    classCount: classDefsSize,
    discoveredClasses: classes,
    discoveredMethods: methods,
  }
}

export class MobileArtifactTriageExecutor implements CyberLabExecutor {
  readonly id = "mobile-artifact-triage-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string }> {
    return { available: true, version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(MobileArtifactTriageInputSchema)(input)
      if (decoded.artifactPath.includes("\0")) return { valid: false, errors: ["Null byte in artifactPath"] }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(MobileArtifactTriageInputSchema)(execInput.input)
    if (!isPathInsideRoot(params.artifactPath, ctx.workspaceRoot)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `artifactPath "${params.artifactPath}" escapes workspaceRoot`,
        exitCode: 2,
      }
    }

    const fullPath = path.resolve(ctx.workspaceRoot, params.artifactPath)
    const st = statSync(fullPath, { throwIfNoEntry: false })
    if (!st || !st.isFile()) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Mobile artifact not found: ${params.artifactPath}`,
        exitCode: 2,
      }
    }
    if (st.size > 64 * 1024 * 1024) {
      return { status: "failed", evidenceIds: [], summary: "Artifact exceeds 64 MiB limit", exitCode: 2 }
    }

    const buf = new Uint8Array(readFileSync(fullPath))
    const sha256 = createHash("sha256").update(buf).digest("hex")
    const isZip = buf.byteLength >= 4 && buf[0] === 0x50 && buf[1] === 0x4b
    const zipEntries = isZip ? parseZipCentralDirectoryEntries(buf) : []

    const zipSlipPaths = zipEntries.filter((e) => e.name.includes("..") || e.name.startsWith("/")).map((e) => e.name)
    const nativeLibraries = zipEntries.filter((e) => e.name.endsWith(".so") || e.name.endsWith(".dylib")).map((e) => e.name)
    const dexFiles = zipEntries.filter((e) => /^classes\d*\.dex$/.test(e.name)).map((e) => e.name)
    const signingFiles = zipEntries.filter((e) => /^META-INF\/.*\.(RSA|DSA|EC|SF)$/i.test(e.name)).map((e) => e.name)

    // Scan printable ASCII & UTF-16LE text inside package/backup for Android permissions, cleartext URLs, and IoCs
    // Break on ZIP record magic ("PK\x03\x04", "PK\x01\x02", "PK\x05\x06") and non-printable boundaries so uncompressed entry tails never fuse into "PK".
    const asciiText = new TextDecoder("latin1").decode(buf).replace(/PK[\x01-\x06][\x02-\x06]/g, " ")
    const utf16Normalized = asciiText
      .replace(/([\x20-\x7e])\0(?=[\x20-\x7e])/g, "$1")
      .replace(/[^\x20-\x7e]+/g, " ")

    const detectedPermissions = HIGH_RISK_ANDROID_PERMISSIONS.filter(
      (perm) => asciiText.includes(perm) || utf16Normalized.includes(perm),
    )

    const urlMatches = Array.from(
      new Set((utf16Normalized.match(/https?:\/\/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=-]{4,140}/g) ?? []).slice(0, 60)),
    )
    const cleartextHttpUrls = urlMatches.filter((u) => u.startsWith("http://"))

    const iocHits = (params.iocDomains ?? []).filter((domain) => {
      const lower = domain.toLowerCase()
      return utf16Normalized.toLowerCase().includes(lower)
    })

    const platformKind = zipEntries.some((e) => e.name === "AndroidManifest.xml")
      ? "android_apk"
      : zipEntries.some((e) => e.name.includes(".app/Info.plist"))
        ? "ios_ipa"
        : isZip
          ? "zip_backup"
          : buf.byteLength >= 8 && buf[0] === 0x64 && buf[1] === 0x65 && buf[2] === 0x78
            ? "android_dex"
            : "raw_mobile_artifact"

    let dalvikDexAnalysis: ReturnType<typeof inspectDalvikDexBytes> = null
    if (platformKind === "android_dex") {
      dalvikDexAnalysis = inspectDalvikDexBytes(buf)
    } else {
      const primaryDexEntry = zipEntries.find((e) => e.name === "classes.dex") ?? zipEntries.find((e) => /^classes\d*\.dex$/.test(e.name))
      if (primaryDexEntry) {
        const dexBytes = readZipEntryBytesSafe(buf, primaryDexEntry)
        if (dexBytes) {
          dalvikDexAnalysis = inspectDalvikDexBytes(dexBytes)
        }
      }
    }

    const report = {
      artifactPath: params.artifactPath,
      platformKind,
      byteLength: buf.byteLength,
      sha256,
      archiveEntryCount: zipEntries.length,
      dexFiles,
      dalvikDexAnalysis,
      nativeLibraries,
      signingFiles,
      zipSlipPaths,
      detectedHighRiskPermissions: detectedPermissions,
      cleartextHttpUrls,
      allExtractedUrls: urlMatches,
      iocHits,
    }

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "json",
        title: `Mobile Forensics Triage ${path.basename(params.artifactPath)} (${platformKind})`,
        rawText: JSON.stringify(report, null, 2),
        mediaType: "application/json",
        toolId: "cyberlab-mobile-triage",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["mobile-forensics", platformKind],
      }),
    )

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `Triaged ${params.artifactPath} [${platformKind}, entries=${zipEntries.length}, highRiskPerms=${detectedPermissions.length}, iocHits=${iocHits.length}].`,
      exitCode: 0,
    }
  }
}
