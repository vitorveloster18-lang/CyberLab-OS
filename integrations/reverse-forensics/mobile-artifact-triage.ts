import { createHash } from "node:crypto"
import { readFileSync, statSync } from "node:fs"
import path from "node:path"
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

function parseZipCentralDirectoryEntries(buf: Uint8Array): Array<{ name: string; compressedSize: number; uncompressedSize: number }> {
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
  const entries: Array<{ name: string; compressedSize: number; uncompressedSize: number }> = []

  let pos = cdOffset
  for (let idx = 0; idx < Math.min(totalEntries, 5_000) && pos + 46 <= buf.byteLength; idx++) {
    if (view.getUint32(pos, true) !== 0x02014b50) break
    const compSize = view.getUint32(pos + 20, true)
    const uncompSize = view.getUint32(pos + 24, true)
    const nameLen = view.getUint16(pos + 28, true)
    const extraLen = view.getUint16(pos + 30, true)
    const commentLen = view.getUint16(pos + 32, true)
    if (pos + 46 + nameLen > buf.byteLength) break
    const name = new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(pos + 46, pos + 46 + nameLen))
    entries.push({ name, compressedSize: compSize, uncompressedSize: uncompSize })
    pos += 46 + nameLen + extraLen + commentLen
  }
  return entries
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
          : "raw_mobile_artifact"

    const report = {
      artifactPath: params.artifactPath,
      platformKind,
      byteLength: buf.byteLength,
      sha256,
      archiveEntryCount: zipEntries.length,
      dexFiles,
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
