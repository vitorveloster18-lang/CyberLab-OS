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

export const BINARY_TRIAGE_INPUT_SCHEMA_ID = "cyberlab.binary-triage.input.v1"
export const BINARY_TRIAGE_OUTPUT_SCHEMA_ID = "cyberlab.binary-triage.output.v1"

export const BinaryStaticTriageInputSchema = Schema.Struct({
  binaryPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  minStringLength: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(4), Schema.isLessThanOrEqualTo(64))),
  maxStrings: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(10), Schema.isLessThanOrEqualTo(500))),
})

export type BinaryStaticTriageInput = typeof BinaryStaticTriageInputSchema.Type

export const BinaryStaticTriageCapability: CapabilityDefinition = {
  id: "reverse-engineering.binary-triage",
  version: "1.0.0",
  title: "Native ELF / PE / Mach-O Binary Static Triage & Entropy Analyzer",
  description:
    "Performs safe offline static reverse-engineering triage of ELF, Windows PE/COFF, and Mach-O binaries inside the workspace: computes SHA-256, parses architecture/headers/sections, detects high-entropy packed sections, checks NX/PIE/ASLR hardening flags, and extracts suspicious strings/IoCs without executing the sample.",
  inputSchemaId: BINARY_TRIAGE_INPUT_SCHEMA_ID,
  outputSchemaId: BINARY_TRIAGE_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "binary-static-triage-executor",
  skillIds: ["reverse-engineering", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

function computeByteEntropy(bytes: Uint8Array): number {
  if (bytes.byteLength === 0) return 0
  const counts = new Uint32Array(256)
  for (let i = 0; i < bytes.byteLength; i++) {
    counts[bytes[i]!]!++
  }
  let entropy = 0
  for (let i = 0; i < 256; i++) {
    const c = counts[i]!
    if (c > 0) {
      const p = c / bytes.byteLength
      entropy -= p * Math.log2(p)
    }
  }
  return Number(entropy.toFixed(4))
}

function parseElfMetadata(buf: Uint8Array) {
  if (buf.byteLength < 64) return { format: "ELF (truncated)" }
  const is64 = buf[4] === 2
  const littleEndian = buf[5] === 1
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  const eType = view.getUint16(16, littleEndian)
  const eMachine = view.getUint16(18, littleEndian)

  const typeMap: Record<number, string> = {
    1: "REL (Relocatable)",
    2: "EXEC (Executable, non-PIE)",
    3: "DYN (Shared Object / PIE Executable)",
    4: "CORE",
  }
  const machineMap: Record<number, string> = {
    3: "x86 (i386)",
    40: "ARM",
    62: "x86_64 (AMD64)",
    183: "AArch64 (ARM64)",
    243: "RISC-V",
  }

  const entryPoint = is64
    ? `0x${view.getBigUint64(24, littleEndian).toString(16)}`
    : `0x${view.getUint32(24, littleEndian).toString(16)}`

  // Check PT_GNU_STACK (0x6474e551) for NX enforcement
  let nxEnabled: boolean | null = null
  const phOff = is64 ? Number(view.getBigUint64(32, littleEndian)) : view.getUint32(28, littleEndian)
  const phEntSize = view.getUint16(is64 ? 54 : 42, littleEndian)
  const phNum = view.getUint16(is64 ? 56 : 44, littleEndian)
  if (phOff > 0 && phEntSize >= 32 && phNum < 128 && phOff + phEntSize * phNum <= buf.byteLength) {
    for (let i = 0; i < phNum; i++) {
      const base = phOff + i * phEntSize
      const pType = view.getUint32(base, littleEndian)
      if (pType === 0x6474e551) {
        const pFlags = view.getUint32(is64 ? base + 4 : base + 24, littleEndian)
        nxEnabled = (pFlags & 0x1) === 0 // PF_X == 1 means executable stack
      }
    }
  }

  return {
    format: is64 ? "ELF64" : "ELF32",
    endianness: littleEndian ? "little" : "big",
    elfType: typeMap[eType] ?? `unknown(${eType})`,
    architecture: machineMap[eMachine] ?? `machine(${eMachine})`,
    entryPoint,
    hardening: {
      pieCandidate: eType === 3,
      nxStackEnabled: nxEnabled,
    },
  }
}

function parsePeMetadata(buf: Uint8Array) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  if (buf.byteLength < 0x40) return { format: "MZ/DOS (truncated)" }
  const peOffset = view.getUint32(0x3c, true)
  if (peOffset + 24 > buf.byteLength) return { format: "MZ/DOS" }
  if (
    buf[peOffset] !== 0x50 ||
    buf[peOffset + 1] !== 0x45 ||
    buf[peOffset + 2] !== 0x00 ||
    buf[peOffset + 3] !== 0x00
  ) {
    return { format: "MZ/DOS" }
  }

  const machine = view.getUint16(peOffset + 4, true)
  const numSections = view.getUint16(peOffset + 6, true)
  const optHeaderSize = view.getUint16(peOffset + 20, true)
  const optOffset = peOffset + 24

  const machineMap: Record<number, string> = {
    0x014c: "x86 (I386)",
    0x8664: "x86_64 (AMD64)",
    0xaa64: "ARM64",
  }

  let isPe32Plus = false
  let aslr = false
  let depNx = false
  if (optOffset + 72 <= buf.byteLength && optHeaderSize >= 72) {
    const magic = view.getUint16(optOffset, true)
    isPe32Plus = magic === 0x20b
    const dllChars = view.getUint16(optOffset + 70, true)
    aslr = (dllChars & 0x0040) !== 0 // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    depNx = (dllChars & 0x0100) !== 0 // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
  }

  const sectionTableOffset = optOffset + optHeaderSize
  const sections: Array<{ name: string; rawSize: number; entropy: number; packedSuspect: boolean }> = []
  for (let i = 0; i < Math.min(numSections, 32); i++) {
    const sOff = sectionTableOffset + i * 40
    if (sOff + 40 > buf.byteLength) break
    const nameBytes = buf.subarray(sOff, sOff + 8)
    const zeroIdx = nameBytes.indexOf(0)
    const name = new TextDecoder("ascii", { fatal: false }).decode(
      zeroIdx === -1 ? nameBytes : nameBytes.subarray(0, zeroIdx),
    )
    const rawSize = view.getUint32(sOff + 16, true)
    const rawPtr = view.getUint32(sOff + 20, true)
    let secEntropy = 0
    if (rawSize > 0 && rawPtr + rawSize <= buf.byteLength) {
      secEntropy = computeByteEntropy(buf.subarray(rawPtr, rawPtr + rawSize))
    }
    sections.push({
      name,
      rawSize,
      entropy: secEntropy,
      packedSuspect: secEntropy > 7.2 || /upx|packed|vmp/i.test(name),
    })
  }

  return {
    format: isPe32Plus ? "PE32+ (64-bit)" : "PE32 (32-bit)",
    architecture: machineMap[machine] ?? `0x${machine.toString(16)}`,
    hardening: { aslr, depNx },
    sections,
  }
}

function extractPrintableAsciiStrings(buf: Uint8Array, minLen: number, maxStrings: number): string[] {
  const results: string[] = []
  let start = -1
  for (let i = 0; i < buf.byteLength && results.length < maxStrings; i++) {
    const b = buf[i]!
    const printable = b >= 0x20 && b <= 0x7e
    if (printable) {
      if (start === -1) start = i
    } else if (start !== -1) {
      if (i - start >= minLen) {
        results.push(new TextDecoder("ascii").decode(buf.subarray(start, Math.min(i, start + 240))))
      }
      start = -1
    }
  }
  if (start !== -1 && buf.byteLength - start >= minLen && results.length < maxStrings) {
    results.push(new TextDecoder("ascii").decode(buf.subarray(start, Math.min(buf.byteLength, start + 240))))
  }
  return results
}

export class BinaryStaticTriageExecutor implements CyberLabExecutor {
  readonly id = "binary-static-triage-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string }> {
    return { available: true, version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(BinaryStaticTriageInputSchema)(input)
      if (decoded.binaryPath.includes("\0")) return { valid: false, errors: ["Null byte in binaryPath"] }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(BinaryStaticTriageInputSchema)(execInput.input)
    if (!isPathInsideRoot(params.binaryPath, ctx.workspaceRoot)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `binaryPath "${params.binaryPath}" escapes workspaceRoot`,
        exitCode: 2,
      }
    }

    const fullPath = path.resolve(ctx.workspaceRoot, params.binaryPath)
    const st = statSync(fullPath, { throwIfNoEntry: false })
    if (!st || !st.isFile()) {
      return { status: "failed", evidenceIds: [], summary: `Binary file not found: ${params.binaryPath}`, exitCode: 2 }
    }
    if (st.size > 64 * 1024 * 1024) {
      return { status: "failed", evidenceIds: [], summary: "Binary exceeds 64 MiB static triage limit", exitCode: 2 }
    }

    const buf = new Uint8Array(readFileSync(fullPath))
    const sha256 = createHash("sha256").update(buf).digest("hex")
    const overallEntropy = computeByteEntropy(buf)

    let binaryInfo: Record<string, unknown> = { format: "Raw / Unknown Binary" }
    if (buf.byteLength >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
      binaryInfo = parseElfMetadata(buf)
    } else if (buf.byteLength >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
      binaryInfo = parsePeMetadata(buf)
    } else if (buf.byteLength >= 4) {
      const magic32 = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false)
      if (magic32 === 0xfeedfacf || magic32 === 0xcffaedfe || magic32 === 0xfeedface || magic32 === 0xcafebabe) {
        binaryInfo = { format: "Mach-O / Universal Binary" }
      }
    }

    const strings = extractPrintableAsciiStrings(buf, params.minStringLength ?? 5, params.maxStrings ?? 200)
    const urls = strings.filter((s) => /https?:\/\/[^\s"'<>]+/i.test(s))
    const ipv4s = strings.filter((s) => /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(s))
    const suspiciousApis = strings.filter((s) =>
      /\b(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|ptrace|LD_PRELOAD|\/bin\/sh|cmd\.exe|powershell|execve|system)\b/i.test(
        s,
      ),
    )

    const report = {
      binaryPath: params.binaryPath,
      byteLength: buf.byteLength,
      sha256,
      overallEntropy,
      highEntropyPackedSuspect: overallEntropy > 7.2,
      binaryInfo,
      extractedStringCount: strings.length,
      indicators: {
        urls,
        ipv4s,
        suspiciousApis,
      },
      sampleStrings: strings.slice(0, 40),
    }

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "json",
        title: `Static Binary Triage ${path.basename(params.binaryPath)} (${String(binaryInfo.format)})`,
        rawText: JSON.stringify(report, null, 2),
        mediaType: "application/json",
        toolId: "cyberlab-binary-triage",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["reverse-engineering", "binary-triage"],
      }),
    )

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `Triaged ${params.binaryPath} [${String(binaryInfo.format)}, entropy=${overallEntropy}, sha256=${sha256.slice(0, 16)}...]; suspiciousIndicators=${suspiciousApis.length + urls.length}.`,
      exitCode: 0,
    }
  }
}
