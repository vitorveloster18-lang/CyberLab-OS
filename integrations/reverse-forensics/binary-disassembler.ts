import { existsSync, lstatSync, readFileSync } from "node:fs"
import path from "node:path"
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

export const BINARY_DISASM_INPUT_SCHEMA_ID = "cyberlab.binary-disasm.input.v1"
export const BINARY_DISASM_OUTPUT_SCHEMA_ID = "cyberlab.binary-disasm.output.v1"

export const BinaryDisasmInputSchema = Schema.Struct({
  binaryPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  architecture: Schema.optionalKey(Schema.Literals(["auto", "x86_64", "arm64"])),
  startOffsetHex: Schema.optionalKey(
    Schema.String.check(Schema.isMaxLength(20), Schema.isPattern(/^(0x)?[0-9a-fA-F]*$/)),
  ),
  maxInstructions: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(8), Schema.isLessThanOrEqualTo(256)),
  ),
})

export type BinaryDisasmInput = typeof BinaryDisasmInputSchema.Type

export const BinaryDisasmCapability: CapabilityDefinition = {
  id: "reverse-engineering.binary-disasm",
  version: "1.0.0",
  title: "Native Multi-Arch Static Disassembler (x86_64 & ARM64 / ELF, PE, Mach-O)",
  description:
    "Disassembles executable code sections (.text / entrypoint) and resolves symbol table entries offline in pure TypeScript for x86_64 and ARM64 binaries without external native dependencies.",
  inputSchemaId: BINARY_DISASM_INPUT_SCHEMA_ID,
  outputSchemaId: BINARY_DISASM_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "binary-disassembler-executor",
  skillIds: ["reverse-engineering", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

const X64_REGS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

export interface DecodedInstruction {
  addressHex: string
  fileOffsetHex: string
  bytesHex: string
  mnemonic: string
  operands: string
  comment?: string
}

function decodeX86_64Slice(
  code: Buffer,
  baseVa: bigint,
  baseFileOffset: number,
  maxInsns: number,
  symbolsByVa: Map<bigint, string>,
): DecodedInstruction[] {
  const out: DecodedInstruction[] = []
  let i = 0
  const hexAddr = (va: bigint) => `0x${va.toString(16).padStart(8, "0")}`

  while (i < code.length && out.length < maxInsns) {
    const start = i
    const va = baseVa + BigInt(start)
    let rexW = false
    let rexR = 0
    let rexB = 0

    if (code[i]! >= 0x40 && code[i]! <= 0x4f && i + 1 < code.length) {
      const rex = code[i]!
      rexW = (rex & 0x08) !== 0
      rexR = (rex & 0x04) !== 0 ? 8 : 0
      rexB = (rex & 0x01) !== 0 ? 8 : 0
      i++
    }

    const op = code[i]!
    let mnemonic = "db"
    let operands = `0x${op.toString(16).padStart(2, "0")}`
    let comment: string | undefined

    if (op === 0xf3 && code[i + 1] === 0x0f && code[i + 2] === 0x1e && code[i + 3] === 0xfa) {
      mnemonic = "endbr64"
      operands = ""
      i += 4
    } else if (op === 0x90) {
      mnemonic = "nop"
      operands = ""
      i += 1
    } else if (op === 0xc3) {
      mnemonic = "ret"
      operands = ""
      i += 1
    } else if (op === 0xcc) {
      mnemonic = "int3"
      operands = ""
      i += 1
    } else if (op === 0xc9) {
      mnemonic = "leave"
      operands = ""
      i += 1
    } else if (op === 0x0f && code[i + 1] === 0x05) {
      mnemonic = "syscall"
      operands = ""
      comment = "Linux x86_64 kernel syscall"
      i += 2
    } else if (op >= 0x50 && op <= 0x57) {
      mnemonic = "push"
      operands = X64_REGS[(op - 0x50) + rexB]!
      i += 1
    } else if (op >= 0x58 && op <= 0x5f) {
      mnemonic = "pop"
      operands = X64_REGS[(op - 0x58) + rexB]!
      i += 1
    } else if (op >= 0xb8 && op <= 0xbf && rexW && i + 9 <= code.length) {
      const reg = X64_REGS[(op - 0xb8) + rexB]!
      const imm64 = code.readBigUInt64LE(i + 1)
      mnemonic = "movabs"
      operands = `${reg}, 0x${imm64.toString(16)}`
      i += 9
    } else if (op >= 0xb8 && op <= 0xbf && !rexW && i + 5 <= code.length) {
      const reg = X64_REGS[(op - 0xb8) + rexB]!.replace(/^r([a-d]x|[sb]p|[sd]i)$/, "e$1")
      const imm32 = code.readUInt32LE(i + 1)
      mnemonic = "mov"
      operands = `${reg}, 0x${imm32.toString(16)}`
      i += 5
    } else if (op === 0x89 && i + 2 <= code.length && (code[i + 1]! & 0xc0) === 0xc0) {
      const modrm = code[i + 1]!
      const src = X64_REGS[((modrm >> 3) & 7) + rexR]!
      const dst = X64_REGS[(modrm & 7) + rexB]!
      mnemonic = "mov"
      operands = `${dst}, ${src}`
      i += 2
    } else if (op === 0x8b && i + 2 <= code.length && (code[i + 1]! & 0xc0) === 0xc0) {
      const modrm = code[i + 1]!
      const dst = X64_REGS[((modrm >> 3) & 7) + rexR]!
      const src = X64_REGS[(modrm & 7) + rexB]!
      mnemonic = "mov"
      operands = `${dst}, ${src}`
      i += 2
    } else if (op === 0x8d && i + 6 <= code.length && (code[i + 1]! & 0xc7) === 0x05) {
      const modrm = code[i + 1]!
      const dst = X64_REGS[((modrm >> 3) & 7) + rexR]!
      const disp = code.readInt32LE(i + 2)
      const nextVa = va + BigInt(i - start + 6)
      const targetVa = nextVa + BigInt(disp)
      mnemonic = "lea"
      operands = `${dst}, [rip + 0x${disp >= 0 ? disp.toString(16) : `(${disp})`}]`
      comment = `target=${hexAddr(targetVa)}${symbolsByVa.has(targetVa) ? ` <${symbolsByVa.get(targetVa)}>` : ""}`
      i += 6
    } else if (op === 0x31 && i + 2 <= code.length && (code[i + 1]! & 0xc0) === 0xc0) {
      const modrm = code[i + 1]!
      const src = X64_REGS[((modrm >> 3) & 7) + rexR]!
      const dst = X64_REGS[(modrm & 7) + rexB]!
      mnemonic = "xor"
      operands = `${dst}, ${src}`
      i += 2
    } else if (op === 0x83 && i + 3 <= code.length && (code[i + 1]! & 0xc0) === 0xc0) {
      const modrm = code[i + 1]!
      const subop = (modrm >> 3) & 7
      const dst = X64_REGS[(modrm & 7) + rexB]!
      const imm8 = code.readInt8(i + 2)
      const names = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
      mnemonic = names[subop]!
      operands = `${dst}, ${imm8 >= 0 ? `0x${imm8.toString(16)}` : `-0x${Math.abs(imm8).toString(16)}`}`
      i += 3
    } else if (op === 0x81 && i + 6 <= code.length && (code[i + 1]! & 0xc0) === 0xc0) {
      const modrm = code[i + 1]!
      const subop = (modrm >> 3) & 7
      const dst = X64_REGS[(modrm & 7) + rexB]!
      const imm32 = code.readInt32LE(i + 2)
      const names = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
      mnemonic = names[subop]!
      operands = `${dst}, 0x${(imm32 >>> 0).toString(16)}`
      i += 6
    } else if ((op === 0xe8 || op === 0xe9) && i + 5 <= code.length) {
      const rel32 = code.readInt32LE(i + 1)
      const nextVa = va + BigInt(i - start + 5)
      const targetVa = nextVa + BigInt(rel32)
      mnemonic = op === 0xe8 ? "call" : "jmp"
      operands = hexAddr(targetVa)
      if (symbolsByVa.has(targetVa)) comment = `<${symbolsByVa.get(targetVa)}>`
      i += 5
    } else if (op === 0xeb && i + 2 <= code.length) {
      const rel8 = code.readInt8(i + 1)
      const targetVa = va + BigInt(i - start + 2 + rel8)
      mnemonic = "jmp"
      operands = hexAddr(targetVa)
      i += 2
    } else if (op >= 0x70 && op <= 0x7f && i + 2 <= code.length) {
      const jcc = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]
      const rel8 = code.readInt8(i + 1)
      const targetVa = va + BigInt(i - start + 2 + rel8)
      mnemonic = jcc[op - 0x70]!
      operands = hexAddr(targetVa)
      i += 2
    } else {
      mnemonic = "db"
      operands = `0x${code[start]!.toString(16).padStart(2, "0")}`
      i = start + 1
    }

    const slice = code.subarray(start, i)
    const symHere = symbolsByVa.get(va)
    out.push({
      addressHex: symHere ? `${hexAddr(va)} <${symHere}>` : hexAddr(va),
      fileOffsetHex: `0x${(baseFileOffset + start).toString(16).padStart(6, "0")}`,
      bytesHex: Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join(" "),
      mnemonic,
      operands,
      ...(comment ? { comment } : {}),
    })
  }

  return out
}

function decodeArm64Slice(
  code: Buffer,
  baseVa: bigint,
  baseFileOffset: number,
  maxInsns: number,
  symbolsByVa: Map<bigint, string>,
): DecodedInstruction[] {
  const out: DecodedInstruction[] = []
  const regName = (r: number, is64 = true) => (r === 31 ? (is64 ? "sp/xzr" : "wzr") : `${is64 ? "x" : "w"}${r}`)
  const hexAddr = (va: bigint) => `0x${va.toString(16).padStart(8, "0")}`

  for (let off = 0; off + 4 <= code.length && out.length < maxInsns; off += 4) {
    const insn = code.readUInt32LE(off)
    const va = baseVa + BigInt(off)
    let mnemonic = ".word"
    let operands = `0x${insn.toString(16).padStart(8, "0")}`
    let comment: string | undefined

    if (insn === 0xd503201f) {
      mnemonic = "nop"
      operands = ""
    } else if (insn === 0xd503233f) {
      mnemonic = "pacibsp"
      operands = ""
    } else if (insn === 0xd65f03c0) {
      mnemonic = "ret"
      operands = ""
    } else if ((insn & 0xffe0001f) === 0xd4000001) {
      const imm16 = (insn >>> 5) & 0xffff
      mnemonic = "svc"
      operands = `#0x${imm16.toString(16)}`
      comment = "ARM64 supervisor syscall"
    } else if ((insn >>> 26) === 0b100101 || (insn >>> 26) === 0b000101) {
      const isBl = (insn >>> 31) === 1
      let imm26 = insn & 0x03ff_ffff
      if (imm26 & 0x0200_0000) imm26 -= 0x0400_0000
      const targetVa = va + BigInt(imm26 * 4)
      mnemonic = isBl ? "bl" : "b"
      operands = hexAddr(targetVa)
      if (symbolsByVa.has(targetVa)) comment = `<${symbolsByVa.get(targetVa)}>`
    } else if ((insn & 0xff000010) === 0x54000000) {
      const conds = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
      let imm19 = (insn >>> 5) & 0x7ffff
      if (imm19 & 0x40000) imm19 -= 0x80000
      const cond = conds[insn & 0x0f]!
      const targetVa = va + BigInt(imm19 * 4)
      mnemonic = `b.${cond}`
      operands = hexAddr(targetVa)
    } else if ((insn & 0x7f800000) === 0x52800000) {
      const sf = (insn >>> 31) === 1
      const rd = insn & 0x1f
      const imm16 = (insn >>> 5) & 0xffff
      mnemonic = "movz"
      operands = `${regName(rd, sf)}, #0x${imm16.toString(16)}`
    } else if ((insn & 0x7f000000) === 0x11000000 || (insn & 0x7f000000) === 0x51000000) {
      const sf = (insn >>> 31) === 1
      const isSub = ((insn >>> 30) & 1) === 1
      const imm12 = (insn >>> 10) & 0xfff
      const rn = (insn >>> 5) & 0x1f
      const rd = insn & 0x1f
      mnemonic = isSub ? "sub" : "add"
      operands = `${regName(rd, sf)}, ${regName(rn, sf)}, #0x${imm12.toString(16)}`
    } else if ((insn & 0xffe0fc00) === 0xaa0003e0) {
      const rm = (insn >>> 16) & 0x1f
      const rd = insn & 0x1f
      mnemonic = "mov"
      operands = `x${rd}, x${rm}`
    } else if ((insn & 0xffc00000) === 0xa9800000 || (insn & 0xffc00000) === 0xa9000000) {
      const rt = insn & 0x1f
      const rn = (insn >>> 5) & 0x1f
      const rt2 = (insn >>> 10) & 0x1f
      mnemonic = "stp"
      operands = `x${rt}, x${rt2}, [${rn === 31 ? "sp" : `x${rn}`}]`
    } else if ((insn & 0xffc00000) === 0xa8c00000 || (insn & 0xffc00000) === 0xa9400000) {
      const rt = insn & 0x1f
      const rn = (insn >>> 5) & 0x1f
      const rt2 = (insn >>> 10) & 0x1f
      mnemonic = "ldp"
      operands = `x${rt}, x${rt2}, [${rn === 31 ? "sp" : `x${rn}`}]`
    }

    const bytes = code.subarray(off, off + 4)
    const symHere = symbolsByVa.get(va)
    out.push({
      addressHex: symHere ? `${hexAddr(va)} <${symHere}>` : hexAddr(va),
      fileOffsetHex: `0x${(baseFileOffset + off).toString(16).padStart(6, "0")}`,
      bytesHex: Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" "),
      mnemonic,
      operands,
      ...(comment ? { comment } : {}),
    })
  }

  return out
}

interface BinaryCodeLocator {
  format: string
  detectedArch: "x86_64" | "arm64"
  codeOffset: number
  codeLength: number
  baseVa: bigint
  entryVa: bigint
  symbols: Array<{ name: string; addressHex: string }>
  symbolsByVa: Map<bigint, string>
}

function locateExecutableCode(buf: Buffer): BinaryCodeLocator {
  const symbols: Array<{ name: string; addressHex: string }> = []
  const symbolsByVa = new Map<bigint, string>()

  if (buf.length >= 64 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46 && buf[4] === 2 && buf[5] === 1) {
    const eMachine = buf.readUInt16LE(18)
    const detectedArch: "x86_64" | "arm64" = eMachine === 183 ? "arm64" : "x86_64"
    const entryVa = buf.readBigUInt64LE(24)
    const shOff = Number(buf.readBigUInt64LE(40))
    const shEntSize = buf.readUInt16LE(58)
    const shNum = buf.readUInt16LE(60)
    const shStrNdx = buf.readUInt16LE(62)

    let textOffset = 0
    let textLen = Math.min(buf.length, 4096)
    let textVa = entryVa

    if (shOff > 0 && shEntSize >= 64 && shOff + shNum * shEntSize <= buf.length) {
      let shStrOff = 0
      let shStrSize = 0
      if (shStrNdx < shNum) {
        const strHdr = shOff + shStrNdx * shEntSize
        shStrOff = Number(buf.readBigUInt64LE(strHdr + 24))
        shStrSize = Number(buf.readBigUInt64LE(strHdr + 32))
      }
      const readShName = (nameIdx: number) => {
        if (!shStrOff || nameIdx >= shStrSize || shStrOff + nameIdx >= buf.length) return ""
        const end = buf.indexOf(0, shStrOff + nameIdx)
        return buf.subarray(shStrOff + nameIdx, end === -1 ? shStrOff + shStrSize : end).toString("utf8")
      }

      for (let idx = 0; idx < shNum; idx++) {
        const h = shOff + idx * shEntSize
        const shName = readShName(buf.readUInt32LE(h))
        const shType = buf.readUInt32LE(h + 4)
        const shFlags = Number(buf.readBigUInt64LE(h + 8))
        const shAddr = buf.readBigUInt64LE(h + 16)
        const secOff = Number(buf.readBigUInt64LE(h + 24))
        const secSize = Number(buf.readBigUInt64LE(h + 32))
        const shLink = buf.readUInt32LE(h + 40)

        if ((shName === ".text" || (textOffset === 0 && (shFlags & 0x4) !== 0)) && secOff + secSize <= buf.length && secSize > 0) {
          textOffset = secOff
          textLen = secSize
          textVa = shAddr
        }

        if ((shType === 2 || shType === 11) && shLink < shNum && secOff + secSize <= buf.length) {
          const strSecHdr = shOff + shLink * shEntSize
          const symStrOff = Number(buf.readBigUInt64LE(strSecHdr + 24))
          const symStrSize = Number(buf.readBigUInt64LE(strSecHdr + 32))
          for (let sPos = secOff; sPos + 24 <= secOff + secSize && symbols.length < 80; sPos += 24) {
            const stName = buf.readUInt32LE(sPos)
            const stValue = buf.readBigUInt64LE(sPos + 8)
            if (stValue > 0n && symStrOff + stName < buf.length && stName < symStrSize) {
              const nul = buf.indexOf(0, symStrOff + stName)
              const name = buf
                .subarray(symStrOff + stName, nul === -1 ? symStrOff + symStrSize : nul)
                .toString("utf8")
              if (name) {
                symbolsByVa.set(stValue, name)
                symbols.push({ name, addressHex: `0x${stValue.toString(16)}` })
              }
            }
          }
        }
      }
    }

    // Fallback for stripped / sectionless ELF64 binaries: map e_entry via PT_LOAD program headers
    if (textOffset === 0) {
      const phOff = Number(buf.readBigUInt64LE(32))
      const phEntSize = buf.readUInt16LE(54)
      const phNum = buf.readUInt16LE(56)
      if (phOff > 0 && phEntSize >= 56 && phOff + phNum * phEntSize <= buf.length) {
        for (let idx = 0; idx < phNum; idx++) {
          const ph = phOff + idx * phEntSize
          const pType = buf.readUInt32LE(ph)
          const pFlags = buf.readUInt32LE(ph + 4)
          const pOffset = Number(buf.readBigUInt64LE(ph + 8))
          const pVaddr = buf.readBigUInt64LE(ph + 16)
          const pFilesz = Number(buf.readBigUInt64LE(ph + 32))
          if (
            pType === 1 &&
            pFilesz > 0 &&
            pOffset + pFilesz <= buf.length &&
            ((entryVa >= pVaddr && entryVa < pVaddr + BigInt(pFilesz)) || (pFlags & 0x1) !== 0)
          ) {
            textOffset = pOffset
            textLen = pFilesz
            textVa = pVaddr
            if (entryVa >= pVaddr && entryVa < pVaddr + BigInt(pFilesz)) break
          }
        }
      }
    }

    if (entryVa >= textVa && entryVa < textVa + BigInt(textLen)) {
      const delta = Number(entryVa - textVa)
      textOffset += delta
      textLen -= delta
      textVa = entryVa
    }

    return {
      format: "ELF64",
      detectedArch,
      codeOffset: textOffset,
      codeLength: textLen,
      baseVa: textVa,
      entryVa,
      symbols,
      symbolsByVa,
    }
  }

  if (buf.length >= 128 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const peOff = buf.readUInt32LE(0x3c)
    if (peOff + 24 < buf.length && buf.subarray(peOff, peOff + 4).toString("ascii") === "PE\0\0") {
      const machine = buf.readUInt16LE(peOff + 4)
      const numSecs = buf.readUInt16LE(peOff + 6)
      const optHdrSize = buf.readUInt16LE(peOff + 20)
      const detectedArch: "x86_64" | "arm64" = machine === 0xaa64 ? "arm64" : "x86_64"
      const optOff = peOff + 24
      const entryRva = optOff + 20 <= buf.length ? buf.readUInt32LE(optOff + 16) : 0
      const secTable = optOff + optHdrSize
      for (let s = 0; s < numSecs && secTable + (s + 1) * 40 <= buf.length; s++) {
        const sh = secTable + s * 40
        const name = buf.subarray(sh, sh + 8).toString("ascii").replace(/\0+$/, "")
        const vAddr = buf.readUInt32LE(sh + 12)
        const rawSize = buf.readUInt32LE(sh + 16)
        const rawPtr = buf.readUInt32LE(sh + 20)
        if ((name === ".text" || s === 0) && rawPtr + rawSize <= buf.length && rawSize > 0) {
          return {
            format: "PE/COFF",
            detectedArch,
            codeOffset: rawPtr,
            codeLength: rawSize,
            baseVa: BigInt(0x140000000) + BigInt(vAddr),
            entryVa: BigInt(0x140000000) + BigInt(entryRva),
            symbols,
            symbolsByVa,
          }
        }
      }
    }
  }

  if (buf.length >= 32 && buf.readUInt32LE(0) === 0xfeedfacf) {
    const cpuType = buf.readUInt32LE(4)
    const detectedArch: "x86_64" | "arm64" = cpuType === 0x0100000c ? "arm64" : "x86_64"
    return {
      format: "Mach-O 64",
      detectedArch,
      codeOffset: Math.min(256, Math.max(0, buf.length - 64)),
      codeLength: Math.max(0, buf.length - Math.min(256, buf.length)),
      baseVa: 0x100000000n,
      entryVa: 0x100000000n,
      symbols,
      symbolsByVa,
    }
  }

  return {
    format: "Raw Binary Slice",
    detectedArch: "x86_64",
    codeOffset: 0,
    codeLength: buf.length,
    baseVa: 0x400000n,
    entryVa: 0x400000n,
    symbols,
    symbolsByVa,
  }
}

export class BinaryDisassemblerExecutor implements CyberLabExecutor {
  readonly id = "binary-disassembler-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      Schema.decodeUnknownSync(BinaryDisasmInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, context: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(BinaryDisasmInputSchema)(req.input)
    if (!isPathInsideRoot(parsed.binaryPath, context.workspaceRoot)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Path "${parsed.binaryPath}" escapes workspace confinement`,
        exitCode: 2,
      }
    }
    const resolved = path.resolve(context.workspaceRoot, parsed.binaryPath)
    if (!existsSync(resolved)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Binary file not found: ${parsed.binaryPath}`,
        exitCode: 2,
      }
    }
    const st = lstatSync(resolved)
    if (st.isSymbolicLink() || !st.isFile()) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Refusing symbolic link or non-regular file: ${parsed.binaryPath}`,
        exitCode: 2,
      }
    }
    if (st.size > 32 * 1024 * 1024) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Binary exceeds 32 MB offline disassembly safety cap (${st.size} bytes)`,
        exitCode: 2,
      }
    }

    const buf = readFileSync(resolved)
    const loc = locateExecutableCode(buf)
    const arch = !parsed.architecture || parsed.architecture === "auto" ? loc.detectedArch : parsed.architecture
    const maxInsns = parsed.maxInstructions ?? 64

    let startOffset = loc.codeOffset
    let baseVa = loc.baseVa
    if (parsed.startOffsetHex && parsed.startOffsetHex.trim()) {
      const manual = parseInt(parsed.startOffsetHex.trim().replace(/^0x/i, ""), 16)
      if (!Number.isNaN(manual) && manual >= 0 && manual < buf.length) {
        startOffset = manual
        baseVa = BigInt(manual)
      }
    }

    const slice = buf.subarray(startOffset, Math.min(buf.length, startOffset + maxInsns * 16))
    const instructions =
      arch === "arm64"
        ? decodeArm64Slice(slice, baseVa, startOffset, maxInsns, loc.symbolsByVa)
        : decodeX86_64Slice(slice, baseVa, startOffset, maxInsns, loc.symbolsByVa)

    const formattedListing = instructions
      .map(
        (ins) =>
          `${ins.addressHex.padEnd(22)} | ${ins.bytesHex.padEnd(24)} | ${ins.mnemonic.padEnd(8)} ${ins.operands}${
            ins.comment ? `   ; ${ins.comment}` : ""
          }`,
      )
      .join("\n")

    const report = {
      binaryPath: parsed.binaryPath,
      fileBytes: buf.length,
      detectedFormat: loc.format,
      architecture: arch,
      entryPointHex: `0x${loc.entryVa.toString(16)}`,
      disassemblyOffsetHex: `0x${startOffset.toString(16)}`,
      instructionCount: instructions.length,
      discoveredSymbols: loc.symbols.slice(0, 40),
      listingText: formattedListing,
      instructions,
    }

    const redacted = redactSensitiveContent(
      `=== DISASSEMBLY: ${parsed.binaryPath} (${loc.format} / ${arch}) ===\n${formattedListing}\n\n=== JSON ===\n${JSON.stringify(
        report,
        null,
        2,
      )}`,
    )

    const evId = await context.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "stdout",
        title: `Static Disassembly (${arch}) ${parsed.binaryPath}`,
        rawText: redacted.text,
        mediaType: "text/plain; charset=utf-8",
        toolId: "cyberlab-binary-disassembler",
        toolVersion: this.version,
        executorId: this.id,
        executionId: context.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["disassembly", `arch:${arch}`, `format:${loc.format}`],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `Disassembly estático (${loc.format} / ${arch}) decodificou ${instructions.length} instruções e ${loc.symbols.length} símbolo(s) em ${parsed.binaryPath}.`,
      exitCode: 0,
    }
  }
}
