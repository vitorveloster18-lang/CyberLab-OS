import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs"
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

export const YARA_SCAN_INPUT_SCHEMA_ID = "cyberlab.yara-scan.input.v1"
export const YARA_SCAN_OUTPUT_SCHEMA_ID = "cyberlab.yara-scan.output.v1"

export const YaraScanInputSchema = Schema.Struct({
  targetPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  rulesText: Schema.String.check(Schema.isMinLength(16), Schema.isMaxLength(65_536)),
  maxFiles: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(200)),
  ),
  maxFileSizeBytes: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(1024), Schema.isLessThanOrEqualTo(16 * 1024 * 1024)),
  ),
})

export type YaraScanInput = typeof YaraScanInputSchema.Type

export const YaraScanCapability: CapabilityDefinition = {
  id: "forensics.yara-scan",
  version: "1.0.0",
  title: "Native YARA Indicator & Malware Signature Rule Scanner",
  description:
    "Parses and evaluates YARA indicator rules (ASCII, wide UTF-16LE, nocase, and wildcard hex byte patterns with boolean conditions) offline against workspace files or directories.",
  inputSchemaId: YARA_SCAN_INPUT_SCHEMA_ID,
  outputSchemaId: YARA_SCAN_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "yara-rule-scanner-executor",
  skillIds: ["reverse-engineering", "mobile-forensics", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

interface ParsedYaraPattern {
  id: string
  kind: "text" | "hex"
  rawValue: string
  nocase: boolean
  wide: boolean
  ascii: boolean
  hexBytes?: Array<number | null>
}

interface ParsedYaraRule {
  name: string
  tags: string[]
  meta: Record<string, string>
  patterns: ParsedYaraPattern[]
  conditionExpr: string
}

function parseHexSignature(hexBody: string): Array<number | null> {
  const tokens = hexBody
    .replace(/\/\/.*$/gm, "")
    .trim()
    .split(/\s+/)
    .filter(Boolean)
  const out: Array<number | null> = []
  for (const tok of tokens) {
    if (tok === "??" || tok === "?") {
      out.push(null)
    } else if (/^[0-9a-fA-F]{2}$/.test(tok)) {
      out.push(parseInt(tok, 16))
    }
  }
  return out
}

export function parseYaraRules(source: string): ParsedYaraRule[] {
  const cleaned = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "")
  const rules: ParsedYaraRule[] = []

  const headerRegex = /\brule\s+([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*:\s*([^{]+))?\s*\{/g
  let match: RegExpExecArray | null
  while ((match = headerRegex.exec(cleaned)) !== null) {
    const name = match[1]!
    const tags = match[2] ? match[2].trim().split(/\s+/).filter(Boolean) : []
    const bodyStart = headerRegex.lastIndex
    let depth = 1
    let pos = bodyStart
    let inQuotes = false
    while (pos < cleaned.length && depth > 0) {
      const ch = cleaned[pos]!
      if (ch === '"' && cleaned[pos - 1] !== "\\") {
        inQuotes = !inQuotes
      } else if (!inQuotes) {
        if (ch === "{") depth++
        else if (ch === "}") depth--
      }
      pos++
    }
    if (depth !== 0) break
    const body = cleaned.slice(bodyStart, pos - 1)
    headerRegex.lastIndex = pos

    const meta: Record<string, string> = {}
    const metaMatch = /\bmeta\s*:([\s\S]*?)(?=\bstrings\s*:|\bcondition\s*:|$)/i.exec(body)
    if (metaMatch) {
      for (const line of metaMatch[1]!.split("\n")) {
        const kv = /^\s*([a-zA-Z0-9_]+)\s*=\s*"?([^"\n]+)"?\s*$/.exec(line)
        if (kv) meta[kv[1]!] = kv[2]!.trim()
      }
    }

    const patterns: ParsedYaraPattern[] = []
    const stringsMatch = /\bstrings\s*:([\s\S]*?)(?=\bcondition\s*:|$)/i.exec(body)
    if (stringsMatch) {
      for (const line of stringsMatch[1]!.split("\n")) {
        const trimmed = line.trim()
        if (!trimmed) continue
        const textM = /^(\$[a-zA-Z0-9_]+)\s*=\s*"((?:\\.|[^"\\])*)"(.*)$/.exec(trimmed)
        if (textM) {
          const mods = textM[3]!.toLowerCase()
          const unescaped = textM[2]!
            .replace(/\\n/g, "\n")
            .replace(/\\r/g, "\r")
            .replace(/\\t/g, "\t")
            .replace(/\\"/g, '"')
            .replace(/\\\\/g, "\\")
          const wideOnly = /\bwide\b/.test(mods) && !/\bascii\b/.test(mods)
          patterns.push({
            id: textM[1]!,
            kind: "text",
            rawValue: unescaped,
            nocase: /\bnocase\b/.test(mods),
            wide: /\bwide\b/.test(mods),
            ascii: !wideOnly,
          })
          continue
        }
        const hexM = /^(\$[a-zA-Z0-9_]+)\s*=\s*\{([^}]+)\}/.exec(trimmed)
        if (hexM) {
          patterns.push({
            id: hexM[1]!,
            kind: "hex",
            rawValue: hexM[2]!.trim(),
            nocase: false,
            wide: false,
            ascii: false,
            hexBytes: parseHexSignature(hexM[2]!),
          })
        }
      }
    }

    const condMatch = /\bcondition\s*:([\s\S]*)$/i.exec(body)
    const conditionExpr = condMatch ? condMatch[1]!.trim() : "any of them"
    rules.push({ name, tags, meta, patterns, conditionExpr })
  }

  if (rules.length === 0) {
    throw new Error("Nenhuma regra válida encontrada (use sintaxe: rule Nome { strings: $a = \"...\" condition: any of them })")
  }
  return rules
}

function findBufferMatches(haystack: Buffer, pat: ParsedYaraPattern): number[] {
  const offsets: number[] = []
  if (pat.kind === "hex" && pat.hexBytes && pat.hexBytes.length > 0) {
    const seq = pat.hexBytes
    outer: for (let i = 0; i <= haystack.length - seq.length && offsets.length < 16; i++) {
      for (let j = 0; j < seq.length; j++) {
        const expected = seq[j]
        if (expected !== null && haystack[i + j] !== expected) continue outer
      }
      offsets.push(i)
    }
    return offsets
  }

  const encodings: Buffer[] = []
  if (pat.ascii) encodings.push(Buffer.from(pat.rawValue, "utf8"))
  if (pat.wide) encodings.push(Buffer.from(pat.rawValue, "utf16le"))

  if (!pat.nocase) {
    for (const needle of encodings) {
      if (needle.length === 0) continue
      let pos = 0
      while (pos <= haystack.length - needle.length && offsets.length < 16) {
        const idx = haystack.indexOf(needle, pos)
        if (idx === -1) break
        offsets.push(idx)
        pos = idx + Math.max(1, needle.length)
      }
    }
  } else {
    const lowerText = haystack.toString("latin1").toLowerCase()
    const lowerNeedle = pat.rawValue.toLowerCase()
    if (lowerNeedle.length > 0) {
      let pos = 0
      while (pos <= lowerText.length - lowerNeedle.length && offsets.length < 16) {
        const idx = lowerText.indexOf(lowerNeedle, pos)
        if (idx === -1) break
        offsets.push(idx)
        pos = idx + lowerNeedle.length
      }
    }
  }
  return offsets
}

function evaluateYaraCondition(
  expr: string,
  matchedSet: Set<string>,
  allPatternIds: string[],
  fileSize: number,
  buf: Buffer,
): boolean {
  let e = expr.trim().replace(/\s+/g, " ")
  if (/^true$/i.test(e)) return true
  if (/^false$/i.test(e)) return false

  e = e.replace(/\buint16\(\s*(\d+)\s*\)\s*==\s*0x([0-9a-fA-F]+)/g, (_m, offStr, hexVal) => {
    const off = Number(offStr)
    const val = off + 2 <= buf.length ? buf.readUInt16LE(off) : -1
    return val === parseInt(hexVal, 16) ? "true" : "false"
  })
  e = e.replace(/\buint32\(\s*(\d+)\s*\)\s*==\s*0x([0-9a-fA-F]+)/g, (_m, offStr, hexVal) => {
    const off = Number(offStr)
    const val = off + 4 <= buf.length ? buf.readUInt32LE(off) : -1
    return val === parseInt(hexVal, 16) ? "true" : "false"
  })

  e = e.replace(/\bfilesize\s*(<=|>=|<|>|==)\s*(\d+)\s*(KB|MB)?/gi, (_m, op, numStr, unit) => {
    const mult = String(unit || "").toUpperCase() === "MB" ? 1024 * 1024 : String(unit || "").toUpperCase() === "KB" ? 1024 : 1
    const limit = Number(numStr) * mult
    const ok =
      op === "<"
        ? fileSize < limit
        : op === "<="
          ? fileSize <= limit
          : op === ">"
            ? fileSize > limit
            : op === ">="
              ? fileSize >= limit
              : fileSize === limit
    return ok ? "true" : "false"
  })

  e = e.replace(/\ball\s+of\s+them\b/gi, () =>
    allPatternIds.length > 0 && allPatternIds.every((id) => matchedSet.has(id)) ? "true" : "false",
  )
  e = e.replace(/\bany\s+of\s+them\b/gi, () => (matchedSet.size > 0 ? "true" : "false"))
  e = e.replace(/\b(\d+)\s+of\s+them\b/gi, (_m, nStr) =>
    matchedSet.size >= Number(nStr) ? "true" : "false",
  )
  e = e.replace(/\b(any|all|\d+)\s+of\s*\(\s*(\$[a-zA-Z0-9_]*)\*\s*\)/gi, (_m, quant, prefix) => {
    const subset = allPatternIds.filter((id) => id.startsWith(prefix))
    const hitCount = subset.filter((id) => matchedSet.has(id)).length
    const q = String(quant).toLowerCase()
    if (q === "any") return hitCount >= 1 ? "true" : "false"
    if (q === "all") return subset.length > 0 && hitCount === subset.length ? "true" : "false"
    return hitCount >= Number(q) ? "true" : "false"
  })

  const sortedIds = [...allPatternIds].sort((a, b) => b.length - a.length)
  for (const id of sortedIds) {
    const escaped = id.replace(/\$/g, "\\$")
    e = e.replace(new RegExp(escaped, "g"), matchedSet.has(id) ? "true" : "false")
  }

  const normalized = e
    .replace(/\band\b/gi, "&&")
    .replace(/\bor\b/gi, "||")
    .replace(/\bnot\b/gi, "!")
  if (!/^[truefals&|!()\s]+$/.test(normalized)) {
    return matchedSet.size > 0
  }
  try {
    return Boolean(Function(`"use strict"; return (${normalized});`)())
  } catch {
    return matchedSet.size > 0
  }
}

const SKIP_DIRS = new Set([".git", "node_modules", ".cyberlab", "dist", "build"])

function collectFilesSafe(rootDir: string, targetAbs: string, maxFiles: number, maxSizeBytes: number): string[] {
  const out: string[] = []
  const visit = (p: string) => {
    if (out.length >= maxFiles) return
    if (!isPathInsideRoot(p, rootDir) || !existsSync(p)) return
    const st = lstatSync(p)
    if (st.isSymbolicLink()) return
    if (st.isFile()) {
      if (st.size <= maxSizeBytes) out.push(p)
      return
    }
    if (st.isDirectory()) {
      for (const entry of readdirSync(p)) {
        if (SKIP_DIRS.has(entry)) continue
        visit(path.join(p, entry))
        if (out.length >= maxFiles) break
      }
    }
  }
  visit(targetAbs)
  return out
}

export class YaraRuleScannerExecutor implements CyberLabExecutor {
  readonly id = "yara-rule-scanner-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      const parsed = Schema.decodeUnknownSync(YaraScanInputSchema)(input)
      parseYaraRules(parsed.rulesText)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, context: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(YaraScanInputSchema)(req.input)
    if (!isPathInsideRoot(parsed.targetPath, context.workspaceRoot)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Target path "${parsed.targetPath}" escapes workspace confinement`,
        exitCode: 2,
      }
    }
    const resolvedTarget = path.resolve(context.workspaceRoot, parsed.targetPath)
    if (!existsSync(resolvedTarget)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Target path not found: ${parsed.targetPath}`,
        exitCode: 2,
      }
    }

    const rules = parseYaraRules(parsed.rulesText)
    const maxFiles = parsed.maxFiles ?? 80
    const maxFileSize = parsed.maxFileSizeBytes ?? 8 * 1024 * 1024
    const files = collectFilesSafe(context.workspaceRoot, resolvedTarget, maxFiles, maxFileSize)

    const matches: Array<{
      ruleName: string
      tags: string[]
      meta: Record<string, string>
      file: string
      matchedPatterns: Array<{ patternId: string; offsetsHex: string[] }>
    }> = []

    for (const fileAbs of files) {
      if (context.signal.aborted) break
      const buf = readFileSync(fileAbs)
      const relFile = path.relative(context.workspaceRoot, fileAbs).replace(/\\/g, "/") || path.basename(fileAbs)

      for (const rule of rules) {
        const hitMap = new Map<string, number[]>()
        for (const pat of rule.patterns) {
          const offs = findBufferMatches(buf, pat)
          if (offs.length > 0) hitMap.set(pat.id, offs)
        }
        const matchedIds = new Set(hitMap.keys())
        const allIds = rule.patterns.map((p) => p.id)
        if (evaluateYaraCondition(rule.conditionExpr, matchedIds, allIds, buf.length, buf)) {
          matches.push({
            ruleName: rule.name,
            tags: rule.tags,
            meta: rule.meta,
            file: relFile,
            matchedPatterns: Array.from(hitMap.entries()).map(([patternId, offs]) => ({
              patternId,
              offsetsHex: offs.slice(0, 8).map((o) => `0x${o.toString(16)}`),
            })),
          })
        }
      }
    }

    const report = {
      targetPath: parsed.targetPath,
      compiledRulesCount: rules.length,
      compiledRuleNames: rules.map((r) => r.name),
      scannedFilesCount: files.length,
      matchesCount: matches.length,
      matches,
    }

    const redacted = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await context.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "json",
        title: `YARA Rule Scan: ${parsed.targetPath} (${matches.length} hit(s))`,
        rawText: redacted.text,
        mediaType: "application/json",
        toolId: "cyberlab-yara-scanner",
        toolVersion: this.version,
        executorId: this.id,
        executionId: context.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["yara", "indicator-hunt"],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `Varredura YARA compilou ${rules.length} regra(s) sobre ${files.length} arquivo(s) em ${parsed.targetPath}: ${matches.length} correspondência(s) detectada(s).`,
      exitCode: 0,
    }
  }
}
