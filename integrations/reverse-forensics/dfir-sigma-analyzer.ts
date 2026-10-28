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

export const DFIR_SIGMA_INPUT_SCHEMA_ID = "cyberlab.dfir-sigma.input.v1"
export const DFIR_SIGMA_OUTPUT_SCHEMA_ID = "cyberlab.dfir-sigma.output.v1"

export const DfirSigmaInputSchema = Schema.Struct({
  logPath: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512))),
  rawLogText: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(524_288))),
  sigmaRulesYaml: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(131_072))),
  sigmaRulesPath: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512))),
  includeBuiltinRules: Schema.optionalKey(Schema.Boolean),
  maxEvents: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(10), Schema.isLessThanOrEqualTo(10_000)),
  ),
})

export type DfirSigmaInput = typeof DfirSigmaInputSchema.Type

export const DfirSigmaCapability: CapabilityDefinition = {
  id: "forensics.dfir-sigma-triage",
  version: "1.0.0",
  title: "DFIR Log Analyzer, Sigma Rule Engine & Incident Timeline (Blue Team / SOC)",
  description:
    "Parses Linux syslog/auth.log, Nginx/Apache web access logs, and JSON/Windows Event exports, evaluates built-in and custom Sigma YAML detection rules, and generates a chronological SHA-256 incident timeline.",
  inputSchemaId: DFIR_SIGMA_INPUT_SCHEMA_ID,
  outputSchemaId: DFIR_SIGMA_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "dfir-sigma-analyzer-executor",
  skillIds: ["evidence-review", "code-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export interface NormalizedLogEvent {
  lineNumber: number
  timestamp: string
  format: "linux_syslog" | "web_access" | "json_event" | "raw"
  fields: Record<string, string>
  rawLine: string
}

export interface CompiledSigmaRule {
  id: string
  title: string
  level: string
  description: string
  selections: Record<string, Array<{ field: string | null; modifier: string; values: string[] }>>
  condition: string
}

export const BUILTIN_SIGMA_RULES_YAML = `
title: Linux SSH Brute Force or Root Failed Login
id: cl-sigma-linux-ssh-001
level: medium
description: Detects failed SSH authentication attempts or invalid users in auth.log
detection:
  selection:
    message|contains:
      - "Failed password for"
      - "Invalid user"
      - "authentication failure"
  condition: selection
---
title: Linux Privilege Escalation or Suspicious Sudo Command
id: cl-sigma-linux-privesc-002
level: high
description: Detects sudo shell spawning, shadow file reads, or SUID bit modifications
detection:
  selection:
    message|contains:
      - "COMMAND=/bin/bash"
      - "COMMAND=/bin/sh"
      - "/etc/shadow"
      - "chmod +s"
      - "chmod 4755"
  condition: selection
---
title: Web Server Webshell, Traversal or Injection Probe
id: cl-sigma-web-attack-003
level: high
description: Detects path traversal, webshell filenames, or command/SQL injection markers in HTTP access logs
detection:
  selection:
    request|contains:
      - "../"
      - "..%2f"
      - "cmd.jsp"
      - "shell.php"
      - "/etc/passwd"
      - "UNION%20SELECT"
      - "UNION+SELECT"
  condition: selection
---
title: Windows Suspicious Encoded PowerShell or Credential Dumping Indicator
id: cl-sigma-win-ps-004
level: critical
description: Detects encoded PowerShell execution, Sekurlsa/LSASS access, or suspicious service creation in JSON/Windows logs
detection:
  selection:
    CommandLine|contains:
      - "-enc "
      - "-EncodedCommand"
      - "FromBase64String"
      - "sekurlsa::"
      - "lsass"
      - "vssadmin delete shadows"
  condition: selection
`.trim()

export function parseLogLine(line: string, lineNumber: number): NormalizedLogEvent {
  const trimmed = line.trim()

  // 1. Structured JSON / JSONL / Windows Event JSON
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>
      const fields: Record<string, string> = {}
      for (const [k, v] of Object.entries(obj)) {
        fields[k] = typeof v === "string" ? v : JSON.stringify(v)
      }
      const ts =
        fields.timestamp || fields["@timestamp"] || fields.TimeCreated || fields.time || `line-${lineNumber}`
      return {
        lineNumber,
        timestamp: String(ts),
        format: "json_event",
        fields: { ...fields, message: trimmed },
        rawLine: trimmed,
      }
    } catch {
      // fall through
    }
  }

  // 2. Nginx / Apache Combined Access Log: 10.0.0.5 - - [28/Oct/2026:12:01:02 +0000] "GET /shell.php?c=id HTTP/1.1" 200 124 "-" "curl/8.5"
  const webMatch =
    /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/.exec(
      trimmed,
    )
  if (webMatch) {
    return {
      lineNumber,
      timestamp: webMatch[3]!,
      format: "web_access",
      fields: {
        client_ip: webMatch[1]!,
        user: webMatch[2]!,
        method: webMatch[4]!,
        request: webMatch[5]!,
        status: webMatch[6]!,
        bytes: webMatch[7]!,
        user_agent: webMatch[9] ?? "",
        message: trimmed,
      },
      rawLine: trimmed,
    }
  }

  // 3. Linux Syslog / RFC3164 / ISO8601 auth.log
  const sysMatch =
    /^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}[^\s]*)\s+(\S+)\s+([^:\s]+?)(?:\[(\d+)\])?:\s*(.*)$/.exec(
      trimmed,
    )
  if (sysMatch) {
    return {
      lineNumber,
      timestamp: sysMatch[1]!,
      format: "linux_syslog",
      fields: {
        host: sysMatch[2]!,
        process: sysMatch[3]!,
        pid: sysMatch[4] ?? "",
        message: sysMatch[5]!,
      },
      rawLine: trimmed,
    }
  }

  return {
    lineNumber,
    timestamp: `line-${lineNumber}`,
    format: "raw",
    fields: { message: trimmed },
    rawLine: trimmed,
  }
}

export function compileSigmaYamlDocuments(yamlSource: string): CompiledSigmaRule[] {
  const docs = yamlSource.split(/^---\s*$/m).map((d) => d.trim()).filter(Boolean)
  const rules: CompiledSigmaRule[] = []

  for (const doc of docs) {
    const lines = doc.split(/\r?\n/)
    let title = "Custom Sigma Rule"
    let id = `sigma-${rules.length + 1}`
    let level = "medium"
    let description = ""
    let condition = "selection"
    const selections: CompiledSigmaRule["selections"] = {}

    let inDetection = false
    let currentSel: string | null = null
    let currentFieldSpec: { field: string | null; modifier: string; values: string[] } | null = null

    for (const rawLine of lines) {
      if (!rawLine.trim() || rawLine.trim().startsWith("#")) continue
      const indent = rawLine.search(/\S/)
      const trimmed = rawLine.trim()

      if (indent === 0) {
        inDetection = false
        currentSel = null
        currentFieldSpec = null
        const kv = /^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/.exec(trimmed)
        if (!kv) continue
        const key = kv[1]!.toLowerCase()
        const val = kv[2]!.replace(/^["']|["']$/g, "").trim()
        if (key === "title" && val) title = val
        else if (key === "id" && val) id = val
        else if (key === "level" && val) level = val
        else if (key === "description" && val) description = val
        else if (key === "detection") inDetection = true
        continue
      }

      if (!inDetection) continue

      if (indent === 2) {
        currentFieldSpec = null
        const kv = /^([a-zA-Z0-9_*-]+)\s*:\s*(.*)$/.exec(trimmed)
        if (!kv) continue
        if (kv[1] === "condition") {
          condition = kv[2]!.trim()
          currentSel = null
        } else {
          currentSel = kv[1]!
          selections[currentSel] = selections[currentSel] ?? []
          if (kv[2]!.trim()) {
            selections[currentSel]!.push({
              field: null,
              modifier: "contains",
              values: [kv[2]!.replace(/^["']|["']$/g, "").trim()],
            })
          }
        }
        continue
      }

      if (indent >= 4 && currentSel) {
        if (trimmed.startsWith("- ")) {
          const itemVal = trimmed.slice(2).replace(/^["']|["']$/g, "").trim()
          if (currentFieldSpec) {
            currentFieldSpec.values.push(itemVal)
          } else {
            selections[currentSel]!.push({ field: null, modifier: "contains", values: [itemVal] })
          }
        } else {
          const fkv = /^([^:]+)\s*:\s*(.*)$/.exec(trimmed)
          if (fkv) {
            const parts = fkv[1]!.trim().split("|")
            const field = parts[0]!.trim()
            const modifier = parts.slice(1).join("|") || "equals"
            const inlineVal = fkv[2]!.replace(/^["']|["']$/g, "").trim()
            currentFieldSpec = {
              field,
              modifier,
              values: inlineVal ? [inlineVal] : [],
            }
            selections[currentSel]!.push(currentFieldSpec)
          }
        }
      }
    }

    if (Object.keys(selections).length > 0) {
      rules.push({ id, title, level, description, selections, condition })
    }
  }

  return rules
}

function matchSinglePredicate(
  ev: NormalizedLogEvent,
  pred: { field: string | null; modifier: string; values: string[] },
): boolean {
  if (pred.values.length === 0) return false
  const candidateText =
    pred.field === null
      ? ev.rawLine
      : (ev.fields[pred.field] ??
        Object.entries(ev.fields).find(([k]) => k.toLowerCase() === pred.field!.toLowerCase())?.[1] ??
        ev.rawLine)

  const hay = candidateText.toLowerCase()
  const mod = pred.modifier.toLowerCase()
  const requireAll = mod.includes("all")

  const evalOne = (val: string): boolean => {
    const needle = val.toLowerCase()
    if (mod.includes("startswith")) return hay.startsWith(needle)
    if (mod.includes("endswith")) return hay.endsWith(needle)
    if (mod.includes("re")) {
      try {
        return new RegExp(val, "i").test(candidateText)
      } catch {
        return false
      }
    }
    if (mod === "equals") return hay === needle || hay.includes(needle)
    return hay.includes(needle)
  }

  return requireAll ? pred.values.every(evalOne) : pred.values.some(evalOne)
}

function evaluateSigmaRule(rule: CompiledSigmaRule, ev: NormalizedLogEvent): boolean {
  const selHits = new Map<string, boolean>()
  for (const [selName, preds] of Object.entries(rule.selections)) {
    const matched = preds.length > 0 && preds.every((p) => matchSinglePredicate(ev, p))
    selHits.set(selName, matched)
  }

  let expr = rule.condition.trim()
  expr = expr.replace(/\b1\s+of\s+([a-zA-Z0-9_]+)\*/gi, (_m, prefix: string) => {
    const anyHit = [...selHits.entries()].some(([k, v]) => k.startsWith(prefix) && v)
    return anyHit ? "true" : "false"
  })
  expr = expr.replace(/\b1\s+of\s+them\b/gi, () => ([...selHits.values()].some(Boolean) ? "true" : "false"))
  expr = expr.replace(/\ball\s+of\s+them\b/gi, () => ([...selHits.values()].every(Boolean) ? "true" : "false"))

  const sortedNames = [...selHits.keys()].sort((a, b) => b.length - a.length)
  for (const name of sortedNames) {
    expr = expr.replace(new RegExp(`\\b${name}\\b`, "g"), selHits.get(name) ? "true" : "false")
  }
  const normalized = expr.replace(/\band\b/gi, "&&").replace(/\bor\b/gi, "||").replace(/\bnot\b/gi, "!")
  if (!/^[truefals&|!()\s]+$/.test(normalized)) {
    return [...selHits.values()].some(Boolean)
  }
  try {
    return Boolean(Function(`"use strict"; return (${normalized});`)())
  } catch {
    return [...selHits.values()].some(Boolean)
  }
}

export class DfirSigmaAnalyzerExecutor implements CyberLabExecutor {
  readonly id = "dfir-sigma-analyzer-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      const parsed = Schema.decodeUnknownSync(DfirSigmaInputSchema)(input)
      if (!parsed.logPath && (!parsed.rawLogText || !parsed.rawLogText.trim())) {
        return { valid: false, errors: ["Informe logPath (arquivo de log no projeto) ou cole eventos em rawLogText."] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(DfirSigmaInputSchema)(req.input)
    const maxEvents = parsed.maxEvents ?? 2_500

    let logContent = parsed.rawLogText ?? ""
    if (parsed.logPath) {
      const absLog = path.resolve(ctx.workspaceRoot, parsed.logPath)
      if (!isPathInsideRoot(absLog, ctx.workspaceRoot) || !existsSync(absLog) || lstatSync(absLog).isSymbolicLink()) {
        return {
          status: "failed",
          evidenceIds: [],
          summary: `Arquivo de log fora do escopo ou não encontrado: ${parsed.logPath}`,
          exitCode: 2,
        }
      }
      logContent = readFileSync(absLog, "utf8")
    }

    let customSigmaYaml = parsed.sigmaRulesYaml ?? ""
    if (parsed.sigmaRulesPath) {
      const absRule = path.resolve(ctx.workspaceRoot, parsed.sigmaRulesPath)
      if (!isPathInsideRoot(absRule, ctx.workspaceRoot) || !existsSync(absRule) || lstatSync(absRule).isSymbolicLink()) {
        return {
          status: "failed",
          evidenceIds: [],
          summary: `Arquivo de regras Sigma fora do escopo ou não encontrado: ${parsed.sigmaRulesPath}`,
          exitCode: 2,
        }
      }
      customSigmaYaml = readFileSync(absRule, "utf8")
    }

    const combinedYaml = [
      parsed.includeBuiltinRules !== false ? BUILTIN_SIGMA_RULES_YAML : "",
      customSigmaYaml,
    ]
      .filter(Boolean)
      .join("\n---\n")

    const compiledRules = compileSigmaYamlDocuments(combinedYaml)
    const rawLines = logContent
      .split(/\r?\n/)
      .filter((l) => l.trim().length > 0)
      .slice(0, maxEvents)

    const timelineAlerts: Array<{
      timestamp: string
      lineNumber: number
      ruleId: string
      ruleTitle: string
      level: string
      format: string
      excerpt: string
    }> = []

    const formatBreakdown: Record<string, number> = {}
    for (let i = 0; i < rawLines.length; i++) {
      if (ctx.signal.aborted) break
      const ev = parseLogLine(rawLines[i]!, i + 1)
      formatBreakdown[ev.format] = (formatBreakdown[ev.format] ?? 0) + 1
      for (const rule of compiledRules) {
        if (evaluateSigmaRule(rule, ev)) {
          timelineAlerts.push({
            timestamp: ev.timestamp,
            lineNumber: ev.lineNumber,
            ruleId: rule.id,
            ruleTitle: rule.title,
            level: rule.level,
            format: ev.format,
            excerpt: ev.rawLine.slice(0, 260),
          })
        }
      }
    }

    const report = {
      source: parsed.logPath ?? "inline_log_buffer",
      totalEventsParsed: rawLines.length,
      formatBreakdown,
      sigmaRulesLoaded: compiledRules.length,
      alertsCount: timelineAlerts.length,
      incidentTimeline: timelineAlerts,
    }

    const redacted = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await ctx.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "json",
        title: `DFIR Sigma Timeline (${timelineAlerts.length} alerta(s) em ${rawLines.length} eventos)`,
        rawText: redacted.text,
        mediaType: "application/json",
        toolId: "cyberlab-dfir-sigma",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["dfir", "sigma", "timeline", "blue-team"],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `DFIR Sigma analisou ${rawLines.length} evento(s) com ${compiledRules.length} regra(s) Sigma: ${timelineAlerts.length} detecção(ões) na linha do tempo.`,
      exitCode: 0,
    }
  }
}
