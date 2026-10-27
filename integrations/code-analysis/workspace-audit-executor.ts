import { readdirSync, readFileSync, statSync } from "node:fs"
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

export const WORKSPACE_AUDIT_INPUT_SCHEMA_ID = "cyberlab.workspace-audit.input.v1"
export const WORKSPACE_AUDIT_OUTPUT_SCHEMA_ID = "cyberlab.workspace-audit.output.v1"

export const WorkspaceAuditInputSchema = Schema.Struct({
  subpath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  maxFiles: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThan(0), Schema.isLessThanOrEqualTo(500))),
  maxFileBytes: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThan(0), Schema.isLessThanOrEqualTo(1_048_576))),
})

export type WorkspaceAuditInput = typeof WorkspaceAuditInputSchema.Type

export const WorkspaceAuditCapability: CapabilityDefinition = {
  id: "code-analysis.workspace-audit",
  version: "1.0.0",
  title: "Read-Only Workspace Configuration & Secret Audit",
  description:
    "Scans authorized files inside the project workspace for hardcoded credentials, disabled TLS verification, and unsafe shell execution patterns without invoking external processes.",
  inputSchemaId: WORKSPACE_AUDIT_INPUT_SCHEMA_ID,
  outputSchemaId: WORKSPACE_AUDIT_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "workspace-audit-executor",
  skillIds: ["code-audit", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

interface PatternRule {
  ruleId: string
  title: string
  regex: RegExp
}

const AUDIT_PATTERNS: readonly PatternRule[] = [
  {
    ruleId: "SEC-001",
    title: "Disabled TLS certificate verification (rejectUnauthorized: false)",
    regex: /rejectUnauthorized\s*:\s*false/,
  },
  {
    ruleId: "SEC-002",
    title: "Potential hardcoded AWS Access Key ID",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    ruleId: "SEC-003",
    title: "Potential hardcoded private key block",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  },
  {
    ruleId: "SEC-004",
    title: "Dynamic code evaluation via eval()",
    regex: /\beval\s*\(/,
  },
]

const IGNORED_DIRS = new Set([".git", "node_modules", ".cyberlab", "dist", "build", ".turbo"])

export class WorkspaceAuditExecutor implements CyberLabExecutor {
  readonly id = "workspace-audit-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    return { available: true, version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(WorkspaceAuditInputSchema)(input)
      if (decoded.subpath.includes("\0")) {
        return { valid: false, errors: ["subpath contains null byte"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return {
        valid: false,
        errors: [err instanceof Error ? err.message : String(err)],
      }
    }
  }

  async execute(execInput: ExecutorInput, context: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(WorkspaceAuditInputSchema)(execInput.input)
    const maxFiles = params.maxFiles ?? 100
    const maxFileBytes = params.maxFileBytes ?? 256 * 1024

    if (!isPathInsideRoot(params.subpath, context.workspaceRoot)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Target subpath "${params.subpath}" is outside workspaceRoot`,
        exitCode: 2,
      }
    }

    const startPath = path.resolve(context.workspaceRoot, params.subpath)
    await context.log("info", `Starting read-only workspace audit on ${startPath}`)

    const filesToScan: string[] = []
    const collectFiles = (target: string) => {
      if (context.signal.aborted || filesToScan.length >= maxFiles) return
      const st = statSync(target, { throwIfNoEntry: false })
      if (!st) return
      if (st.isFile()) {
        if (st.size <= maxFileBytes) filesToScan.push(target)
        return
      }
      if (st.isDirectory()) {
        for (const entry of readdirSync(target, { withFileTypes: true })) {
          if (filesToScan.length >= maxFiles || context.signal.aborted) break
          if (IGNORED_DIRS.has(entry.name)) continue
          const child = path.join(target, entry.name)
          if (!isPathInsideRoot(child, context.workspaceRoot)) continue
          if (entry.isDirectory()) {
            collectFiles(child)
          } else if (entry.isFile()) {
            const childStat = statSync(child, { throwIfNoEntry: false })
            if (childStat && childStat.size <= maxFileBytes) {
              filesToScan.push(child)
            }
          }
        }
      }
    }

    collectFiles(startPath)

    if (context.signal.aborted) {
      return { status: "cancelled", evidenceIds: [], summary: "Cancelled during file enumeration" }
    }

    const observations: Array<{
      ruleId: string
      title: string
      file: string
      line: number
      excerpt: string
    }> = []

    for (const file of filesToScan) {
      if (context.signal.aborted) {
        return { status: "cancelled", evidenceIds: [], summary: "Cancelled during file inspection" }
      }
      const raw = readFileSync(file, "utf8")
      const lines = raw.split(/\r?\n/)
      const relFile = path.relative(context.workspaceRoot, file)

      for (let idx = 0; idx < lines.length; idx++) {
        const lineText = lines[idx] ?? ""
        for (const rule of AUDIT_PATTERNS) {
          if (rule.regex.test(lineText)) {
            observations.push({
              ruleId: rule.ruleId,
              title: rule.title,
              file: relFile,
              line: idx + 1,
              excerpt: lineText.trim().slice(0, 200),
            })
          }
        }
      }
    }

    const summaryPayload = {
      scannedSubpath: params.subpath,
      filesScanned: filesToScan.length,
      observationCount: observations.length,
      observations,
    }

    const evidenceId = await context.emitEvidence(
      normalizeRawOutputDraft({
        kind: "json",
        title: `Workspace static audit raw observations (${observations.length} matches across ${filesToScan.length} files)`,
        toolId: "cyberlab-workspace-audit",
        toolVersion: this.version,
        executorId: this.id,
        executionId: context.executionId,
        mediaType: "application/json",
        rawText: JSON.stringify(summaryPayload, null, 2),
        maxOutputBytes: 512 * 1024,
        labels: ["read_only", "static_analysis"],
      }),
    )

    return {
      status: "succeeded",
      evidenceIds: [evidenceId],
      summary: `Scanned ${filesToScan.length} file(s); recorded ${observations.length} raw observation(s).`,
      exitCode: 0,
    }
  }
}
