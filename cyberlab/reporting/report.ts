import type { EvidenceRecord, SecurityFinding } from "../contracts/evidence.js"
import type { ExecutionRecord } from "../contracts/execution.js"

export interface ProjectAssessmentReportInput {
  projectId: string
  projectName?: string
  generatedAt?: string
  executions: ExecutionRecord[]
  evidence: EvidenceRecord[]
  findings: SecurityFinding[]
}

export function renderAssessmentMarkdownReport(input: ProjectAssessmentReportInput): string {
  const generatedAt = input.generatedAt ?? new Date().toISOString()
  const confirmed = input.findings.filter((f) => f.status === "confirmed")
  const unverified = input.findings.filter((f) => f.status !== "confirmed" && f.status !== "rejected")

  const lines: string[] = [
    `# CyberLab OS Assessment Report — ${input.projectName ?? input.projectId}`,
    "",
    `- **Project ID**: \`${input.projectId}\``,
    `- **Generated At**: \`${generatedAt}\``,
    `- **Executions Recorded**: ${input.executions.length}`,
    `- **Immutable Evidence Records**: ${input.evidence.length}`,
    `- **Confirmed Findings**: ${confirmed.length}`,
    `- **Unverified / Inconclusive Hypotheses**: ${unverified.length}`,
    "",
    "---",
    "",
    "## 1. Verified Raw Observations (Evidence Inventory)",
    "",
  ]

  if (input.evidence.length === 0) {
    lines.push("_No evidence artifacts recorded._", "")
  } else {
    for (const ev of input.evidence) {
      lines.push(
        `- **\`${ev.evidenceId}\`** (${ev.kind}) — ${ev.title}`,
        `  - Tool / Executor: \`${ev.source.toolId}\` via \`${ev.source.executorId}\` (execution \`${ev.source.executionId}\`)`,
        `  - SHA-256: \`${ev.integrity.sha256}\` · Redaction: \`${ev.redactionStatus}\``,
      )
    }
    lines.push("")
  }

  lines.push("## 2. Confirmed Security Findings", "")
  if (confirmed.length === 0) {
    lines.push("_No findings have been confirmed with verified evidence yet._", "")
  } else {
    for (const f of confirmed) {
      const conf = f.confidence !== undefined ? `${Math.round(f.confidence * 100)}%` : "n/a"
      lines.push(
        `### [${f.severity.toUpperCase()}] ${f.title} (\`${f.findingId}\`)`,
        `- **Status**: \`${f.status}\` · **Confidence**: \`${conf}\``,
        `- **Affected Assets**: ${f.affectedAssets.join(", ") || "n/a"}`,
        `- **Linked Evidence IDs**: ${f.evidenceIds.map((id) => `\`${id}\``).join(", ")}`,
        `- **Description**: ${f.description}`,
      )
      if (f.proposedRemediation) {
        lines.push(`- **Proposed Remediation**: ${f.proposedRemediation}`)
      }
      if (f.review) {
        lines.push(`- **Reviewed By**: \`${f.review.reviewedBy}\` at \`${f.review.reviewedAt}\` (${f.review.decision})`)
      }
      lines.push("")
    }
  }

  lines.push("## 3. Unverified Alerts & Inconclusive Hypotheses", "")
  if (unverified.length === 0) {
    lines.push("_None._", "")
  } else {
    for (const f of unverified) {
      const conf = f.confidence !== undefined ? `${Math.round(f.confidence * 100)}%` : "n/a"
      lines.push(
        `- **[${f.severity.toUpperCase()} / ${f.status}]** ${f.title} (\`${f.findingId}\`, confidence: \`${conf}\`) — Evidence: ${
          f.evidenceIds.length > 0 ? f.evidenceIds.map((id) => `\`${id}\``).join(", ") : "_pending verification_"
        }`,
      )
    }
    lines.push("")
  }

  return lines.join("\n")
}
