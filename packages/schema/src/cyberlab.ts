import { Schema } from "effect"
import { optional } from "./schema.js"

export namespace CyberLab {
  export const ScopeRule = Schema.Struct({
    kind: Schema.Literals(["ip", "cidr", "domain", "url_origin", "workspace_path"]),
    value: Schema.String,
    notes: optional(Schema.String),
  })

  export const Scope = Schema.Struct({
    scopeId: Schema.String,
    projectId: Schema.String,
    name: Schema.String,
    workspaceRoot: Schema.String,
    allowedTargets: Schema.Array(ScopeRule),
    blockedTargets: Schema.Array(ScopeRule),
    allowExternalTargets: Schema.Boolean,
    active: Schema.Boolean,
    updatedAt: Schema.String,
  })

  export const ScopePatch = Schema.Struct({
    name: optional(Schema.String),
    allowedTargets: optional(Schema.Array(ScopeRule)),
    blockedTargets: optional(Schema.Array(ScopeRule)),
    allowExternalTargets: optional(Schema.Boolean),
    active: optional(Schema.Boolean),
  })

  export const EnvironmentInfo = Schema.Struct({
    platform: Schema.String,
    arch: Schema.String,
    release: Schema.String,
    isLinux: Schema.Boolean,
    isWsl2: Schema.Boolean,
    workspaceOnWindowsMount: Schema.Boolean,
  })

  export const WorkspaceStatus = Schema.Struct({
    projectId: Schema.String,
    workspaceRoot: Schema.String,
    environment: EnvironmentInfo,
    activeScope: optional(Scope),
    capabilityCount: Schema.Number,
    skillCount: Schema.Number,
    executionCount: Schema.Number,
    pendingApprovalCount: Schema.Number,
    evidenceCount: Schema.Number,
    findingCount: Schema.Number,
  })

  export const CapabilityInfo = Schema.Struct({
    id: Schema.String,
    version: Schema.String,
    title: Schema.String,
    description: Schema.String,
    risk: Schema.Literals(["read_only", "low", "moderate", "high", "destructive"]),
    requiresScope: Schema.Boolean,
    executorId: Schema.String,
    skillIds: Schema.Array(Schema.String),
    enabled: Schema.Boolean,
  })

  export const ExecutionInfo = Schema.Struct({
    executionId: Schema.String,
    requestId: Schema.String,
    projectId: Schema.String,
    capabilityId: Schema.String,
    status: Schema.Literals([
      "draft",
      "awaiting_approval",
      "queued",
      "running",
      "succeeded",
      "failed",
      "cancelled",
      "blocked",
      "timed_out",
    ]),
    startedAt: optional(Schema.String),
    finishedAt: optional(Schema.String),
    policyReason: optional(Schema.String),
    evidenceIds: Schema.Array(Schema.String),
    error: optional(
      Schema.Struct({
        code: Schema.String,
        message: Schema.String,
        retryable: Schema.Boolean,
      }),
    ),
  })

  export const SubmitExecutionInput = Schema.Struct({
    capabilityId: Schema.String,
    input: Schema.Unknown,
    mode: optional(Schema.Literals(["manual", "proposed", "approved", "lab_automation"])),
    idempotencyKey: optional(Schema.String),
  })

  export const ApproveExecutionInput = Schema.Struct({
    approvalId: Schema.String,
    decidedBy: Schema.String,
    reason: optional(Schema.String),
  })

  export const CancelExecutionInput = Schema.Struct({
    executionId: Schema.String,
    reason: Schema.String,
  })

  export const ApprovalInfo = Schema.Struct({
    approvalId: Schema.String,
    projectId: Schema.String,
    executionId: Schema.String,
    capabilityId: Schema.String,
    targetSummary: Schema.String,
    status: Schema.Literals(["pending", "approved", "rejected", "expired", "consumed"]),
    createdAt: Schema.String,
    expiresAt: Schema.String,
  })

  export const EvidenceInfo = Schema.Struct({
    evidenceId: Schema.String,
    projectId: Schema.String,
    kind: Schema.String,
    title: Schema.String,
    sha256: Schema.String,
    sizeBytes: Schema.Number,
    mediaType: Schema.String,
    observedAt: Schema.String,
    createdAt: Schema.String,
    executionId: Schema.String,
    redactionStatus: Schema.Literals(["not_checked", "checked", "redacted"]),
  })

  export const VerifyEvidenceInput = Schema.Struct({
    evidenceId: Schema.String,
  })

  export const VerifyEvidenceResult = Schema.Struct({
    evidenceId: Schema.String,
    valid: Schema.Boolean,
    expectedSha256: Schema.String,
    actualSha256: optional(Schema.String),
    reason: optional(Schema.String),
  })

  export const FindingInfo = Schema.Struct({
    findingId: Schema.String,
    projectId: Schema.String,
    title: Schema.String,
    description: Schema.String,
    severity: Schema.Literals(["info", "low", "medium", "high", "critical"]),
    confidence: optional(Schema.Number),
    status: Schema.Literals(["unreviewed", "supported", "confirmed", "rejected", "inconclusive"]),
    evidenceIds: Schema.Array(Schema.String),
    affectedAssets: Schema.Array(Schema.String),
    proposedRemediation: optional(Schema.String),
    createdAt: Schema.String,
    updatedAt: Schema.String,
  })

  export const CreateFindingInput = Schema.Struct({
    title: Schema.String,
    description: Schema.String,
    severity: Schema.Literals(["info", "low", "medium", "high", "critical"]),
    confidence: optional(Schema.Number),
    evidenceIds: Schema.Array(Schema.String),
    affectedAssets: Schema.Array(Schema.String),
    proposedRemediation: optional(Schema.String),
  })

  export const ReviewFindingInput = Schema.Struct({
    findingId: Schema.String,
    reviewedBy: Schema.String,
    decision: Schema.Literals(["accept", "reject", "needs_more_evidence"]),
    notes: optional(Schema.String),
  })

  export const ReportOutput = Schema.Struct({
    markdown: Schema.String,
  })
}
