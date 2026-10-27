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

  export const ExternalToolInfo = Schema.Struct({
    toolId: Schema.String,
    displayName: Schema.String,
    available: Schema.Boolean,
    resolvedPath: Schema.NullOr(Schema.String),
    sourceLocation: Schema.Literals(["workspace_local_bin", "system_path", "custom_config", "missing"]),
    licenseSpdx: Schema.String,
    integrationMode: Schema.Literals(["plugin_only", "approved_internal_process", "mcp"]),
    governedCapabilityId: Schema.NullOr(Schema.String),
    installHint: Schema.String,
    description: Schema.String,
  })

  export const ExternalToolsOverview = Schema.Struct({
    pendingInboxCount: Schema.Number,
    inboxDirectory: Schema.String,
    tools: Schema.Array(ExternalToolInfo),
  })

  export const IngestExternalActionInput = Schema.Struct({
    toolId: Schema.String,
    title: optional(Schema.String),
    origin: optional(Schema.Literals(["manual_external", "external_plugin", "mcp_bridge", "inbox_drop"])),
    target: optional(Schema.String),
    commandSummary: optional(Schema.String),
    rawOutput: Schema.String,
    mediaType: optional(Schema.String),
  })

  export const IngestExternalActionOutput = Schema.Struct({
    evidenceId: Schema.String,
    sha256: Schema.String,
    redactionStatus: Schema.Literals(["not_checked", "checked", "redacted"]),
    scopeAuditStatus: Schema.Literals(["in_scope", "out_of_scope_flagged", "no_target_declared"]),
    scopeReason: Schema.String,
    origin: Schema.Literals(["manual_external", "external_plugin", "mcp_bridge", "inbox_drop"]),
    toolId: Schema.String,
  })

  export const InboxSyncOutput = Schema.Struct({
    scannedCount: Schema.Number,
    ingested: Schema.Array(
      Schema.Struct({
        fileName: Schema.String,
        archivedTo: Schema.String,
        evidenceId: Schema.String,
        sha256: Schema.String,
      }),
    ),
    skippedReasons: Schema.Array(Schema.String),
  })

  export const ReadEvidenceInput = Schema.Struct({
    evidenceId: Schema.String,
  })

  export const ReadEvidenceOutput = Schema.Struct({
    evidenceId: Schema.String,
    kind: Schema.String,
    title: Schema.String,
    mediaType: Schema.String,
    sha256: Schema.String,
    redacted: Schema.Boolean,
    text: Schema.String,
  })

  export const ProxyStatusInfo = Schema.Struct({
    running: Schema.Boolean,
    listenHost: Schema.String,
    listenPort: Schema.NullOr(Schema.Number),
    scopeOnly: Schema.Boolean,
    capturedCount: Schema.Number,
  })

  export const ProxyHistoryEntryInfo = Schema.Struct({
    entryId: Schema.String,
    timestamp: Schema.String,
    method: Schema.String,
    url: Schema.String,
    host: Schema.String,
    path: Schema.String,
    statusCode: Schema.Number,
    elapsedMs: Schema.Number,
    requestHeaders: Schema.Record(Schema.String, Schema.String),
    requestBody: Schema.String,
    responseHeaders: Schema.Record(Schema.String, Schema.String),
    responseBody: Schema.String,
    responseBytes: Schema.Number,
    blockedByScope: Schema.Boolean,
    blockReason: optional(Schema.String),
    persistedEvidenceId: optional(Schema.String),
  })

  export const ProxyOverview = Schema.Struct({
    status: ProxyStatusInfo,
    history: Schema.Array(ProxyHistoryEntryInfo),
  })

  export const ProxyControlInput = Schema.Struct({
    action: Schema.Literals(["start", "stop", "clear", "set_scope_only"]),
    port: optional(Schema.Number),
    scopeOnly: optional(Schema.Boolean),
  })

  export const ProxyPersistInput = Schema.Struct({
    entryId: Schema.String,
  })

  export const ProxyPersistOutput = Schema.Struct({
    evidenceId: Schema.String,
    sha256: Schema.String,
  })

  export const CdiPermissionsInfo = Schema.Struct({
    readProjectState: Schema.Boolean,
    readEvidenceAndFiles: Schema.Boolean,
    createArtifactsAndFindings: Schema.Boolean,
    initiateActions: Schema.Literals(["disabled", "propose_only", "allow_readonly_propose_others"]),
  })

  export const CdiPartnerInfo = Schema.Struct({
    partnerId: Schema.String,
    displayName: Schema.String,
    specialty: Schema.String,
    endpointUrl: Schema.String,
    enabled: Schema.Boolean,
    usesCustomSecret: Schema.Boolean,
    permissions: CdiPermissionsInfo,
  })

  export const CdiInboundActivityInfo = Schema.Struct({
    activityId: Schema.String,
    partnerId: Schema.String,
    action: Schema.String,
    outcome: Schema.Literals(["allowed", "queued_for_approval", "denied"]),
    summary: Schema.String,
    timestamp: Schema.String,
  })

  export const CdiHubOverview = Schema.Struct({
    secretConfigured: Schema.Boolean,
    secretPreview: Schema.String,
    cyberlabCallbackUrl: Schema.String,
    configFilePath: Schema.String,
    partners: Schema.Array(CdiPartnerInfo),
    inboundActivity: Schema.Array(CdiInboundActivityInfo),
  })

  export const CdiPartnerManageInput = Schema.Struct({
    operation: Schema.Literals(["upsert", "remove", "preset_4"]),
    partnerId: optional(Schema.String),
    displayName: optional(Schema.String),
    specialty: optional(Schema.String),
    endpointUrl: optional(Schema.String),
    enabled: optional(Schema.Boolean),
    secretOverride: optional(Schema.String),
    baseHost: optional(Schema.String),
    permissions: optional(CdiPermissionsInfo),
  })

  export const CdiSecretManageInput = Schema.Struct({
    operation: Schema.Literals(["reveal", "generate", "custom"]),
    customSecret: optional(Schema.String),
    cyberlabCallbackUrl: optional(Schema.String),
  })

  export const CdiSecretManageOutput = Schema.Struct({
    sharedSecret: Schema.String,
    cyberlabCallbackUrl: Schema.String,
  })

  export const CdiMultiDispatchInput = Schema.Struct({
    partnerIds: Schema.Array(Schema.String),
    objective: Schema.String,
    evidenceIds: optional(Schema.Array(Schema.String)),
    contextText: optional(Schema.String),
    timeoutMs: optional(Schema.Number),
  })
}

