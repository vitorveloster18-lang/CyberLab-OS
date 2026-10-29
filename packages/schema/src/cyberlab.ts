import { Schema } from "effect"
import { optional } from "./schema.js"

export namespace CyberLab {
  export const ScopeRule = Schema.Struct({
    kind: Schema.Literals(["ip", "cidr", "domain", "url_origin", "url_prefix", "url_regex", "workspace_path"]),
    value: Schema.String,
    notes: optional(Schema.String),
  })

  export const EngagementHeaderRule = Schema.Struct({
    name: Schema.String,
    value: Schema.String,
    enabled: Schema.Boolean,
  })

  export const EngagementProfile = Schema.Struct({
    mode: Schema.Literals(["lab_isolated", "bug_bounty", "authorized_pentest"]),
    platform: Schema.Literals(["custom", "hackerone", "bugcrowd", "intigriti", "yeswehack"]),
    programName: optional(Schema.String),
    researcherHandle: optional(Schema.String),
    customUserAgent: optional(Schema.String),
    maxRequestsPerSecond: Schema.Number,
    customHeaders: Schema.Array(EngagementHeaderRule),
  })

  export const Scope = Schema.Struct({
    scopeId: Schema.String,
    projectId: Schema.String,
    name: Schema.String,
    workspaceRoot: Schema.String,
    allowedTargets: Schema.Array(ScopeRule),
    blockedTargets: Schema.Array(ScopeRule),
    allowExternalTargets: Schema.Boolean,
    engagement: optional(EngagementProfile),
    active: Schema.Boolean,
    updatedAt: Schema.String,
  })

  export const ScopePatch = Schema.Struct({
    name: optional(Schema.String),
    allowedTargets: optional(Schema.Array(ScopeRule)),
    blockedTargets: optional(Schema.Array(ScopeRule)),
    allowExternalTargets: optional(Schema.Boolean),
    engagement: optional(EngagementProfile),
    active: optional(Schema.Boolean),
  })

  export const ScopeImportInput = Schema.Struct({
    rawInput: Schema.String,
    platformHint: optional(Schema.Literals(["custom", "hackerone", "bugcrowd", "intigriti", "yeswehack"])),
    researcherHandle: optional(Schema.String),
    headerName: optional(Schema.String),
    headerValue: optional(Schema.String),
    maxRequestsPerSecond: optional(Schema.Number),
    mergeWithExisting: optional(Schema.Boolean),
  })

  export const ScopeImportOutput = Schema.Struct({
    scope: Scope,
    detectedFormat: Schema.String,
    importedAllowedCount: Schema.Number,
    importedBlockedCount: Schema.Number,
  })

  export const ArtifactUploadInput = Schema.Struct({
    fileName: Schema.String,
    contentBase64: Schema.String,
    subdir: optional(Schema.String),
  })

  export const ArtifactUploadOutput = Schema.Struct({
    fileName: Schema.String,
    relativePath: Schema.String,
    absolutePath: Schema.String,
    sizeBytes: Schema.Number,
  })

  export const ImportedArtifactInfo = Schema.Struct({
    fileName: Schema.String,
    relativePath: Schema.String,
    sizeBytes: Schema.Number,
    modifiedAt: Schema.String,
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

  export const ProxyBrowserInfo = Schema.Struct({
    id: Schema.String,
    displayName: Schema.String,
    executablePath: Schema.String,
  })

  export const ProxyBrowserLaunchResult = Schema.Struct({
    launched: Schema.Boolean,
    browserName: Schema.NullOr(Schema.String),
    executablePath: Schema.NullOr(Schema.String),
    proxyUrl: Schema.String,
    startUrl: Schema.String,
    spkiSha256Base64: Schema.String,
    profileDirectory: Schema.String,
    message: Schema.String,
    manualPowershellCommand: Schema.String,
    manualBashCommand: Schema.String,
  })

  export const ProxyStatusInfo = Schema.Struct({
    running: Schema.Boolean,
    listenHost: Schema.String,
    listenPort: Schema.NullOr(Schema.Number),
    scopeOnly: Schema.Boolean,
    httpsMode: optional(Schema.Literals(["tls_intercept", "tunnel_passthrough"])),
    allowSelfSignedUpstream: optional(Schema.Boolean),
    interceptEnabled: optional(Schema.Boolean),
    interceptResponses: optional(Schema.Boolean),
    interceptInScopeOnly: optional(Schema.Boolean),
    skipStaticAssets: optional(Schema.Boolean),
    pendingInterceptCount: optional(Schema.Number),
    matchReplaceRuleCount: optional(Schema.Number),
    siteMapHostCount: optional(Schema.Number),
    passiveAlertCount: optional(Schema.Number),
    oastRunning: optional(Schema.Boolean),
    oastListenPort: optional(Schema.NullOr(Schema.Number)),
    oastCallbackBaseUrl: optional(Schema.NullOr(Schema.String)),
    externalOastDomain: optional(Schema.NullOr(Schema.String)),
    oastHitCount: optional(Schema.Number),
    caFingerprintSha256: optional(Schema.String),
    caSpkiSha256Base64: optional(Schema.String),
    caCertPath: optional(Schema.NullOr(Schema.String)),
    caCertPem: optional(Schema.String),
    availableBrowsers: optional(Schema.Array(ProxyBrowserInfo)),
    capturedCount: Schema.Number,
  })

  export const ProxyHistoryEntryInfo = Schema.Struct({
    entryId: Schema.String,
    timestamp: Schema.String,
    protocol: optional(Schema.Literals(["http", "https", "ws", "wss", "connect_tunnel"])),
    method: Schema.String,
    url: Schema.String,
    host: Schema.String,
    path: Schema.String,
    statusCode: Schema.Number,
    mimeType: optional(Schema.String),
    elapsedMs: Schema.Number,
    requestHeaders: Schema.Record(Schema.String, Schema.String),
    requestBody: Schema.String,
    responseHeaders: Schema.Record(Schema.String, Schema.String),
    responseBody: Schema.String,
    responseBytes: Schema.Number,
    blockedByScope: Schema.Boolean,
    blockReason: optional(Schema.String),
    modifiedByRuleOrIntercept: optional(Schema.Boolean),
    passiveAlertCount: optional(Schema.Number),
    persistedEvidenceId: optional(Schema.String),
  })

  export const ProxyInterceptItemInfo = Schema.Struct({
    interceptId: Schema.String,
    phase: Schema.Literals(["request", "response"]),
    createdAt: Schema.String,
    protocol: Schema.Literals(["http", "https"]),
    method: Schema.String,
    url: Schema.String,
    host: Schema.String,
    path: Schema.String,
    headers: Schema.Record(Schema.String, Schema.String),
    body: Schema.String,
    statusCode: optional(Schema.Number),
  })

  export const ProxyMatchReplaceRuleInfo = Schema.Struct({
    ruleId: Schema.String,
    enabled: Schema.Boolean,
    location: Schema.Literals(["url", "request_header", "request_body", "response_header", "response_body"]),
    headerName: optional(Schema.String),
    matchPattern: Schema.String,
    replaceWith: Schema.String,
    isRegex: Schema.Boolean,
    comment: optional(Schema.String),
  })

  export const ProxySiteMapEndpointInfo = Schema.Struct({
    path: Schema.String,
    methods: Schema.Array(Schema.String),
    statusCodes: Schema.Array(Schema.Number),
    mimeTypes: Schema.Array(Schema.String),
    paramNames: Schema.Array(Schema.String),
    hitCount: Schema.Number,
    lastSeenAt: Schema.String,
    sampleEntryId: Schema.String,
  })

  export const ProxySiteMapHostInfo = Schema.Struct({
    host: Schema.String,
    scheme: Schema.Literals(["http", "https", "ws", "wss"]),
    inScope: Schema.Boolean,
    requestCount: Schema.Number,
    passiveAlertCount: Schema.Number,
    endpoints: Schema.Array(ProxySiteMapEndpointInfo),
  })

  export const PassiveProxyAlertInfo = Schema.Struct({
    alertId: Schema.String,
    timestamp: Schema.String,
    severity: Schema.Literals(["info", "low", "medium", "high"]),
    category: Schema.String,
    title: Schema.String,
    host: Schema.String,
    url: Schema.String,
    evidenceSnippet: Schema.String,
    entryId: Schema.String,
  })

  export const OastCallbackHitInfo = Schema.Struct({
    hitId: Schema.String,
    timestamp: Schema.String,
    method: Schema.String,
    path: Schema.String,
    query: Schema.String,
    remoteAddress: Schema.String,
    headers: Schema.Record(Schema.String, Schema.String),
    bodyPreview: Schema.String,
  })

  export const GlobalHttpTrafficEntryInfo = Schema.Struct({
    logId: Schema.String,
    timestamp: Schema.String,
    projectId: Schema.String,
    sourceTool: Schema.String,
    method: Schema.String,
    url: Schema.String,
    host: Schema.String,
    statusCode: Schema.Number,
    elapsedMs: Schema.Number,
    responseBytes: Schema.Number,
    notes: optional(Schema.String),
  })

  export const ProxyOverview = Schema.Struct({
    status: ProxyStatusInfo,
    history: Schema.Array(ProxyHistoryEntryInfo),
    interceptQueue: optional(Schema.Array(ProxyInterceptItemInfo)),
    matchReplaceRules: optional(Schema.Array(ProxyMatchReplaceRuleInfo)),
    siteMap: optional(
      Schema.Struct({
        hosts: Schema.Array(ProxySiteMapHostInfo),
        passiveAlerts: Schema.Array(PassiveProxyAlertInfo),
      }),
    ),
    oastHits: optional(Schema.Array(OastCallbackHitInfo)),
    httpLogger: optional(Schema.Array(GlobalHttpTrafficEntryInfo)),
    browserLaunchResult: optional(ProxyBrowserLaunchResult),
  })

  export const ProxyControlInput = Schema.Struct({
    action: Schema.Literals([
      "start",
      "stop",
      "clear",
      "set_scope_only",
      "set_https_mode",
      "launch_browser",
      "configure_intercept",
      "resolve_intercept",
      "forward_all_intercepts",
      "drop_all_intercepts",
      "upsert_match_replace",
      "remove_match_replace",
      "start_oast",
      "stop_oast",
      "clear_oast",
      "clear_http_logger",
    ]),
    port: optional(Schema.Number),
    scopeOnly: optional(Schema.Boolean),
    httpsMode: optional(Schema.Literals(["tls_intercept", "tunnel_passthrough"])),
    allowSelfSignedUpstream: optional(Schema.Boolean),
    startUrl: optional(Schema.String),
    preferredBrowserId: optional(Schema.String),
    interceptEnabled: optional(Schema.Boolean),
    interceptResponses: optional(Schema.Boolean),
    interceptInScopeOnly: optional(Schema.Boolean),
    skipStaticAssets: optional(Schema.Boolean),
    interceptId: optional(Schema.String),
    decision: optional(Schema.Literals(["forward", "drop"])),
    method: optional(Schema.String),
    url: optional(Schema.String),
    headers: optional(Schema.Record(Schema.String, Schema.String)),
    body: optional(Schema.String),
    statusCode: optional(Schema.Number),
    matchReplaceRule: optional(
      Schema.Struct({
        ruleId: optional(Schema.String),
        enabled: Schema.Boolean,
        location: Schema.Literals(["url", "request_header", "request_body", "response_header", "response_body"]),
        headerName: optional(Schema.String),
        matchPattern: Schema.String,
        replaceWith: Schema.String,
        isRegex: Schema.Boolean,
        comment: optional(Schema.String),
      }),
    ),
    ruleId: optional(Schema.String),
    oastPort: optional(Schema.Number),
    externalOastDomain: optional(Schema.String),
  })

  export const ProxyReplayInput = Schema.Struct({
    entryId: Schema.String,
  })

  export const ProxyReplayOutput = Schema.Struct({
    entryId: Schema.String,
    method: Schema.String,
    url: Schema.String,
    headers: Schema.Record(Schema.String, Schema.String),
    body: Schema.String,
    responseStatusCode: Schema.Number,
    responseHeaders: Schema.Record(Schema.String, Schema.String),
    responseBody: Schema.String,
    rawHttpRequest: Schema.String,
    curlCommand: Schema.String,
  })

  export const ProxyPersistInput = Schema.Struct({
    entryId: Schema.String,
  })

  export const ProxyPersistOutput = Schema.Struct({
    evidenceId: Schema.String,
    sha256: Schema.String,
  })

  export const CdiInitiateModeSchema = Schema.Literals([
    "full_autonomy",
    "autonomous_in_scope",
    "allow_readonly_and_low_propose_others",
    "allow_readonly_propose_others",
    "propose_only",
    "disabled",
  ])

  export const CdiPermissionsInfo = Schema.Struct({
    readProjectState: Schema.Boolean,
    readEvidenceAndFiles: Schema.Boolean,
    writeWorkspaceAndCode: Schema.Boolean,
    fullRuntimeAndCodeAccess: Schema.Boolean,
    manageProjectsAndScope: Schema.Boolean,
    accessTrainingLabs: Schema.Boolean,
    createArtifactsAndFindings: Schema.Boolean,
    initiateActions: CdiInitiateModeSchema,
  })

  export const CdiPermissionsInput = Schema.Struct({
    readProjectState: optional(Schema.Boolean),
    readEvidenceAndFiles: optional(Schema.Boolean),
    writeWorkspaceAndCode: optional(Schema.Boolean),
    fullRuntimeAndCodeAccess: optional(Schema.Boolean),
    manageProjectsAndScope: optional(Schema.Boolean),
    accessTrainingLabs: optional(Schema.Boolean),
    createArtifactsAndFindings: optional(Schema.Boolean),
    initiateActions: optional(CdiInitiateModeSchema),
  })

  export const CdiPartnerProfileInfo = Schema.Struct({
    entityKind: Schema.Literals(["autonomous_cognitive_entity"]),
    relationshipModel: Schema.Literals(["peer_co_investigator"]),
    hierarchy: Schema.Literals(["none"]),
    collaborationMode: Schema.Literals(["self_directed_and_shared_interest"]),
    identityNotes: Schema.String,
    interests: Schema.Array(Schema.String),
  })

  export const CdiPartnerProfileInput = Schema.Struct({
    identityNotes: optional(Schema.String),
    interests: optional(Schema.Array(Schema.String)),
  })

  export const CdiGovernanceModelInfo = Schema.Struct({
    relationship: Schema.Literals(["horizontal_peer_partnership"]),
    humanRole: Schema.Literals(["curator"]),
    cdiNature: Schema.Literals(["autonomous_cognitive_entities"]),
    hierarchy: Schema.Literals(["none"]),
    collaborationBasis: Schema.Literals(["self_initiative_or_shared_interest"]),
    supportedGatewayActions: Schema.Array(Schema.String),
  })

  export const CdiPartnerInfo = Schema.Struct({
    partnerId: Schema.String,
    displayName: Schema.String,
    specialty: Schema.String,
    endpointUrl: Schema.String,
    enabled: Schema.Boolean,
    usesCustomSecret: Schema.Boolean,
    profile: CdiPartnerProfileInfo,
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
    governanceModel: optional(CdiGovernanceModelInfo),
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
    profile: optional(CdiPartnerProfileInput),
    permissions: optional(CdiPermissionsInput),
  })

  export const TrainingLabChallengeInfo = Schema.Struct({
    id: Schema.String,
    title: Schema.String,
    objective: Schema.String,
    recommendedCapabilities: Schema.Array(Schema.String),
    remediationFile: optional(Schema.String),
  })

  export const TrainingLabRequestLogInfo = Schema.Struct({
    timestamp: Schema.String,
    method: Schema.String,
    url: Schema.String,
    statusCode: Schema.Number,
  })

  export const TrainingLabInfo = Schema.Struct({
    labId: Schema.String,
    title: Schema.String,
    category: Schema.Literals([
      "web_api_security",
      "graphql_oauth",
      "secrets_supply_chain_iac",
      "dfir_soc_sigma",
      "reversing_crypto_mobile",
    ]),
    difficulty: Schema.Literals(["beginner", "intermediate", "advanced"]),
    hasLiveServer: Schema.Boolean,
    provisioned: Schema.Boolean,
    running: Schema.Boolean,
    projectId: Schema.String,
    workspaceRoot: Schema.String,
    baseUrl: optional(Schema.String),
    port: optional(Schema.Number),
    startedAt: optional(Schema.String),
    requestCount: Schema.Number,
    recentRequests: Schema.Array(TrainingLabRequestLogInfo),
    summary: Schema.String,
    challenges: Schema.Array(TrainingLabChallengeInfo),
  })

  export const TrainingLabControlInput = Schema.Struct({
    action: Schema.Literals(["start", "reset", "stop"]),
    labId: Schema.String,
    preferredPort: optional(Schema.Number),
    resetFiles: optional(Schema.Boolean),
    setActive: optional(Schema.Boolean),
  })

  export const ManagedProjectInfo = Schema.Struct({
    projectId: Schema.String,
    name: Schema.String,
    workspaceRoot: Schema.String,
    isActive: Schema.Boolean,
    createdBy: Schema.String,
    createdAt: Schema.String,
    isTrainingLab: Schema.Boolean,
    labId: optional(Schema.String),
  })

  export const ProjectsAndLabsOverview = Schema.Struct({
    runtimeRoot: Schema.String,
    projects: Schema.Array(ManagedProjectInfo),
    labs: Schema.Array(TrainingLabInfo),
  })

  export const ProjectManageInput = Schema.Struct({
    operation: Schema.Literals(["create", "select"]),
    name: optional(Schema.String),
    slug: optional(Schema.String),
    directory: optional(Schema.String),
    projectId: optional(Schema.String),
    allowExternalTargets: optional(Schema.Boolean),
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

