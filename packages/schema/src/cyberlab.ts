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
    sourceLocation: Schema.Literals([
      "workspace_local_bin",
      "system_path",
      "custom_config",
      "wsl_distro",
      "missing",
    ]),
    licenseSpdx: Schema.String,
    integrationMode: Schema.Literals(["plugin_only", "approved_internal_process", "mcp"]),
    governedCapabilityId: Schema.NullOr(Schema.String),
    installHint: Schema.String,
    description: Schema.String,
    installHintWsl: optional(Schema.String),
    wslDistro: optional(Schema.NullOr(Schema.String)),
    wslPath: optional(Schema.NullOr(Schema.String)),
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

  export const ArsenalCategoryInfo = Schema.Struct({
    id: Schema.String,
    title: Schema.String,
    subtitle: Schema.String,
  })

  export const ArsenalPresetCommandInfo = Schema.Struct({
    id: Schema.String,
    label: Schema.String,
    description: Schema.String,
    argsTemplate: Schema.String,
  })

  export const ArsenalSlotOverrideInfo = Schema.Struct({
    customExecutablePath: optional(Schema.String),
    customEmbedUrl: optional(Schema.String),
    preferredRuntime: optional(Schema.Literals(["auto", "windows", "wsl", "linux_mac"])),
    defaultArgs: optional(Schema.String),
    companionProxyPort: optional(Schema.Number),
  })

  export const ArsenalSlotStatusInfo = Schema.Struct({
    slotId: Schema.String,
    name: Schema.String,
    shortLabel: Schema.String,
    category: Schema.String,
    kind: Schema.Literals(["web_embed", "desktop_gui", "cli_runner"]),
    tagline: Schema.String,
    description: Schema.String,
    upstreamUrl: Schema.String,
    licenseNote: Schema.String,
    isCustom: Schema.Boolean,
    installed: Schema.Boolean,
    availableRuntimes: Schema.Array(Schema.Literals(["windows", "wsl", "linux_mac", "web"])),
    activeRuntime: Schema.Literals(["windows", "wsl", "linux_mac", "web", "none"]),
    resolvedPath: Schema.NullOr(Schema.String),
    windowsPath: Schema.NullOr(Schema.String),
    wslPath: Schema.NullOr(Schema.String),
    posixPath: Schema.NullOr(Schema.String),
    embedUrl: Schema.NullOr(Schema.String),
    daemonRunning: Schema.Boolean,
    companionProxyPort: Schema.NullOr(Schema.Number),
    mcpCapable: Schema.Boolean,
    mcpConnected: Schema.Boolean,
    mcpLabel: Schema.NullOr(Schema.String),
    installPowerShell: Schema.String,
    installKaliWsl: Schema.String,
    presets: Schema.Array(ArsenalPresetCommandInfo),
    override: ArsenalSlotOverrideInfo,
  })

  export const ArsenalLiveRunInfo = Schema.Struct({
    runId: Schema.String,
    slotId: Schema.String,
    slotName: Schema.String,
    runtime: Schema.Literals(["windows", "wsl", "linux_mac", "installer"]),
    commandPreview: Schema.String,
    status: Schema.Literals(["running", "succeeded", "failed", "stopped"]),
    exitCode: Schema.NullOr(Schema.Number),
    startedAt: Schema.String,
    finishedAt: Schema.NullOr(Schema.String),
    outputLogPath: Schema.NullOr(Schema.String),
    outputTail: Schema.String,
    lineCount: Schema.Number,
  })

  export const ArsenalEnvironmentSummaryInfo = Schema.Struct({
    hostPlatform: Schema.String,
    toolsRootDir: Schema.String,
    wslAvailable: Schema.Boolean,
    wslDistros: Schema.Array(Schema.String),
    preferredWslDistro: Schema.String,
    enforceScopeOnCliRuns: Schema.Boolean,
    lastProbedAt: Schema.NullOr(Schema.String),
  })

  export const ArsenalSlotHealthInfo = Schema.Struct({
    slotId: Schema.String,
    name: Schema.String,
    kind: Schema.Literals([
      "ghost_custom_slot",
      "duplicate_custom_slot",
      "non_executable_target",
      "unconfigured_custom_slot",
    ]),
    severity: Schema.Literals(["warning", "error"]),
    message: Schema.String,
    configuredPath: Schema.NullOr(Schema.String),
    suggestion: Schema.String,
    duplicateOfSlotId: Schema.NullOr(Schema.String),
  })

  export const ArsenalOverview = Schema.Struct({
    environment: ArsenalEnvironmentSummaryInfo,
    categories: Schema.Array(ArsenalCategoryInfo),
    slots: Schema.Array(ArsenalSlotStatusInfo),
    runs: Schema.Array(ArsenalLiveRunInfo),
    availableBrowsers: optional(Schema.Array(ProxyBrowserInfo)),
    health: Schema.Array(ArsenalSlotHealthInfo),
  })

  export const ArsenalPruneCustomSlotsInput = Schema.Struct({
    removeGhosts: optional(Schema.Boolean),
    removeDuplicates: optional(Schema.Boolean),
    /** v6.7: confirmação humana exigida pela guarda de ações destrutivas. */
    confirm: optional(Schema.Boolean),
  })

  export const ArsenalConfigPatchInput = Schema.Struct({
    toolsRootDir: optional(Schema.String),
    preferredWslDistro: optional(Schema.String),
    enforceScopeOnCliRuns: optional(Schema.Boolean),
    slotId: optional(Schema.String),
    slotOverride: optional(ArsenalSlotOverrideInfo),
  })

  export const ArsenalCustomSlotInput = Schema.Struct({
    slotId: optional(Schema.String),
    name: Schema.String,
    shortLabel: optional(Schema.String),
    kind: Schema.Literals(["web_embed", "desktop_gui", "cli_runner"]),
    tagline: optional(Schema.String),
    description: optional(Schema.String),
    executableOrUrl: Schema.String,
    preferredRuntime: optional(Schema.Literals(["auto", "windows", "wsl", "linux_mac"])),
    companionProxyPort: optional(Schema.Number),
    defaultArgsTemplate: optional(Schema.String),
  })

  export const ArsenalCustomSlotRemoveInput = Schema.Struct({
    slotId: Schema.String,
    /** v6.7: confirmação humana exigida pela guarda de ações destrutivas. */
    confirm: optional(Schema.Boolean),
  })

  export const ArsenalLaunchInput = Schema.Struct({
    slotId: Schema.String,
    action: Schema.Literals(["run_cli", "launch_desktop", "start_web", "stop_web", "install_tool"]),
    target: optional(Schema.String),
    rawArgs: optional(Schema.String),
    runtimeOverride: optional(Schema.Literals(["windows", "wsl", "linux_mac"])),
  })

  export const ArsenalLaunchResult = Schema.Struct({
    ok: Schema.Boolean,
    message: Schema.String,
    embedUrl: optional(Schema.String),
    run: optional(ArsenalLiveRunInfo),
    overview: ArsenalOverview,
  })

  export const ArsenalStopRunInput = Schema.Struct({
    runId: Schema.String,
  })

  export const ArsenalProxyBrowserInput = Schema.Struct({
    proxyPort: optional(Schema.Number),
    startUrl: optional(Schema.String),
    preferredBrowserId: optional(Schema.String),
  })

  export const ArsenalPersistOutputInput = Schema.Struct({
    title: Schema.String,
    content: Schema.String,
    slotId: optional(Schema.String),
  })

  export const ArsenalPersistOutputResult = Schema.Struct({
    evidenceId: Schema.String,
    sha256: Schema.String,
  })

  export const WorkspaceFileEntryInfo = Schema.Struct({
    name: Schema.String,
    relativePath: Schema.String,
    kind: Schema.Literals(["file", "directory"]),
    sizeBytes: Schema.Number,
    modifiedAt: Schema.String,
  })

  export const WorkspaceFilesListInput = Schema.Struct({
    subpath: optional(Schema.String),
  })

  export const WorkspaceFilesListOutput = Schema.Struct({
    currentDir: Schema.String,
    entries: Schema.Array(WorkspaceFileEntryInfo),
  })

  export const WorkspaceFilePreviewInput = Schema.Struct({
    relativePath: Schema.String,
  })

  export const WorkspaceFilePreviewOutput = Schema.Struct({
    relativePath: Schema.String,
    sizeBytes: Schema.Number,
    truncated: Schema.Boolean,
    content: Schema.String,
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
    /** v6.7: confirmação humana para `reset` e `stop` (destrutivos). */
    confirm: optional(Schema.Boolean),
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

  export const VaultNoteSummaryInfo = Schema.Struct({
    relativePath: Schema.String,
    title: Schema.String,
    folder: Schema.String,
    tags: Schema.Array(Schema.String),
    wikiLinks: Schema.Array(Schema.String),
    snippet: Schema.String,
    sizeBytes: Schema.Number,
    updatedAt: Schema.String,
  })

  export const VaultOverviewInfo = Schema.Struct({
    vaultRootDir: Schema.String,
    isCustomPath: Schema.Boolean,
    notes: Schema.Array(VaultNoteSummaryInfo),
    allTags: Schema.Array(Schema.String),
  })

  export const VaultNoteDocumentInfo = Schema.Struct({
    relativePath: Schema.String,
    title: Schema.String,
    content: Schema.String,
    tags: Schema.Array(Schema.String),
    wikiLinks: Schema.Array(Schema.String),
    backlinks: Schema.Array(Schema.String),
    updatedAt: Schema.String,
  })

  export const VaultReadInput = Schema.Struct({
    relativePath: Schema.String,
  })

  export const VaultWriteInput = Schema.Struct({
    relativePath: Schema.String,
    content: Schema.String,
  })

  export const VaultWriteResult = Schema.Struct({
    note: VaultNoteDocumentInfo,
    overview: VaultOverviewInfo,
  })

  export const VaultDeleteInput = Schema.Struct({
    relativePath: Schema.String,
    /** v6.7: confirmação humana (risco `irreversible`). */
    confirm: optional(Schema.Boolean),
    confirmPhrase: optional(Schema.String),
  })

  export const VaultConfigInput = Schema.Struct({
    customVaultRootDir: optional(Schema.NullOr(Schema.String)),
  })
}

