export type ArsenalSlotKindDto = "web_embed" | "desktop_gui" | "cli_runner"
export type ArsenalRuntimePrefDto = "auto" | "windows" | "wsl" | "linux_mac"

export type LeftSidebarTab = "slots" | "files"
export type CenterViewMode = "tool" | "scope" | "labs" | "cdi" | "custody" | "guide"

export interface ArsenalPresetDto {
  id: string
  label: string
  description: string
  argsTemplate: string
}

export interface ArsenalSlotOverrideDto {
  customExecutablePath?: string
  customEmbedUrl?: string
  preferredRuntime?: ArsenalRuntimePrefDto
  defaultArgs?: string
  companionProxyPort?: number
}

export interface ArsenalSlotStatusDto {
  slotId: string
  name: string
  shortLabel: string
  category: string
  kind: ArsenalSlotKindDto
  tagline: string
  description: string
  upstreamUrl: string
  licenseNote: string
  isCustom: boolean
  installed: boolean
  availableRuntimes: Array<"windows" | "wsl" | "linux_mac" | "web">
  activeRuntime: "windows" | "wsl" | "linux_mac" | "web" | "none"
  resolvedPath: string | null
  windowsPath: string | null
  wslPath: string | null
  posixPath: string | null
  embedUrl: string | null
  daemonRunning: boolean
  companionProxyPort: number | null
  mcpCapable: boolean
  mcpConnected: boolean
  mcpLabel: string | null
  installPowerShell: string
  installKaliWsl: string
  presets: ArsenalPresetDto[]
  override: ArsenalSlotOverrideDto
}

export interface ArsenalLiveRunDto {
  runId: string
  slotId: string
  slotName: string
  runtime: "windows" | "wsl" | "linux_mac" | "installer"
  commandPreview: string
  status: "running" | "succeeded" | "failed" | "stopped"
  exitCode: number | null
  startedAt: string
  finishedAt: string | null
  outputLogPath: string | null
  outputTail: string
  lineCount: number
}

export interface ArsenalCategoryDto {
  id: string
  title: string
  subtitle: string
}

export interface ArsenalEnvironmentDto {
  hostPlatform: string
  toolsRootDir: string
  wslAvailable: boolean
  wslDistros: string[]
  preferredWslDistro: string
  enforceScopeOnCliRuns: boolean
  lastProbedAt: string | null
}

export interface ProxyBrowserInfoDto {
  id: string
  displayName: string
  executablePath: string
}

export interface ProxyBrowserLaunchResultDto {
  launched: boolean
  browserName: string | null
  executablePath: string | null
  proxyUrl: string
  startUrl: string
  spkiSha256Base64: string
  profileDirectory: string
  message: string
  manualPowershellCommand: string
  manualBashCommand: string
}

export interface ArsenalOverviewDto {
  environment: ArsenalEnvironmentDto
  categories: ArsenalCategoryDto[]
  slots: ArsenalSlotStatusDto[]
  runs: ArsenalLiveRunDto[]
  availableBrowsers?: ProxyBrowserInfoDto[]
}

export interface ArsenalLaunchResultDto {
  ok: boolean
  message: string
  embedUrl?: string
  run?: ArsenalLiveRunDto
  overview: ArsenalOverviewDto
}

export interface WorkspaceFileEntryDto {
  name: string
  relativePath: string
  kind: "file" | "directory"
  sizeBytes: number
  modifiedAt: string
}

export interface WorkspaceFilesListDto {
  currentDir: string
  entries: WorkspaceFileEntryDto[]
}

export interface WorkspaceFilePreviewDto {
  relativePath: string
  sizeBytes: number
  truncated: boolean
  content: string
}

export interface ScopeRuleDto {
  kind: "ip" | "cidr" | "domain" | "url_origin" | "url_prefix" | "url_regex" | "workspace_path"
  value: string
  notes?: string
}

export interface EngagementHeaderRuleDto {
  name: string
  value: string
  enabled: boolean
}

export interface EngagementProfileDto {
  mode: "lab_isolated" | "bug_bounty" | "authorized_pentest"
  platform: "custom" | "hackerone" | "bugcrowd" | "intigriti" | "yeswehack"
  programName?: string
  researcherHandle?: string
  customUserAgent?: string
  maxRequestsPerSecond: number
  customHeaders: EngagementHeaderRuleDto[]
}

export interface ScopeDto {
  scopeId: string
  projectId: string
  name: string
  workspaceRoot: string
  allowedTargets: ScopeRuleDto[]
  blockedTargets: ScopeRuleDto[]
  allowExternalTargets: boolean
  engagement?: EngagementProfileDto
  active: boolean
  updatedAt: string
}

export interface WorkspaceStatusDto {
  projectId: string
  workspaceRoot: string
  environment: {
    platform: string
    arch: string
    release: string
    isLinux: boolean
    isWsl2: boolean
    workspaceOnWindowsMount: boolean
  }
  activeScope?: ScopeDto
  capabilityCount: number
  skillCount: number
  executionCount: number
  pendingApprovalCount: number
  evidenceCount: number
  findingCount: number
}

export interface ApprovalDto {
  approvalId: string
  projectId: string
  executionId: string
  capabilityId: string
  targetSummary: string
  status: string
  createdAt: string
  expiresAt: string
}

export interface EvidenceDto {
  evidenceId: string
  projectId: string
  kind: string
  title: string
  sha256: string
  sizeBytes: number
  mediaType: string
  observedAt: string
  createdAt: string
  executionId: string
  redactionStatus: string
}

export interface ReadEvidenceDto {
  evidenceId: string
  kind: string
  title: string
  mediaType: string
  sha256: string
  redacted: boolean
  text: string
}

export interface FindingDto {
  findingId: string
  projectId: string
  title: string
  description: string
  severity: "info" | "low" | "medium" | "high" | "critical"
  confidence?: number
  status: string
  evidenceIds: string[]
  affectedAssets: string[]
  proposedRemediation?: string
  createdAt: string
  updatedAt: string
}

export interface CdiPartnerDto {
  partnerId: string
  displayName: string
  specialty: string
  endpointUrl: string
  enabled: boolean
  usesCustomSecret: boolean
  profile: {
    entityKind: string
    relationshipModel: string
    hierarchy: string
    collaborationMode: string
    identityNotes: string
    interests: string[]
  }
  permissions: {
    readProjectState: boolean
    readEvidenceAndFiles: boolean
    writeWorkspaceAndCode: boolean
    fullRuntimeAndCodeAccess: boolean
    manageProjectsAndScope: boolean
    accessTrainingLabs: boolean
    createArtifactsAndFindings: boolean
    initiateActions: string
  }
}

export interface PartnersOverviewDto {
  secretConfigured: boolean
  secretPreview: string
  cyberlabCallbackUrl: string
  configFilePath: string
  partners: CdiPartnerDto[]
  inboundActivity: Array<{
    activityId: string
    partnerId: string
    action: string
    outcome: string
    summary: string
    timestamp: string
  }>
}

export interface TrainingLabDto {
  labId: string
  title: string
  category: string
  difficulty: string
  hasLiveServer: boolean
  provisioned: boolean
  running: boolean
  projectId: string
  workspaceRoot: string
  baseUrl?: string
  port?: number
  startedAt?: string
  requestCount: number
  recentRequests: Array<{ timestamp: string; method: string; url: string; statusCode: number }>
  summary: string
  challenges: Array<{
    id: string
    title: string
    objective: string
    recommendedCapabilities: string[]
    remediationFile?: string
  }>
}

export interface ManagedProjectDto {
  projectId: string
  name: string
  workspaceRoot: string
  isActive: boolean
  createdBy: string
  createdAt: string
  isTrainingLab: boolean
  labId?: string
}

export interface ProjectsAndLabsOverviewDto {
  runtimeRoot: string
  projects: ManagedProjectDto[]
  labs: TrainingLabDto[]
}
