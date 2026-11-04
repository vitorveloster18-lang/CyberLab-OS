export type WorkspaceSectionId = "web" | "network" | "cdi" | "evidence"

export type WebToolId = "repeater" | "proxy" | "scanner" | "decoder"
export type NetworkToolId = "tls" | "ports" | "pcap" | "binary"

export interface HeaderRow {
  id: string
  enabled: boolean
  name: string
  value: string
}

export interface ScopeRuleDto {
  kind: "ip" | "cidr" | "domain" | "url_origin" | "workspace_path"
  value: string
  notes?: string
}

export interface WorkspaceStatusDto {
  projectId: string
  workspaceRoot: string
  environment: { platform: string; arch: string; isLinux: boolean; isWsl2: boolean }
  activeScope?: {
    scopeId: string
    name: string
    allowExternalTargets: boolean
    allowedTargets: ScopeRuleDto[]
    blockedTargets: ScopeRuleDto[]
  }
  capabilityCount: number
  skillCount: number
  executionCount: number
  pendingApprovalCount: number
  evidenceCount: number
  findingCount: number
}

export interface CapabilityDto {
  id: string
  version: string
  title: string
  risk: string
}

export interface ApprovalDto {
  approvalId: string
  executionId: string
  capabilityId: string
  targetSummary: string
  status: string
}

export interface ExecutionDto {
  executionId: string
  capabilityId: string
  status: string
  evidenceIds: string[]
  policyReason?: string
  error?: { code: string; message: string }
}

export interface EvidenceDto {
  evidenceId: string
  kind: string
  title: string
  sha256: string
  sizeBytes: number
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
  title: string
  severity: string
  confidence?: number
  status: string
  evidenceIds: string[]
  affectedAssets: string[]
  proposedRemediation?: string
}

export interface ExternalToolStatusDto {
  toolId: string
  displayName: string
  available: boolean
  resolvedPath: string | null
  sourceLocation: "workspace_local_bin" | "system_path" | "custom_config" | "wsl_distro" | "missing"
  licenseSpdx: string
  integrationMode: "plugin_only" | "approved_internal_process" | "mcp"
  governedCapabilityId: string | null
  installHint: string
  description: string
  installHintWsl?: string
  wslDistro?: string | null
  wslPath?: string | null
}

export interface ExternalToolsOverviewDto {
  pendingInboxCount: number
  inboxDirectory: string
  tools: ExternalToolStatusDto[]
}

export interface ProxyHistoryEntryDto {
  entryId: string
  timestamp: string
  method: string
  url: string
  host: string
  path: string
  statusCode: number
  elapsedMs: number
  requestHeaders: Record<string, string>
  requestBody: string
  responseBody: string
  responseBytes: number
  blockedByScope: boolean
  blockReason?: string
  persistedEvidenceId?: string
}

export interface ProxyOverviewDto {
  status: {
    running: boolean
    listenHost: string
    listenPort: number | null
    scopeOnly: boolean
    capturedCount: number
  }
  history: ProxyHistoryEntryDto[]
}

export type CdiInitiateMode = "disabled" | "propose_only" | "allow_readonly_propose_others"

export interface CdiPartnerPermissionsDto {
  readProjectState: boolean
  readEvidenceAndFiles: boolean
  createArtifactsAndFindings: boolean
  initiateActions: CdiInitiateMode
}

export interface CdiPartnerDto {
  partnerId: string
  displayName: string
  specialty: string
  endpointUrl: string
  enabled: boolean
  usesCustomSecret: boolean
  permissions: CdiPartnerPermissionsDto
}

export interface CdiInboundActivityDto {
  activityId: string
  partnerId: string
  action: string
  outcome: "allowed" | "queued_for_approval" | "denied"
  summary: string
  timestamp: string
}

export interface PartnersOverviewDto {
  secretConfigured: boolean
  secretPreview: string
  cyberlabCallbackUrl: string
  configFilePath: string
  partners: CdiPartnerDto[]
  inboundActivity: CdiInboundActivityDto[]
}

export interface CdiSecretOutputDto {
  sharedSecret: string
  cyberlabCallbackUrl: string
}

export interface MultiCdiDispatchItemDto {
  partnerId: string
  displayName: string
  ok: boolean
  durationMs: number
  outcome?: {
    result?: {
      summary?: string
    }
    rawEvidenceId?: string
  }
  error?: string
}

export interface DispatchPartnersResultDto {
  mode: "single" | "parallel"
  objective: string
  totalDispatched: number
  succeededCount: number
  failedCount: number
  results: MultiCdiDispatchItemDto[]
}
