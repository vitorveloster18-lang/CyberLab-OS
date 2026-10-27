export type StudioTabId =
  | "repeater"
  | "decoder"
  | "webscan"
  | "network"
  | "packets"
  | "forensics"
  | "cockpit"

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
}

export interface ExternalToolsOverviewDto {
  pendingInboxCount: number
  inboxDirectory: string
  tools: Array<{
    toolId: string
    displayName: string
    available: boolean
    resolvedPath: string | null
    licenseSpdx: string
    integrationMode: string
    governedCapabilityId: string | null
    installHint: string
  }>
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
  responseHeaders: Record<string, string>
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
