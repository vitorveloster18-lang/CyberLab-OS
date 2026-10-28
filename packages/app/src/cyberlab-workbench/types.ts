import type { IconName } from "@opencode/plugin/gui"

export type ManualToolCategoryId = "web" | "network" | "forensics" | "cdi_external" | "governance"

export type ToolSuiteId =
  | "web-suite"
  | "network-suite"
  | "packet-suite"
  | "reversing-suite"
  | "dfir-suite"
  | "code-suite"
  | "cdi-suite"
  | "governance-suite"

export interface ToolSuiteEngineOption {
  toolId: ManualToolId
  label: string
  badge: string
  description: string
}

export interface ToolSuiteFunctionTab {
  id: string
  label: string
  description: string
  /** Sub-aba específica quando aponta para scope-governance ou cdi-hub */
  governanceSubTab?: ScopeGovernanceDraft["subTab"]
  cdiSubTab?: "dispatch" | "setup"
  /** Lista de motores selecionáveis dentro desta mesma função (estilo Burp / Scanner) */
  engines: ToolSuiteEngineOption[]
}

export interface ToolSuiteMeta {
  id: ToolSuiteId
  title: string
  shortTitle: string
  subtitle: string
  icon: IconName
  keywords: string[]
  functions: ToolSuiteFunctionTab[]
}

export type ManualToolId =
  | "http-repeater"
  | "http-proxy"
  | "http-intruder"
  | "param-audit"
  | "dalfox"
  | "api-security-lab"
  | "http-headers"
  | "web-surface"
  | "nuclei"
  | "ffuf"
  | "decoder-jwt"
  | "tls-inspector"
  | "tcp-probe"
  | "nmap"
  | "dns-recon"
  | "ad-smb-ldap"
  | "pcap-analyzer"
  | "tshark"
  | "workspace-audit"
  | "sca-sbom-iac"
  | "trivy"
  | "binary-triage"
  | "binary-disasm"
  | "ghidra"
  | "entropy-recipe"
  | "mobile-triage"
  | "jadx"
  | "yara-scan"
  | "yarax"
  | "dfir-sigma"
  | "cdi-hub"
  | "external-ingest"
  | "scope-governance"

export type WorkbenchLayoutMode = "split" | "fullscreen"

export interface KeyValueHeaderRow {
  id: string
  enabled: boolean
  name: string
  value: string
}

export type DecoderTransformStep =
  | "url_decode"
  | "url_encode"
  | "base64_decode"
  | "base64_encode"
  | "base64url_decode"
  | "hex_decode"
  | "hex_encode"
  | "html_decode"
  | "sha256"

export interface HttpRepeaterDraft {
  method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
  url: string
  headers: KeyValueHeaderRow[]
  body: string
  enableBaseline: boolean
  baselineUrl: string
  baselineHeaders: KeyValueHeaderRow[]
  timeoutMs: number
  maxBodyBytes: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface HttpProxyDraft {
  port: number
  scopeOnly: boolean
  httpsMode: "tls_intercept" | "tunnel_passthrough"
  allowSelfSignedUpstream: boolean
  filterText: string
  selectedEntryId: string
}

export interface HttpIntruderDraft {
  method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
  url: string
  headers: KeyValueHeaderRow[]
  bodyTemplate: string
  attackMode: "sniper" | "battering_ram" | "pitchfork"
  payloadSet1Text: string
  payloadSet2Text: string
  maxRequests: number
  concurrency: number
  delayMs: number
  timeoutMs: number
  grepMatch: string
  urlEncodePayloads: boolean
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface ParamAuditDraft {
  url: string
  method: "GET" | "POST"
  parameterNamesText: string
  checkReflectionContext: boolean
  checkErrorLeakage: boolean
  checkRedirectHygiene: boolean
  timeoutMs: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface DalfoxDraft {
  url: string
  paramName: string
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface DnsReconDraft {
  host: string
  nameserver: string
  checkEmailPosture: boolean
  enumerateSubdomains: boolean
  subdomainPrefixesText: string
  includeCrtSh: boolean
  timeoutMs: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface BinaryDisasmDraft {
  binaryPath: string
  architecture: "auto" | "x86_64" | "arm64"
  startOffsetHex: string
  maxInstructions: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface GhidraDraft {
  binaryPath: string
  processor: string
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface JadxDraft {
  artifactPath: string
  deobfuscate: boolean
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface YaraScanDraft {
  targetPath: string
  rulesText: string
  maxFiles: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface YaraXDraft {
  rulesPath: string
  targetPath: string
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface HttpHeadersDraft {
  url: string
  method: "GET" | "HEAD"
  timeoutMs: number
  maxBodyBytes: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface WebSurfaceDraft {
  baseUrl: string
  customPathsText: string
  concurrency: number
  timeoutMs: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface NucleiDraft {
  url: string
  tags: string
  rateLimit: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface FfufDraft {
  baseUrl: string
  wordlistPath: string
  rateLimit: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface DecoderJwtDraft {
  value: string
  transforms: DecoderTransformStep[]
  inspectJwt: boolean
  tokenSamplesText: string
  useRawJson: boolean
  rawJson: string
}

export interface TlsInspectorDraft {
  host: string
  port: number
  servername: string
  deepCipherAudit: boolean
  checkHsts: boolean
  timeoutMs: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface ApiSecurityLabDraft {
  baseUrl: string
  specPath: string
  inlineSpecJson: string
  userAAuthHeader: string
  userBAuthHeader: string
  testUnauthenticated: boolean
  maxEndpoints: number
  graphqlUrl: string
  graphqlTestBatching: boolean
  graphqlMaxDepthProbe: number
  issuerUrl: string
  authorizeUrl: string
  timeoutMs: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface ScaSbomIacDraft {
  targetPath: string
  queryOsv: boolean
  generateCycloneDx: boolean
  auditIac: boolean
  maxFiles: number
  timeoutMs: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface TrivyDraft {
  targetPath: string
  scanners: string
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface DfirSigmaDraft {
  logPath: string
  logFormat: "auto" | "syslog" | "nginx" | "json"
  useBuiltinSigma: boolean
  sigmaRulesPath: string
  inlineSigmaYaml: string
  maxEvents: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface AdSmbLdapDraft {
  host: string
  checkSmbSigning: boolean
  smbPort: number
  checkLdapRootDse: boolean
  ldapPort: number
  ntlmHttpUrl: string
  timeoutMs: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export type EntropyRecipeOp =
  | "from_base64"
  | "to_base64"
  | "from_hex"
  | "to_hex"
  | "url_decode"
  | "url_encode"
  | "gunzip"
  | "gzip"
  | "zlib_inflate"
  | "raw_inflate"
  | "xor_key"
  | "xor_single_byte_bruteforce"
  | "aes_cbc_decrypt"
  | "aes_gcm_decrypt"
  | "protobuf_raw_decode"
  | "extract_strings"
  | "sha256"

export interface EntropyRecipeStepRow {
  id: string
  op: EntropyRecipeOp
  key: string
  keyEncoding: "utf8" | "hex"
  ivHex: string
  authTagHex: string
  minLength: number
}

export interface SavedCyberChefRecipe {
  id: string
  name: string
  steps: EntropyRecipeStepRow[]
}

export interface EntropyRecipeDraft {
  targetPath: string
  windowSize: number
  rawInput: string
  inputEncoding: "utf8" | "hex" | "base64"
  recipeSteps: EntropyRecipeStepRow[]
  newRecipeName: string
  savedRecipes: SavedCyberChefRecipe[]
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface TcpProbeDraft {
  host: string
  port: number
  multiPortList: string
  useMultiPort: boolean
  connectTimeoutMs: number
  bannerWaitMs: number
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface NmapDraft {
  host: string
  ports: string
  serviceVersion: boolean
  executionMode: "manual" | "proposed"
  useRawJson: boolean
  rawJson: string
}

export interface PcapAnalyzerDraft {
  pcapPath: string
  maxPackets: number
  useRawJson: boolean
  rawJson: string
}

export interface TsharkDraft {
  pcapPath: string
  maxPackets: number
  useRawJson: boolean
  rawJson: string
}

export interface WorkspaceAuditDraft {
  subpath: string
  maxFiles: number
  maxFileBytes: number
  useRawJson: boolean
  rawJson: string
}

export interface BinaryTriageDraft {
  binaryPath: string
  minStringLength: number
  maxStrings: number
  useRawJson: boolean
  rawJson: string
}

export interface MobileTriageDraft {
  artifactPath: string
  iocDomainsText: string
  useRawJson: boolean
  rawJson: string
}

export interface CdiHubDraft {
  cdiSubTab?: "dispatch" | "setup"
  selectedPartnerIds: string[]
  objective: string
  contextText: string
  selectedEvidenceIds: string[]
  timeoutMs: number
  customSecretInput: string
}

export interface ExternalIngestDraft {
  toolId: string
  title: string
  origin: string
  target: string
  commandSummary: string
  mediaType: string
  rawOutput: string
}

export interface ScopeGovernanceDraft {
  subTab: "scope" | "approvals" | "evidence" | "findings" | "report"
  newRuleKind: "ip" | "cidr" | "domain" | "url_origin" | "workspace_path"
  newRuleValue: string
  newRuleNotes: string
  newRuleBlocked: boolean
  findingTitle: string
  findingDescription: string
  findingSeverity: "critical" | "high" | "medium" | "low" | "info"
  findingConfidence: number
  findingAssetsText: string
  findingEvidenceIds: string[]
  findingRemediation: string
}

export interface ManualToolDraftMap {
  "http-repeater": HttpRepeaterDraft
  "http-proxy": HttpProxyDraft
  "http-intruder": HttpIntruderDraft
  "param-audit": ParamAuditDraft
  dalfox: DalfoxDraft
  "api-security-lab": ApiSecurityLabDraft
  "http-headers": HttpHeadersDraft
  "web-surface": WebSurfaceDraft
  nuclei: NucleiDraft
  ffuf: FfufDraft
  "decoder-jwt": DecoderJwtDraft
  "tls-inspector": TlsInspectorDraft
  "tcp-probe": TcpProbeDraft
  nmap: NmapDraft
  "dns-recon": DnsReconDraft
  "ad-smb-ldap": AdSmbLdapDraft
  "pcap-analyzer": PcapAnalyzerDraft
  tshark: TsharkDraft
  "workspace-audit": WorkspaceAuditDraft
  "sca-sbom-iac": ScaSbomIacDraft
  trivy: TrivyDraft
  "binary-triage": BinaryTriageDraft
  "binary-disasm": BinaryDisasmDraft
  ghidra: GhidraDraft
  "entropy-recipe": EntropyRecipeDraft
  "mobile-triage": MobileTriageDraft
  jadx: JadxDraft
  "yara-scan": YaraScanDraft
  yarax: YaraXDraft
  "dfir-sigma": DfirSigmaDraft
  "cdi-hub": CdiHubDraft
  "external-ingest": ExternalIngestDraft
  "scope-governance": ScopeGovernanceDraft
}

export interface ManualToolMeta {
  id: ManualToolId
  category: ManualToolCategoryId
  title: string
  shortTitle: string
  subtitle: string
  icon: IconName
  badge: "MIT Nativo" | "Plugin Externo" | "Agentes CDI" | "Governança"
  capabilityId?: string
  riskLabel: string
}

export interface ToolHistoryEntry {
  id: string
  toolId: ManualToolId
  capabilityId?: string
  timestamp: string
  targetSummary: string
  status: "succeeded" | "queued" | "failed" | "cancelled" | "running"
  durationMs?: number
  executionId?: string
  approvalId?: string
  evidenceIds: string[]
  sha256?: string
  summaryText: string
  outputText: string
  draftSnapshot: Record<string, unknown>
  rawInputPayload?: Record<string, unknown>
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

export interface ApprovalDto {
  approvalId: string
  executionId: string
  capabilityId: string
  targetSummary: string
  status: string
  createdAt?: string
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
  mediaType?: string
  observedAt?: string
  executionId?: string
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
  description?: string
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
  sourceLocation: string
  licenseSpdx: string
  integrationMode: string
  governedCapabilityId: string | null
  installHint: string
  description: string
}

export interface ExternalToolsOverviewDto {
  pendingInboxCount: number
  inboxDirectory: string
  tools: ExternalToolStatusDto[]
}

export interface ProxyHistoryEntryDto {
  entryId: string
  timestamp: string
  protocol?: "http" | "https" | "ws" | "wss" | "connect_tunnel"
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
    httpsMode?: "tls_intercept" | "tunnel_passthrough"
    allowSelfSignedUpstream?: boolean
    caFingerprintSha256?: string
    caCertPath?: string | null
    caCertPem?: string
    capturedCount: number
  }
  history: ProxyHistoryEntryDto[]
}

export interface CdiPartnerDto {
  partnerId: string
  displayName: string
  specialty: string
  endpointUrl: string
  enabled: boolean
  usesCustomSecret: boolean
  permissions: {
    readProjectState: boolean
    readEvidenceAndFiles: boolean
    createArtifactsAndFindings: boolean
    initiateActions: "disabled" | "propose_only" | "allow_readonly_propose_others"
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

export interface DispatchPartnersResultDto {
  mode: "single" | "parallel"
  objective: string
  totalDispatched: number
  succeededCount: number
  failedCount: number
  results: Array<{
    partnerId: string
    displayName: string
    ok: boolean
    durationMs: number
    outcome?: {
      result?: { summary?: string }
      rawEvidenceId?: string
    }
    error?: string
  }>
}
