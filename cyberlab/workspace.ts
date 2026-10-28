import path from "node:path"
import { fileURLToPath } from "node:url"
import { createDefaultCyberLabConfig, detectRuntimeEnvironment } from "./config/config.js"
import type { CapabilityDefinition } from "./contracts/capability.js"
import type { EvidenceRecord, FindingSeverity, SecurityFinding } from "./contracts/evidence.js"
import type { ExecutionMode } from "./contracts/capability.js"
import type { ExecutionRecord } from "./contracts/execution.js"
import type { ApprovalTicket, ProjectScope, ScopeTargetRule } from "./contracts/policy.js"
import { EvidenceStore, type IntegrityCheckResult } from "./evidence/store.js"
import { CyberLabExecutionDispatcher } from "./execution/dispatcher.js"
import { PartnerAuthenticator } from "./partners/authentication.js"
import { PartnerBridge, type PartnerDispatchOutcome } from "./partners/bridge.js"
import { CdiPartnerHub, type MultiCdiDispatchReport } from "./partners/cdi-hub.js"
import { HttpPartnerTransport } from "./partners/transport.js"
import {
  EXTERNAL_DALFOX_INPUT_SCHEMA_ID,
  EXTERNAL_FFUF_INPUT_SCHEMA_ID,
  EXTERNAL_GHIDRA_INPUT_SCHEMA_ID,
  EXTERNAL_JADX_INPUT_SCHEMA_ID,
  EXTERNAL_NMAP_INPUT_SCHEMA_ID,
  EXTERNAL_NUCLEI_INPUT_SCHEMA_ID,
  EXTERNAL_TSHARK_INPUT_SCHEMA_ID,
  EXTERNAL_YARAX_INPUT_SCHEMA_ID,
  ExternalControlPlane,
  ExternalDalfoxCapability,
  ExternalDalfoxExecutor,
  ExternalDalfoxInputSchema,
  ExternalFfufCapability,
  ExternalFfufExecutor,
  ExternalFfufInputSchema,
  ExternalGhidraCapability,
  ExternalGhidraExecutor,
  ExternalGhidraInputSchema,
  ExternalJadxCapability,
  ExternalJadxExecutor,
  ExternalJadxInputSchema,
  ExternalNmapCapability,
  ExternalNmapExecutor,
  ExternalNmapInputSchema,
  ExternalNucleiCapability,
  ExternalNucleiExecutor,
  ExternalNucleiInputSchema,
  ExternalTsharkCapability,
  ExternalTsharkExecutor,
  ExternalTsharkInputSchema,
  ExternalYaraXCapability,
  ExternalYaraXExecutor,
  ExternalYaraXInputSchema,
  type ExternalToolRuntimeStatus,
  type InboxSyncResult,
  type IngestExternalActionInput,
  type IngestExternalActionResult,
} from "./external/control-plane.js"
import { CyberLabHttpProxy, type ProxyHistoryEntry, type ProxyHttpsMode, type ProxyStatus } from "./proxy/http-proxy.js"
import { ApprovalManager } from "./policy/approval.js"
import { PolicyEngine } from "./policy/authorize.js"
import { ScopeController } from "./policy/scope.js"
import { ControlledCapabilityRegistry, InputOutputSchemaRegistry } from "./registry/capabilities.js"
import { CyberLabSkillCatalog } from "./registry/skills.js"
import { ExecutorRegistry } from "./registry/tools.js"
import { renderAssessmentMarkdownReport } from "./reporting/report.js"
import {
  WORKSPACE_AUDIT_INPUT_SCHEMA_ID,
  WorkspaceAuditCapability,
  WorkspaceAuditExecutor,
  WorkspaceAuditInputSchema,
} from "../integrations/code-analysis/workspace-audit-executor.js"
import {
  HTTP_SECURITY_INSPECTOR_INPUT_SCHEMA_ID,
  HttpSecurityInspectorCapability,
  HttpSecurityInspectorInputSchema,
  WebHttpSecurityInspectorExecutor,
} from "../integrations/web-security/http-security-inspector.js"
import {
  HTTP_REPEATER_INPUT_SCHEMA_ID,
  HttpRepeaterCapability,
  HttpRepeaterComparerExecutor,
  HttpRepeaterInputSchema,
} from "../integrations/web-security/http-repeater-comparer.js"
import {
  DECODER_SEQUENCER_INPUT_SCHEMA_ID,
  DecoderSequencerCapability,
  DecoderSequencerExecutor,
  DecoderSequencerInputSchema,
} from "../integrations/web-security/decoder-sequencer.js"
import {
  WEB_SURFACE_DISCOVERY_INPUT_SCHEMA_ID,
  WebSurfaceDiscoveryCapability,
  WebSurfaceDiscoveryExecutor,
  WebSurfaceDiscoveryInputSchema,
} from "../integrations/web-security/surface-discovery.js"
import {
  TCP_SURFACE_PROBE_INPUT_SCHEMA_ID,
  TcpSurfaceInspectorExecutor,
  TcpSurfaceProbeCapability,
  TcpSurfaceProbeInputSchema,
} from "../integrations/network-observation/tcp-banner-inspector.js"
import {
  TLS_INSPECTOR_INPUT_SCHEMA_ID,
  TlsCertificateInspectorExecutor,
  TlsInspectorCapability,
  TlsInspectorInputSchema,
} from "../integrations/network-observation/tls-certificate-inspector.js"
import {
  PCAP_ANALYZER_INPUT_SCHEMA_ID,
  PcapAnalyzerCapability,
  PcapAnalyzerInputSchema,
  PcapPacketAnalyzerExecutor,
} from "../integrations/network-observation/pcap-packet-analyzer.js"
import {
  BINARY_TRIAGE_INPUT_SCHEMA_ID,
  BinaryStaticTriageCapability,
  BinaryStaticTriageExecutor,
  BinaryStaticTriageInputSchema,
} from "../integrations/reverse-forensics/binary-static-triage.js"
import {
  MOBILE_TRIAGE_INPUT_SCHEMA_ID,
  MobileArtifactTriageCapability,
  MobileArtifactTriageExecutor,
  MobileArtifactTriageInputSchema,
} from "../integrations/reverse-forensics/mobile-artifact-triage.js"
import {
  HTTP_INTRUDER_INPUT_SCHEMA_ID,
  HttpIntruderCapability,
  HttpIntruderInputSchema,
  HttpIntruderMatrixExecutor,
} from "../integrations/web-security/http-intruder-matrix.js"
import {
  WEB_PARAM_AUDIT_INPUT_SCHEMA_ID,
  DifferentialParamAuditorExecutor,
  WebParamAuditCapability,
  WebParamAuditInputSchema,
} from "../integrations/web-security/differential-param-auditor.js"
import {
  DNS_RECON_INPUT_SCHEMA_ID,
  DnsReconCapability,
  DnsReconInputSchema,
  DnsSurfaceReconExecutor,
} from "../integrations/network-observation/dns-surface-recon.js"
import {
  BINARY_DISASM_INPUT_SCHEMA_ID,
  BinaryDisasmCapability,
  BinaryDisasmInputSchema,
  BinaryDisassemblerExecutor,
} from "../integrations/reverse-forensics/binary-disassembler.js"
import {
  YARA_SCAN_INPUT_SCHEMA_ID,
  YaraRuleScannerExecutor,
  YaraScanCapability,
  YaraScanInputSchema,
} from "../integrations/reverse-forensics/yara-rule-scanner.js"

const repoSkillsDir = fileURLToPath(new URL("../skills", import.meta.url))

export type WorkspaceBootstrapHook = (workspace: CyberLabWorkspace) => Promise<void> | void

const globalBootstrapHooks: WorkspaceBootstrapHook[] = []

export function registerWorkspaceBootstrapHook(hook: WorkspaceBootstrapHook): void {
  globalBootstrapHooks.push(hook)
}

export interface CyberLabWorkspaceStatus {
  projectId: string
  workspaceRoot: string
  environment: ReturnType<typeof detectRuntimeEnvironment>
  activeScope: ProjectScope | undefined
  capabilityCount: number
  skillCount: number
  executionCount: number
  pendingApprovalCount: number
  evidenceCount: number
  findingCount: number
}

export class CyberLabWorkspace {
  readonly projectId: string
  readonly workspaceRoot: string
  readonly capabilities: ControlledCapabilityRegistry
  readonly schemas: InputOutputSchemaRegistry
  readonly executors: ExecutorRegistry
  readonly scopes: ScopeController
  readonly approvals: ApprovalManager
  readonly policy: PolicyEngine
  readonly evidenceStore: EvidenceStore
  readonly dispatcher: CyberLabExecutionDispatcher
  readonly skills: CyberLabSkillCatalog
  readonly partnerAuth: PartnerAuthenticator
  readonly partnerBridge: PartnerBridge
  readonly cdiHub: CdiPartnerHub
  readonly externalControl: ExternalControlPlane
  readonly httpProxy: CyberLabHttpProxy
  private initialized = false

  constructor(options: { projectId: string; workspaceRoot: string; inMemoryDb?: boolean }) {
    this.projectId = options.projectId
    this.workspaceRoot = path.resolve(options.workspaceRoot)

    const cfg = createDefaultCyberLabConfig(this.workspaceRoot)
    this.capabilities = new ControlledCapabilityRegistry()
    this.schemas = new InputOutputSchemaRegistry()
    this.executors = new ExecutorRegistry()
    this.scopes = new ScopeController()
    this.approvals = new ApprovalManager()
    this.policy = new PolicyEngine(this.capabilities, this.scopes, this.approvals)
    this.evidenceStore = new EvidenceStore({
      databasePath: options.inMemoryDb ? ":memory:" : cfg.databaseFilename,
      artifactsDir: cfg.artifactsDirectory,
    })
    this.dispatcher = new CyberLabExecutionDispatcher({
      capabilities: this.capabilities,
      schemas: this.schemas,
      executors: this.executors,
      scopes: this.scopes,
      approvals: this.approvals,
      policy: this.policy,
      evidenceStore: this.evidenceStore,
      defaultTimeoutMs: cfg.defaultTimeoutMs,
      maxOutputBytes: cfg.maxOutputBytes,
    })
    this.skills = new CyberLabSkillCatalog()
    this.partnerAuth = new PartnerAuthenticator(cfg.partnerMaxClockSkewMs)
    this.partnerBridge = new PartnerBridge({
      authenticator: this.partnerAuth,
      evidenceStore: this.evidenceStore,
      dispatcher: this.dispatcher,
      maxEnvelopeBytes: cfg.maxPartnerEnvelopeBytes,
    })
    this.externalControl = new ExternalControlPlane({
      projectId: this.projectId,
      workspaceRoot: this.workspaceRoot,
      scopes: this.scopes,
      evidenceStore: this.evidenceStore,
    })
    this.httpProxy = new CyberLabHttpProxy({
      projectId: this.projectId,
      scopes: this.scopes,
      evidenceStore: this.evidenceStore,
      ...(options.inMemoryDb ? {} : { workspaceRoot: this.workspaceRoot }),
    })
    this.cdiHub = new CdiPartnerHub({
      projectId: this.projectId,
      workspaceRoot: this.workspaceRoot,
      persistToDisk: !options.inMemoryDb,
      capabilities: this.capabilities,
      scopes: this.scopes,
      approvals: this.approvals,
      policy: this.policy,
      dispatcher: this.dispatcher,
      evidenceStore: this.evidenceStore,
      partnerAuth: this.partnerAuth,
      partnerBridge: this.partnerBridge,
      getStatusSnapshot: () => this.getStatus(),
    })
  }

  async ensureInitialized(): Promise<this> {
    if (this.initialized) return this
    this.initialized = true

    // Default safe local scope (external network disabled by default)
    this.scopes.setProjectScope({
      scopeId: `scope-${this.projectId}`,
      projectId: this.projectId,
      name: "Default Isolated Lab & Workspace Scope",
      workspaceRoot: this.workspaceRoot,
      allowedTargets: [
        { kind: "ip", value: "127.0.0.1", notes: "Localhost IPv4 loopback" },
        { kind: "domain", value: "localhost", notes: "Localhost loopback hostname" },
      ],
      blockedTargets: [
        { kind: "workspace_path", value: ".git", notes: "Protect repository VCS metadata" },
      ],
      allowExternalTargets: false,
      active: true,
      updatedAt: new Date().toISOString(),
    })

    // Register built-in read-only workspace audit executor & capability
    this.schemas.registerEffectSchema(WORKSPACE_AUDIT_INPUT_SCHEMA_ID, WorkspaceAuditInputSchema)
    this.executors.registerExecutor(new WorkspaceAuditExecutor())
    await this.capabilities.register(WorkspaceAuditCapability)

    // Register license-approved passive web & lab network assessment capabilities
    this.schemas.registerEffectSchema(HTTP_SECURITY_INSPECTOR_INPUT_SCHEMA_ID, HttpSecurityInspectorInputSchema)
    this.executors.registerExecutor(new WebHttpSecurityInspectorExecutor())
    await this.capabilities.register(HttpSecurityInspectorCapability)

    this.schemas.registerEffectSchema(HTTP_REPEATER_INPUT_SCHEMA_ID, HttpRepeaterInputSchema)
    this.executors.registerExecutor(new HttpRepeaterComparerExecutor())
    await this.capabilities.register(HttpRepeaterCapability)

    this.schemas.registerEffectSchema(DECODER_SEQUENCER_INPUT_SCHEMA_ID, DecoderSequencerInputSchema)
    this.executors.registerExecutor(new DecoderSequencerExecutor())
    await this.capabilities.register(DecoderSequencerCapability)

    this.schemas.registerEffectSchema(WEB_SURFACE_DISCOVERY_INPUT_SCHEMA_ID, WebSurfaceDiscoveryInputSchema)
    this.executors.registerExecutor(new WebSurfaceDiscoveryExecutor())
    await this.capabilities.register(WebSurfaceDiscoveryCapability)

    this.schemas.registerEffectSchema(TCP_SURFACE_PROBE_INPUT_SCHEMA_ID, TcpSurfaceProbeInputSchema)
    this.executors.registerExecutor(new TcpSurfaceInspectorExecutor())
    await this.capabilities.register(TcpSurfaceProbeCapability)

    this.schemas.registerEffectSchema(TLS_INSPECTOR_INPUT_SCHEMA_ID, TlsInspectorInputSchema)
    this.executors.registerExecutor(new TlsCertificateInspectorExecutor())
    await this.capabilities.register(TlsInspectorCapability)

    this.schemas.registerEffectSchema(PCAP_ANALYZER_INPUT_SCHEMA_ID, PcapAnalyzerInputSchema)
    this.executors.registerExecutor(new PcapPacketAnalyzerExecutor())
    await this.capabilities.register(PcapAnalyzerCapability)

    this.schemas.registerEffectSchema(BINARY_TRIAGE_INPUT_SCHEMA_ID, BinaryStaticTriageInputSchema)
    this.executors.registerExecutor(new BinaryStaticTriageExecutor())
    await this.capabilities.register(BinaryStaticTriageCapability)

    this.schemas.registerEffectSchema(MOBILE_TRIAGE_INPUT_SCHEMA_ID, MobileArtifactTriageInputSchema)
    this.executors.registerExecutor(new MobileArtifactTriageExecutor())
    await this.capabilities.register(MobileArtifactTriageCapability)

    this.schemas.registerEffectSchema(HTTP_INTRUDER_INPUT_SCHEMA_ID, HttpIntruderInputSchema)
    this.executors.registerExecutor(new HttpIntruderMatrixExecutor())
    await this.capabilities.register(HttpIntruderCapability)

    this.schemas.registerEffectSchema(WEB_PARAM_AUDIT_INPUT_SCHEMA_ID, WebParamAuditInputSchema)
    this.executors.registerExecutor(new DifferentialParamAuditorExecutor())
    await this.capabilities.register(WebParamAuditCapability)

    this.schemas.registerEffectSchema(DNS_RECON_INPUT_SCHEMA_ID, DnsReconInputSchema)
    this.executors.registerExecutor(new DnsSurfaceReconExecutor())
    await this.capabilities.register(DnsReconCapability)

    this.schemas.registerEffectSchema(BINARY_DISASM_INPUT_SCHEMA_ID, BinaryDisasmInputSchema)
    this.executors.registerExecutor(new BinaryDisassemblerExecutor())
    await this.capabilities.register(BinaryDisasmCapability)

    this.schemas.registerEffectSchema(YARA_SCAN_INPUT_SCHEMA_ID, YaraScanInputSchema)
    this.executors.registerExecutor(new YaraRuleScannerExecutor())
    await this.capabilities.register(YaraScanCapability)

    // Register governed External Tool Control Plane bridges (Nmap, Nuclei, ffuf, tshark, dalfox, ghidra, jadx, yarax)
    this.schemas.registerEffectSchema(EXTERNAL_NMAP_INPUT_SCHEMA_ID, ExternalNmapInputSchema)
    this.executors.registerExecutor(new ExternalNmapExecutor(() => this.workspaceRoot))
    await this.capabilities.register(ExternalNmapCapability)

    this.schemas.registerEffectSchema(EXTERNAL_NUCLEI_INPUT_SCHEMA_ID, ExternalNucleiInputSchema)
    this.executors.registerExecutor(new ExternalNucleiExecutor(() => this.workspaceRoot))
    await this.capabilities.register(ExternalNucleiCapability)

    this.schemas.registerEffectSchema(EXTERNAL_FFUF_INPUT_SCHEMA_ID, ExternalFfufInputSchema)
    this.executors.registerExecutor(new ExternalFfufExecutor(() => this.workspaceRoot))
    await this.capabilities.register(ExternalFfufCapability)

    this.schemas.registerEffectSchema(EXTERNAL_TSHARK_INPUT_SCHEMA_ID, ExternalTsharkInputSchema)
    this.executors.registerExecutor(new ExternalTsharkExecutor(() => this.workspaceRoot))
    await this.capabilities.register(ExternalTsharkCapability)

    this.schemas.registerEffectSchema(EXTERNAL_DALFOX_INPUT_SCHEMA_ID, ExternalDalfoxInputSchema)
    this.executors.registerExecutor(new ExternalDalfoxExecutor(() => this.workspaceRoot))
    await this.capabilities.register(ExternalDalfoxCapability)

    this.schemas.registerEffectSchema(EXTERNAL_GHIDRA_INPUT_SCHEMA_ID, ExternalGhidraInputSchema)
    this.executors.registerExecutor(new ExternalGhidraExecutor(() => this.workspaceRoot))
    await this.capabilities.register(ExternalGhidraCapability)

    this.schemas.registerEffectSchema(EXTERNAL_JADX_INPUT_SCHEMA_ID, ExternalJadxInputSchema)
    this.executors.registerExecutor(new ExternalJadxExecutor(() => this.workspaceRoot))
    await this.capabilities.register(ExternalJadxCapability)

    this.schemas.registerEffectSchema(EXTERNAL_YARAX_INPUT_SCHEMA_ID, ExternalYaraXInputSchema)
    this.executors.registerExecutor(new ExternalYaraXExecutor(() => this.workspaceRoot))
    await this.capabilities.register(ExternalYaraXCapability)

    // Load CyberLab skills
    this.skills.loadFromDirectory(repoSkillsDir)

    // Auto-register external partner (e.g. chat_py_bridge.py) when CYBERLAB_PARTNER_SECRET is configured
    const envPartnerSecret = process.env.CYBERLAB_PARTNER_SECRET
    if (envPartnerSecret && envPartnerSecret.length >= 16) {
      const partnerId = process.env.CYBERLAB_PARTNER_ID?.trim() || "chat-py-agent"
      const endpointUrl = process.env.CYBERLAB_PARTNER_URL?.trim() || "http://127.0.0.1:8788/cyberlab/partner"
      this.partnerAuth.registerPartner({
        partnerId,
        displayName: `External Partner Runtime (${partnerId})`,
        sharedSecret: envPartnerSecret,
        allowedActions: ["analyze.evidence", "propose.check"],
        prohibitedActions: ["shell.exec", "exploit.execute"],
        enabled: true,
      })
      this.partnerBridge.registerTransport(partnerId, new HttpPartnerTransport(endpointUrl))
    }

    for (const hook of globalBootstrapHooks) {
      await hook(this)
    }

    return this
  }

  async getStatus(): Promise<CyberLabWorkspaceStatus> {
    await this.ensureInitialized()
    const caps = await this.capabilities.list()
    return {
      projectId: this.projectId,
      workspaceRoot: this.workspaceRoot,
      environment: detectRuntimeEnvironment(this.workspaceRoot),
      activeScope: this.scopes.getProjectScope(this.projectId),
      capabilityCount: caps.length,
      skillCount: this.skills.list().length,
      executionCount: this.dispatcher.list(this.projectId).length,
      pendingApprovalCount: this.approvals.listPending(this.projectId).length,
      evidenceCount: this.evidenceStore.listEvidence(this.projectId).length,
      findingCount: this.evidenceStore.listFindings(this.projectId).length,
    }
  }

  async listCapabilities(): Promise<CapabilityDefinition[]> {
    await this.ensureInitialized()
    return this.capabilities.list()
  }

  async getScope(): Promise<ProjectScope | undefined> {
    await this.ensureInitialized()
    return this.scopes.getProjectScope(this.projectId)
  }

  async updateScope(patch: {
    name?: string
    allowedTargets?: ScopeTargetRule[]
    blockedTargets?: ScopeTargetRule[]
    allowExternalTargets?: boolean
    active?: boolean
  }): Promise<ProjectScope> {
    await this.ensureInitialized()
    const current = this.scopes.getProjectScope(this.projectId)
    return this.scopes.setProjectScope({
      scopeId: current?.scopeId ?? `scope-${this.projectId}`,
      projectId: this.projectId,
      name: patch.name ?? current?.name ?? "Project Scope",
      workspaceRoot: this.workspaceRoot,
      allowedTargets: patch.allowedTargets ?? current?.allowedTargets ?? [],
      blockedTargets: patch.blockedTargets ?? current?.blockedTargets ?? [],
      allowExternalTargets: patch.allowExternalTargets ?? current?.allowExternalTargets ?? false,
      active: patch.active ?? current?.active ?? true,
      updatedAt: new Date().toISOString(),
    })
  }

  async submitExecution(params: {
    capabilityId: string
    input: unknown
    mode?: ExecutionMode
    requestedBy?: { type: "user" | "assistant" | "partner"; id: string }
    idempotencyKey?: string
    parentSignal?: AbortSignal
  }): Promise<ExecutionRecord> {
    await this.ensureInitialized()
    return this.dispatcher.submit(
      {
        requestId: `req-${crypto.randomUUID()}`,
        projectId: this.projectId,
        capabilityId: params.capabilityId,
        requestedBy: params.requestedBy ?? { type: "user", id: "local-operator" },
        input: params.input,
        mode: params.mode ?? "manual",
        ...(params.idempotencyKey !== undefined ? { idempotencyKey: params.idempotencyKey } : {}),
      },
      { ...(params.parentSignal !== undefined ? { parentSignal: params.parentSignal } : {}) },
    )
  }

  async approveExecution(params: {
    approvalId: string
    decidedBy: string
    reason?: string
  }): Promise<ExecutionRecord> {
    await this.ensureInitialized()
    const ticket = this.approvals.decide(params.approvalId, "approved", params.decidedBy, params.reason)
    return this.dispatcher.approveAndRun(ticket.executionId, ticket.approvalId)
  }

  async rejectApproval(params: {
    approvalId: string
    decidedBy: string
    reason: string
  }): Promise<ApprovalTicket> {
    await this.ensureInitialized()
    const ticket = this.approvals.decide(params.approvalId, "rejected", params.decidedBy, params.reason)
    await this.dispatcher.cancel(ticket.executionId, `Rejected by ${params.decidedBy}: ${params.reason}`)
    return ticket
  }

  async cancelExecution(executionId: string, reason: string): Promise<void> {
    await this.ensureInitialized()
    await this.dispatcher.cancel(executionId, reason)
  }

  async listExecutions(): Promise<ExecutionRecord[]> {
    await this.ensureInitialized()
    return this.dispatcher.list(this.projectId)
  }

  async listPendingApprovals(): Promise<ApprovalTicket[]> {
    await this.ensureInitialized()
    return this.approvals.listPending(this.projectId)
  }

  async listEvidence(executionId?: string): Promise<EvidenceRecord[]> {
    await this.ensureInitialized()
    return this.evidenceStore.listEvidence(this.projectId, executionId)
  }

  async verifyEvidence(evidenceId: string, actor?: string): Promise<IntegrityCheckResult> {
    await this.ensureInitialized()
    return this.evidenceStore.verifyIntegrity(evidenceId, actor)
  }

  async readEvidenceContent(
    evidenceId: string,
    actor = "operator:workbench",
  ): Promise<{
    evidenceId: string
    kind: string
    title: string
    mediaType: string
    sha256: string
    redacted: boolean
    text: string
  }> {
    await this.ensureInitialized()
    const rec = this.evidenceStore.getEvidence(evidenceId)
    if (!rec || rec.projectId !== this.projectId) {
      throw new Error(`Evidence "${evidenceId}" not found in project "${this.projectId}"`)
    }
    const shared = this.evidenceStore.readRedactedForSharing(evidenceId, actor)
    return {
      evidenceId: rec.evidenceId,
      kind: rec.kind,
      title: rec.title,
      mediaType: rec.content.mediaType,
      sha256: shared.sha256,
      redacted: shared.redacted,
      text: shared.text,
    }
  }

  async getProxyOverview(): Promise<{ status: ProxyStatus; history: ProxyHistoryEntry[] }> {
    await this.ensureInitialized()
    return {
      status: this.httpProxy.getStatus(),
      history: this.httpProxy.listHistory(),
    }
  }

  async controlProxy(params: {
    action: "start" | "stop" | "clear" | "set_scope_only" | "set_https_mode"
    port?: number
    scopeOnly?: boolean
    httpsMode?: ProxyHttpsMode
    allowSelfSignedUpstream?: boolean
  }): Promise<{ status: ProxyStatus; history: ProxyHistoryEntry[] }> {
    await this.ensureInitialized()
    if (params.action === "start") {
      await this.httpProxy.start({
        ...(params.port !== undefined ? { port: params.port } : {}),
        ...(params.scopeOnly !== undefined ? { scopeOnly: params.scopeOnly } : {}),
        ...(params.httpsMode !== undefined ? { httpsMode: params.httpsMode } : {}),
        ...(params.allowSelfSignedUpstream !== undefined
          ? { allowSelfSignedUpstream: params.allowSelfSignedUpstream }
          : {}),
      })
    } else if (params.action === "stop") {
      await this.httpProxy.stop()
    } else if (params.action === "clear") {
      this.httpProxy.clearHistory()
    } else if (params.action === "set_scope_only") {
      this.httpProxy.setScopeOnly(params.scopeOnly ?? true)
    } else if (params.action === "set_https_mode") {
      this.httpProxy.setHttpsMode(params.httpsMode ?? "tls_intercept", params.allowSelfSignedUpstream)
    }
    return this.getProxyOverview()
  }

  async persistProxyEntry(entryId: string, actor?: string): Promise<{ evidenceId: string; sha256: string }> {
    await this.ensureInitialized()
    return this.httpProxy.persistEntryToEvidence(entryId, actor)
  }

  async listFindings(): Promise<SecurityFinding[]> {
    await this.ensureInitialized()
    return this.evidenceStore.listFindings(this.projectId)
  }

  async createFinding(params: {
    title: string
    description: string
    severity: FindingSeverity
    confidence?: number
    evidenceIds: string[]
    affectedAssets: string[]
    proposedRemediation?: string
    createdBy?: string
  }): Promise<SecurityFinding> {
    await this.ensureInitialized()
    return this.evidenceStore.createFinding({
      projectId: this.projectId,
      ...params,
    })
  }

  async reviewFinding(params: {
    findingId: string
    reviewedBy: string
    decision: "accept" | "reject" | "needs_more_evidence"
    notes?: string
  }): Promise<SecurityFinding> {
    await this.ensureInitialized()
    return this.evidenceStore.reviewFinding(params)
  }

  async generateMarkdownReport(projectName?: string): Promise<string> {
    await this.ensureInitialized()
    return renderAssessmentMarkdownReport({
      projectId: this.projectId,
      ...(projectName !== undefined ? { projectName } : {}),
      executions: this.dispatcher.list(this.projectId),
      evidence: this.evidenceStore.listEvidence(this.projectId),
      findings: this.evidenceStore.listFindings(this.projectId),
    })
  }

  async listExternalTools(): Promise<ExternalToolRuntimeStatus[]> {
    await this.ensureInitialized()
    return this.externalControl.listTools()
  }

  async ingestExternalAction(input: IngestExternalActionInput): Promise<IngestExternalActionResult> {
    await this.ensureInitialized()
    return this.externalControl.ingestExternalAction(input)
  }

  async syncExternalInbox(actor?: string): Promise<InboxSyncResult> {
    await this.ensureInitialized()
    return this.externalControl.syncInbox(actor)
  }

  async runSupervisedExternalCommand(params: {
    toolId: string
    binary: string
    args: readonly string[]
    target: string
    signal?: AbortSignal
    onStdoutChunk?: (chunk: string) => void
    onStderrChunk?: (chunk: string) => void
  }) {
    await this.ensureInitialized()
    return this.externalControl.runSupervisedExternalCommand(params)
  }

  async delegateToPartner(params: {
    partnerId?: string
    endpointUrl?: string
    sharedSecret?: string
    objective: string
    evidenceIds?: string[]
    contextText?: string
    timeoutMs?: number
  }): Promise<PartnerDispatchOutcome> {
    await this.ensureInitialized()
    const partnerId = params.partnerId?.trim() || process.env.CYBERLAB_PARTNER_ID?.trim() || "chat-py-agent"
    const secret = params.sharedSecret ?? process.env.CYBERLAB_PARTNER_SECRET
    const endpoint = params.endpointUrl?.trim() || process.env.CYBERLAB_PARTNER_URL?.trim()

    if (!this.partnerAuth.getPublicProfile(partnerId)) {
      if (!secret || secret.length < 16) {
        throw new Error(
          `Partner "${partnerId}" is not configured. Set CYBERLAB_PARTNER_SECRET (>= 16 chars) and run integrations/partners/chat_py_bridge.py.`,
        )
      }
      this.partnerAuth.registerPartner({
        partnerId,
        displayName: `External Partner Runtime (${partnerId})`,
        sharedSecret: secret,
        allowedActions: ["analyze.evidence", "propose.check"],
        prohibitedActions: ["shell.exec", "exploit.execute"],
        enabled: true,
      })
    }

    if (endpoint) {
      this.partnerBridge.registerTransport(partnerId, new HttpPartnerTransport(endpoint))
    }

    return this.partnerBridge.submitTask(
      partnerId,
      {
        taskId: `ptask-${crypto.randomUUID()}`,
        projectId: this.projectId,
        objective: params.objective,
        contextBundle: {
          evidenceIds: params.evidenceIds ?? [],
          ...(params.contextText !== undefined ? { text: params.contextText } : {}),
        },
        allowedActions: ["analyze.evidence", "propose.check"],
        prohibitedActions: ["shell.exec", "exploit.execute"],
        requestedOutput: {
          summary: true,
          findings: true,
          evidenceReferences: true,
          limitations: true,
        },
      },
      { ...(params.timeoutMs !== undefined ? { timeoutMs: params.timeoutMs } : {}) },
    )
  }

  async delegateToMultiplePartners(params: {
    partnerIds: string[]
    objective: string
    evidenceIds?: string[]
    contextText?: string
    timeoutMs?: number
  }): Promise<MultiCdiDispatchReport> {
    await this.ensureInitialized()
    return this.cdiHub.dispatchTasks(params)
  }

  close(): void {
    void this.httpProxy.stop()
    this.evidenceStore.close()
  }
}

export class CyberLabWorkspaceManager {
  static readonly global = new CyberLabWorkspaceManager()

  private readonly instances = new Map<string, CyberLabWorkspace>()

  async forProject(projectId: string, workspaceRoot: string): Promise<CyberLabWorkspace> {
    const key = `${projectId}::${path.resolve(workspaceRoot)}`
    const existing = this.instances.get(key)
    if (existing) {
      return existing.ensureInitialized()
    }
    const created = new CyberLabWorkspace({ projectId, workspaceRoot })
    this.instances.set(key, created)
    return created.ensureInitialized()
  }

  closeAll(): void {
    for (const ws of this.instances.values()) {
      ws.close()
    }
    this.instances.clear()
  }
}
