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
import { PartnerBridge } from "./partners/bridge.js"
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
  TCP_SURFACE_PROBE_INPUT_SCHEMA_ID,
  TcpSurfaceInspectorExecutor,
  TcpSurfaceProbeCapability,
  TcpSurfaceProbeInputSchema,
} from "../integrations/network-observation/tcp-banner-inspector.js"

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

    this.schemas.registerEffectSchema(TCP_SURFACE_PROBE_INPUT_SCHEMA_ID, TcpSurfaceProbeInputSchema)
    this.executors.registerExecutor(new TcpSurfaceInspectorExecutor())
    await this.capabilities.register(TcpSurfaceProbeCapability)

    // Load CyberLab skills
    this.skills.loadFromDirectory(repoSkillsDir)

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

  close(): void {
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
