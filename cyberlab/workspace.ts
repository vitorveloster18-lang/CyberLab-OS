import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { createDefaultCyberLabConfig, detectRuntimeEnvironment } from "./config/config.js"
import type { CapabilityDefinition } from "./contracts/capability.js"
import type { EvidenceRecord, FindingSeverity, SecurityFinding } from "./contracts/evidence.js"
import type { ExecutionMode } from "./contracts/capability.js"
import type { ExecutionRecord } from "./contracts/execution.js"
import type {
  ApprovalTicket,
  BugBountyPlatform,
  EngagementProfile,
  ProjectScope,
  ScopeTargetRule,
} from "./contracts/policy.js"
import { createDefaultEngagementProfile } from "./contracts/policy.js"
import { EvidenceStore, type IntegrityCheckResult } from "./evidence/store.js"
import { CyberLabExecutionDispatcher } from "./execution/dispatcher.js"
import { TrainingLabManager, type TrainingLabStatus } from "./labs/training-labs.js"
import {
  listWorkspaceFiles as listWorkspaceFilesImpl,
  readWorkspaceFilePreview as readWorkspaceFilePreviewImpl,
  type WorkspaceFileEntry,
} from "./workspace-files.js"
import {
  CyberLabObsidianVault,
  type VaultNoteDocument,
  type VaultOverview,
} from "./vault/obsidian-vault.js"
import { PartnerAuthenticator } from "./partners/authentication.js"
import { PartnerBridge, type PartnerDispatchOutcome } from "./partners/bridge.js"
import {
  CdiPartnerHub,
  type CdiAutonomousEnvironmentBridge,
  type ManagedProjectSummary,
  type MultiCdiDispatchReport,
} from "./partners/cdi-hub.js"
import { HttpPartnerTransport } from "./partners/transport.js"
import { ApprovalManager } from "./policy/approval.js"
import { PolicyEngine } from "./policy/authorize.js"
import { ScopeController, parseBugBountyScopeImport } from "./policy/scope.js"
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
  readonly vault: CyberLabObsidianVault
  private readonly scopePersistencePath: string | null
  private readonly ownedManager?: CyberLabWorkspaceManager
  private initialized = false

  constructor(options: {
    projectId: string
    workspaceRoot: string
    inMemoryDb?: boolean
    environmentBridge?: CdiAutonomousEnvironmentBridge
  }) {
    this.projectId = options.projectId
    this.workspaceRoot = path.resolve(options.workspaceRoot)
    this.scopePersistencePath = options.inMemoryDb
      ? null
      : path.join(this.workspaceRoot, ".cyberlab", "scope.json")

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
    this.vault = new CyberLabObsidianVault({
      projectId: this.projectId,
      workspaceRoot: this.workspaceRoot,
      ...(options.inMemoryDb ? { globalConfigDir: path.join(this.workspaceRoot, ".cyberlab") } : {}),
    })

    let envBridge = options.environmentBridge
    if (!envBridge) {
      this.ownedManager = new CyberLabWorkspaceManager({
        projectsRootDir: path.join(this.workspaceRoot, ".cyberlab", "projects"),
        // v6.6: permite alinhar o servidor (UI) com o CLI — antes cada um usava
        // uma raiz diferente e um não enxergava o laboratório do outro.
        labsRootDir:
          process.env.CYBERLAB_LABS_ROOT?.trim() ||
          path.join(this.workspaceRoot, ".cyberlab", "training-labs"),
        inMemoryChildren: Boolean(options.inMemoryDb),
      })
      this.ownedManager.registerExistingWorkspace(this, {
        name: this.projectId,
        createdBy: "curator",
        isTrainingLab: false,
      })
      envBridge = this.ownedManager.createEnvironmentBridge()
    }

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
      environmentBridge: envBridge,
    })
  }

  private persistScopeToDisk(scope: ProjectScope): void {
    if (!this.scopePersistencePath) return
    try {
      mkdirSync(path.dirname(this.scopePersistencePath), { recursive: true })
      writeFileSync(this.scopePersistencePath, `${JSON.stringify(scope, null, 2)}\n`, "utf8")
    } catch {
      // Non-fatal best-effort persistence
    }
  }

  private tryLoadScopeFromDisk(): ProjectScope | null {
    if (!this.scopePersistencePath || !existsSync(this.scopePersistencePath)) return null
    try {
      const parsed = JSON.parse(readFileSync(this.scopePersistencePath, "utf8")) as ProjectScope
      if (!parsed || typeof parsed !== "object") return null
      return this.scopes.setProjectScope({
        ...parsed,
        projectId: this.projectId,
        workspaceRoot: this.workspaceRoot,
      })
    } catch {
      return null
    }
  }

  async ensureInitialized(): Promise<this> {
    if (this.initialized) return this
    this.initialized = true

    const restoredScope = this.tryLoadScopeFromDisk()
    if (!restoredScope) {
      // Default safe local scope (external network disabled by default until operator configures scope)
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
        engagement: createDefaultEngagementProfile(),
        active: true,
        updatedAt: new Date().toISOString(),
      })
    }

    // Register built-in read-only workspace audit executor & capability
    this.schemas.registerEffectSchema(WORKSPACE_AUDIT_INPUT_SCHEMA_ID, WorkspaceAuditInputSchema)
    this.executors.registerExecutor(new WorkspaceAuditExecutor())
    await this.capabilities.register(WorkspaceAuditCapability)

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
    engagement?: EngagementProfile
    active?: boolean
  }): Promise<ProjectScope> {
    await this.ensureInitialized()
    const current = this.scopes.getProjectScope(this.projectId)
    const nextEngagement = patch.engagement ?? current?.engagement ?? createDefaultEngagementProfile()
    const updated = this.scopes.setProjectScope({
      scopeId: current?.scopeId ?? `scope-${this.projectId}`,
      projectId: this.projectId,
      name: patch.name ?? current?.name ?? "Project Scope",
      workspaceRoot: this.workspaceRoot,
      allowedTargets: patch.allowedTargets ?? current?.allowedTargets ?? [],
      blockedTargets: patch.blockedTargets ?? current?.blockedTargets ?? [],
      allowExternalTargets: patch.allowExternalTargets ?? current?.allowExternalTargets ?? false,
      engagement: nextEngagement,
      active: patch.active ?? current?.active ?? true,
      updatedAt: new Date().toISOString(),
    })
    this.persistScopeToDisk(updated)
    return updated
  }

  async importBugBountyScope(params: {
    rawInput: string
    platformHint?: BugBountyPlatform
    researcherHandle?: string
    headerName?: string
    headerValue?: string
    maxRequestsPerSecond?: number
    mergeWithExisting?: boolean
  }): Promise<{
    scope: ProjectScope
    detectedFormat: string
    importedAllowedCount: number
    importedBlockedCount: number
  }> {
    await this.ensureInitialized()
    const parsed = parseBugBountyScopeImport(params.rawInput, {
      ...(params.platformHint ? { platformHint: params.platformHint } : {}),
      ...(params.researcherHandle ? { researcherHandle: params.researcherHandle } : {}),
      ...(params.headerName ? { headerName: params.headerName } : {}),
      ...(params.headerValue ? { headerValue: params.headerValue } : {}),
      ...(params.maxRequestsPerSecond !== undefined ? { maxRequestsPerSecond: params.maxRequestsPerSecond } : {}),
    })
    const current = this.scopes.getProjectScope(this.projectId)
    const merge = params.mergeWithExisting ?? true

    const dedupRules = (rules: ScopeTargetRule[]): ScopeTargetRule[] => {
      const seen = new Set<string>()
      const out: ScopeTargetRule[] = []
      for (const r of rules) {
        const key = `${r.kind}:${r.value.toLowerCase()}`
        if (seen.has(key)) continue
        seen.add(key)
        out.push(r)
      }
      return out
    }

    const allowedTargets = dedupRules([
      ...(merge ? (current?.allowedTargets ?? []) : []),
      ...parsed.allowedTargets,
    ])
    const blockedTargets = dedupRules([
      ...(merge ? (current?.blockedTargets ?? []) : []),
      ...parsed.blockedTargets,
    ])

    const updated = await this.updateScope({
      name: parsed.programName ? `Bug Bounty — ${parsed.programName}` : current?.name ?? "Bug Bounty Program Scope",
      allowedTargets,
      blockedTargets,
      allowExternalTargets: parsed.allowExternalTargets || Boolean(current?.allowExternalTargets),
      engagement: parsed.engagement,
      active: true,
    })

    return {
      scope: updated,
      detectedFormat: parsed.detectedFormat,
      importedAllowedCount: parsed.allowedTargets.length,
      importedBlockedCount: parsed.blockedTargets.length,
    }
  }

  async importArtifactToWorkspace(params: {
    fileName: string
    contentBase64: string
    subdir?: string
  }): Promise<{
    fileName: string
    relativePath: string
    absolutePath: string
    sizeBytes: number
  }> {
    await this.ensureInitialized()
    const safeName = path
      .basename(params.fileName || "artifact.bin")
      .replace(/[^a-zA-Z0-9._-]/g, "_")
      .slice(0, 140)
    if (!safeName || safeName === "." || safeName === "..") {
      throw new Error("Invalid artifact fileName")
    }
    const cleanSubdir = (params.subdir ?? "imports").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 40) || "imports"
    const cleanBase64 = params.contentBase64.includes(",")
      ? params.contentBase64.slice(params.contentBase64.indexOf(",") + 1)
      : params.contentBase64
    const buf = Buffer.from(cleanBase64, "base64")
    if (buf.byteLength > 48 * 1024 * 1024) {
      throw new Error("Imported artifact exceeds 48 MB inline upload limit; add an external workspace_path in Scope instead")
    }

    const targetDir = path.join(this.workspaceRoot, ".cyberlab", cleanSubdir)
    mkdirSync(targetDir, { recursive: true })
    const absolutePath = path.join(targetDir, safeName)
    writeFileSync(absolutePath, buf)
    const relativePath = path.posix.join(".cyberlab", cleanSubdir, safeName)
    return {
      fileName: safeName,
      relativePath,
      absolutePath,
      sizeBytes: buf.byteLength,
    }
  }

  async listImportedArtifacts(): Promise<
    Array<{ fileName: string; relativePath: string; sizeBytes: number; modifiedAt: string }>
  > {
    await this.ensureInitialized()
    const targetDir = path.join(this.workspaceRoot, ".cyberlab", "imports")
    if (!existsSync(targetDir)) return []
    const items: Array<{ fileName: string; relativePath: string; sizeBytes: number; modifiedAt: string }> = []
    for (const entry of readdirSync(targetDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue
      const abs = path.join(targetDir, entry.name)
      const st = statSync(abs, { throwIfNoEntry: false })
      if (!st) continue
      items.push({
        fileName: entry.name,
        relativePath: path.posix.join(".cyberlab", "imports", entry.name),
        sizeBytes: st.size,
        modifiedAt: st.mtime.toISOString(),
      })
    }
    items.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt))
    return items
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

  async listWorkspaceFiles(relativeDir = "."): Promise<{
    currentDir: string
    entries: WorkspaceFileEntry[]
  }> {
    await this.ensureInitialized()
    return listWorkspaceFilesImpl(this.workspaceRoot, relativeDir)
  }

  async readWorkspaceFilePreview(relativeFilePath: string): Promise<{
    relativePath: string
    sizeBytes: number
    truncated: boolean
    content: string
  }> {
    await this.ensureInitialized()
    return readWorkspaceFilePreviewImpl(this.workspaceRoot, relativeFilePath)
  }

  async getVaultOverview(): Promise<VaultOverview> {
    await this.ensureInitialized()
    return this.vault.getOverview()
  }

  async readVaultNote(relativePath: string): Promise<VaultNoteDocument> {
    await this.ensureInitialized()
    return this.vault.readNote(relativePath)
  }

  async writeVaultNote(
    relativePath: string,
    content: string,
  ): Promise<{ note: VaultNoteDocument; overview: VaultOverview }> {
    await this.ensureInitialized()
    return this.vault.writeNote(relativePath, content)
  }

  async deleteVaultNote(relativePath: string): Promise<VaultOverview> {
    await this.ensureInitialized()
    return this.vault.deleteNote(relativePath)
  }

  async configureVaultRoot(customDir?: string | null): Promise<VaultOverview> {
    await this.ensureInitialized()
    return this.vault.setCustomVaultRoot(customDir)
  }

  async persistOutputToEvidence(params: {
    title: string
    content: string
    slotId?: string
    actor?: string
  }): Promise<{ evidenceId: string; sha256: string }> {
    await this.ensureInitialized()
    const rec = this.evidenceStore.storeEvidence(
      this.projectId,
      {
        kind: "stdout",
        title: params.title,
        source: {
          toolId: params.slotId ?? "manual-ingest",
          executorId: "cyberlab-workspace",
          executionId: `ing-${crypto.randomUUID().slice(0, 8)}`,
        },
        content: {
          mediaType: "text/plain",
          inlineText: params.content,
        },
        observedAt: new Date().toISOString(),
      },
      { applyRedactionBeforeStore: true },
    )
    return { evidenceId: rec.evidenceId, sha256: rec.content.sha256 ?? "" }
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

  private closed = false

  close(): void {
    if (this.closed) return
    this.closed = true
    if (this.ownedManager) {
      this.ownedManager.closeAll()
    }
    this.evidenceStore.close()
  }
}

interface ManagedProjectMeta {
  projectId: string
  name: string
  workspaceRoot: string
  createdBy: string
  createdAt: string
  isTrainingLab: boolean
  labId?: string
}

const RUNTIME_REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

function slugifyProjectName(input: string): string {
  const cleaned = input
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
  return cleaned || `project-${Date.now()}`
}

export class CyberLabWorkspaceManager {
  static readonly global = new CyberLabWorkspaceManager()

  readonly runtimeRoot: string
  readonly projectsRootDir: string
  readonly trainingLabs: TrainingLabManager

  private readonly instances = new Map<string, CyberLabWorkspace>()
  private readonly projectRegistry = new Map<string, ManagedProjectMeta>()
  private readonly inMemoryChildren: boolean
  private readonly registryFilePath: string | null
  private lastActiveKey: string | null = null

  constructor(options?: {
    runtimeRoot?: string
    projectsRootDir?: string
    labsRootDir?: string
    inMemoryChildren?: boolean
  }) {
    this.runtimeRoot = path.resolve(options?.runtimeRoot ?? RUNTIME_REPO_ROOT)
    this.projectsRootDir = path.resolve(
      options?.projectsRootDir ?? path.join(this.runtimeRoot, ".cyberlab", "projects"),
    )
    const labsRoot = path.resolve(
      options?.labsRootDir ?? path.join(this.runtimeRoot, ".cyberlab", "training-labs"),
    )
    this.inMemoryChildren = Boolean(options?.inMemoryChildren)
    this.trainingLabs = new TrainingLabManager(labsRoot)
    this.registryFilePath = this.inMemoryChildren
      ? null
      : path.join(path.dirname(this.projectsRootDir), "managed-projects.json")
    this.loadPersistedRegistry()
  }

  private loadPersistedRegistry(): void {
    if (!this.registryFilePath || !existsSync(this.registryFilePath)) return
    try {
      const parsed = JSON.parse(readFileSync(this.registryFilePath, "utf8")) as {
        projects?: ManagedProjectMeta[]
      }
      if (Array.isArray(parsed.projects)) {
        for (const p of parsed.projects) {
          if (p && p.projectId && p.workspaceRoot && existsSync(p.workspaceRoot)) {
            this.projectRegistry.set(this.keyFor(p.projectId, p.workspaceRoot), p)
          }
        }
      }
    } catch {
      // Ignore malformed registry
    }
  }

  private savePersistedRegistry(): void {
    if (!this.registryFilePath) return
    try {
      mkdirSync(path.dirname(this.registryFilePath), { recursive: true })
      writeFileSync(
        this.registryFilePath,
        `${JSON.stringify({ projects: Array.from(this.projectRegistry.values()) }, null, 2)}\n`,
        "utf8",
      )
    } catch {
      // Best-effort persistence
    }
  }

  private keyFor(projectId: string, workspaceRoot: string): string {
    return `${projectId}::${path.resolve(workspaceRoot)}`
  }

  registerExistingWorkspace(
    ws: CyberLabWorkspace,
    meta: { name: string; createdBy: string; isTrainingLab: boolean; labId?: string },
  ): void {
    const key = this.keyFor(ws.projectId, ws.workspaceRoot)
    this.instances.set(key, ws)
    if (!this.lastActiveKey) this.lastActiveKey = key
    this.projectRegistry.set(key, {
      projectId: ws.projectId,
      name: meta.name,
      workspaceRoot: ws.workspaceRoot,
      createdBy: meta.createdBy,
      createdAt: new Date().toISOString(),
      isTrainingLab: meta.isTrainingLab,
      ...(meta.labId ? { labId: meta.labId } : {}),
    })
  }

  async forProject(projectId: string, workspaceRoot: string, markActive = true): Promise<CyberLabWorkspace> {
    const absRoot = path.resolve(workspaceRoot)
    const key = this.keyFor(projectId, absRoot)
    const existing = this.instances.get(key)
    if (existing) {
      if (markActive) this.lastActiveKey = key
      return existing.ensureInitialized()
    }

    // Capture active hub credentials so newly created/opened workspaces share the same CDI HMAC keys seamlessly
    const activeHub = this.lastActiveKey ? this.instances.get(this.lastActiveKey)?.cdiHub : undefined

    const created = new CyberLabWorkspace({
      projectId,
      workspaceRoot: absRoot,
      inMemoryDb: this.inMemoryChildren,
      environmentBridge: this.createEnvironmentBridge(),
    })
    if (activeHub) {
      created.cdiHub.importCredentialsSnapshot(activeHub.exportCredentialsSnapshot())
    }
    this.instances.set(key, created)
    if (!this.projectRegistry.has(key)) {
      this.projectRegistry.set(key, {
        projectId,
        name: path.basename(absRoot) || projectId,
        workspaceRoot: absRoot,
        createdBy: "curator",
        createdAt: new Date().toISOString(),
        isTrainingLab: false,
      })
      this.savePersistedRegistry()
    }
    if (markActive) this.lastActiveKey = key
    return created.ensureInitialized()
  }

  async forInboundGateway(fallbackProjectId: string, fallbackRoot: string, hasExplicitDir: boolean): Promise<CyberLabWorkspace> {
    if (!hasExplicitDir && this.lastActiveKey) {
      const active = this.instances.get(this.lastActiveKey)
      if (active) {
        return active.ensureInitialized()
      }
    }
    return this.forProject(fallbackProjectId, fallbackRoot, false)
  }

  listManagedProjects(): ManagedProjectSummary[] {
    return Array.from(this.projectRegistry.entries()).map(([key, meta]) => ({
      projectId: meta.projectId,
      name: meta.name,
      workspaceRoot: meta.workspaceRoot,
      isActive: this.lastActiveKey === key,
      createdBy: meta.createdBy,
      createdAt: meta.createdAt,
      isTrainingLab: meta.isTrainingLab,
      ...(meta.labId ? { labId: meta.labId } : {}),
    }))
  }

  async createAutonomousProject(params: {
    name: string
    slug?: string
    directory?: string
    files?: Record<string, string>
    allowedTargets?: ScopeTargetRule[]
    allowExternalTargets?: boolean
    createdBy: string
    setActive?: boolean
    sourceHub?: CdiPartnerHub
  }): Promise<{ project: ManagedProjectSummary; scope: ProjectScope | undefined; filesWritten: string[] }> {
    const slug = slugifyProjectName(params.slug ?? params.name)
    const targetDir = params.directory
      ? path.resolve(params.directory)
      : path.join(this.projectsRootDir, slug)

    mkdirSync(targetDir, { recursive: true })

    // Seed README if empty and no README specified
    const initialFiles: Record<string, string> = {
      "README.md": `# ${params.name}\n\nProjeto autônomo criado por \`${params.createdBy}\` no CyberLab OS.\n`,
      ...(params.files ?? {}),
    }

    const filesWritten: string[] = []
    for (const [relPath, fileContent] of Object.entries(initialFiles)) {
      const cleaned = relPath.trim()
      if (!cleaned || cleaned.includes("\0")) continue
      const absFile = path.resolve(targetDir, cleaned)
      const relCheck = path.relative(targetDir, absFile)
      if (relCheck.startsWith("..") || path.isAbsolute(relCheck)) continue
      mkdirSync(path.dirname(absFile), { recursive: true })
      writeFileSync(absFile, fileContent, "utf8")
      filesWritten.push(relCheck.replace(/\\/g, "/"))
    }

    const projectId = `proj-${slug}`
    if (!existsSync(path.join(targetDir, ".git"))) {
      try {
        execFileSync("git", ["init", "-q"], { cwd: targetDir, stdio: "ignore" })
      } catch {
        // git optional
      }
    }
    const dotGitDir = path.join(targetDir, ".git")
    if (existsSync(dotGitDir)) {
      writeFileSync(path.join(dotGitDir, "opencode"), `${projectId}\n`, "utf8")
    }
    const key = this.keyFor(projectId, targetDir)
    this.projectRegistry.set(key, {
      projectId,
      name: params.name,
      workspaceRoot: targetDir,
      createdBy: params.createdBy,
      createdAt: new Date().toISOString(),
      isTrainingLab: false,
    })
    this.savePersistedRegistry()

    const ws = await this.forProject(projectId, targetDir, params.setActive !== false)
    if (params.sourceHub) {
      ws.cdiHub.importCredentialsSnapshot(params.sourceHub.exportCredentialsSnapshot())
    }

    const scope = ws.scopes.getProjectScope(projectId)
    if (scope && (params.allowedTargets || typeof params.allowExternalTargets === "boolean")) {
      const mergedRules = [...scope.allowedTargets]
      for (const r of params.allowedTargets ?? []) {
        if (r && r.kind && r.value && !mergedRules.some((m) => m.kind === r.kind && m.value === r.value)) {
          mergedRules.push(r)
        }
      }
      ws.scopes.setProjectScope({
        ...scope,
        name: params.name,
        allowedTargets: mergedRules,
        allowExternalTargets:
          typeof params.allowExternalTargets === "boolean"
            ? params.allowExternalTargets
            : scope.allowExternalTargets,
        updatedAt: new Date().toISOString(),
      })
    }

    const summary = this.listManagedProjects().find((p) => p.projectId === projectId && p.workspaceRoot === targetDir)!
    return {
      project: summary,
      scope: ws.scopes.getProjectScope(projectId),
      filesWritten,
    }
  }

  async selectProject(params: {
    projectId?: string
    directory?: string
    sourceHub?: CdiPartnerHub
  }): Promise<ManagedProjectSummary> {
    let foundEntry: [string, ManagedProjectMeta] | undefined
    if (params.projectId) {
      foundEntry = Array.from(this.projectRegistry.entries()).find(([, m]) => m.projectId === params.projectId)
    }
    if (!foundEntry && params.directory) {
      const absDir = path.resolve(params.directory)
      foundEntry = Array.from(this.projectRegistry.entries()).find(([, m]) => m.workspaceRoot === absDir)
      if (!foundEntry && existsSync(absDir)) {
        const slug = slugifyProjectName(path.basename(absDir))
        const pid = `proj-${slug}`
        await this.forProject(pid, absDir, true)
        foundEntry = Array.from(this.projectRegistry.entries()).find(([, m]) => m.workspaceRoot === absDir)
      }
    }
    if (!foundEntry) {
      throw new Error(`Project not found for projectId="${params.projectId ?? ""}" directory="${params.directory ?? ""}"`)
    }
    const [, meta] = foundEntry
    const ws = await this.forProject(meta.projectId, meta.workspaceRoot, true)
    if (params.sourceHub) {
      ws.cdiHub.importCredentialsSnapshot(params.sourceHub.exportCredentialsSnapshot())
    }
    return this.listManagedProjects().find((p) => p.projectId === meta.projectId && p.workspaceRoot === meta.workspaceRoot)!
  }

  async startTrainingLab(params: {
    labId: string
    preferredPort?: number
    resetFiles?: boolean
    setActive?: boolean
    startedBy: string
    sourceHub?: CdiPartnerHub
  }): Promise<TrainingLabStatus> {
    const status = await this.trainingLabs.startLab({
      labId: params.labId,
      ...(params.preferredPort !== undefined ? { preferredPort: params.preferredPort } : {}),
      ...(params.resetFiles !== undefined ? { resetFiles: params.resetFiles } : {}),
    })

    const key = this.keyFor(status.projectId, status.workspaceRoot)
    this.projectRegistry.set(key, {
      projectId: status.projectId,
      name: `[Lab] ${status.title}`,
      workspaceRoot: status.workspaceRoot,
      createdBy: params.startedBy,
      createdAt: status.startedAt ?? new Date().toISOString(),
      isTrainingLab: true,
      labId: status.labId,
    })
    this.savePersistedRegistry()

    const previousActiveWs = this.lastActiveKey ? this.instances.get(this.lastActiveKey) : undefined
    const labWs = await this.forProject(status.projectId, status.workspaceRoot, params.setActive !== false)
    if (params.sourceHub) {
      labWs.cdiHub.importCredentialsSnapshot(params.sourceHub.exportCredentialsSnapshot())
    }

    // Automatically authorize the live training lab URL origin inside both the lab project scope and previous active scope
    if (status.baseUrl) {
      for (const targetWs of [labWs, previousActiveWs]) {
        if (!targetWs) continue
        const sc = targetWs.scopes.getProjectScope(targetWs.projectId)
        if (sc && !sc.allowedTargets.some((r) => r.value === status.baseUrl)) {
          targetWs.scopes.setProjectScope({
            ...sc,
            allowedTargets: [
              ...sc.allowedTargets,
              {
                kind: "url_origin",
                value: status.baseUrl,
                notes: `Training Lab ${status.title} (${status.labId})`,
              },
            ],
            updatedAt: new Date().toISOString(),
          })
        }
      }
    }

    return status
  }

  async resetTrainingLab(labId: string): Promise<TrainingLabStatus> {
    return this.trainingLabs.resetLab(labId)
  }

  async stopTrainingLab(labId: string): Promise<TrainingLabStatus> {
    return this.trainingLabs.stopLab(labId)
  }

  createEnvironmentBridge(): CdiAutonomousEnvironmentBridge {
    return {
      runtimeRoot: this.runtimeRoot,
      listProjects: () => this.listManagedProjects(),
      createProject: (p) => this.createAutonomousProject(p),
      selectProject: (p) => this.selectProject(p),
      listTrainingLabs: () => this.trainingLabs.listLabs(),
      getTrainingLabStatus: (labId) => this.trainingLabs.getLabStatus(labId),
      startTrainingLab: (p) => this.startTrainingLab(p),
      resetTrainingLab: (labId) => this.resetTrainingLab(labId),
      stopTrainingLab: (labId) => this.stopTrainingLab(labId),
    }
  }

  closeAll(): void {
    void this.trainingLabs.stopAll()
    for (const ws of this.instances.values()) {
      ws.close()
    }
    this.instances.clear()
    this.lastActiveKey = null
  }
}
