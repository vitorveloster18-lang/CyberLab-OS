import crypto, { timingSafeEqual } from "node:crypto"
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs"
import path from "node:path"
import type { CapabilityRegistry } from "../contracts/capability.js"
import type { EvidenceKind, FindingSeverity } from "../contracts/evidence.js"
import type { EvidenceStore } from "../evidence/store.js"
import { canonicalJson } from "../evidence/hashing.js"
import { redactSensitiveContent } from "../evidence/provenance.js"
import type { CyberLabExecutionDispatcher } from "../execution/dispatcher.js"
import type { ApprovalManager } from "../policy/approval.js"
import type { PolicyEngine } from "../policy/authorize.js"
import type { ScopeController } from "../policy/scope.js"
import { PartnerAuthError, type PartnerAuthenticator } from "./authentication.js"
import type { PartnerBridge, PartnerDispatchOutcome } from "./bridge.js"
import { HttpPartnerTransport } from "./transport.js"

export type CdiInitiateMode = "disabled" | "propose_only" | "allow_readonly_propose_others"

export interface CdiPartnerPermissions {
  readProjectState: boolean
  readEvidenceAndFiles: boolean
  createArtifactsAndFindings: boolean
  initiateActions: CdiInitiateMode
}

export interface CdiPartnerEntry {
  partnerId: string
  displayName: string
  specialty: string
  endpointUrl: string
  enabled: boolean
  /** Optional per-CDI secret override; if omitted, inherits global sharedSecret. */
  secretOverride?: string
  permissions: CdiPartnerPermissions
}

export interface CdiPublicPartnerEntry extends Omit<CdiPartnerEntry, "secretOverride"> {
  usesCustomSecret: boolean
}

interface PersistedPartnersFile {
  version: "1.0"
  sharedSecret: string
  cyberlabCallbackUrl?: string
  partners: CdiPartnerEntry[]
  updatedAt: string
}

export type CdiInboundAction =
  | "project.state"
  | "evidence.list"
  | "evidence.read"
  | "workspace.list_files"
  | "workspace.read_file"
  | "artifact.create"
  | "finding.propose"
  | "action.initiate"
  | "execution.status"

export interface CdiInboundRequestEnvelope {
  protocol: "cyberlab-cdi-gateway"
  protocolVersion: "1.0"
  messageId: string
  sentAt: string
  partnerId: string
  action: CdiInboundAction
  params?: Record<string, unknown>
  signature: string
}

export interface CdiInboundResponseEnvelope {
  protocol: "cyberlab-cdi-gateway"
  protocolVersion: "1.0"
  messageId: string
  inReplyTo: string
  sentAt: string
  ok: boolean
  data?: unknown
  error?: string
  signature: string
}

export interface CdiInboundActivityEntry {
  activityId: string
  partnerId: string
  action: string
  outcome: "allowed" | "queued_for_approval" | "denied"
  summary: string
  timestamp: string
}

export interface MultiCdiDispatchItem {
  partnerId: string
  displayName: string
  ok: boolean
  durationMs: number
  outcome?: PartnerDispatchOutcome
  error?: string
}

export interface MultiCdiDispatchReport {
  mode: "single" | "parallel"
  objective: string
  totalDispatched: number
  succeededCount: number
  failedCount: number
  results: MultiCdiDispatchItem[]
}

const DEFAULT_PERMISSIONS: CdiPartnerPermissions = {
  readProjectState: true,
  readEvidenceAndFiles: true,
  createArtifactsAndFindings: true,
  initiateActions: "allow_readonly_propose_others",
}

export const FOUR_CDI_PRESET_ENTRIES: readonly CdiPartnerEntry[] = [
  {
    partnerId: "kairos",
    displayName: "Kairós",
    specialty: "Arquitetura de Segurança, Modelagem de Ameaças e Estratégia de Mitigação",
    endpointUrl: "http://127.0.0.1:8788/cyberlab/partner",
    enabled: true,
    permissions: { ...DEFAULT_PERMISSIONS },
  },
  {
    partnerId: "naia",
    displayName: "Naia",
    specialty: "Pesquisa Profunda, Forense Digital, Evidências e Inteligência de Ameaças",
    endpointUrl: "http://127.0.0.1:8789/cyberlab/partner",
    enabled: true,
    permissions: { ...DEFAULT_PERMISSIONS },
  },
  {
    partnerId: "salem",
    displayName: "Salem",
    specialty: "Análise de Logs, Triagem de CVEs, Resposta a Incidentes e Correlação de Alertas",
    endpointUrl: "http://127.0.0.1:8790/cyberlab/partner",
    enabled: true,
    permissions: { ...DEFAULT_PERMISSIONS },
  },
  {
    partnerId: "nova",
    displayName: "Nova",
    specialty: "Auditoria de Código, Revisão de Superfície de Ataque e Validação Técnica",
    endpointUrl: "http://127.0.0.1:8791/cyberlab/partner",
    enabled: true,
    permissions: { ...DEFAULT_PERMISSIONS },
  },
]

const MAX_INBOUND_BODY_BYTES = 256 * 1024
const MAX_WORKSPACE_READ_BYTES = 128 * 1024
const BLOCKED_WORKSPACE_SEGMENTS = new Set([".git", ".cyberlab", "node_modules"])

function computeGatewayHmac(payloadWithoutSig: Record<string, unknown>, secret: string): string {
  const canonical = canonicalJson(payloadWithoutSig)
  return crypto.createHmac("sha256", secret).update(canonical, "utf8").digest("hex")
}

function isSensitiveDotfile(relPath: string): boolean {
  const base = path.basename(relPath).toLowerCase()
  return (
    base === ".env" ||
    (base.startsWith(".env.") && base !== ".env.example") ||
    base.endsWith(".pem") ||
    base.endsWith(".key") ||
    base === "id_rsa" ||
    base === "id_ed25519"
  )
}

export interface CdiPartnerHubDeps {
  projectId: string
  workspaceRoot: string
  persistToDisk: boolean
  capabilities: CapabilityRegistry
  scopes: ScopeController
  approvals: ApprovalManager
  policy: PolicyEngine
  dispatcher: CyberLabExecutionDispatcher
  evidenceStore: EvidenceStore
  partnerAuth: PartnerAuthenticator
  partnerBridge: PartnerBridge
  getStatusSnapshot: () => Promise<unknown>
}

export class CdiPartnerHub {
  private sharedSecret: string
  private cyberlabCallbackUrl: string
  private readonly partners = new Map<string, CdiPartnerEntry>()
  private readonly seenInboundIds = new Map<string, number>()
  private readonly inboundActivity: CdiInboundActivityEntry[] = []
  private readonly configPath: string
  private readonly maxClockSkewMs = 5 * 60 * 1000
  private readonlyPolicyRuleInstalled = false

  constructor(private readonly deps: CdiPartnerHubDeps) {
    this.configPath = path.join(deps.workspaceRoot, ".cyberlab", "partners.json")
    this.sharedSecret =
      process.env.CYBERLAB_PARTNER_SECRET?.trim() && process.env.CYBERLAB_PARTNER_SECRET.trim().length >= 16
        ? process.env.CYBERLAB_PARTNER_SECRET.trim()
        : crypto.randomBytes(32).toString("hex")
    this.cyberlabCallbackUrl =
      process.env.CYBERLAB_CALLBACK_URL?.trim() || "http://127.0.0.1:4096/api/cyberlab/partner-gateway"

    this.loadInitialConfig()
    this.syncAllToAuthenticator()
  }

  private loadInitialConfig(): void {
    const candidates = [
      this.configPath,
      path.join(this.deps.workspaceRoot, "config", "partners.json"),
    ]
    for (const candidate of candidates) {
      if (!existsSync(candidate)) continue
      try {
        const raw = JSON.parse(readFileSync(candidate, "utf8")) as Partial<PersistedPartnersFile>
        if (typeof raw.sharedSecret === "string" && raw.sharedSecret.trim().length >= 16) {
          // Explicit env var still overrides if user set CYBERLAB_PARTNER_SECRET in shell
          if (!process.env.CYBERLAB_PARTNER_SECRET?.trim()) {
            this.sharedSecret = raw.sharedSecret.trim()
          }
        }
        if (typeof raw.cyberlabCallbackUrl === "string" && raw.cyberlabCallbackUrl.trim()) {
          this.cyberlabCallbackUrl = raw.cyberlabCallbackUrl.trim()
        }
        if (Array.isArray(raw.partners)) {
          for (const p of raw.partners) {
            if (p && typeof p.partnerId === "string" && p.partnerId.trim()) {
              this.partners.set(p.partnerId.trim(), {
                partnerId: p.partnerId.trim(),
                displayName: p.displayName || p.partnerId.trim(),
                specialty: p.specialty || "General Security Analyst",
                endpointUrl: p.endpointUrl || "http://127.0.0.1:8788/cyberlab/partner",
                enabled: p.enabled !== false,
                ...(p.secretOverride && p.secretOverride.length >= 16 ? { secretOverride: p.secretOverride } : {}),
                permissions: {
                  ...DEFAULT_PERMISSIONS,
                  ...(p.permissions ?? {}),
                },
              })
            }
          }
        }
        return
      } catch {
        // Ignore malformed optional config file
      }
    }

    // Seed from single-partner env vars if provided
    if (process.env.CYBERLAB_PARTNER_URL?.trim()) {
      const envId = process.env.CYBERLAB_PARTNER_ID?.trim() || "chat-py-agent"
      this.partners.set(envId, {
        partnerId: envId,
        displayName: envId,
        specialty: "External Python CDI Agent",
        endpointUrl: process.env.CYBERLAB_PARTNER_URL.trim(),
        enabled: true,
        permissions: { ...DEFAULT_PERMISSIONS },
      })
    }
  }

  private saveConfigIfPersistent(): void {
    if (!this.deps.persistToDisk) return
    const dir = path.dirname(this.configPath)
    mkdirSync(dir, { recursive: true })
    const doc: PersistedPartnersFile = {
      version: "1.0",
      sharedSecret: this.sharedSecret,
      cyberlabCallbackUrl: this.cyberlabCallbackUrl,
      partners: Array.from(this.partners.values()),
      updatedAt: new Date().toISOString(),
    }
    writeFileSync(this.configPath, JSON.stringify(doc, null, 2), "utf8")
    try {
      chmodSync(this.configPath, 0o600)
    } catch {
      // Windows NTFS ignores POSIX chmod; safe no-op
    }
  }

  private resolveSecretFor(partner: CdiPartnerEntry): string {
    return partner.secretOverride && partner.secretOverride.length >= 16
      ? partner.secretOverride
      : this.sharedSecret
  }

  private syncAllToAuthenticator(): void {
    for (const p of this.partners.values()) {
      this.deps.partnerAuth.registerPartner({
        partnerId: p.partnerId,
        displayName: p.displayName,
        sharedSecret: this.resolveSecretFor(p),
        allowedActions: ["analyze.evidence", "propose.check"],
        prohibitedActions: ["shell.exec", "exploit.execute"],
        enabled: p.enabled,
      })
      if (p.endpointUrl.trim()) {
        this.deps.partnerBridge.registerTransport(p.partnerId, new HttpPartnerTransport(p.endpointUrl.trim()))
      }
    }
  }

  private ensureReadonlyPartnerRuleInstalled(): void {
    if (this.readonlyPolicyRuleInstalled) return
    this.deps.policy.addRule({
      id: "cdi-hub.allow-partner-readonly",
      description: "Allow authenticated CDI partners with allow_readonly_propose_others to run read_only capabilities inside scope",
      capabilityPattern: "*",
      actorTypes: ["partner"],
      risks: ["read_only"],
      modes: ["approved", "lab_automation"],
      effect: "allow",
    })
    this.readonlyPolicyRuleInstalled = true
  }

  getOverview(): {
    secretConfigured: boolean
    secretPreview: string
    cyberlabCallbackUrl: string
    configFilePath: string
    partners: CdiPublicPartnerEntry[]
    inboundActivity: CdiInboundActivityEntry[]
  } {
    const s = this.sharedSecret
    const preview = s.length >= 12 ? `${s.slice(0, 6)}...${s.slice(-4)} (${s.length} chars)` : "not-set"
    return {
      secretConfigured: s.length >= 16,
      secretPreview: preview,
      cyberlabCallbackUrl: this.cyberlabCallbackUrl,
      configFilePath: this.configPath,
      partners: Array.from(this.partners.values()).map(({ secretOverride, ...rest }) => ({
        ...rest,
        usesCustomSecret: Boolean(secretOverride && secretOverride.length >= 16),
      })),
      inboundActivity: this.inboundActivity.slice(-40).reverse(),
    }
  }

  revealSharedSecret(): { sharedSecret: string; cyberlabCallbackUrl: string } {
    return {
      sharedSecret: this.sharedSecret,
      cyberlabCallbackUrl: this.cyberlabCallbackUrl,
    }
  }

  configureSecretAndGateway(params: {
    mode: "generate" | "custom"
    customSecret?: string
    cyberlabCallbackUrl?: string
  }): { sharedSecret: string; secretPreview: string; cyberlabCallbackUrl: string } {
    if (params.mode === "generate") {
      this.sharedSecret = crypto.randomBytes(32).toString("hex")
    } else {
      const trimmed = params.customSecret?.trim() ?? ""
      if (trimmed.length < 16) {
        throw new Error("CYBERLAB_PARTNER_SECRET must have at least 16 characters (32+ recommended)")
      }
      this.sharedSecret = trimmed
    }
    if (params.cyberlabCallbackUrl?.trim()) {
      this.cyberlabCallbackUrl = params.cyberlabCallbackUrl.trim()
    }
    this.syncAllToAuthenticator()
    this.saveConfigIfPersistent()
    return {
      sharedSecret: this.sharedSecret,
      secretPreview: `${this.sharedSecret.slice(0, 6)}...${this.sharedSecret.slice(-4)} (${this.sharedSecret.length} chars)`,
      cyberlabCallbackUrl: this.cyberlabCallbackUrl,
    }
  }

  upsertPartner(entry: {
    partnerId: string
    displayName: string
    specialty?: string
    endpointUrl: string
    enabled?: boolean
    secretOverride?: string
    permissions?: Partial<CdiPartnerPermissions>
  }): CdiPublicPartnerEntry {
    const id = entry.partnerId.trim()
    if (!/^[a-zA-Z0-9._-]{1,64}$/.test(id)) {
      throw new Error(`Invalid partnerId "${id}" (use letters, digits, '-', '_', '.')`)
    }
    const existing = this.partners.get(id)
    const merged: CdiPartnerEntry = {
      partnerId: id,
      displayName: entry.displayName.trim() || existing?.displayName || id,
      specialty: entry.specialty?.trim() ?? existing?.specialty ?? "CDI Specialist Agent",
      endpointUrl: entry.endpointUrl.trim() || existing?.endpointUrl || "http://127.0.0.1:8788/cyberlab/partner",
      enabled: entry.enabled ?? existing?.enabled ?? true,
      ...(entry.secretOverride && entry.secretOverride.trim().length >= 16
        ? { secretOverride: entry.secretOverride.trim() }
        : existing?.secretOverride && entry.secretOverride === undefined
          ? { secretOverride: existing.secretOverride }
          : {}),
      permissions: {
        ...(existing?.permissions ?? DEFAULT_PERMISSIONS),
        ...(entry.permissions ?? {}),
      },
    }
    this.partners.set(id, merged)
    this.syncAllToAuthenticator()
    this.saveConfigIfPersistent()
    const { secretOverride, ...pub } = merged
    return { ...pub, usesCustomSecret: Boolean(secretOverride) }
  }

  removePartner(partnerId: string): boolean {
    const existed = this.partners.delete(partnerId.trim())
    if (existed) {
      this.saveConfigIfPersistent()
    }
    return existed
  }

  loadFourCdiPreset(baseHost = "http://127.0.0.1"): CdiPublicPartnerEntry[] {
    // Remove legacy "cdi-4" placeholder when migrating to kairos/naia/salem/nova
    this.partners.delete("cdi-4")
    const ports = [8788, 8789, 8790, 8791]
    FOUR_CDI_PRESET_ENTRIES.forEach((preset, idx) => {
      const cleanHost = baseHost.replace(/\/+$/, "")
      this.upsertPartner({
        ...preset,
        endpointUrl: `${cleanHost}:${ports[idx]}/cyberlab/partner`,
      })
    })
    return this.getOverview().partners
  }

  async pingPartner(partnerId: string): Promise<{ partnerId: string; reachable: boolean; status?: number; details: string }> {
    const entry = this.partners.get(partnerId.trim())
    if (!entry) {
      throw new Error(`Partner "${partnerId}" is not registered`)
    }
    try {
      const u = new URL(entry.endpointUrl)
      const healthUrl = `${u.origin}/health`
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 2500)
      try {
        const res = await fetch(healthUrl, { signal: controller.signal })
        const txt = await res.text()
        return {
          partnerId: entry.partnerId,
          reachable: res.ok,
          status: res.status,
          details: txt.slice(0, 300),
        }
      } finally {
        clearTimeout(timer)
      }
    } catch (err) {
      return {
        partnerId: entry.partnerId,
        reachable: false,
        details: err instanceof Error ? err.message : String(err),
      }
    }
  }

  async dispatchTasks(params: {
    partnerIds: string[]
    objective: string
    evidenceIds?: string[]
    contextText?: string
    timeoutMs?: number
  }): Promise<MultiCdiDispatchReport> {
    const requestedIds =
      params.partnerIds.length === 1 && params.partnerIds[0] === "*"
        ? Array.from(this.partners.values())
            .filter((p) => p.enabled)
            .map((p) => p.partnerId)
        : params.partnerIds.map((id) => id.trim()).filter(Boolean)

    if (requestedIds.length === 0) {
      throw new Error("Select at least one enabled CDI partner to dispatch the task")
    }

    const enrichedContext = [
      `[CyberLab OS Bidirectional Gateway] callbackUrl=${this.cyberlabCallbackUrl} | projectId=${this.deps.projectId}`,
      params.contextText,
    ]
      .filter(Boolean)
      .join("\n\n")

    const runOne = async (partnerId: string): Promise<MultiCdiDispatchItem> => {
      const started = Date.now()
      const entry = this.partners.get(partnerId)
      const displayName = entry?.displayName ?? partnerId
      try {
        const outcome = await this.deps.partnerBridge.submitTask(
          partnerId,
          {
            taskId: `ptask-${crypto.randomUUID()}`,
            projectId: this.deps.projectId,
            objective: params.objective,
            contextBundle: {
              evidenceIds: params.evidenceIds ?? [],
              text: enrichedContext,
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
        return {
          partnerId,
          displayName,
          ok: true,
          durationMs: Date.now() - started,
          outcome,
        }
      } catch (err) {
        return {
          partnerId,
          displayName,
          ok: false,
          durationMs: Date.now() - started,
          error: err instanceof Error ? err.message : String(err),
        }
      }
    }

    // Execute in parallel when >1 CDI is selected!
    const results = await Promise.all(requestedIds.map((id) => runOne(id)))
    const succeededCount = results.filter((r) => r.ok).length
    return {
      mode: requestedIds.length > 1 ? "parallel" : "single",
      objective: params.objective,
      totalDispatched: requestedIds.length,
      succeededCount,
      failedCount: results.length - succeededCount,
      results,
    }
  }

  private recordInboundActivity(
    partnerId: string,
    action: string,
    outcome: CdiInboundActivityEntry["outcome"],
    summary: string,
  ): void {
    this.inboundActivity.push({
      activityId: `cdi-act-${crypto.randomUUID()}`,
      partnerId,
      action,
      outcome,
      summary,
      timestamp: new Date().toISOString(),
    })
    if (this.inboundActivity.length > 200) {
      this.inboundActivity.shift()
    }
  }

  private pruneSeenInboundIds(nowMs: number): void {
    for (const [id, seenAt] of this.seenInboundIds.entries()) {
      if (nowMs - seenAt > this.maxClockSkewMs * 2) {
        this.seenInboundIds.delete(id)
      }
    }
  }

  private buildSignedGatewayResponse(
    inReplyTo: string,
    secret: string,
    ok: boolean,
    data?: unknown,
    error?: string,
  ): CdiInboundResponseEnvelope {
    const base: Record<string, unknown> = {
      protocol: "cyberlab-cdi-gateway",
      protocolVersion: "1.0",
      messageId: `gw-resp-${crypto.randomUUID()}`,
      inReplyTo,
      sentAt: new Date().toISOString(),
      ok,
      ...(data !== undefined ? { data } : {}),
      ...(error !== undefined ? { error } : {}),
    }
    const signature = computeGatewayHmac(base, secret)
    return { ...(base as Omit<CdiInboundResponseEnvelope, "signature">), signature }
  }

  /**
   * Bidirectional CDI -> CyberLab OS Gateway handler.
   * Authenticates inbound HMAC-SHA256 requests from external CDI runtimes and executes
   * governed read/write/propose actions inside CyberLab OS's ScopeController & PolicyEngine.
   */
  async handleInboundGatewayRequest(
    rawPayload: unknown,
    options?: { now?: Date },
  ): Promise<{ httpStatus: number; body: CdiInboundResponseEnvelope | { ok: false; error: string } }> {
    const nowMs = (options?.now ?? new Date()).getTime()
    this.pruneSeenInboundIds(nowMs)

    const serialized = typeof rawPayload === "string" ? rawPayload : JSON.stringify(rawPayload)
    if (!serialized || Buffer.byteLength(serialized, "utf8") > MAX_INBOUND_BODY_BYTES) {
      return { httpStatus: 413, body: { ok: false, error: "Payload exceeds 256 KiB limit or is empty" } }
    }

    const parsed = (typeof rawPayload === "string" ? JSON.parse(rawPayload) : rawPayload) as Partial<CdiInboundRequestEnvelope>
    if (
      !parsed ||
      typeof parsed !== "object" ||
      parsed.protocol !== "cyberlab-cdi-gateway" ||
      parsed.protocolVersion !== "1.0" ||
      typeof parsed.partnerId !== "string" ||
      typeof parsed.messageId !== "string" ||
      typeof parsed.sentAt !== "string" ||
      typeof parsed.action !== "string" ||
      typeof parsed.signature !== "string"
    ) {
      return { httpStatus: 400, body: { ok: false, error: "Malformed cyberlab-cdi-gateway v1.0 envelope" } }
    }

    const partner = this.partners.get(parsed.partnerId)
    if (!partner || !partner.enabled) {
      return {
        httpStatus: 403,
        body: { ok: false, error: `CDI Partner "${parsed.partnerId}" is not registered or is disabled` },
      }
    }

    const secret = this.resolveSecretFor(partner)
    const { signature, ...withoutSig } = parsed as Record<string, unknown>
    if (!/^[a-f0-9]{64}$/.test(String(signature))) {
      this.recordInboundActivity(partner.partnerId, parsed.action, "denied", "Invalid signature format")
      return { httpStatus: 401, body: { ok: false, error: "Invalid HMAC signature format" } }
    }

    const expectedHex = computeGatewayHmac(withoutSig, secret)
    const sigBuf = Buffer.from(String(signature), "hex")
    const expBuf = Buffer.from(expectedHex, "hex")
    if (sigBuf.byteLength !== expBuf.byteLength || !timingSafeEqual(sigBuf, expBuf)) {
      this.recordInboundActivity(partner.partnerId, parsed.action, "denied", "HMAC signature mismatch")
      return { httpStatus: 401, body: { ok: false, error: "HMAC-SHA256 verification failed" } }
    }

    const sentAtMs = Date.parse(parsed.sentAt)
    if (Number.isNaN(sentAtMs) || Math.abs(nowMs - sentAtMs) > this.maxClockSkewMs) {
      this.recordInboundActivity(partner.partnerId, parsed.action, "denied", "Timestamp outside 5m window")
      return {
        httpStatus: 401,
        body: this.buildSignedGatewayResponse(parsed.messageId, secret, false, undefined, "Timestamp outside allowed 5-minute window"),
      }
    }

    const replayKey = `${partner.partnerId}::${parsed.messageId}`
    if (this.seenInboundIds.has(replayKey)) {
      this.recordInboundActivity(partner.partnerId, parsed.action, "denied", "Replay detected")
      return {
        httpStatus: 409,
        body: this.buildSignedGatewayResponse(parsed.messageId, secret, false, undefined, "Replay messageId rejected"),
      }
    }
    this.seenInboundIds.set(replayKey, nowMs)

    const params = (parsed.params && typeof parsed.params === "object" ? parsed.params : {}) as Record<string, unknown>

    try {
      // 1. Real-time Project State
      if (parsed.action === "project.state") {
        if (!partner.permissions.readProjectState) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks readProjectState permission`)
        }
        const [status, capabilities, executions, pendingApprovals, findings] = await Promise.all([
          this.deps.getStatusSnapshot(),
          this.deps.capabilities.list(),
          Promise.resolve(this.deps.dispatcher.list(this.deps.projectId)),
          Promise.resolve(this.deps.approvals.listPending(this.deps.projectId)),
          Promise.resolve(this.deps.evidenceStore.listFindings(this.deps.projectId)),
        ])
        this.recordInboundActivity(partner.partnerId, "project.state", "allowed", "Queried live project state & capabilities")
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            status,
            capabilities: capabilities.map((c) => ({
              id: c.id,
              title: c.title,
              risk: c.risk,
              description: c.description,
            })),
            recentExecutions: executions.slice(-15),
            pendingApprovals,
            findingsCount: findings.length,
            findings: findings.slice(-20),
          }),
        }
      }

      // 2. Direct Evidence Access (List & Redacted Read)
      if (parsed.action === "evidence.list") {
        if (!partner.permissions.readEvidenceAndFiles) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks readEvidenceAndFiles permission`)
        }
        const list = this.deps.evidenceStore.listEvidence(this.deps.projectId).map((e) => ({
          evidenceId: e.evidenceId,
          kind: e.kind,
          title: e.title,
          sha256: e.integrity.sha256,
          byteLength: e.content.byteLength ?? 0,
          redactionStatus: e.redactionStatus,
          observedAt: e.observedAt,
        }))
        this.recordInboundActivity(partner.partnerId, "evidence.list", "allowed", `Listed ${list.length} evidence record(s)`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { evidence: list }),
        }
      }

      if (parsed.action === "evidence.read") {
        if (!partner.permissions.readEvidenceAndFiles) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks readEvidenceAndFiles permission`)
        }
        const evidenceId = String(params.evidenceId ?? "").trim()
        const rec = this.deps.evidenceStore.getEvidence(evidenceId)
        if (!rec || rec.projectId !== this.deps.projectId) {
          throw new Error(`Evidence "${evidenceId}" not found in project "${this.deps.projectId}"`)
        }
        const shared = this.deps.evidenceStore.readRedactedForSharing(evidenceId, `partner:${partner.partnerId}`)
        this.recordInboundActivity(partner.partnerId, "evidence.read", "allowed", `Read redacted evidence ${evidenceId}`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            evidenceId: rec.evidenceId,
            kind: rec.kind,
            title: rec.title,
            mediaType: rec.content.mediaType,
            sha256: shared.sha256,
            redacted: shared.redacted,
            text: shared.text,
          }),
        }
      }

      // 3. Direct Scoped Workspace File Listing & Redacted Reading
      if (parsed.action === "workspace.list_files") {
        if (!partner.permissions.readEvidenceAndFiles) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks readEvidenceAndFiles permission`)
        }
        const subpath = String(params.subpath ?? ".").trim() || "."
        const scopeCheck = this.deps.scopes.verifyTargets(
          this.deps.projectId,
          { networkTargets: [], workspacePaths: [subpath] },
          ["workspace"],
        )
        if (!scopeCheck.allowed) {
          throw new Error(scopeCheck.reason)
        }
        const absDir = path.resolve(this.deps.workspaceRoot, subpath)
        const relCheck = path.relative(this.deps.workspaceRoot, absDir)
        if (relCheck.split(path.sep).some((seg) => BLOCKED_WORKSPACE_SEGMENTS.has(seg))) {
          throw new Error(`Access to protected directory "${subpath}" is prohibited`)
        }
        const entries = readdirSync(absDir, { withFileTypes: true })
          .filter((d) => !BLOCKED_WORKSPACE_SEGMENTS.has(d.name) && !d.isSymbolicLink())
          .slice(0, 200)
          .map((d) => ({
            name: d.name,
            path: path.posix.join(subpath === "." ? "" : subpath.replace(/\\/g, "/"), d.name),
            type: d.isDirectory() ? "directory" : "file",
          }))
        this.recordInboundActivity(partner.partnerId, "workspace.list_files", "allowed", `Listed files in "${subpath}"`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { subpath, entries }),
        }
      }

      if (parsed.action === "workspace.read_file") {
        if (!partner.permissions.readEvidenceAndFiles) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks readEvidenceAndFiles permission`)
        }
        const filePath = String(params.path ?? "").trim()
        if (!filePath) throw new Error("params.path is required")
        const scopeCheck = this.deps.scopes.verifyTargets(
          this.deps.projectId,
          { networkTargets: [], workspacePaths: [filePath] },
          ["workspace"],
        )
        if (!scopeCheck.allowed) {
          throw new Error(scopeCheck.reason)
        }
        const absFile = path.resolve(this.deps.workspaceRoot, filePath)
        const rel = path.relative(this.deps.workspaceRoot, absFile)
        if (rel.split(path.sep).some((seg) => BLOCKED_WORKSPACE_SEGMENTS.has(seg)) || isSensitiveDotfile(rel)) {
          throw new Error(`Access to protected or secret file "${filePath}" is prohibited`)
        }
        const lst = lstatSync(absFile)
        if (lst.isSymbolicLink() || !statSync(absFile).isFile()) {
          throw new Error(`"${filePath}" is not a regular in-scope file`)
        }
        const rawBuf = readFileSync(absFile)
        const sliced = rawBuf.subarray(0, MAX_WORKSPACE_READ_BYTES)
        const red = redactSensitiveContent(sliced.toString("utf8"))
        this.recordInboundActivity(partner.partnerId, "workspace.read_file", "allowed", `Read file "${rel}" (redacted=${red.redacted})`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            path: rel.replace(/\\/g, "/"),
            byteLength: rawBuf.byteLength,
            truncated: rawBuf.byteLength > MAX_WORKSPACE_READ_BYTES,
            redacted: red.redacted,
            content: red.text,
          }),
        }
      }

      // 4. Create Artifacts & Findings Directly in CyberLab OS
      if (parsed.action === "artifact.create") {
        if (!partner.permissions.createArtifactsAndFindings) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks createArtifactsAndFindings permission`)
        }
        const title = String(params.title ?? "").trim()
        const rawContent = typeof params.content === "string" ? params.content : JSON.stringify(params.content ?? {}, null, 2)
        const requestedKind = String(params.kind ?? "json").trim().toLowerCase()
        const kindAliases: Record<string, EvidenceKind> = {
          log: "stdout",
          note: "file",
          json: "json",
          stdout: "stdout",
          stderr: "stderr",
          file: "file",
          http_exchange: "http_exchange",
          network_observation: "network_observation",
        }
        const kind: EvidenceKind = kindAliases[requestedKind] ?? "file"
        const mediaType = String(params.mediaType ?? (kind === "json" ? "application/json" : "text/plain")).trim()
        if (!title || !rawContent) {
          throw new Error("artifact.create requires non-empty title and content")
        }

        const stored = this.deps.evidenceStore.storeEvidence(
          this.deps.projectId,
          {
            kind,
            title: `[CDI:${partner.displayName}] ${title}`.slice(0, 240),
            source: {
              toolId: `cdi:${partner.partnerId}`,
              executorId: "cdi-bidirectional-gateway",
              executionId: `cdi-art-${crypto.randomUUID()}`,
            },
            content: {
              mediaType,
              inlineText: rawContent,
            },
            observedAt: new Date().toISOString(),
          },
          {
            actor: `partner:${partner.partnerId}`,
            applyRedactionBeforeStore: true,
          },
        )
        this.recordInboundActivity(
          partner.partnerId,
          "artifact.create",
          "allowed",
          `Created artifact ${stored.evidenceId} (${stored.title})`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            evidenceId: stored.evidenceId,
            sha256: stored.integrity.sha256,
            redactionStatus: stored.redactionStatus,
          }),
        }
      }

      if (parsed.action === "finding.propose") {
        if (!partner.permissions.createArtifactsAndFindings) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks createArtifactsAndFindings permission`)
        }
        const title = String(params.title ?? "").trim()
        const description = String(params.description ?? "").trim()
        const sevRaw = String(params.severity ?? "medium").toLowerCase()
        const normalizedSev = sevRaw === "informational" ? "info" : sevRaw
        const validSev: readonly FindingSeverity[] = ["info", "low", "medium", "high", "critical"]
        const severity: FindingSeverity = (validSev as readonly string[]).includes(normalizedSev)
          ? (normalizedSev as FindingSeverity)
          : "medium"
        const confidence = typeof params.confidence === "number" ? Math.max(0, Math.min(1, params.confidence)) : 0.75
        const rawEvIds = Array.isArray(params.evidenceIds) ? params.evidenceIds.map(String) : []
        const verifiedEvIds = rawEvIds.filter((id) => {
          const ev = this.deps.evidenceStore.getEvidence(id)
          return Boolean(ev && ev.projectId === this.deps.projectId)
        })
        const affectedAssets = Array.isArray(params.affectedAssets)
          ? params.affectedAssets.map(String).filter(Boolean)
          : ["(reported-by-cdi)"]

        const finding = this.deps.evidenceStore.createFinding({
          projectId: this.deps.projectId,
          title: `[${partner.displayName}] ${title}`.slice(0, 260),
          description,
          severity,
          confidence,
          evidenceIds: verifiedEvIds,
          affectedAssets: affectedAssets.length > 0 ? affectedAssets : ["(reported-by-cdi)"],
          ...(typeof params.proposedRemediation === "string" ? { proposedRemediation: params.proposedRemediation } : {}),
          createdBy: `partner:${partner.partnerId}`,
        })
        this.recordInboundActivity(
          partner.partnerId,
          "finding.propose",
          "allowed",
          `Proposed finding ${finding.findingId} (${finding.severity}): ${title}`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { finding }),
        }
      }

      // 5. Initiate CyberLab OS Actions & Poll Execution Status
      if (parsed.action === "action.initiate") {
        if (partner.permissions.initiateActions === "disabled") {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" is not permitted to initiate actions`)
        }
        const capabilityId = String(params.capabilityId ?? "").trim()
        const cap = await this.deps.capabilities.get(capabilityId)
        if (!cap) {
          throw new Error(`Capability "${capabilityId}" is not registered in CyberLab OS`)
        }

        let execMode: "proposed" | "approved" = "proposed"
        if (
          partner.permissions.initiateActions === "allow_readonly_propose_others" &&
          cap.risk === "read_only" &&
          cap.supportedModes.includes("approved")
        ) {
          this.ensureReadonlyPartnerRuleInstalled()
          execMode = "approved"
        }

        const record = await this.deps.dispatcher.submit({
          requestId: `cdi-req-${crypto.randomUUID()}`,
          projectId: this.deps.projectId,
          capabilityId,
          requestedBy: { type: "partner", id: partner.partnerId },
          input: params.input ?? {},
          mode: execMode,
        })

        const actOutcome =
          record.status === "succeeded"
            ? "allowed"
            : record.status === "awaiting_approval"
              ? "queued_for_approval"
              : "denied"
        this.recordInboundActivity(
          partner.partnerId,
          "action.initiate",
          actOutcome,
          `${capabilityId} -> ${record.status}`,
        )

        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            executionId: record.executionId,
            status: record.status,
            resultEvidenceIds: record.resultEvidenceIds,
            ...(record.error ? { error: record.error } : {}),
          }),
        }
      }

      if (parsed.action === "execution.status") {
        const executionId = String(params.executionId ?? "").trim()
        const rec = await this.deps.dispatcher.get(executionId)
        if (!rec || rec.request.projectId !== this.deps.projectId) {
          throw new Error(`Execution "${executionId}" not found in project "${this.deps.projectId}"`)
        }
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            executionId: rec.executionId,
            capabilityId: rec.request.capabilityId,
            status: rec.status,
            resultEvidenceIds: rec.resultEvidenceIds,
            ...(rec.error ? { error: rec.error } : {}),
          }),
        }
      }

      throw new Error(`Unsupported CDI gateway action "${String(parsed.action)}"`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      this.recordInboundActivity(partner.partnerId, parsed.action, "denied", msg)
      return {
        httpStatus: err instanceof PartnerAuthError ? 403 : 400,
        body: this.buildSignedGatewayResponse(parsed.messageId, secret, false, undefined, msg),
      }
    }
  }
}
