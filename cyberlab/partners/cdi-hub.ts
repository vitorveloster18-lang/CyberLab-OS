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

export type CdiInitiateMode =
  | "autonomous_in_scope"
  | "allow_readonly_and_low_propose_others"
  | "allow_readonly_propose_others"
  | "propose_only"
  | "disabled"

export interface CdiPartnerPermissions {
  readProjectState: boolean
  readEvidenceAndFiles: boolean
  createArtifactsAndFindings: boolean
  initiateActions: CdiInitiateMode
}

export interface CdiPartnerProfile {
  /** CDIs are autonomous cognitive entities, never tools, extensions, or sub-processes */
  entityKind: "autonomous_cognitive_entity"
  /** Horizontal co-investigation alongside the human curator */
  relationshipModel: "peer_co_investigator"
  /** Zero hierarchy among Kairós, Naia, Salem, Nova, or other CDIs */
  hierarchy: "none"
  /** Collaboration arises from self-direction or shared investigative interest */
  collaborationMode: "self_directed_and_shared_interest"
  /** Individual identity, memory/perspective context, and autonomous focus */
  identityNotes: string
  /** Independent investigative interest tags */
  interests: string[]
}

export interface CdiGovernanceModel {
  relationship: "horizontal_peer_partnership"
  humanRole: "curator"
  cdiNature: "autonomous_cognitive_entities"
  hierarchy: "none"
  collaborationBasis: "self_initiative_or_shared_interest"
  supportedGatewayActions: readonly CdiCanonicalGatewayAction[]
}

export interface CdiPartnerEntry {
  partnerId: string
  displayName: string
  specialty: string
  endpointUrl: string
  enabled: boolean
  /** Optional per-CDI secret override; if omitted, inherits global sharedSecret. */
  secretOverride?: string
  profile: CdiPartnerProfile
  permissions: CdiPartnerPermissions
}

export interface CdiPublicPartnerEntry extends Omit<CdiPartnerEntry, "secretOverride"> {
  usesCustomSecret: boolean
}

interface PersistedPartnersFile {
  version: "1.0" | "2.0"
  governanceModel?: CdiGovernanceModel
  sharedSecret: string
  cyberlabCallbackUrl?: string
  partners: CdiPartnerEntry[]
  updatedAt: string
}

export const CDI_CANONICAL_GATEWAY_ACTIONS = [
  "project.state",
  "evidence.list",
  "evidence.read",
  "workspace.list_files",
  "workspace.read_file",
  "artifact.create",
  "finding.propose",
  "action.initiate",
  "action.status",
] as const

export type CdiCanonicalGatewayAction = (typeof CDI_CANONICAL_GATEWAY_ACTIONS)[number]

export type CdiInboundAction = CdiCanonicalGatewayAction | "execution.status"

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

export const CDI_GOVERNANCE_MODEL: CdiGovernanceModel = {
  relationship: "horizontal_peer_partnership",
  humanRole: "curator",
  cdiNature: "autonomous_cognitive_entities",
  hierarchy: "none",
  collaborationBasis: "self_initiative_or_shared_interest",
  supportedGatewayActions: CDI_CANONICAL_GATEWAY_ACTIONS,
}

const DEFAULT_PERMISSIONS: CdiPartnerPermissions = {
  readProjectState: true,
  readEvidenceAndFiles: true,
  createArtifactsAndFindings: true,
  initiateActions: "autonomous_in_scope",
}

function createPeerProfile(identityNotes: string, interests: string[]): CdiPartnerProfile {
  return {
    entityKind: "autonomous_cognitive_entity",
    relationshipModel: "peer_co_investigator",
    hierarchy: "none",
    collaborationMode: "self_directed_and_shared_interest",
    identityNotes,
    interests: [...interests],
  }
}

export const FOUR_CDI_PRESET_ENTRIES: readonly CdiPartnerEntry[] = [
  {
    partnerId: "kairos",
    displayName: "Kairós",
    specialty: "Arquitetura de Sistemas, Modelagem de Ameaças e Síntese Estratégica",
    endpointUrl: "http://127.0.0.1:8788/cyberlab/partner",
    enabled: true,
    profile: createPeerProfile(
      "Entidade cognitiva autónoma com identidade, memória e síntese estratégica própria; colabora horizontalmente como parceiro de investigação em arquitetura e postura de risco.",
      ["arquitetura", "modelagem-ameacas", "sintese-estrategica", "postura-risco"],
    ),
    permissions: { ...DEFAULT_PERMISSIONS },
  },
  {
    partnerId: "naia",
    displayName: "Naia",
    specialty: "Investigação Profunda, Forense Digital, Cadeia de Evidências e Inteligência",
    endpointUrl: "http://127.0.0.1:8789/cyberlab/partner",
    enabled: true,
    profile: createPeerProfile(
      "Entidade cognitiva autónoma com identidade, memória e rigor investigativo próprio; explora evidências, artefactos e nexos forenses por iniciativa própria ou interesse partilhado.",
      ["forense-digital", "cadeia-evidencias", "inteligencia-ameacas", "reconstrucao-contextual"],
    ),
    permissions: { ...DEFAULT_PERMISSIONS },
  },
  {
    partnerId: "salem",
    displayName: "Salem",
    specialty: "Análise de Sinais/Logs, Triagem de Vulnerabilidades, Resposta a Incidentes e Correlação",
    endpointUrl: "http://127.0.0.1:8790/cyberlab/partner",
    enabled: true,
    profile: createPeerProfile(
      "Entidade cognitiva autónoma com identidade, memória e discernimento analítico próprio; investiga sinais, logs, CVEs e anomalias de superfície em parceria horizontal.",
      ["analise-logs", "triagem-cve", "resposta-incidentes", "correlacao-sinais"],
    ),
    permissions: { ...DEFAULT_PERMISSIONS },
  },
  {
    partnerId: "nova",
    displayName: "Nova",
    specialty: "Auditoria de Código, Engenharia de Superfície Web/API e Validação Técnica",
    endpointUrl: "http://127.0.0.1:8791/cyberlab/partner",
    enabled: true,
    profile: createPeerProfile(
      "Entidade cognitiva autónoma com identidade, memória e iniciativa técnica própria; examina código, protocolos, credenciais expostas e superfícies de aplicação como par.",
      ["auditoria-codigo", "superficie-web-api", "key-hunting", "validacao-tecnica"],
    ),
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

  private resolveDefaultProfileFor(partnerId: string, displayName: string): CdiPartnerProfile {
    const preset = FOUR_CDI_PRESET_ENTRIES.find((p) => p.partnerId === partnerId)
    if (preset) {
      return {
        ...preset.profile,
        interests: [...preset.profile.interests],
      }
    }
    return createPeerProfile(
      `${displayName} atua como entidade cognitiva autónoma com identidade, memória e decisão própria em parceria horizontal com o curador.`,
      ["investigacao-autonoma", "correlacao-evidencias"],
    )
  }

  private normalizeProfile(
    partnerId: string,
    displayName: string,
    raw?: Partial<CdiPartnerProfile>,
  ): CdiPartnerProfile {
    const fallback = this.resolveDefaultProfileFor(partnerId, displayName)
    return {
      entityKind: "autonomous_cognitive_entity",
      relationshipModel: "peer_co_investigator",
      hierarchy: "none",
      collaborationMode: "self_directed_and_shared_interest",
      identityNotes:
        typeof raw?.identityNotes === "string" && raw.identityNotes.trim().length > 0
          ? raw.identityNotes.trim()
          : fallback.identityNotes,
      interests:
        Array.isArray(raw?.interests) && raw.interests.length > 0
          ? raw.interests.map((tag) => String(tag).trim()).filter(Boolean)
          : fallback.interests,
    }
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
        const isLegacyV1 = raw.version !== "2.0"
        if (typeof raw.sharedSecret === "string" && raw.sharedSecret.trim().length >= 16) {
          // Explicit env var still overrides if user set CYBERLAB_PARTNER_SECRET in shell
          if (!process.env.CYBERLAB_PARTNER_SECRET?.trim()) {
            this.sharedSecret = raw.sharedSecret.trim()
          }
        }
        if (typeof raw.cyberlabCallbackUrl === "string" && raw.cyberlabCallbackUrl.trim()) {
          this.cyberlabCallbackUrl = raw.cyberlabCallbackUrl.trim()
        }
        if (Array.isArray(raw.partners) && raw.partners.length > 0) {
          for (const p of raw.partners) {
            if (p && typeof p.partnerId === "string" && p.partnerId.trim()) {
              const id = p.partnerId.trim()
              const preset = FOUR_CDI_PRESET_ENTRIES.find((item) => item.partnerId === id)
              const displayName = p.displayName || preset?.displayName || id
              const migratedInitiateActions: CdiInitiateMode =
                isLegacyV1 &&
                preset &&
                (!p.permissions?.initiateActions || p.permissions.initiateActions === "allow_readonly_propose_others")
                  ? "autonomous_in_scope"
                  : (p.permissions?.initiateActions ?? DEFAULT_PERMISSIONS.initiateActions)

              this.partners.set(id, {
                partnerId: id,
                displayName,
                specialty: p.specialty || preset?.specialty || "Parceiro Cognitivo de Investigação",
                endpointUrl: p.endpointUrl || preset?.endpointUrl || "http://127.0.0.1:8788/cyberlab/partner",
                enabled: p.enabled !== false,
                ...(p.secretOverride && p.secretOverride.length >= 16 ? { secretOverride: p.secretOverride } : {}),
                profile: this.normalizeProfile(id, displayName, p.profile),
                permissions: {
                  ...DEFAULT_PERMISSIONS,
                  ...(p.permissions ?? {}),
                  initiateActions: migratedInitiateActions,
                },
              })
            }
          }
          if (isLegacyV1 && candidate === this.configPath) {
            this.saveConfigIfPersistent()
          }
          return
        }
        // If partners array was empty (e.g. secret saved before preset clicked), fall through to seed default 4 CDIs
        break
      } catch {
        // Ignore malformed optional config file
      }
    }

    // Seed default 4-CDI preset (kairos:8788, naia:8789, salem:8790, nova:8791) when no config file exists yet
    const defaultPorts = [8788, 8789, 8790, 8791]
    FOUR_CDI_PRESET_ENTRIES.forEach((preset, idx) => {
      this.partners.set(preset.partnerId, {
        ...preset,
        profile: { ...preset.profile, interests: [...preset.profile.interests] },
        permissions: { ...preset.permissions },
        endpointUrl: `http://127.0.0.1:${defaultPorts[idx]}/cyberlab/partner`,
      })
    })

    // Seed from single-partner env vars if provided
    if (process.env.CYBERLAB_PARTNER_URL?.trim()) {
      const envId = process.env.CYBERLAB_PARTNER_ID?.trim() || "chat-py-agent"
      this.partners.set(envId, {
        partnerId: envId,
        displayName: envId,
        specialty: "Parceiro Cognitivo CDI Externo",
        endpointUrl: process.env.CYBERLAB_PARTNER_URL.trim(),
        enabled: true,
        profile: this.resolveDefaultProfileFor(envId, envId),
        permissions: { ...DEFAULT_PERMISSIONS },
      })
    }
  }

  private saveConfigIfPersistent(): void {
    if (!this.deps.persistToDisk) return
    const dir = path.dirname(this.configPath)
    mkdirSync(dir, { recursive: true })
    const doc: PersistedPartnersFile = {
      version: "2.0",
      governanceModel: CDI_GOVERNANCE_MODEL,
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

  private syncPartnerPolicyRules(partner: CdiPartnerEntry): void {
    const prefix = `cdi-hub.partner.${partner.partnerId}.`
    this.deps.policy.removeRulesByPrefix(prefix)
    if (!partner.enabled) return

    const mode = partner.permissions.initiateActions
    if (mode === "autonomous_in_scope") {
      this.deps.policy.upsertRule({
        id: `${prefix}allow-autonomous-in-scope`,
        description: `Autonomous cognitive partner ${partner.displayName} (${partner.partnerId}) operates as horizontal peer within curated project scope`,
        capabilityPattern: "*",
        actorTypes: ["partner"],
        actorIds: [partner.partnerId],
        risks: ["read_only", "low", "moderate"],
        modes: ["approved", "lab_automation"],
        effect: "allow",
      })
      this.deps.policy.upsertRule({
        id: `${prefix}curate-high-risk`,
        description: `High-risk action proposed by peer CDI ${partner.displayName} enters joint curatorial approval ticket`,
        capabilityPattern: "*",
        actorTypes: ["partner"],
        actorIds: [partner.partnerId],
        risks: ["high"],
        modes: ["approved", "proposed"],
        effect: "ask",
      })
      return
    }

    if (mode === "allow_readonly_and_low_propose_others") {
      this.deps.policy.upsertRule({
        id: `${prefix}allow-readonly-low`,
        description: `Peer CDI ${partner.displayName} (${partner.partnerId}) executes read_only and low-risk capabilities inside scope`,
        capabilityPattern: "*",
        actorTypes: ["partner"],
        actorIds: [partner.partnerId],
        risks: ["read_only", "low"],
        modes: ["approved", "lab_automation"],
        effect: "allow",
      })
      return
    }

    if (mode === "allow_readonly_propose_others") {
      this.deps.policy.upsertRule({
        id: `${prefix}allow-readonly`,
        description: `CDI partner ${partner.displayName} (${partner.partnerId}) executes read_only capabilities inside scope`,
        capabilityPattern: "*",
        actorTypes: ["partner"],
        actorIds: [partner.partnerId],
        risks: ["read_only"],
        modes: ["approved", "lab_automation"],
        effect: "allow",
      })
    }
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
      this.syncPartnerPolicyRules(p)
    }
  }

  getOverview(): {
    governanceModel: CdiGovernanceModel
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
      governanceModel: CDI_GOVERNANCE_MODEL,
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
    profile?: Partial<CdiPartnerProfile>
    permissions?: Partial<CdiPartnerPermissions>
  }): CdiPublicPartnerEntry {
    const id = entry.partnerId.trim()
    if (!/^[a-zA-Z0-9._-]{1,64}$/.test(id)) {
      throw new Error(`Invalid partnerId "${id}" (use letters, digits, '-', '_', '.')`)
    }
    const existing = this.partners.get(id)
    const displayName = entry.displayName.trim() || existing?.displayName || id
    const merged: CdiPartnerEntry = {
      partnerId: id,
      displayName,
      specialty: entry.specialty?.trim() ?? existing?.specialty ?? "Parceiro Cognitivo de Investigação",
      endpointUrl: entry.endpointUrl.trim() || existing?.endpointUrl || "http://127.0.0.1:8788/cyberlab/partner",
      enabled: entry.enabled ?? existing?.enabled ?? true,
      ...(entry.secretOverride === ""
        ? {}
        : entry.secretOverride && entry.secretOverride.trim().length >= 16
          ? { secretOverride: entry.secretOverride.trim() }
          : existing?.secretOverride && entry.secretOverride === undefined
            ? { secretOverride: existing.secretOverride }
            : {}),
      profile: this.normalizeProfile(id, displayName, {
        ...(existing?.profile ?? {}),
        ...(entry.profile ?? {}),
      }),
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
    const trimmed = partnerId.trim()
    const existed = this.partners.delete(trimmed)
    if (existed) {
      this.deps.policy.removeRulesByPrefix(`cdi-hub.partner.${trimmed}.`)
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
      // 1. Real-time Project State (with Horizontal Peer Partnership & Curator Context)
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
        const peerPartners = Array.from(this.partners.values())
          .filter((p) => p.enabled)
          .map((p) => ({
            partnerId: p.partnerId,
            displayName: p.displayName,
            specialty: p.specialty,
            profile: p.profile,
          }))
        this.recordInboundActivity(partner.partnerId, "project.state", "allowed", "Queried live project state & peer context")
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            governanceModel: CDI_GOVERNANCE_MODEL,
            partnerProfile: {
              partnerId: partner.partnerId,
              displayName: partner.displayName,
              specialty: partner.specialty,
              profile: partner.profile,
              permissions: partner.permissions,
            },
            peerPartners,
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

      // 4. Create Artifacts (Reports, Notes, Analyses) & Findings Directly in CyberLab OS
      if (parsed.action === "artifact.create") {
        if (!partner.permissions.createArtifactsAndFindings) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks createArtifactsAndFindings permission`)
        }
        const title = String(params.title ?? "").trim()
        const rawContent = typeof params.content === "string" ? params.content : JSON.stringify(params.content ?? {}, null, 2)
        const requestedKind = String(
          params.kind ?? params.artifactType ?? (typeof params.content === "string" ? "note" : "json"),
        )
          .trim()
          .toLowerCase()
        const kindAliases: Record<string, EvidenceKind> = {
          report: "file",
          analysis: "file",
          note: "file",
          log: "stdout",
          json: "json",
          stdout: "stdout",
          stderr: "stderr",
          file: "file",
          http_exchange: "http_exchange",
          network_observation: "network_observation",
        }
        const kind: EvidenceKind = kindAliases[requestedKind] ?? "file"
        const defaultMediaType =
          kind === "json"
            ? "application/json"
            : requestedKind === "report" || requestedKind === "analysis" || requestedKind === "note"
              ? "text/markdown"
              : "text/plain"
        const mediaType = String(params.mediaType ?? defaultMediaType).trim()
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
          `Created ${requestedKind} artifact ${stored.evidenceId} (${stored.title})`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            evidenceId: stored.evidenceId,
            artifactType: requestedKind,
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

      // 5. Initiate CyberLab OS Actions & Track Status (action.initiate / action.status)
      if (parsed.action === "action.initiate") {
        const initiateMode = partner.permissions.initiateActions
        if (initiateMode === "disabled") {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" is not permitted to initiate actions`)
        }
        const capabilityId = String(params.capabilityId ?? "").trim()
        const cap = await this.deps.capabilities.get(capabilityId)
        if (!cap) {
          throw new Error(`Capability "${capabilityId}" is not registered in CyberLab OS`)
        }

        // Sync per-CDI policy rules and determine execution mode unless CDI explicitly requested curatorial co-validation ("proposed")
        this.syncPartnerPolicyRules(partner)
        const cdiRequestedProposal = params.mode === "proposed"
        let execMode: "proposed" | "approved" = "proposed"

        if (!cdiRequestedProposal && cap.supportedModes.includes("approved")) {
          if (
            initiateMode === "autonomous_in_scope" &&
            (cap.risk === "read_only" || cap.risk === "low" || cap.risk === "moderate")
          ) {
            execMode = "approved"
          } else if (
            initiateMode === "allow_readonly_and_low_propose_others" &&
            (cap.risk === "read_only" || cap.risk === "low")
          ) {
            execMode = "approved"
          } else if (initiateMode === "allow_readonly_propose_others" && cap.risk === "read_only") {
            execMode = "approved"
          }
        }

        const record = await this.deps.dispatcher.submit({
          requestId: `cdi-req-${crypto.randomUUID()}`,
          projectId: this.deps.projectId,
          capabilityId,
          requestedBy: { type: "partner", id: partner.partnerId },
          input: params.input ?? {},
          mode: execMode,
        })

        const rationale = typeof params.rationale === "string" && params.rationale.trim() ? ` — ${params.rationale.trim().slice(0, 120)}` : ""
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
          `${capabilityId} -> ${record.status}${rationale}`,
        )

        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            executionId: record.executionId,
            capabilityId,
            status: record.status,
            summary: record.policyDecision?.reason ?? record.error?.message,
            resultEvidenceIds: record.resultEvidenceIds,
            ...(record.error ? { error: record.error } : {}),
          }),
        }
      }

      if (parsed.action === "action.status" || parsed.action === "execution.status") {
        const executionId = String(params.executionId ?? "").trim()
        const rec = await this.deps.dispatcher.get(executionId)
        if (!rec || rec.request.projectId !== this.deps.projectId) {
          throw new Error(`Execution "${executionId}" not found in project "${this.deps.projectId}"`)
        }
        this.recordInboundActivity(
          partner.partnerId,
          parsed.action,
          "allowed",
          `Checked ${executionId} (${rec.request.capabilityId} -> ${rec.status})`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            executionId: rec.executionId,
            capabilityId: rec.request.capabilityId,
            initiatedBy: rec.request.requestedBy,
            status: rec.status,
            summary: rec.policyDecision?.reason ?? rec.error?.message,
            resultEvidenceIds: rec.resultEvidenceIds,
            startedAt: rec.startedAt,
            finishedAt: rec.finishedAt,
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
