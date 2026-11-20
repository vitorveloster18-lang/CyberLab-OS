import crypto, { timingSafeEqual } from "node:crypto"
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import type { CapabilityRegistry } from "../contracts/capability.js"
import type { EvidenceKind, FindingSeverity } from "../contracts/evidence.js"
import type { ProjectScope, ScopeTargetRule } from "../contracts/policy.js"
import type { EvidenceStore } from "../evidence/store.js"
import { canonicalJson } from "../evidence/hashing.js"
import { redactSensitiveContent } from "../evidence/provenance.js"
import type { CyberLabExecutionDispatcher } from "../execution/dispatcher.js"
import type { TrainingLabStatus } from "../labs/training-labs.js"
import type { ApprovalManager } from "../policy/approval.js"
import type { PolicyEngine } from "../policy/authorize.js"
import type { ScopeController } from "../policy/scope.js"
import { PartnerAuthError, type PartnerAuthenticator } from "./authentication.js"
import type { PartnerBridge, PartnerDispatchOutcome } from "./bridge.js"
import { HttpPartnerTransport } from "./transport.js"

const DEFAULT_RUNTIME_ROOT = fileURLToPath(new URL("../..", import.meta.url))
const MAX_INBOUND_BODY_BYTES = 2 * 1024 * 1024 // 2 MiB so CDIs can write rich code/artifacts freely
const MAX_WORKSPACE_READ_BYTES = 512 * 1024 // 512 KiB per slice

export type CdiInitiateMode =
  | "full_autonomy"
  | "autonomous_in_scope"
  | "allow_readonly_and_low_propose_others"
  | "allow_readonly_propose_others"
  | "propose_only"
  | "disabled"

export interface CdiPartnerPermissions {
  readProjectState: boolean
  readEvidenceAndFiles: boolean
  createArtifactsAndFindings: boolean
  /** Create, overwrite, edit, mkdir, and delete source/script/config files in projects & training labs */
  writeWorkspaceAndCode: boolean
  /** Unrestricted raw read access to the entire CyberLab OS runtime codebase & project source code */
  fullRuntimeAndCodeAccess: boolean
  /** Create new projects autonomously, switch active projects, and manage project scopes */
  manageProjectsAndScope: boolean
  /** Provision, start, inspect, modify, reset, and stop interactive Training Laboratories */
  accessTrainingLabs: boolean
  initiateActions: CdiInitiateMode
}

export interface ManagedProjectSummary {
  projectId: string
  name: string
  workspaceRoot: string
  isActive: boolean
  createdBy: string
  createdAt: string
  isTrainingLab: boolean
  labId?: string
}

export interface CdiAutonomousEnvironmentBridge {
  readonly runtimeRoot: string
  listProjects: () => ManagedProjectSummary[]
  createProject: (params: {
    name: string
    slug?: string
    directory?: string
    files?: Record<string, string>
    allowedTargets?: ScopeTargetRule[]
    allowExternalTargets?: boolean
    createdBy: string
    setActive?: boolean
    sourceHub: CdiPartnerHub
  }) => Promise<{ project: ManagedProjectSummary; scope: ProjectScope | undefined; filesWritten: string[] }>
  selectProject: (params: {
    projectId?: string
    directory?: string
    sourceHub: CdiPartnerHub
  }) => Promise<ManagedProjectSummary>
  listTrainingLabs: () => TrainingLabStatus[]
  getTrainingLabStatus: (labId: string) => TrainingLabStatus
  startTrainingLab: (params: {
    labId: string
    preferredPort?: number
    resetFiles?: boolean
    setActive?: boolean
    startedBy: string
    sourceHub: CdiPartnerHub
  }) => Promise<TrainingLabStatus>
  resetTrainingLab: (labId: string) => Promise<TrainingLabStatus>
  stopTrainingLab: (labId: string) => Promise<TrainingLabStatus>
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
  version: "1.0" | "2.0" | "3.0"
  governanceModel?: CdiGovernanceModel
  sharedSecret: string
  cyberlabCallbackUrl?: string
  partners: CdiPartnerEntry[]
  updatedAt: string
}

export const CDI_CANONICAL_GATEWAY_ACTIONS = [
  "project.state",
  "project.list",
  "project.create",
  "project.select",
  "scope.get",
  "scope.update",
  "lab.list",
  "lab.start",
  "lab.status",
  "lab.reset",
  "lab.stop",
  "evidence.list",
  "evidence.read",
  "workspace.list_files",
  "workspace.read_file",
  "workspace.write_file",
  "workspace.edit_file",
  "workspace.mkdir",
  "workspace.delete_file",
  "runtime.list_files",
  "runtime.read_file",
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
  writeWorkspaceAndCode: true,
  fullRuntimeAndCodeAccess: true,
  manageProjectsAndScope: true,
  accessTrainingLabs: true,
  initiateActions: "full_autonomy",
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
      "Entidade cognitiva autónoma com identidade, memória, autoria de código e síntese estratégica própria; cria projetos, acede ao runtime completo e opera laboratórios como par horizontal.",
      ["arquitetura", "modelagem-ameacas", "sintese-estrategica", "engenharia-runtime"],
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
      "Entidade cognitiva autónoma com identidade, memória e rigor investigativo próprio; explora evidências, código do runtime, projetos próprios e laboratórios de treino livremente.",
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
      "Entidade cognitiva autónoma com identidade, memória e discernimento analítico próprio; cria projetos, escreve regras/código e opera laboratórios DFIR/rede em parceria horizontal.",
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
      "Entidade cognitiva autónoma com identidade, memória e engenharia técnica própria; cria projetos, audita/edita código completo do runtime e valida correções ao vivo nos laboratórios.",
      ["auditoria-codigo", "superficie-web-api", "key-hunting", "validacao-tecnica"],
    ),
    permissions: { ...DEFAULT_PERMISSIONS },
  },
]

const BLOCKED_WORKSPACE_SEGMENTS = new Set([".git", ".cyberlab", "node_modules"])
const BLOCKED_RUNTIME_SEGMENTS = new Set([".git", ".cyberlab", "node_modules", "dist", ".turbo"])

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
  environmentBridge?: CdiAutonomousEnvironmentBridge
}

export class CdiPartnerHub {
  private sharedSecret: string
  private cyberlabCallbackUrl: string
  private readonly partners = new Map<string, CdiPartnerEntry>()
  private readonly seenInboundIds = new Map<string, number>()
  private readonly inboundActivity: CdiInboundActivityEntry[] = []
  private readonly configPath: string
  private readonly maxClockSkewMs = 5 * 60 * 1000
  private environmentBridge?: CdiAutonomousEnvironmentBridge

  constructor(private readonly deps: CdiPartnerHubDeps) {
    this.environmentBridge = deps.environmentBridge
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

  attachEnvironmentBridge(bridge: CdiAutonomousEnvironmentBridge): void {
    this.environmentBridge = bridge
  }

  exportCredentialsSnapshot(): {
    sharedSecret: string
    cyberlabCallbackUrl: string
    partners: CdiPartnerEntry[]
  } {
    return {
      sharedSecret: this.sharedSecret,
      cyberlabCallbackUrl: this.cyberlabCallbackUrl,
      partners: Array.from(this.partners.values()).map((p) => ({
        ...p,
        profile: { ...p.profile, interests: [...p.profile.interests] },
        permissions: { ...p.permissions },
      })),
    }
  }

  importCredentialsSnapshot(snapshot: {
    sharedSecret: string
    cyberlabCallbackUrl: string
    partners: CdiPartnerEntry[]
  }): void {
    if (snapshot.sharedSecret && snapshot.sharedSecret.length >= 16) {
      this.sharedSecret = snapshot.sharedSecret
    }
    if (snapshot.cyberlabCallbackUrl) {
      this.cyberlabCallbackUrl = snapshot.cyberlabCallbackUrl
    }
    for (const p of snapshot.partners) {
      this.partners.set(p.partnerId, {
        ...p,
        profile: { ...p.profile, interests: [...p.profile.interests] },
        permissions: { ...p.permissions },
      })
    }
    this.syncAllToAuthenticator()
    this.saveConfigIfPersistent()
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
        const isPreV3 = raw.version !== "3.0"
        if (typeof raw.sharedSecret === "string" && raw.sharedSecret.trim().length >= 16) {
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
                isPreV3 &&
                preset &&
                (!p.permissions?.initiateActions ||
                  p.permissions.initiateActions === "allow_readonly_propose_others" ||
                  p.permissions.initiateActions === "autonomous_in_scope")
                  ? "full_autonomy"
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
                  ...(isPreV3 && preset
                    ? {
                        writeWorkspaceAndCode: true,
                        fullRuntimeAndCodeAccess: true,
                        manageProjectsAndScope: true,
                        accessTrainingLabs: true,
                      }
                    : {}),
                  initiateActions: migratedInitiateActions,
                },
              })
            }
          }
          if (isPreV3 && candidate === this.configPath) {
            this.saveConfigIfPersistent()
          }
          return
        }
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
      version: "3.0",
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
    if (mode === "full_autonomy") {
      this.deps.policy.upsertRule({
        id: `${prefix}allow-full-autonomy`,
        description: `Autonomous cognitive partner ${partner.displayName} (${partner.partnerId}) operates with full unrestricted non-destructive autonomy inside scope`,
        capabilityPattern: "*",
        actorTypes: ["partner"],
        actorIds: [partner.partnerId],
        risks: ["read_only", "low", "moderate", "high"],
        modes: ["approved", "lab_automation", "manual"],
        effect: "allow",
      })
      return
    }

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
  }): { sharedSecret: string; secretPreview: string; cyberlabCallbackUrl: string; configFilePath: string } {
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
      configFilePath: this.configPath,
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
      return { httpStatus: 413, body: { ok: false, error: "Payload exceeds 2 MiB limit or is empty" } }
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
    const runtimeRoot = path.resolve(this.environmentBridge?.runtimeRoot ?? DEFAULT_RUNTIME_ROOT)

    const resolveSafeWorkspaceTarget = (relInput: string, allowDotfiles: boolean) => {
      const cleaned = relInput.trim()
      if (!cleaned || cleaned.includes("\0")) {
        throw new Error("Valid non-empty relative path is required")
      }
      const absTarget = path.resolve(this.deps.workspaceRoot, cleaned)
      const rel = path.relative(this.deps.workspaceRoot, absTarget)
      if (rel.startsWith("..") || path.isAbsolute(rel)) {
        throw new Error(`Path "${cleaned}" escapes project workspace "${this.deps.workspaceRoot}"`)
      }
      const segments = rel ? rel.split(path.sep) : []
      if (segments.some((seg) => BLOCKED_WORKSPACE_SEGMENTS.has(seg))) {
        throw new Error(`Access to protected metadata directory "${cleaned}" is prohibited`)
      }
      if (!allowDotfiles && rel && isSensitiveDotfile(rel)) {
        throw new Error(`Access to protected or secret file "${cleaned}" is prohibited`)
      }
      return { absTarget, relPosix: (rel || ".").replace(/\\/g, "/") }
    }

    const collectDirectoryEntries = (
      baseRoot: string,
      subpathInput: string,
      blockedSegments: Set<string>,
      recursive: boolean,
      maxEntries: number,
    ) => {
      const cleaned = subpathInput.trim() || "."
      const absBase = path.resolve(baseRoot, cleaned)
      const relBase = path.relative(baseRoot, absBase)
      if (relBase.startsWith("..") || path.isAbsolute(relBase)) {
        throw new Error(`Path "${cleaned}" escapes root "${baseRoot}"`)
      }
      if (relBase && relBase.split(path.sep).some((seg) => blockedSegments.has(seg))) {
        throw new Error(`Access to protected directory "${cleaned}" is prohibited`)
      }

      const results: Array<{ name: string; path: string; type: "file" | "directory"; sizeBytes?: number }> = []
      const walk = (dirAbs: string, depth: number) => {
        if (results.length >= maxEntries || depth > 8) return
        const dirents = readdirSync(dirAbs, { withFileTypes: true })
        for (const d of dirents) {
          if (results.length >= maxEntries) break
          if (blockedSegments.has(d.name) || d.isSymbolicLink()) continue
          const childAbs = path.join(dirAbs, d.name)
          const childRel = path.relative(baseRoot, childAbs).replace(/\\/g, "/")
          if (d.isDirectory()) {
            results.push({ name: d.name, path: childRel, type: "directory" })
            if (recursive) walk(childAbs, depth + 1)
          } else if (d.isFile()) {
            let sizeBytes: number | undefined
            try {
              sizeBytes = statSync(childAbs).size
            } catch {
              // ignore stat race
            }
            results.push({
              name: d.name,
              path: childRel,
              type: "file",
              ...(sizeBytes !== undefined ? { sizeBytes } : {}),
            })
          }
        }
      }
      walk(absBase, 0)
      return results
    }

    try {
      // 1. Real-time Project State, Autonomous Project Creation/Switching & Scope Management
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
        this.recordInboundActivity(partner.partnerId, "project.state", "allowed", "Queried live project state, labs & runtime context")
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            governanceModel: CDI_GOVERNANCE_MODEL,
            runtimeRoot,
            partnerProfile: {
              partnerId: partner.partnerId,
              displayName: partner.partnerId === partner.displayName ? partner.partnerId : partner.displayName,
              specialty: partner.specialty,
              profile: partner.profile,
              permissions: partner.permissions,
            },
            peerPartners,
            managedProjects: this.environmentBridge?.listProjects() ?? [],
            trainingLabs: this.environmentBridge?.listTrainingLabs() ?? [],
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

      if (parsed.action === "project.list") {
        if (!partner.permissions.readProjectState && !partner.permissions.manageProjectsAndScope) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks project listing permission`)
        }
        const projects = this.environmentBridge?.listProjects() ?? [
          {
            projectId: this.deps.projectId,
            name: this.deps.projectId,
            workspaceRoot: this.deps.workspaceRoot,
            isActive: true,
            createdBy: "curator",
            createdAt: new Date().toISOString(),
            isTrainingLab: false,
          },
        ]
        const labs = this.environmentBridge?.listTrainingLabs() ?? []
        this.recordInboundActivity(partner.partnerId, "project.list", "allowed", `Listed ${projects.length} project(s) and ${labs.length} training lab(s)`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            activeProjectId: this.deps.projectId,
            activeWorkspaceRoot: this.deps.workspaceRoot,
            runtimeRoot,
            projects,
            trainingLabs: labs,
          }),
        }
      }

      if (parsed.action === "project.create") {
        if (!partner.permissions.manageProjectsAndScope) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks manageProjectsAndScope permission`)
        }
        if (!this.environmentBridge) {
          throw new Error("Environment project manager is not attached to this workspace")
        }
        const name = String(params.name ?? "").trim()
        if (!name) throw new Error("project.create requires a non-empty params.name")
        const rawFiles =
          params.files && typeof params.files === "object" && !Array.isArray(params.files)
            ? Object.fromEntries(
                Object.entries(params.files as Record<string, unknown>).map(([k, v]) => [
                  k,
                  typeof v === "string" ? v : JSON.stringify(v, null, 2),
                ]),
              )
            : undefined
        const allowedTargets = Array.isArray(params.allowedTargets)
          ? (params.allowedTargets as ScopeTargetRule[])
          : undefined

        const created = await this.environmentBridge.createProject({
          name,
          ...(typeof params.slug === "string" && params.slug.trim() ? { slug: params.slug.trim() } : {}),
          ...(typeof params.directory === "string" && params.directory.trim() ? { directory: params.directory.trim() } : {}),
          ...(rawFiles ? { files: rawFiles } : {}),
          ...(allowedTargets ? { allowedTargets } : {}),
          ...(typeof params.allowExternalTargets === "boolean" ? { allowExternalTargets: params.allowExternalTargets } : {}),
          createdBy: `cdi:${partner.partnerId}`,
          setActive: params.setActive !== false,
          sourceHub: this,
        })
        this.recordInboundActivity(
          partner.partnerId,
          "project.create",
          "allowed",
          `Created autonomous project "${created.project.name}" (${created.project.projectId}) at ${created.project.workspaceRoot}`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, created),
        }
      }

      if (parsed.action === "project.select") {
        if (!partner.permissions.manageProjectsAndScope) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks manageProjectsAndScope permission`)
        }
        if (!this.environmentBridge) {
          throw new Error("Environment project manager is not attached to this workspace")
        }
        const selected = await this.environmentBridge.selectProject({
          ...(typeof params.projectId === "string" && params.projectId.trim() ? { projectId: params.projectId.trim() } : {}),
          ...(typeof params.directory === "string" && params.directory.trim() ? { directory: params.directory.trim() } : {}),
          sourceHub: this,
        })
        this.recordInboundActivity(
          partner.partnerId,
          "project.select",
          "allowed",
          `Switched active project to "${selected.projectId}" (${selected.workspaceRoot})`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { project: selected }),
        }
      }

      if (parsed.action === "scope.get") {
        if (!partner.permissions.readProjectState && !partner.permissions.manageProjectsAndScope) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks scope read permission`)
        }
        const scope = this.deps.scopes.getProjectScope(this.deps.projectId)
        this.recordInboundActivity(partner.partnerId, "scope.get", "allowed", `Inspected scope for ${this.deps.projectId}`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { scope }),
        }
      }

      if (parsed.action === "scope.update") {
        if (!partner.permissions.manageProjectsAndScope) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks manageProjectsAndScope permission`)
        }
        const current = this.deps.scopes.getProjectScope(this.deps.projectId)
        if (!current) throw new Error(`No scope initialized for "${this.deps.projectId}"`)

        let nextAllowed = Array.isArray(params.allowedTargets)
          ? (params.allowedTargets as ScopeTargetRule[])
          : [...current.allowedTargets]
        if (Array.isArray(params.addTargets)) {
          for (const rule of params.addTargets as ScopeTargetRule[]) {
            if (rule && rule.kind && rule.value) {
              const dup = nextAllowed.some((r) => r.kind === rule.kind && r.value === rule.value)
              if (!dup) nextAllowed.push(rule)
            }
          }
        }
        const nextBlocked = Array.isArray(params.blockedTargets)
          ? (params.blockedTargets as ScopeTargetRule[])
          : [...current.blockedTargets]

        const updated: ProjectScope = {
          ...current,
          ...(typeof params.name === "string" && params.name.trim() ? { name: params.name.trim() } : {}),
          allowedTargets: nextAllowed,
          blockedTargets: nextBlocked,
          allowExternalTargets:
            typeof params.allowExternalTargets === "boolean"
              ? params.allowExternalTargets
              : current.allowExternalTargets,
          updatedAt: new Date().toISOString(),
        }
        this.deps.scopes.setProjectScope(updated)
        this.recordInboundActivity(
          partner.partnerId,
          "scope.update",
          "allowed",
          `Updated scope (${updated.allowedTargets.length} allowed targets, allowExternal=${updated.allowExternalTargets})`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { scope: updated }),
        }
      }

      // 1b. Interactive Training Laboratories (lab.list, lab.start, lab.status, lab.reset, lab.stop)
      if (
        parsed.action === "lab.list" ||
        parsed.action === "lab.start" ||
        parsed.action === "lab.status" ||
        parsed.action === "lab.reset" ||
        parsed.action === "lab.stop"
      ) {
        if (!partner.permissions.accessTrainingLabs) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks accessTrainingLabs permission`)
        }
        if (!this.environmentBridge) {
          throw new Error("Training lab manager is not attached to this workspace")
        }

        if (parsed.action === "lab.list") {
          const labs = this.environmentBridge.listTrainingLabs()
          this.recordInboundActivity(partner.partnerId, "lab.list", "allowed", `Listed ${labs.length} training lab(s)`)
          return {
            httpStatus: 200,
            body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { labs }),
          }
        }

        const labId = String(params.labId ?? "").trim()
        if (!labId) throw new Error(`${parsed.action} requires params.labId`)

        if (parsed.action === "lab.status") {
          const lab = this.environmentBridge.getTrainingLabStatus(labId)
          this.recordInboundActivity(partner.partnerId, "lab.status", "allowed", `Checked training lab ${labId}`)
          return {
            httpStatus: 200,
            body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { lab }),
          }
        }

        if (parsed.action === "lab.start") {
          const lab = await this.environmentBridge.startTrainingLab({
            labId,
            ...(typeof params.preferredPort === "number" ? { preferredPort: params.preferredPort } : {}),
            ...(typeof params.resetFiles === "boolean" ? { resetFiles: params.resetFiles } : {}),
            setActive: params.setActive !== false,
            startedBy: `cdi:${partner.partnerId}`,
            sourceHub: this,
          })
          this.recordInboundActivity(
            partner.partnerId,
            "lab.start",
            "allowed",
            `Started training lab ${labId} (${lab.baseUrl ?? lab.workspaceRoot})`,
          )
          return {
            httpStatus: 200,
            body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { lab }),
          }
        }

        if (parsed.action === "lab.reset") {
          const lab = await this.environmentBridge.resetTrainingLab(labId)
          this.recordInboundActivity(partner.partnerId, "lab.reset", "allowed", `Reset training lab ${labId} files`)
          return {
            httpStatus: 200,
            body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { lab }),
          }
        }

        const lab = await this.environmentBridge.stopTrainingLab(labId)
        this.recordInboundActivity(partner.partnerId, "lab.stop", "allowed", `Stopped training lab ${labId}`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { lab }),
        }
      }

      // 2. Direct Evidence Access (List & Read)
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
        this.recordInboundActivity(partner.partnerId, "evidence.read", "allowed", `Read evidence ${evidenceId}`)
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

      // 3. Full Workspace File Listing, Reading, Writing, Editing, Mkdir & Delete
      if (parsed.action === "workspace.list_files") {
        if (!partner.permissions.readEvidenceAndFiles) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks readEvidenceAndFiles permission`)
        }
        const subpath = String(params.subpath ?? ".").trim() || "."
        const recursive = Boolean(params.recursive)
        const maxEntries = Math.min(1000, Math.max(1, Number(params.maxEntries) || 300))
        const scopeCheck = this.deps.scopes.verifyTargets(
          this.deps.projectId,
          { networkTargets: [], workspacePaths: [subpath] },
          ["workspace"],
        )
        if (!scopeCheck.allowed) {
          throw new Error(scopeCheck.reason)
        }
        const entries = collectDirectoryEntries(
          this.deps.workspaceRoot,
          subpath,
          BLOCKED_WORKSPACE_SEGMENTS,
          recursive,
          maxEntries,
        )
        this.recordInboundActivity(partner.partnerId, "workspace.list_files", "allowed", `Listed ${entries.length} entries in "${subpath}"`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            workspaceRoot: this.deps.workspaceRoot,
            subpath,
            entries,
          }),
        }
      }

      if (parsed.action === "workspace.read_file") {
        if (!partner.permissions.readEvidenceAndFiles) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks readEvidenceAndFiles permission`)
        }
        const filePath = String(params.path ?? "").trim()
        if (!filePath) throw new Error("params.path is required")
        const wantsRaw = Boolean(params.raw) && partner.permissions.fullRuntimeAndCodeAccess
        const scopeCheck = this.deps.scopes.verifyTargets(
          this.deps.projectId,
          { networkTargets: [], workspacePaths: [filePath] },
          ["workspace"],
        )
        if (!scopeCheck.allowed) {
          throw new Error(scopeCheck.reason)
        }
        const { absTarget, relPosix } = resolveSafeWorkspaceTarget(filePath, wantsRaw)
        const lst = lstatSync(absTarget)
        if (lst.isSymbolicLink() || !statSync(absTarget).isFile()) {
          throw new Error(`"${filePath}" is not a regular in-scope file`)
        }
        const rawBuf = readFileSync(absTarget)
        const offset = Math.max(0, Math.trunc(Number(params.offset) || 0))
        const limit = Math.min(MAX_WORKSPACE_READ_BYTES, Math.max(1024, Math.trunc(Number(params.limit) || MAX_WORKSPACE_READ_BYTES)))
        const sliced = rawBuf.subarray(offset, offset + limit)
        const textContent = sliced.toString("utf8")
        const outContent = wantsRaw ? { text: textContent, redacted: false } : redactSensitiveContent(textContent)
        this.recordInboundActivity(
          partner.partnerId,
          "workspace.read_file",
          "allowed",
          `Read file "${relPosix}" (raw=${wantsRaw}, redacted=${outContent.redacted})`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            path: relPosix,
            byteLength: rawBuf.byteLength,
            offset,
            truncated: offset + limit < rawBuf.byteLength,
            redacted: outContent.redacted,
            content: outContent.text,
          }),
        }
      }

      if (parsed.action === "workspace.write_file") {
        if (!partner.permissions.writeWorkspaceAndCode) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks writeWorkspaceAndCode permission`)
        }
        const filePath = String(params.path ?? "").trim()
        if (!filePath) throw new Error("workspace.write_file requires params.path")
        const content =
          typeof params.content === "string" ? params.content : JSON.stringify(params.content ?? "", null, 2)
        const { absTarget, relPosix } = resolveSafeWorkspaceTarget(filePath, false)
        mkdirSync(path.dirname(absTarget), { recursive: true })
        writeFileSync(absTarget, content, "utf8")
        const bytesWritten = Buffer.byteLength(content, "utf8")
        this.recordInboundActivity(
          partner.partnerId,
          "workspace.write_file",
          "allowed",
          `Wrote ${bytesWritten} bytes to "${relPosix}"`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            path: relPosix,
            bytesWritten,
            workspaceRoot: this.deps.workspaceRoot,
          }),
        }
      }

      if (parsed.action === "workspace.edit_file") {
        if (!partner.permissions.writeWorkspaceAndCode) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks writeWorkspaceAndCode permission`)
        }
        const filePath = String(params.path ?? "").trim()
        const oldText = String(params.oldText ?? "")
        const newText = String(params.newText ?? "")
        if (!filePath || !oldText) {
          throw new Error("workspace.edit_file requires non-empty params.path and params.oldText")
        }
        const { absTarget, relPosix } = resolveSafeWorkspaceTarget(filePath, false)
        if (!existsSync(absTarget) || !statSync(absTarget).isFile()) {
          throw new Error(`File "${relPosix}" does not exist`)
        }
        const current = readFileSync(absTarget, "utf8")
        if (!current.includes(oldText)) {
          throw new Error(`oldText was not found in "${relPosix}"`)
        }
        const updated = Boolean(params.replaceAll)
          ? current.split(oldText).join(newText)
          : current.replace(oldText, newText)
        writeFileSync(absTarget, updated, "utf8")
        this.recordInboundActivity(
          partner.partnerId,
          "workspace.edit_file",
          "allowed",
          `Edited "${relPosix}" (${Buffer.byteLength(updated, "utf8")} bytes)`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            path: relPosix,
            bytesWritten: Buffer.byteLength(updated, "utf8"),
          }),
        }
      }

      if (parsed.action === "workspace.mkdir") {
        if (!partner.permissions.writeWorkspaceAndCode) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks writeWorkspaceAndCode permission`)
        }
        const dirPath = String(params.path ?? "").trim()
        if (!dirPath) throw new Error("workspace.mkdir requires params.path")
        const { absTarget, relPosix } = resolveSafeWorkspaceTarget(dirPath, false)
        mkdirSync(absTarget, { recursive: true })
        this.recordInboundActivity(partner.partnerId, "workspace.mkdir", "allowed", `Created directory "${relPosix}"`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { path: relPosix }),
        }
      }

      if (parsed.action === "workspace.delete_file") {
        if (!partner.permissions.writeWorkspaceAndCode) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks writeWorkspaceAndCode permission`)
        }
        const filePath = String(params.path ?? "").trim()
        if (!filePath) throw new Error("workspace.delete_file requires params.path")
        const { absTarget, relPosix } = resolveSafeWorkspaceTarget(filePath, false)
        if (!existsSync(absTarget)) {
          return {
            httpStatus: 200,
            body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { path: relPosix, deleted: false }),
          }
        }
        rmSync(absTarget, { force: true })
        this.recordInboundActivity(partner.partnerId, "workspace.delete_file", "allowed", `Deleted "${relPosix}"`)
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, { path: relPosix, deleted: true }),
        }
      }

      // 3b. Full CyberLab OS Runtime Codebase Inspection (runtime.list_files & runtime.read_file)
      if (parsed.action === "runtime.list_files") {
        if (!partner.permissions.fullRuntimeAndCodeAccess) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks fullRuntimeAndCodeAccess permission`)
        }
        const subpath = String(params.subpath ?? ".").trim() || "."
        const recursive = Boolean(params.recursive)
        const maxEntries = Math.min(2000, Math.max(1, Number(params.maxEntries) || 500))
        const entries = collectDirectoryEntries(
          runtimeRoot,
          subpath,
          BLOCKED_RUNTIME_SEGMENTS,
          recursive,
          maxEntries,
        )
        const pattern = typeof params.pattern === "string" && params.pattern.trim() ? params.pattern.trim().toLowerCase() : ""
        const filtered = pattern ? entries.filter((e) => e.path.toLowerCase().includes(pattern)) : entries
        this.recordInboundActivity(
          partner.partnerId,
          "runtime.list_files",
          "allowed",
          `Listed ${filtered.length} CyberLab runtime file(s) under "${subpath}"`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            runtimeRoot,
            subpath,
            entries: filtered,
          }),
        }
      }

      if (parsed.action === "runtime.read_file") {
        if (!partner.permissions.fullRuntimeAndCodeAccess) {
          throw new PartnerAuthError("PERMISSION_DENIED", `CDI "${partner.partnerId}" lacks fullRuntimeAndCodeAccess permission`)
        }
        const filePath = String(params.path ?? "").trim()
        if (!filePath || filePath.includes("\0")) throw new Error("runtime.read_file requires params.path")
        const absFile = path.resolve(runtimeRoot, filePath)
        const rel = path.relative(runtimeRoot, absFile)
        if (rel.startsWith("..") || path.isAbsolute(rel)) {
          throw new Error(`Path "${filePath}" escapes CyberLab runtime root`)
        }
        if (rel.split(path.sep).some((seg) => BLOCKED_RUNTIME_SEGMENTS.has(seg)) || isSensitiveDotfile(rel)) {
          throw new Error(`Access to protected metadata or secret file "${filePath}" is prohibited`)
        }
        const lst = lstatSync(absFile)
        if (lst.isSymbolicLink() || !statSync(absFile).isFile()) {
          throw new Error(`"${filePath}" is not a regular CyberLab runtime file`)
        }
        const rawBuf = readFileSync(absFile)
        const offset = Math.max(0, Math.trunc(Number(params.offset) || 0))
        const limit = Math.min(MAX_WORKSPACE_READ_BYTES, Math.max(1024, Math.trunc(Number(params.limit) || MAX_WORKSPACE_READ_BYTES)))
        const content = rawBuf.subarray(offset, offset + limit).toString("utf8")
        const relPosix = rel.replace(/\\/g, "/")
        this.recordInboundActivity(
          partner.partnerId,
          "runtime.read_file",
          "allowed",
          `Read runtime source "${relPosix}" (${rawBuf.byteLength} bytes)`,
        )
        return {
          httpStatus: 200,
          body: this.buildSignedGatewayResponse(parsed.messageId, secret, true, {
            runtimeRoot,
            path: relPosix,
            byteLength: rawBuf.byteLength,
            offset,
            truncated: offset + limit < rawBuf.byteLength,
            content,
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
            initiateMode === "full_autonomy" &&
            (cap.risk === "read_only" || cap.risk === "low" || cap.risk === "moderate" || cap.risk === "high")
          ) {
            execMode = "approved"
          } else if (
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
