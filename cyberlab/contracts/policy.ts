import { Schema } from "effect"
import { optional } from "@opencode/schema/schema"
import { CapabilityRiskSchema, ExecutionModeSchema, type CapabilityRisk, type ExecutionMode } from "./capability.js"

export const PolicyEffectValues = ["allow", "deny", "ask"] as const
export type PolicyEffect = (typeof PolicyEffectValues)[number]
export const PolicyEffectSchema = Schema.Literals(PolicyEffectValues)

export const ScopeTargetKindValues = [
  "cidr",
  "ip",
  "domain",
  "url_origin",
  "url_prefix",
  "url_regex",
  "workspace_path",
] as const
export type ScopeTargetKind = (typeof ScopeTargetKindValues)[number]
export const ScopeTargetKindSchema = Schema.Literals(ScopeTargetKindValues)

export const EngagementModeValues = ["lab_isolated", "bug_bounty", "authorized_pentest"] as const
export type EngagementMode = (typeof EngagementModeValues)[number]
export const EngagementModeSchema = Schema.Literals(EngagementModeValues)

export const BugBountyPlatformValues = [
  "custom",
  "hackerone",
  "bugcrowd",
  "intigriti",
  "yeswehack",
] as const
export type BugBountyPlatform = (typeof BugBountyPlatformValues)[number]
export const BugBountyPlatformSchema = Schema.Literals(BugBountyPlatformValues)

const NonEmptyString = Schema.String.check(Schema.isMinLength(1))

export interface ScopeTargetRule {
  kind: ScopeTargetKind
  value: string
  notes?: string
}

export const ScopeTargetRuleSchema = Schema.Struct({
  kind: ScopeTargetKindSchema,
  value: NonEmptyString,
  notes: Schema.String.pipe(optional),
}).annotate({ identifier: "CyberLab.ScopeTargetRule" })

export interface EngagementHeaderRule {
  name: string
  value: string
  enabled: boolean
}

export const EngagementHeaderRuleSchema = Schema.Struct({
  name: NonEmptyString,
  value: Schema.String,
  enabled: Schema.Boolean,
}).annotate({ identifier: "CyberLab.EngagementHeaderRule" })

export interface EngagementProfile {
  mode: EngagementMode
  platform: BugBountyPlatform
  programName?: string
  researcherHandle?: string
  customUserAgent?: string
  customHeaders: EngagementHeaderRule[]
  maxRequestsPerSecond: number
}

export const EngagementProfileSchema = Schema.Struct({
  mode: EngagementModeSchema,
  platform: BugBountyPlatformSchema,
  programName: Schema.String.pipe(optional),
  researcherHandle: Schema.String.pipe(optional),
  customUserAgent: Schema.String.pipe(optional),
  customHeaders: Schema.Array(EngagementHeaderRuleSchema),
  maxRequestsPerSecond: Schema.Number,
}).annotate({ identifier: "CyberLab.EngagementProfile" })

export interface ProjectScope {
  scopeId: string
  projectId: string
  name: string
  workspaceRoot: string
  allowedTargets: ScopeTargetRule[]
  blockedTargets: ScopeTargetRule[]
  /** Defaults to false: public/routable external IP targets are blocked unless explicitly enabled. */
  allowExternalTargets: boolean
  engagement?: EngagementProfile
  active: boolean
  updatedAt: string
}

export const ProjectScopeSchema = Schema.Struct({
  scopeId: NonEmptyString,
  projectId: NonEmptyString,
  name: NonEmptyString,
  workspaceRoot: NonEmptyString,
  allowedTargets: Schema.Array(ScopeTargetRuleSchema),
  blockedTargets: Schema.Array(ScopeTargetRuleSchema),
  allowExternalTargets: Schema.Boolean,
  engagement: EngagementProfileSchema.pipe(optional),
  active: Schema.Boolean,
  updatedAt: NonEmptyString,
}).annotate({ identifier: "CyberLab.ProjectScope" })

export interface PolicyRule {
  id: string
  description: string
  actorTypes?: Array<"user" | "assistant" | "partner">
  actorIds?: string[]
  capabilityPattern: string
  risks?: CapabilityRisk[]
  modes?: ExecutionMode[]
  effect: PolicyEffect
}

export const PolicyRuleSchema = Schema.Struct({
  id: NonEmptyString,
  description: NonEmptyString,
  actorTypes: Schema.Array(Schema.Literals(["user", "assistant", "partner"])).pipe(optional),
  actorIds: Schema.Array(NonEmptyString).pipe(optional),
  capabilityPattern: NonEmptyString,
  risks: Schema.Array(CapabilityRiskSchema).pipe(optional),
  modes: Schema.Array(ExecutionModeSchema).pipe(optional),
  effect: PolicyEffectSchema,
}).annotate({ identifier: "CyberLab.PolicyRule" })

export interface PolicyDecision {
  decision: PolicyEffect
  policyIds: string[]
  reason: string
  evaluatedAt: string
  phase: "submission" | "execution"
}

export interface ApprovalTicket {
  approvalId: string
  executionId: string
  projectId: string
  capabilityId: string
  requestedBy: {
    type: "user" | "assistant" | "partner"
    id: string
  }
  targetSummary: string
  status: "pending" | "approved" | "rejected" | "expired" | "consumed"
  createdAt: string
  expiresAt: string
  decidedBy?: string
  decidedAt?: string
  reason?: string
}

export interface PolicyAuditEntry {
  auditId: string
  executionId: string
  projectId: string
  capabilityId: string
  actor: {
    type: "user" | "assistant" | "partner"
    id: string
  }
  target?: string
  phase: "submission" | "execution"
  decision: PolicyEffect
  policyIds: string[]
  reason: string
  timestamp: string
}

export function createDefaultEngagementProfile(): EngagementProfile {
  return {
    mode: "lab_isolated",
    platform: "custom",
    customHeaders: [],
    maxRequestsPerSecond: 20,
  }
}

export function validateProjectScope(input: unknown): ProjectScope {
  const decoded = Schema.decodeUnknownSync(ProjectScopeSchema)(input)
  return {
    scopeId: decoded.scopeId,
    projectId: decoded.projectId,
    name: decoded.name,
    workspaceRoot: decoded.workspaceRoot,
    allowExternalTargets: decoded.allowExternalTargets,
    active: decoded.active,
    updatedAt: decoded.updatedAt,
    allowedTargets: decoded.allowedTargets.map((rule) => ({
      kind: rule.kind,
      value: rule.value,
      ...(rule.notes !== undefined ? { notes: rule.notes } : {}),
    })),
    blockedTargets: decoded.blockedTargets.map((rule) => ({
      kind: rule.kind,
      value: rule.value,
      ...(rule.notes !== undefined ? { notes: rule.notes } : {}),
    })),
    ...(decoded.engagement
      ? {
          engagement: {
            mode: decoded.engagement.mode,
            platform: decoded.engagement.platform,
            ...(decoded.engagement.programName !== undefined ? { programName: decoded.engagement.programName } : {}),
            ...(decoded.engagement.researcherHandle !== undefined
              ? { researcherHandle: decoded.engagement.researcherHandle }
              : {}),
            ...(decoded.engagement.customUserAgent !== undefined
              ? { customUserAgent: decoded.engagement.customUserAgent }
              : {}),
            maxRequestsPerSecond: Math.max(1, Math.min(200, Math.round(decoded.engagement.maxRequestsPerSecond || 20))),
            customHeaders: decoded.engagement.customHeaders.map((h) => ({
              name: h.name,
              value: h.value,
              enabled: h.enabled,
            })),
          },
        }
      : {}),
  }
}
