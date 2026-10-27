import { Schema } from "effect"
import { optional } from "@opencode/schema/schema"
import { CapabilityRiskSchema, ExecutionModeSchema, type CapabilityRisk, type ExecutionMode } from "./capability.js"

export const PolicyEffectValues = ["allow", "deny", "ask"] as const
export type PolicyEffect = (typeof PolicyEffectValues)[number]
export const PolicyEffectSchema = Schema.Literals(PolicyEffectValues)

export const ScopeTargetKindValues = ["cidr", "ip", "domain", "url_origin", "workspace_path"] as const
export type ScopeTargetKind = (typeof ScopeTargetKindValues)[number]
export const ScopeTargetKindSchema = Schema.Literals(ScopeTargetKindValues)

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

export interface ProjectScope {
  scopeId: string
  projectId: string
  name: string
  workspaceRoot: string
  allowedTargets: ScopeTargetRule[]
  blockedTargets: ScopeTargetRule[]
  /** Defaults to false: public/routable external IP targets are blocked unless explicitly enabled. */
  allowExternalTargets: boolean
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
  active: Schema.Boolean,
  updatedAt: NonEmptyString,
}).annotate({ identifier: "CyberLab.ProjectScope" })

export interface PolicyRule {
  id: string
  description: string
  actorTypes?: Array<"user" | "assistant" | "partner">
  capabilityPattern: string
  risks?: CapabilityRisk[]
  modes?: ExecutionMode[]
  effect: PolicyEffect
}

export const PolicyRuleSchema = Schema.Struct({
  id: NonEmptyString,
  description: NonEmptyString,
  actorTypes: Schema.Array(Schema.Literals(["user", "assistant", "partner"])).pipe(optional),
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

export function validateProjectScope(input: unknown): ProjectScope {
  const decoded = Schema.decodeUnknownSync(ProjectScopeSchema)(input)
  return {
    ...decoded,
    allowedTargets: decoded.allowedTargets.map((rule) => ({ ...rule })),
    blockedTargets: decoded.blockedTargets.map((rule) => ({ ...rule })),
  }
}
