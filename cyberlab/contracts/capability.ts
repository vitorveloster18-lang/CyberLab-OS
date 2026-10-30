import { Schema } from "effect"
import { optional } from "@opencode/schema/schema"

export const CapabilityRiskValues = ["read_only", "low", "moderate", "high", "destructive"] as const
export type CapabilityRisk = (typeof CapabilityRiskValues)[number]
export const CapabilityRiskSchema = Schema.Literals(CapabilityRiskValues)

export const ExecutionModeValues = ["manual", "proposed", "approved", "lab_automation"] as const
export type ExecutionMode = (typeof ExecutionModeValues)[number]
export const ExecutionModeSchema = Schema.Literals(ExecutionModeValues)

const NonEmptyId = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(128),
  Schema.isPattern(/^[a-zA-Z0-9._:-]+$/),
)

const SemverLike = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(64),
  Schema.isPattern(/^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$/),
)

export interface CapabilityDefinition {
  id: string
  version: string
  title: string
  description: string

  inputSchemaId: string
  outputSchemaId: string

  risk: CapabilityRisk
  supportedModes: ExecutionMode[]

  requiredPermissions: string[]
  requiredScope?: string[]

  executorId: string
  skillIds: string[]

  licenseRefs: string[]
  enabled: boolean
}

export const CapabilityDefinitionSchema = Schema.Struct({
  id: NonEmptyId,
  version: SemverLike,
  title: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(200)),
  description: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(4000)),

  inputSchemaId: NonEmptyId,
  outputSchemaId: NonEmptyId,

  risk: CapabilityRiskSchema,
  supportedModes: Schema.Array(ExecutionModeSchema).check(Schema.isMinLength(1)),

  requiredPermissions: Schema.Array(Schema.String.check(Schema.isMinLength(1))),
  requiredScope: Schema.Array(Schema.String.check(Schema.isMinLength(1))).pipe(optional),

  executorId: NonEmptyId,
  skillIds: Schema.Array(NonEmptyId),

  licenseRefs: Schema.Array(Schema.String.check(Schema.isMinLength(1))).check(Schema.isMinLength(1)),
  enabled: Schema.Boolean,
}).annotate({ identifier: "CyberLab.CapabilityDefinition" })

export interface CapabilityRegistry {
  list(): Promise<CapabilityDefinition[]>
  get(id: string): Promise<CapabilityDefinition | undefined>
  register(definition: CapabilityDefinition): Promise<void>
  disable(id: string, reason: string): Promise<void>
}

export interface CapabilityActor {
  type: "system" | "admin" | "user" | "assistant" | "partner"
  id: string
}

export interface CapabilityProposal {
  proposalId: string
  proposedBy: CapabilityActor
  proposedAt: string
  definition: CapabilityDefinition
  status: "pending_review" | "rejected" | "accepted"
  notes?: string
}

export function validateCapabilityDefinition(input: unknown): CapabilityDefinition {
  const { requiredScope, ...decoded } = Schema.decodeUnknownSync(CapabilityDefinitionSchema)(input)
  return {
    ...decoded,
    supportedModes: [...decoded.supportedModes],
    requiredPermissions: [...decoded.requiredPermissions],
    ...(requiredScope !== undefined ? { requiredScope: [...requiredScope] } : {}),
    skillIds: [...decoded.skillIds],
    licenseRefs: [...decoded.licenseRefs],
  }
}
