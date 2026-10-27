import { Schema } from "effect"
import {
  validateCapabilityDefinition,
  type CapabilityActor,
  type CapabilityDefinition,
  type CapabilityProposal,
  type CapabilityRegistry,
} from "../contracts/capability.js"

export class CapabilityRegistrationDeniedError extends Error {
  readonly code = "CAPABILITY_REGISTRATION_DENIED"
  constructor(message: string) {
    super(message)
    this.name = "CapabilityRegistrationDeniedError"
  }
}

export class ControlledCapabilityRegistry implements CapabilityRegistry {
  private readonly capabilities = new Map<string, CapabilityDefinition>()
  private readonly disabledReasons = new Map<string, string>()
  private readonly proposals: CapabilityProposal[] = []

  async list(): Promise<CapabilityDefinition[]> {
    return Array.from(this.capabilities.values()).map((cap) => ({
      ...cap,
      supportedModes: [...cap.supportedModes],
      requiredPermissions: [...cap.requiredPermissions],
      ...(cap.requiredScope !== undefined ? { requiredScope: [...cap.requiredScope] } : {}),
      skillIds: [...cap.skillIds],
      licenseRefs: [...cap.licenseRefs],
    }))
  }

  async get(id: string): Promise<CapabilityDefinition | undefined> {
    const found = this.capabilities.get(id)
    if (!found) return undefined
    return {
      ...found,
      supportedModes: [...found.supportedModes],
      requiredPermissions: [...found.requiredPermissions],
      ...(found.requiredScope !== undefined ? { requiredScope: [...found.requiredScope] } : {}),
      skillIds: [...found.skillIds],
      licenseRefs: [...found.licenseRefs],
    }
  }

  async register(definition: CapabilityDefinition): Promise<void> {
    await this.registerWithActor(definition, { type: "system", id: "local-admin" })
  }

  /**
   * Enforces the security rule from Section 5.1:
   * Remote partners and unapproved assistants cannot silently register capabilities with executor access.
   */
  async registerWithActor(definition: CapabilityDefinition, actor: CapabilityActor): Promise<void> {
    if (actor.type === "partner" || actor.type === "assistant") {
      throw new CapabilityRegistrationDeniedError(
        `Actor "${actor.type}:${actor.id}" is not permitted to register executable capabilities directly; use propose() instead.`,
      )
    }
    const validated = validateCapabilityDefinition(definition)
    this.capabilities.set(validated.id, validated)
    if (validated.enabled) {
      this.disabledReasons.delete(validated.id)
    }
  }

  async propose(definition: CapabilityDefinition, actor: CapabilityActor, notes?: string): Promise<CapabilityProposal> {
    const validated = validateCapabilityDefinition(definition)
    const proposal: CapabilityProposal = {
      proposalId: `cap-prop-${crypto.randomUUID()}`,
      proposedBy: actor,
      proposedAt: new Date().toISOString(),
      definition: { ...validated, enabled: false },
      status: "pending_review",
      ...(notes !== undefined ? { notes } : {}),
    }
    this.proposals.push(proposal)
    return proposal
  }

  listProposals(): CapabilityProposal[] {
    return [...this.proposals]
  }

  async disable(id: string, reason: string): Promise<void> {
    const trimmed = reason.trim()
    if (!trimmed) {
      throw new Error("Disabling a capability requires a non-empty reason")
    }
    const current = this.capabilities.get(id)
    if (!current) {
      throw new Error(`Capability "${id}" not found`)
    }
    this.capabilities.set(id, { ...current, enabled: false })
    this.disabledReasons.set(id, trimmed)
  }

  getDisabledReason(id: string): string | undefined {
    return this.disabledReasons.get(id)
  }
}

export class InputOutputSchemaRegistry {
  private readonly validators = new Map<string, (value: unknown) => unknown>()

  registerEffectSchema<S extends Schema.Top>(schemaId: string, schema: S): void {
    const decode = Schema.decodeUnknownSync(schema as unknown as Schema.Codec<unknown, unknown, never, never>)
    this.validators.set(schemaId, (value) => decode(value))
  }

  registerValidator(schemaId: string, validator: (value: unknown) => unknown): void {
    this.validators.set(schemaId, validator)
  }

  has(schemaId: string): boolean {
    return this.validators.has(schemaId)
  }

  validate(schemaId: string, value: unknown): unknown {
    const validator = this.validators.get(schemaId)
    if (!validator) {
      throw new Error(`Schema "${schemaId}" is not registered in InputOutputSchemaRegistry`)
    }
    return validator(value)
  }
}
