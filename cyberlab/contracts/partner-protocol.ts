import { Schema } from "effect"
import { optional } from "@opencode/schema/schema"

export const PartnerMessageTypeValues = [
  "task.submit",
  "task.accepted",
  "task.progress",
  "task.request_context",
  "task.result",
  "task.error",
  "task.cancel",
  "approval.request",
] as const
export type PartnerMessageType = (typeof PartnerMessageTypeValues)[number]
export const PartnerMessageTypeSchema = Schema.Literals(PartnerMessageTypeValues)

const NonEmptyId = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(160))
const IsoTimestamp = Schema.String.check(
  Schema.isMinLength(10),
  Schema.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/),
)

export const DEFAULT_MAX_PARTNER_ENVELOPE_BYTES = 256 * 1024

export interface PartnerEnvelope<TPayload = unknown> {
  protocol: "cyberlab-partner"
  protocolVersion: "1.0"

  messageId: string
  correlationId: string
  sentAt: string

  sender: {
    id: string
    type: "cyberlab" | "partner"
  }

  recipient: {
    id: string
  }

  type: PartnerMessageType
  payload: TPayload
}

export interface SignedPartnerEnvelope<TPayload = unknown> extends PartnerEnvelope<TPayload> {
  signature: string
}

export const PartnerEnvelopeSchema = Schema.Struct({
  protocol: Schema.Literal("cyberlab-partner"),
  protocolVersion: Schema.Literal("1.0"),
  messageId: NonEmptyId,
  correlationId: NonEmptyId,
  sentAt: IsoTimestamp,
  sender: Schema.Struct({
    id: NonEmptyId,
    type: Schema.Literals(["cyberlab", "partner"]),
  }),
  recipient: Schema.Struct({
    id: NonEmptyId,
  }),
  type: PartnerMessageTypeSchema,
  payload: Schema.Unknown,
}).annotate({ identifier: "CyberLab.PartnerEnvelope" })

export interface PartnerTask {
  taskId: string
  projectId: string
  objective: string

  contextBundle: {
    evidenceIds: string[]
    text?: string
    files?: string[]
  }

  allowedActions: string[]
  prohibitedActions: string[]

  requestedOutput: {
    summary: boolean
    findings: boolean
    evidenceReferences: boolean
    limitations: boolean
  }
}

export const PartnerTaskSchema = Schema.Struct({
  taskId: NonEmptyId,
  projectId: NonEmptyId,
  objective: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(8000)),
  contextBundle: Schema.Struct({
    evidenceIds: Schema.Array(NonEmptyId),
    text: Schema.String.pipe(optional),
    files: Schema.Array(Schema.String.check(Schema.isMinLength(1))).pipe(optional),
  }),
  allowedActions: Schema.Array(Schema.String.check(Schema.isMinLength(1))),
  prohibitedActions: Schema.Array(Schema.String.check(Schema.isMinLength(1))),
  requestedOutput: Schema.Struct({
    summary: Schema.Boolean,
    findings: Schema.Boolean,
    evidenceReferences: Schema.Boolean,
    limitations: Schema.Boolean,
  }),
}).annotate({ identifier: "CyberLab.PartnerTask" })

export interface PartnerResult {
  taskId: string
  status: "completed" | "partial" | "failed"

  summary: string
  findings: Array<{
    title: string
    description: string
    evidenceRefs: string[]
    confidence?: number
  }>

  limitations: string[]
  artifactRefs: string[]
}

export const PartnerResultSchema = Schema.Struct({
  taskId: NonEmptyId,
  status: Schema.Literals(["completed", "partial", "failed"]),
  summary: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(32000)),
  findings: Schema.Array(
    Schema.Struct({
      title: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(300)),
      description: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(16000)),
      evidenceRefs: Schema.Array(NonEmptyId),
      confidence: Schema.Number.check(Schema.isGreaterThanOrEqualTo(0), Schema.isLessThanOrEqualTo(1)).pipe(optional),
    }),
  ),
  limitations: Schema.Array(Schema.String.check(Schema.isMinLength(1))),
  artifactRefs: Schema.Array(NonEmptyId),
}).annotate({ identifier: "CyberLab.PartnerResult" })

export interface PartnerApprovalRequestPayload {
  taskId: string
  capabilityId: string
  rationale: string
  proposedInput: unknown
}

export const PartnerApprovalRequestPayloadSchema = Schema.Struct({
  taskId: NonEmptyId,
  capabilityId: NonEmptyId,
  rationale: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(4000)),
  proposedInput: Schema.Unknown,
}).annotate({ identifier: "CyberLab.PartnerApprovalRequestPayload" })

export function validatePartnerEnvelope(
  raw: unknown,
  maxBytes: number = DEFAULT_MAX_PARTNER_ENVELOPE_BYTES,
): PartnerEnvelope {
  const serialized = typeof raw === "string" ? raw : JSON.stringify(raw)
  if (!serialized || Buffer.byteLength(serialized, "utf8") > maxBytes) {
    throw new Error(`PartnerEnvelope exceeds maximum byte size (${maxBytes} bytes) or is empty`)
  }
  const parsed: unknown = typeof raw === "string" ? JSON.parse(raw) : raw
  return Schema.decodeUnknownSync(PartnerEnvelopeSchema)(parsed)
}

export function validatePartnerTask(input: unknown): PartnerTask {
  const { contextBundle, ...decoded } = Schema.decodeUnknownSync(PartnerTaskSchema)(input)
  const { files, ...bundleRest } = contextBundle
  return {
    ...decoded,
    contextBundle: {
      ...bundleRest,
      evidenceIds: [...bundleRest.evidenceIds],
      ...(files !== undefined ? { files: [...files] } : {}),
    },
    allowedActions: [...decoded.allowedActions],
    prohibitedActions: [...decoded.prohibitedActions],
  }
}

export function validatePartnerResult(input: unknown): PartnerResult {
  const decoded = Schema.decodeUnknownSync(PartnerResultSchema)(input)
  return {
    ...decoded,
    findings: decoded.findings.map((finding) => ({
      ...finding,
      evidenceRefs: [...finding.evidenceRefs],
    })),
    limitations: [...decoded.limitations],
    artifactRefs: [...decoded.artifactRefs],
  }
}
