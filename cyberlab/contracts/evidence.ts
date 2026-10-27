import { Schema } from "effect"
import { optional } from "@opencode/schema/schema"

export const EvidenceKindValues = [
  "stdout",
  "stderr",
  "json",
  "file",
  "http_exchange",
  "network_observation",
  "code_location",
  "screenshot",
  "finding",
  "external_reference",
] as const
export type EvidenceKind = (typeof EvidenceKindValues)[number]
export const EvidenceKindSchema = Schema.Literals(EvidenceKindValues)

export const RetentionClassValues = ["temporary", "project", "forensic"] as const
export type RetentionClass = (typeof RetentionClassValues)[number]
export const RetentionClassSchema = Schema.Literals(RetentionClassValues)

export const RedactionStatusValues = ["not_checked", "checked", "redacted"] as const
export type RedactionStatus = (typeof RedactionStatusValues)[number]
export const RedactionStatusSchema = Schema.Literals(RedactionStatusValues)

export const FindingStatusValues = [
  "unreviewed",
  "supported",
  "confirmed",
  "rejected",
  "inconclusive",
] as const
export type FindingStatus = (typeof FindingStatusValues)[number]
export const FindingStatusSchema = Schema.Literals(FindingStatusValues)

export const FindingSeverityValues = ["info", "low", "medium", "high", "critical"] as const
export type FindingSeverity = (typeof FindingSeverityValues)[number]
export const FindingSeveritySchema = Schema.Literals(FindingSeverityValues)

const NonEmptyString = Schema.String.check(Schema.isMinLength(1))
const Sha256Hex = Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/))
const IsoTimestamp = Schema.String.check(
  Schema.isMinLength(10),
  Schema.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/),
)

export interface EvidenceDraft {
  kind: EvidenceKind
  title: string

  source: {
    toolId: string
    toolVersion?: string
    executorId: string
    executionId: string
  }

  content: {
    mediaType: string
    storageKey?: string
    inlineText?: string
    sha256?: string
    byteLength?: number
  }

  observedAt: string
  labels?: string[]
  redactionApplied?: boolean
}

export const EvidenceDraftSchema = Schema.Struct({
  kind: EvidenceKindSchema,
  title: NonEmptyString,
  source: Schema.Struct({
    toolId: NonEmptyString,
    toolVersion: NonEmptyString.pipe(optional),
    executorId: NonEmptyString,
    executionId: NonEmptyString,
  }),
  content: Schema.Struct({
    mediaType: NonEmptyString,
    storageKey: NonEmptyString.pipe(optional),
    inlineText: Schema.String.pipe(optional),
    sha256: Sha256Hex.pipe(optional),
    byteLength: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)).pipe(optional),
  }),
  observedAt: IsoTimestamp,
  labels: Schema.Array(NonEmptyString).pipe(optional),
  redactionApplied: Schema.Boolean.pipe(optional),
}).annotate({ identifier: "CyberLab.EvidenceDraft" })

export interface EvidenceRecord extends EvidenceDraft {
  evidenceId: string
  projectId: string
  createdAt: string

  provenance: {
    parentEvidenceIds: string[]
    derivedBy?: string
    sourceRevision?: string
  }

  integrity: {
    sha256: string
    immutable: boolean
  }

  retentionClass: RetentionClass
  redactionStatus: RedactionStatus
}

export const EvidenceRecordSchema = Schema.Struct({
  ...EvidenceDraftSchema.fields,
  evidenceId: NonEmptyString,
  projectId: NonEmptyString,
  createdAt: IsoTimestamp,
  provenance: Schema.Struct({
    parentEvidenceIds: Schema.Array(NonEmptyString),
    derivedBy: NonEmptyString.pipe(optional),
    sourceRevision: NonEmptyString.pipe(optional),
  }),
  integrity: Schema.Struct({
    sha256: Sha256Hex,
    immutable: Schema.Boolean,
  }),
  retentionClass: RetentionClassSchema,
  redactionStatus: RedactionStatusSchema,
}).annotate({ identifier: "CyberLab.EvidenceRecord" })

export interface SecurityFinding {
  findingId: string
  projectId: string

  title: string
  description: string
  severity: FindingSeverity

  status: FindingStatus
  confidence?: number

  evidenceIds: string[]
  affectedAssets: string[]

  proposedRemediation?: string
  validationEvidenceIds: string[]

  createdAt: string
  updatedAt: string

  review?: {
    reviewedBy: string
    decision: "accept" | "reject" | "needs_more_evidence"
    notes?: string
    reviewedAt: string
  }
}

export const SecurityFindingSchema = Schema.Struct({
  findingId: NonEmptyString,
  projectId: NonEmptyString,
  title: NonEmptyString,
  description: NonEmptyString,
  severity: FindingSeveritySchema,
  status: FindingStatusSchema,
  confidence: Schema.Number.check(Schema.isGreaterThanOrEqualTo(0), Schema.isLessThanOrEqualTo(1)).pipe(optional),
  evidenceIds: Schema.Array(NonEmptyString),
  affectedAssets: Schema.Array(NonEmptyString),
  proposedRemediation: NonEmptyString.pipe(optional),
  validationEvidenceIds: Schema.Array(NonEmptyString),
  createdAt: IsoTimestamp,
  updatedAt: IsoTimestamp,
  review: Schema.Struct({
    reviewedBy: NonEmptyString,
    decision: Schema.Literals(["accept", "reject", "needs_more_evidence"]),
    notes: Schema.String.pipe(optional),
    reviewedAt: IsoTimestamp,
  }).pipe(optional),
}).annotate({ identifier: "CyberLab.SecurityFinding" })

export function validateEvidenceDraft(input: unknown): EvidenceDraft {
  const { labels, ...decoded } = Schema.decodeUnknownSync(EvidenceDraftSchema)(input)
  if (decoded.content.inlineText === undefined && decoded.content.storageKey === undefined) {
    throw new Error("EvidenceDraft.content requires either inlineText or storageKey")
  }
  return {
    ...decoded,
    ...(labels !== undefined ? { labels: [...labels] } : {}),
  }
}

export function validateEvidenceRecord(input: unknown): EvidenceRecord {
  const { labels, ...decoded } = Schema.decodeUnknownSync(EvidenceRecordSchema)(input)
  if (decoded.content.inlineText === undefined && decoded.content.storageKey === undefined) {
    throw new Error("EvidenceRecord.content requires either inlineText or storageKey")
  }
  return {
    ...decoded,
    ...(labels !== undefined ? { labels: [...labels] } : {}),
    provenance: {
      ...decoded.provenance,
      parentEvidenceIds: [...decoded.provenance.parentEvidenceIds],
    },
  }
}

export function validateSecurityFinding(input: unknown): SecurityFinding {
  const decoded = Schema.decodeUnknownSync(SecurityFindingSchema)(input)
  if ((decoded.status === "confirmed" || decoded.status === "supported") && decoded.evidenceIds.length === 0) {
    throw new Error(`SecurityFinding with status "${decoded.status}" requires at least one linked evidenceId`)
  }
  return {
    ...decoded,
    evidenceIds: [...decoded.evidenceIds],
    affectedAssets: [...decoded.affectedAssets],
    validationEvidenceIds: [...decoded.validationEvidenceIds],
  }
}
