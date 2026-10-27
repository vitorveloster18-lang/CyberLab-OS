import { Schema } from "effect"
import { optional } from "@opencode/schema/schema"
import { ExecutionModeSchema, type ExecutionMode } from "./capability.js"
import type { EvidenceDraft } from "./evidence.js"

export const ExecutionStatusValues = [
  "draft",
  "awaiting_approval",
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "blocked",
  "timed_out",
] as const
export type ExecutionStatus = (typeof ExecutionStatusValues)[number]
export const ExecutionStatusSchema = Schema.Literals(ExecutionStatusValues)

export const ExecutionActorTypeValues = ["user", "assistant", "partner"] as const
export type ExecutionActorType = (typeof ExecutionActorTypeValues)[number]
export const ExecutionActorTypeSchema = Schema.Literals(ExecutionActorTypeValues)

const NonEmptyId = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(160))
const IsoTimestamp = Schema.String.check(
  Schema.isMinLength(10),
  Schema.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/),
)

export interface ExecutionRequest {
  requestId: string
  projectId: string
  capabilityId: string

  requestedBy: {
    type: ExecutionActorType
    id: string
  }

  input: unknown
  mode: ExecutionMode

  scopeId?: string
  parentExecutionId?: string
  idempotencyKey?: string
}

export const ExecutionRequestSchema = Schema.Struct({
  requestId: NonEmptyId,
  projectId: NonEmptyId,
  capabilityId: NonEmptyId,
  requestedBy: Schema.Struct({
    type: ExecutionActorTypeSchema,
    id: NonEmptyId,
  }),
  input: Schema.Unknown,
  mode: ExecutionModeSchema,
  scopeId: NonEmptyId.pipe(optional),
  parentExecutionId: NonEmptyId.pipe(optional),
  idempotencyKey: NonEmptyId.pipe(optional),
}).annotate({ identifier: "CyberLab.ExecutionRequest" })

export interface ExecutionRecord {
  executionId: string
  request: ExecutionRequest
  status: ExecutionStatus

  policyDecision?: {
    decision: "allow" | "deny" | "ask"
    policyIds: string[]
    reason: string
  }

  startedAt?: string
  finishedAt?: string

  resultEvidenceIds: string[]
  error?: {
    code: string
    message: string
    retryable: boolean
  }
}

export const ExecutionRecordSchema = Schema.Struct({
  executionId: NonEmptyId,
  request: ExecutionRequestSchema,
  status: ExecutionStatusSchema,
  policyDecision: Schema.Struct({
    decision: Schema.Literals(["allow", "deny", "ask"]),
    policyIds: Schema.Array(NonEmptyId),
    reason: Schema.String.check(Schema.isMinLength(1)),
  }).pipe(optional),
  startedAt: IsoTimestamp.pipe(optional),
  finishedAt: IsoTimestamp.pipe(optional),
  resultEvidenceIds: Schema.Array(NonEmptyId),
  error: Schema.Struct({
    code: Schema.String.check(Schema.isMinLength(1)),
    message: Schema.String.check(Schema.isMinLength(1)),
    retryable: Schema.Boolean,
  }).pipe(optional),
}).annotate({ identifier: "CyberLab.ExecutionRecord" })

export interface ExecutionController {
  submit(request: ExecutionRequest): Promise<ExecutionRecord>
  get(executionId: string): Promise<ExecutionRecord | undefined>
  cancel(executionId: string, reason: string): Promise<void>
}

export interface ExecutorContext {
  executionId: string
  projectId: string
  signal: AbortSignal

  workspaceRoot: string
  environmentId?: string

  emitEvidence(evidence: EvidenceDraft): Promise<string>
  log(level: "debug" | "info" | "warn" | "error", message: string): Promise<void>
}

export interface ExecutorInput {
  capabilityId: string
  input: unknown
}

export interface ExecutorResult {
  status: "succeeded" | "failed" | "cancelled"
  evidenceIds: string[]
  summary: string
  exitCode?: number
}

export const ExecutorResultSchema = Schema.Struct({
  status: Schema.Literals(["succeeded", "failed", "cancelled"]),
  evidenceIds: Schema.Array(NonEmptyId),
  summary: Schema.String,
  exitCode: Schema.Int.pipe(optional),
}).annotate({ identifier: "CyberLab.ExecutorResult" })

export interface CyberLabExecutor {
  readonly id: string
  readonly version: string

  checkAvailability(): Promise<{
    available: boolean
    version?: string
    reason?: string
  }>

  validate(input: unknown): Promise<{
    valid: boolean
    errors: string[]
  }>

  execute(input: ExecutorInput, context: ExecutorContext): Promise<ExecutorResult>
}

export function validateExecutionRequest(input: unknown): ExecutionRequest {
  return Schema.decodeUnknownSync(ExecutionRequestSchema)(input)
}

export function validateExecutionRecord(input: unknown): ExecutionRecord {
  const { policyDecision, ...decoded } = Schema.decodeUnknownSync(ExecutionRecordSchema)(input)
  return {
    ...decoded,
    ...(policyDecision !== undefined
      ? {
          policyDecision: {
            ...policyDecision,
            policyIds: [...policyDecision.policyIds],
          },
        }
      : {}),
    resultEvidenceIds: [...decoded.resultEvidenceIds],
  }
}
