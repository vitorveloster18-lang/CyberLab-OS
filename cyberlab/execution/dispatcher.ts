import type { CapabilityRegistry } from "../contracts/capability.js"
import {
  validateExecutionRequest,
  type CyberLabExecutor,
  type ExecutionController,
  type ExecutionRecord,
  type ExecutionRequest,
  type ExecutorContext,
} from "../contracts/execution.js"
import type { EvidenceStore } from "../evidence/store.js"
import type { ApprovalManager } from "../policy/approval.js"
import { PolicyEngine, summarizeTargets } from "../policy/authorize.js"
import type { ScopeController } from "../policy/scope.js"
import type { InputOutputSchemaRegistry } from "../registry/capabilities.js"
import type { ExecutorRegistry } from "../registry/tools.js"
import { ManagedExecutionAbort, capOutputBytes } from "./cancellation.js"
import { isTerminalExecutionStatus, transitionExecutionRecord } from "./lifecycle.js"

export interface DispatcherOptions {
  capabilities: CapabilityRegistry
  schemas: InputOutputSchemaRegistry
  executors: ExecutorRegistry
  scopes: ScopeController
  approvals: ApprovalManager
  policy: PolicyEngine
  evidenceStore: EvidenceStore
  defaultTimeoutMs?: number
  maxOutputBytes?: number
}

export interface ExecutionLogEntry {
  executionId: string
  level: "debug" | "info" | "warn" | "error"
  message: string
  timestamp: string
}

export class CyberLabExecutionDispatcher implements ExecutionController {
  private readonly records = new Map<string, ExecutionRecord>()
  private readonly idempotencyIndex = new Map<string, string>()
  private readonly activeAborts = new Map<string, ManagedExecutionAbort>()
  private readonly logs = new Map<string, ExecutionLogEntry[]>()
  private readonly defaultTimeoutMs: number
  private readonly maxOutputBytes: number

  constructor(private readonly deps: DispatcherOptions) {
    this.defaultTimeoutMs = deps.defaultTimeoutMs ?? 30_000
    this.maxOutputBytes = deps.maxOutputBytes ?? 1024 * 1024
  }

  async get(executionId: string): Promise<ExecutionRecord | undefined> {
    const rec = this.records.get(executionId)
    return rec ? structuredClone(rec) : undefined
  }

  list(projectId?: string): ExecutionRecord[] {
    return Array.from(this.records.values())
      .filter((r) => !projectId || r.request.projectId === projectId)
      .map((r) => structuredClone(r))
  }

  getLogs(executionId: string): ExecutionLogEntry[] {
    return [...(this.logs.get(executionId) ?? [])]
  }

  async cancel(executionId: string, reason: string): Promise<void> {
    const current = this.records.get(executionId)
    if (!current || isTerminalExecutionStatus(current.status)) {
      return
    }
    const active = this.activeAborts.get(executionId)
    if (active) {
      active.cancel(reason)
      return
    }
    const cancelled = transitionExecutionRecord(current, "cancelled", {
      finishedAt: new Date().toISOString(),
      error: {
        code: "EXECUTION_CANCELLED",
        message: reason,
        retryable: false,
      },
    })
    this.records.set(executionId, cancelled)
  }

  async submit(request: ExecutionRequest, options?: { timeoutMs?: number; parentSignal?: AbortSignal }): Promise<ExecutionRecord> {
    const validatedRequest = validateExecutionRequest(request)

    if (validatedRequest.idempotencyKey) {
      const idemKey = `${validatedRequest.projectId}:${validatedRequest.idempotencyKey}`
      const existingId = this.idempotencyIndex.get(idemKey)
      if (existingId) {
        const existing = this.records.get(existingId)
        if (existing) return structuredClone(existing)
      }
    }

    const executionId = `exec-${crypto.randomUUID()}`
    if (validatedRequest.idempotencyKey) {
      this.idempotencyIndex.set(`${validatedRequest.projectId}:${validatedRequest.idempotencyKey}`, executionId)
    }

    let record: ExecutionRecord = {
      executionId,
      request: validatedRequest,
      status: "draft",
      resultEvidenceIds: [],
    }
    this.records.set(executionId, record)

    // 1. Lookup capability & validate unknown input against formal schema BEFORE policy/executor!
    const capability = await this.deps.capabilities.get(validatedRequest.capabilityId)
    if (!capability) {
      record = transitionExecutionRecord(record, "blocked", {
        finishedAt: new Date().toISOString(),
        policyDecision: {
          decision: "deny",
          policyIds: ["builtin.capability-exists"],
          reason: `Capability "${validatedRequest.capabilityId}" is not registered`,
        },
        error: {
          code: "CAPABILITY_NOT_FOUND",
          message: `Capability "${validatedRequest.capabilityId}" is not registered`,
          retryable: false,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    let validatedInput: unknown
    try {
      validatedInput = this.deps.schemas.validate(capability.inputSchemaId, validatedRequest.input)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      record = transitionExecutionRecord(record, "blocked", {
        finishedAt: new Date().toISOString(),
        error: {
          code: "INVALID_CAPABILITY_INPUT",
          message: `Input failed schema "${capability.inputSchemaId}": ${message}`,
          retryable: false,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    record = {
      ...record,
      request: { ...validatedRequest, input: validatedInput },
    }
    this.records.set(executionId, record)

    // 2. Submission-phase policy check
    const submissionDecision = await this.deps.policy.evaluate({
      executionId,
      request: record.request,
      phase: "submission",
    })

    if (submissionDecision.decision === "deny") {
      record = transitionExecutionRecord(record, "blocked", {
        finishedAt: new Date().toISOString(),
        policyDecision: {
          decision: "deny",
          policyIds: submissionDecision.policyIds,
          reason: submissionDecision.reason,
        },
        error: {
          code: "POLICY_DENIED",
          message: submissionDecision.reason,
          retryable: false,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    if (submissionDecision.decision === "ask") {
      this.deps.approvals.createTicket({
        executionId,
        projectId: record.request.projectId,
        capabilityId: capability.id,
        requestedBy: record.request.requestedBy,
        targetSummary: summarizeTargets(validatedInput),
      })
      record = transitionExecutionRecord(record, "awaiting_approval", {
        policyDecision: {
          decision: "ask",
          policyIds: submissionDecision.policyIds,
          reason: submissionDecision.reason,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    record = transitionExecutionRecord(record, "queued", {
      policyDecision: {
        decision: "allow",
        policyIds: submissionDecision.policyIds,
        reason: submissionDecision.reason,
      },
    })
    this.records.set(executionId, record)

    return this.executeQueued(executionId, undefined, options)
  }

  async approveAndRun(
    executionId: string,
    approvalId: string,
    options?: { timeoutMs?: number; parentSignal?: AbortSignal },
  ): Promise<ExecutionRecord> {
    const current = this.records.get(executionId)
    if (!current) {
      throw new Error(`Execution "${executionId}" not found`)
    }
    if (current.status !== "awaiting_approval") {
      throw new Error(`Execution "${executionId}" is in status "${current.status}", expected "awaiting_approval"`)
    }
    const queued = transitionExecutionRecord(current, "queued")
    this.records.set(executionId, queued)
    return this.executeQueued(executionId, approvalId, options)
  }

  private async executeQueued(
    executionId: string,
    approvalId?: string,
    options?: { timeoutMs?: number; parentSignal?: AbortSignal },
  ): Promise<ExecutionRecord> {
    let record = this.records.get(executionId)!

    // Mandatory Phase-2 re-authorization right before invoking executor!
    const execDecision = await this.deps.policy.evaluate({
      executionId,
      request: record.request,
      phase: "execution",
      ...(approvalId !== undefined ? { approvalId } : {}),
    })

    if (execDecision.decision !== "allow") {
      record = transitionExecutionRecord(record, "blocked", {
        finishedAt: new Date().toISOString(),
        policyDecision: {
          decision: execDecision.decision,
          policyIds: execDecision.policyIds,
          reason: execDecision.reason,
        },
        error: {
          code: "EXECUTION_REAUTH_BLOCKED",
          message: execDecision.reason,
          retryable: false,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    const capability = (await this.deps.capabilities.get(record.request.capabilityId))!
    const executor: CyberLabExecutor | undefined = this.deps.executors.getExecutor(capability.executorId)
    if (!executor) {
      record = transitionExecutionRecord(record, "failed", {
        finishedAt: new Date().toISOString(),
        error: {
          code: "EXECUTOR_NOT_FOUND",
          message: `Executor "${capability.executorId}" is not registered`,
          retryable: false,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    const availability = await executor.checkAvailability()
    if (!availability.available) {
      record = transitionExecutionRecord(record, "failed", {
        finishedAt: new Date().toISOString(),
        error: {
          code: "EXECUTOR_UNAVAILABLE",
          message: availability.reason ?? `Executor "${executor.id}" is unavailable`,
          retryable: true,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    const validation = await executor.validate(record.request.input)
    if (!validation.valid) {
      record = transitionExecutionRecord(record, "failed", {
        finishedAt: new Date().toISOString(),
        error: {
          code: "EXECUTOR_INPUT_REJECTED",
          message: validation.errors.join("; "),
          retryable: false,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    const scope = this.deps.scopes.getProjectScope(record.request.projectId)
    if (!scope) {
      record = transitionExecutionRecord(record, "blocked", {
        finishedAt: new Date().toISOString(),
        error: {
          code: "MISSING_SCOPE",
          message: "ProjectScope missing at execution start",
          retryable: false,
        },
      })
      this.records.set(executionId, record)
      return structuredClone(record)
    }

    const timeoutMs = options?.timeoutMs ?? this.defaultTimeoutMs
    const managedAbort = new ManagedExecutionAbort(timeoutMs, options?.parentSignal)
    this.activeAborts.set(executionId, managedAbort)

    const emittedEvidenceIds: string[] = []
    const executionLogs: ExecutionLogEntry[] = []
    this.logs.set(executionId, executionLogs)

    record = transitionExecutionRecord(record, "running", {
      startedAt: new Date().toISOString(),
      policyDecision: {
        decision: "allow",
        policyIds: execDecision.policyIds,
        reason: execDecision.reason,
      },
    })
    this.records.set(executionId, record)

    const context: ExecutorContext = {
      executionId,
      projectId: record.request.projectId,
      signal: managedAbort.signal,
      workspaceRoot: scope.workspaceRoot,
      emitEvidence: async (draft) => {
        const cappedInline =
          draft.content.inlineText !== undefined
            ? capOutputBytes(draft.content.inlineText, this.maxOutputBytes).text
            : undefined
        const stored = this.deps.evidenceStore.storeEvidence(
          record.request.projectId,
          {
            ...draft,
            source: {
              ...draft.source,
              executorId: executor.id,
              executionId,
            },
            content: {
              ...draft.content,
              ...(cappedInline !== undefined ? { inlineText: cappedInline } : {}),
            },
          },
          { actor: `executor:${executor.id}` },
        )
        emittedEvidenceIds.push(stored.evidenceId)
        return stored.evidenceId
      },
      log: async (level, message) => {
        executionLogs.push({
          executionId,
          level,
          message,
          timestamp: new Date().toISOString(),
        })
      },
    }

    try {
      const abortPromise = new Promise<never>((_, reject) => {
        if (managedAbort.signal.aborted) {
          reject(managedAbort.signal.reason ?? new Error("Execution aborted"))
          return
        }
        managedAbort.signal.addEventListener(
          "abort",
          () => reject(managedAbort.signal.reason ?? new Error("Execution aborted")),
          { once: true },
        )
      })

      const result = await Promise.race([
        executor.execute(
          {
            capabilityId: capability.id,
            input: record.request.input,
          },
          context,
        ),
        abortPromise,
      ])

      const allEvidenceIds = Array.from(new Set([...emittedEvidenceIds, ...result.evidenceIds]))

      if (managedAbort.signal.aborted) {
        const finalStatus = managedAbort.kind === "timed_out" ? "timed_out" : "cancelled"
        record = transitionExecutionRecord(record, finalStatus, {
          finishedAt: new Date().toISOString(),
          resultEvidenceIds: allEvidenceIds,
          error: {
            code: finalStatus === "timed_out" ? "EXECUTION_TIMED_OUT" : "EXECUTION_CANCELLED",
            message: managedAbort.reason ?? "Execution interrupted",
            retryable: finalStatus === "timed_out",
          },
        })
      } else if (result.status === "succeeded") {
        record = transitionExecutionRecord(record, "succeeded", {
          finishedAt: new Date().toISOString(),
          resultEvidenceIds: allEvidenceIds,
        })
      } else if (result.status === "cancelled") {
        record = transitionExecutionRecord(record, "cancelled", {
          finishedAt: new Date().toISOString(),
          resultEvidenceIds: allEvidenceIds,
          error: {
            code: "EXECUTOR_REPORTED_CANCELLED",
            message: result.summary || "Executor cancelled operation",
            retryable: false,
          },
        })
      } else {
        record = transitionExecutionRecord(record, "failed", {
          finishedAt: new Date().toISOString(),
          resultEvidenceIds: allEvidenceIds,
          error: {
            code: "EXECUTOR_FAILED",
            message: result.summary || "Executor reported failure",
            retryable: false,
          },
        })
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      if (managedAbort.signal.aborted) {
        const finalStatus = managedAbort.kind === "timed_out" ? "timed_out" : "cancelled"
        record = transitionExecutionRecord(record, finalStatus, {
          finishedAt: new Date().toISOString(),
          resultEvidenceIds: [...emittedEvidenceIds],
          error: {
            code: finalStatus === "timed_out" ? "EXECUTION_TIMED_OUT" : "EXECUTION_CANCELLED",
            message: managedAbort.reason ?? message,
            retryable: finalStatus === "timed_out",
          },
        })
      } else {
        record = transitionExecutionRecord(record, "failed", {
          finishedAt: new Date().toISOString(),
          resultEvidenceIds: [...emittedEvidenceIds],
          error: {
            code: "EXECUTOR_EXCEPTION",
            message,
            retryable: false,
          },
        })
      }
    } finally {
      managedAbort.dispose()
      this.activeAborts.delete(executionId)
      this.records.set(executionId, record)
    }

    return structuredClone(record)
  }
}
