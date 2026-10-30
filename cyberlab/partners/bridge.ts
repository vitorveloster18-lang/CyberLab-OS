import type { SecurityFinding } from "../contracts/evidence.js"
import type { ExecutionRecord } from "../contracts/execution.js"
import {
  DEFAULT_MAX_PARTNER_ENVELOPE_BYTES,
  PartnerApprovalRequestPayloadSchema,
  validatePartnerResult,
  validatePartnerTask,
  type PartnerEnvelope,
  type PartnerMessageType,
  type PartnerResult,
  type PartnerTask,
} from "../contracts/partner-protocol.js"
import type { EvidenceStore } from "../evidence/store.js"
import type { CyberLabExecutionDispatcher } from "../execution/dispatcher.js"
import { Schema } from "effect"
import { PartnerAuthenticator } from "./authentication.js"
import type { PartnerTransport } from "./transport.js"

export interface PartnerBridgeAuditEntry {
  auditId: string
  taskId: string
  projectId: string
  partnerId: string
  direction: "outbound" | "inbound"
  messageId: string
  correlationId: string
  type: PartnerMessageType
  outcome: "accepted" | "rejected" | "queued_for_approval"
  reason?: string
  timestamp: string
}

export interface PartnerDispatchOutcome {
  taskId: string
  correlationId: string
  partnerId: string
  result?: PartnerResult
  storedEvidenceId?: string
  createdFindings: SecurityFinding[]
  proposedExecutions: ExecutionRecord[]
  ignoredUnverifiedRefs: string[]
}

interface ActiveTaskState {
  task: PartnerTask
  partnerId: string
  correlationId: string
  abortController: AbortController
  authorizedEvidenceIds: Set<string>
}

export interface PartnerBridgeOptions {
  cyberlabNodeId?: string
  authenticator: PartnerAuthenticator
  evidenceStore: EvidenceStore
  dispatcher: CyberLabExecutionDispatcher
  maxEnvelopeBytes?: number
  defaultTimeoutMs?: number
}

export class PartnerBridge {
  private readonly transports = new Map<string, PartnerTransport>()
  private readonly activeTasks = new Map<string, ActiveTaskState>()
  private readonly auditTrail: PartnerBridgeAuditEntry[] = []
  private readonly nodeId: string
  private readonly maxEnvelopeBytes: number
  private readonly defaultTimeoutMs: number

  constructor(private readonly opts: PartnerBridgeOptions) {
    this.nodeId = opts.cyberlabNodeId ?? "cyberlab-core"
    this.maxEnvelopeBytes = opts.maxEnvelopeBytes ?? DEFAULT_MAX_PARTNER_ENVELOPE_BYTES
    this.defaultTimeoutMs = opts.defaultTimeoutMs ?? 30_000
  }

  registerTransport(partnerId: string, transport: PartnerTransport): void {
    this.transports.set(partnerId, transport)
  }

  getAuditTrail(projectId?: string): PartnerBridgeAuditEntry[] {
    return this.auditTrail
      .filter((e) => !projectId || e.projectId === projectId)
      .map((e) => ({ ...e }))
  }

  async submitTask(
    partnerId: string,
    rawTask: PartnerTask,
    options?: { timeoutMs?: number },
  ): Promise<PartnerDispatchOutcome> {
    const profile = this.opts.authenticator.getPublicProfile(partnerId)
    if (!profile || !profile.enabled) {
      throw new Error(`Partner "${partnerId}" is not registered or is disabled`)
    }
    const transport = this.transports.get(partnerId)
    if (!transport) {
      throw new Error(`No PartnerTransport registered for partner "${partnerId}"`)
    }

    const validatedTask = validatePartnerTask(rawTask)

    // Verify requested allowedActions are permitted for this partner profile
    for (const action of validatedTask.allowedActions) {
      if (profile.prohibitedActions.includes(action) || !profile.allowedActions.includes(action)) {
        throw new Error(`Action "${action}" is not authorized for partner "${partnerId}"`)
      }
    }

    // Build minimum redacted contextBundle — NEVER leak raw unredacted credentials or full session history
    const redactedSnippets: string[] = []
    const authorizedEvidenceIds = new Set<string>()
    for (const evId of validatedTask.contextBundle.evidenceIds) {
      const ev = this.opts.evidenceStore.getEvidence(evId)
      if (!ev || ev.projectId !== validatedTask.projectId) {
        throw new Error(`Evidence "${evId}" not found in project "${validatedTask.projectId}"`)
      }
      const shared = this.opts.evidenceStore.readRedactedForSharing(evId, `partner:${partnerId}`)
      authorizedEvidenceIds.add(evId)
      redactedSnippets.push(`--- Evidence ${evId} (sha256: ${shared.sha256}) ---\n${shared.text}`)
    }

    const sanitizedTask: PartnerTask = {
      ...validatedTask,
      contextBundle: {
        evidenceIds: [...authorizedEvidenceIds],
        ...(redactedSnippets.length > 0 || validatedTask.contextBundle.text
          ? {
              text: [validatedTask.contextBundle.text, ...redactedSnippets].filter(Boolean).join("\n\n"),
            }
          : {}),
      },
      prohibitedActions: Array.from(
        new Set([...validatedTask.prohibitedActions, ...profile.prohibitedActions, "shell.arbitrary", "capability.register"]),
      ),
    }

    const correlationId = `corr-${crypto.randomUUID()}`
    const outboundEnvelope: PartnerEnvelope<PartnerTask> = {
      protocol: "cyberlab-partner",
      protocolVersion: "1.0",
      messageId: `msg-${crypto.randomUUID()}`,
      correlationId,
      sentAt: new Date().toISOString(),
      sender: { id: this.nodeId, type: "cyberlab" },
      recipient: { id: partnerId },
      type: "task.submit",
      payload: sanitizedTask,
    }

    const signedOutbound = this.opts.authenticator.signOutbound(partnerId, outboundEnvelope)
    const abortController = new AbortController()
    const state: ActiveTaskState = {
      task: sanitizedTask,
      partnerId,
      correlationId,
      abortController,
      authorizedEvidenceIds,
    }
    this.activeTasks.set(sanitizedTask.taskId, state)

    this.recordAudit({
      taskId: sanitizedTask.taskId,
      projectId: sanitizedTask.projectId,
      partnerId,
      direction: "outbound",
      messageId: outboundEnvelope.messageId,
      correlationId,
      type: "task.submit",
      outcome: "accepted",
    })

    try {
      const inboundMessages = await transport.send(signedOutbound, {
        signal: abortController.signal,
        timeoutMs: options?.timeoutMs ?? this.defaultTimeoutMs,
      })

      return await this.processInboundResponses(state, inboundMessages)
    } finally {
      this.activeTasks.delete(sanitizedTask.taskId)
    }
  }

  async cancelTask(taskId: string, reason: string): Promise<boolean> {
    const active = this.activeTasks.get(taskId)
    if (!active) return false

    active.abortController.abort(new Error(reason))
    const transport = this.transports.get(active.partnerId)
    if (transport) {
      const cancelEnv: PartnerEnvelope<{ taskId: string; reason: string }> = {
        protocol: "cyberlab-partner",
        protocolVersion: "1.0",
        messageId: `msg-${crypto.randomUUID()}`,
        correlationId: active.correlationId,
        sentAt: new Date().toISOString(),
        sender: { id: this.nodeId, type: "cyberlab" },
        recipient: { id: active.partnerId },
        type: "task.cancel",
        payload: { taskId, reason },
      }
      const signed = this.opts.authenticator.signOutbound(active.partnerId, cancelEnv)
      this.recordAudit({
        taskId,
        projectId: active.task.projectId,
        partnerId: active.partnerId,
        direction: "outbound",
        messageId: cancelEnv.messageId,
        correlationId: active.correlationId,
        type: "task.cancel",
        outcome: "accepted",
        reason,
      })
      const ctrl = new AbortController()
      await transport.send(signed, { signal: ctrl.signal, timeoutMs: 2_000 }).catch(() => undefined)
    }
    this.activeTasks.delete(taskId)
    return true
  }

  /**
   * Processes untrusted inbound partner messages with strict authentication, correlation check,
   * schema validation, and prohibition of direct command execution.
   */
  private async processInboundResponses(
    state: ActiveTaskState,
    rawMessages: unknown[],
  ): Promise<PartnerDispatchOutcome> {
    const createdFindings: SecurityFinding[] = []
    const proposedExecutions: ExecutionRecord[] = []
    const ignoredUnverifiedRefs: string[] = []
    let finalResult: PartnerResult | undefined
    let storedEvidenceId: string | undefined

    for (const rawMsg of rawMessages) {
      const verified = this.opts.authenticator.verifyInbound(rawMsg, {
        maxEnvelopeBytes: this.maxEnvelopeBytes,
      })

      if (verified.sender.id !== state.partnerId) {
        this.recordAudit({
          taskId: state.task.taskId,
          projectId: state.task.projectId,
          partnerId: verified.sender.id,
          direction: "inbound",
          messageId: verified.messageId,
          correlationId: verified.correlationId,
          type: verified.type,
          outcome: "rejected",
          reason: `Expected sender "${state.partnerId}", got "${verified.sender.id}"`,
        })
        throw new Error(`Partner sender mismatch: expected "${state.partnerId}", got "${verified.sender.id}"`)
      }

      if (verified.correlationId !== state.correlationId) {
        this.recordAudit({
          taskId: state.task.taskId,
          projectId: state.task.projectId,
          partnerId: state.partnerId,
          direction: "inbound",
          messageId: verified.messageId,
          correlationId: verified.correlationId,
          type: verified.type,
          outcome: "rejected",
          reason: "Correlation ID mismatch",
        })
        throw new Error(`Correlation ID mismatch on message "${verified.messageId}"`)
      }

      if (verified.type === "task.result") {
        const result = validatePartnerResult(verified.payload)
        if (result.taskId !== state.task.taskId) {
          throw new Error(`PartnerResult taskId "${result.taskId}" does not match "${state.task.taskId}"`)
        }

        // Persist the raw untrusted partner analysis as an external_reference EvidenceRecord
        const partnerEvidence = this.opts.evidenceStore.storeEvidence(
          state.task.projectId,
          {
            kind: "external_reference",
            title: `Partner "${state.partnerId}" analysis for task ${state.task.taskId}`,
            source: {
              toolId: `partner:${state.partnerId}`,
              executorId: "partner-bridge",
              executionId: `partner-task-${state.task.taskId}`,
            },
            content: {
              mediaType: "application/json",
              inlineText: JSON.stringify(result, null, 2),
            },
            observedAt: verified.sentAt,
            labels: ["partner_response", "untrusted_external"],
          },
          {
            parentEvidenceIds: [...state.authorizedEvidenceIds],
            derivedBy: `partner:${state.partnerId}`,
            actor: `partner-bridge:${state.partnerId}`,
          },
        )
        storedEvidenceId = partnerEvidence.evidenceId

        // Convert partner findings into strictly "unreviewed" SecurityFindings (never auto-confirmed!)
        for (const item of result.findings) {
          const validRefs: string[] = []
          for (const ref of item.evidenceRefs) {
            if (state.authorizedEvidenceIds.has(ref)) {
              validRefs.push(ref)
            } else {
              ignoredUnverifiedRefs.push(ref)
            }
          }
          const linkedEvidence = Array.from(new Set([...validRefs, partnerEvidence.evidenceId]))
          const created = this.opts.evidenceStore.createFinding({
            projectId: state.task.projectId,
            title: `[Partner:${state.partnerId}] ${item.title}`,
            description: `${item.description}\n\nLimitations: ${result.limitations.join("; ") || "None declared"}`,
            severity: "medium",
            status: "unreviewed",
            ...(item.confidence !== undefined ? { confidence: Math.min(item.confidence, 0.85) } : {}),
            evidenceIds: linkedEvidence,
            affectedAssets: [],
            createdBy: `partner:${state.partnerId}`,
          })
          createdFindings.push(created)
        }

        finalResult = result
        this.recordAudit({
          taskId: state.task.taskId,
          projectId: state.task.projectId,
          partnerId: state.partnerId,
          direction: "inbound",
          messageId: verified.messageId,
          correlationId: verified.correlationId,
          type: verified.type,
          outcome: "accepted",
        })
      } else if (verified.type === "approval.request") {
        // Partner requests an additional capability check: NEVER execute directly!
        // Route through CyberLabExecutionDispatcher as a "partner" actor in "proposed" mode,
        // which either blocks (if prohibited/out-of-scope/high-risk) or places in "awaiting_approval".
        const approvalReq = Schema.decodeUnknownSync(PartnerApprovalRequestPayloadSchema)(verified.payload)
        const execRecord = await this.opts.dispatcher.submit({
          requestId: `partner-req-${verified.messageId}`,
          projectId: state.task.projectId,
          capabilityId: approvalReq.capabilityId,
          requestedBy: { type: "partner", id: state.partnerId },
          input: approvalReq.proposedInput,
          mode: "proposed",
        })
        proposedExecutions.push(execRecord)

        this.recordAudit({
          taskId: state.task.taskId,
          projectId: state.task.projectId,
          partnerId: state.partnerId,
          direction: "inbound",
          messageId: verified.messageId,
          correlationId: verified.correlationId,
          type: verified.type,
          outcome: execRecord.status === "blocked" ? "rejected" : "queued_for_approval",
          reason: execRecord.policyDecision?.reason ?? execRecord.error?.message,
        })
      } else {
        this.recordAudit({
          taskId: state.task.taskId,
          projectId: state.task.projectId,
          partnerId: state.partnerId,
          direction: "inbound",
          messageId: verified.messageId,
          correlationId: verified.correlationId,
          type: verified.type,
          outcome: "accepted",
        })
      }
    }

    return {
      taskId: state.task.taskId,
      correlationId: state.correlationId,
      partnerId: state.partnerId,
      ...(finalResult !== undefined ? { result: finalResult } : {}),
      ...(storedEvidenceId !== undefined ? { storedEvidenceId } : {}),
      createdFindings,
      proposedExecutions,
      ignoredUnverifiedRefs,
    }
  }

  private recordAudit(entry: Omit<PartnerBridgeAuditEntry, "auditId" | "timestamp">): void {
    this.auditTrail.push({
      ...entry,
      auditId: `pba-${crypto.randomUUID()}`,
      timestamp: new Date().toISOString(),
    })
  }
}
