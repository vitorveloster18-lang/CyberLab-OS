import type { ApprovalTicket } from "../contracts/policy.js"

export interface CreateApprovalInput {
  executionId: string
  projectId: string
  capabilityId: string
  requestedBy: {
    type: "user" | "assistant" | "partner"
    id: string
  }
  targetSummary: string
  ttlMs?: number
}

const DEFAULT_APPROVAL_TTL_MS = 15 * 60 * 1000 // 15 minutes

export class ApprovalManager {
  private readonly tickets = new Map<string, ApprovalTicket>()

  createTicket(input: CreateApprovalInput, now: Date = new Date()): ApprovalTicket {
    const ttl = input.ttlMs ?? DEFAULT_APPROVAL_TTL_MS
    const ticket: ApprovalTicket = {
      approvalId: `appr-${crypto.randomUUID()}`,
      executionId: input.executionId,
      projectId: input.projectId,
      capabilityId: input.capabilityId,
      requestedBy: { ...input.requestedBy },
      targetSummary: input.targetSummary,
      status: "pending",
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttl).toISOString(),
    }
    this.tickets.set(ticket.approvalId, ticket)
    return { ...ticket }
  }

  getTicket(approvalId: string): ApprovalTicket | undefined {
    const found = this.tickets.get(approvalId)
    return found ? { ...found, requestedBy: { ...found.requestedBy } } : undefined
  }

  findForExecution(executionId: string): ApprovalTicket | undefined {
    for (const ticket of this.tickets.values()) {
      if (ticket.executionId === executionId) {
        return { ...ticket, requestedBy: { ...ticket.requestedBy } }
      }
    }
    return undefined
  }

  listPending(projectId?: string): ApprovalTicket[] {
    return Array.from(this.tickets.values())
      .filter((t) => t.status === "pending" && (!projectId || t.projectId === projectId))
      .map((t) => ({ ...t, requestedBy: { ...t.requestedBy } }))
  }

  decide(
    approvalId: string,
    decision: "approved" | "rejected",
    decidedBy: string,
    reason?: string,
    now: Date = new Date(),
  ): ApprovalTicket {
    const ticket = this.tickets.get(approvalId)
    if (!ticket) {
      throw new Error(`ApprovalTicket "${approvalId}" not found`)
    }
    if (ticket.status !== "pending") {
      throw new Error(`ApprovalTicket "${approvalId}" is already in terminal/consumed status "${ticket.status}"`)
    }
    if (now.getTime() > Date.parse(ticket.expiresAt)) {
      ticket.status = "expired"
      throw new Error(`ApprovalTicket "${approvalId}" expired at ${ticket.expiresAt}`)
    }

    ticket.status = decision
    ticket.decidedBy = decidedBy
    ticket.decidedAt = now.toISOString()
    if (reason !== undefined) {
      ticket.reason = reason
    }
    return { ...ticket, requestedBy: { ...ticket.requestedBy } }
  }

  /**
   * Verifies and consumes an approved ticket for a specific execution, project, capability and target summary.
   */
  verifyAndConsumeForExecution(
    params: {
      approvalId: string
      executionId: string
      projectId: string
      capabilityId: string
      targetSummary: string
    },
    now: Date = new Date(),
  ): { valid: boolean; reason: string } {
    const ticket = this.tickets.get(params.approvalId)
    if (!ticket) {
      return { valid: false, reason: `ApprovalTicket "${params.approvalId}" does not exist` }
    }
    if (now.getTime() > Date.parse(ticket.expiresAt)) {
      ticket.status = "expired"
      return { valid: false, reason: `ApprovalTicket "${params.approvalId}" has expired` }
    }
    if (ticket.status !== "approved") {
      return { valid: false, reason: `ApprovalTicket "${params.approvalId}" has status "${ticket.status}", expected "approved"` }
    }
    if (
      ticket.executionId !== params.executionId ||
      ticket.projectId !== params.projectId ||
      ticket.capabilityId !== params.capabilityId ||
      ticket.targetSummary !== params.targetSummary
    ) {
      return {
        valid: false,
        reason: "ApprovalTicket binding mismatch (executionId, projectId, capabilityId, or targetSummary changed after approval)",
      }
    }

    ticket.status = "consumed"
    return { valid: true, reason: `Approved by ${ticket.decidedBy ?? "operator"}` }
  }
}
