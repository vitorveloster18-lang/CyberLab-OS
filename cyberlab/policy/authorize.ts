import type { CapabilityDefinition, CapabilityRegistry } from "../contracts/capability.js"
import type { ExecutionRequest } from "../contracts/execution.js"
import type { PolicyAuditEntry, PolicyDecision, PolicyEffect, PolicyRule } from "../contracts/policy.js"
import { ApprovalManager } from "./approval.js"
import { ScopeController, extractTargetsFromInput } from "./scope.js"

function matchesWildcardPattern(value: string, pattern: string): boolean {
  if (pattern === "*") return true
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")
  return new RegExp(`^${escaped}$`).test(value)
}

export function summarizeTargets(input: unknown): string {
  const extracted = extractTargetsFromInput(input)
  const parts = [...extracted.networkTargets, ...extracted.workspacePaths].sort()
  return parts.length > 0 ? parts.join(",") : "(workspace-default)"
}

export interface PolicyAuthorizeContext {
  executionId: string
  request: ExecutionRequest
  phase: "submission" | "execution"
  approvalId?: string
  now?: Date
}

export class PolicyEngine {
  private readonly rules: PolicyRule[] = []
  private readonly auditLog: PolicyAuditEntry[] = []

  constructor(
    private readonly capabilities: CapabilityRegistry,
    private readonly scopes: ScopeController,
    private readonly approvals: ApprovalManager,
  ) {}

  addRule(rule: PolicyRule): void {
    this.rules.push({ ...rule })
  }

  getAuditLog(projectId?: string): PolicyAuditEntry[] {
    return this.auditLog
      .filter((entry) => !projectId || entry.projectId === projectId)
      .map((entry) => ({
        ...entry,
        actor: { ...entry.actor },
        policyIds: [...entry.policyIds],
      }))
  }

  async evaluate(ctx: PolicyAuthorizeContext): Promise<PolicyDecision> {
    const now = ctx.now ?? new Date()
    const targetSummary = summarizeTargets(ctx.request.input)

    const recordDecision = (decision: PolicyEffect, policyIds: string[], reason: string): PolicyDecision => {
      const result: PolicyDecision = {
        decision,
        policyIds,
        reason,
        evaluatedAt: now.toISOString(),
        phase: ctx.phase,
      }
      this.auditLog.push({
        auditId: `pol-audit-${crypto.randomUUID()}`,
        executionId: ctx.executionId,
        projectId: ctx.request.projectId,
        capabilityId: ctx.request.capabilityId,
        actor: { ...ctx.request.requestedBy },
        target: targetSummary,
        phase: ctx.phase,
        decision,
        policyIds: [...policyIds],
        reason,
        timestamp: now.toISOString(),
      })
      return result
    }

    // 1. Capability existence and enabled check
    const capability = await this.capabilities.get(ctx.request.capabilityId)
    if (!capability) {
      return recordDecision(
        "deny",
        ["builtin.capability-exists"],
        `Capability "${ctx.request.capabilityId}" is not registered`,
      )
    }
    if (!capability.enabled) {
      return recordDecision(
        "deny",
        ["builtin.capability-enabled"],
        `Capability "${capability.id}" is currently disabled`,
      )
    }

    // 2. Execution mode check
    if (!capability.supportedModes.includes(ctx.request.mode)) {
      return recordDecision(
        "deny",
        ["builtin.supported-mode"],
        `Execution mode "${ctx.request.mode}" is not supported by capability "${capability.id}"`,
      )
    }

    // 3. Scope verification (runs BOTH at submission and immediately before execution!)
    const extractedTargets = extractTargetsFromInput(ctx.request.input)
    const scopeCheck = this.scopes.verifyTargets(
      ctx.request.projectId,
      extractedTargets,
      capability.requiredScope,
    )
    if (!scopeCheck.allowed) {
      return recordDecision("deny", ["builtin.project-scope"], scopeCheck.reason)
    }

    // 4. Custom policy rules (last matching rule wins; explicit deny cannot be overridden by default matrix)
    const matchingRules = this.rules.filter((rule) => {
      if (!matchesWildcardPattern(capability.id, rule.capabilityPattern)) return false
      if (rule.actorTypes && !rule.actorTypes.includes(ctx.request.requestedBy.type)) return false
      if (rule.risks && !rule.risks.includes(capability.risk)) return false
      if (rule.modes && !rule.modes.includes(ctx.request.mode)) return false
      return true
    })

    const lastCustomRule = matchingRules.at(-1)
    if (lastCustomRule?.effect === "deny") {
      return recordDecision("deny", [lastCustomRule.id], `Denied by policy rule "${lastCustomRule.id}": ${lastCustomRule.description}`)
    }

    // 5. Built-in risk & actor baseline matrix
    let baseDecision = this.computeBaselineDecision(capability, ctx.request)
    const policyIds = [...matchingRules.map((r) => r.id), `builtin.risk.${capability.risk}`]

    if (lastCustomRule) {
      // Custom rule can tighten allow -> ask, or explicitly allow non-destructive operations
      if (lastCustomRule.effect === "ask" && baseDecision.effect === "allow") {
        baseDecision = { effect: "ask", reason: `Approval required by rule "${lastCustomRule.id}"` }
      } else if (lastCustomRule.effect === "allow" && capability.risk !== "destructive") {
        baseDecision = { effect: "allow", reason: `Allowed by rule "${lastCustomRule.id}"` }
      }
    }

    if (baseDecision.effect === "deny") {
      return recordDecision("deny", policyIds, baseDecision.reason)
    }

    // 6. Handle approval ticket verification when baseDecision === "ask"
    if (baseDecision.effect === "ask") {
      if (ctx.approvalId) {
        const verification = this.approvals.verifyAndConsumeForExecution(
          {
            approvalId: ctx.approvalId,
            executionId: ctx.executionId,
            projectId: ctx.request.projectId,
            capabilityId: capability.id,
            targetSummary,
          },
          now,
        )
        if (!verification.valid) {
          return recordDecision("deny", [...policyIds, "builtin.approval-verification"], verification.reason)
        }
        return recordDecision("allow", [...policyIds, "builtin.approval-verified"], verification.reason)
      }

      if (ctx.phase === "execution") {
        return recordDecision(
          "deny",
          [...policyIds, "builtin.unapproved-execution"],
          `Execution phase reached without verified ApprovalTicket: ${baseDecision.reason}`,
        )
      }

      return recordDecision("ask", policyIds, baseDecision.reason)
    }

    return recordDecision("allow", policyIds, baseDecision.reason)
  }

  private computeBaselineDecision(
    capability: CapabilityDefinition,
    request: ExecutionRequest,
  ): { effect: PolicyEffect; reason: string } {
    const actor = request.requestedBy.type
    const risk = capability.risk
    const mode = request.mode

    // Proposed mode always pauses for human confirmation regardless of actor
    if (mode === "proposed") {
      return { effect: "ask", reason: "Execution requested in 'proposed' mode requires explicit operator approval" }
    }

    // Partner safety boundary: partners can NEVER trigger high/destructive or silent tool execution
    if (actor === "partner") {
      if (risk === "high" || risk === "destructive") {
        return {
          effect: "deny",
          reason: `Partner "${request.requestedBy.id}" is prohibited from requesting "${risk}" risk capabilities`,
        }
      }
      return {
        effect: "ask",
        reason: `Partner-originated capability "${capability.id}" requires explicit human approval`,
      }
    }

    // Assistant safety boundary
    if (actor === "assistant") {
      if (risk === "destructive") {
        return {
          effect: "deny",
          reason: "AI assistant cannot execute destructive capabilities",
        }
      }
      if (risk === "high" || risk === "moderate") {
        return {
          effect: "ask",
          reason: `Assistant request for "${risk}" risk capability "${capability.id}" requires human approval`,
        }
      }
      if (risk === "low") {
        if (mode === "approved" || mode === "lab_automation") {
          return { effect: "allow", reason: "Low-risk capability permitted within scoped lab session" }
        }
        return { effect: "ask", reason: "Low-risk assistant request in manual mode requires confirmation" }
      }
      return { effect: "allow", reason: "Read-only capability permitted within authorized scope" }
    }

    // Local human operator ("user")
    if (risk === "destructive" || risk === "high") {
      return {
        effect: "ask",
        reason: `High/destructive capability "${capability.id}" requires explicit confirmation ticket`,
      }
    }
    return { effect: "allow", reason: `User-initiated "${risk}" capability permitted within active scope` }
  }
}
