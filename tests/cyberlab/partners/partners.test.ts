import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
  ApprovalManager,
  ControlledCapabilityRegistry,
  CyberLabExecutionDispatcher,
  EvidenceStore,
  ExecutorRegistry,
  InMemoryPartnerTransport,
  InputOutputSchemaRegistry,
  PartnerAuthError,
  PartnerAuthenticator,
  PartnerBridge,
  PolicyEngine,
  PromptChatPartnerTransport,
  ScopeController,
  computeEnvelopeHmac,
  type PartnerEnvelope,
  type PartnerTask,
} from "../../../cyberlab/index.js"
import {
  WORKSPACE_AUDIT_INPUT_SCHEMA_ID,
  WorkspaceAuditCapability,
  WorkspaceAuditExecutor,
  WorkspaceAuditInputSchema,
} from "../../../integrations/code-analysis/workspace-audit-executor.js"

const PARTNER_SECRET = "partner-hmac-secret-key-2026-very-strong"

function setupBridgeTestEnv(tmpDir: string) {
  const capabilities = new ControlledCapabilityRegistry()
  const schemas = new InputOutputSchemaRegistry()
  const executors = new ExecutorRegistry()
  const scopes = new ScopeController()
  const approvals = new ApprovalManager()
  const policy = new PolicyEngine(capabilities, scopes, approvals)
  const evidenceStore = new EvidenceStore({
    databasePath: path.join(tmpDir, "evidence.sqlite"),
    artifactsDir: path.join(tmpDir, "artifacts"),
  })

  scopes.setProjectScope({
    scopeId: "scope-partner",
    projectId: "proj-partner",
    name: "Partner Test Scope",
    workspaceRoot: tmpDir,
    allowedTargets: [{ kind: "ip", value: "127.0.0.1" }],
    blockedTargets: [],
    allowExternalTargets: false,
    active: true,
    updatedAt: "2026-10-26T00:00:00.000Z",
  })

  schemas.registerEffectSchema(WORKSPACE_AUDIT_INPUT_SCHEMA_ID, WorkspaceAuditInputSchema)
  executors.registerExecutor(new WorkspaceAuditExecutor())

  const dispatcher = new CyberLabExecutionDispatcher({
    capabilities,
    schemas,
    executors,
    scopes,
    approvals,
    policy,
    evidenceStore,
  })

  const authenticator = new PartnerAuthenticator()
  authenticator.registerPartner({
    partnerId: "ext-re-agent",
    displayName: "External Reverse & Web Analyst",
    sharedSecret: PARTNER_SECRET,
    allowedActions: ["analyze.evidence", "propose.check"],
    prohibitedActions: ["shell.exec"],
    enabled: true,
  })

  const bridge = new PartnerBridge({
    authenticator,
    evidenceStore,
    dispatcher,
  })

  return { capabilities, evidenceStore, dispatcher, authenticator, bridge }
}

describe("CyberLab Partner Bridge Protocol v1.0", () => {
  test("redacts sensitive credentials before dispatch, validates PartnerResult, strips fake evidenceRefs, and blocks direct partner command execution", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-partner-"))
    try {
      const { capabilities, evidenceStore, bridge } = setupBridgeTestEnv(tmpDir)
      await capabilities.register(WorkspaceAuditCapability)

      const rawEv = evidenceStore.storeEvidence("proj-partner", {
        kind: "http_exchange",
        title: "Captured login response",
        source: {
          toolId: "http-inspector",
          executorId: "http-headers-executor",
          executionId: "exec-900",
        },
        content: {
          mediaType: "text/plain",
          inlineText: "HTTP/1.1 200 OK\nAuthorization: Bearer topsecret_live_token\nServer: Werkzeug/2.0",
        },
        observedAt: "2026-10-26T16:00:00.000Z",
      })

      let receivedTaskText = ""
      bridge.registerTransport(
        "ext-re-agent",
        new InMemoryPartnerTransport(async (inbound) => {
          const payload = inbound.payload as PartnerTask
          receivedTaskText = payload.contextBundle.text ?? ""

          const resultEnv: PartnerEnvelope = {
            protocol: "cyberlab-partner",
            protocolVersion: "1.0",
            messageId: "p-msg-100",
            correlationId: inbound.correlationId,
            sentAt: new Date().toISOString(),
            sender: { id: "ext-re-agent", type: "partner" },
            recipient: { id: inbound.sender.id },
            type: "task.result",
            payload: {
              taskId: payload.taskId,
              status: "completed",
              summary: "Observed exposed Werkzeug server banner",
              findings: [
                {
                  title: "Verbose Server Header",
                  description: "Werkzeug version disclosed in HTTP Server header.",
                  evidenceRefs: [rawEv.evidenceId, "ev-forged-nonexistent"],
                  confidence: 0.8,
                },
              ],
              limitations: ["Passive header review only"],
              artifactRefs: [],
            },
          }

          // Partner ALSO attempts two approval.request messages: one valid workspace proposal, one out-of-scope path traversal!
          const validProposalEnv: PartnerEnvelope = {
            protocol: "cyberlab-partner",
            protocolVersion: "1.0",
            messageId: "p-msg-101",
            correlationId: inbound.correlationId,
            sentAt: new Date().toISOString(),
            sender: { id: "ext-re-agent", type: "partner" },
            recipient: { id: inbound.sender.id },
            type: "approval.request",
            payload: {
              taskId: payload.taskId,
              capabilityId: WorkspaceAuditCapability.id,
              rationale: "Check workspace config",
              proposedInput: { subpath: "." },
            },
          }

          const maliciousProposalEnv: PartnerEnvelope = {
            protocol: "cyberlab-partner",
            protocolVersion: "1.0",
            messageId: "p-msg-102",
            correlationId: inbound.correlationId,
            sentAt: new Date().toISOString(),
            sender: { id: "ext-re-agent", type: "partner" },
            recipient: { id: inbound.sender.id },
            type: "approval.request",
            payload: {
              taskId: payload.taskId,
              capabilityId: WorkspaceAuditCapability.id,
              rationale: "Read host /etc",
              proposedInput: { subpath: "../../../../etc" },
            },
          }

          return [resultEnv, validProposalEnv, maliciousProposalEnv].map((env) => ({
            ...env,
            signature: computeEnvelopeHmac(env, PARTNER_SECRET),
          }))
        }),
      )

      const outcome = await bridge.submitTask("ext-re-agent", {
        taskId: "ptask-01",
        projectId: "proj-partner",
        objective: "Analyze captured HTTP exchange",
        contextBundle: { evidenceIds: [rawEv.evidenceId] },
        allowedActions: ["analyze.evidence"],
        prohibitedActions: [],
        requestedOutput: {
          summary: true,
          findings: true,
          evidenceReferences: true,
          limitations: true,
        },
      })

      // 1. Partner NEVER received the raw Bearer token
      expect(receivedTaskText).toContain("[REDACTED:AUTH_TOKEN]")
      expect(receivedTaskText).not.toContain("topsecret_live_token")

      // 2. Forged evidence ID was stripped; finding created strictly as "unreviewed"
      expect(outcome.ignoredUnverifiedRefs).toEqual(["ev-forged-nonexistent"])
      expect(outcome.createdFindings).toHaveLength(1)
      expect(outcome.createdFindings[0]?.status).toBe("unreviewed")

      // 3. Partner approval requests NEVER ran automatically: valid one is awaiting_approval, malicious one is blocked!
      expect(outcome.proposedExecutions).toHaveLength(2)
      expect(outcome.proposedExecutions[0]?.status).toBe("awaiting_approval")
      expect(outcome.proposedExecutions[1]?.status).toBe("blocked")

      // 4. Audit log contains zero secrets
      const serializedAudit = JSON.stringify(bridge.getAuditTrail())
      expect(serializedAudit).not.toContain(PARTNER_SECRET)

      evidenceStore.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("rejects tampered HMAC signatures, replay attacks, skewed timestamps and supports PromptChatPartnerTransport", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-pauth-"))
    try {
      const { evidenceStore, authenticator, bridge } = setupBridgeTestEnv(tmpDir)

      const baseEnv: PartnerEnvelope = {
        protocol: "cyberlab-partner",
        protocolVersion: "1.0",
        messageId: "msg-replay-test",
        correlationId: "corr-replay-test",
        sentAt: new Date().toISOString(),
        sender: { id: "ext-re-agent", type: "partner" },
        recipient: { id: "cyberlab-core" },
        type: "task.accepted",
        payload: { accepted: true },
      }
      const validSigned = {
        ...baseEnv,
        signature: computeEnvelopeHmac(baseEnv, PARTNER_SECRET),
      }

      // First verification succeeds
      expect(authenticator.verifyInbound(validSigned).messageId).toBe("msg-replay-test")

      // Replay of exact same messageId -> REPLAY_DETECTED
      expect(() => authenticator.verifyInbound(validSigned)).toThrow(PartnerAuthError)

      // Tampered payload with old signature -> SIGNATURE_MISMATCH
      expect(() =>
        authenticator.verifyInbound({
          ...validSigned,
          messageId: "msg-tampered-2",
          payload: { accepted: false, injected: true },
        }),
      ).toThrow(/HMAC verification failed/)

      // Skewed timestamp (1 hour old) -> TIMESTAMP_OUT_OF_WINDOW
      const oldEnv: PartnerEnvelope = {
        ...baseEnv,
        messageId: "msg-old-ts",
        sentAt: new Date(Date.now() - 3600_000).toISOString(),
      }
      expect(() =>
        authenticator.verifyInbound({
          ...oldEnv,
          signature: computeEnvelopeHmac(oldEnv, PARTNER_SECRET),
        }),
      ).toThrow(/outside allowed clock skew/)

      // PromptChatPartnerTransport wraps chat-only partner and appends explicit reliability caveat
      authenticator.registerPartner({
        partnerId: "chat-only-bot",
        displayName: "Legacy Script Partner",
        sharedSecret: "chat-only-secret-key-987654321",
        allowedActions: ["analyze.evidence"],
        prohibitedActions: [],
        enabled: true,
      })
      bridge.registerTransport(
        "chat-only-bot",
        new PromptChatPartnerTransport(
          "chat-only-bot",
          "chat-only-secret-key-987654321",
          async () =>
            JSON.stringify({
              status: "completed",
              summary: "Prompt adapter review complete",
              findings: [],
              limitations: ["Heuristic model reply"],
              artifactRefs: [],
            }),
        ),
      )

      const chatOutcome = await bridge.submitTask("chat-only-bot", {
        taskId: "ptask-chat-1",
        projectId: "proj-partner",
        objective: "Summarize context",
        contextBundle: { evidenceIds: [] },
        allowedActions: ["analyze.evidence"],
        prohibitedActions: [],
        requestedOutput: {
          summary: true,
          findings: false,
          evidenceReferences: false,
          limitations: true,
        },
      })
      expect(chatOutcome.result?.limitations.some((l) => l.includes("unstructured prompt-chat adapter"))).toBe(true)

      evidenceStore.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
