import { describe, expect, test } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { Schema } from "effect"
import {
  ApprovalManager,
  ControlledCapabilityRegistry,
  CyberLabExecutionDispatcher,
  EvidenceStore,
  ExecutorRegistry,
  InputOutputSchemaRegistry,
  PolicyEngine,
  ScopeController,
  type CapabilityDefinition,
  type CyberLabExecutor,
} from "../../../cyberlab/index.js"
import {
  WORKSPACE_AUDIT_INPUT_SCHEMA_ID,
  WorkspaceAuditCapability,
  WorkspaceAuditExecutor,
  WorkspaceAuditInputSchema,
} from "../../../integrations/code-analysis/workspace-audit-executor.js"
import { rmWithRetry } from "../helpers/env-gates.js"

function setupExecutionEnv(workspaceRoot: string) {
  const capabilities = new ControlledCapabilityRegistry()
  const schemas = new InputOutputSchemaRegistry()
  const executors = new ExecutorRegistry()
  const scopes = new ScopeController()
  const approvals = new ApprovalManager()
  const policy = new PolicyEngine(capabilities, scopes, approvals)
  const evidenceStore = new EvidenceStore({
    databasePath: path.join(workspaceRoot, ".cyberlab", "evidence.sqlite"),
    artifactsDir: path.join(workspaceRoot, ".cyberlab", "artifacts"),
  })

  scopes.setProjectScope({
    scopeId: "scope-exec",
    projectId: "proj-exec",
    name: "Execution Test Workspace",
    workspaceRoot,
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
    defaultTimeoutMs: 5_000,
    maxOutputBytes: 64 * 1024,
  })

  return { capabilities, schemas, executors, scopes, approvals, policy, evidenceStore, dispatcher }
}

describe("CyberLab Execution Dispatcher & First Read-Only Lab Executor", () => {
  test("executes WorkspaceAuditExecutor reproducibly, preserves raw JSON evidence, and honours idempotencyKey", async () => {
    const tmpWorkspace = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ws-"))
    try {
      mkdirSync(path.join(tmpWorkspace, "src"), { recursive: true })
      writeFileSync(
        path.join(tmpWorkspace, "src", "insecure-client.ts"),
        `export const agentOpts = { rejectUnauthorized: false };\n`,
      )

      const { capabilities, evidenceStore, dispatcher } = setupExecutionEnv(tmpWorkspace)
      await capabilities.register(WorkspaceAuditCapability)

      const record = await dispatcher.submit({
        requestId: "req-audit-1",
        projectId: "proj-exec",
        capabilityId: WorkspaceAuditCapability.id,
        requestedBy: { type: "user", id: "operator-1" },
        input: { subpath: "src", maxFiles: 20 },
        mode: "manual",
        idempotencyKey: "idem-audit-1",
      })

      expect(record.status).toBe("succeeded")
      expect(record.resultEvidenceIds).toHaveLength(1)

      // Idempotent retry returns the exact same executionId
      const duplicate = await dispatcher.submit({
        requestId: "req-audit-1-retry",
        projectId: "proj-exec",
        capabilityId: WorkspaceAuditCapability.id,
        requestedBy: { type: "user", id: "operator-1" },
        input: { subpath: "src", maxFiles: 20 },
        mode: "manual",
        idempotencyKey: "idem-audit-1",
      })
      expect(duplicate.executionId).toBe(record.executionId)

      const rawEvidence = evidenceStore.getEvidence(record.resultEvidenceIds[0]!)
      expect(rawEvidence).toBeDefined()
      expect(evidenceStore.verifyIntegrity(rawEvidence!.evidenceId).valid).toBe(true)

      const parsed = JSON.parse(rawEvidence!.content.inlineText!) as {
        observationCount: number
        observations: Array<{ ruleId: string; file: string; line: number }>
      }
      expect(parsed.observationCount).toBe(1)
      expect(parsed.observations[0]?.ruleId).toBe("SEC-001")
      expect(parsed.observations[0]?.file).toBe("src/insecure-client.ts")

      evidenceStore.close()
    } finally {
      rmWithRetry(tmpWorkspace)
    }
  })

  test("handles timeout (timed_out), mid-flight cancellation (cancelled), and executor crashes safely", async () => {
    const tmpWorkspace = mkdtempSync(path.join(os.tmpdir(), "cyberlab-timeout-"))
    try {
      const { capabilities, schemas, executors, evidenceStore, dispatcher } = setupExecutionEnv(tmpWorkspace)

      schemas.registerEffectSchema(
        "schema.slow.input",
        Schema.Struct({ delayMs: Schema.Int.check(Schema.isGreaterThan(0)), shouldCrash: Schema.optionalKey(Schema.Boolean) }),
      )

      const slowCap: CapabilityDefinition = {
        ...WorkspaceAuditCapability,
        id: "lab.slow-probe",
        inputSchemaId: "schema.slow.input",
        executorId: "slow-executor",
      }
      await capabilities.register(slowCap)

      const slowExecutor: CyberLabExecutor = {
        id: "slow-executor",
        version: "1.0.0",
        checkAvailability: async () => ({ available: true, version: "1.0.0" }),
        validate: async () => ({ valid: true, errors: [] }),
        execute: async (execInput, ctx) => {
          const { delayMs, shouldCrash } = execInput.input as { delayMs: number; shouldCrash?: boolean }
          if (shouldCrash) {
            throw new Error("Simulated native tool crash")
          }
          await new Promise<void>((resolve, reject) => {
            const t = setTimeout(resolve, delayMs)
            ctx.signal.addEventListener(
              "abort",
              () => {
                clearTimeout(t)
                reject(new Error("Aborted inside slowExecutor"))
              },
              { once: true },
            )
          })
          return { status: "succeeded", evidenceIds: [], summary: "Done" }
        },
      }
      executors.registerExecutor(slowExecutor)

      // 1. Timeout enforcement -> timed_out
      const timedOut = await dispatcher.submit(
        {
          requestId: "req-to",
          projectId: "proj-exec",
          capabilityId: "lab.slow-probe",
          requestedBy: { type: "user", id: "op-1" },
          input: { delayMs: 500 },
          mode: "manual",
        },
        { timeoutMs: 40 },
      )
      expect(timedOut.status).toBe("timed_out")
      expect(timedOut.error?.code).toBe("EXECUTION_TIMED_OUT")
      expect(timedOut.error?.retryable).toBe(true)

      // 2. Parent AbortSignal cancellation -> cancelled
      const extAbort = new AbortController()
      setTimeout(() => extAbort.abort(new Error("User pressed Ctrl+C")), 30)
      const cancelled = await dispatcher.submit(
        {
          requestId: "req-cancel",
          projectId: "proj-exec",
          capabilityId: "lab.slow-probe",
          requestedBy: { type: "user", id: "op-1" },
          input: { delayMs: 500 },
          mode: "manual",
        },
        { timeoutMs: 2_000, parentSignal: extAbort.signal },
      )
      expect(cancelled.status).toBe("cancelled")
      expect(cancelled.error?.code).toBe("EXECUTION_CANCELLED")

      // 3. Uncaught executor exception -> failed cleanly
      const crashed = await dispatcher.submit({
        requestId: "req-crash",
        projectId: "proj-exec",
        capabilityId: "lab.slow-probe",
        requestedBy: { type: "user", id: "op-1" },
        input: { delayMs: 10, shouldCrash: true },
        mode: "manual",
      })
      expect(crashed.status).toBe("failed")
      expect(crashed.error?.code).toBe("EXECUTOR_EXCEPTION")
      expect(crashed.error?.message).toContain("Simulated native tool crash")

      // 4. Invalid unknown input -> blocked before executor ever runs
      const badInput = await dispatcher.submit({
        requestId: "req-bad-in",
        projectId: "proj-exec",
        capabilityId: "lab.slow-probe",
        requestedBy: { type: "user", id: "op-1" },
        input: { delayMs: "not-a-number" },
        mode: "manual",
      })
      expect(badInput.status).toBe("blocked")
      expect(badInput.error?.code).toBe("INVALID_CAPABILITY_INPUT")

      evidenceStore.close()
    } finally {
      rmWithRetry(tmpWorkspace)
    }
  })
})
