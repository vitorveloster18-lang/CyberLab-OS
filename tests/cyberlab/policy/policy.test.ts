import { describe, expect, test } from "bun:test"
import {
  ApprovalManager,
  ControlledCapabilityRegistry,
  PolicyEngine,
  ScopeController,
  summarizeTargets,
  type CapabilityDefinition,
  type ExecutionRequest,
  type ProjectScope,
} from "../../../cyberlab/index.js"

const baseScope: ProjectScope = {
  scopeId: "scope-lab-01",
  projectId: "proj-lab",
  name: "Isolated Docker Lab",
  workspaceRoot: "/home/user/CyberLab-OS",
  allowedTargets: [
    { kind: "cidr", value: "10.240.0.0/24", notes: "Lab Docker subnet" },
    { kind: "ip", value: "127.0.0.1", notes: "Localhost loopback" },
    { kind: "domain", value: "*.lab.internal", notes: "Internal lab domains" },
  ],
  blockedTargets: [
    { kind: "ip", value: "10.240.0.1", notes: "Lab gateway router" },
    { kind: "workspace_path", value: ".git", notes: "Git internals blocked" },
  ],
  allowExternalTargets: false,
  active: true,
  updatedAt: "2026-10-26T00:00:00.000Z",
}

const networkCapability: CapabilityDefinition = {
  id: "network.port-check",
  version: "1.0.0",
  title: "Scoped Port Service Check",
  description: "Checks authorized ports on lab hosts.",
  inputSchemaId: "schema.port-check.input",
  outputSchemaId: "schema.port-check.output",
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:network"],
  requiredScope: ["cidr"],
  executorId: "tcp-inspector",
  skillIds: ["network-assessment"],
  licenseRefs: ["MIT"],
  enabled: true,
}

const destructiveCapability: CapabilityDefinition = {
  ...networkCapability,
  id: "exploit.active-payload",
  risk: "destructive",
}

async function setupPolicy() {
  const registry = new ControlledCapabilityRegistry()
  await registry.register(networkCapability)
  await registry.register(destructiveCapability)
  const scopes = new ScopeController()
  scopes.setProjectScope(baseScope)
  const approvals = new ApprovalManager()
  const engine = new PolicyEngine(registry, scopes, approvals)
  return { registry, scopes, approvals, engine }
}

describe("CyberLab Execution Policy & Scope Enforcement", () => {
  test("blocks out-of-scope IPs, gateway blocklist IPs, cloud metadata and workspace path traversal", async () => {
    const { engine } = await setupPolicy()

    // 1. Out-of-scope public IP (8.8.8.8) -> blocked
    const publicIpReq: ExecutionRequest = {
      requestId: "req-1",
      projectId: "proj-lab",
      capabilityId: "network.port-check",
      requestedBy: { type: "user", id: "op-1" },
      input: { target: "8.8.8.8" },
      mode: "manual",
    }
    const dec1 = await engine.evaluate({ executionId: "ex-1", request: publicIpReq, phase: "submission" })
    expect(dec1.decision).toBe("deny")
    expect(dec1.reason).toMatch(/allowExternalTargets is false/)

    // 2. Private IP inside CIDR BUT explicitly in blockedTargets (10.240.0.1) -> blocked
    const gatewayReq: ExecutionRequest = {
      ...publicIpReq,
      requestId: "req-2",
      input: { target: "10.240.0.1" },
    }
    const dec2 = await engine.evaluate({ executionId: "ex-2", request: gatewayReq, phase: "submission" })
    expect(dec2.decision).toBe("deny")
    expect(dec2.reason).toMatch(/matches blocked scope rule/)

    // 3. Cloud metadata SSRF (169.254.169.254) -> blocked unconditionally
    const metadataReq: ExecutionRequest = {
      ...publicIpReq,
      requestId: "req-3",
      input: { url: "http://169.254.169.254/latest/meta-data/" },
    }
    const dec3 = await engine.evaluate({ executionId: "ex-3", request: metadataReq, phase: "submission" })
    expect(dec3.decision).toBe("deny")
    expect(dec3.reason).toMatch(/169\.254\.169\.254/)

    // 4. Workspace path traversal (../../etc/passwd) -> blocked
    const traversalReq: ExecutionRequest = {
      ...publicIpReq,
      requestId: "req-4",
      input: { target: "10.240.0.15", path: "../../etc/passwd" },
    }
    const dec4 = await engine.evaluate({ executionId: "ex-4", request: traversalReq, phase: "submission" })
    expect(dec4.decision).toBe("deny")
    expect(dec4.reason).toMatch(/escapes project workspaceRoot/)

    // 5. Authorized target inside 10.240.0.0/24 -> allowed for manual user
    const validReq: ExecutionRequest = {
      ...publicIpReq,
      requestId: "req-5",
      input: { target: "10.240.0.25" },
    }
    const dec5 = await engine.evaluate({ executionId: "ex-5", request: validReq, phase: "submission" })
    expect(dec5.decision).toBe("allow")
  })

  test("prevents accidental external network expansion even if 0.0.0.0/0 is mistakenly added while allowExternalTargets is false", async () => {
    const { scopes, engine } = await setupPolicy()
    scopes.setProjectScope({
      ...baseScope,
      allowedTargets: [{ kind: "cidr", value: "0.0.0.0/0" }],
      allowExternalTargets: false,
    })

    const externalReq: ExecutionRequest = {
      requestId: "req-ext",
      projectId: "proj-lab",
      capabilityId: "network.port-check",
      requestedBy: { type: "user", id: "op-1" },
      input: { target: "1.1.1.1" },
      mode: "manual",
    }
    const decision = await engine.evaluate({ executionId: "ex-ext", request: externalReq, phase: "submission" })
    expect(decision.decision).toBe("deny")
    expect(decision.reason).toMatch(/allowExternalTargets is false/)
  })

  test("enforces partner & assistant boundaries and binds single-use ApprovalTickets to exact targets", async () => {
    const { registry, scopes, approvals, engine } = await setupPolicy()

    // Partner requesting destructive capability -> immediate deny
    const partnerDestructive: ExecutionRequest = {
      requestId: "req-p1",
      projectId: "proj-lab",
      capabilityId: "exploit.active-payload",
      requestedBy: { type: "partner", id: "partner-scanner" },
      input: { target: "10.240.0.10" },
      mode: "approved",
    }
    const pDec = await engine.evaluate({ executionId: "ex-p1", request: partnerDestructive, phase: "submission" })
    expect(pDec.decision).toBe("deny")

    // Assistant requesting moderate capability -> ask at submission, deny at execution if unapproved
    const assistantModerate: ExecutionRequest = {
      requestId: "req-a1",
      projectId: "proj-lab",
      capabilityId: "network.port-check",
      requestedBy: { type: "assistant", id: "main-llm" },
      input: { url: "https://api.lab.internal:8443/health" },
      mode: "approved",
    }
    const subDec = await engine.evaluate({ executionId: "ex-a1", request: assistantModerate, phase: "submission" })
    expect(subDec.decision).toBe("ask")

    const unapprovedExecDec = await engine.evaluate({
      executionId: "ex-a1",
      request: assistantModerate,
      phase: "execution",
    })
    expect(unapprovedExecDec.decision).toBe("deny")

    // Create & approve ticket for https://api.lab.internal:8443/health
    const ticket = approvals.createTicket({
      executionId: "ex-a1",
      projectId: "proj-lab",
      capabilityId: "network.port-check",
      requestedBy: assistantModerate.requestedBy,
      targetSummary: summarizeTargets(assistantModerate.input),
    })
    approvals.decide(ticket.approvalId, "approved", "operator-vitor", "Verified lab target")

    // Attempt target swap after approval -> MUST fail binding check
    const swappedDec = await engine.evaluate({
      executionId: "ex-a1",
      request: { ...assistantModerate, input: { url: "https://db.lab.internal:5432" } },
      phase: "execution",
      approvalId: ticket.approvalId,
    })
    expect(swappedDec.decision).toBe("deny")
    expect(swappedDec.reason).toMatch(/binding mismatch/)

    // Valid execution with exact approved target -> allow (and consumes ticket!)
    const approvedExecDec = await engine.evaluate({
      executionId: "ex-a1",
      request: assistantModerate,
      phase: "execution",
      approvalId: ticket.approvalId,
    })
    expect(approvedExecDec.decision).toBe("allow")

    // Replay of consumed ticket -> deny
    const replayDec = await engine.evaluate({
      executionId: "ex-a1",
      request: assistantModerate,
      phase: "execution",
      approvalId: ticket.approvalId,
    })
    expect(replayDec.decision).toBe("deny")
    expect(replayDec.reason).toMatch(/consumed/)

    // Dual-phase safety: if capability is disabled or scope revoked AFTER approval, execution phase blocks it
    const ticket2 = approvals.createTicket({
      executionId: "ex-a2",
      projectId: "proj-lab",
      capabilityId: "network.port-check",
      requestedBy: assistantModerate.requestedBy,
      targetSummary: summarizeTargets(assistantModerate.input),
    })
    approvals.decide(ticket2.approvalId, "approved", "operator-vitor")
    scopes.setProjectScope({ ...baseScope, active: false })

    const postRevokeDec = await engine.evaluate({
      executionId: "ex-a2",
      request: assistantModerate,
      phase: "execution",
      approvalId: ticket2.approvalId,
    })
    expect(postRevokeDec.decision).toBe("deny")
    expect(postRevokeDec.reason).toMatch(/No active ProjectScope/)

    // Re-enable scope and test capability disablement before execution
    scopes.setProjectScope({ ...baseScope, active: true })
    await registry.disable("network.port-check", "Emergency stop")
    const disabledDec = await engine.evaluate({
      executionId: "ex-a2",
      request: assistantModerate,
      phase: "execution",
      approvalId: ticket2.approvalId,
    })
    expect(disabledDec.decision).toBe("deny")
    expect(disabledDec.reason).toMatch(/currently disabled/)

    // Audit log recorded all 8 evaluations
    expect(engine.getAuditLog("proj-lab")).toHaveLength(8)
  })
})
