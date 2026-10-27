import { describe, expect, test } from "bun:test"
import { Schema } from "effect"
import {
  CapabilityRegistrationDeniedError,
  ControlledCapabilityRegistry,
  InputOutputSchemaRegistry,
  evaluateDistributionCompliance,
  validateCapabilityDefinition,
  validateEvidenceDraft,
  validateEvidenceRecord,
  validateExecutionRecord,
  validateExecutionRequest,
  validatePartnerEnvelope,
  validatePartnerResult,
  validatePartnerTask,
  validateProjectScope,
  validateSecurityFinding,
  validateToolManifest,
  type CapabilityDefinition,
} from "../../../cyberlab/index.js"

const sampleCapability: CapabilityDefinition = {
  id: "workspace.static-audit",
  version: "1.0.0",
  title: "Workspace Static Security Audit",
  description: "Scans authorized workspace files for exposed secrets and insecure configuration patterns.",
  inputSchemaId: "schema.workspace-audit.input",
  outputSchemaId: "schema.workspace-audit.output",
  risk: "read_only",
  supportedModes: ["manual", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "workspace-audit-executor",
  skillIds: ["code-audit"],
  licenseRefs: ["MIT"],
  enabled: true,
}

describe("CyberLab Domain Contracts & Registry", () => {
  test("validates well-formed CapabilityDefinition and rejects invalid definitions", () => {
    const valid = validateCapabilityDefinition(sampleCapability)
    expect(valid.id).toBe("workspace.static-audit")
    expect(valid.risk).toBe("read_only")

    expect(() =>
      validateCapabilityDefinition({
        ...sampleCapability,
        version: "not-a-semver",
      }),
    ).toThrow()

    expect(() =>
      validateCapabilityDefinition({
        ...sampleCapability,
        supportedModes: [],
      }),
    ).toThrow()

    expect(() =>
      validateCapabilityDefinition({
        ...sampleCapability,
        licenseRefs: [],
      }),
    ).toThrow()
  })

  test("prevents remote partners and assistants from self-registering executable capabilities", async () => {
    const registry = new ControlledCapabilityRegistry()

    await expect(
      registry.registerWithActor(sampleCapability, { type: "partner", id: "remote-agent-1" }),
    ).rejects.toBeInstanceOf(CapabilityRegistrationDeniedError)

    await expect(
      registry.registerWithActor(sampleCapability, { type: "assistant", id: "llm-main" }),
    ).rejects.toBeInstanceOf(CapabilityRegistrationDeniedError)

    // Partners can propose non-enabled capabilities for human review
    const proposal = await registry.propose(
      { ...sampleCapability, enabled: true },
      { type: "partner", id: "remote-agent-1" },
      "Suggested passive check",
    )
    expect(proposal.status).toBe("pending_review")
    expect(proposal.definition.enabled).toBe(false)
    expect(await registry.list()).toHaveLength(0)

    // Admin/user can register and disable
    await registry.registerWithActor(sampleCapability, { type: "user", id: "local-operator" })
    expect(await registry.get("workspace.static-audit")).toBeDefined()

    await registry.disable("workspace.static-audit", "Maintenance window")
    const disabled = await registry.get("workspace.static-audit")
    expect(disabled?.enabled).toBe(false)
    expect(registry.getDisabledReason("workspace.static-audit")).toBe("Maintenance window")
  })

  test("validates unknown capability input payloads through InputOutputSchemaRegistry", () => {
    const schemas = new InputOutputSchemaRegistry()
    schemas.registerEffectSchema(
      "schema.workspace-audit.input",
      Schema.Struct({
        subpath: Schema.String.check(Schema.isMinLength(1)),
        maxFiles: Schema.Int.check(Schema.isGreaterThan(0), Schema.isLessThanOrEqualTo(500)),
      }),
    )

    const valid = schemas.validate("schema.workspace-audit.input", { subpath: "src", maxFiles: 50 }) as {
      subpath: string
      maxFiles: number
    }
    expect(valid.subpath).toBe("src")

    expect(() => schemas.validate("schema.workspace-audit.input", { subpath: "", maxFiles: -1 })).toThrow()
    expect(() => schemas.validate("schema.missing", {})).toThrow()
  })

  test("validates ExecutionRequest and ExecutionRecord contracts", () => {
    const req = validateExecutionRequest({
      requestId: "req-001",
      projectId: "proj-alpha",
      capabilityId: "workspace.static-audit",
      requestedBy: { type: "user", id: "operator-1" },
      input: { subpath: "." },
      mode: "manual",
    })
    expect(req.requestId).toBe("req-001")

    const rec = validateExecutionRecord({
      executionId: "exec-001",
      request: req,
      status: "succeeded",
      policyDecision: {
        decision: "allow",
        policyIds: ["default-read-only"],
        reason: "Read-only capability inside workspace",
      },
      startedAt: "2026-10-26T12:00:00.000Z",
      finishedAt: "2026-10-26T12:00:01.200Z",
      resultEvidenceIds: ["ev-001"],
    })
    expect(rec.status).toBe("succeeded")

    expect(() =>
      validateExecutionRequest({
        requestId: "",
        projectId: "proj-alpha",
        capabilityId: "workspace.static-audit",
        requestedBy: { type: "unknown-actor", id: "x" },
        input: {},
        mode: "manual",
      }),
    ).toThrow()
  })

  test("enforces EvidenceRecord SHA-256 format and prevents confirmed SecurityFinding without evidence", () => {
    const sha = "a".repeat(64)
    const draft = validateEvidenceDraft({
      kind: "stdout",
      title: "Raw scan stdout",
      source: {
        toolId: "workspace-audit",
        executorId: "workspace-audit-executor",
        executionId: "exec-001",
      },
      content: {
        mediaType: "text/plain",
        inlineText: "0 exposures detected",
        sha256: sha,
        byteLength: 20,
      },
      observedAt: "2026-10-26T12:00:01.000Z",
    })
    expect(draft.kind).toBe("stdout")

    // Missing both inlineText and storageKey must be rejected
    expect(() =>
      validateEvidenceDraft({
        ...draft,
        content: { mediaType: "text/plain" },
      }),
    ).toThrow(/inlineText or storageKey/)

    const record = validateEvidenceRecord({
      ...draft,
      evidenceId: "ev-001",
      projectId: "proj-alpha",
      createdAt: "2026-10-26T12:00:01.100Z",
      provenance: { parentEvidenceIds: [] },
      integrity: { sha256: sha, immutable: true },
      retentionClass: "forensic",
      redactionStatus: "checked",
    })
    expect(record.integrity.immutable).toBe(true)

    // Invalid SHA-256 rejected
    expect(() =>
      validateEvidenceRecord({
        ...record,
        integrity: { sha256: "not-a-sha256", immutable: true },
      }),
    ).toThrow()

    // High severity + low confidence is valid when unreviewed/inconclusive,
    // but "confirmed" without evidenceIds MUST fail
    const inconclusive = validateSecurityFinding({
      findingId: "find-001",
      projectId: "proj-alpha",
      title: "Potential exposed debug endpoint",
      description: "Heuristic alert requires verification",
      severity: "high",
      status: "inconclusive",
      confidence: 0.25,
      evidenceIds: [],
      affectedAssets: ["http://127.0.0.1:8080/debug"],
      validationEvidenceIds: [],
      createdAt: "2026-10-26T12:05:00.000Z",
      updatedAt: "2026-10-26T12:05:00.000Z",
    })
    expect(inconclusive.severity).toBe("high")
    expect(inconclusive.confidence).toBe(0.25)

    expect(() =>
      validateSecurityFinding({
        ...inconclusive,
        status: "confirmed",
        evidenceIds: [],
      }),
    ).toThrow(/requires at least one linked evidenceId/)
  })

  test("validates PartnerEnvelope, PartnerTask, PartnerResult and enforces size caps", () => {
    const task = validatePartnerTask({
      taskId: "task-01",
      projectId: "proj-alpha",
      objective: "Review redacted HTTP headers for misconfigurations",
      contextBundle: { evidenceIds: ["ev-001"], text: "Server: nginx" },
      allowedActions: ["analyze.headers"],
      prohibitedActions: ["shell.exec", "network.scan"],
      requestedOutput: {
        summary: true,
        findings: true,
        evidenceReferences: true,
        limitations: true,
      },
    })

    const env = validatePartnerEnvelope({
      protocol: "cyberlab-partner",
      protocolVersion: "1.0",
      messageId: "msg-01",
      correlationId: "corr-01",
      sentAt: "2026-10-26T12:10:00.000Z",
      sender: { id: "cyberlab-main", type: "cyberlab" },
      recipient: { id: "partner-audit-bot" },
      type: "task.submit",
      payload: task,
    })
    expect(env.type).toBe("task.submit")

    // Oversized envelope rejected
    expect(() => validatePartnerEnvelope(env, 32)).toThrow(/exceeds maximum byte size/)

    const res = validatePartnerResult({
      taskId: "task-01",
      status: "completed",
      summary: "Missing Strict-Transport-Security header observed",
      findings: [
        {
          title: "Missing HSTS",
          description: "HTTPS response lacked HSTS header",
          evidenceRefs: ["ev-001"],
          confidence: 0.9,
        },
      ],
      limitations: ["Only inspected single response"],
      artifactRefs: [],
    })
    expect(res.findings).toHaveLength(1)
  })

  test("enforces license compliance rules on ToolComponentManifest", () => {
    const unreviewed = validateToolManifest({
      id: "shannon",
      version: "0.1.0",
      source: "https://github.com/KeygraphHQ/shannon",
      commit: "0000000000000000000000000000000000000000",
      license: {
        spdx: "AGPL-3.0-only",
        reviewStatus: "license_review",
        reviewNotes: ["AGPL obligations under review"],
      },
      integration: {
        mode: "embedded",
      },
      dependenciesReviewed: false,
      noticesRecorded: false,
      lastReviewedAt: null,
    })
    const report = evaluateDistributionCompliance(unreviewed)
    expect(report.validForDistribution).toBe(false)
    expect(report.violations.length).toBeGreaterThanOrEqual(3)

    const approvedNative = validateToolManifest({
      id: "cyberlab-static-audit",
      version: "1.0.0",
      source: "https://github.com/vitorveloster18-lang/CyberLab-OS",
      commit: "dae4077a96243257ea0a2086068504b791629f10",
      license: {
        spdx: "MIT",
        reviewStatus: "approved_embed",
        reviewNotes: ["First-party MIT module"],
      },
      integration: {
        mode: "embedded",
        executorId: "workspace-audit-executor",
      },
      dependenciesReviewed: true,
      noticesRecorded: true,
      lastReviewedAt: "2026-10-26T00:00:00.000Z",
    })
    expect(evaluateDistributionCompliance(approvedNative).validForDistribution).toBe(true)

    const scope = validateProjectScope({
      scopeId: "scope-01",
      projectId: "proj-alpha",
      name: "Local Lab",
      workspaceRoot: "/home/user/CyberLab-OS",
      allowedTargets: [{ kind: "cidr", value: "127.0.0.1/32" }],
      blockedTargets: [],
      allowExternalTargets: false,
      active: true,
      updatedAt: "2026-10-26T00:00:00.000Z",
    })
    expect(scope.allowExternalTargets).toBe(false)
  })
})
