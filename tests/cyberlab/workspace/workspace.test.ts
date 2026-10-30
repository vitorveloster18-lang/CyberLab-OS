import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { Schema } from "effect"
import { CyberLab } from "../../../packages/schema/src/cyberlab.js"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"
import { WorkspaceAuditCapability } from "../../../integrations/code-analysis/workspace-audit-executor.js"

describe("Unified CyberLab Workspace (Manual + Assistant + Approval + Report)", () => {
  test("coordinates manual operator runs, assistant proposed runs, human approval, SHA-256 custody, findings and report in one workspace", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-unified-"))
    try {
      writeFileSync(
        path.join(tmpDir, "package.json"),
        JSON.stringify({ name: "demo-target", version: "1.0.0" }, null, 2),
      )
      writeFileSync(path.join(tmpDir, "server.ts"), "export const PORT = 8080\n")

      const ws = new CyberLabWorkspace({
        projectId: "proj-unified",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      })

      // 1. Validate status against @opencode/schema/cyberlab contract
      const initialStatus = await ws.getStatus()
      const decodedStatus = Schema.decodeUnknownSync(CyberLab.WorkspaceStatus)(initialStatus)
      expect(decodedStatus.projectId).toBe("proj-unified")
      expect(decodedStatus.capabilityCount).toBeGreaterThanOrEqual(1)
      expect(decodedStatus.skillCount).toBeGreaterThanOrEqual(6)
      expect(decodedStatus.activeScope?.allowExternalTargets).toBe(false)

      // 2. Manual operator execution succeeds immediately within workspace scope
      const manualExec = await ws.submitExecution({
        capabilityId: WorkspaceAuditCapability.id,
        input: { subpath: ".", maxFiles: 50 },
        mode: "manual",
        requestedBy: { type: "user", id: "analyst-vitor" },
      })
      expect(manualExec.status).toBe("succeeded")
      expect(manualExec.resultEvidenceIds.length).toBeGreaterThanOrEqual(1)

      // 3. Assistant proposed execution pauses at awaiting_approval until human approves
      const proposedExec = await ws.submitExecution({
        capabilityId: WorkspaceAuditCapability.id,
        input: { subpath: ".", maxFiles: 10 },
        mode: "proposed",
        requestedBy: { type: "assistant", id: "build-agent" },
      })
      expect(proposedExec.status).toBe("awaiting_approval")

      const pendingApprovals = await ws.listPendingApprovals()
      expect(pendingApprovals).toHaveLength(1)
      const ticket = pendingApprovals[0]!

      const approvedExec = await ws.approveExecution({
        approvalId: ticket.approvalId,
        decidedBy: "analyst-vitor",
        reason: "Verified read-only audit parameters",
      })
      expect(approvedExec.status).toBe("succeeded")

      // 4. Verify SHA-256 custody of generated evidence
      const evidenceList = await ws.listEvidence()
      expect(evidenceList.length).toBeGreaterThanOrEqual(2)
      const integrity = await ws.verifyEvidence(evidenceList[0]!.evidenceId, "analyst-vitor")
      expect(integrity.valid).toBe(true)

      // 5. Create unreviewed finding and confirm via human analyst review
      const finding = await ws.createFinding({
        title: "Unauthenticated HTTP port constant in server.ts",
        description: "Observed default Cleartext HTTP port configuration.",
        severity: "low",
        confidence: 0.9,
        evidenceIds: [evidenceList[0]!.evidenceId],
        affectedAssets: ["server.ts"],
        proposedRemediation: "Bind behind TLS reverse proxy or local loopback.",
        createdBy: "assistant:build-agent",
      })
      expect(finding.status).toBe("unreviewed")

      const reviewed = await ws.reviewFinding({
        findingId: finding.findingId,
        reviewedBy: "analyst-vitor",
        decision: "accept",
        notes: "Confirmed in server.ts",
      })
      expect(reviewed.status).toBe("confirmed")

      // 6. Generate reproducible Markdown report referencing SHA-256 evidence
      const report = await ws.generateMarkdownReport("Demo Target Audit")
      expect(report).toContain("Demo Target Audit")
      expect(report).toContain(evidenceList[0]!.integrity.sha256)
      expect(report).toContain("Unauthenticated HTTP port constant in server.ts")

      ws.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
