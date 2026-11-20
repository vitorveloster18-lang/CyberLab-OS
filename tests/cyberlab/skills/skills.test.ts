import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"
import {
  ApprovalManager,
  ControlledCapabilityRegistry,
  CyberLabSkillCatalog,
  PolicyEngine,
  ScopeController,
} from "../../../cyberlab/index.js"
import { WorkspaceAuditCapability } from "../../../integrations/code-analysis/workspace-audit-executor.js"
import { SkillFile } from "../../../packages/core/src/config/plugin/skill-file.js"

const repoRoot = path.resolve(import.meta.dir, "../../..")
const skillsDir = path.join(repoRoot, "skills")

describe("CyberLab Native Skills & Policy Separation", () => {
  test("discovers all CyberLab skills with companion files and parses them via OpenCode V2 SkillFile.parse", async () => {
    const catalog = new CyberLabSkillCatalog()
    const skills = catalog.loadFromDirectory(skillsDir)

    expect(skills.map((s) => s.id)).toEqual([
      "code-audit",
      "digital-forensics",
      "evidence-review",
      "incident-response",
      "mobile-forensics",
      "network-assessment",
      "network-recon",
      "pentest-methodology",
      "reverse-engineering",
      "web-appsec",
      "web-assessment",
    ])

    const netSkill = catalog.get("network-assessment")!
    expect(netSkill.grantsExecutionPrivileges).toBe(false)
    expect(netSkill.companionFiles.map((f) => path.basename(f))).toEqual([
      "evidence-format.md",
      "methodology.md",
    ])

    // Verify native OpenCode V2 SkillFile.parse compatibility on every SKILL.md
    for (const skill of skills) {
      const raw = readFileSync(skill.skillFilePath, "utf8")
      const parsed = SkillFile.parse(skillsDir, skill.skillFilePath, raw)
      expect(parsed._tag).toBe("Parsed")
      if (parsed._tag === "Parsed") {
        expect(String(parsed.skill.id)).toBe(skill.id)
        expect(parsed.skill.description).toBeTruthy()
      }
    }

    // Verify skill <-> capability mapping
    const registry = new ControlledCapabilityRegistry()
    await registry.register(WorkspaceAuditCapability)
    const linked = await catalog.capabilitiesForSkill("code-audit", registry)
    expect(linked.map((c) => c.id)).toEqual([WorkspaceAuditCapability.id])
  })

  test("loading skills never grants execution permissions or bypasses ScopeController", async () => {
    const catalog = new CyberLabSkillCatalog()
    catalog.loadFromDirectory(skillsDir)
    expect(catalog.get("code-audit")).toBeDefined()

    const registry = new ControlledCapabilityRegistry()
    await registry.register(WorkspaceAuditCapability)
    const scopes = new ScopeController()
    scopes.setProjectScope({
      scopeId: "scope-skill-test",
      projectId: "proj-skill",
      name: "Strict Workspace",
      workspaceRoot: repoRoot,
      allowedTargets: [],
      blockedTargets: [],
      allowExternalTargets: false,
      active: true,
      updatedAt: "2026-10-26T00:00:00.000Z",
    })
    const engine = new PolicyEngine(registry, scopes, new ApprovalManager())

    // Assistant attempting path escape while referencing a valid skill capability is still denied
    const decision = await engine.evaluate({
      executionId: "ex-skill-escape",
      request: {
        requestId: "req-skill-escape",
        projectId: "proj-skill",
        capabilityId: WorkspaceAuditCapability.id,
        requestedBy: { type: "assistant", id: "llm-with-skill" },
        input: { subpath: "../../etc" },
        mode: "approved",
      },
      phase: "submission",
    })
    expect(decision.decision).toBe("deny")
    expect(decision.reason).toMatch(/escapes project workspaceRoot/)
  })
})
