import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"

const catalogUrl = new URL("../../../packages/app/src/cyberlab-workbench/catalog.ts", import.meta.url).href

describe("CyberLab Manual Workbench Suites, Catalog & Schema Parity", () => {
  test("consolidates all 33 underlying manual modes into 8 distinct Burp-Suite-style suites and validates every default capability payload against backend Effect schemas", async () => {
    const catalog = (await import(catalogUrl)) as {
      TOOL_SUITES: Array<{
        id: string
        title: string
        functions: Array<{
          id: string
          label: string
          engines: Array<{ toolId: string; label: string }>
        }>
      }>
      MANUAL_TOOLS: Array<{ id: string; capabilityId?: string; category: string; title: string }>
      MANUAL_TOOL_CATEGORIES: Array<{ id: string; label: string }>
      findSuiteAndFunctionForTool: (toolId: string) => { suiteId: string; functionId: string }
      getSuiteAllToolIds: (suiteId: string) => string[]
      createDefaultToolDrafts: () => Record<string, unknown>
      buildCapabilityInput: (
        toolId: string,
        drafts: Record<string, unknown>,
      ) => { capabilityId: string; mode: string; targetSummary: string; input: Record<string, unknown> }
    }

    expect(catalog.TOOL_SUITES.length).toBe(8)
    expect(catalog.TOOL_SUITES.map((s) => s.id)).toEqual([
      "web-suite",
      "network-suite",
      "packet-suite",
      "reversing-suite",
      "dfir-suite",
      "code-suite",
      "cdi-suite",
      "governance-suite",
    ])

    // Verify all 33 underlying tool modes are reachable through the 8 distinct suites
    const coveredToolIds = new Set<string>()
    for (const suite of catalog.TOOL_SUITES) {
      expect(suite.functions.length).toBeGreaterThanOrEqual(1)
      for (const tid of catalog.getSuiteAllToolIds(suite.id)) {
        coveredToolIds.add(tid)
      }
    }
    expect(coveredToolIds.size).toBe(33)
    for (const tool of catalog.MANUAL_TOOLS) {
      expect(coveredToolIds.has(tool.id)).toBe(true)
      const loc = catalog.findSuiteAndFunctionForTool(tool.id)
      expect(loc.suiteId.length).toBeGreaterThan(0)
      expect(loc.functionId.length).toBeGreaterThan(0)
    }

    const tempRoot = mkdtempSync(path.join(tmpdir(), "cyberlab-wb-schema-"))
    try {
      const ws = await new CyberLabWorkspace({
        projectId: "wb-schema-test",
        workspaceRoot: tempRoot,
        inMemoryDb: true,
      }).ensureInitialized()

      const drafts = catalog.createDefaultToolDrafts()
      const capabilityTools = catalog.MANUAL_TOOLS.filter((t) => Boolean(t.capabilityId))
      expect(capabilityTools.length).toBe(29)

      for (const tool of capabilityTools) {
        const built = catalog.buildCapabilityInput(tool.id, drafts)
        expect(built.capabilityId).toBe(tool.capabilityId!)
        const capDef = await ws.capabilities.get(built.capabilityId)
        expect(capDef).toBeDefined()
        const decoded = ws.schemas.validate(capDef!.inputSchemaId, built.input)
        expect(decoded).toBeDefined()
      }

      ws.close()
    } finally {
      rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
