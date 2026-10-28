import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"

const catalogUrl = new URL("../../../packages/app/src/cyberlab-workbench/catalog.ts", import.meta.url).href

describe("CyberLab Manual Workbench Catalog & Schema Parity", () => {
  test("exposes all 18 manual tools across 5 categories and validates every default capability payload against backend Effect schemas", async () => {
    const catalog = (await import(catalogUrl)) as {
      MANUAL_TOOLS: Array<{ id: string; capabilityId?: string; category: string; title: string }>
      MANUAL_TOOL_CATEGORIES: Array<{ id: string; label: string }>
      createDefaultToolDrafts: () => Record<string, unknown>
      buildCapabilityInput: (
        toolId: string,
        drafts: Record<string, unknown>,
      ) => { capabilityId: string; mode: string; targetSummary: string; input: Record<string, unknown> }
    }

    expect(catalog.MANUAL_TOOL_CATEGORIES.length).toBe(5)
    expect(catalog.MANUAL_TOOLS.length).toBe(18)

    const tempRoot = mkdtempSync(path.join(tmpdir(), "cyberlab-wb-schema-"))
    try {
      const ws = await new CyberLabWorkspace({
        projectId: "wb-schema-test",
        workspaceRoot: tempRoot,
        inMemoryDb: true,
      }).ensureInitialized()

      const drafts = catalog.createDefaultToolDrafts()
      const capabilityTools = catalog.MANUAL_TOOLS.filter((t) => Boolean(t.capabilityId))
      expect(capabilityTools.length).toBe(14)

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
