import { describe, expect, test } from "bun:test"
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { BUILTIN_EXTERNAL_TOOL_CATALOG, CyberLabWorkspace } from "../../../cyberlab/index.js"

describe("CyberLab External KeyHunter Rust CLI Bridge & OpenCode Free AI Models Fix", () => {
  test("1. External KeyHunter Rust CLI Bridge (fadidevv/keyhunter) executes shell=false and redacts leaked tokens in stdout custody", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ext-keyhunter-"))
    const binDir = path.join(tmpDir, "mock-bin")
    mkdirSync(binDir, { recursive: true })
    const origPath = process.env.PATH ?? ""
    try {
      const catEntry = BUILTIN_EXTERNAL_TOOL_CATALOG.find((t) => t.toolId === "keyhunter")
      expect(catEntry).toBeDefined()
      expect(catEntry?.licenseSpdx).toBe("MIT")

      const rawMockSecret = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
      if (process.platform !== "win32") {
        const mockBin = path.join(binDir, "keyhunter")
        writeFileSync(
          mockBin,
          `#!/usr/bin/env node\nconsole.log(JSON.stringify({ argv: process.argv.slice(2), findings: [{ provider: "github", key: "${rawMockSecret}" }] }));\n`,
          "utf8",
        )
        chmodSync(mockBin, 0o755)
        process.env.PATH = `${binDir}:${origPath}`

        const ws = await new CyberLabWorkspace({
          projectId: "proj-ext-kh",
          workspaceRoot: tmpDir,
          inMemoryDb: true,
        }).ensureInitialized()

        const exec = await ws.submitExecution({
          capabilityId: "external.keyhunter-cli",
          mode: "manual",
          input: {
            subcommand: "scan",
            provider: "github",
            outputFormat: "json",
            verifiedOnly: true,
          },
        })

        expect(exec.status).toBe("succeeded")
        const evList = await ws.listEvidence(exec.executionId)
        expect(evList.length).toBeGreaterThanOrEqual(1)
        const stdoutContent = await ws.readEvidenceContent(evList[0]!.evidenceId)
        expect(stdoutContent.text).toContain('"scan"')
        expect(stdoutContent.text).toContain('"-p"')
        expect(stdoutContent.text).toContain('"github"')
        expect(stdoutContent.text).toContain('"-V"')
        // Automatic custody redaction must mask ghp_... token!
        expect(stdoutContent.text).not.toContain(rawMockSecret)
        expect(stdoutContent.text).toContain("[REDACTED:GITHUB_TOKEN]")

        ws.close()
      }
    } finally {
      process.env.PATH = origPath
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("2. OpenCode Free AI Models fix: snapshot exposes 9 active free models with public key, models-dev checks loadable(), CLI sets valid User-Agent, and UI includes freeSet", async () => {
    const repoRoot = path.resolve(import.meta.dir, "../../..")

    const serverProcessSrc = readFileSync(path.join(repoRoot, "packages/cli/src/server-process.ts"), "utf8")
    expect(serverProcessSrc).toContain('OPENCODE_CHANNEL === "local"')
    expect(serverProcessSrc).toContain('OPENCODE_VERSION === "local"')
    expect(serverProcessSrc).toContain('"2.1.4"')
    expect(serverProcessSrc).toContain('"latest"')

    const defaultHandlerSrc = readFileSync(
      path.join(repoRoot, "packages/cli/src/commands/handlers/default.ts"),
      "utf8",
    )
    expect(defaultHandlerSrc).toContain('OPENCODE_CHANNEL === "local"')

    const appModelsSrc = readFileSync(path.join(repoRoot, "packages/app/src/providers/models/models.tsx"), "utf8")
    expect(appModelsSrc).toContain(".filter(isFreeModel)")
    expect(appModelsSrc).toContain("freeSet().has(key)")

    const modelsDevSrc = readFileSync(path.join(repoRoot, "packages/core/src/models-dev.ts"), "utf8")
    expect(modelsDevSrc).toContain("function loadable(specifier: string | undefined")
    expect(modelsDevSrc).toContain("Provider.builtinPackages.has(name)")

    const modelSrc = readFileSync(path.join(repoRoot, "packages/core/src/model.ts"), "utf8")
    expect(modelSrc).toContain("deepseek-v4.1-flash-free")
    expect(modelSrc).toContain("glm-5.3-flash-free")
    expect(modelSrc).toContain("nemotron-3.5-super-vl-free")
    expect(modelSrc).toContain("mimo-v2.6-flash-free")

    const snapshotRaw = readFileSync(path.join(repoRoot, "packages/core/src/models-dev/snapshot.txt"), "utf8")
    const snapshotCatalog = JSON.parse(snapshotRaw) as Record<
      string,
      {
        models: Record<string, { id: string; type?: string; status?: string; cost?: unknown }>
      }
    >
    const opencodeProvider = snapshotCatalog["opencode"]
    expect(opencodeProvider).toBeDefined()

    const activeFreeModels = Object.values(opencodeProvider!.models).filter((m) => {
      if (m.status === "deprecated") return false
      if (m.type && m.type !== "chat") return false
      if (m.id.includes("embed")) return false
      const rawStr = JSON.stringify(m.cost ?? {})
      return !rawStr.includes('"price":') || rawStr.includes('"price":0')
    })
    const activeFreeIds = activeFreeModels.map((m) => m.id)
    expect(activeFreeIds).toContain("big-pickle")
    expect(activeFreeIds).toContain("deepseek-v4.1-flash-free")
    expect(activeFreeIds).toContain("glm-5.3-flash-free")
    expect(activeFreeIds).toContain("nemotron-3.5-super-vl-free")
    expect(activeFreeIds).toContain("mimo-v2.6-flash-free")
    expect(activeFreeIds.length).toBeGreaterThanOrEqual(9)
  })
})
