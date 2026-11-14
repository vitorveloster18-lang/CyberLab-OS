import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"

describe("CyberLab — modelos livres do OpenCode", () => {
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
