import { afterEach, describe, expect, test } from "bun:test"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
  computeArsenalSlotHealth,
  normalizeSlotNameForComparison,
  type ArsenalSlotStatus,
} from "../../../cyberlab/arsenal/slot-manager.js"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"

const tempDirs: string[] = []
const workspaces: CyberLabWorkspace[] = []

afterEach(() => {
  delete process.env.CYBERLAB_GLOBAL_CONFIG_DIR
  for (const ws of workspaces.splice(0)) ws.close()
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 })
})

function fakeSlot(over: Partial<ArsenalSlotStatus> & { slotId: string; name: string }): ArsenalSlotStatus {
  return {
    shortLabel: over.name.slice(0, 12),
    category: "custom",
    kind: "cli_runner",
    tagline: "",
    description: "",
    upstreamUrl: "local://custom-slot",
    licenseNote: "Custom User Tool (Externo)",
    isCustom: true,
    installed: false,
    availableRuntimes: [],
    activeRuntime: "none",
    resolvedPath: null,
    windowsPath: null,
    wslPath: null,
    posixPath: null,
    embedUrl: null,
    daemonRunning: false,
    companionProxyPort: null,
    mcpCapable: false,
    mcpConnected: false,
    mcpLabel: null,
    installPowerShell: "",
    installKaliWsl: "",
    presets: [],
    override: {},
    ...over,
  }
}

describe("CyberLab OS v6.3.1 — Higiene de Slots Personalizados (fantasmas, duplicatas e alvos não-executáveis)", () => {
  test("normalizeSlotNameForComparison ignora caixa, acentos e pontuação", () => {
    expect(normalizeSlotNameForComparison("Metasploit Framework")).toBe("metasploitframework")
    expect(normalizeSlotNameForComparison("metasploit-framework")).toBe("metasploitframework")
    expect(normalizeSlotNameForComparison("SSTI Advanced Payload List")).toBe("sstiadvancedpayloadlist")
    expect(normalizeSlotNameForComparison("SSTI  Ádvanced  Payload-List!")).toBe("sstiadvancedpayloadlist")
  })

  test("detecta slot fantasma (binário configurado inexistente em qualquer runtime)", () => {
    const missing = path.join(os.tmpdir(), "nao-existe-binario-cyberlab-631")
    const issues = computeArsenalSlotHealth(
      [fakeSlot({ slotId: "custom-metasploit-framework-c421", name: "Metasploit Framework", installed: false })],
      { "custom-metasploit-framework-c421": { customExecutablePath: missing } },
    )
    const ghost = issues.find((i) => i.slotId === "custom-metasploit-framework-c421")
    expect(ghost).toBeDefined()
    expect(ghost?.kind).toBe("ghost_custom_slot")
    expect(ghost?.severity).toBe("error")
    expect(ghost?.configuredPath).toBe(missing)
    expect(ghost?.suggestion.length).toBeGreaterThan(10)
  })

  test("detecta duplicata e preserva o slot instalado como o que deve ser mantido", () => {
    const issues = computeArsenalSlotHealth(
      [
        fakeSlot({ slotId: "custom-ssti-advanced-payload-list-92e8", name: "SSTI Advanced Payload List", installed: true }),
        fakeSlot({ slotId: "custom-ssti-advanced-payload-list-9b27", name: "SSTI Advanced Payload List", installed: false }),
      ],
      {},
    )
    const dupes = issues.filter((i) => i.kind === "duplicate_custom_slot")
    expect(dupes.length).toBe(1)
    expect(dupes[0]!.slotId).toBe("custom-ssti-advanced-payload-list-9b27")
    expect(dupes[0]!.duplicateOfSlotId).toBe("custom-ssti-advanced-payload-list-92e8")
  })

  test("nunca sugere remover um slot oficial, mesmo quando duplicado por um custom", () => {
    const issues = computeArsenalSlotHealth(
      [
        fakeSlot({ slotId: "metasploit", name: "Metasploit Framework", isCustom: false, installed: true }),
        fakeSlot({ slotId: "custom-metasploit-framework-ce52", name: "Metasploit Framework", installed: false }),
      ],
      {},
    )
    const dupes = issues.filter((i) => i.kind === "duplicate_custom_slot")
    expect(dupes.length).toBe(1)
    expect(dupes[0]!.slotId).toBe("custom-metasploit-framework-ce52")
    expect(dupes[0]!.duplicateOfSlotId).toBe("metasploit")
    expect(issues.some((i) => i.slotId === "metasploit")).toBe(false)
  })

  test("detecta slot apontando para arquivo de dados (lista de payload) em vez de executável", () => {
    const listDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-payload-list-"))
    tempDirs.push(listDir)
    const listPath = path.join(listDir, "ssti-payloads.txt")
    writeFileSync(listPath, "{{7*7}}\n", "utf8")

    const issues = computeArsenalSlotHealth(
      [fakeSlot({ slotId: "custom-ssti-list-x", name: "SSTI Payload List", installed: true })],
      { "custom-ssti-list-x": { customExecutablePath: listPath } },
    )
    const issue = issues.find((i) => i.slotId === "custom-ssti-list-x")
    expect(issue?.kind).toBe("non_executable_target")
    expect(issue?.severity).toBe("warning")
  })

  test("detecta slot personalizado sem executável nem URL configurados", () => {
    const issues = computeArsenalSlotHealth([fakeSlot({ slotId: "custom-vazio-1", name: "Slot Vazio" })], {})
    expect(issues[0]?.kind).toBe("unconfigured_custom_slot")
    expect(issues[0]?.severity).toBe("error")
    expect(issues[0]?.configuredPath).toBeNull()
  })

  test("arsenal limpo não produz nenhum diagnóstico", () => {
    const issues = computeArsenalSlotHealth(
      [
        fakeSlot({ slotId: "custom-ok-1", name: "Ferramenta Ok", installed: true }),
        fakeSlot({ slotId: "official-nmap", name: "Nmap", isCustom: false, installed: true }),
      ],
      { "custom-ok-1": { customExecutablePath: process.execPath } },
    )
    expect(issues).toEqual([])
  })

  test("pruneBrokenCustomSlots remove fantasmas e duplicatas sem tocar slots oficiais", async () => {
    const wsDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v631-prune-"))
    tempDirs.push(wsDir)
    process.env.CYBERLAB_GLOBAL_CONFIG_DIR = path.join(wsDir, ".global-cfg")
    mkdirSync(path.join(wsDir, ".global-cfg"), { recursive: true })

    const ws = new CyberLabWorkspace({ projectId: "proj-prune-631", workspaceRoot: wsDir, inMemoryDb: true })
    workspaces.push(ws)

    // Slot custom SAUDÁVEL (aponta para um executável real -> bun)
    await ws.upsertCustomArsenalSlot({
      name: "Ferramenta Saudável",
      kind: "cli_runner",
      executableOrUrl: process.execPath,
    })
    // Dois slots custom quebrados/duplicados (mesmo nome do saudável + caminho inexistente)
    await ws.upsertCustomArsenalSlot({
      name: "Ferramenta Fantasma",
      kind: "cli_runner",
      executableOrUrl: path.join(wsDir, "binario-que-nao-existe-631"),
    })
    await ws.upsertCustomArsenalSlot({
      slotId: "custom-ferramenta-fantasma-dup",
      name: "Ferramenta Fantasma",
      kind: "cli_runner",
      executableOrUrl: path.join(wsDir, "outro-binario-inexistente-631"),
    })

    const before = await ws.getArsenalOverview(true)
    const customBefore = before.slots.filter((s) => s.isCustom)
    expect(customBefore.length).toBe(3)
    expect(before.health.length).toBeGreaterThanOrEqual(2)

    const after = await ws.pruneBrokenCustomArsenalSlots({ removeGhosts: true, removeDuplicates: true })
    const customAfter = after.slots.filter((s) => s.isCustom)

    // Sobrevive apenas o slot saudável
    expect(customAfter.length).toBe(1)
    expect(customAfter[0]!.name).toBe("Ferramenta Saudável")

    // Nenhum slot oficial foi removido
    const officialBefore = before.slots.filter((s) => !s.isCustom).length
    const officialAfter = after.slots.filter((s) => !s.isCustom).length
    expect(officialAfter).toBe(officialBefore)

    // O diagnóstico fica limpo após a poda
    expect(after.health).toEqual([])
  })
})
