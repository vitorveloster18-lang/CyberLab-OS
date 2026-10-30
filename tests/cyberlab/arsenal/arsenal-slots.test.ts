import { afterEach, describe, expect, test } from "bun:test"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
  CyberLabWorkspace,
  OFFICIAL_ARSENAL_SLOTS,
  splitCommandLineArgs,
  windowsPathToWslPath,
} from "../../../cyberlab/index.js"

const tempDirs: string[] = []
const workspaces: CyberLabWorkspace[] = []

afterEach(() => {
  delete process.env.CYBERLAB_GLOBAL_CONFIG_DIR
  for (const ws of workspaces.splice(0)) {
    ws.close()
  }
  for (const d of tempDirs.splice(0)) {
    rmSync(d, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 })
  }
})

describe("CyberLab OS v5.0 — Real External Arsenal Slots (Windows PowerShell + WSL2 Kali + Web Embed + Custom Slots)", () => {
  test("1. Catalog exposes all 25+ best-in-class official real tool slots and translates Windows <-> WSL2 paths accurately", () => {
    expect(OFFICIAL_ARSENAL_SLOTS.length).toBeGreaterThanOrEqual(25)
    const ids = OFFICIAL_ARSENAL_SLOTS.map((s) => s.slotId)
    expect(ids).toContain("burp-suite")
    expect(ids).toContain("opentrap")
    expect(ids).toContain("mitmweb")
    expect(ids).toContain("caido")
    expect(ids).toContain("owasp-zap")
    expect(ids).toContain("nuclei")
    expect(ids).toContain("ffuf")
    expect(ids).toContain("katana")
    expect(ids).toContain("httpx")
    expect(ids).toContain("interactsh")
    expect(ids).toContain("subfinder")
    expect(ids).toContain("nmap")
    expect(ids).toContain("wireshark")
    expect(ids).toContain("ghidra")
    expect(ids).toContain("jadx")
    expect(ids).toContain("keyhunter")
    expect(ids).toContain("cyberchef")
    expect(ids).toContain("kali-desktop-stream")

    expect(windowsPathToWslPath("C:\\Users\\Vitor\\Projetos\\alvo-h1")).toBe("/mnt/c/Users/Vitor/Projetos/alvo-h1")
    expect(splitCommandLineArgs('-u https://app.example.com -H "X-Bug-Bounty: HackerOne-vitor"')).toEqual([
      "-u",
      "https://app.example.com",
      "-H",
      "X-Bug-Bounty: HackerOne-vitor",
    ])
  })

  test("2. Hosts official external GCHQ CyberChef HTML locally on loopback & manages Custom User Slots + Scope Guard + SHA-256 Custody", async () => {
    const wsDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v5-arsenal-"))
    const externalToolsDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v5-ext-tools-"))
    tempDirs.push(wsDir, externalToolsDir)
    process.env.CYBERLAB_GLOBAL_CONFIG_DIR = path.join(wsDir, ".global-cfg")

    // Simulate user downloading GCHQ CyberChef zip into <toolsRoot>/CyberChef/CyberChef_v10.19.4.html
    const chefDir = path.join(externalToolsDir, "CyberChef")
    mkdirSync(chefDir, { recursive: true })
    writeFileSync(
      path.join(chefDir, "CyberChef_v10.19.4.html"),
      "<!doctype html><html><head><title>CyberChef Official</title></head><body>GCHQ CyberChef Local</body></html>",
      "utf8",
    )

    const ws = new CyberLabWorkspace({
      projectId: "arsenal-proj-1",
      workspaceRoot: wsDir,
      inMemoryDb: true,
    })
    workspaces.push(ws)

    const configured = await ws.configureArsenal({
      toolsRootDir: externalToolsDir,
      enforceScopeOnCliRuns: true,
    })
    const chefSlot = configured.slots.find((s) => s.slotId === "cyberchef")!
    expect(chefSlot.installed).toBe(true)

    // Launch CyberChef inside embedded loopback server -> verify 200 OK HTML
    const startedChef = await ws.launchArsenalSlot({
      slotId: "cyberchef",
      action: "start_web",
    })
    expect(startedChef.ok).toBe(true)
    expect(startedChef.embedUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/$/)
    const chefHtml = await (await fetch(startedChef.embedUrl!)).text()
    expect(chefHtml).toContain("GCHQ CyberChef Local")

    // Add a Custom User CLI Slot pointing to `process.execPath` (bun) so this test runs cross-platform on Windows + Linux!
    const afterCustom = await ws.upsertCustomArsenalSlot({
      name: "Meu Scanner Custom",
      shortLabel: "CustomScan",
      kind: "cli_runner",
      executableOrUrl: process.execPath,
      defaultArgsTemplate: '--version',
    })
    const customSlot = afterCustom.slots.find((s) => s.isCustom)!
    expect(customSlot).toBeDefined()
    expect(customSlot.installed).toBe(true)

    // Scope guard blocks out-of-scope public URL when enforceScopeOnCliRuns=true
    await expect(
      ws.launchArsenalSlot({
        slotId: customSlot.slotId,
        action: "run_cli",
        target: "https://out-of-scope-target.example.com",
      }),
    ).rejects.toThrow(/Bloqueado pela Trava de Escopo/)

    // Import HackerOne scope -> target becomes authorized!
    await ws.importBugBountyScope({
      rawInput: "*.authorized-bounty.example\n!out-of-scope.authorized-bounty.example",
      platformHint: "hackerone",
      researcherHandle: "vitor",
    })

    const cliLaunch = await ws.launchArsenalSlot({
      slotId: customSlot.slotId,
      action: "run_cli",
      target: "https://api.authorized-bounty.example",
      rawArgs: "--version",
    })
    expect(cliLaunch.ok).toBe(true)
    expect(cliLaunch.run).toBeDefined()

    // Wait briefly for bun --version to complete and verify live output + SHA-256 Evidence Vault persistence
    for (let i = 0; i < 30; i++) {
      const ov = await ws.getArsenalOverview(false)
      const cur = ov.runs.find((r) => r.runId === cliLaunch.run!.runId)
      if (cur && cur.status !== "running") break
      await new Promise((r) => setTimeout(r, 40))
    }

    const finalOv = await ws.getArsenalOverview(false)
    const finishedRun = finalOv.runs.find((r) => r.runId === cliLaunch.run!.runId)!
    expect(finishedRun.status).toBe("succeeded")
    expect(finishedRun.outputTail.length).toBeGreaterThan(3)

    // Persist tool output to cryptographic SHA-256 EvidenceStore
    const saved = await ws.persistArsenalOutputToEvidence({
      title: "Saída CustomScan",
      content: `${finishedRun.outputTail}\nAuthorization: Bearer topsecret123`,
      slotId: customSlot.slotId,
    })
    expect(saved.sha256).toMatch(/^[a-f0-9]{64}$/)
    const readBack = await ws.readEvidenceContent(saved.evidenceId)
    expect(readBack.text).toContain("[REDACTED")

    // Verify Workspace File Explorer lists .cyberlab/outputs/ log
    const outListing = await ws.listWorkspaceFiles(".cyberlab/outputs")
    expect(outListing.entries.length).toBeGreaterThanOrEqual(1)

    // Verify quote-stripping when operator pastes Windows "Copy as path" quoted string for Burp Suite
    const fakeJar = path.join(externalToolsDir, "burpsuite_community_custom.jar")
    writeFileSync(fakeJar, "PK-mock-jar", "utf8")
    const quotedUpdate = await ws.configureArsenal({
      slotId: "burp-suite",
      slotOverride: { customExecutablePath: `"${fakeJar}"` },
    })
    const updatedBurp = quotedUpdate.slots.find((s) => s.slotId === "burp-suite")!
    expect(updatedBurp.override.customExecutablePath).toBe(fakeJar)

    // Verify Caido enables --allow-guests and mitmweb uses deterministic token + 0.0.0.0 bridgeable host
    const caidoDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "caido")!
    expect(caidoDef.managedDaemonArgs).toContain("--allow-guests")
    const mitmDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "mitmweb")!
    expect(mitmDef.managedDaemonArgs).toContain("web_password=cyberlab")
    expect(mitmDef.managedDaemonArgs).toContain("0.0.0.0")
    const burpDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "burp-suite")!
    expect(burpDef.windowsKnownPaths?.some((p) => p.includes("%LOCALAPPDATA%\\BurpSuiteCommunity\\"))).toBe(true)
    expect(burpDef.windowsBinaries.includes("BurpSuitePro.exe")).toBe(false)
    expect(burpDef.installKaliWsl).toContain("portswigger-cdn.net/burp/releases/download?product=desktop")
    expect(burpDef.installKaliWsl).toContain("--i-accept-the-license-agreement")
    expect(burpDef.installKaliWsl).toContain("unzip -tq /opt/cyberlab-burp/burpsuite.jar")

    const kaliDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "kali-desktop-stream")!
    expect(kaliDef.posixBinaries).toEqual(["startxfce4"])
    expect(kaliDef.installKaliWsl).toContain("xfce4-terminal")
    expect(kaliDef.installKaliWsl).toContain("kali-themes")

    await ws.launchArsenalSlot({ slotId: "cyberchef", action: "stop_web" })
  }, 25_000)
})
