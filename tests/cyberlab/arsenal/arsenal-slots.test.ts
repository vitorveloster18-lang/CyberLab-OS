import { afterEach, describe, expect, test } from "bun:test"
import { spawn } from "node:child_process"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import http from "node:http"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
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
    // v5.6: REA + all previously deferred tools from TOOL_INVENTORY.md
    expect(ids).toContain("rea")
    expect(ids).toContain("mvt")
    expect(ids).toContain("metasploit")
    expect(ids).toContain("impacket-hashcat")
    expect(ids).toContain("strix")
    expect(ids).toContain("shannon")
    expect(ids).toContain("hexstrike-ai")
    expect(ids).toContain("pentagi")
    expect(ids).toContain("pentestgpt-cai")
    expect(ids).toContain("tor-onionshare")
    expect(ids).toContain("veracrypt")
    expect(ids).toContain("mullvad-opsec")
    expect(OFFICIAL_ARSENAL_SLOTS.length).toBeGreaterThanOrEqual(41)

    const reaDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "rea")!
    expect(reaDef.upstreamUrl).toBe("https://github.com/morluto/rea")
    expect(reaDef.presets.some((p) => p.argsTemplate.includes("--client opencode"))).toBe(true)

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
    // Burp must never probe wrapper scripts (/usr/local/bin/burpsuite) that cause false-positive "WSL2 Kali" status
    expect(burpDef.posixBinaries).toEqual([])
    expect(burpDef.posixKnownPaths).toEqual([
      "/opt/cyberlab-burp/burpsuite.jar",
      "/usr/share/burpsuite/burpsuite.jar",
    ])
    expect(burpDef.installKaliWsl).toContain("portswigger-cdn.net/burp/releases/download?product=desktop")
    expect(burpDef.installKaliWsl).toContain("--i-accept-the-license-agreement")
    expect(burpDef.installKaliWsl).toContain("unzip -tq /tmp/burpsuite_dl.jar")
    expect(burpDef.installKaliWsl).not.toContain('[ -z "$BURP_VER" ] &&')

    // v5.7 verified installers for Strix, HexStrike MCP, PentAGI, PentestGPT/CAI, and VeraCrypt
    const strixDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "strix")!
    expect(strixDef.installKaliWsl).toContain("usestrix/strix/releases/latest")
    expect(strixDef.installKaliWsl).toContain("/usr/local/bin/strix")

    const hexDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "hexstrike-ai")!
    expect(hexDef.installKaliWsl).toContain("flask requests psutil mcp")
    expect(hexDef.installKaliWsl).not.toContain("-r /opt/hexstrike-ai/requirements.txt")
    expect(hexDef.installKaliWsl).toContain("/usr/local/bin/hexstrike-server")

    const pentagiDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "pentagi")!
    expect(pentagiDef.posixBinaries).toEqual(["pentagi"])
    expect(pentagiDef.windowsBinaries).not.toContain("docker.exe")
    expect(pentagiDef.installKaliWsl).toContain("/usr/local/bin/pentagi")
    expect(pentagiDef.installKaliWsl).toContain("PENTAGI_LISTEN_IP=0.0.0.0")
    expect(pentagiDef.managedDaemonPort).toBe(8443)

    // v5.8 Kali 2026.1 defensive / auditing / debugging / methodology slots + v6.0 Netcat & Dirsearch
    for (const newId of [
      "betterleaks",
      "gef",
      "atomic-operator",
      "wpprobe",
      "pentest-copilot",
      "netcat-ncat",
      "dirsearch",
    ]) {
      const found = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === newId)
      expect(found).toBeDefined()
    }
    expect(OFFICIAL_ARSENAL_SLOTS.length).toBeGreaterThanOrEqual(48)

    const netcatDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "netcat-ncat")!
    expect(netcatDef.mcpCapable).toBe(true)
    expect(netcatDef.posixBinaries).toContain("ncat")
    expect(netcatDef.windowsBinaries).toContain("ncat.exe")

    const dirsearchDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "dirsearch")!
    expect(dirsearchDef.mcpCapable).toBe(true)
    expect(dirsearchDef.upstreamUrl).toBe("https://github.com/maurosoria/dirsearch")
    expect(dirsearchDef.installKaliWsl).toContain("/usr/local/bin/dirsearch")

    // v5.8 / v6.0 MCP capability badges & 1-click opencode.json toggle
    const preMcpOverview = await ws.getArsenalOverview(false)
    const mcpCapableSlots = preMcpOverview.slots.filter((s) => s.mcpCapable)
    expect(mcpCapableSlots.length).toBeGreaterThanOrEqual(40)

    const toggleOn = await ws.launchArsenalSlot({
      slotId: "betterleaks",
      action: "run_cli",
      rawArgs: "__toggle_mcp__",
    })
    expect(toggleOn.ok).toBe(true)
    const connectedSlot = toggleOn.overview.slots.find((s) => s.slotId === "betterleaks")!
    expect(connectedSlot.mcpConnected).toBe(true)

    const toggleOff = await ws.launchArsenalSlot({
      slotId: "betterleaks",
      action: "run_cli",
      rawArgs: "__toggle_mcp__",
    })
    expect(toggleOff.ok).toBe(true)
    const disconnectedSlot = toggleOff.overview.slots.find((s) => s.slotId === "betterleaks")!
    expect(disconnectedSlot.mcpConnected).toBe(false)

    // v5.8 CyberChef static HTML server injects in-document zoom hook (never outer iframe CSS transform)
    expect(chefHtml).toContain("data-cyberlab-zoom")

    const caiDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "pentestgpt-cai")!
    expect(caiDef.installKaliWsl).toContain("uv tool install --force --python 3.12 cai-framework")
    expect(caiDef.installKaliWsl).toContain("/usr/local/bin/cai")

    const veracryptDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "veracrypt")!
    expect(veracryptDef.installKaliWsl).toContain("veracrypt/VeraCrypt/releases/latest")
    expect(veracryptDef.installKaliWsl).toContain("/tmp/veracrypt.deb")

    const kaliDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "kali-desktop-stream")!
    expect(kaliDef.posixBinaries).toEqual(["startxfce4"])
    expect(kaliDef.installKaliWsl).toContain("xfce4-terminal")
    expect(kaliDef.installKaliWsl).toContain("kali-themes")

    await ws.launchArsenalSlot({ slotId: "cyberchef", action: "stop_web" })
  }, 25_000)

  test("3. Native Obsidian-compatible .md Vault initializes starter notes, parses #tags & [[WikiLinks]], resolves backlinks, and rejects path traversal", async () => {
    const wsDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v6-vault-"))
    const customObsidianDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v6-custom-obsidian-"))
    tempDirs.push(wsDir, customObsidianDir)
    process.env.CYBERLAB_GLOBAL_CONFIG_DIR = path.join(wsDir, ".global-cfg")

    const ws = new CyberLabWorkspace({
      projectId: "vault-proj-1",
      workspaceRoot: wsDir,
      inMemoryDb: true,
    })
    workspaces.push(ws)

    const initial = await ws.getVaultOverview()
    expect(initial.isCustomPath).toBe(false)
    expect(initial.notes.length).toBeGreaterThanOrEqual(4)
    expect(initial.allTags).toContain("comandos")
    expect(initial.allTags).toContain("bugbounty")

    // Read Comandos/Comandos-Rapidos.md and verify starter note has Netcat & Dirsearch commands + backlink from index
    const cmdNote = await ws.readVaultNote("Comandos/Comandos-Rapidos.md")
    expect(cmdNote.content).toContain("ncat -zv")
    expect(cmdNote.content).toContain("dirsearch -u")
    expect(cmdNote.backlinks).toContain("00-Indice-CyberLab.md")

    // Write a new note with [[WikiLinks]], #tags, and a fenced code block containing fake [[IgnoredLink]] & #ignoredtag
    const written = await ws.writeVaultNote(
      "Recon/Alvo-Acme.md",
      [
        "# Recon Alvo Acme",
        "",
        "#recon #acme",
        "",
        "Usar comandos de [[Comandos-Rapidos]] e registrar em [[Diario-Labs|Diário]].",
        "",
        "```bash",
        "#comentario_bash_nao_e_tag [[LinkDentroDeCodigoIgnorado]]",
        "dirsearch -u https://acme.example -e php,json",
        "```",
      ].join("\n"),
    )
    expect(written.note.tags).toEqual(["acme", "recon"])
    expect(written.note.wikiLinks).toEqual(["Comandos-Rapidos", "Diario-Labs"])

    // Verify Comandos-Rapidos now sees Recon/Alvo-Acme.md as a backlink!
    const updatedCmdNote = await ws.readVaultNote("Comandos/Comandos-Rapidos.md")
    expect(updatedCmdNote.backlinks).toContain("Recon/Alvo-Acme.md")

    // Reject path traversal outside Vault root
    await expect(ws.readVaultNote("../../etc/passwd.md")).rejects.toThrow(/Caminho de nota inválido|escapa da raiz/)
    await expect(ws.writeVaultNote("../escape.md", "# bad")).rejects.toThrow(/Caminho de nota inválido|escapa da raiz/)

    // Delete note cleanly
    const afterDelete = await ws.deleteVaultNote("Recon/Alvo-Acme.md")
    expect(afterDelete.notes.some((n) => n.relativePath === "Recon/Alvo-Acme.md")).toBe(false)

    // Switch to a custom external Obsidian folder and back
    const customOv = await ws.configureVaultRoot(customObsidianDir)
    expect(customOv.isCustomPath).toBe(true)
    expect(customOv.vaultRootDir).toBe(path.resolve(customObsidianDir))
    expect(customOv.notes.length).toBeGreaterThanOrEqual(4)

    const resetOv = await ws.configureVaultRoot(null)
    expect(resetOv.isCustomPath).toBe(false)
    expect(resetOv.vaultRootDir).toBe(path.join(wsDir, "vault"))
  })

  test("4. Burp Suite MCP auto-upgrades legacy remote config and bridges stdio JSON-RPC to PortSwigger Ktor SSE server", async () => {
    const wsDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v6-burp-mcp-"))
    tempDirs.push(wsDir)
    process.env.CYBERLAB_GLOBAL_CONFIG_DIR = path.join(wsDir, ".global-cfg")

    // Seed legacy `type: "remote"` entry in opencode.json
    const openCodeCfgPath = path.join(wsDir, "opencode.json")
    writeFileSync(
      openCodeCfgPath,
      JSON.stringify({
        mcp: {
          servers: {
            "cyberlab-burp-suite": {
              type: "remote",
              url: "http://127.0.0.1:9876/sse",
            },
          },
        },
      }),
      "utf8",
    )

    const ws = new CyberLabWorkspace({
      projectId: "burp-mcp-proj",
      workspaceRoot: wsDir,
      inMemoryDb: true,
    })
    workspaces.push(ws)

    const ov = await ws.getArsenalOverview(false)
    const burpSlot = ov.slots.find((s) => s.slotId === "burp-suite")!
    expect(burpSlot.mcpConnected).toBe(true)

    const migratedDoc = JSON.parse(readFileSync(openCodeCfgPath, "utf8")) as {
      mcp: { servers: Record<string, { type: string; command: string[] }> }
    }
    expect(migratedDoc.mcp.servers["cyberlab-burp-suite"]!.type).toBe("local")
    expect(migratedDoc.mcp.servers["cyberlab-burp-suite"]!.command.join(" ")).toContain("arsenal-mcp-stdio.ts")

    // Spin up a mock PortSwigger Ktor MCP SSE server (`GET /` -> `event: endpoint` + `POST /message?sessionId=...`)
    let activeSseRes: http.ServerResponse | null = null
    const mockBurpServer = http.createServer((req, res) => {
      if (req.method === "GET" && (req.url === "/" || req.url === "/sse")) {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        })
        activeSseRes = res
        res.write("event: endpoint\ndata: /message?sessionId=mock-burp-1\n\n")
        return
      }
      if (req.method === "POST" && req.url?.startsWith("/message")) {
        const chunks: Buffer[] = []
        req.on("data", (c: Buffer) => chunks.push(c))
        req.on("end", () => {
          const msg = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
            id?: number
            method?: string
            params?: { name?: string }
          }
          res.writeHead(202)
          res.end("Accepted")
          if (!activeSseRes || msg.id === undefined) return
          if (msg.method === "initialize") {
            const reply = JSON.stringify({
              jsonrpc: "2.0",
              id: msg.id,
              result: {
                protocolVersion: "2024-11-05",
                capabilities: { tools: {} },
                serverInfo: { name: "burp-suite", version: "1.3.0" },
              },
            })
            activeSseRes.write(`event: message\ndata: ${reply}\n\n`)
          } else if (msg.method === "tools/list") {
            const reply = JSON.stringify({
              jsonrpc: "2.0",
              id: msg.id,
              result: {
                tools: [{ name: "get_proxy_http_history", description: "Displays items within proxy history" }],
              },
            })
            activeSseRes.write(`event: message\ndata: ${reply}\n\n`)
          } else if (msg.method === "tools/call") {
            const reply = JSON.stringify({
              jsonrpc: "2.0",
              id: msg.id,
              result: {
                content: [
                  {
                    type: "text",
                    text: "GET /api/v1/me HTTP/1.1\nAuthorization: Bearer supersecret_burp_token_999",
                  },
                ],
              },
            })
            activeSseRes.write(`event: message\ndata: ${reply}\n\n`)
          }
        })
        return
      }
      res.writeHead(404)
      res.end()
    })

    await new Promise<void>((resolve) => mockBurpServer.listen(0, "127.0.0.1", () => resolve()))
    const addr = mockBurpServer.address() as { port: number }
    const bridgeScript = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../../../cyberlab/mcp/arsenal-mcp-stdio.ts",
    )

    try {
      const rpcInput = [
        JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
        JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "burp_suite_status", arguments: { ensureExtensionDownloaded: false } },
        }),
        JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: { name: "burp_suite_get_proxy_history", arguments: { count: 5, offset: 0 } },
        }),
      ].join("\n") + "\n"

      const stdoutText = await new Promise<string>((resolve, reject) => {
        const child = spawn(
          process.execPath,
          [
            "run",
            bridgeScript,
            "--slot",
            "burp-suite",
            "--workspace",
            wsDir,
            "--burp-port",
            String(addr.port),
          ],
          { stdio: ["pipe", "pipe", "pipe"] },
        )
        let acc = ""
        child.stdout.on("data", (chunk: Buffer) => {
          acc += chunk.toString("utf8")
          const countLines = acc.trim().split(/\r?\n/).filter(Boolean).length
          if (countLines >= 3) {
            child.stdin.end()
          }
        })
        child.on("error", reject)
        child.on("close", () => resolve(acc))
        child.stdin.write(rpcInput)
      })

      const lines = stdoutText.trim().split(/\r?\n/).filter(Boolean)
      expect(lines.length).toBeGreaterThanOrEqual(3)
      const listReply = JSON.parse(lines[0]!) as { result: { tools: Array<{ name: string }> } }
      expect(listReply.result.tools.map((t) => t.name)).toContain("burp_suite_get_proxy_history")
      expect(listReply.result.tools.map((t) => t.name)).toContain("burp_suite_create_repeater_tab")

      const statusReply = JSON.parse(lines[1]!) as { result: { content: Array<{ text: string }> } }
      expect(statusReply.result.content[0]!.text).toContain("CONECTADO")

      const histReply = JSON.parse(lines[2]!) as { result: { content: Array<{ text: string }> } }
      expect(histReply.result.content[0]!.text).toContain("GET /api/v1/me HTTP/1.1")
      expect(histReply.result.content[0]!.text).toContain("[REDACTED")
      expect(histReply.result.content[0]!.text).not.toContain("supersecret_burp_token_999")
    } finally {
      mockBurpServer.close()
    }
  })
})
