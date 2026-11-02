#!/usr/bin/env bun
/**
 * CyberLab OS v6.1.0 — Unified Multiplexed Arsenal MCP Hub & Live GUI Bridge (JSON-RPC 2.0)
 *
 * Runs as a SINGLE lightweight stdio MCP server (`--slot __hub__`) serving ALL enabled `🟢 MCP`
 * Arsenal slots without spawning 45+ separate Bun processes on Windows, while also supporting
 * single-slot mode (`--slot <slotId>`) for backward compatibility.
 *
 * Security & Runtime Guarantees:
 * - Zero shell interpolation on CLI tool execution (`spawnSync` with argv array)
 * - Scope validation against `.cyberlab/scope.json` for external targets
 * - Automatic secret/credential redaction (`redactSensitiveContent`) on all tool outputs
 * - Full Windows path resolution (`arsenal-probe-cache.json` + `%ProgramFiles%`, `%LOCALAPPDATA%`,
 *   WinGet, Scoop, Chocolatey, `{toolsRoot}`) + WSL2 Kali Linux path resolution
 * - Live real-time GUI MCP bridges (Host `127.0.0.1` + WSL2 Kali `127.0.0.1` fallback) for:
 *   1. Burp Suite (`PortSwigger/mcp-server`, `:9876` SSE)
 *   2. NSA Ghidra (`LaurieWired/GhidraMCP`, `:8080` HTTP)
 *   3. JADX-GUI (`zinja-coder/jadx-ai-mcp`, `:8650` HTTP)
 * - Hot-reload via `notifications/tools/list_changed` whenever `.cyberlab/mcp-enabled-slots.json` updates
 */

import { spawnSync } from "node:child_process"
import { existsSync, readFileSync, unwatchFile, watchFile } from "node:fs"
import http from "node:http"
import os from "node:os"
import path from "node:path"
import { OFFICIAL_ARSENAL_SLOTS, type ArsenalSlotDefinition } from "../arsenal/catalog.js"
import { redactSensitiveContent } from "../evidence/provenance.js"

const argv = process.argv.slice(2)
function readArg(flag: string, fallback = ""): string {
  const idx = argv.indexOf(flag)
  return idx !== -1 && argv[idx + 1] ? argv[idx + 1]! : fallback
}

const slotId = readArg("--slot", "__hub__")
const isHubMode = slotId === "__hub__" || slotId === "hub" || slotId === "arsenal"
const workspaceRoot = path.resolve(readArg("--workspace", process.cwd()))
const preferredWslDistro = readArg("--wsl-distro", "kali-linux")
const burpMcpPort =
  Number.parseInt(readArg("--burp-port", process.env.CYBERLAB_BURP_MCP_PORT || "9876"), 10) || 9876
const ghidraMcpPort =
  Number.parseInt(readArg("--ghidra-port", process.env.CYBERLAB_GHIDRA_MCP_PORT || "8080"), 10) || 8080
const jadxMcpPort =
  Number.parseInt(readArg("--jadx-port", process.env.CYBERLAB_JADX_MCP_PORT || "8650"), 10) || 8650

const singleSlotDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === slotId)
const safeToolPrefix = slotId.replace(/[^a-zA-Z0-9_]/g, "_")
const displayName = singleSlotDef?.shortLabel ?? slotId

const PURE_WEB_EMBED_SLOTS = new Set(["cyberchef", "pentagi", "pentest-copilot", "kali-desktop-stream"])

interface ProbeCacheSlotEntry {
  windowsPath: string | null
  wslPath: string | null
  posixPath: string | null
  localHtmlEntry: string | null
}

interface ProbeCacheSnapshot {
  toolsRootDir?: string
  preferredWslDistro?: string
  slotOverrides?: Record<
    string,
    {
      customBinaryPath?: string
      customEmbedUrl?: string
      preferredRuntime?: "auto" | "windows" | "wsl" | "linux_mac" | "web"
    }
  >
  customSlots?: ArsenalSlotDefinition[]
  slots?: Record<string, ProbeCacheSlotEntry>
}

function defaultToolsRoot(): string {
  return process.platform === "win32" ? "C:\\CyberLab-Tools" : path.join(os.homedir(), "CyberLab-Tools")
}

function readProbeCache(): ProbeCacheSnapshot {
  const p = path.join(workspaceRoot, ".cyberlab", "arsenal-probe-cache.json")
  if (!existsSync(p)) return {}
  try {
    return JSON.parse(readFileSync(p, "utf8")) as ProbeCacheSnapshot
  } catch {
    return {}
  }
}

function readEnabledHubSlotIds(): Set<string> {
  const p = path.join(workspaceRoot, ".cyberlab", "mcp-enabled-slots.json")
  if (existsSync(p)) {
    try {
      const parsed = JSON.parse(readFileSync(p, "utf8")) as { enabledSlots?: unknown }
      if (Array.isArray(parsed.enabledSlots)) {
        return new Set(parsed.enabledSlots.filter((x): x is string => typeof x === "string" && x.length > 0))
      }
    } catch {
      // Ignore malformed file
    }
  }
  return new Set(OFFICIAL_ARSENAL_SLOTS.map((s) => s.slotId))
}

function getAllKnownSlotDefinitions(cache: ProbeCacheSnapshot): Map<string, ArsenalSlotDefinition> {
  const map = new Map<string, ArsenalSlotDefinition>()
  for (const def of OFFICIAL_ARSENAL_SLOTS) {
    map.set(def.slotId, def)
  }
  for (const custom of cache.customSlots ?? []) {
    if (custom?.slotId) map.set(custom.slotId, custom)
  }
  return map
}

function expandWindowsCandidatePath(template: string, toolsRoot: string): string {
  const programFiles = process.env.ProgramFiles || "C:\\Program Files"
  const programFilesX86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)"
  const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local")
  const appData = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming")
  const userProfile = process.env.USERPROFILE || os.homedir()

  return template
    .replace(/\{toolsRoot\}/gi, toolsRoot)
    .replace(/%ProgramFiles%/gi, programFiles)
    .replace(/%ProgramFiles\(x86\)%/gi, programFilesX86)
    .replace(/%LOCALAPPDATA%/gi, localAppData)
    .replace(/%APPDATA%/gi, appData)
    .replace(/%USERPROFILE%/gi, userProfile)
}

function expandPosixCandidatePath(template: string, toolsRoot: string): string {
  return template.replace(/\{toolsRoot\}/gi, toolsRoot).replace(/^~(?=\/|$)/, os.homedir())
}

function selectCliCompanionOnWindows(targetSlotId: string, baseResolvedPath: string, isHelpOrVersion: boolean): string {
  const dir = path.dirname(baseResolvedPath)
  if (targetSlotId === "wireshark") {
    const tshark = path.join(dir, "tshark.exe")
    if (existsSync(tshark)) return tshark
  }
  if (targetSlotId === "mitmweb" && !isHelpOrVersion) {
    const mitmdump = path.join(dir, "mitmdump.exe")
    if (existsSync(mitmdump)) return mitmdump
  }
  if (targetSlotId === "ghidra") {
    const hl1 = path.join(dir, "support", "analyzeHeadless.bat")
    if (existsSync(hl1)) return hl1
    const hl2 = path.join(dir, "analyzeHeadless.bat")
    if (existsSync(hl2)) return hl2
  }
  if (targetSlotId === "jadx") {
    for (const cliName of ["jadx.bat", "jadx.exe"]) {
      const candidate = path.join(dir, cliName)
      if (existsSync(candidate)) return candidate
    }
  }
  return baseResolvedPath
}

function selectCliCompanionPosix(targetSlotId: string, basePosixBin: string, isHelpOrVersion: boolean): string {
  if (targetSlotId === "wireshark") return "tshark"
  if (targetSlotId === "mitmweb" && !isHelpOrVersion) return "mitmdump"
  if (targetSlotId === "ghidra") {
    if (basePosixBin.endsWith("/ghidraRun")) {
      return `${path.posix.dirname(basePosixBin)}/support/analyzeHeadless`
    }
    return "analyzeHeadless"
  }
  if (targetSlotId === "jadx") return "jadx"
  return basePosixBin
}

interface ResolvedSlotExecutionTarget {
  slotId: string
  label: string
  kind: "cli" | "web_embed" | "missing"
  runtime: "windows" | "wsl" | "linux_mac" | "web" | "none"
  executablePath: string | null
  detail: string
}

function resolveWindowsExecutableForSlot(
  def: ArsenalSlotDefinition | undefined,
  cache: ProbeCacheSnapshot,
  targetSlotId: string,
): string | null {
  const toolsRoot = cache.toolsRootDir || defaultToolsRoot()
  const overridePath = cache.slotOverrides?.[targetSlotId]?.customBinaryPath
  if (overridePath && existsSync(overridePath)) return overridePath

  const cachedWin = cache.slots?.[targetSlotId]?.windowsPath
  if (cachedWin && existsSync(cachedWin)) return cachedWin

  for (const tmpl of def?.windowsKnownPaths ?? []) {
    const expanded = expandWindowsCandidatePath(tmpl, toolsRoot)
    if (existsSync(expanded)) return expanded
  }

  const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local")
  const userProfile = process.env.USERPROFILE || os.homedir()
  const extraSearchDirs = [
    path.join(localAppData, "Microsoft", "WinGet", "Links"),
    path.join(userProfile, "scoop", "shims"),
    "C:\\ProgramData\\chocolatey\\bin",
    "C:\\Program Files\\mitmproxy\\bin",
    "C:\\Program Files\\Wireshark",
    "C:\\Program Files (x86)\\Nmap",
    "C:\\Program Files\\Nmap",
  ]
  for (const binName of def?.windowsBinaries ?? []) {
    for (const dir of extraSearchDirs) {
      const candidate = path.join(dir, binName.endsWith(".exe") || binName.endsWith(".bat") ? binName : `${binName}.exe`)
      if (existsSync(candidate)) return candidate
      const rawCandidate = path.join(dir, binName)
      if (existsSync(rawCandidate)) return rawCandidate
    }
    const whereRes = spawnSync("where.exe", [binName], {
      encoding: "utf8",
      timeout: 3_000,
      windowsHide: true,
    })
    if (whereRes.status === 0 && whereRes.stdout) {
      const firstLine = whereRes.stdout.trim().split(/\r?\n/)[0]?.trim()
      if (firstLine && existsSync(firstLine)) return firstLine
    }
  }
  return null
}

function batchProbeWslBinaries(slotDefs: ArsenalSlotDefinition[], distro: string): Map<string, string> {
  const found = new Map<string, string>()
  if (slotDefs.length === 0) return found
  const checks: string[] = [
    'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/go/bin:/root/.cargo/bin:/root/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:$HOME/.local/bin"',
  ]
  for (const def of slotDefs) {
    const candidates = [...(def.posixKnownPaths ?? []), ...(def.posixBinaries ?? [])]
    if (candidates.length === 0) continue
    const quotedList = candidates.map((c) => `'${c.replace(/'/g, "'\\''")}'`).join(" ")
    checks.push(
      `for c in ${quotedList}; do if [[ "$c" == /* ]]; then [ -e "$c" ] && { echo "${def.slotId}|$c"; break; }; else p=$(command -v "$c" 2>/dev/null || true); [ -n "$p" ] && { echo "${def.slotId}|$p"; break; }; fi; done`,
    )
  }
  const res = spawnSync("wsl.exe", ["-d", distro, "--", "bash", "-c", checks.join("\n")], {
    encoding: "utf8",
    timeout: 12_000,
    windowsHide: true,
  })
  for (const line of (res.stdout ?? "").split(/\r?\n/)) {
    const sep = line.indexOf("|")
    if (sep > 0) {
      found.set(line.slice(0, sep).trim(), line.slice(sep + 1).trim())
    }
  }
  return found
}

function resolveSlotTarget(
  targetSlotId: string,
  cache: ProbeCacheSnapshot,
  wslBatchFallback?: Map<string, string>,
): ResolvedSlotExecutionTarget {
  const defs = getAllKnownSlotDefinitions(cache)
  const def = defs.get(targetSlotId)
  const label = def?.shortLabel ?? targetSlotId
  const cachedEntry = cache.slots?.[targetSlotId]
  const override = cache.slotOverrides?.[targetSlotId]
  const toolsRoot = cache.toolsRootDir || defaultToolsRoot()

  // Pure HTML/Web-Embed check (e.g., CyberChef HTML file)
  if (cachedEntry?.localHtmlEntry && existsSync(cachedEntry.localHtmlEntry)) {
    return {
      slotId: targetSlotId,
      label,
      kind: "web_embed",
      runtime: "web",
      executablePath: cachedEntry.localHtmlEntry,
      detail: `Web Embed HTML local (${path.basename(cachedEntry.localHtmlEntry)})`,
    }
  }
  if (def?.localStaticDirSubpath) {
    const dirCandidate = path.join(toolsRoot, def.localStaticDirSubpath)
    if (existsSync(dirCandidate)) {
      return {
        slotId: targetSlotId,
        label,
        kind: "web_embed",
        runtime: "web",
        executablePath: dirCandidate,
        detail: `Web Embed HTML local (${dirCandidate})`,
      }
    }
  }
  if (override?.customEmbedUrl && PURE_WEB_EMBED_SLOTS.has(targetSlotId)) {
    return {
      slotId: targetSlotId,
      label,
      kind: "web_embed",
      runtime: "web",
      executablePath: override.customEmbedUrl,
      detail: `Web Embed (${override.customEmbedUrl})`,
    }
  }

  if (process.platform === "win32") {
    const winExe = resolveWindowsExecutableForSlot(def, cache, targetSlotId)
    if (winExe && override?.preferredRuntime !== "wsl") {
      return {
        slotId: targetSlotId,
        label,
        kind: "cli",
        runtime: "windows",
        executablePath: winExe,
        detail: `Windows (${winExe})`,
      }
    }
    const wslHit = cachedEntry?.wslPath || wslBatchFallback?.get(targetSlotId) || null
    if (wslHit) {
      return {
        slotId: targetSlotId,
        label,
        kind: "cli",
        runtime: "wsl",
        executablePath: wslHit,
        detail: `WSL2 Kali (${wslHit})`,
      }
    }
    if (winExe) {
      return {
        slotId: targetSlotId,
        label,
        kind: "cli",
        runtime: "windows",
        executablePath: winExe,
        detail: `Windows (${winExe})`,
      }
    }
    if (PURE_WEB_EMBED_SLOTS.has(targetSlotId)) {
      return {
        slotId: targetSlotId,
        label,
        kind: "web_embed",
        runtime: "none",
        executablePath: null,
        detail: "Aplicação Web Embed (instale pelo botão 'Instalar' na aba Slots)",
      }
    }
    return {
      slotId: targetSlotId,
      label,
      kind: "missing",
      runtime: "none",
      executablePath: null,
      detail: "Aguardando instalação externa",
    }
  }

  // Linux / macOS host
  const posixCached = cachedEntry?.posixPath
  if (posixCached && existsSync(posixCached)) {
    return {
      slotId: targetSlotId,
      label,
      kind: "cli",
      runtime: "linux_mac",
      executablePath: posixCached,
      detail: `POSIX (${posixCached})`,
    }
  }
  for (const tmpl of def?.posixKnownPaths ?? []) {
    const expanded = expandPosixCandidatePath(tmpl, toolsRoot)
    if (existsSync(expanded)) {
      return {
        slotId: targetSlotId,
        label,
        kind: "cli",
        runtime: "linux_mac",
        executablePath: expanded,
        detail: `POSIX (${expanded})`,
      }
    }
  }
  for (const bin of def?.posixBinaries ?? [targetSlotId]) {
    const whichRes = spawnSync("which", [bin], { encoding: "utf8", timeout: 2_500 })
    if (whichRes.status === 0 && whichRes.stdout?.trim()) {
      const p = whichRes.stdout.trim().split(/\r?\n/)[0]!
      return {
        slotId: targetSlotId,
        label,
        kind: "cli",
        runtime: "linux_mac",
        executablePath: p,
        detail: `POSIX (${p})`,
      }
    }
  }

  return {
    slotId: targetSlotId,
    label,
    kind: PURE_WEB_EMBED_SLOTS.has(targetSlotId) ? "web_embed" : "missing",
    runtime: "none",
    executablePath: null,
    detail: "Aguardando instalação externa",
  }
}

function checkTargetAllowedInWorkspaceScope(target: string): { allowed: boolean; reason?: string } {
  const trimmed = target.trim()
  if (!trimmed) return { allowed: true }
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    const candidate = path.resolve(workspaceRoot, trimmed)
    if (candidate.startsWith(workspaceRoot) && existsSync(candidate)) {
      return { allowed: true }
    }
  }
  const localLoopback = /^(https?:\/\/)?(127\.0\.0\.1|localhost)(:\d+)?(\/|$)/i
  if (localLoopback.test(trimmed)) return { allowed: true }

  const scopeRulesPath = path.join(workspaceRoot, ".cyberlab", "scope.json")
  if (!existsSync(scopeRulesPath)) {
    return {
      allowed: false,
      reason: `Alvo externo "${trimmed}" bloqueado: cadastre primeiro o escopo autorizado na aba 'Escopo Bug Bounty' do CyberLab OS.`,
    }
  }
  try {
    const raw = JSON.parse(readFileSync(scopeRulesPath, "utf8")) as {
      allowExternalTargets?: boolean
      allowedHosts?: string[]
      allowedDomains?: string[]
    }
    if (!raw.allowExternalTargets) {
      return {
        allowed: false,
        reason: `Alvos externos estão desativados no escopo atual (.cyberlab/scope.json).`,
      }
    }
    let host = trimmed
    try {
      host = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`).hostname.toLowerCase()
    } catch {
      host = trimmed.split("/")[0]!.split(":")[0]!.toLowerCase()
    }
    const hosts = [...(raw.allowedHosts ?? []), ...(raw.allowedDomains ?? [])].map((h) => h.toLowerCase())
    const matched = hosts.some((rule) => {
      if (rule.startsWith("*.")) {
        const suffix = rule.slice(1)
        return host.endsWith(suffix) || host === rule.slice(2)
      }
      return host === rule
    })
    if (!matched) {
      return {
        allowed: false,
        reason: `Host "${host}" fora da lista de domínios autorizados no escopo ativo.`,
      }
    }
    return { allowed: true }
  } catch {
    return { allowed: false, reason: "Não foi possível validar .cyberlab/scope.json." }
  }
}

function executeResolvedSlotCli(
  targetSlotId: string,
  args: string[],
): { exitCode: number; output: string; resolvedDetail: string } {
  const cache = readProbeCache()
  const distro = cache.preferredWslDistro || preferredWslDistro
  const defs = getAllKnownSlotDefinitions(cache)
  const def = defs.get(targetSlotId)
  const wslFallback =
    process.platform === "win32" && !cache.slots?.[targetSlotId]?.wslPath && def
      ? batchProbeWslBinaries([def], distro)
      : undefined
  const resolved = resolveSlotTarget(targetSlotId, cache, wslFallback)

  if (resolved.kind === "web_embed") {
    return {
      exitCode: 0,
      resolvedDetail: resolved.detail,
      output: `${resolved.label} está instalado como Aplicação Web Embed (${resolved.detail}) — abra pelo painel central do CyberLab OS. Para operações de encode/decode via IA, utilize burp_suite_call_tool (url_encode, url_decode, base64_encode, base64_decode).`,
    }
  }

  const isHelpOrVersion = args.some((a) => a === "--help" || a === "-h" || a === "--version" || a === "-V")

  if (resolved.runtime === "windows" && resolved.executablePath) {
    const exe = selectCliCompanionOnWindows(targetSlotId, resolved.executablePath, isHelpOrVersion)
    const isBat = exe.toLowerCase().endsWith(".bat") || exe.toLowerCase().endsWith(".cmd")
    const res = isBat
      ? spawnSync("cmd.exe", ["/d", "/s", "/c", exe, ...args], {
          cwd: workspaceRoot,
          encoding: "utf8",
          timeout: 60_000,
          windowsHide: true,
        })
      : spawnSync(exe, args, {
          cwd: workspaceRoot,
          encoding: "utf8",
          timeout: 60_000,
          windowsHide: true,
        })
    const combined = `${res.stdout ?? ""}\n${res.stderr ?? ""}`.trim()
    return {
      exitCode: res.status ?? (res.error ? 1 : 0),
      resolvedDetail: `Windows (${exe})`,
      output: redactSensitiveContent(combined || (res.error ? res.error.message : "")).text,
    }
  }

  if (process.platform === "win32") {
    const basePosix = resolved.executablePath || def?.posixBinaries?.[0] || targetSlotId
    const posixCmd = selectCliCompanionPosix(targetSlotId, basePosix, isHelpOrVersion)
    const wslRes = spawnSync(
      "wsl.exe",
      [
        "-d",
        distro,
        "--",
        "env",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/go/bin:/root/.cargo/bin:/root/.local/bin",
        posixCmd,
        ...args,
      ],
      {
        cwd: workspaceRoot,
        encoding: "utf8",
        timeout: 60_000,
        windowsHide: true,
      },
    )
    const combined = `${wslRes.stdout ?? ""}\n${wslRes.stderr ?? ""}`.trim()
    return {
      exitCode: wslRes.status ?? 1,
      resolvedDetail: `WSL2 ${distro} (${posixCmd})`,
      output: redactSensitiveContent(combined).text,
    }
  }

  const posixExe = selectCliCompanionPosix(
    targetSlotId,
    resolved.executablePath || def?.posixBinaries?.[0] || targetSlotId,
    isHelpOrVersion,
  )
  const res = spawnSync(posixExe, args, {
    cwd: workspaceRoot,
    encoding: "utf8",
    timeout: 60_000,
  })
  const combined = `${res.stdout ?? ""}\n${res.stderr ?? ""}`.trim()
  return {
    exitCode: res.status ?? (res.error ? 1 : 0),
    resolvedDetail: `POSIX (${posixExe})`,
    output: redactSensitiveContent(combined || (res.error ? res.error.message : "")).text,
  }
}

// =========================================================================
// GENERIC LOOPBACK + WSL2 HTTP HELPER (FOR GHIDRA :8080 & JADX :8650)
// =========================================================================

function httpRequestLoopback(
  port: number,
  method: "GET" | "POST",
  endpoint: string,
  params: Record<string, unknown> = {},
  timeoutMs = 12_000,
): Promise<{ status: number; text: string }> {
  const cleanParams = Object.entries(params).filter(([, v]) => v !== undefined && v !== null)
  const qs = new URLSearchParams(cleanParams.map(([k, v]): [string, string] => [k, String(v)])).toString()
  const normPath = `/${endpoint.replace(/^\/+/, "")}`
  const isPostForm = method === "POST"
  const reqPath = !isPostForm && qs ? `${normPath}?${qs}` : qs ? `${normPath}?${qs}` : normPath
  const body = isPostForm && qs ? qs : ""

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path: reqPath,
        method,
        headers: {
          Host: `127.0.0.1:${port}`,
          "User-Agent": "CyberLab-MCP-Bridge/1.0",
          ...(body
            ? {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": Buffer.byteLength(body, "utf8"),
              }
            : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on("data", (c: Buffer) => chunks.push(c))
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }),
        )
      },
    )
    req.on("error", reject)
    req.on("timeout", () => req.destroy(new Error(`Timeout HTTP :${port}${normPath}`)))
    if (body) req.write(body)
    req.end()
  })
}

async function callLocalOrWslHttpPlugin(
  port: number,
  method: "GET" | "POST",
  endpoint: string,
  params: Record<string, unknown> = {},
  timeoutMs = 15_000,
): Promise<{ ok: boolean; status?: number; body?: string; error?: string }> {
  try {
    const hostRes = await httpRequestLoopback(port, method, endpoint, params, timeoutMs)
    if (hostRes.status >= 200 && hostRes.status < 500) {
      return { ok: hostRes.status < 400, status: hostRes.status, body: hostRes.text }
    }
  } catch (err) {
    if (process.platform !== "win32") {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  }

  if (process.platform === "win32") {
    const py = `
import http.client, json, sys, urllib.parse
port = int(sys.argv[1])
method = sys.argv[2]
endpoint = "/" + sys.argv[3].lstrip("/")
params = {k: str(v) for k, v in json.loads(sys.argv[4]).items() if v is not None}
qs = urllib.parse.urlencode(params)
path = endpoint + (("?" + qs) if qs else "")
body = qs.encode("utf-8") if method == "POST" and qs else None
headers = {"Host": f"127.0.0.1:{port}", "User-Agent": "CyberLab-MCP-Bridge/1.0"}
if body is not None:
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Content-Length"] = str(len(body))
try:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    txt = r.read().decode("utf-8", "replace")
    print(json.dumps({"ok": 200 <= r.status < 400, "status": r.status, "body": txt}))
except Exception as e:
    print(json.dumps({"ok": False, "error": str(e)}))
`
    const wslRes = spawnSync(
      "wsl.exe",
      [
        "-d",
        preferredWslDistro,
        "--",
        "python3",
        "-c",
        py,
        String(port),
        method,
        endpoint,
        JSON.stringify(params),
      ],
      { encoding: "utf8", timeout: timeoutMs + 5_000, windowsHide: true },
    )
    const last = (wslRes.stdout ?? "").trim().split(/\r?\n/).pop() ?? ""
    try {
      return JSON.parse(last) as { ok: boolean; status?: number; body?: string; error?: string }
    } catch {
      return { ok: false, error: (wslRes.stderr || last || `Porta :${port} indisponível`).trim() }
    }
  }

  return { ok: false, error: `Porta :${port} indisponível` }
}

// =========================================================================
// BURP SUITE MCP (:9876 SSE) NATIVE BRIDGE (HOST LOOPBACK + WSL2 FALLBACK)
// =========================================================================

function postJsonHttp(targetUrl: URL, payload: unknown): Promise<{ status: number; text: string }> {
  const body = JSON.stringify(payload)
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: targetUrl.hostname,
        port: targetUrl.port || 80,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        method: "POST",
        headers: {
          Host: `${targetUrl.hostname}:${targetUrl.port || 80}`,
          "User-Agent": "CyberLab-MCP-Bridge/1.0",
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body, "utf8"),
        },
        timeout: 15_000,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on("data", (c: Buffer) => chunks.push(c))
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }),
        )
      },
    )
    req.on("error", reject)
    req.on("timeout", () => {
      req.destroy(new Error("HTTP POST timeout"))
    })
    req.write(body)
    req.end()
  })
}

function callBurpSseOverHostPath(
  ssePath: string,
  rpcMethod: string,
  rpcParams: Record<string, unknown>,
  timeoutMs = 15_000,
): Promise<unknown> {
  const baseUrl = `http://127.0.0.1:${burpMcpPort}`
  return new Promise((resolve, reject) => {
    let settled = false
    let postEndpoint: URL | null = null
    let initSent = false
    let callSent = false
    let sseBuf = ""

    const finish = (err: Error | null, val?: unknown) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        sseReq.destroy()
      } catch {
        // Ignore
      }
      if (err) reject(err)
      else resolve(val)
    }

    const timer = setTimeout(() => {
      finish(new Error(`Timeout aguardando resposta SSE do Burp MCP em ${baseUrl}${ssePath}`))
    }, timeoutMs)

    const sseReq = http.request(
      {
        hostname: "127.0.0.1",
        port: burpMcpPort,
        path: ssePath,
        method: "GET",
        headers: {
          Host: `127.0.0.1:${burpMcpPort}`,
          Accept: "text/event-stream",
          "Cache-Control": "no-cache",
          "User-Agent": "CyberLab-MCP-Bridge/1.0",
        },
      },
      (res) => {
        if ((res.statusCode ?? 0) !== 200) {
          finish(new Error(`HTTP ${res.statusCode} em ${baseUrl}${ssePath}`))
          return
        }

        res.on("data", (chunk: Buffer) => {
          sseBuf += chunk.toString("utf8").replace(/\r\n/g, "\n")
          let boundaryIdx: number
          while ((boundaryIdx = sseBuf.indexOf("\n\n")) !== -1) {
            const rawBlock = sseBuf.slice(0, boundaryIdx)
            sseBuf = sseBuf.slice(boundaryIdx + 2)
            let eventName = "message"
            const dataLines: string[] = []
            for (const line of rawBlock.split("\n")) {
              if (line.startsWith("event:")) {
                eventName = line.slice(6).trim()
              } else if (line.startsWith("data:")) {
                dataLines.push(line.slice(5).trimStart())
              }
            }
            const dataStr = dataLines.join("\n").trim()
            if (!dataStr) continue

            if (eventName === "endpoint" && !initSent) {
              initSent = true
              try {
                postEndpoint = new URL(dataStr, `${baseUrl}/`)
              } catch (e) {
                finish(e instanceof Error ? e : new Error(String(e)))
                return
              }
              void postJsonHttp(postEndpoint, {
                jsonrpc: "2.0",
                id: 1,
                method: "initialize",
                params: {
                  protocolVersion: "2024-11-05",
                  capabilities: {},
                  clientInfo: { name: "cyberlab-burp-bridge", version: "6.1.0" },
                },
              }).catch((err) => finish(err instanceof Error ? err : new Error(String(err))))
              continue
            }

            if (eventName === "message") {
              let parsed: { id?: number; result?: unknown; error?: { message?: string } }
              try {
                parsed = JSON.parse(dataStr)
              } catch {
                continue
              }
              if (parsed.id === 1 && postEndpoint && !callSent) {
                callSent = true
                void (async () => {
                  try {
                    await postJsonHttp(postEndpoint!, {
                      jsonrpc: "2.0",
                      method: "notifications/initialized",
                    })
                    await postJsonHttp(postEndpoint!, {
                      jsonrpc: "2.0",
                      id: 2,
                      method: rpcMethod,
                      params: rpcParams,
                    })
                  } catch (err) {
                    finish(err instanceof Error ? err : new Error(String(err)))
                  }
                })()
                continue
              }
              if (parsed.id === 2) {
                if (parsed.error) {
                  finish(new Error(parsed.error.message ?? JSON.stringify(parsed.error)))
                } else {
                  finish(null, parsed.result)
                }
                return
              }
            }
          }
        })

        res.on("error", (err) => finish(err))
        res.on("end", () => {
          if (!settled) finish(new Error("Stream SSE encerrado antes da resposta JSON-RPC"))
        })
      },
    )

    sseReq.on("error", (err) => finish(err))
    sseReq.end()
  })
}

function callBurpSseInsideWsl(
  rpcMethod: string,
  rpcParams: Record<string, unknown>,
  timeoutSec = 12,
): { ok: boolean; result?: unknown; error?: string } {
  const pyScript = `
import http.client, json, sys, urllib.parse

port = int(sys.argv[1])
method = sys.argv[2]
params = json.loads(sys.argv[3])
tsec = int(sys.argv[4])

def post_msg(path_and_query, payload):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=tsec)
    body = json.dumps(payload).encode("utf-8")
    c.request("POST", path_and_query, body=body, headers={
        "Host": f"127.0.0.1:{port}",
        "User-Agent": "CyberLab-MCP-Bridge/1.0",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    c.getresponse().read()
    c.close()

last_err = "no response"
for sse_path in ("/", "/sse"):
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=tsec)
        conn.request("GET", sse_path, headers={
            "Host": f"127.0.0.1:{port}",
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "User-Agent": "CyberLab-MCP-Bridge/1.0",
        })
        resp = conn.getresponse()
        if resp.status != 200:
            last_err = f"HTTP {resp.status} on {sse_path}"
            conn.close()
            continue
        ev_name = "message"
        data_lines = []
        post_target = None
        while True:
            raw_line = resp.fp.readline()
            if not raw_line:
                break
            line = raw_line.decode("utf-8", "replace").rstrip("\\r\\n")
            if line == "":
                data_str = "\\n".join(data_lines).strip()
                data_lines = []
                cur_ev = ev_name
                ev_name = "message"
                if not data_str:
                    continue
                if cur_ev == "endpoint" and post_target is None:
                    parsed_u = urllib.parse.urljoin(f"http://127.0.0.1:{port}/", data_str)
                    u = urllib.parse.urlsplit(parsed_u)
                    post_target = u.path + (("?" + u.query) if u.query else "")
                    post_msg(post_target, {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "cyberlab-burp-wsl-bridge", "version": "6.1.0"},
                        },
                    })
                elif cur_ev == "message":
                    msg = json.loads(data_str)
                    if msg.get("id") == 1 and post_target:
                        post_msg(post_target, {"jsonrpc": "2.0", "method": "notifications/initialized"})
                        post_msg(post_target, {"jsonrpc": "2.0", "id": 2, "method": method, "params": params})
                    elif msg.get("id") == 2:
                        conn.close()
                        if "error" in msg:
                            print(json.dumps({"ok": False, "error": msg["error"]}))
                        else:
                            print(json.dumps({"ok": True, "result": msg.get("result")}))
                        sys.exit(0)
            elif line.startswith("event:"):
                ev_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
    except Exception as exc:
        last_err = str(exc)

print(json.dumps({"ok": False, "error": last_err}))
`
  const wslRes = spawnSync(
    "wsl.exe",
    [
      "-d",
      preferredWslDistro,
      "--",
      "python3",
      "-c",
      pyScript,
      String(burpMcpPort),
      rpcMethod,
      JSON.stringify(rpcParams),
      String(timeoutSec),
    ],
    {
      encoding: "utf8",
      timeout: (timeoutSec + 8) * 1000,
      windowsHide: true,
    },
  )
  const out = (wslRes.stdout ?? "").trim().split(/\r?\n/).pop() ?? ""
  try {
    const parsed = JSON.parse(out) as { ok: boolean; result?: unknown; error?: unknown }
    if (parsed.ok) return { ok: true, result: parsed.result }
    return {
      ok: false,
      error: typeof parsed.error === "string" ? parsed.error : JSON.stringify(parsed.error),
    }
  } catch {
    return { ok: false, error: (wslRes.stderr || out || "Falha ao conectar via WSL2").trim() }
  }
}

async function callBurpMcpRpc(
  rpcMethod: string,
  rpcParams: Record<string, unknown>,
  fastProbe = false,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  let hostErr = ""
  const hostTimeout = fastProbe ? 2_000 : 8_000
  for (const ssePath of ["/", "/sse"]) {
    try {
      const result = await callBurpSseOverHostPath(ssePath, rpcMethod, rpcParams, hostTimeout)
      return { ok: true, result }
    } catch (err) {
      hostErr = err instanceof Error ? err.message : String(err)
    }
  }

  if (process.platform === "win32") {
    const wslAttempt = callBurpSseInsideWsl(rpcMethod, rpcParams, fastProbe ? 3 : 12)
    if (wslAttempt.ok) return wslAttempt
    return {
      ok: false,
      error: `${hostErr} | WSL2: ${wslAttempt.error ?? "indisponível"}`,
    }
  }

  return { ok: false, error: hostErr }
}

function ensureBurpExtensionJarDownloadedInWsl(): string {
  const script = [
    "mkdir -p /opt/cyberlab-burp",
    "if [ ! -s /opt/cyberlab-burp/burp-mcp-all.jar ]; then curl -fsSL --max-time 25 https://github.com/PortSwigger/mcp-server/releases/latest/download/burp-mcp-all.jar -o /opt/cyberlab-burp/burp-mcp-all.jar && chmod 644 /opt/cyberlab-burp/burp-mcp-all.jar; fi",
    "if [ -s /opt/cyberlab-burp/burp-mcp-all.jar ]; then echo READY:/opt/cyberlab-burp/burp-mcp-all.jar; else echo MISSING; fi",
  ].join(" && ")

  if (process.platform === "win32") {
    const res = spawnSync("wsl.exe", ["-d", preferredWslDistro, "--", "bash", "-c", script], {
      encoding: "utf8",
      timeout: 30_000,
      windowsHide: true,
    })
    return `${res.stdout ?? ""}\n${res.stderr ?? ""}`.trim()
  }
  if (existsSync("/opt/cyberlab-burp/burp-mcp-all.jar")) {
    return "READY:/opt/cyberlab-burp/burp-mcp-all.jar"
  }
  return "MISSING"
}

function ensureGhidraMcpExtensionInstalled(): string {
  const script = [
    "mkdir -p /opt/cyberlab-ghidra-mcp",
    'if [ ! -s /opt/cyberlab-ghidra-mcp/GhidraMCP-release.zip ]; then GMCP_URL=$(curl -fsSL --max-time 20 https://api.github.com/repos/LaurieWired/GhidraMCP/releases/latest | jq -r ".assets[0].browser_download_url"); [ -n "$GMCP_URL" ] && [ "$GMCP_URL" != "null" ] && curl -fsSL --max-time 30 "$GMCP_URL" -o /opt/cyberlab-ghidra-mcp/GhidraMCP-release.zip && unzip -oq /opt/cyberlab-ghidra-mcp/GhidraMCP-release.zip -d /opt/cyberlab-ghidra-mcp; fi',
    'EXT_ZIP=$(find /opt/cyberlab-ghidra-mcp -maxdepth 2 -iname "*GhidraMCP*.zip" ! -name "GhidraMCP-release.zip" 2>/dev/null | head -n 1)',
    'if [ -n "$EXT_ZIP" ]; then for GEXT in /usr/share/ghidra/Ghidra/Extensions /opt/ghidra/Ghidra/Extensions; do [ -d "$GEXT" ] && unzip -oq "$EXT_ZIP" -d "$GEXT/" 2>/dev/null || true; done; echo "READY:$EXT_ZIP"; else echo "MISSING"; fi',
  ].join(" && ")

  if (process.platform === "win32") {
    const res = spawnSync("wsl.exe", ["-d", preferredWslDistro, "--", "bash", "-c", script], {
      encoding: "utf8",
      timeout: 40_000,
      windowsHide: true,
    })
    return `${res.stdout ?? ""}\n${res.stderr ?? ""}`.trim()
  }
  return existsSync("/opt/cyberlab-ghidra-mcp") ? "READY:/opt/cyberlab-ghidra-mcp" : "MISSING"
}

function ensureJadxAiMcpPluginInstalled(): string {
  if (process.platform === "win32") {
    const cache = readProbeCache()
    const winJadx = resolveWindowsExecutableForSlot(
      OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === "jadx"),
      cache,
      "jadx",
    )
    if (winJadx) {
      const cliJadx = selectCliCompanionOnWindows("jadx", winJadx, false)
      const isBat = cliJadx.toLowerCase().endsWith(".bat")
      const r = isBat
        ? spawnSync("cmd.exe", ["/d", "/s", "/c", cliJadx, "plugins", "--install", "github:zinja-coder:jadx-ai-mcp"], {
            encoding: "utf8",
            timeout: 35_000,
            windowsHide: true,
          })
        : spawnSync(cliJadx, ["plugins", "--install", "github:zinja-coder:jadx-ai-mcp"], {
            encoding: "utf8",
            timeout: 35_000,
            windowsHide: true,
          })
      if (r.status === 0) return `READY:Windows (${cliJadx})`
    }
    const wslRes = spawnSync(
      "wsl.exe",
      [
        "-d",
        preferredWslDistro,
        "--",
        "bash",
        "-c",
        'command -v jadx >/dev/null 2>&1 && jadx plugins --install "github:zinja-coder:jadx-ai-mcp" && echo READY:WSL2 || echo MISSING',
      ],
      { encoding: "utf8", timeout: 35_000, windowsHide: true },
    )
    return `${wslRes.stdout ?? ""}\n${wslRes.stderr ?? ""}`.trim()
  }
  const r = spawnSync("jadx", ["plugins", "--install", "github:zinja-coder:jadx-ai-mcp"], {
    encoding: "utf8",
    timeout: 35_000,
  })
  return r.status === 0 ? "READY:POSIX" : "MISSING"
}

function extractBurpResultText(rawResult: unknown): string {
  if (!rawResult || typeof rawResult !== "object") {
    return redactSensitiveContent(String(rawResult ?? "")).text
  }
  const obj = rawResult as { content?: Array<{ type?: string; text?: string }> }
  if (Array.isArray(obj.content)) {
    const joined = obj.content
      .map((item) => (typeof item?.text === "string" ? item.text : JSON.stringify(item)))
      .join("\n")
    return redactSensitiveContent(joined).text
  }
  return redactSensitiveContent(JSON.stringify(rawResult, null, 2)).text
}

function offlineBurpGuideMessage(detail?: string): string {
  return [
    `⚠️ O Burp Suite ainda não está respondendo na porta MCP :${burpMcpPort} (${detail ?? "conexão recusada"}).`,
    "",
    "Como ativar em 30 segundos dentro do CyberLab OS (sem precisar reiniciar o OpenCode):",
    "1. Na barra esquerda ('Slots'), clique em 'Burp Suite' e depois em '🖥 Abrir Aqui Dentro do CyberLab' (o CyberLab já baixa automaticamente '/opt/cyberlab-burp/burp-mcp-all.jar').",
    "2. Dentro da janela do Burp Suite, abra 'Extensions' -> 'Installed' e marque 'Loaded' em 'Burp MCP Server' (ou clique em 'Add' -> '/opt/cyberlab-burp/burp-mcp-all.jar').",
    "3. Pronto! Basta pedir novamente aqui no chat que a conexão será feita ao vivo.",
  ].join("\n")
}

// =========================================================================
// MCP TOOL DEFINITIONS
// =========================================================================

const BURP_MCP_TOOLS = [
  {
    name: "burp_suite_status",
    description:
      "Verifica se o servidor MCP oficial do Burp Suite (:9876) está online (no host ou dentro do Kali WSL2), garante o download automático de '/opt/cyberlab-burp/burp-mcp-all.jar' e lista todas as ferramentas ativas do Burp.",
    inputSchema: {
      type: "object",
      properties: {
        ensureExtensionDownloaded: {
          type: "boolean",
          description: "Se true (padrão), baixa automaticamente burp-mcp-all.jar em /opt/cyberlab-burp/ caso ainda não exista.",
        },
      },
    },
  },
  {
    name: "burp_suite_get_proxy_history",
    description:
      "Lê o histórico HTTP capturado pelo Proxy do Burp Suite (com suporte opcional a filtro Regex e redação automática de segredos).",
    inputSchema: {
      type: "object",
      properties: {
        count: { type: "number", description: "Quantidade de itens para retornar (padrão: 20)" },
        offset: { type: "number", description: "Índice inicial para paginação (padrão: 0)" },
        regex: { type: "string", description: "Expressão regular opcional para filtrar URLs/requests/responses" },
      },
    },
  },
  {
    name: "burp_suite_send_http1_request",
    description:
      "Envia uma requisição HTTP/1.1 bruta diretamente pelo motor do Burp Suite (validada pela Trava de Escopo Bug Bounty do CyberLab OS) e retorna a resposta completa.",
    inputSchema: {
      type: "object",
      required: ["targetHostname", "targetPort", "usesHttps", "content"],
      properties: {
        targetHostname: { type: "string", description: "Hostname do alvo autorizado no escopo" },
        targetPort: { type: "number", description: "Porta TCP de destino (ex.: 443 ou 80)" },
        usesHttps: { type: "boolean", description: "true para HTTPS/TLS, false para HTTP" },
        content: { type: "string", description: "Requisição HTTP/1.1 completa (headers + linha em branco + body opcional)" },
      },
    },
  },
  {
    name: "burp_suite_create_repeater_tab",
    description:
      "Cria uma nova aba no Repeater dentro da janela aberta do Burp Suite com a requisição HTTP especificada.",
    inputSchema: {
      type: "object",
      required: ["targetHostname", "targetPort", "usesHttps", "content"],
      properties: {
        tabName: { type: "string", description: "Título opcional da aba no Repeater" },
        targetHostname: { type: "string", description: "Hostname do alvo autorizado" },
        targetPort: { type: "number", description: "Porta TCP (ex.: 443 ou 80)" },
        usesHttps: { type: "boolean", description: "true para HTTPS, false para HTTP" },
        content: { type: "string", description: "Requisição HTTP/1.1 bruta" },
      },
    },
  },
  {
    name: "burp_suite_send_to_intruder",
    description: "Envia uma requisição HTTP para uma nova aba do Intruder dentro do Burp Suite.",
    inputSchema: {
      type: "object",
      required: ["targetHostname", "targetPort", "usesHttps", "content"],
      properties: {
        tabName: { type: "string", description: "Título opcional da aba no Intruder" },
        targetHostname: { type: "string", description: "Hostname do alvo autorizado" },
        targetPort: { type: "number", description: "Porta TCP" },
        usesHttps: { type: "boolean", description: "true para HTTPS, false para HTTP" },
        content: { type: "string", description: "Requisição HTTP/1.1 bruta" },
      },
    },
  },
  {
    name: "burp_suite_set_intercept",
    description: "Liga ou desliga o botão 'Intercept is on/off' do Proxy do Burp Suite.",
    inputSchema: {
      type: "object",
      required: ["intercepting"],
      properties: {
        intercepting: { type: "boolean", description: "true para ligar Intercept, false para desligar" },
      },
    },
  },
  {
    name: "burp_suite_call_tool",
    description:
      "Executa qualquer ferramenta adicional exposta pela extensão oficial Burp MCP Server (:9876), como send_http2_request, create_repeater_tab_http2, get_proxy_websocket_history, get_organizer_items, get_active_editor_contents, output_project_options, url_encode ou base64_encode.",
    inputSchema: {
      type: "object",
      required: ["toolName"],
      properties: {
        toolName: { type: "string", description: "Nome exato da tool na extensão Burp MCP Server" },
        toolArgs: { type: "object", description: "Objeto JSON de argumentos para a tool" },
      },
    },
  },
]

const GHIDRA_MCP_TOOLS = [
  {
    name: "ghidra_mcp_status",
    description:
      "Verifica se a extensão oficial LaurieWired/GhidraMCP (:8080) está ativa na janela aberta do Ghidra (Host ou WSL2), baixa/pré-instala automaticamente o plugin em /opt/cyberlab-ghidra-mcp/ caso falte, e informa também o status do analyzeHeadless.",
    inputSchema: {
      type: "object",
      properties: {
        ensureExtensionInstalled: {
          type: "boolean",
          description: "Se true (padrão), garante o download e descompactação automática do GhidraMCP nas Extensions do Ghidra.",
        },
      },
    },
  },
  {
    name: "ghidra_mcp_decompile",
    description:
      "Descompila uma função C/C++ diretamente do binário aberto na GUI do Ghidra (via plugin GhidraMCP :8080) por nome da função ou endereço hexadecimal.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Nome da função (ex.: main, check_license)" },
        address: { type: "string", description: "Endereço hexadecimal da função (ex.: 0x004011a0)" },
      },
    },
  },
  {
    name: "ghidra_mcp_call",
    description:
      "Chama qualquer endpoint em tempo real do plugin LaurieWired/GhidraMCP (:8080) no Ghidra aberto: program_info, functions, classes, imports, exports, strings, data, segments, current_function, current_address, disassemble_function, xrefs_to, xrefs_from, read_memory, rename_function, rename_data, set_function_prototype, set_decompiler_comment.",
    inputSchema: {
      type: "object",
      required: ["endpoint"],
      properties: {
        endpoint: { type: "string", description: "Endpoint do GhidraMCP (ex.: functions, strings, imports, rename_function)" },
        method: { type: "string", enum: ["GET", "POST"], description: "GET para leitura (padrão), POST para renomear/comentar" },
        params: { type: "object", description: "Parâmetros query/form (ex.: { offset: 0, limit: 50, filter: 'crypt' })" },
      },
    },
  },
]

const JADX_MCP_TOOLS = [
  {
    name: "jadx_mcp_status",
    description:
      "Verifica se o plugin oficial zinja-coder/jadx-ai-mcp (:8650) está ativo no JADX-GUI aberto (Host ou WSL2) e instala automaticamente o plugin via 'jadx plugins --install github:zinja-coder:jadx-ai-mcp' caso ainda não esteja instalado.",
    inputSchema: {
      type: "object",
      properties: {
        ensurePluginInstalled: {
          type: "boolean",
          description: "Se true (padrão), instala automaticamente o plugin jadx-ai-mcp caso falte.",
        },
      },
    },
  },
  {
    name: "jadx_mcp_get_class_source",
    description:
      "Obtém o código-fonte Java ou Smali descompilado da classe atualmente selecionada no JADX-GUI (sem argumentos) ou de qualquer classe específica do APK aberto.",
    inputSchema: {
      type: "object",
      properties: {
        className: {
          type: "string",
          description: "Nome completo da classe Java (ex.: com.acme.app.MainActivity). Se omitido, retorna a classe aberta atualmente na GUI.",
        },
        smali: { type: "boolean", description: "Se true, retorna Smali em vez de Java" },
      },
    },
  },
  {
    name: "jadx_mcp_call",
    description:
      "Chama qualquer endpoint em tempo real do plugin JADX-AI-MCP (:8650) no JADX-GUI aberto: current-class, selected-text, all-classes, class-source, smali-of-class, methods-of-class, fields-of-class, method-by-name, search-classes-by-keyword, manifest, strings, main-activity, main-application-classes-names, package-tree, rename-class, rename-method, rename-field.",
    inputSchema: {
      type: "object",
      required: ["endpoint"],
      properties: {
        endpoint: { type: "string", description: "Endpoint do JADX-AI-MCP (ex.: manifest, strings, all-classes)" },
        method: { type: "string", enum: ["GET", "POST"], description: "GET (padrão) ou POST (ex.: cache-clear)" },
        params: { type: "object", description: "Parâmetros (ex.: { class_name: 'com.app.Auth', offset: 0, count: 50 })" },
      },
    },
  },
]

function buildHubToolsList() {
  const enabled = readEnabledHubSlotIds()
  const enabledSorted = Array.from(enabled).sort()
  const slotListPreview =
    enabledSorted.length > 0 ? enabledSorted.join(", ") : "nenhum slot habilitado no momento"

  const hubCoreTools = [
    {
      name: "arsenal_mcp_status",
      description: `Verifica instantaneamente o status real de TODAS as ${enabledSorted.length} ferramentas com botão 🟢 MCP ativo no CyberLab OS (${slotListPreview}) — incluindo servidores GUI em tempo real (Burp :9876, Ghidra :8080, JADX :8650), binários Windows (C:\\Program Files\\...), binários Kali WSL2 e aplicações Web Embed (CyberChef). SEMPRE chame esta tool primeiro quando o usuário pedir para testar/listar conexões MCP!`,
      inputSchema: {
        type: "object",
        properties: {
          onlyInstalled: {
            type: "boolean",
            description: "Se true, oculta da tabela ferramentas ainda não instaladas no disco.",
          },
        },
      },
    },
    {
      name: "arsenal_run_tool",
      description: `Executa qualquer ferramenta CLI/scanner habilitada com 🟢 MCP no CyberLab OS (${slotListPreview}) resolvendo automaticamente caminhos completos do Windows (C:\\Program Files\\..., WinGet, Scoop) ou Kali WSL2, com proteção da Trava de Escopo Bug Bounty e redação SHA-256 de segredos.`,
      inputSchema: {
        type: "object",
        required: ["slotId"],
        properties: {
          slotId: {
            type: "string",
            description: `ID do slot habilitado (ex.: nuclei, nmap, ffuf, httpx, sqlmap, dirsearch, netcat-ncat, mitmweb, wireshark, caido, ghidra, jadx, subfinder, dalfox, katana, gitleaks-trufflehog, betterleaks, semgrep, trivy, keyhunter, wpprobe)`,
          },
          target: {
            type: "string",
            description: "Alvo opcional (arquivo local do workspace ou domínio/URL autorizado no escopo Bug Bounty)",
          },
          args: {
            type: "array",
            items: { type: "string" },
            description: "Lista de argumentos CLI seguros (sem interpolação de shell), ex.: ['-u', 'https://alvo.exemplo', '-silent']",
          },
        },
      },
    },
    {
      name: "arsenal_tool_help",
      description:
        "Consulta a versão, caminho resolvido (Windows ou WSL2) e flags (--help / --version) de qualquer ferramenta habilitada com 🟢 MCP.",
      inputSchema: {
        type: "object",
        required: ["slotId"],
        properties: {
          slotId: { type: "string", description: "ID do slot habilitado (ex.: nuclei, mitmweb, wireshark, dirsearch)" },
        },
      },
    },
  ]

  const extraGuiTools: Array<Record<string, unknown>> = []
  if (enabled.has("burp-suite")) extraGuiTools.push(...BURP_MCP_TOOLS)
  if (enabled.has("ghidra")) extraGuiTools.push(...GHIDRA_MCP_TOOLS)
  if (enabled.has("jadx")) extraGuiTools.push(...JADX_MCP_TOOLS)

  return [...hubCoreTools, ...extraGuiTools]
}

// =========================================================================
// JSON-RPC FRAMING & HANDLERS
// =========================================================================

interface JsonRpcRequest {
  jsonrpc: "2.0"
  id?: string | number | null
  method: string
  params?: Record<string, unknown>
}

let useContentLengthFraming = false
let initializedClient = false

function sendResponse(payload: Record<string, unknown>) {
  const json = JSON.stringify(payload)
  if (useContentLengthFraming) {
    const byteLen = Buffer.byteLength(json, "utf8")
    process.stdout.write(`Content-Length: ${byteLen}\r\n\r\n${json}`)
  } else {
    process.stdout.write(`${json}\n`)
  }
}

async function handleArsenalStatusCall(
  id: string | number | null,
  callArgs: Record<string, unknown>,
): Promise<void> {
  const enabled = readEnabledHubSlotIds()
  const cache = readProbeCache()
  const distro = cache.preferredWslDistro || preferredWslDistro
  const defs = getAllKnownSlotDefinitions(cache)

  // Batch-probe WSL2 in 1 single call only for enabled slots lacking cached paths
  const needsWslProbe: ArsenalSlotDefinition[] = []
  if (process.platform === "win32") {
    for (const sId of enabled) {
      const c = cache.slots?.[sId]
      if (!c?.windowsPath && !c?.wslPath && !c?.localHtmlEntry) {
        const d = defs.get(sId)
        if (d) needsWslProbe.push(d)
      }
    }
  }
  const wslBatch = needsWslProbe.length > 0 ? batchProbeWslBinaries(needsWslProbe, distro) : undefined

  // Probe live GUI MCP servers in parallel if enabled
  const [burpProbe, ghidraProbe, jadxProbe] = await Promise.all([
    enabled.has("burp-suite")
      ? callBurpMcpRpc("tools/list", {}, true)
      : Promise.resolve<{ ok: boolean; result?: unknown; error?: string }>({ ok: false, error: "desativado" }),
    enabled.has("ghidra")
      ? callLocalOrWslHttpPlugin(ghidraMcpPort, "GET", "health", {}, 2_000)
      : Promise.resolve({ ok: false, error: "desativado" }),
    enabled.has("jadx")
      ? callLocalOrWslHttpPlugin(jadxMcpPort, "GET", "cache-stats", {}, 2_000)
      : Promise.resolve({ ok: false, error: "desativado" }),
  ])

  const liveGuiLines: string[] = []
  if (enabled.has("burp-suite")) {
    const toolCount =
      ((burpProbe.result as { tools?: unknown[] } | undefined)?.tools ?? []).length
    liveGuiLines.push(
      burpProbe.ok
        ? `- 🟢 **Burp Suite** (:9876 SSE) — CONECTADO AO VIVO (${toolCount} tools ativas: Proxy History, Repeater, Intruder, Intercept, Encoder)`
        : `- 🟡 **Burp Suite** (:9876 SSE) — Extensão pronta, aguardando abrir a janela do Burp Suite`,
    )
  }
  if (enabled.has("ghidra")) {
    const ghResolved = resolveSlotTarget("ghidra", cache, wslBatch)
    liveGuiLines.push(
      ghidraProbe.ok
        ? `- 🟢 **Ghidra (GhidraMCP :${ghidraMcpPort})** — GUI CONECTADA AO VIVO + Headless (${ghResolved.detail})`
        : `- 🟢 **Ghidra** — CLI Headless pronto (${ghResolved.detail}); para GUI ao vivo (:${ghidraMcpPort}) abra o Ghidra com GhidraMCPPlugin ativo`,
    )
  }
  if (enabled.has("jadx")) {
    const jxResolved = resolveSlotTarget("jadx", cache, wslBatch)
    liveGuiLines.push(
      jadxProbe.ok
        ? `- 🟢 **JADX (JADX-AI-MCP :${jadxMcpPort})** — GUI CONECTADA AO VIVO + CLI (${jxResolved.detail})`
        : `- 🟢 **JADX** — CLI pronto (${jxResolved.detail}); plugin JADX-AI-MCP (:${jadxMcpPort}) conecta automaticamente ao abrir um APK no jadx-gui`,
    )
  }

  const readyCliLines: string[] = []
  const readyWebLines: string[] = []
  const pendingInstallLines: string[] = []

  for (const sId of Array.from(enabled).sort()) {
    if (sId === "burp-suite" || sId === "ghidra" || sId === "jadx") continue
    const r = resolveSlotTarget(sId, cache, wslBatch)
    if (r.kind === "cli" && r.runtime !== "none") {
      readyCliLines.push(`- 🟢 **${r.label}** (\`${sId}\`) — Pronto via ${r.detail}`)
    } else if (r.kind === "web_embed" && r.runtime !== "none") {
      readyWebLines.push(`- 🟢 **${r.label}** (\`${sId}\`) — Pronto como ${r.detail}`)
    } else {
      pendingInstallLines.push(`- ⚪ **${r.label}** (\`${sId}\`) — Botão 🟢 MCP ativo (binário externo ainda não instalado no disco)`)
    }
  }

  const sections: string[] = [
    `# Status Unificado do Hub MCP CyberLab OS (${enabled.size} slots com 🟢 MCP habilitado)`,
    "",
    "## 1. Servidores GUI MCP em Tempo Real (Burp / Ghidra / JADX)",
    ...(liveGuiLines.length > 0 ? liveGuiLines : ["- Nenhum slot GUI selecionado."]),
    "",
    `## 2. Ferramentas CLI / Scanners Prontas p/ Execução via \`arsenal_run_tool\` (${readyCliLines.length})`,
    ...(readyCliLines.length > 0 ? readyCliLines : ["- Nenhuma ferramenta CLI instalada encontrada nos slots ativos."]),
  ]

  if (readyWebLines.length > 0) {
    sections.push("", `## 3. Aplicações Web Embed Integradas (${readyWebLines.length})`, ...readyWebLines)
  }
  if (!callArgs.onlyInstalled && pendingInstallLines.length > 0) {
    sections.push(
      "",
      `## 4. Slots com 🟢 MCP Ligado Aguardando Instalação Externa (${pendingInstallLines.length})`,
      ...pendingInstallLines,
    )
  }

  sendResponse({
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: sections.join("\n") }],
    },
  })
}

async function handleGhidraToolCall(
  id: string | number | null,
  toolName: string,
  callArgs: Record<string, unknown>,
): Promise<void> {
  if (toolName === "ghidra_mcp_status") {
    const extState =
      callArgs.ensureExtensionInstalled !== false ? ensureGhidraMcpExtensionInstalled() : "SKIPPED"
    const health = await callLocalOrWslHttpPlugin(ghidraMcpPort, "GET", "health", {}, 4_000)
    const prog = health.ok
      ? await callLocalOrWslHttpPlugin(ghidraMcpPort, "GET", "program_info", {}, 4_000)
      : { ok: false, body: "" }
    const cache = readProbeCache()
    const cliTarget = resolveSlotTarget("ghidra", cache)
    const text = health.ok
      ? `✅ GhidraMCP CONECTADO AO VIVO na porta :${ghidraMcpPort}!\nHealth: ${health.body}\nPrograma aberto: ${prog.body ?? "nenhum binário aberto no CodeBrowser ainda"}\nCLI Headless: ${cliTarget.detail}`
      : [
          `🟡 GhidraMCP ainda não está ouvindo na porta :${ghidraMcpPort} (${health.error ?? "GUI fechada"}).`,
          `Extensão oficial LaurieWired/GhidraMCP preparada automaticamente: ${extState}`,
          `CLI Headless disponível agora via arsenal_run_tool(slotId="ghidra"): ${cliTarget.detail}`,
          "",
          "Para ativar o controle da janela GUI do Ghidra em tempo real:",
          "1. Abra o Ghidra pelo botão '🖥 Abrir Aqui Dentro do CyberLab'.",
          "2. Na primeira vez, em 'File -> Configure -> Developer' (no CodeBrowser), marque 'GhidraMCPPlugin' (se não aparecer na lista, importe o .zip em /opt/cyberlab-ghidra-mcp via 'File -> Install Extensions').",
        ].join("\n")
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: { content: [{ type: "text", text: redactSensitiveContent(text).text }] },
    })
    return
  }

  if (toolName === "ghidra_mcp_decompile") {
    const fnName = typeof callArgs.name === "string" ? callArgs.name.trim() : ""
    const addr = typeof callArgs.address === "string" ? callArgs.address.trim() : ""
    const endpoint = addr ? "decompile_function" : "decompile"
    const params = addr ? { address: addr } : { name: fnName || "main" }
    const res = await callLocalOrWslHttpPlugin(ghidraMcpPort, "GET", endpoint, params, 45_000)
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        isError: !res.ok,
        content: [
          {
            type: "text",
            text: redactSensitiveContent(
              res.body || res.error || `GhidraMCP :${ghidraMcpPort} não respondeu.`,
            ).text,
          },
        ],
      },
    })
    return
  }

  if (toolName === "ghidra_mcp_call") {
    const endpoint = String(callArgs.endpoint ?? "program_info")
    const method = callArgs.method === "POST" ? "POST" : "GET"
    const params =
      callArgs.params && typeof callArgs.params === "object"
        ? (callArgs.params as Record<string, unknown>)
        : {}
    const res = await callLocalOrWslHttpPlugin(ghidraMcpPort, method, endpoint, params, 30_000)
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        isError: !res.ok,
        content: [
          {
            type: "text",
            text: redactSensitiveContent(
              res.body || res.error || `GhidraMCP :${ghidraMcpPort} não respondeu.`,
            ).text,
          },
        ],
      },
    })
    return
  }
}

async function handleJadxToolCall(
  id: string | number | null,
  toolName: string,
  callArgs: Record<string, unknown>,
): Promise<void> {
  if (toolName === "jadx_mcp_status") {
    const plugState =
      callArgs.ensurePluginInstalled !== false ? ensureJadxAiMcpPluginInstalled() : "SKIPPED"
    const probe = await callLocalOrWslHttpPlugin(jadxMcpPort, "GET", "cache-stats", {}, 4_000)
    const cache = readProbeCache()
    const cliTarget = resolveSlotTarget("jadx", cache)
    const text = probe.ok
      ? `✅ JADX-AI-MCP CONECTADO AO VIVO na porta :${jadxMcpPort}!\nResposta do JADX-GUI: ${probe.body}\nCLI JADX: ${cliTarget.detail}`
      : [
          `🟡 JADX-AI-MCP ainda não está ouvindo na porta :${jadxMcpPort} (${probe.error ?? "jadx-gui fechado"}).`,
          `Plugin oficial zinja-coder/jadx-ai-mcp preparado automaticamente: ${plugState}`,
          `CLI JADX disponível agora via arsenal_run_tool(slotId="jadx"): ${cliTarget.detail}`,
          "",
          "Assim que você abrir um arquivo .apk/.dex no JADX-GUI, o plugin JADX-AI-MCP sobe automaticamente na porta :8650!",
        ].join("\n")
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: { content: [{ type: "text", text: redactSensitiveContent(text).text }] },
    })
    return
  }

  if (toolName === "jadx_mcp_get_class_source") {
    const className = typeof callArgs.className === "string" ? callArgs.className.trim() : ""
    const smali = Boolean(callArgs.smali)
    const endpoint = !className ? "current-class" : smali ? "smali-of-class" : "class-source"
    const params = className ? { class_name: className } : {}
    const res = await callLocalOrWslHttpPlugin(jadxMcpPort, "GET", endpoint, params, 30_000)
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        isError: !res.ok,
        content: [
          {
            type: "text",
            text: redactSensitiveContent(
              res.body || res.error || `JADX-AI-MCP :${jadxMcpPort} não respondeu.`,
            ).text,
          },
        ],
      },
    })
    return
  }

  if (toolName === "jadx_mcp_call") {
    const endpoint = String(callArgs.endpoint ?? "current-class")
    const method = callArgs.method === "POST" ? "POST" : "GET"
    const params =
      callArgs.params && typeof callArgs.params === "object"
        ? (callArgs.params as Record<string, unknown>)
        : {}
    const res = await callLocalOrWslHttpPlugin(jadxMcpPort, method, endpoint, params, 45_000)
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        isError: !res.ok,
        content: [
          {
            type: "text",
            text: redactSensitiveContent(
              res.body || res.error || `JADX-AI-MCP :${jadxMcpPort} não respondeu.`,
            ).text,
          },
        ],
      },
    })
    return
  }
}

async function handleBurpToolCall(
  id: string | number | null,
  toolName: string,
  callArgs: Record<string, unknown>,
): Promise<void> {
  if (toolName === "burp_suite_status") {
    const shouldEnsure = callArgs.ensureExtensionDownloaded !== false
    const extState = shouldEnsure ? ensureBurpExtensionJarDownloadedInWsl() : "SKIPPED"
    const listRes = await callBurpMcpRpc("tools/list", {})
    if (!listRes.ok) {
      sendResponse({
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: `${offlineBurpGuideMessage(listRes.error)}\n\nExtensão em disco (/opt/cyberlab-burp/burp-mcp-all.jar): ${extState}`,
            },
          ],
        },
      })
      return
    }
    const toolsArr =
      ((listRes.result as { tools?: Array<{ name?: string; description?: string }> })?.tools ?? [])
        .map((t) => `- ${t.name}: ${t.description ?? ""}`)
        .join("\n")
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        content: [
          {
            type: "text",
            text: `✅ Burp Suite MCP Server CONECTADO na porta :${burpMcpPort}!\nFerramentas ativas expostas pelo Burp:\n${toolsArr}`,
          },
        ],
      },
    })
    return
  }

  const targetHost =
    typeof callArgs.targetHostname === "string"
      ? callArgs.targetHostname.trim()
      : typeof (callArgs.toolArgs as Record<string, unknown> | undefined)?.targetHostname === "string"
        ? String((callArgs.toolArgs as Record<string, unknown>).targetHostname).trim()
        : ""
  if (targetHost) {
    const scopeCheck = checkTargetAllowedInWorkspaceScope(targetHost)
    if (!scopeCheck.allowed) {
      sendResponse({
        jsonrpc: "2.0",
        id,
        result: {
          isError: true,
          content: [{ type: "text", text: scopeCheck.reason ?? "Alvo fora de escopo." }],
        },
      })
      return
    }
  }

  let upstreamName = ""
  let upstreamArgs: Record<string, unknown> = {}

  if (toolName === "burp_suite_get_proxy_history") {
    const count = typeof callArgs.count === "number" ? callArgs.count : 20
    const offset = typeof callArgs.offset === "number" ? callArgs.offset : 0
    const regex = typeof callArgs.regex === "string" ? callArgs.regex.trim() : ""
    if (regex) {
      upstreamName = "get_proxy_http_history_regex"
      upstreamArgs = { regex, count, offset }
    } else {
      upstreamName = "get_proxy_http_history"
      upstreamArgs = { count, offset }
    }
  } else if (toolName === "burp_suite_send_http1_request") {
    upstreamName = "send_http1_request"
    upstreamArgs = {
      targetHostname: String(callArgs.targetHostname ?? ""),
      targetPort: Number(callArgs.targetPort ?? 443),
      usesHttps: Boolean(callArgs.usesHttps ?? true),
      content: String(callArgs.content ?? ""),
    }
  } else if (toolName === "burp_suite_create_repeater_tab") {
    upstreamName = "create_repeater_tab"
    upstreamArgs = {
      tabName: typeof callArgs.tabName === "string" ? callArgs.tabName : null,
      targetHostname: String(callArgs.targetHostname ?? ""),
      targetPort: Number(callArgs.targetPort ?? 443),
      usesHttps: Boolean(callArgs.usesHttps ?? true),
      content: String(callArgs.content ?? ""),
    }
  } else if (toolName === "burp_suite_send_to_intruder") {
    upstreamName = "send_to_intruder"
    upstreamArgs = {
      tabName: typeof callArgs.tabName === "string" ? callArgs.tabName : null,
      targetHostname: String(callArgs.targetHostname ?? ""),
      targetPort: Number(callArgs.targetPort ?? 443),
      usesHttps: Boolean(callArgs.usesHttps ?? true),
      content: String(callArgs.content ?? ""),
    }
  } else if (toolName === "burp_suite_set_intercept") {
    upstreamName = "set_proxy_intercept_state"
    upstreamArgs = {
      intercepting: Boolean(callArgs.intercepting),
    }
  } else if (toolName === "burp_suite_call_tool") {
    upstreamName = String(callArgs.toolName ?? "")
    upstreamArgs =
      callArgs.toolArgs && typeof callArgs.toolArgs === "object"
        ? (callArgs.toolArgs as Record<string, unknown>)
        : {}
  } else {
    sendResponse({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Tool Burp desconhecida: ${toolName}` },
    })
    return
  }

  const rpcRes = await callBurpMcpRpc("tools/call", {
    name: upstreamName,
    arguments: upstreamArgs,
  })

  if (!rpcRes.ok) {
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        isError: true,
        content: [{ type: "text", text: offlineBurpGuideMessage(rpcRes.error) }],
      },
    })
    return
  }

  sendResponse({
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: extractBurpResultText(rpcRes.result) }],
    },
  })
}

async function handleRpc(msg: JsonRpcRequest): Promise<void> {
  if (msg.method === "notifications/initialized" || msg.id === undefined) {
    if (msg.method === "notifications/initialized") initializedClient = true
    return
  }

  if (msg.method === "initialize") {
    initializedClient = true
    sendResponse({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: {
          tools: { listChanged: true },
        },
        serverInfo: {
          name: isHubMode ? "cyberlab-arsenal" : `cyberlab-mcp-${slotId}`,
          version: "6.1.0",
        },
      },
    })
    return
  }

  if (msg.method === "ping") {
    sendResponse({ jsonrpc: "2.0", id: msg.id, result: {} })
    return
  }

  if (msg.method === "tools/list") {
    if (isHubMode) {
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: { tools: buildHubToolsList() },
      })
      return
    }
    if (slotId === "burp-suite") {
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: { tools: BURP_MCP_TOOLS },
      })
      return
    }
    if (slotId === "ghidra") {
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: { tools: GHIDRA_MCP_TOOLS },
      })
      return
    }
    if (slotId === "jadx") {
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: { tools: JADX_MCP_TOOLS },
      })
      return
    }

    sendResponse({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        tools: [
          {
            name: `${safeToolPrefix}_help`,
            description: `Consulta a versão, flags e capacidades da ferramenta externa ${displayName} instalada no ambiente.`,
            inputSchema: { type: "object", properties: {} },
          },
          {
            name: `${safeToolPrefix}_audit`,
            description: `Executa auditoria/inspeção supervisionada com ${displayName} respeitando estritamente a Trava de Escopo do CyberLab OS e redação SHA-256.`,
            inputSchema: {
              type: "object",
              properties: {
                target: {
                  type: "string",
                  description: "Arquivo local do workspace ou alvo autorizado no escopo Bug Bounty",
                },
                args: {
                  type: "array",
                  items: { type: "string" },
                  description: "Lista de argumentos seguros (sem shell) para inspeção/auditoria",
                },
              },
            },
          },
        ],
      },
    })
    return
  }

  if (msg.method === "tools/call") {
    const params = (msg.params ?? {}) as { name?: string; arguments?: Record<string, unknown> }
    const toolName = params.name ?? ""
    const callArgs = params.arguments ?? {}

    if (toolName.startsWith("burp_suite_")) {
      await handleBurpToolCall(msg.id ?? null, toolName, callArgs)
      return
    }
    if (toolName.startsWith("ghidra_mcp_")) {
      await handleGhidraToolCall(msg.id ?? null, toolName, callArgs)
      return
    }
    if (toolName.startsWith("jadx_mcp_")) {
      await handleJadxToolCall(msg.id ?? null, toolName, callArgs)
      return
    }

    if (toolName === "arsenal_mcp_status") {
      await handleArsenalStatusCall(msg.id ?? null, callArgs)
      return
    }

    if (toolName === "arsenal_tool_help") {
      const targetSlot = String(callArgs.slotId ?? "").trim()
      const enabled = readEnabledHubSlotIds()
      if (!targetSlot || (isHubMode && !enabled.has(targetSlot))) {
        sendResponse({
          jsonrpc: "2.0",
          id: msg.id,
          result: {
            isError: true,
            content: [
              {
                type: "text",
                text: `O slot "${targetSlot}" não está com 🟢 MCP habilitado na barra Slots do CyberLab OS.`,
              },
            ],
          },
        })
        return
      }
      const res = executeResolvedSlotCli(targetSlot, ["--help"])
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          content: [
            {
              type: "text",
              text: `[${res.resolvedDetail}]\n${res.output || `Código de saída ${res.exitCode}`}`,
            },
          ],
        },
      })
      return
    }

    if (toolName === "arsenal_run_tool") {
      const targetSlot = String(callArgs.slotId ?? "").trim()
      const enabled = readEnabledHubSlotIds()
      if (!targetSlot || (isHubMode && !enabled.has(targetSlot))) {
        sendResponse({
          jsonrpc: "2.0",
          id: msg.id,
          result: {
            isError: true,
            content: [
              {
                type: "text",
                text: `O slot "${targetSlot}" não está com 🟢 MCP habilitado na barra Slots do CyberLab OS.`,
              },
            ],
          },
        })
        return
      }
      const target = typeof callArgs.target === "string" ? callArgs.target.trim() : ""
      if (target) {
        const scopeCheck = checkTargetAllowedInWorkspaceScope(target)
        if (!scopeCheck.allowed) {
          sendResponse({
            jsonrpc: "2.0",
            id: msg.id,
            result: {
              isError: true,
              content: [{ type: "text", text: scopeCheck.reason ?? "Alvo fora de escopo." }],
            },
          })
          return
        }
      }
      const rawList = Array.isArray(callArgs.args)
        ? callArgs.args.filter((x): x is string => typeof x === "string")
        : ["--version"]
      // Also scope-check URL-like arguments passed inside args
      for (const item of rawList) {
        if (/^https?:\/\//i.test(item)) {
          const sc = checkTargetAllowedInWorkspaceScope(item)
          if (!sc.allowed) {
            sendResponse({
              jsonrpc: "2.0",
              id: msg.id,
              result: {
                isError: true,
                content: [{ type: "text", text: sc.reason ?? "URL em args fora de escopo." }],
              },
            })
            return
          }
        }
      }
      const finalArgs = target ? [...rawList, target] : rawList
      const res = executeResolvedSlotCli(targetSlot, finalArgs)
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          isError: res.exitCode !== 0 && !res.output,
          content: [
            {
              type: "text",
              text: `[${res.resolvedDetail}]\n${res.output || `Concluído (exitCode=${res.exitCode}).`}`,
            },
          ],
        },
      })
      return
    }

    // Legacy single-slot tool calls (`<slot>_help` / `<slot>_audit`)
    if (toolName === `${safeToolPrefix}_help`) {
      const res = executeResolvedSlotCli(slotId, ["--help"])
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          content: [
            {
              type: "text",
              text: `[${res.resolvedDetail}]\n${res.output || `${displayName} respondeu com código ${res.exitCode}.`}`,
            },
          ],
        },
      })
      return
    }

    if (toolName === `${safeToolPrefix}_audit`) {
      const target = typeof callArgs.target === "string" ? callArgs.target.trim() : ""
      if (target) {
        const scopeCheck = checkTargetAllowedInWorkspaceScope(target)
        if (!scopeCheck.allowed) {
          sendResponse({
            jsonrpc: "2.0",
            id: msg.id,
            result: {
              isError: true,
              content: [{ type: "text", text: scopeCheck.reason ?? "Alvo fora de escopo." }],
            },
          })
          return
        }
      }
      const rawList = Array.isArray(callArgs.args)
        ? callArgs.args.filter((x): x is string => typeof x === "string")
        : ["--version"]
      const finalArgs = target ? [...rawList, target] : rawList
      const res = executeResolvedSlotCli(slotId, finalArgs)
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          isError: res.exitCode !== 0 && !res.output,
          content: [
            {
              type: "text",
              text: `[${res.resolvedDetail}]\n${res.output || `Concluído (exitCode=${res.exitCode}).`}`,
            },
          ],
        },
      })
      return
    }

    sendResponse({
      jsonrpc: "2.0",
      id: msg.id,
      error: { code: -32601, message: `Tool desconhecida: ${toolName}` },
    })
    return
  }

  sendResponse({
    jsonrpc: "2.0",
    id: msg.id,
    error: { code: -32601, message: `Método MCP não suportado: ${msg.method}` },
  })
}

// Watch `.cyberlab/mcp-enabled-slots.json` in Hub mode (`persistent: false` so EOF exits cleanly)
if (isHubMode) {
  const slotsCfgFile = path.join(workspaceRoot, ".cyberlab", "mcp-enabled-slots.json")
  watchFile(slotsCfgFile, { persistent: false, interval: 800 }, (curr, prev) => {
    if (initializedClient && curr.mtimeMs !== prev.mtimeMs) {
      sendResponse({
        jsonrpc: "2.0",
        method: "notifications/tools/list_changed",
      })
    }
  })
  process.stdin.on("end", () => unwatchFile(slotsCfgFile))
  process.stdin.on("close", () => unwatchFile(slotsCfgFile))
}

let rpcQueue: Promise<void> = Promise.resolve()
function enqueueRpc(req: JsonRpcRequest) {
  rpcQueue = rpcQueue.then(() => handleRpc(req)).catch(() => undefined)
}

let buffer = Buffer.alloc(0)
process.stdin.on("data", (chunk: Buffer) => {
  buffer = Buffer.concat([buffer, chunk])
  while (buffer.length > 0) {
    const preview = buffer.toString("utf8", 0, Math.min(buffer.length, 64))
    if (preview.startsWith("Content-Length:")) {
      useContentLengthFraming = true
      const headerEnd = buffer.indexOf("\r\n\r\n")
      if (headerEnd === -1) return
      const headerStr = buffer.toString("utf8", 0, headerEnd)
      const match = headerStr.match(/Content-Length:\s*(\d+)/i)
      const len = match ? Number.parseInt(match[1]!, 10) : 0
      const totalNeeded = headerEnd + 4 + len
      if (buffer.length < totalNeeded) return
      const bodyStr = buffer.toString("utf8", headerEnd + 4, totalNeeded)
      buffer = buffer.subarray(totalNeeded)
      try {
        enqueueRpc(JSON.parse(bodyStr) as JsonRpcRequest)
      } catch {
        // Ignore malformed frame
      }
    } else {
      const nlIdx = buffer.indexOf("\n")
      if (nlIdx === -1) return
      const line = buffer.toString("utf8", 0, nlIdx).trim()
      buffer = buffer.subarray(nlIdx + 1)
      if (!line) continue
      try {
        enqueueRpc(JSON.parse(line) as JsonRpcRequest)
      } catch {
        // Ignore malformed line
      }
    }
  }
})
