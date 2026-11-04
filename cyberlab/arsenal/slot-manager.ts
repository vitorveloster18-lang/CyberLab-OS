import { spawn, spawnSync, type ChildProcess } from "node:child_process"
import crypto from "node:crypto"
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs"
import http from "node:http"
import https from "node:https"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import tls from "node:tls"
import { fileURLToPath } from "node:url"
import type { ProjectScope } from "../contracts/policy.js"
import { redactSensitiveContent } from "../evidence/provenance.js"
import { isPathInsideRoot, type ScopeController } from "../policy/scope.js"
import {
  ARSENAL_CATEGORY_LABELS,
  OFFICIAL_ARSENAL_SLOTS,
  type ArsenalCategory,
  type ArsenalPresetCommand,
  type ArsenalRuntimePreference,
  type ArsenalSlotDefinition,
  type ArsenalSlotKind,
} from "./catalog.js"

export interface SlotUserOverride {
  customExecutablePath?: string
  customEmbedUrl?: string
  preferredRuntime?: ArsenalRuntimePreference
  defaultArgs?: string
  companionProxyPort?: number
}

export interface PersistedArsenalConfig {
  toolsRootDir: string
  preferredWslDistro: string
  enforceScopeOnCliRuns: boolean
  slotOverrides: Record<string, SlotUserOverride>
  customSlots: ArsenalSlotDefinition[]
}

export interface ArsenalSlotStatus {
  slotId: string
  name: string
  shortLabel: string
  category: ArsenalCategory
  kind: ArsenalSlotKind
  tagline: string
  description: string
  upstreamUrl: string
  licenseNote: string
  isCustom: boolean
  installed: boolean
  availableRuntimes: Array<"windows" | "wsl" | "linux_mac" | "web">
  activeRuntime: "windows" | "wsl" | "linux_mac" | "web" | "none"
  resolvedPath: string | null
  windowsPath: string | null
  wslPath: string | null
  posixPath: string | null
  embedUrl: string | null
  daemonRunning: boolean
  companionProxyPort: number | null
  mcpCapable: boolean
  mcpConnected: boolean
  mcpLabel: string | null
  installPowerShell: string
  installKaliWsl: string
  presets: ArsenalPresetCommand[]
  override: SlotUserOverride
}

export interface ArsenalLiveRun {
  runId: string
  slotId: string
  slotName: string
  runtime: "windows" | "wsl" | "linux_mac" | "installer"
  commandPreview: string
  status: "running" | "succeeded" | "failed" | "stopped"
  exitCode: number | null
  startedAt: string
  finishedAt: string | null
  outputLogPath: string | null
  outputTail: string
  lineCount: number
}

export interface WorkspaceFileEntry {
  name: string
  relativePath: string
  kind: "file" | "directory"
  sizeBytes: number
  modifiedAt: string
}

export interface ArsenalEnvironmentSummary {
  hostPlatform: NodeJS.Platform
  toolsRootDir: string
  wslAvailable: boolean
  wslDistros: string[]
  preferredWslDistro: string
  enforceScopeOnCliRuns: boolean
  lastProbedAt: string | null
}

export interface ArsenalOverview {
  environment: ArsenalEnvironmentSummary
  categories: Array<{ id: ArsenalCategory; title: string; subtitle: string }>
  slots: ArsenalSlotStatus[]
  runs: ArsenalLiveRun[]
}

const IN_DOCUMENT_ZOOM_SCRIPT = `<script data-cyberlab-zoom="1">(function(){if(window.__cyberlabZoomHook)return;window.__cyberlabZoomHook=true;window.addEventListener("message",function(ev){var d=ev&&ev.data;if(!d||d.type!=="cyberlab-canvas-control")return;var z=typeof d.zoom==="number"?Math.max(50,Math.min(180,d.zoom))/100:1;document.documentElement.style.zoom=z===1?"":String(z);if(d.mode==="scroll"){document.documentElement.style.overflow="auto";if(document.body)document.body.style.overflow="auto";}});})();</script>`

function injectZoomHelperIntoHtml(rawHtml: Buffer): Buffer {
  const text = rawHtml.toString("utf8")
  if (text.includes("data-cyberlab-zoom")) return rawHtml
  const lower = text.toLowerCase()
  const closeBody = lower.lastIndexOf("</body>")
  if (closeBody !== -1) {
    return Buffer.from(`${text.slice(0, closeBody)}${IN_DOCUMENT_ZOOM_SCRIPT}${text.slice(closeBody)}`, "utf8")
  }
  const closeHead = lower.lastIndexOf("</head>")
  if (closeHead !== -1) {
    return Buffer.from(`${text.slice(0, closeHead)}${IN_DOCUMENT_ZOOM_SCRIPT}${text.slice(closeHead)}`, "utf8")
  }
  return Buffer.from(`${text}${IN_DOCUMENT_ZOOM_SCRIPT}`, "utf8")
}

const NON_MCP_SLOT_IDS = new Set([
  "kali-desktop-stream",
  "veracrypt",
  "tor-onionshare",
  "mullvad-opsec",
])

const CUSTOM_MCP_LABELS: Record<string, string> = {
  "burp-suite": "Burp MCP (:9876/sse)",
  opentrap: "OpenTRAP Proxy MCP",
  mitmweb: "mitmproxy MCP",
  caido: "Caido GraphQL/MCP",
  "owasp-zap": "OWASP ZAP API MCP",
  rea: "REA Native MCP",
  ghidra: "Ghidra Live + Headless MCP (:8080)",
  jadx: "JADX Live + CLI MCP (:8650)",
  "rizin-cutter": "Rizin / Cutter MCP",
  wireshark: "TShark PCAP MCP",
  semgrep: "OpenGrep / Semgrep MCP",
  "hexstrike-ai": "HexStrike Kali MCP",
  pentagi: "PentAGI MCP",
  "pentest-copilot": "Pentest Copilot MCP",
  betterleaks: "Betterleaks Audit MCP",
  gef: "GEF Binary Inspector MCP",
  "atomic-operator": "MITRE ATT&CK MCP",
  wpprobe: "WPProbe CVE MCP",
  "netcat-ncat": "Netcat / Ncat Socket MCP",
  dirsearch: "Dirsearch Web Path MCP",
}

const MIME_BY_EXT: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
  ".wasm": "application/wasm",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".txt": "text/plain; charset=utf-8",
}

export function windowsPathToWslPath(winPath: string): string {
  const normalized = winPath.replace(/\\/g, "/")
  const driveMatch = normalized.match(/^([a-zA-Z]):\/(.*)$/)
  if (driveMatch) {
    return `/mnt/${driveMatch[1]!.toLowerCase()}/${driveMatch[2]!}`
  }
  return normalized
}

export function splitCommandLineArgs(raw: string): string[] {
  const args: string[] = []
  let current = ""
  let quote: '"' | "'" | null = null
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!
    if (quote) {
      if (ch === quote) {
        quote = null
      } else if (ch === "\\" && quote === '"' && i + 1 < raw.length) {
        const next = raw[i + 1]!
        if (next === '"' || next === "\\") {
          current += next
          i++
        } else {
          current += ch
        }
      } else {
        current += ch
      }
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (/\s/.test(ch)) {
      if (current.length > 0) {
        args.push(current)
        current = ""
      }
      continue
    }
    current += ch
  }
  if (current.length > 0) args.push(current)
  return args
}

function defaultToolsRoot(): string {
  if (process.platform === "win32") {
    return "C:\\CyberLab-Tools"
  }
  return path.join(os.homedir(), "CyberLab-Tools")
}

function expandWindowsCandidatePath(template: string, toolsRoot: string): string {
  return template
    .replace(/\{toolsRoot\}/gi, toolsRoot)
    .replace(/%LOCALAPPDATA%/gi, process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"))
    .replace(/%APPDATA%/gi, process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming"))
    .replace(/%ProgramFiles\(x86\)%/gi, process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)")
    .replace(/%ProgramFiles%/gi, process.env.ProgramFiles || "C:\\Program Files")
    .replace(/%USERPROFILE%/gi, process.env.USERPROFILE || os.homedir())
}

function expandPosixCandidatePath(template: string, toolsRoot: string): string {
  return template
    .replace(/\{toolsRoot\}/gi, toolsRoot)
    .replace(/^~(?=\/|$)/, os.homedir())
}

function stripSurroundingQuotes(raw: string): string {
  const trimmed = raw.trim()
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1).trim()
  }
  return trimmed
}

function safeRealpath(targetPath: string): string {
  try {
    return realpathSync(targetPath)
  } catch {
    return targetPath
  }
}

function decodePotentialUtf16Le(buf: Buffer | string | null | undefined): string {
  if (!buf) return ""
  if (typeof buf === "string") return buf.replace(/\0/g, "")
  if (buf.includes(0)) {
    return buf.toString("utf16le").replace(/^\uFEFF/, "").replace(/\0/g, "")
  }
  return buf.toString("utf8")
}

interface ManagedDaemonHandle {
  child: ChildProcess | null
  staticServer: http.Server | null
  tcpBridges?: net.Server[]
  wslDisplayNum?: number
  embedUrl: string
}

interface LiveRunRecord {
  info: ArsenalLiveRun
  lines: string[]
  child: ChildProcess | null
}

export class ArsenalSlotManager {
  private readonly workspaceRoot: string
  private readonly projectId: string
  private readonly scopes: ScopeController
  private readonly configFilePath: string
  private config: PersistedArsenalConfig
  private wslAvailable = false
  private wslDistros: string[] = []
  private cachedSlotProbes = new Map<
    string,
    { windowsPath: string | null; wslPath: string | null; posixPath: string | null; localHtmlEntry: string | null }
  >()
  private lastProbedAt: string | null = null
  private readonly daemons = new Map<string, ManagedDaemonHandle>()
  private readonly runs = new Map<string, LiveRunRecord>()

  constructor(options: {
    projectId: string
    workspaceRoot: string
    scopes: ScopeController
    globalConfigDir?: string
  }) {
    this.projectId = options.projectId
    this.workspaceRoot = path.resolve(options.workspaceRoot)
    this.scopes = options.scopes
    const baseCfgDir =
      options.globalConfigDir ??
      process.env.CYBERLAB_GLOBAL_CONFIG_DIR ??
      path.join(os.homedir(), ".cyberlab")
    this.configFilePath = path.join(baseCfgDir, "arsenal-config.json")
    this.config = this.loadConfig()
  }

  private loadConfig(): PersistedArsenalConfig {
    const fallback: PersistedArsenalConfig = {
      toolsRootDir: defaultToolsRoot(),
      preferredWslDistro: "kali-linux",
      enforceScopeOnCliRuns: false,
      slotOverrides: {},
      customSlots: [],
    }
    if (!existsSync(this.configFilePath)) return fallback
    try {
      const parsed = JSON.parse(readFileSync(this.configFilePath, "utf8")) as Partial<PersistedArsenalConfig>
      return {
        toolsRootDir:
          typeof parsed.toolsRootDir === "string" && parsed.toolsRootDir.trim()
            ? parsed.toolsRootDir.trim()
            : fallback.toolsRootDir,
        preferredWslDistro:
          typeof parsed.preferredWslDistro === "string" && parsed.preferredWslDistro.trim()
            ? parsed.preferredWslDistro.trim()
            : fallback.preferredWslDistro,
        enforceScopeOnCliRuns: Boolean(parsed.enforceScopeOnCliRuns),
        slotOverrides:
          parsed.slotOverrides && typeof parsed.slotOverrides === "object" ? parsed.slotOverrides : {},
        customSlots: Array.isArray(parsed.customSlots) ? parsed.customSlots : [],
      }
    } catch {
      return fallback
    }
  }

  private saveConfig(): void {
    try {
      mkdirSync(path.dirname(this.configFilePath), { recursive: true })
      writeFileSync(this.configFilePath, `${JSON.stringify(this.config, null, 2)}\n`, "utf8")
    } catch {
      // Non-fatal in read-only sandboxes
    }
  }

  getAllDefinitions(): ArsenalSlotDefinition[] {
    return [...OFFICIAL_ARSENAL_SLOTS, ...this.config.customSlots]
  }

  private collectExtraWindowsToolDirs(): string[] {
    const extra: string[] = []
    const localAppData =
      process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local")
    const progFiles = process.env.ProgramFiles ?? "C:\\Program Files"
    const userHome = os.homedir()

    const directCandidates = [
      path.join(this.workspaceRoot, ".cyberlab", "bin"),
      path.join(this.config.toolsRootDir, "bin"),
      this.config.toolsRootDir,
      path.join(localAppData, "BurpSuiteCommunity"),
      path.join(localAppData, "Programs", "BurpSuiteCommunity"),
      path.join(progFiles, "BurpSuiteCommunity"),
      path.join(userHome, "BurpSuiteCommunity"),
      path.join(localAppData, "Microsoft", "WinGet", "Links"),
      path.join(localAppData, "Programs", "caido"),
      path.join(localAppData, "Programs", "Caido"),
      path.join(localAppData, "caido"),
      path.join(progFiles, "Caido"),
      path.join(userHome, ".cargo", "bin"),
      path.join(userHome, "go", "bin"),
      path.join(userHome, "scoop", "shims"),
    ]
    for (const d of directCandidates) {
      if (d && existsSync(d)) extra.push(d)
    }

    // Scan WinGet\Packages (up to 2 levels deep) so freshly installed Winget tools are found without restarting PowerShell
    const wingetPkgs = path.join(localAppData, "Microsoft", "WinGet", "Packages")
    if (existsSync(wingetPkgs)) {
      try {
        for (const pkgEntry of readdirSync(wingetPkgs, { withFileTypes: true })) {
          if (!pkgEntry.isDirectory()) continue
          const pkgDir = path.join(wingetPkgs, pkgEntry.name)
          extra.push(pkgDir)
          try {
            for (const sub of readdirSync(pkgDir, { withFileTypes: true })) {
              if (!sub.isDirectory()) continue
              const subDir = path.join(pkgDir, sub.name)
              extra.push(subDir)
              const binSub = path.join(subDir, "bin")
              if (existsSync(binSub)) extra.push(binSub)
            }
          } catch {
            // Ignore unreadable subfolder
          }
        }
      } catch {
        // Ignore unreadable WinGet Packages dir
      }
    }

    // Also check 1 subfolder level inside toolsRootDir (e.g. C:\CyberLab-Tools\ghidra_11.x, C:\CyberLab-Tools\jadx\bin)
    if (existsSync(this.config.toolsRootDir)) {
      try {
        for (const ent of readdirSync(this.config.toolsRootDir, { withFileTypes: true })) {
          if (!ent.isDirectory()) continue
          const sub = path.join(this.config.toolsRootDir, ent.name)
          extra.push(sub)
          const subBin = path.join(sub, "bin")
          if (existsSync(subBin)) extra.push(subBin)
        }
      } catch {
        // Ignore
      }
    }

    return extra
  }

  private findWhereOnWindows(binNames: string[], extraDirs?: string[]): string | null {
    const pathDirs = [
      ...(extraDirs ?? this.collectExtraWindowsToolDirs()),
      ...(process.env.PATH ?? "").split(path.delimiter).filter(Boolean),
    ]
    const winExts = ["", ".exe", ".cmd", ".bat"]

    for (const rawBin of binNames) {
      const bin = rawBin.trim()
      if (!bin) continue
      if (path.isAbsolute(bin) && existsSync(bin)) return bin

      const hasExt = /\.[a-z0-9]+$/i.test(bin)
      for (const dir of pathDirs) {
        for (const ext of hasExt ? [""] : winExts) {
          const candidate = path.join(dir, `${bin}${ext}`)
          if (existsSync(candidate)) return candidate
        }
      }
    }
    return null
  }

  private findWhichOnPosix(binNames: string[]): string | null {
    const pathDirs = [
      path.join(this.workspaceRoot, ".cyberlab", "bin"),
      path.join(this.config.toolsRootDir, "bin"),
      ...(process.env.PATH ?? "").split(path.delimiter).filter(Boolean),
    ]
    for (const rawBin of binNames) {
      const bin = rawBin.trim()
      if (!bin) continue
      if (path.isAbsolute(bin) && existsSync(bin)) return bin
      for (const dir of pathDirs) {
        const candidate = path.join(dir, bin)
        if (existsSync(candidate)) return candidate
      }
    }
    return null
  }

  private detectLocalStaticHtml(dirSubpath: string): string | null {
    const candidateDirs = [
      path.join(this.config.toolsRootDir, dirSubpath),
      path.join(this.workspaceRoot, ".cyberlab", dirSubpath),
    ]
    for (const dir of candidateDirs) {
      if (!existsSync(dir)) continue
      try {
        const entries = readdirSync(dir)
        const htmlFile =
          entries.find((e) => /^CyberChef.*\.html$/i.test(e)) ??
          entries.find((e) => e.toLowerCase() === "index.html") ??
          entries.find((e) => e.toLowerCase().endsWith(".html"))
        if (htmlFile) {
          return path.join(dir, htmlFile)
        }
      } catch {
        // Ignore
      }
    }
    return null
  }

  probeEnvironment(): void {
    const defs = this.getAllDefinitions()
    const nextCache = new Map<
      string,
      { windowsPath: string | null; wslPath: string | null; posixPath: string | null; localHtmlEntry: string | null }
    >()

    if (process.platform === "win32") {
      // 1. Probe WSL2 distros cleanly (handling UTF-16LE output of wsl.exe and cold Hyper-V VM wakeups)
      this.wslAvailable = false
      this.wslDistros = []
      try {
        const wslList = spawnSync("wsl.exe", ["-l", "-q"], {
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
          timeout: 20000,
        })
        if (wslList.status === 0 && wslList.stdout) {
          const distros = decodePotentialUtf16Le(wslList.stdout)
            .replace(/^\uFEFF/, "")
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter(
              (s) =>
                s.length > 0 &&
                /^[A-Za-z0-9._-]+$/.test(s) &&
                !s.toLowerCase().includes("docker-desktop"),
            )
          if (distros.length > 0) {
            this.wslAvailable = true
            this.wslDistros = distros
            if (!distros.includes(this.config.preferredWslDistro)) {
              const kali = distros.find((d) => d.toLowerCase().includes("kali"))
              this.config.preferredWslDistro = kali ?? distros[0]!
            }
          }
        }
      } catch {
        this.wslAvailable = false
      }

      // 2. Batched single WSL2 probe across all candidate binaries & known paths
      //    NOTE: Pass bash script via `input` (stdin) to `wsl.exe -d <distro> -- bash -s`
      //    so Windows CreateProcessW / wsl.exe never splits spaces or mangles `$` / quotes!
      const wslResolvedByBin = new Map<string, string>()
      if (this.wslAvailable && this.config.preferredWslDistro) {
        const allPosixBins = Array.from(
          new Set(
            defs.flatMap((d) => [
              ...d.posixBinaries,
              ...(d.posixKnownPaths ?? []),
            ]),
          ),
        ).filter((b) => /^[a-zA-Z0-9._/~-]+$/.test(b))

        if (allPosixBins.length > 0) {
          const scriptLines = [
            // Strip Windows /mnt/* paths appended by WSL2 so Windows .bat/.sh scripts in C:\Program Files are never mistaken for native Linux binaries!
            'CLEAN_PATH=""',
            'IFS=:; for seg in $PATH; do case "$seg" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$seg" ;; esac; done; unset IFS',
            'PATH="$CLEAN_PATH"',
            'for d in "$HOME/.local/bin" "$HOME/go/bin" "$HOME/.cargo/bin" "$HOME/.pdtm/go/bin" "$HOME/.strix/bin" /home/*/.local/bin /home/*/go/bin /home/*/.cargo/bin /home/*/.pdtm/go/bin /home/*/.strix/bin /root/.local/bin /root/go/bin /root/.cargo/bin /root/.strix/bin /opt/opentrap /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do [ -d "$d" ] && PATH="$d:$PATH"; done',
            "export PATH",
            ...allPosixBins.map((token) => {
              if (token.startsWith("~/")) {
                const sub = token.slice(2)
                return `for cand in "$HOME/${sub}" /home/*/${sub} "/root/${sub}"; do if [ -x "$cand" ]; then echo "HIT:${token}=$cand"; break; fi; done`
              }
              if (token.includes("/")) {
                if (token.endsWith(".jar")) {
                  return `p="${token}"; [ -f "$p" ] && [ "$(stat -c%s "$p" 2>/dev/null || echo 0)" -gt 10000000 ] && echo "HIT:${token}=$p"`
                }
                if (/\.(yml|yaml|json|html)$/i.test(token)) {
                  return `p="${token}"; [ -s "$p" ] && echo "HIT:${token}=$p"`
                }
                return `p="${token}"; [ -x "$p" ] && echo "HIT:${token}=$p"`
              }
              return `p=$(command -v "${token}" 2>/dev/null | head -n 1); case "$p" in /mnt/*|"") ;; *) echo "HIT:${token}=$p" ;; esac`
            }),
          ].join("\n")

          const runWslProbeOnce = () => {
            try {
              const wslProbe = spawnSync(
                "wsl.exe",
                ["-d", this.config.preferredWslDistro, "-u", "root", "--", "bash", "-s"],
                {
                  input: Buffer.from(`${scriptLines}\n`, "utf8"),
                  encoding: "utf8",
                  stdio: ["pipe", "pipe", "ignore"],
                  windowsHide: true,
                  timeout: 30000,
                },
              )
              if (wslProbe.stdout) {
                for (const line of wslProbe.stdout.replace(/\0/g, "").split(/\r?\n/)) {
                  if (!line.startsWith("HIT:")) continue
                  const eqIdx = line.indexOf("=")
                  if (eqIdx === -1) continue
                  const key = line.slice(4, eqIdx).trim()
                  const val = line.slice(eqIdx + 1).trim()
                  if (key && val && !val.startsWith("/mnt/")) {
                    wslResolvedByBin.set(key, val)
                  }
                }
              }
            } catch {
              // Ignore WSL probe timeout
            }
          }

          runWslProbeOnce()
          // If WSL2 VM was cold-booting on the first call and returned 0 hits, run one immediate warm retry
          if (wslResolvedByBin.size === 0) {
            runWslProbeOnce()
          }
        }
      }

      // 3. Probe Windows paths + merge WSL hits
      const extraWinDirs = this.collectExtraWindowsToolDirs()
      for (const def of defs) {
        const override = this.config.slotOverrides[def.slotId]
        let winHit: string | null = null
        if (override?.customExecutablePath && existsSync(override.customExecutablePath)) {
          winHit = override.customExecutablePath
        }
        if (!winHit && def.windowsKnownPaths) {
          for (const tmpl of def.windowsKnownPaths) {
            const expanded = expandWindowsCandidatePath(tmpl, this.config.toolsRootDir)
            if (existsSync(expanded)) {
              winHit = expanded
              break
            }
          }
        }
        if (!winHit && def.windowsBinaries.length > 0) {
          winHit = this.findWhereOnWindows(def.windowsBinaries, extraWinDirs)
        }

        let wslHit: string | null = null
        if (override?.customExecutablePath && override.customExecutablePath.startsWith("/")) {
          wslHit = override.customExecutablePath
        }
        if (!wslHit) {
          for (const kp of def.posixKnownPaths ?? []) {
            const hit = wslResolvedByBin.get(kp)
            if (hit) {
              wslHit = hit
              break
            }
          }
        }
        if (!wslHit) {
          for (const pb of def.posixBinaries) {
            const hit = wslResolvedByBin.get(pb)
            if (hit) {
              wslHit = hit
              break
            }
          }
        }

        const localHtmlEntry = def.localStaticDirSubpath
          ? this.detectLocalStaticHtml(def.localStaticDirSubpath)
          : null

        nextCache.set(def.slotId, {
          windowsPath: winHit,
          wslPath: wslHit,
          posixPath: null,
          localHtmlEntry,
        })
      }
    } else {
      // Linux / Kali / WSL2 native / macOS
      this.wslAvailable = existsSync("/mnt/c/Windows")
      this.wslDistros = this.wslAvailable ? ["current-wsl-linux"] : []

      for (const def of defs) {
        const override = this.config.slotOverrides[def.slotId]
        let posixHit: string | null = null
        if (override?.customExecutablePath && existsSync(override.customExecutablePath)) {
          posixHit = override.customExecutablePath
        }
        if (!posixHit && def.posixKnownPaths) {
          for (const tmpl of def.posixKnownPaths) {
            const expanded = expandPosixCandidatePath(tmpl, this.config.toolsRootDir)
            if (existsSync(expanded)) {
              if (expanded.endsWith(".jar")) {
                try {
                  if (statSync(expanded).size <= 10_000_000) continue
                } catch {
                  continue
                }
              }
              posixHit = expanded
              break
            }
          }
        }
        if (!posixHit && def.posixBinaries.length > 0) {
          posixHit = this.findWhichOnPosix(def.posixBinaries)
        }
        const localHtmlEntry = def.localStaticDirSubpath
          ? this.detectLocalStaticHtml(def.localStaticDirSubpath)
          : null

        nextCache.set(def.slotId, {
          windowsPath: null,
          wslPath: null,
          posixPath: posixHit,
          localHtmlEntry,
        })
      }
    }

    this.cachedSlotProbes = nextCache
    this.lastProbedAt = new Date().toISOString()
    this.persistProbeCacheSnapshot()
  }

  private persistProbeCacheSnapshot(): void {
    try {
      const cyberlabDir = path.join(this.workspaceRoot, ".cyberlab")
      mkdirSync(cyberlabDir, { recursive: true })
      const slotsObj: Record<
        string,
        {
          windowsPath: string | null
          wslPath: string | null
          posixPath: string | null
          localHtmlEntry: string | null
        }
      > = {}
      for (const [slotId, probe] of this.cachedSlotProbes.entries()) {
        slotsObj[slotId] = probe
      }
      writeFileSync(
        path.join(cyberlabDir, "arsenal-probe-cache.json"),
        `${JSON.stringify(
          {
            updatedAt: this.lastProbedAt,
            toolsRootDir: this.config.toolsRootDir,
            preferredWslDistro: this.config.preferredWslDistro,
            slotOverrides: this.config.slotOverrides,
            customSlots: this.config.customSlots,
            slots: slotsObj,
          },
          null,
          2,
        )}\n`,
        "utf8",
      )
    } catch {
      // Ignore read-only workspace
    }
  }

  private getMcpEnabledSlotsFilePath(): string {
    return path.join(this.workspaceRoot, ".cyberlab", "mcp-enabled-slots.json")
  }

  private readEnabledHubSlotsFromDisk(): Set<string> {
    const filePath = this.getMcpEnabledSlotsFilePath()
    if (!existsSync(filePath)) return new Set<string>()
    try {
      const parsed = JSON.parse(readFileSync(filePath, "utf8")) as { enabledSlots?: unknown }
      if (Array.isArray(parsed.enabledSlots)) {
        return new Set(parsed.enabledSlots.filter((x): x is string => typeof x === "string" && x.length > 0))
      }
    } catch {
      // Ignore malformed file
    }
    return new Set<string>()
  }

  private writeEnabledHubSlotsToDisk(enabledSlots: Set<string>): void {
    try {
      const cyberlabDir = path.join(this.workspaceRoot, ".cyberlab")
      mkdirSync(cyberlabDir, { recursive: true })
      writeFileSync(
        this.getMcpEnabledSlotsFilePath(),
        `${JSON.stringify(
          {
            updatedAt: new Date().toISOString(),
            enabledSlots: Array.from(enabledSlots).sort(),
          },
          null,
          2,
        )}\n`,
        "utf8",
      )
    } catch {
      // Ignore read-only workspace
    }
  }

  private buildHubServerEntry(): Record<string, unknown> {
    const bridgeScript = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "..",
      "mcp",
      "arsenal-mcp-stdio.ts",
    )
    const bunBin = process.execPath || "bun"
    return {
      type: "local",
      command: [
        bunBin,
        "run",
        bridgeScript,
        "--slot",
        "__hub__",
        "--workspace",
        this.workspaceRoot,
        "--wsl-distro",
        this.config.preferredWslDistro,
      ],
    }
  }

  private readConnectedMcpServerKeys(): Set<string> {
    const out = new Set<string>()
    const enabledHubSlots = this.readEnabledHubSlotsFromDisk()
    const cfgPath = path.join(this.workspaceRoot, "opencode.json")
    if (!existsSync(cfgPath)) return out
    try {
      const parsed = JSON.parse(readFileSync(cfgPath, "utf8")) as {
        mcp?: { servers?: Record<string, { type?: string; disabled?: boolean; command?: string[] }> }
      }
      if (!parsed.mcp || typeof parsed.mcp !== "object") {
        parsed.mcp = { servers: {} }
      }
      if (!parsed.mcp.servers || typeof parsed.mcp.servers !== "object") {
        parsed.mcp.servers = {}
      }
      const servers = parsed.mcp.servers

      // Consolidate legacy per-slot `cyberlab-<slotId>` entries (including 40+ individual bun processes
      // or legacy `type: "remote"` Burp entries) into a SINGLE ultra-fast `cyberlab-arsenal` Hub server
      // so Windows never suffers a 45-process startup storm and OpenCode sees 100% of enabled tools!
      let migratedAny = false
      for (const [k, v] of Object.entries({ ...servers })) {
        if (!k.startsWith("cyberlab-") || k === "cyberlab-arsenal") continue
        const slotId = k.slice("cyberlab-".length)
        // Preserve native standalone MCP binaries (rea mcp / hexstrike-mcp) if explicitly configured
        const cmdJoined = Array.isArray(v?.command) ? v.command.join(" ") : ""
        const isDedicatedNative =
          (slotId === "rea" || slotId === "hexstrike-ai") &&
          !cmdJoined.includes("arsenal-mcp-stdio.ts")
        if (isDedicatedNative) continue

        if (v && !v.disabled) {
          enabledHubSlots.add(slotId)
        }
        delete servers[k]
        migratedAny = true
      }

      if (migratedAny) {
        this.writeEnabledHubSlotsToDisk(enabledHubSlots)
        if (enabledHubSlots.size > 0) {
          servers["cyberlab-arsenal"] = this.buildHubServerEntry() as {
            type?: string
            disabled?: boolean
            command?: string[]
          }
        }
        try {
          writeFileSync(cfgPath, `${JSON.stringify(parsed, null, 2)}\n`, "utf8")
        } catch {
          // Ignore read-only workspace
        }
      }

      const hubServer = servers["cyberlab-arsenal"]
      if (hubServer && !hubServer.disabled) {
        for (const slotId of enabledHubSlots) {
          out.add(`cyberlab-${slotId}`)
        }
      }

      for (const [k, v] of Object.entries(servers)) {
        if (v && !v.disabled) out.add(k)
      }
    } catch {
      // Ignore malformed opencode.json
    }
    return out
  }

  private resolveSlotMcpMeta(def: ArsenalSlotDefinition): {
    mcpCapable: boolean
    mcpLabel: string | null
  } {
    if (NON_MCP_SLOT_IDS.has(def.slotId)) {
      return { mcpCapable: false, mcpLabel: null }
    }
    const mcpCapable =
      def.mcpCapable !== undefined
        ? def.mcpCapable
        : def.kind === "cli_runner" ||
          def.kind === "web_embed" ||
          def.category === "web_proxy_suite" ||
          def.category === "reverse_mobile" ||
          def.slotId === "wireshark"
    if (!mcpCapable) return { mcpCapable: false, mcpLabel: null }
    const mcpLabel =
      def.mcpLabel ??
      CUSTOM_MCP_LABELS[def.slotId] ??
      `${def.shortLabel} MCP`
    return { mcpCapable: true, mcpLabel }
  }

  private toggleSlotMcpInOpenCodeConfig(slot: ArsenalSlotStatus): {
    connected: boolean
    message: string
  } {
    // Ensure any legacy per-slot entries are migrated first
    this.readConnectedMcpServerKeys()

    const cfgPath = path.join(this.workspaceRoot, "opencode.json")
    let doc: Record<string, unknown> = {}
    if (existsSync(cfgPath)) {
      try {
        doc = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>
      } catch {
        doc = {}
      }
    }
    if (!doc.mcp || typeof doc.mcp !== "object") {
      doc.mcp = { servers: {} }
    }
    const mcpObj = doc.mcp as { servers?: Record<string, unknown> }
    if (!mcpObj.servers || typeof mcpObj.servers !== "object") {
      mcpObj.servers = {}
    }

    const dedicatedKey = `cyberlab-${slot.slotId}`
    const isNativeStandalone =
      (slot.slotId === "rea" && Boolean(slot.wslPath || slot.posixPath || slot.windowsPath)) ||
      (slot.slotId === "hexstrike-ai" && Boolean(slot.wslPath || slot.posixPath))

    if (isNativeStandalone) {
      const existingDedicated = mcpObj.servers[dedicatedKey] as { disabled?: boolean } | undefined
      if (existingDedicated && !existingDedicated.disabled) {
        delete mcpObj.servers[dedicatedKey]
        writeFileSync(cfgPath, `${JSON.stringify(doc, null, 2)}\n`, "utf8")
        return {
          connected: false,
          message: `Conexão MCP dedicada de "${slot.shortLabel}" desconectada do opencode.json.`,
        }
      }
      mcpObj.servers[dedicatedKey] =
        slot.slotId === "rea"
          ? process.platform === "win32" && !slot.windowsPath
            ? {
                type: "local",
                command: ["wsl.exe", "-d", this.config.preferredWslDistro, "--", "rea", "mcp"],
              }
            : {
                type: "local",
                command: [slot.windowsPath ?? slot.posixPath ?? "rea", "mcp"],
              }
          : process.platform === "win32"
            ? {
                type: "local",
                command: ["wsl.exe", "-d", this.config.preferredWslDistro, "--", "/usr/local/bin/hexstrike-mcp"],
              }
            : {
                type: "local",
                command: ["/usr/local/bin/hexstrike-mcp"],
              }
      writeFileSync(cfgPath, `${JSON.stringify(doc, null, 2)}\n`, "utf8")
      return {
        connected: true,
        message: `🔌 MCP Nativo "${slot.mcpLabel ?? slot.shortLabel}" conectado ao Agente OpenCode (${dedicatedKey})!`,
      }
    }

    const enabledHubSlots = this.readEnabledHubSlotsFromDisk()
    const hubServer = mcpObj.servers["cyberlab-arsenal"] as { disabled?: boolean } | undefined
    const currentlyActive = Boolean(hubServer && !hubServer.disabled && enabledHubSlots.has(slot.slotId))

    if (currentlyActive) {
      enabledHubSlots.delete(slot.slotId)
      this.writeEnabledHubSlotsToDisk(enabledHubSlots)
      // Keep cyberlab-arsenal Hub online so CyberLab-Knowledge/ and investigation_memory MCP tools remain available
      mcpObj.servers["cyberlab-arsenal"] = this.buildHubServerEntry()
      writeFileSync(cfgPath, `${JSON.stringify(doc, null, 2)}\n`, "utf8")
      return {
        connected: false,
        message: `Conexão MCP de "${slot.shortLabel}" desativada no Hub CyberLab Arsenal (biblioteca CyberLab-Knowledge permanece online).`,
      }
    }

    enabledHubSlots.add(slot.slotId)
    this.writeEnabledHubSlotsToDisk(enabledHubSlots)
    mcpObj.servers["cyberlab-arsenal"] = this.buildHubServerEntry()
    writeFileSync(cfgPath, `${JSON.stringify(doc, null, 2)}\n`, "utf8")
    return {
      connected: true,
      message: `🔌 MCP "${slot.mcpLabel ?? slot.shortLabel}" ativado em tempo real no Hub CyberLab Arsenal (${enabledHubSlots.size} ferramenta(s) ativa(s))!`,
    }
  }

  getOverview(forceRefresh = false): ArsenalOverview {
    if (forceRefresh || !this.lastProbedAt) {
      this.probeEnvironment()
    }

    const connectedMcpKeys = this.readConnectedMcpServerKeys()

    const slots: ArsenalSlotStatus[] = this.getAllDefinitions().map((def) => {
      const override = this.config.slotOverrides[def.slotId] ?? {}
      const probe = this.cachedSlotProbes.get(def.slotId) ?? {
        windowsPath: null,
        wslPath: null,
        posixPath: null,
        localHtmlEntry: null,
      }
      const daemon = this.daemons.get(def.slotId)
      const availableRuntimes: Array<"windows" | "wsl" | "linux_mac" | "web"> = []
      if (probe.windowsPath) availableRuntimes.push("windows")
      if (probe.wslPath) availableRuntimes.push("wsl")
      if (probe.posixPath) availableRuntimes.push("linux_mac")

      const embedUrl =
        daemon?.embedUrl ??
        override.customEmbedUrl ??
        null

      if (def.kind === "web_embed" && (probe.localHtmlEntry || embedUrl || def.defaultEmbedUrl)) {
        availableRuntimes.push("web")
      }

      const pref = override.preferredRuntime ?? "auto"
      let activeRuntime: ArsenalSlotStatus["activeRuntime"] = "none"
      let resolvedPath: string | null = null

      if (pref === "windows" && probe.windowsPath) {
        activeRuntime = "windows"
        resolvedPath = probe.windowsPath
      } else if (pref === "wsl" && probe.wslPath) {
        activeRuntime = "wsl"
        resolvedPath = probe.wslPath
      } else if (pref === "linux_mac" && probe.posixPath) {
        activeRuntime = "linux_mac"
        resolvedPath = probe.posixPath
      } else if (probe.windowsPath) {
        activeRuntime = "windows"
        resolvedPath = probe.windowsPath
      } else if (probe.posixPath) {
        activeRuntime = "linux_mac"
        resolvedPath = probe.posixPath
      } else if (probe.wslPath) {
        activeRuntime = "wsl"
        resolvedPath = probe.wslPath
      } else if (probe.localHtmlEntry) {
        activeRuntime = "web"
        resolvedPath = probe.localHtmlEntry
      } else if (def.kind === "web_embed" && override.customEmbedUrl) {
        activeRuntime = "web"
        resolvedPath = override.customEmbedUrl
      }

      const installed =
        Boolean(probe.windowsPath || probe.wslPath || probe.posixPath || probe.localHtmlEntry) ||
        Boolean(override.customEmbedUrl) ||
        def.slotId === "kali-desktop-stream" && this.wslAvailable

      const { mcpCapable, mcpLabel } = this.resolveSlotMcpMeta(def)
      const mcpConnected =
        connectedMcpKeys.has(`cyberlab-${def.slotId}`) ||
        connectedMcpKeys.has(def.slotId)

      return {
        slotId: def.slotId,
        name: def.name,
        shortLabel: def.shortLabel,
        category: def.category,
        kind: def.kind,
        tagline: def.tagline,
        description: def.description,
        upstreamUrl: def.upstreamUrl,
        licenseNote: def.licenseNote,
        isCustom: Boolean(def.isCustom),
        installed,
        availableRuntimes,
        activeRuntime,
        resolvedPath,
        windowsPath: probe.windowsPath,
        wslPath: probe.wslPath,
        posixPath: probe.posixPath,
        embedUrl,
        daemonRunning: Boolean(daemon),
        companionProxyPort: override.companionProxyPort ?? def.companionProxyPort ?? null,
        mcpCapable,
        mcpConnected,
        mcpLabel,
        installPowerShell: def.installPowerShell,
        installKaliWsl: def.installKaliWsl,
        presets: def.presets,
        override,
      }
    })

    const runs = Array.from(this.runs.values())
      .map((r) => ({ ...r.info }))
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt))

    const categories = (Object.keys(ARSENAL_CATEGORY_LABELS) as ArsenalCategory[]).map((id) => ({
      id,
      title: ARSENAL_CATEGORY_LABELS[id].title,
      subtitle: ARSENAL_CATEGORY_LABELS[id].subtitle,
    }))

    return {
      environment: {
        hostPlatform: process.platform,
        toolsRootDir: this.config.toolsRootDir,
        wslAvailable: this.wslAvailable,
        wslDistros: [...this.wslDistros],
        preferredWslDistro: this.config.preferredWslDistro,
        enforceScopeOnCliRuns: this.config.enforceScopeOnCliRuns,
        lastProbedAt: this.lastProbedAt,
      },
      categories,
      slots,
      runs,
    }
  }

  configureSettings(params: {
    toolsRootDir?: string
    preferredWslDistro?: string
    enforceScopeOnCliRuns?: boolean
    slotId?: string
    slotOverride?: SlotUserOverride
  }): ArsenalOverview {
    if (params.toolsRootDir !== undefined && stripSurroundingQuotes(params.toolsRootDir)) {
      this.config.toolsRootDir = stripSurroundingQuotes(params.toolsRootDir)
    }
    if (params.preferredWslDistro !== undefined && params.preferredWslDistro.trim()) {
      this.config.preferredWslDistro = params.preferredWslDistro.trim()
    }
    if (params.enforceScopeOnCliRuns !== undefined) {
      this.config.enforceScopeOnCliRuns = params.enforceScopeOnCliRuns
    }
    if (params.slotId && params.slotOverride) {
      const cleaned: SlotUserOverride = { ...params.slotOverride }
      if (cleaned.customExecutablePath !== undefined) {
        const p = stripSurroundingQuotes(cleaned.customExecutablePath)
        cleaned.customExecutablePath = p || undefined
      }
      if (cleaned.customEmbedUrl !== undefined) {
        const u = stripSurroundingQuotes(cleaned.customEmbedUrl)
        cleaned.customEmbedUrl = u || undefined
      }
      this.config.slotOverrides[params.slotId] = {
        ...this.config.slotOverrides[params.slotId],
        ...cleaned,
      }
      // Stop any running daemon for this slot so the next launch uses the updated executable/JAR/URL
      const runningDaemon = this.daemons.get(params.slotId)
      if (runningDaemon) {
        if (runningDaemon.child) this.terminateProcessTree(runningDaemon.child)
        if (runningDaemon.tcpBridges) {
          for (const srv of runningDaemon.tcpBridges) srv.close()
        }
        if (runningDaemon.staticServer) runningDaemon.staticServer.close()
        this.daemons.delete(params.slotId)
      }
    }
    this.saveConfig()
    return this.getOverview(true)
  }

  upsertCustomSlot(slot: {
    slotId?: string
    name: string
    shortLabel?: string
    kind: ArsenalSlotKind
    tagline?: string
    description?: string
    executableOrUrl: string
    preferredRuntime?: ArsenalRuntimePreference
    companionProxyPort?: number
    defaultArgsTemplate?: string
  }): ArsenalOverview {
    const cleanName = slot.name.trim().slice(0, 80)
    if (!cleanName) throw new Error("Custom slot name is required")
    const id =
      slot.slotId && slot.slotId.startsWith("custom-")
        ? slot.slotId
        : `custom-${cleanName.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 28)}-${crypto.randomUUID().slice(0, 4)}`

    const execOrUrl = slot.executableOrUrl.trim()
    const isWeb = slot.kind === "web_embed"

    const def: ArsenalSlotDefinition = {
      slotId: id,
      name: cleanName,
      shortLabel: (slot.shortLabel?.trim() || cleanName).slice(0, 24),
      category: "custom",
      kind: slot.kind,
      tagline: slot.tagline?.trim() || `Slot personalizado (${slot.kind})`,
      description: slot.description?.trim() || `Ferramenta externa personalizada conectada pelo operador: ${execOrUrl}`,
      upstreamUrl: isWeb ? execOrUrl : "local://custom-slot",
      licenseNote: "Custom User Tool (Externo)",
      isCustom: true,
      windowsBinaries: !isWeb && process.platform === "win32" ? [execOrUrl] : [],
      posixBinaries: !isWeb ? [execOrUrl] : [],
      ...(isWeb ? { defaultEmbedUrl: execOrUrl } : {}),
      ...(slot.companionProxyPort ? { companionProxyPort: slot.companionProxyPort } : {}),
      installPowerShell: `# Configurado manualmente: ${execOrUrl}`,
      installKaliWsl: `# Configurado manualmente: ${execOrUrl}`,
      presets: slot.defaultArgsTemplate?.trim()
        ? [
            {
              id: `${id}-default`,
              label: "Comando Padrão",
              description: "Preset salvo no slot personalizado",
              argsTemplate: slot.defaultArgsTemplate.trim(),
            },
          ]
        : [],
    }

    const idx = this.config.customSlots.findIndex((s) => s.slotId === id)
    if (idx >= 0) {
      this.config.customSlots[idx] = def
    } else {
      this.config.customSlots.push(def)
    }

    if (!isWeb && execOrUrl) {
      this.config.slotOverrides[id] = {
        ...this.config.slotOverrides[id],
        customExecutablePath: execOrUrl,
        ...(slot.preferredRuntime ? { preferredRuntime: slot.preferredRuntime } : {}),
      }
    } else if (isWeb && execOrUrl) {
      this.config.slotOverrides[id] = {
        ...this.config.slotOverrides[id],
        customEmbedUrl: execOrUrl,
      }
    }

    this.saveConfig()
    return this.getOverview(true)
  }

  removeCustomSlot(slotId: string): ArsenalOverview {
    this.config.customSlots = this.config.customSlots.filter((s) => s.slotId !== slotId)
    delete this.config.slotOverrides[slotId]
    this.saveConfig()
    return this.getOverview(true)
  }

  private buildTemplateVars(useWslPaths: boolean, target?: string): Record<string, string> {
    const outputsHost = path.join(this.workspaceRoot, ".cyberlab", "outputs")
    const importsHost = path.join(this.workspaceRoot, ".cyberlab", "imports")
    mkdirSync(outputsHost, { recursive: true })
    mkdirSync(importsHost, { recursive: true })

    const wsPath = useWslPaths ? windowsPathToWslPath(this.workspaceRoot) : this.workspaceRoot
    const outPath = useWslPaths ? windowsPathToWslPath(outputsHost) : outputsHost
    const impPath = useWslPaths ? windowsPathToWslPath(importsHost) : importsHost

    const scope: ProjectScope | undefined = this.scopes.getProjectScope(this.projectId)
    const firstHeader = scope?.engagement?.customHeaders?.find((h) => h.enabled)
    const bountyHeaderFlag = firstHeader ? `-H "${firstHeader.name}: ${firstHeader.value}"` : ""

    return {
      workspace: wsPath,
      outputs: outPath,
      imports: impPath,
      target: target?.trim() || "http://127.0.0.1:4096",
      bounty_header_flag: bountyHeaderFlag,
    }
  }

  private expandArgsString(rawArgs: string, vars: Record<string, string>): string {
    return rawArgs
      .replace(/\{workspace\}/g, vars.workspace ?? "")
      .replace(/\{outputs\}/g, vars.outputs ?? "")
      .replace(/\{imports\}/g, vars.imports ?? "")
      .replace(/\{target\}/g, vars.target ?? "")
      .replace(/\{bounty_header_flag\}/g, vars.bounty_header_flag ?? "")
      .trim()
  }

  private verifyTargetAgainstScopeIfEnabled(target?: string, expandedArgs?: string): void {
    if (!this.config.enforceScopeOnCliRuns) return
    const candidates: string[] = []
    if (target?.trim()) candidates.push(target.trim())
    if (expandedArgs) {
      const urlMatches = expandedArgs.match(/https?:\/\/[^\s"']+/gi) ?? []
      candidates.push(...urlMatches)
    }
    if (candidates.length === 0) return
    const check = this.scopes.verifyTargets(this.projectId, {
      networkTargets: candidates,
      workspacePaths: [],
    })
    if (!check.allowed) {
      throw new Error(`Bloqueado pela Trava de Escopo Bug Bounty: ${check.reason ?? "alvo fora do escopo"}`)
    }
  }

  private async startStaticHtmlServer(entryHtmlPath: string): Promise<{ server: http.Server; url: string }> {
    const baseDir = path.dirname(entryHtmlPath)
    const entryFile = path.basename(entryHtmlPath)
    const srv = http.createServer((req, res) => {
      try {
        const parsed = new URL(req.url ?? "/", "http://127.0.0.1")
        const rel = decodeURIComponent(parsed.pathname === "/" ? entryFile : parsed.pathname.replace(/^\/+/, ""))
        const targetFile = path.resolve(baseDir, rel)
        if (!isPathInsideRoot(targetFile, baseDir) || !existsSync(targetFile)) {
          res.writeHead(404)
          res.end("Not found")
          return
        }
        const ext = path.extname(targetFile).toLowerCase()
        const rawBuf = readFileSync(targetFile)
        const bodyBuf = ext === ".html" || ext === ".htm" ? injectZoomHelperIntoHtml(rawBuf) : rawBuf
        res.writeHead(200, {
          "Content-Type": MIME_BY_EXT[ext] ?? "application/octet-stream",
          "Cache-Control": "no-cache",
        })
        res.end(bodyBuf)
      } catch {
        res.writeHead(500)
        res.end("Static server error")
      }
    })
    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject)
      srv.listen(0, "127.0.0.1", () => resolve())
    })
    const port = (srv.address() as net.AddressInfo).port
    return { server: srv, url: `http://127.0.0.1:${port}/` }
  }

  private allocateX11Display(): number {
    const used = new Set<number>()
    for (const d of this.daemons.values()) {
      if (d.wslDisplayNum !== undefined) used.add(d.wslDisplayNum)
    }
    for (let disp = 91; disp <= 98; disp++) {
      if (!used.has(disp)) return disp
    }
    return 99
  }

  private async createTcpBridgeServer(
    remoteHosts: string[],
    remotePort: number,
    listenPort = 0,
  ): Promise<{ server: net.Server; localPort: number } | null> {
    const srv = net.createServer((clientSocket) => {
      clientSocket.setNoDelay(true)
      let connected = false
      const tryConnect = (idx: number) => {
        if (idx >= remoteHosts.length) {
          clientSocket.destroy()
          return
        }
        const upstream = net.connect({ host: remoteHosts[idx]!, port: remotePort })
        upstream.setNoDelay(true)
        upstream.once("connect", () => {
          connected = true
          clientSocket.pipe(upstream)
          upstream.pipe(clientSocket)
        })
        upstream.once("error", () => {
          if (!connected) {
            upstream.destroy()
            tryConnect(idx + 1)
          } else {
            clientSocket.destroy()
          }
        })
        clientSocket.once("error", () => upstream.destroy())
        clientSocket.once("close", () => upstream.destroy())
        upstream.once("close", () => clientSocket.destroy())
      }
      tryConnect(0)
    })

    try {
      await new Promise<void>((resolve, reject) => {
        srv.once("error", reject)
        srv.listen(listenPort, "127.0.0.1", () => resolve())
      })
      const localPort = (srv.address() as net.AddressInfo).port
      return { server: srv, localPort }
    } catch {
      try {
        srv.close()
      } catch {
        // Ignore
      }
      return null
    }
  }

  private async waitForTcpPort(hosts: string[], port: number, timeoutMs = 4000): Promise<string | null> {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      for (const host of hosts) {
        const ok = await new Promise<boolean>((resolve) => {
          const sock = net.connect({ host, port })
          const timer = setTimeout(() => {
            sock.destroy()
            resolve(false)
          }, 350)
          sock.once("connect", () => {
            clearTimeout(timer)
            sock.end()
            resolve(true)
          })
          sock.once("error", () => {
            clearTimeout(timer)
            sock.destroy()
            resolve(false)
          })
        })
        if (ok) return host
      }
      await new Promise((r) => setTimeout(r, 180))
    }
    return null
  }

  private async createEmbedHttpProxyServer(
    remoteHosts: string[],
    remotePort: number,
    options?: { upstreamTls?: boolean },
  ): Promise<{ server: http.Server; localPort: number } | null> {
    const upstreamTls = Boolean(options?.upstreamTls)
    const scheme = upstreamTls ? "https" : "http"

    const pickHost = async (): Promise<string> => {
      for (const h of remoteHosts) {
        const ok = await new Promise<boolean>((resolve) => {
          const s = net.connect({ host: h, port: remotePort })
          const t = setTimeout(() => {
            s.destroy()
            resolve(false)
          }, 300)
          s.once("connect", () => {
            clearTimeout(t)
            s.end()
            resolve(true)
          })
          s.once("error", () => {
            clearTimeout(t)
            s.destroy()
            resolve(false)
          })
        })
        if (ok) return h
      }
      return remoteHosts[0] ?? "127.0.0.1"
    }

    let cachedUpstreamHost = await pickHost()

    const srv = http.createServer((req, res) => {
      const forwardHeaders: http.OutgoingHttpHeaders = { ...req.headers }
      const acceptHdr = typeof req.headers.accept === "string" ? req.headers.accept : ""
      const wantsHtmlDoc = req.method === "GET" && acceptHdr.includes("text/html")
      if (wantsHtmlDoc) {
        // Request uncompressed HTML on top-level iframe navigations so we can inject the native page-zoom helper cleanly
        forwardHeaders["accept-encoding"] = "identity"
      }
      forwardHeaders.host = `127.0.0.1:${remotePort}`
      forwardHeaders.origin = `${scheme}://127.0.0.1:${remotePort}`
      forwardHeaders.referer = `${scheme}://127.0.0.1:${remotePort}/`
      if (forwardHeaders["sec-fetch-site"]) {
        forwardHeaders["sec-fetch-site"] = "same-origin"
      }

      const handleUpstreamResponse = (upstreamRes: http.IncomingMessage) => {
        const outHeaders: http.OutgoingHttpHeaders = { ...upstreamRes.headers }
        delete outHeaders["x-frame-options"]
        delete outHeaders["X-Frame-Options"]
        const csp = outHeaders["content-security-policy"]
        if (typeof csp === "string") {
          const stripped = csp.replace(/frame-ancestors\s+[^;]+;?/gi, "").trim()
          if (stripped) outHeaders["content-security-policy"] = stripped
          else delete outHeaders["content-security-policy"]
        }
        // When terminating local self-signed HTTPS (e.g. PentAGI :8443) onto 127.0.0.1 HTTP, normalize Set-Cookie
        const setCookie = outHeaders["set-cookie"]
        if (upstreamTls && setCookie) {
          const list = Array.isArray(setCookie) ? setCookie : [String(setCookie)]
          outHeaders["set-cookie"] = list.map((c) =>
            c
              .replace(/;\s*Secure/gi, "")
              .replace(/SameSite=Strict/gi, "SameSite=Lax"),
          )
        }
        // Rewrite absolute https://127.0.0.1:8443 Location redirects to relative paths
        if (upstreamTls && typeof outHeaders.location === "string") {
          outHeaders.location = outHeaders.location.replace(
            new RegExp(`^https:\\/\\/(?:127\\.0\\.0\\.1|localhost|[^/]+):${remotePort}`, "i"),
            "",
          ) || "/"
        }

        const ctype = String(outHeaders["content-type"] ?? "").toLowerCase()
        const cenc = String(outHeaders["content-encoding"] ?? "").toLowerCase()
        if (wantsHtmlDoc && ctype.includes("text/html") && (!cenc || cenc === "identity")) {
          const chunks: Buffer[] = []
          upstreamRes.on("data", (ch: Buffer) => chunks.push(ch))
          upstreamRes.on("end", () => {
            const injected = injectZoomHelperIntoHtml(Buffer.concat(chunks))
            outHeaders["content-length"] = String(injected.byteLength)
            res.writeHead(upstreamRes.statusCode ?? 200, outHeaders)
            res.end(injected)
          })
          return
        }

        res.writeHead(upstreamRes.statusCode ?? 200, outHeaders)
        upstreamRes.pipe(res)
      }

      const upstreamReq = upstreamTls
        ? https.request(
            {
              host: cachedUpstreamHost,
              port: remotePort,
              method: req.method,
              path: req.url ?? "/",
              headers: forwardHeaders,
              rejectUnauthorized: false,
            },
            handleUpstreamResponse,
          )
        : http.request(
            {
              host: cachedUpstreamHost,
              port: remotePort,
              method: req.method,
              path: req.url ?? "/",
              headers: forwardHeaders,
            },
            handleUpstreamResponse,
          )

      upstreamReq.on("error", async () => {
        cachedUpstreamHost = await pickHost()
        if (!res.headersSent) {
          res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" })
        }
        res.end("Aguardando inicialização do servidor Web local da ferramenta... Clique em Recarregar em instantes.")
      })

      req.pipe(upstreamReq)
    })

    srv.on("upgrade", (req, clientSocket, head) => {
      const upstream = upstreamTls
        ? tls.connect({
            host: cachedUpstreamHost,
            port: remotePort,
            rejectUnauthorized: false,
          })
        : net.connect({ host: cachedUpstreamHost, port: remotePort })
      upstream.setNoDelay(true)
      clientSocket.on("error", () => upstream.destroy())
      upstream.on("error", () => clientSocket.destroy())
      const connectEvent = upstreamTls ? "secureConnect" : "connect"
      upstream.once(connectEvent, () => {
        const headerLines: string[] = [`${req.method ?? "GET"} ${req.url ?? "/"} HTTP/1.1`]
        for (const [k, v] of Object.entries(req.headers)) {
          if (v === undefined) continue
          const low = k.toLowerCase()
          if (low === "host") {
            headerLines.push(`Host: 127.0.0.1:${remotePort}`)
          } else if (low === "origin") {
            headerLines.push(`Origin: ${scheme}://127.0.0.1:${remotePort}`)
          } else if (low === "sec-fetch-site") {
            headerLines.push("Sec-Fetch-Site: same-origin")
          } else if (Array.isArray(v)) {
            for (const item of v) headerLines.push(`${k}: ${item}`)
          } else {
            headerLines.push(`${k}: ${v}`)
          }
        }
        headerLines.push("", "")
        upstream.write(headerLines.join("\r\n"))
        if (head && head.byteLength > 0) upstream.write(head)
        upstream.pipe(clientSocket)
        clientSocket.pipe(upstream)
      })
    })

    try {
      await new Promise<void>((resolve, reject) => {
        srv.once("error", reject)
        srv.listen(0, "127.0.0.1", () => resolve())
      })
      const localPort = (srv.address() as net.AddressInfo).port
      return { server: srv, localPort }
    } catch {
      try {
        srv.close()
      } catch {
        // Ignore
      }
      return null
    }
  }

  private findWindowsJavaExecutable(preferredBaseDir?: string): string {
    const localAppData =
      process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local")
    const progFiles = process.env.ProgramFiles ?? "C:\\Program Files"
    const directCandidates = [
      preferredBaseDir ? path.join(preferredBaseDir, "jre", "bin", "javaw.exe") : "",
      preferredBaseDir ? path.join(preferredBaseDir, "jre", "bin", "java.exe") : "",
      path.join(localAppData, "BurpSuiteCommunity", "jre", "bin", "javaw.exe"),
      path.join(localAppData, "Programs", "BurpSuiteCommunity", "jre", "bin", "javaw.exe"),
      path.join(progFiles, "BurpSuiteCommunity", "jre", "bin", "javaw.exe"),
    ].filter(Boolean)
    for (const c of directCandidates) {
      if (existsSync(c)) return c
    }
    for (const vendorRoot of [
      path.join(progFiles, "Eclipse Adoptium"),
      path.join(progFiles, "Java"),
      path.join(progFiles, "Microsoft"),
    ]) {
      if (!existsSync(vendorRoot)) continue
      try {
        for (const sub of readdirSync(vendorRoot)) {
          const jw = path.join(vendorRoot, sub, "bin", "javaw.exe")
          if (existsSync(jw)) return jw
        }
      } catch {
        // Ignore
      }
    }
    return this.findWhereOnWindows(["javaw.exe", "java.exe"]) ?? "javaw.exe"
  }

  private findPreferredWindowsBurpJar(slot: ArsenalSlotStatus): string | null {
    // 0. Explicit user override (.jar or .exe) takes highest priority!
    const customRaw = slot.override.customExecutablePath
      ? stripSurroundingQuotes(slot.override.customExecutablePath)
      : ""
    if (customRaw && existsSync(customRaw)) {
      const realCustom = safeRealpath(customRaw)
      if (/\.jar$/i.test(realCustom)) {
        return realCustom
      }
      const customDir = path.dirname(realCustom)
      for (const d of [customDir, path.join(customDir, "app"), path.dirname(customDir)]) {
        if (!existsSync(d)) continue
        try {
          const jar =
            readdirSync(d).find((f) => /^burpsuite_community.*\.jar$/i.test(f)) ??
            readdirSync(d).find((f) => /^burpsuite.*\.jar$/i.test(f)) ??
            readdirSync(d).find((f) => /\.jar$/i.test(f))
          if (jar) return path.join(d, jar)
        } catch {
          // Ignore
        }
      }
    }

    const localAppData =
      process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local")
    const progFiles = process.env.ProgramFiles ?? "C:\\Program Files"
    const userHome = os.homedir()
    const resolvedWinSlot = slot.windowsPath ? safeRealpath(slot.windowsPath) : ""
    if (resolvedWinSlot && /\.jar$/i.test(resolvedWinSlot) && existsSync(resolvedWinSlot)) {
      return resolvedWinSlot
    }

    const extraDownloadDirs: string[] = []
    for (const userFolder of [path.join(userHome, "Downloads"), path.join(userHome, "Desktop")]) {
      if (!existsSync(userFolder)) continue
      extraDownloadDirs.push(userFolder)
      try {
        for (const ent of readdirSync(userFolder, { withFileTypes: true })) {
          if (ent.isDirectory() && /burp/i.test(ent.name)) {
            extraDownloadDirs.push(path.join(userFolder, ent.name))
          }
        }
      } catch {
        // Ignore
      }
    }

    const candidateDirs = Array.from(
      new Set(
        [
          resolvedWinSlot ? path.dirname(resolvedWinSlot) : "",
          path.join(localAppData, "BurpSuiteCommunity"),
          path.join(localAppData, "Programs", "BurpSuiteCommunity"),
          path.join(progFiles, "BurpSuiteCommunity"),
          path.join(userHome, "BurpSuiteCommunity"),
          path.join(localAppData, "BurpSuite"),
          path.join(progFiles, "BurpSuite"),
          path.join(this.config.toolsRootDir, "BurpSuite"),
          this.config.toolsRootDir,
          ...extraDownloadDirs,
        ].filter(Boolean),
      ),
    )

    // Pass 1: strictly prefer Burp Suite Community JAR (free, zero license key blocking)
    for (const dir of candidateDirs) {
      if (!existsSync(dir)) continue
      try {
        const comm = readdirSync(dir).find((f) => /^burpsuite_community.*\.jar$/i.test(f))
        if (comm) return path.join(dir, comm)
      } catch {
        // Ignore
      }
    }

    // Pass 2: accept any burpsuite*.jar if Community wasn't found
    for (const dir of candidateDirs) {
      if (!existsSync(dir)) continue
      try {
        const anyJar = readdirSync(dir).find((f) => /^burpsuite.*\.jar$/i.test(f))
        if (anyJar) return path.join(dir, anyJar)
      } catch {
        // Ignore
      }
    }
    return null
  }

  private buildCyberLabCanvasHtml(slotTitle: string): string {
    const safeTitle = slotTitle.replace(/[<>&"]/g, "")
    return `<!DOCTYPE html>
<html lang="pt-BR" translate="no" class="notranslate">
<head>
  <meta charset="utf-8" />
  <meta name="google" content="notranslate" />
  <title>${safeTitle}</title>
  <style>
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      width: 100%;
      height: 100%;
      background: #09090b;
      overflow: hidden;
      font-family: system-ui, -apple-system, sans-serif;
    }
    #status_pill {
      position: fixed;
      top: 8px;
      right: 12px;
      z-index: 50;
      background: rgba(16, 185, 129, 0.16);
      border: 1px solid rgba(16, 185, 129, 0.45);
      color: #6ee7b7;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 11px;
      pointer-events: none;
      transition: opacity 0.25s ease;
    }
    #status_pill.hidden { opacity: 0; }
    #screen {
      width: 100%;
      height: 100%;
      overflow: hidden;
      background: #09090b;
    }
    #screen > div {
      scrollbar-width: thin;
      scrollbar-color: #10b981 #18181b;
    }
    #screen.scroll-mode > div {
      overflow: auto !important;
      align-items: flex-start !important;
      justify-content: flex-start !important;
    }
    #screen > div::-webkit-scrollbar { width: 11px; height: 11px; }
    #screen > div::-webkit-scrollbar-track { background: #18181b; }
    #screen > div::-webkit-scrollbar-thumb {
      background: #10b981;
      border-radius: 6px;
      border: 2px solid #18181b;
    }
  </style>
  <script type="module">
    import RFB from './core/rfb.js';

    const pill = document.getElementById('status_pill');
    const screenEl = document.getElementById('screen');
    const params = new URLSearchParams(window.location.search);
    let currentMode = params.get('mode') || 'native';
    let currentZoom = Number(params.get('zoom') || '100');
    let rfb = null;
    let retryTimer = null;

    function installPrecisionZoomHooks(instance) {
      // NEVER use CSS canvas.style.zoom or CSS transform: scale()!
      // Instead, drive scaling EXCLUSIVELY through noVNC's own Display._scale (so absX/absY divide pointer coords by the exact same scale!)
      // and ExtendedDesktopSize (so X11 reflows cleanly to containerSize / zoomFactor in native mode!).
      instance._updateScale = function () {
        if (!this._display) return;
        const z = Math.max(0.6, Math.min(1.8, currentZoom / 100));
        if (currentMode === 'scroll') {
          this._display.scale = z;
        } else if (this._scaleViewport) {
          const r = screenEl.getBoundingClientRect();
          if (r.width > 0 && r.height > 0) {
            this._display.autoscale(r.width, r.height);
          }
        } else {
          this._display.scale = 1.0;
        }
        this._fixScrollbars();
      };

      const origRequestRemoteResize = instance._requestRemoteResize.bind(instance);
      instance._requestRemoteResize = function () {
        if (!this._resizeSession || this._viewOnly || !this._supportsSetDesktopSize) {
          return origRequestRemoteResize();
        }
        if (this._pendingRemoteResize) return;
        const r = screenEl.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return;
        const z = currentMode === 'native' ? Math.max(0.6, Math.min(1.8, currentZoom / 100)) : 1.0;
        const desiredW = Math.max(680, Math.floor(r.width / z));
        const desiredH = Math.max(440, Math.floor(r.height / z));
        if (desiredW === this._fbWidth && desiredH === this._fbHeight) {
          this._updateScale();
          return;
        }
        const origScreenSize = this._screenSize;
        this._screenSize = () => ({ w: desiredW, h: desiredH });
        try {
          origRequestRemoteResize();
        } finally {
          this._screenSize = origScreenSize;
        }
      };
    }

    function applyFraming() {
      if (!rfb) return;
      const canvas = screenEl.querySelector('canvas');
      if (canvas) {
        canvas.style.zoom = '';
        canvas.style.transform = '';
      }
      if (currentMode === 'native') {
        screenEl.classList.remove('scroll-mode');
        rfb.clipViewport = false;
        rfb.scaleViewport = true;
        rfb.resizeSession = true;
        rfb._requestRemoteResize();
        rfb._updateScale();
      } else if (currentMode === 'fit') {
        screenEl.classList.remove('scroll-mode');
        rfb.resizeSession = false;
        rfb.clipViewport = false;
        rfb.scaleViewport = true;
        rfb._updateScale();
      } else {
        screenEl.classList.add('scroll-mode');
        rfb.resizeSession = false;
        rfb.clipViewport = false;
        rfb.scaleViewport = false;
        rfb._updateScale();
      }
    }

    function connectVnc() {
      clearTimeout(retryTimer);
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = proto + '//' + window.location.host + '/websockify';
      try {
        rfb = new RFB(screenEl, wsUrl);
        installPrecisionZoomHooks(rfb);
        rfb.background = '#09090b';
        rfb.addEventListener('connect', () => {
          pill.classList.add('hidden');
          applyFraming();
          setTimeout(applyFraming, 220);
          setTimeout(applyFraming, 700);
        });
        rfb.addEventListener('disconnect', () => {
          pill.textContent = 'Reconectando tela gráfica...';
          pill.classList.remove('hidden');
          retryTimer = setTimeout(connectVnc, 850);
        });
      } catch {
        retryTimer = setTimeout(connectVnc, 850);
      }
    }

    if (typeof ResizeObserver !== 'undefined') {
      new ResizeObserver(() => {
        if (rfb) applyFraming();
      }).observe(screenEl);
    }

    window.addEventListener('message', (ev) => {
      const d = ev && ev.data;
      if (!d || d.type !== 'cyberlab-canvas-control') return;
      if (d.mode) currentMode = d.mode;
      if (typeof d.zoom === 'number') currentZoom = d.zoom;
      applyFraming();
    });

    connectVnc();
  </script>
</head>
<body>
  <div id="status_pill">Carregando ${safeTitle}...</div>
  <div id="screen"></div>
</body>
</html>`
  }

  private resolveEmbeddedLinuxGuiCommand(slot: ArsenalSlotStatus): {
    launchCmd: string
    needsJava: boolean
    wslSourceBurpJar?: string
  } {
    // 1. Burp Suite: stage JAR onto fast Linux ext4 (/opt/cyberlab-burp/burpsuite.jar) & launch with Genuine Java 21 LTS
    //    (with automatic fallback to system /usr/bin/java if compiled with newer JDK bytecode!)
    if (slot.slotId === "burp-suite") {
      const customRaw = slot.override.customExecutablePath
        ? stripSurroundingQuotes(slot.override.customExecutablePath)
        : ""
      const winJar = process.platform === "win32" ? this.findPreferredWindowsBurpJar(slot) : null
      const wslSourceBurpJar = winJar
        ? windowsPathToWslPath(winJar)
        : customRaw.startsWith("/") && /\.jar$/i.test(customRaw)
          ? customRaw
          : undefined
      const burpFlags = [
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/javax.crypto=ALL-UNNAMED",
        "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
        "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
        "--add-opens=java.desktop/java.awt.color=ALL-UNNAMED",
        "--add-opens=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
        "-XX:MaxRAMPercentage=50",
        "-Djava.awt.headless=false",
        "-Dawt.useSystemAAFontSettings=on",
        "-Dswing.aatext=true",
        '-jar "$BURP_JAR_TARGET"',
        "--suppress-jre-check",
        "--disable-check-for-updates-dialog",
        "--disable-auto-update",
        "--i-accept-the-license-agreement",
      ].join(" ")
      return {
        needsJava: true,
        ...(wslSourceBurpJar ? { wslSourceBurpJar } : {}),
        launchCmd: `(rm -f "$HOME/.BurpSuite/UserConfigPro.json" 2>/dev/null || true; "$JAVA21_BIN" ${burpFlags} || (grep -qi "UnsupportedClassVersionError" "$GUI_LOG" && /usr/bin/java ${burpFlags}))`,
      }
    }

    // 2. OpenTRAP AppImage
    if (slot.slotId === "opentrap") {
      const p = slot.wslPath ?? slot.posixPath ?? "/opt/opentrap/OpenTRAP.AppImage"
      const escaped = p.replace(/'/g, "'\\''")
      return {
        needsJava: true,
        launchCmd: p.toLowerCase().endsWith(".appimage")
          ? `'${escaped}' --appimage-extract-and-run`
          : `'${escaped}'`,
      }
    }

    // 3. Kali full XFCE desktop stream (isolated from WSLg Wayland/D-Bus, with compositor off for snappy X11 rendering!)
    if (slot.slotId === "kali-desktop-stream") {
      return {
        needsJava: false,
        launchCmd:
          "export XDG_CURRENT_DESKTOP=XFCE DESKTOP_SESSION=xfce; if command -v startxfce4 >/dev/null 2>&1; then (sleep 2 && xfconf-query -c xfwm4 -p /general/use_compositing -s false 2>/dev/null || true) & dbus-launch --exit-with-session startxfce4; else openbox & sleep 0.6 && (xfce4-terminal || xterm); fi",
      }
    }

    // 4. OWASP ZAP, Ghidra, Wireshark, JADX-GUI, Cutter, or custom GUI slot
    if (slot.slotId === "owasp-zap") {
      return {
        needsJava: true,
        launchCmd:
          'if [ -x /usr/share/zaproxy/zap.sh ]; then /usr/share/zaproxy/zap.sh; else zaproxy; fi',
      }
    }
    if (slot.slotId === "ghidra") {
      const p =
        slot.wslPath && !slot.wslPath.startsWith("/mnt/")
          ? slot.wslPath
          : slot.posixPath ?? "ghidra"
      return { needsJava: true, launchCmd: `'${p.replace(/'/g, "'\\''")}'` }
    }
    if (slot.slotId === "jadx") {
      const p =
        slot.wslPath && !slot.wslPath.startsWith("/mnt/")
          ? slot.wslPath
          : slot.posixPath ?? "jadx-gui"
      return { needsJava: true, launchCmd: `'${p.replace(/'/g, "'\\''")}'` }
    }
    if (slot.slotId === "wireshark") {
      return { needsJava: false, launchCmd: "wireshark" }
    }
    if (slot.slotId === "rizin-cutter") {
      return { needsJava: false, launchCmd: "cutter" }
    }
    if (slot.slotId === "veracrypt") {
      return { needsJava: false, launchCmd: "veracrypt" }
    }

    const fallback = slot.wslPath ?? slot.posixPath
    if (!fallback) {
      throw new Error(
        `Para abrir "${slot.name}" dentro do palco central, instale a versão Linux/WSL2 ou ative o Kali WSL2.`,
      )
    }
    return { needsJava: false, launchCmd: `'${fallback.replace(/'/g, "'\\''")}'` }
  }

  private runAsyncWslRootScript(script: string, timeoutMs = 180000): Promise<string> {
    return new Promise((resolve) => {
      const proc = spawn(
        "wsl.exe",
        ["-d", this.config.preferredWslDistro, "-u", "root", "--", "bash", "-s"],
        {
          cwd: this.workspaceRoot,
          stdio: ["pipe", "pipe", "ignore"],
          windowsHide: true,
        },
      )
      let out = ""
      const timer = setTimeout(() => {
        this.terminateProcessTree(proc)
        resolve(out)
      }, timeoutMs)
      proc.stdout?.on("data", (chunk: Buffer) => {
        out += chunk.toString("utf8")
      })
      proc.once("close", () => {
        clearTimeout(timer)
        resolve(out)
      })
      proc.once("error", () => {
        clearTimeout(timer)
        resolve(out)
      })
      proc.stdin?.write(`${script}\n`)
      proc.stdin?.end()
    })
  }

  private async startEmbeddedGuiCanvas(slot: ArsenalSlotStatus): Promise<{
    embedUrl: string
    message: string
  }> {
    const useWsl = process.platform === "win32"
    if (useWsl && (!this.wslAvailable || !this.config.preferredWslDistro)) {
      throw new Error(
        `Para abrir a interface gráfica de "${slot.name}" dentro do centro do CyberLab OS no Windows, o WSL2 (kali-linux) precisa estar instalado. Caso prefira, clique em "Janela Externa".`,
      )
    }

    const { launchCmd, needsJava, wslSourceBurpJar } = this.resolveEmbeddedLinuxGuiCommand(slot)
    const dispNum = this.allocateX11Display()
    const vncPort = 5900 + dispNum
    const wsPort = 6000 + dispNum
    const escapedWslSrcJar = wslSourceBurpJar ? wslSourceBurpJar.replace(/'/g, "'\\''") : ""
    const canvasHtmlB64 = Buffer.from(this.buildCyberLabCanvasHtml(slot.shortLabel), "utf8").toString("base64")

    // 1. Non-blocking async check in Kali WSL2 (never freezes Bun's HTTP event loop!)
    const bootstrapCheckAndInstall = [
      "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH",
      "export DEBIAN_FRONTEND=noninteractive",
      "MISSING=0",
      "command -v Xtigervnc >/dev/null 2>&1 || MISSING=1",
      "command -v openbox >/dev/null 2>&1 || MISSING=1",
      "command -v websockify >/dev/null 2>&1 || MISSING=1",
      "command -v xmessage >/dev/null 2>&1 || MISSING=1",
      "[ -d /usr/share/novnc ] || MISSING=1",
      "[ -f /usr/lib/x86_64-linux-gnu/libXtst.so.6 ] || MISSING=1",
      'if [ "$MISSING" = "1" ]; then',
      "  apt-get update -qq || true",
      "  apt-get install -y -qq curl jq unzip tar file tigervnc-standalone-server openbox novnc websockify dbus-x11 x11-xserver-utils x11-utils fonts-dejavu-core libxtst6 libxi6 libxrender1 libxext6 libxfixes3 libxrandr2 libxcomposite1 libxdamage1 libxkbcommon0 libgbm1 libdrm2 libnss3 libnspr4 libfreetype6 fontconfig || true",
      "fi",
      ...(slot.slotId === "owasp-zap"
        ? [
            "if [ ! -x /usr/share/zaproxy/zap.sh ] && ! command -v zaproxy >/dev/null 2>&1; then apt-get update -qq || true; apt-get install -y -qq zaproxy || true; fi",
          ]
        : []),
      ...(slot.slotId === "wireshark"
        ? [
            'if ! command -v wireshark >/dev/null 2>&1; then echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections 2>/dev/null || true; apt-get update -qq || true; apt-get install -y -qq wireshark tshark || true; fi',
          ]
        : []),
      ...(slot.slotId === "ghidra"
        ? [
            "if ! command -v ghidra >/dev/null 2>&1 && [ ! -x /opt/ghidra/ghidraRun ]; then apt-get update -qq || true; apt-get install -y -qq ghidra curl jq unzip || true; fi",
            'if [ ! -s /opt/cyberlab-ghidra-mcp/GhidraMCP-release.zip ]; then mkdir -p /opt/cyberlab-ghidra-mcp; GMCP_URL=$(curl -fsSL --max-time 20 https://api.github.com/repos/LaurieWired/GhidraMCP/releases/latest 2>/dev/null | jq -r ".assets[0].browser_download_url" 2>/dev/null); if [ -n "$GMCP_URL" ] && [ "$GMCP_URL" != "null" ]; then curl -fsSL --max-time 30 "$GMCP_URL" -o /opt/cyberlab-ghidra-mcp/GhidraMCP-release.zip 2>/dev/null && unzip -oq /opt/cyberlab-ghidra-mcp/GhidraMCP-release.zip -d /opt/cyberlab-ghidra-mcp 2>/dev/null || rm -f /opt/cyberlab-ghidra-mcp/GhidraMCP-release.zip; fi; fi',
            'EXT_ZIP=$(find /opt/cyberlab-ghidra-mcp -maxdepth 2 -iname "*GhidraMCP*.zip" ! -name "GhidraMCP-release.zip" 2>/dev/null | head -n 1); if [ -n "$EXT_ZIP" ]; then for GEXT in /usr/share/ghidra/Ghidra/Extensions /opt/ghidra/Ghidra/Extensions; do [ -d "$GEXT" ] && [ ! -d "$GEXT/GhidraMCP" ] && unzip -oq "$EXT_ZIP" -d "$GEXT/" 2>/dev/null || true; done; fi',
          ]
        : []),
      ...(slot.slotId === "jadx"
        ? [
            "if ! command -v jadx-gui >/dev/null 2>&1; then apt-get update -qq || true; apt-get install -y -qq jadx || true; fi",
            'if command -v jadx >/dev/null 2>&1 && ! ls "$HOME"/.local/share/jadx/plugins/*jadx-ai-mcp* >/dev/null 2>&1; then timeout 30 jadx plugins --install "github:zinja-coder:jadx-ai-mcp" >/dev/null 2>&1 || true; fi',
          ]
        : []),
      ...(slot.slotId === "burp-suite"
        ? [
            "mkdir -p /opt/cyberlab-burp",
            "[ -L /opt/cyberlab-burp/burpsuite.jar ] && [ ! -e /opt/cyberlab-burp/burpsuite.jar ] && rm -f /opt/cyberlab-burp/burpsuite.jar",
            ...(escapedWslSrcJar
              ? [
                  `if [ -f '${escapedWslSrcJar}' ]; then`,
                  `  SRC_SZ=$(stat -c%s '${escapedWslSrcJar}' 2>/dev/null || echo 0)`,
                  `  DST_SZ=$(stat -c%s /opt/cyberlab-burp/burpsuite.jar 2>/dev/null || echo -1)`,
                  `  if [ -L /opt/cyberlab-burp/burpsuite.jar ] || [ "$SRC_SZ" != "$DST_SZ" ]; then`,
                  `    rm -f /opt/cyberlab-burp/burpsuite.jar && cp -f '${escapedWslSrcJar}' /opt/cyberlab-burp/burpsuite.jar && chmod 644 /opt/cyberlab-burp/burpsuite.jar`,
                  `  fi`,
                  `fi`,
                ]
              : []),
            "if [ ! -s /opt/cyberlab-burp/burpsuite.jar ] && [ -s /usr/share/burpsuite/burpsuite.jar ]; then ln -sf /usr/share/burpsuite/burpsuite.jar /opt/cyberlab-burp/burpsuite.jar; fi",
            "if [ ! -s /opt/cyberlab-burp/burp-mcp-all.jar ]; then curl -fsSL --max-time 25 https://github.com/PortSwigger/mcp-server/releases/latest/download/burp-mcp-all.jar -o /opt/cyberlab-burp/burp-mcp-all.jar 2>/dev/null && chmod 644 /opt/cyberlab-burp/burp-mcp-all.jar || rm -f /opt/cyberlab-burp/burp-mcp-all.jar; fi",
            "if [ -s /opt/cyberlab-burp/burp-mcp-all.jar ] && command -v jq >/dev/null 2>&1; then mkdir -p \"$HOME/.BurpSuite\"; UCFG=\"$HOME/.BurpSuite/UserConfigCommunity.json\"; if [ ! -s \"$UCFG\" ]; then printf '{\"user_options\":{\"extender\":{\"extensions\":[{\"errors\":\"ui\",\"extension_file\":\"/opt/cyberlab-burp/burp-mcp-all.jar\",\"extension_type\":\"java\",\"loaded\":true,\"name\":\"Burp MCP Server\",\"output\":\"ui\"}]}}}\\n' > \"$UCFG\"; elif ! grep -q 'burp-mcp-all.jar' \"$UCFG\" 2>/dev/null; then jq '.user_options.extender.extensions = ((.user_options.extender.extensions // []) + [{\"errors\":\"ui\",\"extension_file\":\"/opt/cyberlab-burp/burp-mcp-all.jar\",\"extension_type\":\"java\",\"loaded\":true,\"name\":\"Burp MCP Server\",\"output\":\"ui\"}])' \"$UCFG\" > \"$UCFG.tmp\" 2>/dev/null && mv -f \"$UCFG.tmp\" \"$UCFG\" || rm -f \"$UCFG.tmp\"; fi; fi",
          ]
        : []),
      ...(needsJava
        ? [
            'if [ ! -x /opt/cyberlab-jre21/bin/java ] && [ ! -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java ]; then',
            "  apt-get install -y -qq curl jq tar ca-certificates || true",
            "  JRE_URL=$(curl -fsSL https://api.github.com/repos/adoptium/temurin21-binaries/releases/latest | jq -r '.assets[] | select(.name | test(\"OpenJDK21U-jre_x64_linux_hotspot_.*\\\\.tar\\\\.gz$\")) | .browser_download_url' | head -n 1)",
            '  if [ -n "$JRE_URL" ]; then',
            '    mkdir -p /opt/cyberlab-jre21 && curl -fsSL "$JRE_URL" -o /tmp/jre21.tar.gz && tar -xzf /tmp/jre21.tar.gz -C /opt/cyberlab-jre21 --strip-components=1 && rm -f /tmp/jre21.tar.gz',
            "  fi",
            "fi",
          ]
        : []),
      "hostname -I 2>/dev/null | awk '{print $1}'",
    ].join("\n")

    let wslIp = "127.0.0.1"
    if (useWsl) {
      const bootOut = await this.runAsyncWslRootScript(bootstrapCheckAndInstall, 180000)
      const ipLine = bootOut
        .replace(/\0/g, "")
        .trim()
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => /^\d+\.\d+\.\d+\.\d+$/.test(s))
        .pop()
      if (ipLine) wslIp = ipLine
    }

    // 2. Start dedicated spacious 1366x860 Xtigervnc + Openbox
    //    CRITICAL WSL2 FIX: unset SESSION_MANAGER, DBUS_SESSION_BUS_ADDRESS, and WAYLAND_DISPLAY so WSLg
    //    never hijacks XFCE4 / GTK3 / Qt6 / Burp Chromium windows away from Xtigervnc :dispNum!
    const sessionScript = [
      'cd "$HOME" 2>/dev/null || cd /tmp',
      "unset SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS WAYLAND_DISPLAY",
      "export XDG_SESSION_TYPE=x11 GDK_BACKEND=x11 QT_QPA_PLATFORM=xcb NO_AT_BRIDGE=1",
      'CLEAN_PATH=""',
      'IFS=:; for seg in $PATH; do case "$seg" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$seg" ;; esac; done; unset IFS',
      'export PATH="$CLEAN_PATH"',
      'if [ -x /opt/cyberlab-jre21/bin/java ]; then export JAVA_HOME=/opt/cyberlab-jre21; export JAVA21_BIN=/opt/cyberlab-jre21/bin/java; elif [ -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java ]; then export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64; export JAVA21_BIN=/usr/lib/jvm/java-21-openjdk-amd64/bin/java; else export JAVA21_BIN=java; fi',
      'export BURP_JAR_TARGET=/opt/cyberlab-burp/burpsuite.jar; [ ! -s "$BURP_JAR_TARGET" ] && [ -s /usr/share/burpsuite/burpsuite.jar ] && export BURP_JAR_TARGET=/usr/share/burpsuite/burpsuite.jar',
      'export PATH="${JAVA_HOME:+$JAVA_HOME/bin:}$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:/opt/opentrap:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"',
      `export GUI_LOG=/tmp/cyberlab-gui-${dispNum}.log`,
      `pkill -f "Xtigervnc :${dispNum}" 2>/dev/null || true`,
      `pkill -f "websockify.*:${wsPort}" 2>/dev/null || true`,
      `rm -f /tmp/.X${dispNum}-lock /tmp/.X11-unix/X${dispNum} 2>/dev/null || true`,
      `mkdir -p /tmp/cyberlab-web-${dispNum}`,
      `ln -sf /usr/share/novnc/* /tmp/cyberlab-web-${dispNum}/ 2>/dev/null || true`,
      `echo '${canvasHtmlB64}' | base64 -d > /tmp/cyberlab-web-${dispNum}/cyberlab_canvas.html`,
      `cat > /tmp/cyberlab-ob-${dispNum}.xml << 'EOF_OB'`,
      `<?xml version="1.0" encoding="UTF-8"?>`,
      `<openbox_config xmlns="http://openbox.org/3.4/rc">`,
      `  <focus>`,
      `    <focusNew>yes</focusNew>`,
      `    <followMouse>yes</followMouse>`,
      `    <raiseOnFocus>yes</raiseOnFocus>`,
      `  </focus>`,
      `  <desktops><number>1</number></desktops>`,
      `  <applications>`,
      `    <application type="normal">`,
      `      <decor>yes</decor>`,
      `      <focus>yes</focus>`,
      `      <maximized>yes</maximized>`,
      `    </application>`,
      `    <application type="dialog">`,
      `      <decor>yes</decor>`,
      `      <focus>yes</focus>`,
      `      <position force="no"><x>center</x><y>center</y></position>`,
      `    </application>`,
      `  </applications>`,
      `</openbox_config>`,
      `EOF_OB`,
      `Xtigervnc :${dispNum} -rfbport ${vncPort} -SecurityTypes None -AlwaysShared -AcceptSetDesktopSize=1 -geometry 1200x780 -depth 24 -dpi 110 >/dev/null 2>&1 &`,
      "VNC_PID=$!",
      "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do [ -S /tmp/.X11-unix/X" + dispNum + " ] && break; sleep 0.2; done",
      `export DISPLAY=:${dispNum}`,
      "export GDK_SCALE=1 GDK_DPI_SCALE=1.12 QT_FONT_DPI=110 _JAVA_OPTIONS='-Dsun.java2d.uiScale=1.12 -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true'",
      "printf 'Xft.dpi: 110\\nXft.antialias: 1\\nXft.hinting: 1\\nXft.rgba: rgb\\n' | xrdb -merge 2>/dev/null || true",
      "xsetroot -solid '#09090b' 2>/dev/null || true",
      ...(slot.slotId === "kali-desktop-stream"
        ? []
        : [`openbox --config-file /tmp/cyberlab-ob-${dispNum}.xml >/dev/null 2>&1 &`, "sleep 0.35"]),
      `websockify --web=/tmp/cyberlab-web-${dispNum} 0.0.0.0:${wsPort} 127.0.0.1:${vncPort} >/dev/null 2>&1 &`,
      "WS_PID=$!",
      `(xmessage -center -timeout 8 -buttons "" "Iniciando ${slot.shortLabel}... Aguarde alguns segundos." >/dev/null 2>&1 || true) &`,
      `(${launchCmd} >"$GUI_LOG" 2>&1 || (sleep 1.2 && xmessage -center -buttons "Fechar:0" -title "Diagnóstico ${slot.shortLabel}" -file "$GUI_LOG" >/dev/null 2>&1)) &`,
      "wait $WS_PID $VNC_PID",
    ].join("\n")

    const child = useWsl
      ? spawn("wsl.exe", ["-d", this.config.preferredWslDistro, "--", "bash", "-s"], {
          cwd: this.workspaceRoot,
          stdio: ["pipe", "ignore", "ignore"],
          windowsHide: true,
        })
      : spawn("bash", ["-s"], {
          cwd: this.workspaceRoot,
          stdio: ["pipe", "ignore", "ignore"],
        })

    child.stdin?.write(`${sessionScript}\n`)
    child.stdin?.end()

    const candidateHosts = Array.from(new Set([wslIp, "127.0.0.1", "localhost"]))
    const liveHost = await this.waitForTcpPort(candidateHosts, wsPort, 7500)
    if (!liveHost) {
      this.terminateProcessTree(child)
      throw new Error(
        `O servidor gráfico central (:${wsPort}) não respondeu a tempo. Verifique sua instância Kali WSL2.`,
      )
    }

    const tcpBridges: net.Server[] = []
    const orderedHosts = Array.from(new Set([liveHost, ...candidateHosts]))
    const mainBridge = await this.createTcpBridgeServer(orderedHosts, wsPort, 0)
    if (!mainBridge) {
      this.terminateProcessTree(child)
      throw new Error("Falha ao criar túnel TCP loopback p/ o Canvas Gráfico Central.")
    }
    tcpBridges.push(mainBridge.server)

    // If this GUI tool exposes an intercepting proxy port (e.g. Burp/OpenTRAP :8080) inside WSL2 and host :8080 is free, bridge it too!
    if (useWsl && slot.companionProxyPort && wslIp !== "127.0.0.1") {
      const proxyBridge = await this.createTcpBridgeServer(
        orderedHosts,
        slot.companionProxyPort,
        slot.companionProxyPort,
      )
      if (proxyBridge) {
        tcpBridges.push(proxyBridge.server)
      }
    }

    const embedUrl = `http://127.0.0.1:${mainBridge.localPort}/cyberlab_canvas.html?mode=fit`
    this.daemons.set(slot.slotId, {
      child,
      staticServer: null,
      tcpBridges,
      wslDisplayNum: dispNum,
      embedUrl,
    })

    return {
      embedUrl,
      message: `${slot.name} aberto no Palco Central (use "📐 Ajustar" ou "↕ Rolagem + Zoom" na barra superior conforme preferir).`,
    }
  }

  async launchSlot(params: {
    slotId: string
    action: "run_cli" | "launch_desktop" | "start_web" | "stop_web" | "install_tool"
    target?: string
    rawArgs?: string
    runtimeOverride?: "windows" | "wsl" | "linux_mac"
  }): Promise<{
    ok: boolean
    message: string
    embedUrl?: string
    run?: ArsenalLiveRun
    overview: ArsenalOverview
  }> {
    const currentOverview = this.getOverview(false)

    // 0. One-Click Batch Install of ALL Missing Tools (`slotId === "__all_missing__"`)
    if (params.slotId === "__all_missing__" && params.action === "install_tool") {
      const missingSlots = currentOverview.slots.filter((s) => !s.installed && !s.isCustom)
      if (missingSlots.length === 0) {
        return {
          ok: true,
          message: "Todos os 29 slots oficiais já estão instalados e prontos!",
          overview: currentOverview,
        }
      }

      // Order: fast prebuilt releases first -> apt packages -> pip -> cargo last
      const priorityRank = (id: string): number => {
        if (["katana", "interactsh", "dalfox", "caido", "opentrap", "capa", "hayabusa-yarax"].includes(id)) return 1
        if (["sqlmap", "jadx", "ghidra", "burp-suite"].includes(id)) return 2
        if (["semgrep", "frida-apktool"].includes(id)) return 3
        if (id === "keyhunter") return 4
        return 2
      }
      const ordered = [...missingSlots].sort((a, b) => priorityRank(a.slotId) - priorityRank(b.slotId))

      if (process.platform === "win32" && !this.wslAvailable) {
        const psSteps = ordered
          .filter((s) => s.installPowerShell.trim() && !s.installPowerShell.trim().startsWith("#"))
          .map(
            (s, idx) =>
              `Write-Host "=== [${idx + 1}/${ordered.length}] Instalando ${s.shortLabel} ==="; try { ${s.installPowerShell}; Write-Host "[CONCLUIDO_SLOT] ${s.slotId}" } catch { Write-Host "[AVISO] Falha em ${s.shortLabel}: $_" }`,
          )
          .join("\n")
        const run = this.startStreamingProcess({
          slotId: "__all_missing__",
          slotName: `Instalador Completo (${ordered.length} ferramentas)`,
          runtime: "installer",
          commandPreview: `Instalação automática de ${ordered.length} ferramentas faltantes via PowerShell`,
          executable: "powershell.exe",
          args: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psSteps],
          cwd: this.workspaceRoot,
          onStepDone: () => this.probeEnvironment(),
          onComplete: () => this.probeEnvironment(),
        })
        return {
          ok: true,
          message: `Instalando ${ordered.length} ferramentas faltantes em lote...`,
          run,
          overview: this.getOverview(false),
        }
      }

      const bashSteps = [
        "set +e",
        "export DEBIAN_FRONTEND=noninteractive",
        'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.cargo/bin:/root/go/bin:/root/.strix/bin:$PATH"',
        "FAILED_COUNT=0",
        'FAILED_LIST=""',
        'echo "=== Preparando base (curl, jq, unzip, tar, ca-certificates) ==="',
        "apt-get update -qq || true",
        "apt-get install -y -qq curl jq unzip tar ca-certificates || true",
        ...ordered.map((s, idx) => {
          const cleanCmd = s.installKaliWsl.replace(/\bsudo\s+/g, "")
          const safeLabel = s.shortLabel.replace(/["$`\\]/g, "")
          return [
            `echo ""`,
            `echo "============================================================"`,
            `echo "  [${idx + 1}/${ordered.length}] Instalando ${safeLabel}..."`,
            `echo "============================================================"`,
            `if (${cleanCmd}); then`,
            `  echo "[CONCLUIDO_SLOT] ${s.slotId}"`,
            `else`,
            `  FAILED_COUNT=$((FAILED_COUNT + 1))`,
            `  FAILED_LIST="\${FAILED_LIST} [${safeLabel}]"`,
            `  echo "[ERRO_SLOT] Falha ao instalar ${safeLabel} (verifique o log acima)"`,
            `fi`,
          ].join("\n")
        }),
        'echo ""',
        'if [ "$FAILED_COUNT" -gt 0 ]; then',
        '  echo "=== FINALIZADO COM $FAILED_COUNT FALHA(S):$FAILED_LIST ==="',
        "  exit 1",
        "fi",
        'echo "=== TODAS AS ETAPAS CONCLUIDAS COM 100% DE SUCESSO! ==="',
      ].join("\n")

      const run =
        process.platform === "win32"
          ? this.startStreamingProcess({
              slotId: "__all_missing__",
              slotName: `Instalador Completo (${ordered.length} ferramentas)`,
              runtime: "installer",
              commandPreview: `[WSL2 ${this.config.preferredWslDistro}] Instalando ${ordered.length} ferramentas faltantes em 1 clique`,
              executable: "wsl.exe",
              args: ["-d", this.config.preferredWslDistro, "-u", "root", "--", "bash", "-s"],
              stdinPayload: `${bashSteps}\n`,
              cwd: this.workspaceRoot,
              onStepDone: () => this.probeEnvironment(),
              onComplete: () => this.probeEnvironment(),
            })
          : this.startStreamingProcess({
              slotId: "__all_missing__",
              slotName: `Instalador Completo (${ordered.length} ferramentas)`,
              runtime: "installer",
              commandPreview: `Instalando ${ordered.length} ferramentas faltantes em 1 clique`,
              executable: "bash",
              args: ["-s"],
              stdinPayload: `${bashSteps}\n`,
              cwd: this.workspaceRoot,
              onStepDone: () => this.probeEnvironment(),
              onComplete: () => this.probeEnvironment(),
            })

      return {
        ok: true,
        message: `Instalação em lote iniciada para ${ordered.length} ferramentas! Acompanhe o progresso ao vivo no console.`,
        run,
        overview: this.getOverview(false),
      }
    }

    const slot = currentOverview.slots.find((s) => s.slotId === params.slotId)
    const def = this.getAllDefinitions().find((d) => d.slotId === params.slotId)
    if (!slot || !def) {
      throw new Error(`Slot "${params.slotId}" não encontrado`)
    }

    // 0a. 1-Click MCP Connection Toggle in opencode.json (`rawArgs === "__toggle_mcp__"`)
    if (params.rawArgs === "__toggle_mcp__") {
      const toggled = this.toggleSlotMcpInOpenCodeConfig(slot)
      return {
        ok: true,
        message: toggled.message,
        overview: this.getOverview(false),
      }
    }

    // 0b. Native Windows File Picker (`rawArgs === "__pick_executable__"`) so the operator can pick any .jar / .exe on disk in 1 click!
    if (params.rawArgs === "__pick_executable__") {
      if (process.platform !== "win32") {
        throw new Error("Informe o caminho do arquivo .jar ou executável no campo de configuração do slot.")
      }
      const psPicker = [
        "Add-Type -AssemblyName System.Windows.Forms",
        "$dlg = New-Object System.Windows.Forms.OpenFileDialog",
        `$dlg.Title = 'Selecionar arquivo para ${slot.shortLabel.replace(/'/g, "")} (.jar ou .exe)'`,
        "$dlg.Filter = 'Arquivos Suportados (*.jar;*.exe;*.bat;*.cmd)|*.jar;*.exe;*.bat;*.cmd|Todos os arquivos (*.*)|*.*'",
        "if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.WriteLine($dlg.FileName) }",
      ].join("; ")
      const pickRes = spawnSync(
        "powershell.exe",
        ["-NoProfile", "-Sta", "-ExecutionPolicy", "Bypass", "-Command", psPicker],
        {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
          timeout: 120000,
        },
      )
      const picked = stripSurroundingQuotes((pickRes.stdout ?? "").trim().split(/\r?\n/).pop() ?? "")
      if (!picked) {
        return {
          ok: true,
          message: "Seleção de arquivo cancelada.",
          overview: currentOverview,
        }
      }
      if (
        slot.slotId === "burp-suite" &&
        /burpsuite_windows.*\.exe$|installer.*\.exe$|setup.*\.exe$/i.test(path.basename(picked))
      ) {
        throw new Error(
          `O arquivo selecionado (${path.basename(picked)}) é um instalador de Setup do Windows e não o arquivo .jar executável! Clique no botão "🧹 Limpar Antigas + Baixar Burp Community Oficial" para remover as versões conflitantes e baixar o JAR oficial automaticamente.`,
        )
      }
      const updated = this.configureSettings({
        slotId: slot.slotId,
        slotOverride: { customExecutablePath: picked },
      })
      return {
        ok: true,
        message: `Arquivo vinculado com sucesso: ${picked}. Clique agora em "Abrir Aqui Dentro" ou "Janela Externa"!`,
        overview: updated,
      }
    }

    // 0c. 1-Click Clean Wipe of Old Burp Pro/Community + Fresh PortSwigger CDN Burp Community Download!
    if (params.rawArgs === "__clean_reinstall_burp__" && slot.slotId === "burp-suite") {
      delete this.config.slotOverrides["burp-suite"]
      this.saveConfig()
      const existingBurp = this.daemons.get("burp-suite")
      if (existingBurp) {
        if (existingBurp.child) this.terminateProcessTree(existingBurp.child)
        if (existingBurp.tcpBridges) for (const s of existingBurp.tcpBridges) s.close()
        if (existingBurp.staticServer) existingBurp.staticServer.close()
        this.daemons.delete("burp-suite")
      }

      if (process.platform === "win32") {
        // Non-blocking cleanup (never freezes Bun's 10s HTTP idleTimeout!)
        const localAppData = process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local")
        const appData = process.env.APPDATA ?? path.join(os.homedir(), "AppData", "Roaming")
        const progFiles = process.env.ProgramFiles ?? "C:\\Program Files"
        const userHome = os.homedir()
        const winTargets = [
          path.join(localAppData, "BurpSuitePro"),
          path.join(localAppData, "Programs", "BurpSuitePro"),
          path.join(progFiles, "BurpSuitePro"),
          path.join(localAppData, "BurpSuiteCommunity"),
          path.join(localAppData, "Programs", "BurpSuiteCommunity"),
          path.join(progFiles, "BurpSuiteCommunity"),
          path.join(localAppData, "BurpSuite"),
          path.join(appData, "BurpSuite"),
          path.join(userHome, ".BurpSuite"),
          path.join(userHome, "Downloads", "burpsuite_windows-x64_v2026_9_2.exe"),
        ]
        for (const t of winTargets) {
          try {
            if (existsSync(t)) rmSync(t, { recursive: true, force: true })
          } catch {
            // Ignore locked files; background PowerShell cleans processes below
          }
        }
        try {
          const bgClean = spawn(
            "powershell.exe",
            [
              "-NoProfile",
              "-ExecutionPolicy",
              "Bypass",
              "-Command",
              'Get-Process | Where-Object { $_.ProcessName -like "BurpSuite*" } | Stop-Process -Force -ErrorAction SilentlyContinue; winget uninstall --id PortSwigger.BurpSuite.Professional --silent 2>$null | Out-Null; winget uninstall --id PortSwigger.BurpSuite.Community --silent 2>$null | Out-Null',
            ],
            { detached: true, stdio: "ignore", windowsHide: true },
          )
          bgClean.unref()
        } catch {
          // Ignore
        }
      }

      return this.launchSlot({
        slotId: "burp-suite",
        action: "install_tool",
        runtimeOverride: process.platform === "win32" && this.wslAvailable ? "wsl" : undefined,
      })
    }

    // 1. Stop Web Daemon / Embedded GUI Canvas
    if (params.action === "stop_web") {
      const existing = this.daemons.get(slot.slotId)
      if (existing) {
        if (existing.child && existing.child.pid) {
          this.terminateProcessTree(existing.child)
        }
        if (existing.wslDisplayNum !== undefined && process.platform === "win32" && this.wslAvailable) {
          const disp = existing.wslDisplayNum
          const wsPort = 6000 + disp
          try {
            spawnSync(
              "wsl.exe",
              ["-d", this.config.preferredWslDistro, "--", "bash", "-s"],
              {
                input: Buffer.from(
                  `pkill -f "Xtigervnc :${disp}\\b" 2>/dev/null || true; pkill -f "websockify.*:${wsPort}\\b" 2>/dev/null || true\n`,
                  "utf8",
                ),
                stdio: ["pipe", "ignore", "ignore"],
                windowsHide: true,
                timeout: 3000,
              },
            )
          } catch {
            // Ignore cleanup timeout
          }
        }
        if (existing.tcpBridges) {
          for (const srv of existing.tcpBridges) {
            await new Promise<void>((resolve) => srv.close(() => resolve()))
          }
        }
        if (existing.staticServer) {
          await new Promise<void>((resolve) => existing.staticServer!.close(() => resolve()))
        }
        this.daemons.delete(slot.slotId)
      }
      return {
        ok: true,
        message: `Sessão central de ${slot.name} encerrada.`,
        overview: this.getOverview(false),
      }
    }

    // 2. Start / Embed Web Tool OR Embedded X11/noVNC Desktop GUI Canvas right inside Center Stage!
    if (params.action === "start_web") {
      const existing = this.daemons.get(slot.slotId)
      if (existing) {
        return {
          ok: true,
          message: `${slot.name} já está ativo no Palco Central`,
          embedUrl: existing.embedUrl,
          overview: this.getOverview(false),
        }
      }

      // 2a. Local static HTML app (e.g. GCHQ CyberChef Oficial)
      const probe = this.cachedSlotProbes.get(slot.slotId)
      if (probe?.localHtmlEntry && existsSync(probe.localHtmlEntry)) {
        const hosted = await this.startStaticHtmlServer(probe.localHtmlEntry)
        this.daemons.set(slot.slotId, {
          child: null,
          staticServer: hosted.server,
          embedUrl: hosted.url,
        })
        return {
          ok: true,
          message: `${slot.name} carregado localmente no centro`,
          embedUrl: hosted.url,
          overview: this.getOverview(false),
        }
      }

      // 2b. Desktop GUI tools (Burp Suite, OpenTRAP, OWASP ZAP, Ghidra, Wireshark, JADX-GUI, Cutter) + Kali Desktop Stream -> Embedded X11/noVNC Canvas!
      if (
        (slot.kind === "desktop_gui" || slot.slotId === "kali-desktop-stream") &&
        !slot.override.customEmbedUrl
      ) {
        // If Kali XFCE Desktop (startxfce4) or Burp Suite JAR is not yet downloaded, trigger live streaming installer so HTTP never times out!
        if (slot.slotId === "kali-desktop-stream" && !slot.wslPath && !slot.posixPath) {
          const inst = await this.launchSlot({
            slotId: slot.slotId,
            action: "install_tool",
            runtimeOverride: process.platform === "win32" ? "wsl" : undefined,
          })
          return {
            ok: true,
            message:
              "Baixando o ambiente gráfico XFCE completo do Kali WSL2 (1ª vez — acompanhe o progresso ao vivo no Console abaixo!). Assim que concluir, clique em '▶ Abrir Aqui no Centro'.",
            run: inst.run,
            overview: inst.overview,
          }
        }
        if (
          (slot.slotId === "burp-suite" || slot.slotId === "veracrypt") &&
          !slot.wslPath &&
          !slot.posixPath &&
          !(slot.windowsPath && slot.windowsPath.toLowerCase().endsWith(".jar"))
        ) {
          const inst = await this.launchSlot({
            slotId: slot.slotId,
            action: "install_tool",
            runtimeOverride: process.platform === "win32" ? "wsl" : undefined,
          })
          return {
            ok: true,
            message: `${slot.shortLabel} ainda não estava instalado no Kali WSL2 — baixando agora automaticamente (acompanhe o progresso ao vivo no Console abaixo!). Assim que concluir, clique novamente em '🖥 Abrir Aqui Dentro do CyberLab'.`,
            run: inst.run,
            overview: inst.overview,
          }
        }
        if (
          slot.slotId === "burp-suite" &&
          !slot.wslPath &&
          !slot.posixPath &&
          !this.findPreferredWindowsBurpJar(slot)
        ) {
          const inst = await this.launchSlot({
            slotId: slot.slotId,
            action: "install_tool",
            runtimeOverride: process.platform === "win32" && this.wslAvailable ? "wsl" : undefined,
          })
          return {
            ok: true,
            message:
              "Baixando o Burp Suite Community Oficial mais recente direto da PortSwigger CDN (acompanhe no Console abaixo!). Ao terminar, clique em '🖥 Abrir Burp Suite Aqui Dentro'.",
            run: inst.run,
            overview: inst.overview,
          }
        }

        const guiCanvas = await this.startEmbeddedGuiCanvas(slot)
        return {
          ok: true,
          message: guiCanvas.message,
          embedUrl: guiCanvas.embedUrl,
          overview: this.getOverview(false),
        }
      }

      // 2c. Managed local Web daemon (e.g. mitmweb :8081, Caido :7000 — supports both Windows native AND WSL2 Kali,
      //     strips X-Frame-Options/CSP via loopback HTTP+WS proxy, and enables Caido --allow-guests!)
      let liveSlot = slot
      const targetEmbedUrl = liveSlot.override.customEmbedUrl ?? def.defaultEmbedUrl

      // If a managed Web daemon (mitmweb / caido) is not installed yet and Kali WSL2 is available, auto-install non-blockingly!
      if (
        def.managedDaemonArgs &&
        !liveSlot.resolvedPath &&
        process.platform === "win32" &&
        this.wslAvailable &&
        liveSlot.installKaliWsl.trim() &&
        !liveSlot.installKaliWsl.trim().startsWith("#")
      ) {
        const cleanInstall = liveSlot.installKaliWsl.replace(/\bsudo\s+/g, "")
        await this.runAsyncWslRootScript(`export DEBIAN_FRONTEND=noninteractive\n${cleanInstall}`, 180000)
        const refreshed = this.getOverview(true)
        liveSlot = refreshed.slots.find((s) => s.slotId === slot.slotId) ?? liveSlot
      }

      if (def.managedDaemonArgs && liveSlot.resolvedPath && liveSlot.activeRuntime !== "web" && liveSlot.activeRuntime !== "none") {
        // For Caido Web UI, prefer caido-cli (WSL2 or Windows caido-cli.exe) over the Electron desktop binary Caido.exe
        let daemonRuntime: "windows" | "wsl" | "linux_mac" = liveSlot.activeRuntime
        let daemonBin = liveSlot.resolvedPath
        if (
          liveSlot.slotId === "caido" &&
          daemonRuntime === "windows" &&
          /Caido\.exe$/i.test(daemonBin) &&
          !/caido-cli/i.test(daemonBin) &&
          liveSlot.wslPath
        ) {
          daemonRuntime = "wsl"
          daemonBin = liveSlot.wslPath
        }

        const port = def.managedDaemonPort ?? 8081
        let wslDaemonIp = "127.0.0.1"
        if (daemonRuntime === "wsl" && process.platform === "win32") {
          try {
            const prep = spawnSync(
              "wsl.exe",
              ["-d", this.config.preferredWslDistro, "--", "bash", "-s"],
              {
                input: Buffer.from(
                  `pkill -f "caido.*${port}" 2>/dev/null || true; pkill -f "mitmweb.*${port}" 2>/dev/null || true; hostname -I 2>/dev/null | awk '{print $1}'\n`,
                  "utf8",
                ),
                encoding: "utf8",
                stdio: ["pipe", "pipe", "ignore"],
                windowsHide: true,
                timeout: 4000,
              },
            )
            const firstIp = (prep.stdout ?? "")
              .replace(/\0/g, "")
              .trim()
              .split(/\r?\n/)
              .pop()
              ?.trim()
            if (firstIp && /^\d+\.\d+\.\d+\.\d+$/.test(firstIp)) wslDaemonIp = firstIp
          } catch {
            // Ignore
          }
        }

        let tokenSuffix = liveSlot.slotId === "mitmweb" ? "/?token=cyberlab" : "/"
        const child = this.spawnForRuntimeWithPipes(
          daemonRuntime,
          daemonBin,
          def.managedDaemonArgs,
          this.workspaceRoot,
          (chunk) => {
            const match = chunk.match(/https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0):\d+(\/\?token=[a-zA-Z0-9._-]+)/i)
            if (match?.[1]) tokenSuffix = match[1]
          },
        )

        const candidateHosts = Array.from(new Set([wslDaemonIp, "127.0.0.1", "localhost"]))
        await this.waitForTcpPort(candidateHosts, port, 7500)

        const tcpBridges: net.Server[] = []
        if (
          daemonRuntime === "wsl" &&
          process.platform === "win32" &&
          liveSlot.companionProxyPort &&
          liveSlot.companionProxyPort !== port &&
          wslDaemonIp !== "127.0.0.1"
        ) {
          const proxyBridge = await this.createTcpBridgeServer(
            candidateHosts,
            liveSlot.companionProxyPort,
            liveSlot.companionProxyPort,
          )
          if (proxyBridge) tcpBridges.push(proxyBridge.server)
        }

        const embedProxy = await this.createEmbedHttpProxyServer(candidateHosts, port)
        const url = embedProxy
          ? `http://127.0.0.1:${embedProxy.localPort}${tokenSuffix}`
          : `${targetEmbedUrl ?? `http://127.0.0.1:${port}`}`

        this.daemons.set(liveSlot.slotId, {
          child,
          staticServer: embedProxy?.server ?? null,
          tcpBridges,
          embedUrl: url,
        })
        return {
          ok: true,
          message:
            liveSlot.slotId === "caido"
              ? `${liveSlot.name} iniciado com Modo Convidado ativo ("Continue as guest" liberado sem conta)!`
              : `${liveSlot.name} iniciado e autenticado no Palco Central!`,
          embedUrl: url,
          overview: this.getOverview(false),
        }
      }

      if (targetEmbedUrl && !def.managedDaemonArgs) {
        const parsedTarget = (() => {
          try {
            return new URL(targetEmbedUrl)
          } catch {
            return null
          }
        })()
        const isLocalComposeStack =
          liveSlot.slotId === "pentagi" || liveSlot.slotId === "pentest-copilot"
        const remotePort =
          def.managedDaemonPort ??
          (parsedTarget?.port ? Number.parseInt(parsedTarget.port, 10) : parsedTarget?.protocol === "https:" ? 443 : 80)
        const upstreamTls = parsedTarget?.protocol === "https:"

        if (isLocalComposeStack) {
          // 1. If stack not cloned/installed yet, trigger live streaming installer first
          if (!liveSlot.installed) {
            const inst = await this.launchSlot({
              slotId: liveSlot.slotId,
              action: "install_tool",
              runtimeOverride: process.platform === "win32" && this.wslAvailable ? "wsl" : undefined,
            })
            return {
              ok: true,
              message: `Instalando o stack Docker de ${liveSlot.shortLabel} no Kali WSL2 (acompanhe no Console abaixo!). Assim que concluir, clique novamente em '▶ Abrir Aqui no Centro'.`,
              run: inst.run,
              overview: inst.overview,
            }
          }

          let wslHostIp = "127.0.0.1"
          if (process.platform === "win32" && this.wslAvailable) {
            const ipOut = await this.runAsyncWslRootScript("hostname -I 2>/dev/null | awk '{print $1}'", 5000)
            const candidateIp = ipOut.replace(/\0/g, "").trim().split(/\r?\n/).pop()?.trim()
            if (candidateIp && /^\d+\.\d+\.\d+\.\d+$/.test(candidateIp)) {
              wslHostIp = candidateIp
            }
          }
          const candidateHosts = Array.from(new Set([wslHostIp, "127.0.0.1", "localhost"]))
          const alreadyUp = await this.waitForTcpPort(candidateHosts, remotePort, 900)

          if (!alreadyUp) {
            const stackDir = liveSlot.slotId === "pentagi" ? "/opt/pentagi" : "/opt/pentest-copilot"
            const composeBootScript = [
              "export DEBIAN_FRONTEND=noninteractive",
              "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH",
              'echo "=== Verificando Docker no Kali WSL2 ==="',
              "if ! command -v docker >/dev/null 2>&1; then apt-get update -qq && (apt-get install -y docker.io docker-compose-v2 || apt-get install -y docker.io docker-compose); fi",
              "if ! docker info >/dev/null 2>&1; then",
              '  echo "Iniciando daemon dockerd dentro do Kali WSL2..."',
              "  nohup dockerd >/tmp/cyberlab-dockerd.log 2>&1 &",
              "  for i in 1 2 3 4 5 6 7 8 9 10; do docker info >/dev/null 2>&1 && break; sleep 1; done",
              "fi",
              `cd ${stackDir}`,
              liveSlot.slotId === "pentagi"
                ? 'if [ ! -f .env ] && [ -f .env.example ]; then cp .env.example .env; fi; grep -q "^PENTAGI_LISTEN_IP=" .env && sed -i "s/^PENTAGI_LISTEN_IP=.*/PENTAGI_LISTEN_IP=0.0.0.0/" .env || echo "PENTAGI_LISTEN_IP=0.0.0.0" >> .env'
                : "true",
              `echo "=== Subindo containers de ${liveSlot.shortLabel} (porta :${remotePort}) ==="`,
              "docker compose up -d",
              'echo "=== Containers iniciados! Aguardando porta Web subir... ==="',
              `for i in 1 2 3 4 5 6 7 8 9 10 11 12; do (echo >/dev/tcp/127.0.0.1/${remotePort}) >/dev/null 2>&1 && echo "Porta :${remotePort} ativa!" && break; sleep 1; done`,
            ].join("\n")

            const bootRun =
              process.platform === "win32" && this.wslAvailable
                ? this.startStreamingProcess({
                    slotId: liveSlot.slotId,
                    slotName: `Docker Compose — ${liveSlot.shortLabel}`,
                    runtime: "installer",
                    commandPreview: `[WSL2 ${this.config.preferredWslDistro}] Subindo stack Docker ${liveSlot.shortLabel} (:${remotePort})`,
                    executable: "wsl.exe",
                    args: ["-d", this.config.preferredWslDistro, "-u", "root", "--", "bash", "-s"],
                    stdinPayload: `${composeBootScript}\n`,
                    cwd: this.workspaceRoot,
                  })
                : this.startStreamingProcess({
                    slotId: liveSlot.slotId,
                    slotName: `Docker Compose — ${liveSlot.shortLabel}`,
                    runtime: "installer",
                    commandPreview: `Subindo stack Docker ${liveSlot.shortLabel} (:${remotePort})`,
                    executable: "bash",
                    args: ["-s"],
                    stdinPayload: `${composeBootScript}\n`,
                    cwd: this.workspaceRoot,
                  })

            // Wait briefly in case images were already cached and came up within 3.5s!
            const cameUpFast = await this.waitForTcpPort(candidateHosts, remotePort, 3500)
            if (!cameUpFast) {
              return {
                ok: true,
                message: `Subindo containers Docker do ${liveSlot.shortLabel} (na 1ª vez o Docker baixa as imagens oficiais — acompanhe ao vivo no Console abaixo!). Assim que concluir (succeeded), clique em '▶ Abrir Aqui no Centro'.`,
                run: bootRun,
                overview: this.getOverview(false),
              }
            }
          }

          const proxy = await this.createEmbedHttpProxyServer(candidateHosts, remotePort, {
            upstreamTls,
          })
          const proxiedUrl = proxy ? `http://127.0.0.1:${proxy.localPort}/` : targetEmbedUrl
          this.daemons.set(liveSlot.slotId, {
            child: null,
            staticServer: proxy?.server ?? null,
            embedUrl: proxiedUrl,
          })
          return {
            ok: true,
            message: `${liveSlot.shortLabel} conectado via proxy local seguro (certificado TLS autoassinado tratado automaticamente)!`,
            embedUrl: proxiedUrl,
            overview: this.getOverview(false),
          }
        }

        // Any other custom/local HTTPS or HTTP embed URL -> proxy loopback to strip X-Frame-Options & self-signed TLS errors
        if (
          parsedTarget &&
          (parsedTarget.hostname === "127.0.0.1" || parsedTarget.hostname === "localhost")
        ) {
          const proxy = await this.createEmbedHttpProxyServer(["127.0.0.1", "localhost"], remotePort, {
            upstreamTls,
          })
          if (proxy) {
            const proxiedUrl = `http://127.0.0.1:${proxy.localPort}${parsedTarget.pathname}${parsedTarget.search}`
            this.daemons.set(liveSlot.slotId, {
              child: null,
              staticServer: proxy.server,
              embedUrl: proxiedUrl,
            })
            return {
              ok: true,
              message: `Conectado a ${liveSlot.shortLabel} via ponte local sem bloqueio de iframe/TLS`,
              embedUrl: proxiedUrl,
              overview: this.getOverview(false),
            }
          }
        }

        return {
          ok: true,
          message: `Conectado ao endereço Web ${targetEmbedUrl}`,
          embedUrl: targetEmbedUrl,
          overview: this.getOverview(false),
        }
      }

      throw new Error(
        `${slot.name} ainda não foi localizado em ${this.config.toolsRootDir}. Instale com o comando de 1 clique ou informe a URL local.`,
      )
    }

    // 3. One-Click Official Tool Installation (prefers WSL2 Kali root unattended install when WSL2 is available!)
    if (params.action === "install_tool") {
      const canInstallInKali =
        Boolean(slot.installKaliWsl.trim()) &&
        !slot.installKaliWsl.trim().startsWith("#") &&
        slot.slotId !== "cyberchef"
      const useKali =
        params.runtimeOverride === "wsl" ||
        (params.runtimeOverride !== "windows" && process.platform === "win32" && this.wslAvailable && canInstallInKali)
      if (process.platform === "win32" && !useKali) {
        const cmd = slot.installPowerShell
        const run = this.startStreamingProcess({
          slotId: slot.slotId,
          slotName: `Instalador — ${slot.shortLabel}`,
          runtime: "installer",
          commandPreview: `powershell.exe -NoProfile -Command "${cmd}"`,
          executable: "powershell.exe",
          args: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
          cwd: this.workspaceRoot,
          onComplete: () => this.probeEnvironment(),
        })
        return {
          ok: true,
          message: `Instalação de ${slot.name} iniciada via Windows PowerShell.`,
          run,
          overview: this.getOverview(false),
        }
      }

      if (process.platform === "win32" && useKali) {
        const cmd = slot.installKaliWsl.replace(/\bsudo\s+/g, "")
        const run = this.startStreamingProcess({
          slotId: slot.slotId,
          slotName: `Instalador Kali WSL2 — ${slot.shortLabel}`,
          runtime: "installer",
          commandPreview: `[WSL2 ${this.config.preferredWslDistro}] ${slot.installKaliWsl}`,
          executable: "wsl.exe",
          args: ["-d", this.config.preferredWslDistro, "-u", "root", "--", "bash", "-s"],
          stdinPayload: `export DEBIAN_FRONTEND=noninteractive\nexport PATH="/root/.cargo/bin:/root/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"\n${cmd}\n`,
          cwd: this.workspaceRoot,
          onComplete: () => this.probeEnvironment(),
        })
        return {
          ok: true,
          message: `Instalação de ${slot.name} iniciada no Kali WSL2 (${this.config.preferredWslDistro}).`,
          run,
          overview: this.getOverview(false),
        }
      }

      const cmd = slot.installKaliWsl
      const run = this.startStreamingProcess({
        slotId: slot.slotId,
        slotName: `Instalador — ${slot.shortLabel}`,
        runtime: "installer",
        commandPreview: `bash -lc "${cmd}"`,
        executable: "bash",
        args: ["-lc", cmd],
        cwd: this.workspaceRoot,
        onComplete: () => this.probeEnvironment(),
      })
      return {
        ok: true,
        message: `Instalação de ${slot.name} iniciada.`,
        run,
        overview: this.getOverview(false),
      }
    }

    // Resolve runtime & executable path for Desktop / CLI launch
    const chosenRuntime: "windows" | "wsl" | "linux_mac" =
      params.runtimeOverride ??
      (slot.activeRuntime === "windows" || slot.activeRuntime === "wsl" || slot.activeRuntime === "linux_mac"
        ? slot.activeRuntime
        : process.platform === "win32"
          ? "windows"
          : "linux_mac")

    const binPath =
      chosenRuntime === "windows"
        ? slot.windowsPath
        : chosenRuntime === "wsl"
          ? slot.wslPath
          : slot.posixPath

    if (!binPath) {
      throw new Error(
        `Executável de "${slot.name}" ainda não está instalado no ambiente "${chosenRuntime}". Use o botão Instalar ou aponte o caminho executável.`,
      )
    }

    // 4. Desktop GUI Launch (Burp Suite Community/Pro .exe or .jar, OpenTRAP via WSLg, Wireshark, Ghidra, JADX-GUI)
    if (params.action === "launch_desktop") {
      const extraArgs =
        slot.slotId === "opentrap" && binPath.toLowerCase().endsWith(".appimage")
          ? ["--appimage-extract-and-run"]
          : params.rawArgs?.trim()
            ? splitCommandLineArgs(params.rawArgs)
            : []

      if (chosenRuntime === "wsl") {
        const child = spawn(
          "wsl.exe",
          ["-d", this.config.preferredWslDistro, "--", binPath, ...extraArgs],
          {
            cwd: this.workspaceRoot,
            detached: true,
            stdio: "ignore",
            windowsHide: false,
          },
        )
        child.unref()
      } else if (chosenRuntime === "windows" && /\.jar$/i.test(binPath)) {
        const javaExe = this.findWindowsJavaExecutable(path.dirname(binPath))
        const jvmArgs = [
          "--add-opens=java.base/java.lang=ALL-UNNAMED",
          "--add-opens=java.base/javax.crypto=ALL-UNNAMED",
          "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
          "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
          "--add-opens=java.desktop/java.awt.color=ALL-UNNAMED",
          "--add-opens=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
          "-jar",
          binPath,
          ...extraArgs,
        ]
        const child = spawn(javaExe, jvmArgs, {
          cwd: path.dirname(binPath),
          detached: true,
          stdio: "ignore",
          windowsHide: false,
        })
        child.unref()
      } else if (chosenRuntime === "windows" && /\.(bat|cmd)$/i.test(binPath)) {
        const child = spawn("cmd.exe", ["/c", binPath, ...extraArgs], {
          cwd: this.workspaceRoot,
          detached: true,
          stdio: "ignore",
          windowsHide: false,
        })
        child.unref()
      } else {
        const child = spawn(binPath, extraArgs, {
          cwd: this.workspaceRoot,
          detached: true,
          stdio: "ignore",
          windowsHide: false,
        })
        child.unref()
      }

      return {
        ok: true,
        message: `${slot.name} iniciado (${chosenRuntime}: ${binPath}).`,
        overview: this.getOverview(false),
      }
    }

    // 5. Real Streaming CLI Execution (Windows PowerShell / Native or WSL2 Kali Linux)
    const useWslPaths = chosenRuntime === "wsl" && process.platform === "win32"
    const vars = this.buildTemplateVars(useWslPaths, params.target)
    const expandedArgsStr = this.expandArgsString(
      params.rawArgs ?? slot.presets[0]?.argsTemplate ?? "",
      vars,
    )
    this.verifyTargetAgainstScopeIfEnabled(params.target, expandedArgsStr)
    const parsedArgs = splitCommandLineArgs(expandedArgsStr)

    // When a dual desktop+cli slot like Wireshark or JADX runs CLI mode, prefer tshark / jadx CLI binary if present
    let cliExec = binPath
    if (slot.slotId === "wireshark" && /wireshark(\.exe)?$/i.test(binPath)) {
      const siblingTshark = path.join(path.dirname(binPath), process.platform === "win32" ? "tshark.exe" : "tshark")
      if (existsSync(siblingTshark)) cliExec = siblingTshark
    } else if (slot.slotId === "jadx" && /jadx-gui/i.test(binPath)) {
      const siblingJadx = binPath.replace(/jadx-gui/i, "jadx")
      if (chosenRuntime === "wsl" || existsSync(siblingJadx)) cliExec = siblingJadx
    }

    let spawnExec = cliExec
    let spawnArgs = parsedArgs
    if (chosenRuntime === "wsl") {
      const wslCwd = windowsPathToWslPath(this.workspaceRoot)
      spawnExec = "wsl.exe"
      spawnArgs = ["-d", this.config.preferredWslDistro, "--cd", wslCwd, "--", cliExec, ...parsedArgs]
    } else if (chosenRuntime === "windows" && /\.(bat|cmd)$/i.test(cliExec)) {
      spawnExec = "cmd.exe"
      spawnArgs = ["/c", cliExec, ...parsedArgs]
    }

    const run = this.startStreamingProcess({
      slotId: slot.slotId,
      slotName: slot.shortLabel,
      runtime: chosenRuntime,
      commandPreview:
        chosenRuntime === "wsl"
          ? `[WSL2 ${this.config.preferredWslDistro}] ${cliExec} ${expandedArgsStr}`
          : `${cliExec} ${expandedArgsStr}`,
      executable: spawnExec,
      args: spawnArgs,
      cwd: this.workspaceRoot,
    })

    return {
      ok: true,
      message: `Executando ${slot.shortLabel} ao vivo (${chosenRuntime})...`,
      run,
      overview: this.getOverview(false),
    }
  }

  private spawnForRuntimeWithPipes(
    runtime: "windows" | "wsl" | "linux_mac",
    binPath: string,
    args: string[],
    cwd: string,
    onOutput?: (text: string) => void,
  ): ChildProcess {
    let child: ChildProcess
    if (runtime === "wsl") {
      child = spawn("wsl.exe", ["-d", this.config.preferredWslDistro, "--", binPath, ...args], {
        cwd,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      })
    } else if (runtime === "windows" && /\.(bat|cmd)$/i.test(binPath)) {
      child = spawn("cmd.exe", ["/c", binPath, ...args], {
        cwd,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      })
    } else {
      child = spawn(binPath, args, {
        cwd,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      })
    }
    if (onOutput) {
      child.stdout?.on("data", (buf: Buffer) => onOutput(buf.toString("utf8")))
      child.stderr?.on("data", (buf: Buffer) => onOutput(buf.toString("utf8")))
    } else {
      child.stdout?.resume()
      child.stderr?.resume()
    }
    return child
  }

  private startStreamingProcess(opts: {
    slotId: string
    slotName: string
    runtime: ArsenalLiveRun["runtime"]
    commandPreview: string
    executable: string
    args: string[]
    stdinPayload?: string
    cwd: string
    onStepDone?: () => void
    onComplete?: () => void
  }): ArsenalLiveRun {
    const runId = `run-${crypto.randomUUID().slice(0, 8)}`
    const stamp = new Date().toISOString().replace(/[:.]/g, "-")
    const outputsDir = path.join(this.workspaceRoot, ".cyberlab", "outputs")
    mkdirSync(outputsDir, { recursive: true })
    const logRelPath = path.posix.join(".cyberlab", "outputs", `${opts.slotId}-${stamp}.log`)
    const logAbsPath = path.join(this.workspaceRoot, ".cyberlab", "outputs", `${opts.slotId}-${stamp}.log`)

    const info: ArsenalLiveRun = {
      runId,
      slotId: opts.slotId,
      slotName: opts.slotName,
      runtime: opts.runtime,
      commandPreview: opts.commandPreview,
      status: "running",
      exitCode: null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      outputLogPath: logRelPath,
      outputTail: `$ ${opts.commandPreview}\n`,
      lineCount: 1,
    }

    const record: LiveRunRecord = {
      info,
      lines: [`$ ${opts.commandPreview}`],
      child: null,
    }
    this.runs.set(runId, record)

    const appendChunk = (chunk: Buffer | string) => {
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8")
      const clean = text.replace(/\0/g, "")
      const split = clean.split(/\r?\n/)
      let sawStepDone = false
      for (const line of split) {
        if (!line) continue
        if (line.includes("[CONCLUIDO_SLOT]")) sawStepDone = true
        record.lines.push(line)
        if (record.lines.length > 2500) {
          record.lines.splice(1, record.lines.length - 2500)
        }
      }
      record.info.lineCount = record.lines.length
      record.info.outputTail = record.lines.slice(-400).join("\n")
      if (sawStepDone && opts.onStepDone) {
        setTimeout(() => opts.onStepDone?.(), 40)
      }
    }

    try {
      const child = spawn(opts.executable, opts.args, {
        cwd: opts.cwd,
        stdio: [opts.stdinPayload !== undefined ? "pipe" : "ignore", "pipe", "pipe"],
        windowsHide: true,
      })
      record.child = child
      if (opts.stdinPayload !== undefined) {
        child.stdin?.write(opts.stdinPayload)
        child.stdin?.end()
      }
      child.stdout?.on("data", appendChunk)
      child.stderr?.on("data", appendChunk)
      child.on("error", (err) => {
        appendChunk(`[erro ao iniciar processo] ${err.message}`)
        record.info.status = "failed"
        record.info.finishedAt = new Date().toISOString()
        record.child = null
        this.flushRunLog(logAbsPath, record.lines)
      })
      child.on("close", (code) => {
        if (record.info.status === "running") {
          record.info.status = code === 0 ? "succeeded" : "failed"
        }
        record.info.exitCode = code
        record.info.finishedAt = new Date().toISOString()
        record.child = null
        this.flushRunLog(logAbsPath, record.lines)
        opts.onComplete?.()
      })
    } catch (err) {
      appendChunk(`[falha] ${err instanceof Error ? err.message : String(err)}`)
      record.info.status = "failed"
      record.info.finishedAt = new Date().toISOString()
      this.flushRunLog(logAbsPath, record.lines)
    }

    return { ...record.info }
  }

  private flushRunLog(logAbsPath: string, lines: string[]): void {
    try {
      const redacted = redactSensitiveContent(lines.join("\n")).text
      writeFileSync(logAbsPath, `${redacted}\n`, "utf8")
    } catch {
      // Non-fatal
    }
  }

  private terminateProcessTree(child: ChildProcess): void {
    try {
      if (process.platform === "win32" && child.pid) {
        spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
          stdio: "ignore",
          windowsHide: true,
        })
      } else {
        child.kill("SIGTERM")
      }
    } catch {
      // Ignore
    }
  }

  stopRun(runId: string): ArsenalLiveRun | null {
    const rec = this.runs.get(runId)
    if (!rec) return null
    if (rec.child) {
      rec.info.status = "stopped"
      this.terminateProcessTree(rec.child)
    }
    return { ...rec.info }
  }

  getRun(runId: string): ArsenalLiveRun | null {
    const rec = this.runs.get(runId)
    return rec ? { ...rec.info } : null
  }

  listWorkspaceFiles(relativeDir = "."): {
    currentDir: string
    entries: WorkspaceFileEntry[]
  } {
    const cleanRel = relativeDir.trim() || "."
    if (!isPathInsideRoot(cleanRel, this.workspaceRoot)) {
      throw new Error(`Diretório fora do escopo do projeto: ${cleanRel}`)
    }
    const absDir = path.resolve(this.workspaceRoot, cleanRel)
    if (!existsSync(absDir)) {
      return { currentDir: cleanRel.replace(/\\/g, "/"), entries: [] }
    }
    const rawEntries = readdirSync(absDir, { withFileTypes: true })
    const entries: WorkspaceFileEntry[] = []
    for (const ent of rawEntries) {
      if (ent.name === "node_modules" || ent.name === ".git") continue
      const full = path.join(absDir, ent.name)
      const st = statSync(full, { throwIfNoEntry: false })
      if (!st) continue
      const relPath = path.relative(this.workspaceRoot, full).replace(/\\/g, "/")
      entries.push({
        name: ent.name,
        relativePath: relPath,
        kind: ent.isDirectory() ? "directory" : "file",
        sizeBytes: ent.isDirectory() ? 0 : st.size,
        modifiedAt: st.mtime.toISOString(),
      })
    }
    entries.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === "directory" ? -1 : 1
      return a.name.localeCompare(b.name)
    })
    return {
      currentDir: path.relative(this.workspaceRoot, absDir).replace(/\\/g, "/") || ".",
      entries: entries.slice(0, 300),
    }
  }

  readWorkspaceFilePreview(relativeFilePath: string, maxBytes = 128 * 1024): {
    relativePath: string
    sizeBytes: number
    truncated: boolean
    content: string
  } {
    if (!isPathInsideRoot(relativeFilePath, this.workspaceRoot)) {
      throw new Error(`Arquivo fora do escopo autorizado: ${relativeFilePath}`)
    }
    const abs = path.resolve(this.workspaceRoot, relativeFilePath)
    if (!existsSync(abs)) {
      throw new Error(`Arquivo não encontrado: ${relativeFilePath}`)
    }
    const st = statSync(abs)
    if (st.isDirectory()) {
      throw new Error(`O caminho é um diretório: ${relativeFilePath}`)
    }
    const raw = readFileSync(abs)
    const slice = raw.byteLength > maxBytes ? raw.subarray(0, maxBytes) : raw
    return {
      relativePath: path.relative(this.workspaceRoot, abs).replace(/\\/g, "/"),
      sizeBytes: st.size,
      truncated: raw.byteLength > maxBytes,
      content: slice.toString("utf8"),
    }
  }

  close(): void {
    for (const rec of this.runs.values()) {
      if (rec.child) this.terminateProcessTree(rec.child)
    }
    this.runs.clear()
    for (const daemon of this.daemons.values()) {
      if (daemon.child) this.terminateProcessTree(daemon.child)
      if (daemon.tcpBridges) {
        for (const srv of daemon.tcpBridges) {
          srv.close()
        }
      }
      if (daemon.staticServer) {
        daemon.staticServer.close()
      }
    }
    this.daemons.clear()
  }
}
