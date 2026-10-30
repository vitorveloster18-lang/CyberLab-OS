import { spawn, spawnSync, type ChildProcess } from "node:child_process"
import crypto from "node:crypto"
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs"
import http from "node:http"
import net from "node:net"
import os from "node:os"
import path from "node:path"
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
      path.join(localAppData, "Microsoft", "WinGet", "Links"),
      path.join(localAppData, "Programs", "caido"),
      path.join(localAppData, "Programs", "Caido"),
      path.join(localAppData, "caido"),
      path.join(progFiles, "Caido"),
      path.join(localAppData, "Programs", "BurpSuiteCommunity"),
      path.join(localAppData, "Programs", "BurpSuitePro"),
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
      // 1. Probe WSL2 distros cleanly (handling UTF-16LE output of wsl.exe)
      this.wslAvailable = false
      this.wslDistros = []
      try {
        const wslList = spawnSync("wsl.exe", ["-l", "-q"], {
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
          timeout: 3500,
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
            'for d in "$HOME/.local/bin" "$HOME/go/bin" "$HOME/.cargo/bin" "$HOME/.pdtm/go/bin" /home/*/.local/bin /home/*/go/bin /home/*/.cargo/bin /home/*/.pdtm/go/bin /root/.local/bin /root/go/bin /root/.cargo/bin /opt/opentrap /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do [ -d "$d" ] && PATH="$d:$PATH"; done',
            "export PATH",
            ...allPosixBins.map((token) => {
              if (token.startsWith("~/")) {
                const sub = token.slice(2)
                return `for cand in "$HOME/${sub}" /home/*/${sub} "/root/${sub}"; do if [ -x "$cand" ]; then echo "HIT:${token}=$cand"; break; fi; done`
              }
              if (token.includes("/")) {
                return `p="${token}"; [ -x "$p" ] && echo "HIT:${token}=$p"`
              }
              return `p=$(command -v "${token}" 2>/dev/null | head -n 1); [ -n "$p" ] && echo "HIT:${token}=$p"`
            }),
          ].join("\n")

          try {
            const wslProbe = spawnSync(
              "wsl.exe",
              ["-d", this.config.preferredWslDistro, "--", "bash", "-s"],
              {
                input: Buffer.from(`${scriptLines}\n`, "utf8"),
                encoding: "utf8",
                stdio: ["pipe", "pipe", "ignore"],
                windowsHide: true,
                timeout: 12000,
              },
            )
            if (wslProbe.stdout) {
              for (const line of wslProbe.stdout.replace(/\0/g, "").split(/\r?\n/)) {
                if (!line.startsWith("HIT:")) continue
                const eqIdx = line.indexOf("=")
                if (eqIdx === -1) continue
                const key = line.slice(4, eqIdx).trim()
                const val = line.slice(eqIdx + 1).trim()
                if (key && val) wslResolvedByBin.set(key, val)
              }
            }
          } catch {
            // Ignore WSL probe timeout
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
  }

  getOverview(forceRefresh = false): ArsenalOverview {
    if (forceRefresh || !this.lastProbedAt) {
      this.probeEnvironment()
    }

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
    if (params.toolsRootDir !== undefined && params.toolsRootDir.trim()) {
      this.config.toolsRootDir = params.toolsRootDir.trim()
    }
    if (params.preferredWslDistro !== undefined && params.preferredWslDistro.trim()) {
      this.config.preferredWslDistro = params.preferredWslDistro.trim()
    }
    if (params.enforceScopeOnCliRuns !== undefined) {
      this.config.enforceScopeOnCliRuns = params.enforceScopeOnCliRuns
    }
    if (params.slotId && params.slotOverride) {
      this.config.slotOverrides[params.slotId] = {
        ...this.config.slotOverrides[params.slotId],
        ...params.slotOverride,
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
        res.writeHead(200, {
          "Content-Type": MIME_BY_EXT[ext] ?? "application/octet-stream",
          "Cache-Control": "no-cache",
        })
        res.end(readFileSync(targetFile))
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

  private findPreferredWindowsBurpJar(slot: ArsenalSlotStatus): string | null {
    const localAppData =
      process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local")
    const progFiles = process.env.ProgramFiles ?? "C:\\Program Files"
    const candidateDirs = Array.from(
      new Set(
        [
          path.join(localAppData, "Programs", "BurpSuiteCommunity"),
          path.join(progFiles, "BurpSuiteCommunity"),
          path.join(this.config.toolsRootDir, "BurpSuite"),
          slot.windowsPath ? path.dirname(slot.windowsPath) : "",
          path.join(localAppData, "Programs", "BurpSuitePro"),
          path.join(progFiles, "BurpSuitePro"),
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

  private resolveEmbeddedLinuxGuiCommand(slot: ArsenalSlotStatus): {
    launchCmd: string
    needsJava: boolean
    wslSourceBurpJar?: string
  } {
    // 1. Burp Suite: stage JAR onto fast Linux ext4 (/opt/cyberlab-burp/burpsuite.jar) & launch with Genuine Java 21 LTS
    //    and PortSwigger's exact 2026 module opens!
    if (slot.slotId === "burp-suite") {
      const winJar = process.platform === "win32" ? this.findPreferredWindowsBurpJar(slot) : null
      const wslSourceBurpJar = winJar ? windowsPathToWslPath(winJar) : undefined
      return {
        needsJava: true,
        ...(wslSourceBurpJar ? { wslSourceBurpJar } : {}),
        launchCmd: [
          '"$JAVA21_BIN"',
          "--add-opens=java.base/java.lang=ALL-UNNAMED",
          "--add-opens=java.base/javax.crypto=ALL-UNNAMED",
          "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
          "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
          "--add-opens=java.desktop/java.awt.color=ALL-UNNAMED",
          "--add-opens=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
          "-XX:MaxRAMPercentage=50",
          "-Dawt.useSystemAAFontSettings=on",
          "-Dswing.aatext=true",
          '-jar "$BURP_JAR_TARGET"',
        ].join(" "),
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

    // 3. Kali full desktop stream
    if (slot.slotId === "kali-desktop-stream") {
      return {
        needsJava: false,
        launchCmd: "(command -v startxfce4 >/dev/null 2>&1 && dbus-launch --exit-with-session startxfce4) || openbox-session",
      }
    }

    // 4. OWASP ZAP, Ghidra, Wireshark, JADX-GUI, Cutter, or custom GUI slot
    if (slot.slotId === "owasp-zap") {
      const p = slot.wslPath ?? slot.posixPath ?? "zaproxy"
      return { needsJava: true, launchCmd: `'${p.replace(/'/g, "'\\''")}'` }
    }
    if (slot.slotId === "ghidra") {
      const p = slot.wslPath ?? slot.posixPath ?? "ghidra"
      return { needsJava: true, launchCmd: `'${p.replace(/'/g, "'\\''")}'` }
    }
    if (slot.slotId === "jadx") {
      const p = slot.wslPath ?? slot.posixPath ?? "jadx-gui"
      return { needsJava: true, launchCmd: `'${p.replace(/'/g, "'\\''")}'` }
    }
    if (slot.slotId === "wireshark") {
      return { needsJava: false, launchCmd: "wireshark" }
    }
    if (slot.slotId === "rizin-cutter") {
      return { needsJava: false, launchCmd: "cutter" }
    }

    const fallback = slot.wslPath ?? slot.posixPath
    if (!fallback) {
      throw new Error(
        `Para abrir "${slot.name}" dentro do palco central, instale a versão Linux/WSL2 ou ative o Kali WSL2.`,
      )
    }
    return { needsJava: false, launchCmd: `'${fallback.replace(/'/g, "'\\''")}'` }
  }

  private async startEmbeddedGuiCanvas(slot: ArsenalSlotStatus): Promise<{
    embedUrl: string
    message: string
  }> {
    const useWsl = process.platform === "win32"
    if (useWsl && (!this.wslAvailable || !this.config.preferredWslDistro)) {
      throw new Error(
        `Para abrir a interface gráfica de "${slot.name}" dentro do centro do CyberLab OS no Windows, o WSL2 (kali-linux) precisa estar instalado. Caso prefira, clique em "Janela Externa do Windows".`,
      )
    }

    const { launchCmd, needsJava, wslSourceBurpJar } = this.resolveEmbeddedLinuxGuiCommand(slot)
    const dispNum = this.allocateX11Display()
    const vncPort = 5900 + dispNum
    const wsPort = 6000 + dispNum
    const escapedWslSrcJar = wslSourceBurpJar ? wslSourceBurpJar.replace(/'/g, "'\\''") : ""

    // 1. Ensure Xtigervnc + openbox + novnc + websockify + x11-utils + genuine Java 21 LTS (Temurin 21)
    //    + native ext4 cached Burp JAR (/opt/cyberlab-burp/burpsuite.jar) are ready inside Kali WSL2!
    const bootstrapCheckAndInstall = [
      "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH",
      "MISSING=0",
      "command -v Xtigervnc >/dev/null 2>&1 || MISSING=1",
      "command -v openbox >/dev/null 2>&1 || MISSING=1",
      "command -v websockify >/dev/null 2>&1 || MISSING=1",
      "command -v xmessage >/dev/null 2>&1 || MISSING=1",
      "[ -d /usr/share/novnc ] || MISSING=1",
      'if [ "$MISSING" = "1" ]; then',
      "  export DEBIAN_FRONTEND=noninteractive",
      "  apt-get update -qq || true",
      "  apt-get install -y -qq curl jq tar tigervnc-standalone-server openbox novnc websockify dbus-x11 x11-xserver-utils x11-utils fonts-dejavu-core || true",
      "fi",
      ...(slot.slotId === "burp-suite"
        ? [
            "mkdir -p /opt/cyberlab-burp",
            ...(escapedWslSrcJar
              ? [
                  `if [ ! -s /opt/cyberlab-burp/burpsuite.jar ] && [ -f '${escapedWslSrcJar}' ]; then cp -f '${escapedWslSrcJar}' /opt/cyberlab-burp/burpsuite.jar && chmod 644 /opt/cyberlab-burp/burpsuite.jar; fi`,
                ]
              : []),
            "if [ ! -s /opt/cyberlab-burp/burpsuite.jar ] && [ -f /usr/share/burpsuite/burpsuite.jar ]; then ln -sf /usr/share/burpsuite/burpsuite.jar /opt/cyberlab-burp/burpsuite.jar; fi",
            "if [ ! -s /opt/cyberlab-burp/burpsuite.jar ]; then export DEBIAN_FRONTEND=noninteractive; apt-get update -qq || true; apt-get install -y -qq burpsuite || true; [ -f /usr/share/burpsuite/burpsuite.jar ] && ln -sf /usr/share/burpsuite/burpsuite.jar /opt/cyberlab-burp/burpsuite.jar; fi",
          ]
        : []),
      ...(needsJava
        ? [
            'if [ ! -x /opt/cyberlab-jre21/bin/java ] && [ ! -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java ]; then',
            "  export DEBIAN_FRONTEND=noninteractive",
            "  apt-get install -y -qq curl jq tar ca-certificates || true",
            "  apt-get install -y -qq openjdk-21-jre 2>/dev/null || true",
            "  if [ ! -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java ]; then",
            "    JRE_URL=$(curl -fsSL https://api.github.com/repos/adoptium/temurin21-binaries/releases/latest | jq -r '.assets[] | select(.name | test(\"OpenJDK21U-jre_x64_linux_hotspot_.*\\\\.tar\\\\.gz$\")) | .browser_download_url' | head -n 1)",
            '    if [ -n "$JRE_URL" ]; then',
            '      mkdir -p /opt/cyberlab-jre21 && curl -fsSL "$JRE_URL" -o /tmp/jre21.tar.gz && tar -xzf /tmp/jre21.tar.gz -C /opt/cyberlab-jre21 --strip-components=1 && rm -f /tmp/jre21.tar.gz',
            "    fi",
            "  fi",
            "fi",
          ]
        : []),
      "hostname -I 2>/dev/null | awk '{print $1}'",
    ].join("\n")

    let wslIp = "127.0.0.1"
    if (useWsl) {
      const boot = spawnSync(
        "wsl.exe",
        ["-d", this.config.preferredWslDistro, "-u", "root", "--", "bash", "-s"],
        {
          input: Buffer.from(`${bootstrapCheckAndInstall}\n`, "utf8"),
          encoding: "utf8",
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
          timeout: 240000,
        },
      )
      const ipLine = (boot.stdout ?? "")
        .replace(/\0/g, "")
        .trim()
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => /^\d+\.\d+\.\d+\.\d+$/.test(s))
        .pop()
      if (ipLine) wslIp = ipLine
    }

    // 2. Start dedicated Xtigervnc + Openbox (<decor>yes</decor> so fixed-size startup wizards render properly
    //    and resizable main frames auto-maximize!) + websockify + GUI tool
    const sessionScript = [
      'if [ -x /opt/cyberlab-jre21/bin/java ]; then export JAVA_HOME=/opt/cyberlab-jre21; export JAVA21_BIN=/opt/cyberlab-jre21/bin/java; elif [ -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java ]; then export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64; export JAVA21_BIN=/usr/lib/jvm/java-21-openjdk-amd64/bin/java; else export JAVA21_BIN=java; fi',
      'export BURP_JAR_TARGET=/opt/cyberlab-burp/burpsuite.jar; [ ! -s "$BURP_JAR_TARGET" ] && [ -f /usr/share/burpsuite/burpsuite.jar ] && export BURP_JAR_TARGET=/usr/share/burpsuite/burpsuite.jar',
      'export PATH="${JAVA_HOME:+$JAVA_HOME/bin:}$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:/opt/opentrap:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"',
      `pkill -f "Xtigervnc :${dispNum}" 2>/dev/null || true`,
      `pkill -f "websockify.*:${wsPort}" 2>/dev/null || true`,
      `rm -f /tmp/.X${dispNum}-lock /tmp/.X11-unix/X${dispNum} 2>/dev/null || true`,
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
      `    <application type="*">`,
      `      <decor>yes</decor>`,
      `      <focus>yes</focus>`,
      `      <maximized>yes</maximized>`,
      `      <position force="no"><x>center</x><y>center</y></position>`,
      `    </application>`,
      `  </applications>`,
      `</openbox_config>`,
      `EOF_OB`,
      `Xtigervnc :${dispNum} -rfbport ${vncPort} -SecurityTypes None -AlwaysShared -AcceptSetDesktopSize=1 -geometry 1440x900 -depth 24 -dpi 96 >/dev/null 2>&1 &`,
      "VNC_PID=$!",
      "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do [ -S /tmp/.X11-unix/X" + dispNum + " ] && break; sleep 0.2; done",
      `export DISPLAY=:${dispNum}`,
      "export GDK_SCALE=1",
      "xsetroot -solid '#111827' 2>/dev/null || true",
      ...(slot.slotId === "kali-desktop-stream"
        ? []
        : [`openbox --config-file /tmp/cyberlab-ob-${dispNum}.xml >/dev/null 2>&1 &`, "sleep 0.3"]),
      `websockify --web=/usr/share/novnc 0.0.0.0:${wsPort} 127.0.0.1:${vncPort} >/dev/null 2>&1 &`,
      "WS_PID=$!",
      `(xmessage -center -timeout 6 -buttons "" "Iniciando ${slot.shortLabel} (Java 21 LTS)... Aguarde alguns segundos." >/dev/null 2>&1 || true) &`,
      `(${launchCmd} >/tmp/cyberlab-gui-${dispNum}.log 2>&1 || xmessage -center -title "Diagnóstico ${slot.shortLabel}" -file /tmp/cyberlab-gui-${dispNum}.log >/dev/null 2>&1) &`,
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
    const liveHost = await this.waitForTcpPort(candidateHosts, wsPort, 7000)
    if (!liveHost) {
      this.terminateProcessTree(child)
      throw new Error(
        `O servidor gráfico embutido (noVNC :${wsPort}) não respondeu a tempo. Verifique no Kali WSL2 se os pacotes novnc, websockify e tigervnc-standalone-server estão instalados.`,
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

    const embedUrl = `http://127.0.0.1:${mainBridge.localPort}/vnc.html?autoconnect=true&resize=remote&reconnect=true&reconnect_delay=1000`
    this.daemons.set(slot.slotId, {
      child,
      staticServer: null,
      tcpBridges,
      wslDisplayNum: dispNum,
      embedUrl,
    })

    return {
      embedUrl,
      message: `${slot.name} aberto dentro do Palco Central do CyberLab OS (redimensionamento automático ativo).`,
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
        'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.cargo/bin:/root/go/bin:$PATH"',
        'echo "=== Preparando base (curl, jq, unzip, tar, ca-certificates) ==="',
        "apt-get update -qq || true",
        "apt-get install -y -qq curl jq unzip tar ca-certificates || true",
        ...ordered.map((s, idx) => {
          const cleanCmd = s.installKaliWsl.replace(/\bsudo\s+/g, "")
          return [
            `echo ""`,
            `echo "============================================================"`,
            `echo "  [${idx + 1}/${ordered.length}] Instalando ${s.name}..."`,
            `echo "============================================================"`,
            `(${cleanCmd}) && echo "[CONCLUIDO_SLOT] ${s.slotId}" || echo "[AVISO] Falha parcial em ${s.shortLabel} (continuando para a próxima...)"`,
          ].join("\n")
        }),
        'echo ""',
        'echo "=== TODAS AS ETAPAS FINALIZADAS! ATUALIZANDO SLOTS DO CYBERLAB OS... ==="',
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
        const guiCanvas = await this.startEmbeddedGuiCanvas(slot)
        return {
          ok: true,
          message: guiCanvas.message,
          embedUrl: guiCanvas.embedUrl,
          overview: this.getOverview(false),
        }
      }

      // 2c. Managed local Web daemon (e.g. mitmweb :8081, Caido :7000 — supports both Windows native AND WSL2 Kali!)
      const targetEmbedUrl = slot.override.customEmbedUrl ?? def.defaultEmbedUrl
      if (def.managedDaemonArgs && slot.resolvedPath && slot.activeRuntime !== "web" && slot.activeRuntime !== "none") {
        let tokenUrl: string | null = null
        let wslDaemonIp = "127.0.0.1"
        if (slot.activeRuntime === "wsl" && process.platform === "win32") {
          try {
            const ipCheck = spawnSync(
              "wsl.exe",
              ["-d", this.config.preferredWslDistro, "--", "hostname", "-I"],
              { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], windowsHide: true, timeout: 3000 },
            )
            const firstIp = (ipCheck.stdout ?? "").trim().split(/\s+/)[0]
            if (firstIp && /^\d+\.\d+\.\d+\.\d+$/.test(firstIp)) wslDaemonIp = firstIp
          } catch {
            // Ignore
          }
        }
        const child = this.spawnForRuntimeWithPipes(
          slot.activeRuntime,
          slot.resolvedPath,
          def.managedDaemonArgs,
          this.workspaceRoot,
          (chunk) => {
            const match = chunk.match(/https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0):\d+\/\?token=[a-zA-Z0-9._-]+/i)
            if (match && !tokenUrl) tokenUrl = match[0].replace("0.0.0.0", "127.0.0.1")
          },
        )
        const port = def.managedDaemonPort ?? 8081
        const candidateHosts = Array.from(new Set([wslDaemonIp, "127.0.0.1", "localhost"]))
        await this.waitForTcpPort(candidateHosts, port, 5500)

        const tcpBridges: net.Server[] = []
        let url = tokenUrl ?? targetEmbedUrl ?? `http://127.0.0.1:${port}`
        if (slot.activeRuntime === "wsl" && process.platform === "win32" && wslDaemonIp !== "127.0.0.1") {
          const bridge = await this.createTcpBridgeServer(candidateHosts, port, 0)
          if (bridge) {
            tcpBridges.push(bridge.server)
            const suffix = tokenUrl ? new URL(tokenUrl).search : ""
            url = `http://127.0.0.1:${bridge.localPort}/${suffix}`
          }
        }

        this.daemons.set(slot.slotId, {
          child,
          staticServer: null,
          tcpBridges,
          embedUrl: url,
        })
        return {
          ok: true,
          message: `${slot.name} iniciado no Palco Central (${url})`,
          embedUrl: url,
          overview: this.getOverview(false),
        }
      }

      if (targetEmbedUrl) {
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

    // 4. Desktop GUI Launch (Burp Suite Community/Pro, OpenTRAP via WSLg, Wireshark, Ghidra, JADX-GUI)
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
