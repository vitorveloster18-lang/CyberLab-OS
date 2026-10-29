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

  private findWhereOnWindows(binNames: string[]): string | null {
    for (const bin of binNames) {
      if (!bin) continue
      const localBin = path.join(this.workspaceRoot, ".cyberlab", "bin", bin)
      if (existsSync(localBin)) return localBin
      const toolsBin = path.join(this.config.toolsRootDir, "bin", bin)
      if (existsSync(toolsBin)) return toolsBin
      try {
        const res = spawnSync("where.exe", [bin], {
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
          timeout: 2000,
        })
        if (res.status === 0 && res.stdout) {
          const hit = decodePotentialUtf16Le(res.stdout)
            .split(/\r?\n/)
            .map((s) => s.trim())
            .find((s) => s.length > 0 && existsSync(s))
          if (hit) return hit
        }
      } catch {
        // Ignore
      }
    }
    return null
  }

  private findWhichOnPosix(binNames: string[]): string | null {
    for (const bin of binNames) {
      if (!bin) continue
      const localBin = path.join(this.workspaceRoot, ".cyberlab", "bin", bin)
      if (existsSync(localBin)) return localBin
      const toolsBin = path.join(this.config.toolsRootDir, "bin", bin)
      if (existsSync(toolsBin)) return toolsBin
      try {
        const res = spawnSync("which", [bin], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 1800,
        })
        if (res.status === 0 && res.stdout) {
          const hit = res.stdout.split(/\r?\n/)[0]?.trim()
          if (hit && existsSync(hit)) return hit
        }
      } catch {
        // Ignore
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
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter((s) => s.length > 0 && !s.toLowerCase().includes("docker-desktop"))
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
            'export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:$HOME/.pdtm/go/bin:/usr/local/bin:/usr/bin:/bin:$PATH"',
            ...allPosixBins.map((token) =>
              token.includes("/")
                ? `p=${token.replace(/^~/, "$HOME")}; [ -x "$p" ] && echo "HIT:${token}=$p"`
                : `p=$(command -v "${token}" 2>/dev/null); [ -n "$p" ] && echo "HIT:${token}=$p"`,
            ),
          ].join("; ")

          try {
            const wslProbe = spawnSync(
              "wsl.exe",
              ["-d", this.config.preferredWslDistro, "--", "bash", "-c", scriptLines],
              {
                encoding: "utf8",
                stdio: ["ignore", "pipe", "ignore"],
                windowsHide: true,
                timeout: 6000,
              },
            )
            if (wslProbe.stdout) {
              for (const line of wslProbe.stdout.split(/\r?\n/)) {
                if (!line.startsWith("HIT:")) continue
                const eqIdx = line.indexOf("=")
                if (eqIdx === -1) continue
                const key = line.slice(4, eqIdx)
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
          winHit = this.findWhereOnWindows(def.windowsBinaries)
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
        def.defaultEmbedUrl ??
        null

      if (def.kind === "web_embed" && (probe.localHtmlEntry || embedUrl)) {
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
        const rel = decodeURIComponent(parsed.pathname === "/" ? `/${entryFile}` : parsed.pathname)
        const targetFile = path.resolve(baseDir, `.${rel}`)
        if (!targetFile.startsWith(path.resolve(baseDir)) || !existsSync(targetFile)) {
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
    const slot = currentOverview.slots.find((s) => s.slotId === params.slotId)
    const def = this.getAllDefinitions().find((d) => d.slotId === params.slotId)
    if (!slot || !def) {
      throw new Error(`Slot "${params.slotId}" não encontrado`)
    }

    // 1. Stop Web Daemon
    if (params.action === "stop_web") {
      const existing = this.daemons.get(slot.slotId)
      if (existing) {
        if (existing.child && existing.child.pid) {
          this.terminateProcessTree(existing.child)
        }
        if (existing.staticServer) {
          await new Promise<void>((resolve) => existing.staticServer!.close(() => resolve()))
        }
        this.daemons.delete(slot.slotId)
      }
      return {
        ok: true,
        message: `Serviço Web de ${slot.name} encerrado.`,
        overview: this.getOverview(false),
      }
    }

    // 2. Start / Embed Web Tool (e.g. GCHQ CyberChef Oficial, mitmweb, Caido, Kali Win-KeX / noVNC)
    if (params.action === "start_web") {
      const existing = this.daemons.get(slot.slotId)
      if (existing) {
        return {
          ok: true,
          message: `${slot.name} já está ativo em ${existing.embedUrl}`,
          embedUrl: existing.embedUrl,
          overview: this.getOverview(false),
        }
      }

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
          message: `${slot.name} carregado localmente de ${probe.localHtmlEntry}`,
          embedUrl: hosted.url,
          overview: this.getOverview(false),
        }
      }

      const targetEmbedUrl = slot.override.customEmbedUrl ?? def.defaultEmbedUrl
      if (def.managedDaemonArgs && slot.resolvedPath && slot.activeRuntime !== "web" && slot.activeRuntime !== "none") {
        const child = this.spawnForRuntime(
          slot.activeRuntime,
          slot.resolvedPath,
          def.managedDaemonArgs,
          this.workspaceRoot,
        )
        const url = targetEmbedUrl ?? `http://127.0.0.1:${def.managedDaemonPort ?? 8081}`
        this.daemons.set(slot.slotId, {
          child,
          staticServer: null,
          embedUrl: url,
        })
        await new Promise((r) => setTimeout(r, 900))
        return {
          ok: true,
          message: `Daemon ${slot.name} iniciado em ${url}`,
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

    // 3. One-Click Official Tool Installation (runs PowerShell or WSL2 Kali installer in live streaming console!)
    if (params.action === "install_tool") {
      const useKali =
        params.runtimeOverride === "wsl" ||
        (process.platform === "win32" && !slot.installPowerShell.trim() && this.wslAvailable)
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
        const cmd = slot.installKaliWsl
        const run = this.startStreamingProcess({
          slotId: slot.slotId,
          slotName: `Instalador Kali WSL2 — ${slot.shortLabel}`,
          runtime: "installer",
          commandPreview: `wsl.exe -d ${this.config.preferredWslDistro} -- bash -lc "${cmd}"`,
          executable: "wsl.exe",
          args: ["-d", this.config.preferredWslDistro, "--", "bash", "-lc", cmd],
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

  private spawnForRuntime(
    runtime: "windows" | "wsl" | "linux_mac",
    binPath: string,
    args: string[],
    cwd: string,
  ): ChildProcess {
    if (runtime === "wsl") {
      return spawn("wsl.exe", ["-d", this.config.preferredWslDistro, "--", binPath, ...args], {
        cwd,
        stdio: "ignore",
        windowsHide: true,
      })
    }
    if (runtime === "windows" && /\.(bat|cmd)$/i.test(binPath)) {
      return spawn("cmd.exe", ["/c", binPath, ...args], {
        cwd,
        stdio: "ignore",
        windowsHide: true,
      })
    }
    return spawn(binPath, args, {
      cwd,
      stdio: "ignore",
      windowsHide: true,
    })
  }

  private startStreamingProcess(opts: {
    slotId: string
    slotName: string
    runtime: ArsenalLiveRun["runtime"]
    commandPreview: string
    executable: string
    args: string[]
    cwd: string
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
      for (const line of split) {
        if (!line) continue
        record.lines.push(line)
        if (record.lines.length > 2500) {
          record.lines.splice(1, record.lines.length - 2500)
        }
      }
      record.info.lineCount = record.lines.length
      record.info.outputTail = record.lines.slice(-400).join("\n")
    }

    try {
      const child = spawn(opts.executable, opts.args, {
        cwd: opts.cwd,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      })
      record.child = child
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
      if (daemon.staticServer) {
        daemon.staticServer.close()
      }
    }
    this.daemons.clear()
  }
}
