import { spawn } from "node:child_process"
import {
  accessSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
} from "node:fs"
import path from "node:path"
import { Schema } from "effect"
import type { CapabilityDefinition } from "../contracts/capability.js"
import type { EvidenceKind } from "../contracts/evidence.js"
import type { CyberLabExecutor, ExecutorContext, ExecutorInput, ExecutorResult } from "../contracts/execution.js"
import type { EvidenceStore } from "../evidence/store.js"
import { redactSensitiveContent } from "../evidence/provenance.js"
import { capOutputBytes } from "../execution/cancellation.js"
import { normalizeRawOutputDraft } from "../execution/result-normalizer.js"
import { extractTargetsFromInput, isPathInsideRoot, type ScopeController } from "../policy/scope.js"
import {
  buildProcessLaunch,
  probeWslBinaries,
  probeWslEnvironment,
  type ProcessLaunch,
} from "./wsl-runtime.js"

export type ExternalOriginKind = "manual_external" | "external_plugin" | "mcp_bridge" | "inbox_drop"

export interface ExternalToolCatalogEntry {
  toolId: string
  displayName: string
  binaryCandidates: readonly string[]
  /**
   * Nomes candidatos dentro do Linux (WSL2 Kali / nativo). Quando ausente, herda
   * `binaryCandidates`. Necessário porque o Windows usa wrappers (`.bat`/`.exe`)
   * enquanto o Kali expõe o binário POSIX puro (ex.: `analyzeHeadless`, `jadx`).
   */
  posixBinaries?: readonly string[]
  /**
   * Caminhos absolutos onde o binário POSIX costuma morar **sem estar no PATH**.
   * Motivação real: no Debian/Kali o pacote `ghidra` só coloca o launcher gráfico
   * em `/usr/bin/ghidra`; o `analyzeHeadless` (que é o que o agente invoca) fica em
   * `/usr/share/ghidra/support/analyzeHeadless`, fora do PATH. Procurar só por nome
   * fazia a ferramenta aparecer como "faltando" mesmo estando instalada.
   */
  posixKnownPaths?: readonly string[]
  licenseSpdx: string
  integrationMode: "plugin_only" | "approved_internal_process" | "mcp"
  governedCapabilityId?: string
  installHint: string
  /** Comando de instalação equivalente dentro do WSL2 Kali Linux. */
  installKaliWsl?: string
  description: string
}

export type ExternalBinarySourceLocation =
  | "workspace_local_bin"
  | "system_path"
  | "custom_config"
  | "wsl_distro"
  | "missing"

export interface ExternalToolRuntimeStatus {
  toolId: string
  displayName: string
  available: boolean
  resolvedPath: string | null
  sourceLocation: ExternalBinarySourceLocation
  licenseSpdx: string
  integrationMode: "plugin_only" | "approved_internal_process" | "mcp"
  governedCapabilityId: string | null
  installHint: string
  installHintWsl: string
  description: string
  /** Distro WSL2 que fornece o binário (quando `sourceLocation === "wsl_distro"`). */
  wslDistro: string | null
  /** Caminho POSIX do binário dentro da distro WSL2. */
  wslPath: string | null
}

export const BUILTIN_EXTERNAL_TOOL_CATALOG: readonly ExternalToolCatalogEntry[] = [
  {
    toolId: "nmap",
    displayName: "Nmap Network Mapper",
    binaryCandidates: ["nmap"],
    licenseSpdx: "NPSL-0.95",
    integrationMode: "plugin_only",
    governedCapabilityId: "external.nmap-service-probe",
    installHint: "sudo apt install nmap (or system package manager)",
    posixBinaries: ["nmap"],
    installKaliWsl: "sudo apt update && sudo apt install -y nmap",
    description: "External host/service discovery binary governed via structured non-shell arguments and ScopeController.",
  },
  {
    toolId: "nuclei",
    displayName: "ProjectDiscovery Nuclei",
    binaryCandidates: ["nuclei"],
    licenseSpdx: "MIT",
    integrationMode: "approved_internal_process",
    governedCapabilityId: "external.nuclei-template-scan",
    installHint: "./script/bootstrap-local-tools.sh",
    posixBinaries: ["nuclei"],
    installKaliWsl: "sudo apt update && sudo apt install -y nuclei && nuclei -update-templates",
    description: "Standalone template vulnerability scanner installed in .cyberlab/bin/nuclei or PATH.",
  },
  {
    toolId: "ffuf",
    displayName: "ffuf Fast Web Fuzzer",
    binaryCandidates: ["ffuf"],
    licenseSpdx: "MIT",
    integrationMode: "approved_internal_process",
    governedCapabilityId: "external.ffuf-endpoint-probe",
    installHint: "./script/bootstrap-local-tools.sh",
    posixBinaries: ["ffuf"],
    installKaliWsl: "sudo apt update && sudo apt install -y ffuf seclists",
    description: "Rate-limited web content discovery binary installed in .cyberlab/bin/ffuf or PATH.",
  },
  {
    toolId: "tshark",
    displayName: "Wireshark CLI (tshark)",
    binaryCandidates: ["tshark"],
    licenseSpdx: "GPL-2.0-or-later",
    integrationMode: "plugin_only",
    governedCapabilityId: "external.tshark-pcap-summary",
    installHint: "sudo apt install tshark",
    posixBinaries: ["tshark"],
    installKaliWsl: "sudo apt update && sudo apt install -y tshark",
    description: "External deep protocol dissector invoked strictly on workspace .pcap files without GPL linking.",
  },
  {
    toolId: "opentrap",
    displayName: "OpenTRAP Desktop Proxy (ZAP Engine)",
    binaryCandidates: ["opentrap.AppImage", "opentrap"],
    licenseSpdx: "AGPL-3.0-only",
    integrationMode: "plugin_only",
    installHint: "./script/bootstrap-local-tools.sh --with-agpl",
    posixBinaries: ["opentrap"],
    installKaliWsl: "See slot installer (OpenTRAP AppImage in WSL2)",
    description: "External Linux GUI proxy/repeater; export traffic to .cyberlab/inbox/ or ingest via CyberLab Control Plane.",
  },
  {
    toolId: "mvt-android",
    displayName: "Mobile Verification Toolkit (MVT)",
    binaryCandidates: ["mvt-android", "mvt-ios"],
    licenseSpdx: "LicenseRef-MVT",
    integrationMode: "plugin_only",
    installHint: "pipx install mvt",
    posixBinaries: ["mvt-android", "mvt-ios"],
    installKaliWsl: "pipx install mvt",
    description: "External mobile forensic CLI; drop JSON results into .cyberlab/inbox/ or run via cyberlab external wrap.",
  },
  {
    toolId: "ghidra-headless",
    displayName: "Ghidra AnalyzeHeadless (NSA)",
    binaryCandidates: ["analyzeHeadless", "analyzeHeadless.bat", "ghidra-analyzeHeadless"],
    posixKnownPaths: [
      "/usr/share/ghidra/support/analyzeHeadless",
      "/opt/ghidra/support/analyzeHeadless",
    ],
    licenseSpdx: "Apache-2.0",
    integrationMode: "approved_internal_process",
    governedCapabilityId: "external.ghidra-decompile",
    installHint: "Install Ghidra (Apache-2.0) and expose analyzeHeadless / analyzeHeadless.bat on PATH",
    posixBinaries: ["analyzeHeadless", "ghidra-analyzeHeadless"],
    installKaliWsl: "sudo apt update && sudo apt install -y ghidra",
    description: "External headless decompiler & analyzer synchronized into CyberLab EvidenceStore.",
  },
  {
    toolId: "jadx",
    displayName: "JADX Dex-to-Java Decompiler",
    binaryCandidates: ["jadx", "jadx.bat"],
    licenseSpdx: "Apache-2.0",
    integrationMode: "approved_internal_process",
    governedCapabilityId: "external.jadx-decompile",
    installHint: "winget install skylot.jadx (Windows) or apt/brew install jadx",
    posixBinaries: ["jadx"],
    installKaliWsl: "sudo apt update && sudo apt install -y jadx",
    description: "Apache-2.0 Android .apk / .dex to Java source decompiler outputting into workspace artifacts.",
  },
  {
    toolId: "yarax",
    displayName: "YARA-X / YARA CLI (yr / yara)",
    binaryCandidates: ["yr", "yara64", "yara"],
    licenseSpdx: "BSD-3-Clause",
    integrationMode: "approved_internal_process",
    governedCapabilityId: "external.yarax-scan",
    installHint: "Install VirusTotal YARA-X ('yr', BSD-3-Clause) in .cyberlab/bin or PATH",
    posixBinaries: ["yr", "yara"],
    installKaliWsl: "sudo apt update && sudo apt install -y yara (or install YARA-X 'yr' from VirusTotal)",
    description: "High-speed Rust YARA-X indicator & signature scanner governed on workspace files.",
  },
  {
    toolId: "dalfox",
    displayName: "Dalfox Parameter & Reflection Scanner",
    binaryCandidates: ["dalfox"],
    licenseSpdx: "MIT",
    integrationMode: "approved_internal_process",
    governedCapabilityId: "external.dalfox-param-scan",
    installHint: "go install github.com/hahwul/dalfox/v2@latest (or place in .cyberlab/bin)",
    posixBinaries: ["dalfox"],
    installKaliWsl: "sudo apt update && sudo apt install -y dalfox (or go install github.com/hahwul/dalfox/v2@latest)",
    description: "MIT parameter reflection analyzer governed by ScopeController and ApprovalTicket.",
  },
  {
    toolId: "trivy",
    displayName: "Aqua Trivy SCA / Container / IaC Scanner",
    binaryCandidates: ["trivy"],
    licenseSpdx: "Apache-2.0",
    integrationMode: "approved_internal_process",
    governedCapabilityId: "external.trivy-scan",
    installHint: "winget install AquaSecurity.Trivy (Windows) or brew/apt install trivy",
    posixBinaries: ["trivy"],
    installKaliWsl: "sudo apt update && sudo apt install -y trivy",
    description: "Apache-2.0 filesystem vulnerability, container & IaC misconfiguration scanner governed inside workspace.",
  },
  {
    toolId: "keyhunter",
    displayName: "KeyHunter Rust CLI (fadidevv/keyhunter)",
    binaryCandidates: ["keyhunter", "github-keyhunter"],
    licenseSpdx: "MIT",
    integrationMode: "approved_internal_process",
    governedCapabilityId: "external.keyhunter-cli",
    installHint: "cargo install github-keyhunter (or place keyhunter / keyhunter.exe in .cyberlab/bin)",
    posixBinaries: ["keyhunter", "github-keyhunter"],
    installKaliWsl: "cargo install github-keyhunter (inside WSL2 Kali)",
    description: "MIT Rust API key hunter CLI (45+ providers, scan/verify/patterns) governed with automatic secret redaction and SHA-256 custody.",
  },
]

function expandPlatformNames(name: string): string[] {
  if (process.platform !== "win32") return [name]
  const lower = name.toLowerCase()
  if (lower.endsWith(".exe") || lower.endsWith(".cmd") || lower.endsWith(".bat")) {
    return [name]
  }
  return [`${name}.exe`, `${name}.cmd`, `${name}.bat`, name]
}

function isExecutableFile(candidatePath: string): boolean {
  try {
    const st = statSync(candidatePath, { throwIfNoEntry: false })
    if (!st || !st.isFile()) return false
    if (process.platform === "win32") {
      return true
    }
    accessSync(candidatePath, constants.X_OK)
    return true
  } catch {
    return false
  }
}

export interface ResolvedExternalBinary {
  resolvedPath: string | null
  sourceLocation: ExternalBinarySourceLocation
  /** Preenchido apenas quando o binário foi localizado dentro de uma distro WSL2. */
  wslDistro: string | null
  wslPath: string | null
}

/**
 * Resolve um binário externo em 4 camadas, nesta ordem:
 *   1. `config/external-tools.json` (`binaryPaths`) — override explícito do operador
 *   2. `<workspace>/.cyberlab/bin` — bootstrap local
 *   3. `PATH` do host (Windows ou Linux/macOS nativo)
 *   4. **WSL2** (somente Windows) — probe batido em `kali-linux` (ou 1ª distro),
 *      eliminando a divergência "slot INSTALLED vs. capability not installed".
 */
export function resolveExternalBinary(
  workspaceRoot: string,
  candidates: readonly string[],
  customPaths?: Record<string, string>,
  posixCandidates?: readonly string[],
): ResolvedExternalBinary {
  for (const name of candidates) {
    const configured = customPaths?.[name]
    if (configured && isExecutableFile(configured)) {
      return {
        resolvedPath: path.resolve(configured),
        sourceLocation: "custom_config",
        wslDistro: null,
        wslPath: null,
      }
    }
  }

  const localBinDir = path.join(workspaceRoot, ".cyberlab", "bin")
  for (const name of candidates) {
    for (const variant of expandPlatformNames(path.basename(name))) {
      const localCandidate = path.join(localBinDir, variant)
      if (isExecutableFile(localCandidate)) {
        return {
          resolvedPath: localCandidate,
          sourceLocation: "workspace_local_bin",
          wslDistro: null,
          wslPath: null,
        }
      }
    }
  }

  const envPath = process.env.PATH ?? ""
  const dirs = envPath.split(path.delimiter).filter(Boolean)
  for (const name of candidates) {
    const variants = expandPlatformNames(path.basename(name))
    for (const dir of dirs) {
      for (const variant of variants) {
        const sysCandidate = path.join(dir, variant)
        if (isExecutableFile(sysCandidate)) {
          return {
            resolvedPath: sysCandidate,
            sourceLocation: "system_path",
            wslDistro: null,
            wslPath: null,
          }
        }
      }
    }
  }

  // 4. Camada WSL2 — probe batido (um único `wsl.exe` para todos os candidatos).
  // Nomes primeiro (um binário no PATH é preferível), caminhos absolutos por último.
  const wslNames = Array.from(new Set([...(posixCandidates ?? candidates), ...candidates]))
    .map((n) => n.replace(/\.(exe|cmd|bat)$/i, ""))
    .filter(isProbeablePosix)
  if (wslNames.length > 0) {
    const env = probeWslEnvironment()
    if (env.available) {
      const hits = probeWslBinaries(wslNames)
      for (const name of wslNames) {
        const hit = hits.get(name)
        if (hit) {
          return {
            resolvedPath: hit.linuxPath,
            sourceLocation: "wsl_distro",
            wslDistro: hit.distro,
            wslPath: hit.linuxPath,
          }
        }
      }
    }
  }

  return { resolvedPath: null, sourceLocation: "missing", wslDistro: null, wslPath: null }
}

/**
 * Aceita um nome de binário (`nmap`) ou um caminho absoluto POSIX
 * (`/usr/share/ghidra/support/analyzeHeadless`) — este último para ferramentas que o
 * pacote da distro instala fora do PATH. Deliberadamente restritivo: o valor vai para
 * dentro de um script bash, então só passa o que é inequivocamente seguro.
 */
const POSIX_PROBE_RE = /^(?:\/[a-zA-Z0-9._~-]+)+$|^[a-zA-Z0-9._~-]+$/
export function isProbeablePosix(candidate: string): boolean {
  return POSIX_PROBE_RE.test(candidate) && !candidate.includes("..")
}

/** Aliases Windows -> POSIX para binários cujo wrapper difere no Linux. */
const POSIX_BINARY_ALIASES: Record<string, readonly string[]> = {
  "analyzeHeadless": ["analyzeHeadless", "ghidra-analyzeHeadless"],
  "analyzeHeadless.bat": ["analyzeHeadless", "ghidra-analyzeHeadless"],
  "ghidra-analyzeHeadless": ["analyzeHeadless", "ghidra-analyzeHeadless"],
  "jadx.bat": ["jadx"],
  "yara64": ["yara", "yr"],
  "yara": ["yara", "yr"],
  "github-keyhunter": ["keyhunter", "github-keyhunter"],
  "opentrap.AppImage": ["opentrap"],
}

/**
 * Converte a lista de candidatos usada por uma capability (nomes Windows) nos nomes
 * POSIX equivalentes para o probe WSL2, garantindo paridade com o slot manager.
 */
export function resolvePosixCandidates(windowsCandidates: readonly string[]): string[] {
  const out = new Set<string>()
  for (const entry of BUILTIN_EXTERNAL_TOOL_CATALOG) {
    if (entry.binaryCandidates.some((c) => windowsCandidates.includes(c))) {
      for (const p of entry.posixBinaries ?? entry.binaryCandidates) out.add(p)
    }
  }
  for (const c of windowsCandidates) {
    const base = c.replace(/\.(exe|cmd|bat|AppImage)$/i, "")
    if (base) out.add(base)
    for (const alias of POSIX_BINARY_ALIASES[c] ?? []) out.add(alias)
  }
  for (const entry of BUILTIN_EXTERNAL_TOOL_CATALOG) {
    if (entry.binaryCandidates.some((c) => windowsCandidates.includes(c))) {
      for (const p of entry.posixKnownPaths ?? []) out.add(p)
    }
  }
  return Array.from(out).filter(isProbeablePosix)
}

/**
 * Executa um binário já resolvido, encapsulando automaticamente em `wsl.exe` e
 * traduzindo caminhos Windows -> `/mnt/...` quando ele vive dentro do WSL2.
 */
export async function runExternalBinary(params: {
  resolved: ResolvedExternalBinary
  args: readonly string[]
  cwd: string
  signal: AbortSignal
  maxOutputBytes?: number
  onStdoutChunk?: (chunk: string) => void
  onStderrChunk?: (chunk: string) => void
}): Promise<{ exitCode: number; stdout: string; stderr: string; truncated: boolean }> {
  return runSafeChildProcess({
    ...buildProcessLaunch({
      binaryPath: params.resolved.resolvedPath ?? "",
      args: params.args,
      cwd: params.cwd,
      wsl:
        params.resolved.sourceLocation === "wsl_distro" && params.resolved.wslDistro && params.resolved.wslPath
          ? { distro: params.resolved.wslDistro, linuxBinary: params.resolved.wslPath }
          : null,
    }),
    signal: params.signal,
    maxOutputBytes: params.maxOutputBytes,
    onStdoutChunk: params.onStdoutChunk,
    onStderrChunk: params.onStderrChunk,
  })
}

/** Descreve como um binário resolvido será efetivamente lançado (útil p/ diagnóstico e testes). */
export function describeLaunch(resolved: ResolvedExternalBinary, args: readonly string[], cwd: string): ProcessLaunch {
  return buildProcessLaunch({
    binaryPath: resolved.resolvedPath ?? "",
    args,
    cwd,
    wsl:
      resolved.sourceLocation === "wsl_distro" && resolved.wslDistro && resolved.wslPath
        ? { distro: resolved.wslDistro, linuxBinary: resolved.wslPath }
        : null,
  })
}

function loadCustomBinaryOverrides(workspaceRoot: string): Record<string, string> {
  const candidates = [
    path.join(workspaceRoot, ".cyberlab", "external-tools.json"),
    path.join(workspaceRoot, "config", "external-tools.json"),
  ]
  for (const file of candidates) {
    if (!existsSync(file)) continue
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as { binaryPaths?: Record<string, string> }
      if (parsed && typeof parsed.binaryPaths === "object" && parsed.binaryPaths !== null) {
        return parsed.binaryPaths
      }
    } catch {
      // Ignore malformed optional override files; never crash control plane startup
    }
  }
  return {}
}

export function inspectExternalToolStatuses(workspaceRoot: string): ExternalToolRuntimeStatus[] {
  const overrides = loadCustomBinaryOverrides(workspaceRoot)
  // Um único probe WSL2 cobre todos os candidatos POSIX de todo o catálogo.
  const allPosix = Array.from(
    new Set(
      BUILTIN_EXTERNAL_TOOL_CATALOG.flatMap((e) => [
        ...(e.posixBinaries ?? e.binaryCandidates),
        ...e.binaryCandidates,
        ...(e.posixKnownPaths ?? []),
      ]).map((n) => n.replace(/\.(exe|cmd|bat)$/i, "")),
    ),
  ).filter(isProbeablePosix)
  if (probeWslEnvironment().available) {
    probeWslBinaries(allPosix)
  }
  return BUILTIN_EXTERNAL_TOOL_CATALOG.map((entry) => {
    const res = resolveExternalBinary(
      workspaceRoot,
      entry.binaryCandidates,
      overrides,
      [...(entry.posixBinaries ?? entry.binaryCandidates), ...(entry.posixKnownPaths ?? [])],
    )
    return {
      toolId: entry.toolId,
      displayName: entry.displayName,
      available: res.resolvedPath !== null,
      resolvedPath: res.resolvedPath,
      sourceLocation: res.sourceLocation,
      licenseSpdx: entry.licenseSpdx,
      integrationMode: entry.integrationMode,
      governedCapabilityId: entry.governedCapabilityId ?? null,
      installHint: entry.installHint,
      installHintWsl: entry.installKaliWsl ?? `wsl -d kali-linux -- sudo apt update && sudo apt install -y ${entry.toolId}`,
      description: entry.description,
      wslDistro: res.wslDistro,
      wslPath: res.wslPath,
    }
  })
}

/**
 * No Windows, `spawn(..., { shell: false })` **rejeita** `.cmd` e `.bat` com EINVAL:
 * só aceita `.com`/`.exe`. Como `expandPlatformNames` procura justamente `.cmd` e
 * `.bat` (é assim que npm/pip/choco instalam o shim de quase toda ferramenta), o
 * produto localizava o binário e depois não conseguia executá-lo — um controle que
 * parece funcionar e na hora de rodar falha.
 *
 * A saída é a mesma do `cross-spawn`: passar por `cmd.exe /d /s /c "<linha>"` com
 * cada parte escapada e `windowsVerbatimArguments`, para o Node não reescapar.
 */
const WINDOWS_NATIVE_EXECUTABLE = /\.(?:com|exe)$/i
/** Metacaracteres do cmd.exe — http://www.robvanderwoude.com/escapechars.php */
const CMD_META_CHARS = /([()\][%!^"`<>&|;, *?])/g

export function escapeCmdCommand(arg: string): string {
  return arg.replace(CMD_META_CHARS, "^$1")
}

/**
 * Escapa um argumento para a linha de comando do cmd.exe.
 * Algoritmo canônico de https://qntm.org/cmd (o mesmo do cross-spawn).
 */
export function escapeCmdArgument(arg: string): string {
  let out = `${arg}`
  // Sequência de barras invertidas antes de aspas: dobra as barras e escapa a aspa.
  out = out.replace(/(?=(\\+?)?)\1"/g, '$1$1\\"')
  // Sequência de barras invertidas no fim (vai preceder a aspa de fechamento).
  out = out.replace(/(?=(\\+?)?)\1$/, "$1$1")
  out = `"${out}"`
  return out.replace(CMD_META_CHARS, "^$1")
}

export function resolveSpawnTarget(
  command: string,
  args: readonly string[],
  platform: NodeJS.Platform = process.platform,
): { file: string; args: string[]; windowsVerbatimArguments: boolean } {
  if (platform !== "win32") return { file: command, args: [...args], windowsVerbatimArguments: false }
  // Normalizar separadores: caminho com "/" falha com ENOENT no cmd.
  const normalized = path.normalize(command)
  if (WINDOWS_NATIVE_EXECUTABLE.test(normalized)) {
    return { file: normalized, args: [...args], windowsVerbatimArguments: false }
  }
  const shellCommand = [escapeCmdCommand(normalized), ...args.map((a) => escapeCmdArgument(a))].join(" ")
  return {
    file: process.env.comspec ?? "cmd.exe",
    args: ["/d", "/s", "/c", `"${shellCommand}"`],
    windowsVerbatimArguments: true,
  }
}

export async function runSafeChildProcess(params: {
  /** Executável (Windows/Linux) ou `wsl.exe` quando o alvo vive dentro do WSL2. */
  command: string
  args: readonly string[]
  cwd: string
  signal: AbortSignal
  maxOutputBytes?: number
  onStdoutChunk?: (chunk: string) => void
  onStderrChunk?: (chunk: string) => void
}): Promise<{ exitCode: number; stdout: string; stderr: string; truncated: boolean }> {
  const maxBytes = params.maxOutputBytes ?? 512 * 1024

  return new Promise((resolve, reject) => {
    if (params.signal.aborted) {
      reject(new Error("External process aborted before launch"))
      return
    }

    const target = resolveSpawnTarget(params.command, params.args)
    const child = spawn(target.file, target.args, {
      cwd: params.cwd,
      shell: false,
      windowsVerbatimArguments: target.windowsVerbatimArguments,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
        HOME: process.env.HOME ?? process.env.USERPROFILE ?? params.cwd,
        ...(process.env.SYSTEMROOT ? { SYSTEMROOT: process.env.SYSTEMROOT } : {}),
        ...(process.env.USERPROFILE ? { USERPROFILE: process.env.USERPROFILE } : {}),
        ...(process.env.LOCALAPPDATA ? { LOCALAPPDATA: process.env.LOCALAPPDATA } : {}),
        ...(process.env.APPDATA ? { APPDATA: process.env.APPDATA } : {}),
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
      },
    })

    let stdoutAcc = ""
    let stderrAcc = ""
    let truncated = false
    let killTimer: ReturnType<typeof setTimeout> | undefined

    const onAbort = () => {
      child.kill("SIGTERM")
      killTimer = setTimeout(() => {
        try {
          child.kill("SIGKILL")
        } catch {
          // Process already exited
        }
      }, 400)
    }

    params.signal.addEventListener("abort", onAbort, { once: true })

    child.stdout.on("data", (buf: Buffer) => {
      const text = buf.toString("utf8")
      params.onStdoutChunk?.(text)
      if (Buffer.byteLength(stdoutAcc, "utf8") < maxBytes) {
        stdoutAcc += text
        const capped = capOutputBytes(stdoutAcc, maxBytes)
        stdoutAcc = capped.text
        if (capped.truncated) truncated = true
      } else {
        truncated = true
      }
    })

    child.stderr.on("data", (buf: Buffer) => {
      const text = buf.toString("utf8")
      params.onStderrChunk?.(text)
      if (Buffer.byteLength(stderrAcc, "utf8") < maxBytes) {
        stderrAcc += text
        const capped = capOutputBytes(stderrAcc, maxBytes)
        stderrAcc = capped.text
        if (capped.truncated) truncated = true
      } else {
        truncated = true
      }
    })

    child.once("error", (err: Error) => {
      if (killTimer) clearTimeout(killTimer)
      params.signal.removeEventListener("abort", onAbort)
      reject(err)
    })

    child.once("close", (code) => {
      if (killTimer) clearTimeout(killTimer)
      params.signal.removeEventListener("abort", onAbort)
      if (params.signal.aborted) {
        reject(new Error("External process terminated via CyberLab AbortSignal"))
        return
      }
      resolve({
        exitCode: code ?? 1,
        stdout: stdoutAcc,
        stderr: stderrAcc,
        truncated,
      })
    })
  })
}

// =============================================================================
// Governed External Tool Capabilities (Nmap, Nuclei, ffuf, tshark)
// =============================================================================

export const EXTERNAL_NMAP_INPUT_SCHEMA_ID = "cyberlab.external.nmap.input.v1"
export const ExternalNmapInputSchema = Schema.Struct({
  host: Schema.String.check(
    Schema.isMinLength(1),
    Schema.isMaxLength(253),
    Schema.isPattern(/^[a-zA-Z0-9._:-]+$/),
  ),
  ports: Schema.optionalKey(
    Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(64), Schema.isPattern(/^[0-9,-]+$/)),
  ),
  serviceVersion: Schema.optionalKey(Schema.Boolean),
})

export const ExternalNmapCapability: CapabilityDefinition = {
  id: "external.nmap-service-probe",
  version: "1.0.0",
  title: "External Nmap Controlled Port & Service Probe (Plugin Bridge)",
  description:
    "Controls an externally installed nmap binary from CyberLab OS with shell=false, strict port-range validation, ScopeController target authorization, real-time AbortSignal cancellation, and SHA-256 evidence capture.",
  inputSchemaId: EXTERNAL_NMAP_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["ip"],
  executorId: "external-nmap-executor",
  skillIds: ["network-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export class ExternalNmapExecutor implements CyberLabExecutor {
  readonly id = "external-nmap-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(root, ["nmap"], loadCustomBinaryOverrides(root))
    if (!resolved.resolvedPath) {
      return { available: false, reason: "External binary 'nmap' not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl)" }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(ExternalNmapInputSchema)(input)
      if (decoded.host.startsWith("-")) {
        return { valid: false, errors: ["host must not start with '-' (option injection blocked)"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalNmapInputSchema)(execInput.input)
    if (params.host.startsWith("-")) {
      return { status: "failed", evidenceIds: [], summary: "Blocked leading dash in host", exitCode: 2 }
    }
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["nmap"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["nmap"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "nmap binary not installed", exitCode: 127 }
    }

    const args = ["-Pn", "-T3", "--open"]
    if (params.serviceVersion) args.push("-sV", "--version-light")
    args.push("-p", params.ports ?? "80,443,8080,8443", "--", params.host)

    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const combined = [`# External Binary: ${resolved.resolvedPath}`, `# Args: ${JSON.stringify(args)}`, "", out.stdout, out.stderr]
      .filter(Boolean)
      .join("\n")

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "network_observation",
        title: `External Nmap Probe ${params.host} (exit=${out.exitCode})`,
        rawText: combined,
        mediaType: "text/plain; charset=utf-8",
        toolId: "external:nmap",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["external-plugin", "nmap"],
      }),
    )

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `External nmap exited with code ${out.exitCode} on ${params.host}.`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_NUCLEI_INPUT_SCHEMA_ID = "cyberlab.external.nuclei.input.v1"
export const ExternalNucleiInputSchema = Schema.Struct({
  url: Schema.String.check(
    Schema.isMinLength(8),
    Schema.isMaxLength(2048),
    Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
  ),
  tags: Schema.optionalKey(
    Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(64), Schema.isPattern(/^[a-zA-Z0-9,_-]+$/)),
  ),
  rateLimit: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(50))),
})

export const ExternalNucleiCapability: CapabilityDefinition = {
  id: "external.nuclei-template-scan",
  version: "1.0.0",
  title: "External Nuclei Template Scanner (Controlled Process Bridge)",
  description:
    "Controls an external nuclei binary (.cyberlab/bin/nuclei or PATH) from CyberLab OS with strict rate-limiting, ScopeController URL authorization, real-time AbortSignal cancellation, and SHA-256 evidence persistence.",
  inputSchemaId: EXTERNAL_NUCLEI_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["url_origin"],
  executorId: "external-nuclei-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export class ExternalNucleiExecutor implements CyberLabExecutor {
  readonly id = "external-nuclei-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(root, ["nuclei"], loadCustomBinaryOverrides(root))
    if (!resolved.resolvedPath) {
      return {
        available: false,
        reason: "External binary 'nuclei' not found (run ./script/bootstrap-local-tools.sh)",
      }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(ExternalNucleiInputSchema)(input)
      const u = new URL(decoded.url)
      if (u.username || u.password) return { valid: false, errors: ["Embedded URL credentials prohibited"] }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalNucleiInputSchema)(execInput.input)
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["nuclei"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["nuclei"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "nuclei binary not installed", exitCode: 127 }
    }

    const args = ["-u", params.url, "-rl", String(params.rateLimit ?? 10), "-nc", "-silent", "-jsonl"]
    if (params.tags) args.push("-tags", params.tags)

    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "stdout",
        title: `External Nuclei Scan ${new URL(params.url).host} (exit=${out.exitCode})`,
        rawText: out.stdout || out.stderr || "(no template matches emitted)",
        mediaType: "text/plain; charset=utf-8",
        toolId: "external:nuclei",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["external-plugin", "nuclei"],
      }),
    )

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `External nuclei scan completed on ${params.url} (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_FFUF_INPUT_SCHEMA_ID = "cyberlab.external.ffuf.input.v1"
export const ExternalFfufInputSchema = Schema.Struct({
  baseUrl: Schema.String.check(
    Schema.isMinLength(8),
    Schema.isMaxLength(2048),
    Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
  ),
  wordlistPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  rateLimit: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(25))),
})

export const ExternalFfufCapability: CapabilityDefinition = {
  id: "external.ffuf-endpoint-probe",
  version: "1.0.0",
  title: "External ffuf Rate-Limited Endpoint Probe (Controlled Process Bridge)",
  description:
    "Controls an external ffuf binary (.cyberlab/bin/ffuf or PATH) with mandatory human approval for moderate risk, strict rate-limiting, workspace wordlist confinement, ScopeController URL validation, and SHA-256 evidence capture.",
  inputSchemaId: EXTERNAL_FFUF_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["url_origin", "workspace_path"],
  executorId: "external-ffuf-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export class ExternalFfufExecutor implements CyberLabExecutor {
  readonly id = "external-ffuf-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(root, ["ffuf"], loadCustomBinaryOverrides(root))
    if (!resolved.resolvedPath) {
      return {
        available: false,
        reason: "External binary 'ffuf' not found (run ./script/bootstrap-local-tools.sh)",
      }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(ExternalFfufInputSchema)(input)
      if (decoded.wordlistPath.includes("\0") || decoded.wordlistPath.startsWith("-")) {
        return { valid: false, errors: ["Invalid wordlistPath"] }
      }
      const u = new URL(decoded.baseUrl)
      if (u.username || u.password) return { valid: false, errors: ["Embedded URL credentials prohibited"] }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalFfufInputSchema)(execInput.input)
    if (!isPathInsideRoot(params.wordlistPath, ctx.workspaceRoot)) {
      return { status: "failed", evidenceIds: [], summary: "wordlistPath escapes workspaceRoot", exitCode: 2 }
    }
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["ffuf"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["ffuf"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "ffuf binary not installed", exitCode: 127 }
    }

    const cleanOrigin = params.baseUrl.replace(/\/+$/, "")
    const fuzzUrl = cleanOrigin.includes("FUZZ") ? cleanOrigin : `${cleanOrigin}/FUZZ`
    const fullWordlist = path.resolve(ctx.workspaceRoot, params.wordlistPath)
    const args = ["-u", fuzzUrl, "-w", fullWordlist, "-rate", String(params.rateLimit ?? 10), "-s"]

    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "stdout",
        title: `External ffuf Endpoint Probe ${new URL(params.baseUrl).host}`,
        rawText: out.stdout || out.stderr || "(no endpoints discovered)",
        mediaType: "text/plain; charset=utf-8",
        toolId: "external:ffuf",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["external-plugin", "ffuf"],
      }),
    )

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `External ffuf probe finished on ${params.baseUrl} (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_TSHARK_INPUT_SCHEMA_ID = "cyberlab.external.tshark.input.v1"
export const ExternalTsharkInputSchema = Schema.Struct({
  pcapPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  maxPackets: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(5_000))),
})

export const ExternalTsharkCapability: CapabilityDefinition = {
  id: "external.tshark-pcap-summary",
  version: "1.0.0",
  title: "External Wireshark tshark Deep Dissector (Plugin Bridge)",
  description:
    "Controls an externally installed tshark binary on an in-workspace .pcap file (shell=false, read-only -r mode, no live interface capture) and stores SHA-256 evidence in CyberLab OS.",
  inputSchemaId: EXTERNAL_TSHARK_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "external-tshark-executor",
  skillIds: ["network-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export class ExternalTsharkExecutor implements CyberLabExecutor {
  readonly id = "external-tshark-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(root, ["tshark"], loadCustomBinaryOverrides(root))
    if (!resolved.resolvedPath) {
      return { available: false, reason: "External binary 'tshark' not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl)" }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(ExternalTsharkInputSchema)(input)
      if (decoded.pcapPath.includes("\0") || decoded.pcapPath.startsWith("-")) {
        return { valid: false, errors: ["Invalid pcapPath"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalTsharkInputSchema)(execInput.input)
    if (!isPathInsideRoot(params.pcapPath, ctx.workspaceRoot)) {
      return { status: "failed", evidenceIds: [], summary: "pcapPath escapes workspaceRoot", exitCode: 2 }
    }
    const fullPcap = path.resolve(ctx.workspaceRoot, params.pcapPath)
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["tshark"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["tshark"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "tshark binary not installed", exitCode: 127 }
    }

    const args = ["-n", "-c", String(params.maxPackets ?? 250), "-r", fullPcap]
    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "network_observation",
        title: `External tshark Dissection ${path.basename(params.pcapPath)}`,
        rawText: out.stdout || out.stderr,
        mediaType: "text/plain; charset=utf-8",
        toolId: "external:tshark",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["external-plugin", "tshark"],
      }),
    )

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `External tshark dissected ${params.pcapPath} (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_DALFOX_INPUT_SCHEMA_ID = "cyberlab.external.dalfox.input.v1"
export const ExternalDalfoxInputSchema = Schema.Struct({
  url: Schema.String.check(
    Schema.isMinLength(8),
    Schema.isMaxLength(2048),
    Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
  ),
  paramName: Schema.optionalKey(
    Schema.String.check(Schema.isMaxLength(64), Schema.isPattern(/^[a-zA-Z0-9_-]*$/)),
  ),
})

export const ExternalDalfoxCapability: CapabilityDefinition = {
  id: "external.dalfox-param-scan",
  version: "1.0.0",
  title: "External Dalfox Parameter Reflection Scanner (MIT Bridge)",
  description:
    "Controls an externally installed dalfox binary (MIT) against an authorized in-scope URL with shell=false, ScopeController verification, and SHA-256 evidence capture.",
  inputSchemaId: EXTERNAL_DALFOX_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["url_origin"],
  executorId: "external-dalfox-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export class ExternalDalfoxExecutor implements CyberLabExecutor {
  readonly id = "external-dalfox-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(root, ["dalfox"], loadCustomBinaryOverrides(root))
    if (!resolved.resolvedPath) {
      return { available: false, reason: "External binary 'dalfox' not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl)" }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      Schema.decodeUnknownSync(ExternalDalfoxInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalDalfoxInputSchema)(execInput.input)
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["dalfox"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["dalfox"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "dalfox binary not installed", exitCode: 127 }
    }

    const args = ["url", params.url, "--silence", "--no-color", "--format", "json"]
    if (params.paramName && params.paramName.trim()) {
      args.push("-p", params.paramName.trim())
    }

    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const redacted = redactSensitiveContent(out.stdout || out.stderr || "(no dalfox findings)")
    const evId = await ctx.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "http_exchange",
        title: `External Dalfox Scan ${new URL(params.url).host}`,
        rawText: redacted.text,
        mediaType: "text/plain; charset=utf-8",
        toolId: "external:dalfox",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["external-plugin", "dalfox"],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `External dalfox scan completed on ${params.url} (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_GHIDRA_INPUT_SCHEMA_ID = "cyberlab.external.ghidra.input.v1"
export const ExternalGhidraInputSchema = Schema.Struct({
  binaryPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  processor: Schema.optionalKey(
    Schema.String.check(Schema.isMaxLength(64), Schema.isPattern(/^[a-zA-Z0-9:._-]*$/)),
  ),
})

export const ExternalGhidraCapability: CapabilityDefinition = {
  id: "external.ghidra-decompile",
  version: "1.0.0",
  title: "External Ghidra AnalyzeHeadless Decompiler Bridge (Apache-2.0)",
  description:
    "Runs NSA Ghidra analyzeHeadless (Apache-2.0) in read-only temporary project mode on an in-workspace binary and records SHA-256 analysis evidence.",
  inputSchemaId: EXTERNAL_GHIDRA_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "external-ghidra-executor",
  skillIds: ["reverse-engineering", "evidence-review"],
  licenseRefs: ["Apache-2.0"],
  enabled: true,
}

export class ExternalGhidraExecutor implements CyberLabExecutor {
  readonly id = "external-ghidra-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(
      root,
      ["analyzeHeadless", "analyzeHeadless.bat", "ghidra-analyzeHeadless"],
      loadCustomBinaryOverrides(root),
    )
    if (!resolved.resolvedPath) {
      return { available: false, reason: "Ghidra 'analyzeHeadless' not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl)" }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const d = Schema.decodeUnknownSync(ExternalGhidraInputSchema)(input)
      if (d.binaryPath.includes("\0") || d.binaryPath.startsWith("-")) {
        return { valid: false, errors: ["Invalid binaryPath"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalGhidraInputSchema)(execInput.input)
    if (!isPathInsideRoot(params.binaryPath, ctx.workspaceRoot)) {
      return { status: "failed", evidenceIds: [], summary: "binaryPath escapes workspaceRoot", exitCode: 2 }
    }
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["analyzeHeadless", "analyzeHeadless.bat", "ghidra-analyzeHeadless"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["analyzeHeadless", "analyzeHeadless.bat", "ghidra-analyzeHeadless"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "analyzeHeadless binary not installed", exitCode: 127 }
    }

    const workDir = path.join(ctx.workspaceRoot, ".cyberlab", "artifacts", "ghidra-tmp")
    mkdirSync(workDir, { recursive: true })
    const fullBin = path.resolve(ctx.workspaceRoot, params.binaryPath)
    const args = [workDir, `CyberLab_${ctx.executionId.slice(0, 8)}`, "-import", fullBin, "-deleteProject"]
    if (params.processor && params.processor.trim()) {
      args.push("-processor", params.processor.trim())
    }

    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "stdout",
        title: `Ghidra Headless Analysis ${path.basename(params.binaryPath)}`,
        rawText: [out.stdout, out.stderr].filter(Boolean).join("\n") || "(completed with empty stdout)",
        mediaType: "text/plain; charset=utf-8",
        toolId: "external:ghidra-headless",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["external-plugin", "ghidra"],
      }),
    )

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `Ghidra analyzeHeadless finished on ${params.binaryPath} (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_JADX_INPUT_SCHEMA_ID = "cyberlab.external.jadx.input.v1"
export const ExternalJadxInputSchema = Schema.Struct({
  artifactPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  deobfuscate: Schema.optionalKey(Schema.Boolean),
})

export const ExternalJadxCapability: CapabilityDefinition = {
  id: "external.jadx-decompile",
  version: "1.0.0",
  title: "External JADX Android Dex-to-Java Decompiler (Apache-2.0 Bridge)",
  description:
    "Decompiles an in-workspace Android .apk or .dex file into Java source inside .cyberlab/artifacts/jadx/ using JADX (Apache-2.0) and stores SHA-256 custody.",
  inputSchemaId: EXTERNAL_JADX_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "external-jadx-executor",
  skillIds: ["mobile-forensics", "reverse-engineering", "evidence-review"],
  licenseRefs: ["Apache-2.0"],
  enabled: true,
}

export class ExternalJadxExecutor implements CyberLabExecutor {
  readonly id = "external-jadx-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(root, ["jadx", "jadx.bat"], loadCustomBinaryOverrides(root))
    if (!resolved.resolvedPath) {
      return { available: false, reason: "JADX ('jadx') not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl)" }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const d = Schema.decodeUnknownSync(ExternalJadxInputSchema)(input)
      if (d.artifactPath.includes("\0") || d.artifactPath.startsWith("-")) {
        return { valid: false, errors: ["Invalid artifactPath"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalJadxInputSchema)(execInput.input)
    if (!isPathInsideRoot(params.artifactPath, ctx.workspaceRoot)) {
      return { status: "failed", evidenceIds: [], summary: "artifactPath escapes workspaceRoot", exitCode: 2 }
    }
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["jadx", "jadx.bat"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["jadx", "jadx.bat"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "jadx binary not installed", exitCode: 127 }
    }

    const baseSafe = path.basename(params.artifactPath).replace(/[^a-zA-Z0-9._-]/g, "_")
    const outDirRel = path.join(".cyberlab", "artifacts", "jadx", baseSafe)
    const outDirFull = path.resolve(ctx.workspaceRoot, outDirRel)
    mkdirSync(outDirFull, { recursive: true })

    const fullArtifact = path.resolve(ctx.workspaceRoot, params.artifactPath)
    const args = ["-d", outDirFull, ...(params.deobfuscate ? ["--deobf"] : []), fullArtifact]

    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const summaryPayload = {
      artifactPath: params.artifactPath,
      decompiledOutputDirectory: outDirRel.replace(/\\/g, "/"),
      exitCode: out.exitCode,
      stdout: out.stdout,
      stderr: out.stderr,
    }

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "json",
        title: `JADX Decompilation ${path.basename(params.artifactPath)}`,
        rawText: JSON.stringify(summaryPayload, null, 2),
        mediaType: "application/json",
        toolId: "external:jadx",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["external-plugin", "jadx", "android-decompile"],
      }),
    )

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `JADX decompiled ${params.artifactPath} -> ${outDirRel.replace(/\\/g, "/")} (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_TRIVY_INPUT_SCHEMA_ID = "cyberlab.external.trivy.input.v1"
export const ExternalTrivyInputSchema = Schema.Struct({
  targetPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  scanners: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
})

export const ExternalTrivyCapability: CapabilityDefinition = {
  id: "external.trivy-scan",
  version: "1.0.0",
  title: "External Aqua Trivy SCA, Secret & IaC Scanner (Apache-2.0 Bridge)",
  description:
    "Executes Aqua Trivy ('trivy fs', Apache-2.0) strictly inside workspace paths for dependency CVE, Dockerfile/Kubernetes/Terraform misconfiguration, and secret scanning with SHA-256 custody.",
  inputSchemaId: EXTERNAL_TRIVY_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "external-trivy-executor",
  skillIds: ["code-review", "evidence-review"],
  licenseRefs: ["Apache-2.0"],
  enabled: true,
}

export class ExternalTrivyExecutor implements CyberLabExecutor {
  readonly id = "external-trivy-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(root, ["trivy"], loadCustomBinaryOverrides(root))
    if (!resolved.resolvedPath) {
      return { available: false, reason: "Trivy ('trivy') not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl)" }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const d = Schema.decodeUnknownSync(ExternalTrivyInputSchema)(input)
      if (d.targetPath.includes("\0") || d.targetPath.startsWith("-")) {
        return { valid: false, errors: ["Invalid targetPath"] }
      }
      if (d.scanners && !/^[a-z,]+$/.test(d.scanners)) {
        return { valid: false, errors: ["scanners must contain comma-separated lowercase names (e.g. vuln,misconfig)"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalTrivyInputSchema)(execInput.input)
    if (!isPathInsideRoot(params.targetPath, ctx.workspaceRoot)) {
      return { status: "failed", evidenceIds: [], summary: "targetPath escapes workspaceRoot", exitCode: 2 }
    }
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["trivy"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["trivy"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "trivy binary not installed", exitCode: 127 }
    }

    const fullTarget = path.resolve(ctx.workspaceRoot, params.targetPath)
    const scanners = params.scanners?.trim() || "vuln,misconfig"
    const args = ["fs", "--scanners", scanners, "--format", "json", "--quiet", fullTarget]
    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "json",
        title: `External Trivy Scan ${params.targetPath} (${scanners})`,
        rawText: out.stdout || out.stderr || "{}",
        mediaType: "application/json",
        toolId: "external:trivy",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 768 * 1024,
        labels: ["external-plugin", "trivy", "sca", "iac"],
      }),
    )

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `External Trivy scan finished on ${params.targetPath} (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_YARAX_INPUT_SCHEMA_ID = "cyberlab.external.yarax.input.v1"
export const ExternalYaraXInputSchema = Schema.Struct({
  rulesPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  targetPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
})

export const ExternalYaraXCapability: CapabilityDefinition = {
  id: "external.yarax-scan",
  version: "1.0.0",
  title: "External YARA-X / YARA Indicator Scanner (BSD-3-Clause Bridge)",
  description:
    "Executes VirusTotal YARA-X ('yr') or classic 'yara' CLI (BSD-3-Clause) offline against in-workspace rule and target paths with SHA-256 custody.",
  inputSchemaId: EXTERNAL_YARAX_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "external-yarax-executor",
  skillIds: ["reverse-engineering", "mobile-forensics", "evidence-review"],
  licenseRefs: ["BSD-3-Clause"],
  enabled: true,
}

export class ExternalYaraXExecutor implements CyberLabExecutor {
  readonly id = "external-yarax-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(root, ["yr", "yara64", "yara"], loadCustomBinaryOverrides(root))
    if (!resolved.resolvedPath) {
      return { available: false, reason: "YARA-X ('yr') or 'yara' not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl)" }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const d = Schema.decodeUnknownSync(ExternalYaraXInputSchema)(input)
      if (
        d.rulesPath.includes("\0") ||
        d.rulesPath.startsWith("-") ||
        d.targetPath.includes("\0") ||
        d.targetPath.startsWith("-")
      ) {
        return { valid: false, errors: ["Invalid rulesPath or targetPath"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalYaraXInputSchema)(execInput.input)
    if (
      !isPathInsideRoot(params.rulesPath, ctx.workspaceRoot) ||
      !isPathInsideRoot(params.targetPath, ctx.workspaceRoot)
    ) {
      return { status: "failed", evidenceIds: [], summary: "rulesPath or targetPath escapes workspaceRoot", exitCode: 2 }
    }
    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["yr", "yara64", "yara"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["yr", "yara64", "yara"]),
    )
    if (!resolved.resolvedPath) {
      return { status: "failed", evidenceIds: [], summary: "yr / yara binary not installed", exitCode: 127 }
    }

    const fullRules = path.resolve(ctx.workspaceRoot, params.rulesPath)
    const fullTarget = path.resolve(ctx.workspaceRoot, params.targetPath)
    const isYr = /^yr(\.exe)?$/i.test(path.basename(resolved.resolvedPath))
    const args = isYr ? ["scan", fullRules, fullTarget] : ["-r", fullRules, fullTarget]

    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "stdout",
        title: `External YARA-X Scan ${path.basename(params.targetPath)}`,
        rawText: [out.stdout, out.stderr].filter(Boolean).join("\n") || "(0 rule matches)",
        mediaType: "text/plain; charset=utf-8",
        toolId: "external:yarax",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["external-plugin", "yarax"],
      }),
    )

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `External YARA-X scan finished on ${params.targetPath} (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

export const EXTERNAL_KEYHUNTER_INPUT_SCHEMA_ID = "cyberlab.external.keyhunter.input.v1"
export const ExternalKeyHunterInputSchema = Schema.Struct({
  subcommand: Schema.optionalKey(Schema.Literals(["scan", "verify", "patterns"])),
  provider: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
  query: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  configPath: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  inputFindingsPath: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  outputFormat: Schema.optionalKey(Schema.Literals(["json", "table", "csv"])),
  verifiedOnly: Schema.optionalKey(Schema.Boolean),
  verbose: Schema.optionalKey(Schema.Boolean),
})

export const ExternalKeyHunterCapability: CapabilityDefinition = {
  id: "external.keyhunter-cli",
  version: "1.0.0",
  title: "External KeyHunter Rust CLI Bridge (fadidevv/keyhunter — MIT)",
  description:
    "Executes the upstream Rust KeyHunter CLI ('cargo install github-keyhunter', MIT) via structured non-shell arguments (scan / verify / patterns) with automatic secret redaction and SHA-256 chain of custody.",
  inputSchemaId: EXTERNAL_KEYHUNTER_INPUT_SCHEMA_ID,
  outputSchemaId: "cyberlab.external.output.v1",
  risk: "low",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: [],
  executorId: "external-keyhunter-executor",
  skillIds: ["code-review", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export class ExternalKeyHunterExecutor implements CyberLabExecutor {
  readonly id = "external-keyhunter-executor"
  readonly version = "1.0.0"

  constructor(private readonly getWorkspaceRoot: () => string) {}

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    const root = this.getWorkspaceRoot()
    const resolved = resolveExternalBinary(
      root,
      ["keyhunter", "github-keyhunter"],
      loadCustomBinaryOverrides(root),
    )
    if (!resolved.resolvedPath) {
      return {
        available: false,
        reason: "KeyHunter CLI ('keyhunter') not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl) (install via 'cargo install github-keyhunter')",
      }
    }
    return { available: true, version: resolved.resolvedPath }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const d = Schema.decodeUnknownSync(ExternalKeyHunterInputSchema)(input)
      for (const field of [d.provider, d.query, d.configPath, d.inputFindingsPath]) {
        if (field && (field.includes("\0") || field.trim().startsWith("-"))) {
          return { valid: false, errors: ["Arguments must not start with '-' or contain null bytes"] }
        }
      }
      if ((d.subcommand ?? "scan") === "verify" && !d.inputFindingsPath?.trim()) {
        return { valid: false, errors: ["inputFindingsPath is required when subcommand is 'verify'"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(ExternalKeyHunterInputSchema)(execInput.input)
    if (params.configPath && !isPathInsideRoot(params.configPath, ctx.workspaceRoot)) {
      return { status: "failed", evidenceIds: [], summary: "configPath escapes workspaceRoot", exitCode: 2 }
    }
    if (params.inputFindingsPath && !isPathInsideRoot(params.inputFindingsPath, ctx.workspaceRoot)) {
      return { status: "failed", evidenceIds: [], summary: "inputFindingsPath escapes workspaceRoot", exitCode: 2 }
    }

    const resolved = resolveExternalBinary(
      ctx.workspaceRoot,
      ["keyhunter", "github-keyhunter"],
      loadCustomBinaryOverrides(ctx.workspaceRoot),
      resolvePosixCandidates(["keyhunter", "github-keyhunter"]),
    )
    if (!resolved.resolvedPath) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: "keyhunter binary not installed (run 'cargo install github-keyhunter' or use the built-in MIT Key Hunter engine)",
        exitCode: 127,
      }
    }

    const sub = params.subcommand ?? "scan"
    const args: string[] = [sub]
    if (sub === "scan") {
      if (params.provider?.trim()) {
        args.push("-p", params.provider.trim())
      }
      if (params.query?.trim()) {
        args.push("-q", params.query.trim())
      }
      if (params.configPath?.trim()) {
        args.push("-c", path.resolve(ctx.workspaceRoot, params.configPath.trim()))
      }
      args.push("-o", params.outputFormat ?? "json")
      if (params.verifiedOnly) {
        args.push("-V")
      }
      if (params.verbose) {
        args.push("-v")
      }
    } else if (sub === "verify") {
      args.push("-i", path.resolve(ctx.workspaceRoot, params.inputFindingsPath!.trim()))
      if (params.verbose) args.push("-v")
    }

    const out = await runExternalBinary({
      resolved,
      args,
      cwd: ctx.workspaceRoot,
      signal: ctx.signal,
    })

    const combinedRaw = [out.stdout, out.stderr].filter(Boolean).join("\n") || "(empty output)"
    const redacted = redactSensitiveContent(combinedRaw)
    const isJson = sub === "scan" && (params.outputFormat ?? "json") === "json"

    const evId = await ctx.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: isJson ? "json" : "stdout",
        title: `External KeyHunter CLI (${sub}${params.provider ? ` -p ${params.provider}` : ""})`,
        rawText: redacted.text,
        mediaType: isJson ? "application/json" : "text/plain; charset=utf-8",
        toolId: "external:keyhunter",
        toolVersion: "external",
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 768 * 1024,
        labels: ["external-plugin", "keyhunter", "api-keys"],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: out.exitCode === 0 ? "succeeded" : "failed",
      evidenceIds: [evId],
      summary: `External KeyHunter CLI (${sub}) completed (exit=${out.exitCode}).`,
      exitCode: out.exitCode,
    }
  }
}

// =============================================================================
// Unified External Manual Action & Inbox Control Plane
// =============================================================================

export interface IngestExternalActionInput {
  toolId: string
  title?: string
  origin?: ExternalOriginKind
  target?: string
  commandSummary?: string
  rawOutput: string
  mediaType?: string
  kind?: EvidenceKind
  exitCode?: number
  actor?: string
}

export interface IngestExternalActionResult {
  evidenceId: string
  sha256: string
  redactionStatus: "not_checked" | "checked" | "redacted"
  scopeAuditStatus: "in_scope" | "out_of_scope_flagged" | "no_target_declared"
  scopeReason: string
  origin: ExternalOriginKind
  toolId: string
}

export interface InboxSyncResult {
  scannedCount: number
  ingested: Array<{
    fileName: string
    archivedTo: string
    evidenceId: string
    sha256: string
  }>
  skippedReasons: string[]
}

export class ExternalControlPlane {
  readonly inboxDir: string
  readonly processedDir: string

  constructor(
    private readonly options: {
      projectId: string
      workspaceRoot: string
      scopes: ScopeController
      evidenceStore: EvidenceStore
    },
  ) {
    this.inboxDir = path.join(options.workspaceRoot, ".cyberlab", "inbox")
    this.processedDir = path.join(this.inboxDir, "processed")
  }

  listTools(): ExternalToolRuntimeStatus[] {
    return inspectExternalToolStatuses(this.options.workspaceRoot)
  }

  countPendingInboxFiles(): number {
    if (!existsSync(this.inboxDir)) return 0
    try {
      return readdirSync(this.inboxDir).filter((name) => {
        if (name === "processed" || name.startsWith(".")) return false
        const full = path.join(this.inboxDir, name)
        const lst = lstatSync(full, { throwIfNoEntry: false })
        return Boolean(lst && lst.isFile() && !lst.isSymbolicLink())
      }).length
    } catch {
      return 0
    }
  }

  /**
   * Centralizes any action executed outside CyberLab OS (manual OpenTRAP/Burp/Wireshark/Nmap session,
   * MCP server response, or supervised CLI wrapper) into the single project EvidenceStore with explicit
   * ScopeController verification, secret redaction, and SHA-256 chain of custody.
   */
  ingestExternalAction(input: IngestExternalActionInput): IngestExternalActionResult {
    const cleanToolId = input.toolId.trim().replace(/[^a-zA-Z0-9._:-]/g, "-") || "external-tool"
    const origin: ExternalOriginKind = input.origin ?? "manual_external"

    let scopeAuditStatus: IngestExternalActionResult["scopeAuditStatus"] = "no_target_declared"
    let scopeReason = "No explicit target attached to external action"

    if (input.target && input.target.trim().length > 0) {
      const trimmedTarget = input.target.trim()
      const isUrl = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmedTarget)
      const existsInWorkspace =
        !isUrl &&
        isPathInsideRoot(trimmedTarget, this.options.workspaceRoot) &&
        existsSync(path.resolve(this.options.workspaceRoot, trimmedTarget))
      const looksLikePath =
        existsInWorkspace ||
        trimmedTarget.startsWith("./") ||
        trimmedTarget.startsWith("../") ||
        trimmedTarget.startsWith("/") ||
        /\.(pcap|apk|ipa|ab|elf|exe|dll|bin|json|xml|txt|log)$/i.test(trimmedTarget)

      const extracted = extractTargetsFromInput(
        looksLikePath ? { path: trimmedTarget } : { target: trimmedTarget },
      )
      const check = this.options.scopes.verifyTargets(this.options.projectId, extracted)
      scopeAuditStatus = check.allowed ? "in_scope" : "out_of_scope_flagged"
      scopeReason = check.reason
    }

    const headerLines = [
      `# CyberLab Unified External Action Record`,
      `# Tool: ${cleanToolId} | Origin: ${origin}`,
      ...(input.target ? [`# Target: ${input.target} (Scope Audit: ${scopeAuditStatus} — ${scopeReason})`] : []),
      ...(input.commandSummary ? [`# Command/Action: ${input.commandSummary}`] : []),
      ...(input.exitCode !== undefined ? [`# Exit Code: ${input.exitCode}`] : []),
      "",
      input.rawOutput,
    ].join("\n")

    const executionId = `ext-${crypto.randomUUID()}`
    const redacted = redactSensitiveContent(headerLines)
    const draft = {
      ...normalizeRawOutputDraft({
        kind: input.kind ?? "stdout",
        title:
          input.title?.trim() ||
          `External Action [${cleanToolId}]${input.target ? ` -> ${input.target}` : ""} (${scopeAuditStatus})`,
        rawText: redacted.text,
        mediaType: input.mediaType ?? "text/plain; charset=utf-8",
        toolId: `external:${cleanToolId}`,
        toolVersion: "external",
        executorId: `external-control:${origin}`,
        executionId,
        maxOutputBytes: 1024 * 1024,
        labels: ["external-control", origin, scopeAuditStatus, cleanToolId],
      }),
      redactionApplied: redacted.redacted,
    }

    const stored = this.options.evidenceStore.storeEvidence(this.options.projectId, draft, {
      actor: input.actor ?? `operator:${origin}`,
    })

    return {
      evidenceId: stored.evidenceId,
      sha256: stored.integrity.sha256,
      redactionStatus: stored.redactionStatus,
      scopeAuditStatus,
      scopeReason,
      origin,
      toolId: cleanToolId,
    }
  }

  /**
   * Ingests all files dropped into .cyberlab/inbox/ (e.g. exported from OpenTRAP, Burp, Nmap, Nuclei,
   * Wireshark, or Ghidra) into the unified EvidenceStore and moves them to .cyberlab/inbox/processed/.
   */
  syncInbox(actor = "operator:inbox-sync"): InboxSyncResult {
    mkdirSync(this.processedDir, { recursive: true })
    const entries = readdirSync(this.inboxDir).sort()

    const ingested: InboxSyncResult["ingested"] = []
    const skippedReasons: string[] = []
    let scannedCount = 0

    for (const name of entries) {
      if (name === "processed" || name.startsWith(".")) continue
      scannedCount++
      const fullPath = path.join(this.inboxDir, name)
      const lst = lstatSync(fullPath, { throwIfNoEntry: false })
      if (!lst) continue

      if (lst.isSymbolicLink()) {
        skippedReasons.push(`${name}: skipped symbolic link for workspace confinement safety`)
        continue
      }
      if (!lst.isFile()) {
        skippedReasons.push(`${name}: skipped non-regular file`)
        continue
      }
      if (lst.size > 16 * 1024 * 1024) {
        skippedReasons.push(`${name}: exceeds 16 MiB inbox ingestion cap`)
        continue
      }

      const rawBytes = readFileSync(fullPath)
      const textContent = new TextDecoder("utf-8", { fatal: false }).decode(rawBytes)
      const ext = path.extname(name).toLowerCase()
      const inferredTool = name.split(/[_.-]/)[0] || "inbox-artifact"
      const kind: EvidenceKind =
        ext === ".json"
          ? "json"
          : ext === ".http"
            ? "http_exchange"
            : ext === ".xml" || ext === ".nmap"
              ? "network_observation"
              : "file"

      const res = this.ingestExternalAction({
        toolId: inferredTool,
        title: `Inbox Import: ${name}`,
        origin: "inbox_drop",
        rawOutput: textContent,
        mediaType: ext === ".json" ? "application/json" : "text/plain; charset=utf-8",
        kind,
        actor,
      })

      const archivedName = `${Date.now()}-${name.replace(/[^a-zA-Z0-9._-]/g, "_")}`
      const archivedFull = path.join(this.processedDir, archivedName)
      renameSync(fullPath, archivedFull)

      ingested.push({
        fileName: name,
        archivedTo: path.relative(this.options.workspaceRoot, archivedFull),
        evidenceId: res.evidenceId,
        sha256: res.sha256,
      })
    }

    return {
      scannedCount,
      ingested,
      skippedReasons,
    }
  }

  /**
   * Runs an external binary under direct CyberLab OS supervision:
   * 1. Enforces ScopeController BEFORE spawning the external process (blocks out-of-scope targets!).
   * 2. Spawns with shell=false and supports real-time AbortSignal cancellation.
   * 3. Automatically ingests stdout/stderr into EvidenceStore with secret redaction & SHA-256 hash.
   */
  async runSupervisedExternalCommand(params: {
    toolId: string
    binary: string
    args: readonly string[]
    target: string
    signal?: AbortSignal
    onStdoutChunk?: (chunk: string) => void
    onStderrChunk?: (chunk: string) => void
  }): Promise<{
    blocked: boolean
    reason?: string
    exitCode?: number
    ingested?: IngestExternalActionResult
  }> {
    const trimmedTarget = params.target.trim()
    if (!trimmedTarget) {
      return { blocked: true, reason: "An explicit target is required to supervise an external command" }
    }

    const isUrl = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmedTarget)
    const existsInWorkspace =
      !isUrl &&
      isPathInsideRoot(trimmedTarget, this.options.workspaceRoot) &&
      existsSync(path.resolve(this.options.workspaceRoot, trimmedTarget))
    const looksLikePath =
      existsInWorkspace ||
      trimmedTarget.startsWith("./") ||
      trimmedTarget.startsWith("../") ||
      trimmedTarget.startsWith("/") ||
      /\.(pcap|apk|ipa|ab|elf|exe|dll|bin)$/i.test(trimmedTarget)

    const extracted = extractTargetsFromInput(
      looksLikePath ? { path: trimmedTarget } : { target: trimmedTarget },
    )
    const scopeCheck = this.options.scopes.verifyTargets(
      this.options.projectId,
      extracted,
      looksLikePath ? ["workspace_path"] : ["ip"],
    )
    if (!scopeCheck.allowed) {
      return {
        blocked: true,
        reason: `Blocked by CyberLab ScopeController prior to external launch: ${scopeCheck.reason}`,
      }
    }

    const overrides = loadCustomBinaryOverrides(this.options.workspaceRoot)
    const resolved: ResolvedExternalBinary = isExecutableFile(params.binary)
      ? {
          resolvedPath: path.resolve(params.binary),
          sourceLocation: "custom_config",
          wslDistro: null,
          wslPath: null,
        }
      : resolveExternalBinary(
          this.options.workspaceRoot,
          [params.binary],
          overrides,
          resolvePosixCandidates([params.binary]),
        )

    if (!resolved.resolvedPath) {
      return {
        blocked: true,
        reason: `External binary "${params.binary}" was not found in config/external-tools.json, .cyberlab/bin, PATH or WSL2 (install inside Kali: see installHintWsl)`,
      }
    }

    const abortCtrl = new AbortController()
    const forwardAbort = () => abortCtrl.abort("Aborted by caller")
    params.signal?.addEventListener("abort", forwardAbort, { once: true })

    try {
    const proc = await runExternalBinary({
      resolved,
      args: params.args,
      cwd: this.options.workspaceRoot,
      signal: abortCtrl.signal,
        ...(params.onStdoutChunk !== undefined ? { onStdoutChunk: params.onStdoutChunk } : {}),
        ...(params.onStderrChunk !== undefined ? { onStderrChunk: params.onStderrChunk } : {}),
      })

      const ingested = this.ingestExternalAction({
        toolId: params.toolId,
        origin: "manual_external",
        target: trimmedTarget,
        commandSummary: `${path.basename(resolved.resolvedPath)} ${params.args.join(" ")}`,
        rawOutput: [proc.stdout, proc.stderr].filter(Boolean).join("\n"),
        exitCode: proc.exitCode,
        actor: "operator:supervised-wrap",
      })

      return {
        blocked: false,
        exitCode: proc.exitCode,
        ingested,
      }
    } finally {
      params.signal?.removeEventListener("abort", forwardAbort)
    }
  }
}
