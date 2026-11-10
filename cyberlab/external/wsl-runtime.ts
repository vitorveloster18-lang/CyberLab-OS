import { spawnSync } from "node:child_process"

/**
 * Ponte de runtime WSL2 para o CyberLab OS (v6.3 — Paridade de Runtime).
 *
 * MOTIVAÇÃO (achado real da Fase A, relatório de calibração v6.2):
 * o `ArsenalSlotManager` detecta binários instalados dentro do WSL2 Kali executando um
 * probe batido (`wsl.exe -d <distro> -u root -- bash -s`) e por isso reporta
 * `nuclei`, `tshark`, `ghidra`, `jadx`, `yarax`, `dalfox` e `keyhunter` como INSTALLED.
 * O `external` control plane, porém, resolvia binários apenas em
 * `config/external-tools.json` -> `<workspace>/.cyberlab/bin` -> `PATH` do Windows,
 * fazendo as 7 capabilities `external.*` correspondentes reportarem `not installed`.
 *
 * Este módulo elimina a divergência oferecendo a MESMA técnica de probe usada pelo
 * slot manager (script via stdin, decoding UTF-16LE, retry para VM fria) ao control
 * plane, além de tradução de caminhos Windows -> `/mnt/...` para argumentos.
 *
 * Zero dependências externas (apenas `node:child_process`) para poder ser importado
 * com segurança por testes e pelo MCP stdio sem puxar Effect.
 */

export interface WslEnvironmentInfo {
  available: boolean
  distros: string[]
  preferredDistro: string | null
}

export interface WslBinaryHit {
  /** Nome candidato pedido (ex.: "nuclei") */
  binary: string
  /** Caminho POSIX absoluto dentro da distro (ex.: "/usr/bin/nuclei") */
  linuxPath: string
  /** Distro onde o binário foi encontrado (ex.: "kali-linux") */
  distro: string
}

/** Decodifica saída do `wsl.exe`, que no Windows frequentemente vem em UTF-16LE. */
export function decodePotentialUtf16Le(input: Buffer | string): string {
  if (typeof input === "string") return input
  if (input.length === 0) return ""
  const hasEvenNulls = input.length >= 2 && input[1] === 0
  const hasOddNulls = input.length >= 2 && input[0] === 0
  if (hasEvenNulls || hasOddNulls) {
    try {
      return input.toString("utf16le")
    } catch {
      return input.toString("utf8")
    }
  }
  return input.toString("utf8")
}

/** `C:\CyberLab\ws\a.txt` -> `/mnt/c/CyberLab/ws/a.txt` */
export function windowsPathToWslPath(winPath: string): string {
  const match = /^([A-Za-z]):[\\/](.*)$/.exec(winPath)
  if (!match) return winPath.split("\\").join("/")
  const drive = match[1]!.toLowerCase()
  const rest = match[2]!.split("\\").join("/")
  return `/mnt/${drive}/${rest}`
}

/** Verdadeiro se o argumento é (ou contém) um caminho absoluto do Windows. */
export function containsWindowsPath(arg: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(arg) || /[=:][A-Za-z]:[\\/]/.test(arg)
}

/**
 * Traduz um argumento de linha de comando do Windows para o equivalente POSIX do WSL2.
 * - `C:\ws\list.txt`            -> `/mnt/c/ws/list.txt`
 * - `-o C:\ws\out.json`         -> `-o /mnt/c/ws/out.json` (caso venha colado)
 * - `output=C:\ws\out.json`     -> `output=/mnt/c/ws/out.json`
 * - `https://x.com/api`, `-j`, `10` -> inalterados
 */
export function toWslArg(arg: string): string {
  if (!arg.includes(":") && !arg.includes("\\")) return arg
  // Caminho absoluto isolado
  if (/^[A-Za-z]:[\\/]/.test(arg)) return windowsPathToWslPath(arg)
  // `chave=C:\caminho` (usado por ghidra/jadx/keyhunter em alguns flags)
  const eq = /^([A-Za-z0-9._-]+)=([A-Za-z]:[\\/].*)$/.exec(arg)
  if (eq) return `${eq[1]}=${windowsPathToWslPath(eq[2]!)}`
  // UNC \\wsl$\... ou \\wsl.localhost\... é compreendido nativamente pelo WSL
  if (arg.startsWith("\\\\wsl")) return arg
  return arg
}

const DISTRO_ALLOWLIST = /^[A-Za-z0-9._-]+$/

function listDistros(): string[] {
  if (process.platform !== "win32") return []
  try {
    const res = spawnSync("wsl.exe", ["-l", "-q"], {
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
      timeout: 20000,
    })
    if (res.status !== 0 || !res.stdout) return []
    return decodePotentialUtf16Le(res.stdout)
      .replace(/^﻿/, "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(
        (s) =>
          s.length > 0 &&
          DISTRO_ALLOWLIST.test(s) &&
          !s.toLowerCase().includes("docker-desktop"),
      )
  } catch {
    return []
  }
}

let envCache: { info: WslEnvironmentInfo; at: number } | null = null
const ENV_TTL_MS = 120_000

/** Lista distros WSL2 disponíveis (com cache curto para não acordar a VM a cada chamada). */
export function probeWslEnvironment(force = false): WslEnvironmentInfo {
  if (process.platform !== "win32") {
    return { available: false, distros: [], preferredDistro: null }
  }
  if (!force && envCache && Date.now() - envCache.at < ENV_TTL_MS) {
    return envCache.info
  }
  const distros = listDistros()
  const kali = distros.find((d) => d.toLowerCase().includes("kali"))
  const info: WslEnvironmentInfo = {
    available: distros.length > 0,
    distros,
    preferredDistro: kali ?? (distros.length > 0 ? distros[0]! : null),
  }
  envCache = { info, at: Date.now() }
  return info
}

export interface WslgInfo {
  /** WSLg funcional: apps Linux ganham uma janela NATIVA do Windows. */
  available: boolean
  /** Motivo quando indisponível — vai direto para a mensagem do operador. */
  reason: string
  display: string | null
  xdgRuntimeDir: string | null
  pulseServer: string | null
}

let wslgCache: { distro: string; info: WslgInfo; at: number } | null = null
const WSLG_TTL_MS = 300_000

/**
 * Detecta o WSLg — a camada que dá a apps Linux do WSL2 uma janela nativa do Windows.
 *
 * Por que isso importa tanto: sem WSLg o CyberLab precisa streamar o desktop inteiro
 * do Kali por noVNC dentro de um iframe. Daí vêm dois problemas reais que o operador
 * sentiu na pele — (a) o app abre DENTRO da coluna central e cobre o que estiver lá
 * (o Burp sendo engolido pelo próprio navegador), e (b) a área de transferência do
 * host não chega na sessão, porque um stream VNC não participa do clipboard do Windows.
 */
export function probeWslg(distro: string, force = false): WslgInfo {
  const unavailable = (reason: string): WslgInfo => ({
    available: false,
    reason,
    display: null,
    xdgRuntimeDir: null,
    pulseServer: null,
  })

  if (process.platform !== "win32") {
    return unavailable("WSLg só existe no host Windows.")
  }
  if (!force && wslgCache && wslgCache.distro === distro && Date.now() - wslgCache.at < WSLG_TTL_MS) {
    return wslgCache.info
  }

  const script = [
    'if [ -d /mnt/wslg/runtime-dir ]; then echo "WSLG_DIR=1"; else echo "WSLG_DIR=0"; fi',
    'if [ -S /tmp/.X11-unix/X0 ] || [ -e /mnt/wslg/.X11-unix/X0 ]; then echo "XSOCK=1"; else echo "XSOCK=0"; fi',
    'echo "DISPLAY=${DISPLAY:-}"',
    'echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-}"',
    'echo "PULSE_SERVER=${PULSE_SERVER:-}"',
  ].join("\n")

  let out = ""
  try {
    const res = spawnSync("wsl.exe", ["-d", distro, "--", "bash", "-s"], {
      input: script,
      encoding: "utf8",
      windowsHide: true,
      timeout: 20_000,
    })
    out = decodePotentialUtf16Le(res.stdout ?? "")
  } catch (err) {
    return unavailable(`Falha ao sondar o WSLg: ${err instanceof Error ? err.message : String(err)}`)
  }

  const read = (key: string): string | null => {
    const match = new RegExp(`^${key}=(.*)$`, "m").exec(out)
    const value = match?.[1]?.trim()
    return value && value.length > 0 ? value : null
  }

  const hasDir = read("WSLG_DIR") === "1"
  const hasSock = read("XSOCK") === "1"
  const display = read("DISPLAY") ?? (hasDir ? ":0" : null)
  const xdgRuntimeDir = read("XDG_RUNTIME_DIR") ?? (hasDir ? "/mnt/wslg/runtime-dir" : null)
  const pulseServer = read("PULSE_SERVER") ?? (hasDir ? "/mnt/wslg/PulseServer" : null)

  const info: WslgInfo =
    (hasDir || hasSock) && display
      ? {
          available: true,
          reason: "WSLg ativo — apps Linux abrem em janela nativa do Windows.",
          display,
          xdgRuntimeDir,
          pulseServer,
        }
      : unavailable(
          "WSLg não detectado nesta distro. Ele acompanha o Windows 11 (ou Windows 10 21H2+ com WSL " +
            "atualizado) e é o que permite janela nativa para apps Linux. Rode `wsl --update` e depois " +
            "`wsl --shutdown`. Até lá o CyberLab usa o desktop stream por noVNC, que não compartilha a " +
            "área de transferência do Windows.",
        )

  wslgCache = { distro, info, at: Date.now() }
  return info
}

/**
 * Monta o argv para abrir um app Linux em janela NATIVA via WSLg.
 *
 * As variáveis são exportadas com `env` (não com `export` dentro de um shell) para
 * manter a garantia de execução sem interpolação de shell.
 * Não forçamos `-u root`: apps gráficos rodando como root costumam brigar com o
 * dono do XDG_RUNTIME_DIR.
 */
export function buildWslgLaunchArgs(params: {
  distro: string
  binary: string
  args: readonly string[]
  wslg: WslgInfo
}): string[] {
  const envPairs: string[] = []
  if (params.wslg.display) envPairs.push(`DISPLAY=${params.wslg.display}`)
  if (params.wslg.xdgRuntimeDir) envPairs.push(`XDG_RUNTIME_DIR=${params.wslg.xdgRuntimeDir}`)
  if (params.wslg.pulseServer) envPairs.push(`PULSE_SERVER=${params.wslg.pulseServer}`)

  return ["-d", params.distro, "--", "env", ...envPairs, params.binary, ...params.args]
}

interface ProbeCacheEntry {
  hits: Map<string, WslBinaryHit>
  at: number
}
const probeCache = new Map<string, ProbeCacheEntry>()
const PROBE_TTL_MS = 120_000

export function resetWslRuntimeCaches(): void {
  envCache = null
  wslgCache = null
  probeCache.clear()
}

/**
 * Executa UM único probe batido no WSL2 cobrindo todos os candidatos pedidos.
 * O script bash é enviado por **stdin** (`wsl.exe ... -- bash -s`) para que o
 * `CreateProcessW` do Windows nunca quebre espaços, `$` ou aspas.
 */
export function probeWslBinaries(
  candidates: readonly string[],
  opts: { force?: boolean; distro?: string; timeoutMs?: number } = {},
): Map<string, WslBinaryHit> {
  const names = Array.from(new Set(candidates.filter((c) => /^(?:\/[a-zA-Z0-9._~-]+)+$|^[a-zA-Z0-9._~-]+$/.test(c))))
  if (names.length === 0) return new Map()

  const env = probeWslEnvironment(opts.force)
  const distro = opts.distro?.trim() || env.preferredDistro
  if (!env.available || !distro) return new Map()

  const cacheKey = `${distro}::${names.slice().sort().join("|")}`
  const cached = probeCache.get(cacheKey)
  if (!opts.force && cached && Date.now() - cached.at < PROBE_TTL_MS) {
    return cached.hits
  }

  const hits = new Map<string, WslBinaryHit>()
  const script = [
    // Remove trechos /mnt/* que o WSL2 injeta no PATH: evita confundir
    // scripts .bat/.sh do Windows com binários Linux nativos.
    'CLEAN_PATH=""',
    'IFS=:; for seg in $PATH; do case "$seg" in /mnt/*|"") ;; *) CLEAN_PATH="${CLEAN_PATH:+$CLEAN_PATH:}$seg" ;; esac; done; unset IFS',
    'PATH="$CLEAN_PATH"',
    'for d in "$HOME/.local/bin" "$HOME/go/bin" "$HOME/.cargo/bin" "$HOME/.pdtm/go/bin" "$HOME/.strix/bin" /home/*/.local/bin /home/*/go/bin /home/*/.cargo/bin /home/*/.pdtm/go/bin /opt/opentrap /opt/ghidra /opt/jadx/bin /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /snap/bin; do [ -d "$d" ] && PATH="$d:$PATH"; done',
    "export PATH",
    ...names.map((n) =>
      // Caminho absoluto: `command -v` não serve (não é um nome), então testa
      // executabilidade direto. Cobre ferramentas que a distro instala fora do PATH
      // (ex.: /usr/share/ghidra/support/analyzeHeadless no Debian/Kali).
      n.startsWith("/")
        ? `if [ -x "${n}" ] && [ ! -d "${n}" ]; then echo "HIT:${n}=${n}"; fi`
        : `p=$(command -v "${n}" 2>/dev/null | head -n 1); case "$p" in /mnt/*|"") ;; *) echo "HIT:${n}=$p" ;; esac`,
    ),
  ].join("\n")

  const runOnce = () => {
    try {
      const res = spawnSync("wsl.exe", ["-d", distro, "-u", "root", "--", "bash", "-s"], {
        input: Buffer.from(`${script}\n`, "utf8"),
        encoding: "utf8",
        stdio: ["pipe", "pipe", "ignore"],
        windowsHide: true,
        timeout: opts.timeoutMs ?? 30000,
      })
      if (!res.stdout) return
      for (const line of res.stdout.replace(/\0/g, "").split(/\r?\n/)) {
        if (!line.startsWith("HIT:")) continue
        const eq = line.indexOf("=")
        if (eq === -1) continue
        const key = line.slice(4, eq).trim()
        const val = line.slice(eq + 1).trim()
        if (key && val && !val.startsWith("/mnt/")) {
          hits.set(key, { binary: key, linuxPath: val, distro })
        }
      }
    } catch {
      // Timeout / VM fria / wsl.exe ausente: tratado como "sem hits".
    }
  }

  runOnce()
  // Hyper-V frio costuma devolver 0 hits na primeira chamada — um retry imediato resolve.
  if (hits.size === 0) runOnce()

  probeCache.set(cacheKey, { hits, at: Date.now() })
  return hits
}

export interface ProcessLaunch {
  command: string
  args: string[]
  cwd: string
  /** Preenchido somente quando o binário vive dentro do WSL2. */
  wsl: { distro: string; linuxBinary: string } | null
}

/**
 * Monta o comando final a ser executado:
 * - binário Windows/`.cyberlab/bin` -> executado direto;
 * - binário do WSL2 -> `wsl.exe -d <distro> -u root -- <bin> <args mapeados>`.
 */
export function buildProcessLaunch(params: {
  binaryPath: string
  args: readonly string[]
  cwd: string
  wsl: { distro: string; linuxBinary: string } | null
}): ProcessLaunch {
  if (!params.wsl) {
    return { command: params.binaryPath, args: [...params.args], cwd: params.cwd, wsl: null }
  }
  return {
    command: "wsl.exe",
    args: [
      "-d",
      params.wsl.distro,
      "-u",
      "root",
      "--",
      params.wsl.linuxBinary,
      ...params.args.map(toWslArg),
    ],
    cwd: params.cwd,
    wsl: params.wsl,
  }
}
