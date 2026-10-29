import { spawn, spawnSync } from "node:child_process"
import { existsSync, mkdirSync } from "node:fs"
import os from "node:os"
import path from "node:path"

export interface DetectedProxyBrowser {
  id: string
  displayName: string
  executablePath: string
}

export interface LaunchProxyBrowserResult {
  launched: boolean
  browserName: string | null
  executablePath: string | null
  proxyUrl: string
  startUrl: string
  spkiSha256Base64: string
  profileDirectory: string
  message: string
  manualPowershellCommand: string
  manualBashCommand: string
}

function resolveExecutableInPath(cmd: string): string | null {
  try {
    const checker = process.platform === "win32" ? "where.exe" : "which"
    const res = spawnSync(checker, [cmd], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
      timeout: 3000,
    })
    if (res.status === 0 && res.stdout) {
      const first = res.stdout
        .split(/\r?\n/)
        .map((s) => s.trim())
        .find((s) => s.length > 0 && existsSync(s))
      if (first) return first
    }
  } catch {
    // Ignore
  }
  return null
}

export function detectInstalledProxyBrowsers(): DetectedProxyBrowser[] {
  const found: DetectedProxyBrowser[] = []
  const seenPaths = new Set<string>()

  const addCandidate = (id: string, displayName: string, execPath: string | null) => {
    if (!execPath) return
    const norm = process.platform === "win32" ? execPath.toLowerCase() : execPath
    if (seenPaths.has(norm) || !existsSync(execPath)) return
    seenPaths.add(norm)
    found.push({ id, displayName, executablePath: execPath })
  }

  if (process.platform === "win32") {
    const pf = process.env.ProgramFiles || "C:\\Program Files"
    const pf86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)"
    const localApp = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local")

    const winCandidates: Array<{ id: string; name: string; paths: string[] }> = [
      {
        id: "chrome",
        name: "Google Chrome",
        paths: [
          path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
          path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
          path.join(localApp, "Google", "Chrome", "Application", "chrome.exe"),
        ],
      },
      {
        id: "msedge",
        name: "Microsoft Edge (Chromium)",
        paths: [
          path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
          path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
          path.join(localApp, "Microsoft", "Edge", "Application", "msedge.exe"),
        ],
      },
      {
        id: "brave",
        name: "Brave Browser",
        paths: [
          path.join(pf, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
          path.join(pf86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
          path.join(localApp, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        ],
      },
      {
        id: "chromium",
        name: "Chromium",
        paths: [path.join(localApp, "Chromium", "Application", "chrome.exe")],
      },
    ]

    for (const item of winCandidates) {
      for (const p of item.paths) {
        addCandidate(item.id, item.name, p)
      }
      addCandidate(item.id, item.name, resolveExecutableInPath(`${item.id}.exe`))
    }
    return found
  }

  if (process.platform === "darwin") {
    addCandidate(
      "chrome",
      "Google Chrome",
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    )
    addCandidate(
      "brave",
      "Brave Browser",
      "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    )
    addCandidate(
      "msedge",
      "Microsoft Edge",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    )
    addCandidate("chromium", "Chromium", "/Applications/Chromium.app/Contents/MacOS/Chromium")
    return found
  }

  // Linux & WSL2
  const linuxBins: Array<{ id: string; name: string; cmds: string[] }> = [
    { id: "chromium", name: "Chromium", cmds: ["chromium", "chromium-browser"] },
    { id: "chrome", name: "Google Chrome", cmds: ["google-chrome", "google-chrome-stable"] },
    { id: "brave", name: "Brave Browser", cmds: ["brave-browser", "brave"] },
    { id: "msedge", name: "Microsoft Edge", cmds: ["microsoft-edge", "microsoft-edge-stable"] },
  ]
  for (const item of linuxBins) {
    for (const cmd of item.cmds) {
      addCandidate(item.id, item.name, resolveExecutableInPath(cmd))
    }
  }

  // WSL2 fallback to Windows host browsers
  addCandidate(
    "chrome-wsl",
    "Google Chrome (Windows Host)",
    "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe",
  )
  addCandidate(
    "msedge-wsl",
    "Microsoft Edge (Windows Host)",
    "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  )

  return found
}

export function buildManualBrowserLaunchCommands(options: {
  proxyHost?: string
  proxyPort: number
  spkiSha256Base64?: string
  startUrl: string
  cyberlabUiPort?: number
}): { powershell: string; bash: string } {
  const host = options.proxyHost || "127.0.0.1"
  const proxyUrl = `http://${host}:${options.proxyPort}`
  const uiPort = options.cyberlabUiPort ?? 4096
  const bypass = `<-loopback>;127.0.0.1:${uiPort};localhost:${uiPort}`
  const certFlag = options.spkiSha256Base64
    ? `--ignore-certificate-errors-spki-list="${options.spkiSha256Base64}"`
    : `--ignore-certificate-errors`

  const powershell = [
    `$edge = "${"$"}{env:ProgramFiles(x86)}\\Microsoft\\Edge\\Application\\msedge.exe"`,
    `if (-not (Test-Path $edge)) { $edge = "$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.exe" }`,
    `& $edge --user-data-dir="$env:TEMP\\cyberlab-proxy-browser" --proxy-server="${proxyUrl}" --proxy-bypass-list="${bypass}" ${certFlag} --no-first-run "${options.startUrl}"`,
  ].join("; ")

  const bash = `google-chrome --user-data-dir="/tmp/cyberlab-proxy-browser" --proxy-server="${proxyUrl}" --proxy-bypass-list="${bypass}" ${certFlag} --no-first-run "${options.startUrl}"`

  return { powershell, bash }
}

export function launchPreconfiguredProxyBrowser(options: {
  proxyHost?: string
  proxyPort: number
  spkiSha256Base64?: string
  workspaceRoot: string
  startUrl?: string
  preferredBrowserId?: string
  cyberlabUiPort?: number
}): LaunchProxyBrowserResult {
  const host = options.proxyHost || "127.0.0.1"
  const startUrl = options.startUrl?.trim() || "about:blank"
  const proxyUrl = `http://${host}:${options.proxyPort}`
  const spki = options.spkiSha256Base64?.trim() || ""
  const uiPort = options.cyberlabUiPort ?? 4096
  const profileDirectory = path.join(options.workspaceRoot, ".cyberlab", `browser-profile-${options.proxyPort}`)
  const manual = buildManualBrowserLaunchCommands({
    proxyHost: host,
    proxyPort: options.proxyPort,
    ...(spki ? { spkiSha256Base64: spki } : {}),
    startUrl,
    cyberlabUiPort: uiPort,
  })

  // On Linux without DISPLAY / WAYLAND_DISPLAY (e.g. headless server/container), return manual commands cleanly
  if (
    process.platform === "linux" &&
    !process.env.DISPLAY &&
    !process.env.WAYLAND_DISPLAY &&
    !existsSync("/mnt/c/Windows")
  ) {
    return {
      launched: false,
      browserName: null,
      executablePath: null,
      proxyUrl,
      startUrl,
      spkiSha256Base64: spki,
      profileDirectory,
      message:
        "Ambiente Linux headless detectado (sem DISPLAY gráfico). Copie o comando PowerShell/Bash abaixo para abrir seu navegador local conectado ao Proxy com HTTPS pré-autenticado.",
      manualPowershellCommand: manual.powershell,
      manualBashCommand: manual.bash,
    }
  }

  const browsers = detectInstalledProxyBrowsers()
  const chosen =
    (options.preferredBrowserId
      ? browsers.find((b) => b.id === options.preferredBrowserId)
      : undefined) ?? browsers[0]

  if (!chosen) {
    return {
      launched: false,
      browserName: null,
      executablePath: null,
      proxyUrl,
      startUrl,
      spkiSha256Base64: spki,
      profileDirectory,
      message:
        "Nenhum navegador Chromium/Edge/Chrome/Brave foi localizado automaticamente. Use o comando PowerShell/Bash abaixo ou instale Chrome/Edge.",
      manualPowershellCommand: manual.powershell,
      manualBashCommand: manual.bash,
    }
  }

  try {
    mkdirSync(profileDirectory, { recursive: true })
  } catch {
    // Non-fatal
  }

  const bypassList = `<-loopback>;127.0.0.1:${uiPort};localhost:${uiPort}`
  const browserArgs = [
    `--user-data-dir=${profileDirectory}`,
    `--proxy-server=${proxyUrl}`,
    `--proxy-bypass-list=${bypassList}`,
    spki ? `--ignore-certificate-errors-spki-list=${spki}` : "--ignore-certificate-errors",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    startUrl,
  ]

  try {
    const child = spawn(chosen.executablePath, browserArgs, {
      detached: true,
      stdio: "ignore",
      windowsHide: false,
    })
    child.unref()

    return {
      launched: true,
      browserName: chosen.displayName,
      executablePath: chosen.executablePath,
      proxyUrl,
      startUrl,
      spkiSha256Base64: spki,
      profileDirectory,
      message: `${chosen.displayName} aberto em perfil isolado apontado para o Proxy ${proxyUrl} (HTTPS liberado no perfil de teste).`,
      manualPowershellCommand: manual.powershell,
      manualBashCommand: manual.bash,
    }
  } catch (err) {
    return {
      launched: false,
      browserName: chosen.displayName,
      executablePath: chosen.executablePath,
      proxyUrl,
      startUrl,
      spkiSha256Base64: spki,
      profileDirectory,
      message: `Falha ao abrir ${chosen.displayName}: ${err instanceof Error ? err.message : String(err)}. Use o comando manual abaixo.`,
      manualPowershellCommand: manual.powershell,
      manualBashCommand: manual.bash,
    }
  }
}
