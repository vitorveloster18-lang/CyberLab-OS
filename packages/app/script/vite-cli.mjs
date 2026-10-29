#!/usr/bin/env bun
/**
 * Cross-platform Vite launcher for CyberLab OS (`@opencode/app`).
 *
 * Why this exists:
 * On Windows PowerShell, `"build": "vite build"` invokes `node_modules\.bin\vite.bunx`.
 * Because `vite/bin/vite.js` declares `#!/usr/bin/env node`, Bun's `.bunx` shim tries to
 * spawn `node.exe` via Win32 process creation and crashes immediately with:
 *   `bun: unknown error:`
 * when `node.exe` is not installed on PATH (or when `.bunx` shims are stale after `git pull`).
 *
 * Resolving `vite/bin/vite.js` directly in JS and passing it to `bun.exe` (or a compatible
 * `node.exe` >= 20.19 / >= 22.12 when available on Windows, with automatic fallback to `bun.exe`)
 * completely bypasses `.bunx` shims and `#!/usr/bin/env node` resolution.
 */

import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { createRequire } from "node:module"
import path from "node:path"
import { fileURLToPath } from "node:url"

const MISSING_DEPS_EXIT_CODE = 2

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const appDir = path.resolve(scriptDir, "..")
const appPkgPath = path.join(appDir, "package.json")
const appRequire = createRequire(appPkgPath)

function resolveVitePackage() {
  try {
    const vitePkgJson = appRequire.resolve("vite/package.json")
    const cliPath = path.join(path.dirname(vitePkgJson), "bin", "vite.js")
    if (existsSync(cliPath)) {
      return { vitePkgJson, cliPath }
    }
  } catch {
    // Handled below
  }
  return null
}

function checkWindowsNativeBindings(vitePkgJson) {
  if (process.platform !== "win32") return null
  const arch = process.arch === "arm64" ? "arm64" : "x64"
  try {
    const viteReq = createRequire(vitePkgJson)
    const rolldownReq = createRequire(viteReq.resolve("rolldown/package.json"))
    rolldownReq.resolve(`@rolldown/binding-win32-${arch}-msvc`)

    const lightningReq = createRequire(viteReq.resolve("lightningcss/package.json"))
    lightningReq.resolve(`lightningcss-win32-${arch}-msvc`)

    const twViteReq = createRequire(appRequire.resolve("@tailwindcss/vite/package.json"))
    const twNodeReq = createRequire(twViteReq.resolve("@tailwindcss/node/package.json"))
    const twOxideReq = createRequire(twNodeReq.resolve("@tailwindcss/oxide/package.json"))
    twOxideReq.resolve(`@tailwindcss/oxide-win32-${arch}-msvc`)
    return null
  } catch (err) {
    return err instanceof Error ? err.message : String(err)
  }
}

const resolvedVite = resolveVitePackage()
if (!resolvedVite) {
  console.error(
    "[CyberLab UI Build] Vite não encontrado em node_modules. Execute `bun install --ignore-scripts` na raiz do repositório.",
  )
  process.exit(MISSING_DEPS_EXIT_CODE)
}

const missingBinding = checkWindowsNativeBindings(resolvedVite.vitePkgJson)
if (missingBinding) {
  console.error(
    `[CyberLab UI Build] Binding nativo Windows ausente (${missingBinding}). Execute \`bun install --ignore-scripts\` no PowerShell.`,
  )
  process.exit(MISSING_DEPS_EXIT_CODE)
}

const viteCliPath = resolvedVite.cliPath
const rawArgs = process.argv.slice(2)
let forcePwa = false
let forceSourcemap = false
const viteArgs = []

for (const arg of rawArgs) {
  if (arg === "--pwa") {
    forcePwa = true
    continue
  }
  if (arg === "--sourcemap") {
    forceSourcemap = true
    continue
  }
  viteArgs.push(arg)
}

const isBuildCommand = viteArgs[0] === "build"
const channel = process.env.OPENCODE_CHANNEL || "dev"
const env = {
  ...process.env,
  VITE_CONFIG_NATIVE_IGNORE_WARNING: process.env.VITE_CONFIG_NATIVE_IGNORE_WARNING || "true",
}

if (isBuildCommand) {
  if (forcePwa) {
    env.CYBERLAB_ENABLE_PWA = "1"
  } else if (
    env.CYBERLAB_ENABLE_PWA !== "1" &&
    channel !== "prod" &&
    channel !== "beta" &&
    env.PLAYWRIGHT_BUILD !== "1"
  ) {
    env.CYBERLAB_LOCAL_UI_BUILD = "1"
  }
  if (forceSourcemap) {
    env.CYBERLAB_UI_SOURCEMAP = "1"
  }
}

function hasCompatibleNodeOnWindows() {
  if (process.platform !== "win32") return false
  if (env.CYBERLAB_FORCE_BUN_VITE === "1") return false
  try {
    const probe = spawnSync(
      "node",
      [
        "-e",
        "const [maj,min]=process.versions.node.split('.').map(Number);process.exit((maj===20&&min>=19)||maj>=22?0:1)",
      ],
      {
        cwd: appDir,
        stdio: "ignore",
        windowsHide: true,
        timeout: 5000,
      },
    )
    return probe.status === 0 && !probe.error
  } catch {
    return false
  }
}

if (hasCompatibleNodeOnWindows()) {
  const nodeRun = spawnSync("node", [viteCliPath, ...viteArgs], {
    cwd: appDir,
    stdio: "inherit",
    env,
    windowsHide: true,
  })
  if (!nodeRun.error && nodeRun.status === 0) {
    process.exit(0)
  }
  console.warn(
    "[CyberLab UI Build] Execução via Node retornou erro; tentando novamente diretamente via runtime Bun...",
  )
}

const bunOrCurrentRuntime = process.execPath || "bun"
const directRun = spawnSync(bunOrCurrentRuntime, [viteCliPath, ...viteArgs], {
  cwd: appDir,
  stdio: "inherit",
  env,
  windowsHide: true,
})

if (directRun.error) {
  console.error(`[CyberLab UI Build] Falha ao iniciar Vite (${bunOrCurrentRuntime}): ${directRun.error.message}`)
  process.exit(1)
}

process.exit(directRun.status ?? 1)
