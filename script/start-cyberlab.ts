#!/usr/bin/env bun
/**
 * Lançador Único Unificado do CyberLab OS (baseado no OpenCode V2)
 *
 * Inicia UMA ÚNICA aplicação completa em uma única porta (padrão: 4096) contendo:
 * - Interface completa do OpenCode V2 (Chat, Agentes, Modelos, Provedores, Atalhos, Terminal, Arquivos)
 * - Configurações Nativas do CyberLab OS & Agentes CDI em /settings?tab=cyberlab
 * - Painel Lateral Limpo do CyberLab OS dentro das sessões (botão "CyberLab" no topo ou /cyberlab)
 * - Gateway Bidirecional HMAC-SHA256 dos 4 CDIs em /api/cyberlab/partner-gateway
 */

import { spawn, spawnSync } from "node:child_process"
import { existsSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const UI_BUILD_STAMP = "cyberlab-unified-v2.3-suites"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const distDir = path.join(repoRoot, "packages", "app", "dist")
const distIndex = path.join(distDir, "index.html")
const distStampFile = path.join(distDir, ".cyberlab-ui-build")

const args = process.argv.slice(2)
const bunExecutable = process.execPath || "bun"

function readFlag(name: string, fallback: string): string {
  const idx = args.indexOf(name)
  if (idx !== -1 && args[idx + 1]) return args[idx + 1]!
  const eq = args.find((a) => a.startsWith(`${name}=`))
  if (eq) return eq.slice(name.length + 1)
  return fallback
}

const host = readFlag("--host", readFlag("--hostname", process.env.CYBERLAB_HOST || "0.0.0.0"))
const port = readFlag("--port", process.env.CYBERLAB_PORT || "4096")
const rebuild = args.includes("--rebuild") || args.includes("--build")
const requireAuth = args.includes("--require-auth")
const noOpen = args.includes("--no-open") || Boolean(process.env.CI)
const corsFlag = readFlag("--cors", "*")

let currentStamp = ""
try {
  if (existsSync(distStampFile)) {
    currentStamp = readFileSync(distStampFile, "utf-8").trim()
  }
} catch {
  currentStamp = ""
}

if (rebuild || !existsSync(distIndex) || currentStamp !== UI_BUILD_STAMP) {
  console.log("Construindo interface unificada do CyberLab OS (OpenCode V2 Web App)...")
  const buildRes = spawnSync(bunExecutable, ["--cwd", "packages/app", "build"], {
    cwd: repoRoot,
    stdio: "inherit",
  })
  if (buildRes.status !== 0) {
    process.exit(buildRes.status ?? 1)
  }
  try {
    writeFileSync(distStampFile, `${UI_BUILD_STAMP}\n`, "utf-8")
  } catch {
    // Non-fatal if dist directory is read-only
  }
}

const explicitPassword = process.env.OPENCODE_SERVER_PASSWORD || process.env.OPENCODE_PASSWORD
const disableAuth = !explicitPassword && !requireAuth

const probeHost = host === "0.0.0.0" || host === "::" || host === "::1" || host === "localhost" ? "127.0.0.1" : host
const primaryUrl = `http://${probeHost}:${port}`
const localhostUrl = `http://localhost:${port}`
const openUrl = explicitPassword
  ? `${primaryUrl}/?auth_token=${Buffer.from(`opencode:${explicitPassword}`, "utf-8").toString("base64")}`
  : primaryUrl

console.log("")
console.log("======================================================================")
console.log("  CyberLab OS — Aplicação Única Unificada (OpenCode V2)")
console.log("======================================================================")
console.log(`  App Completo (IPv4 Direto):        ${primaryUrl}`)
console.log(`  App Completo (Localhost):          ${localhostUrl}`)
console.log(`  Configurações CyberLab & CDIs:     ${primaryUrl}/settings?tab=cyberlab`)
console.log(`  Gateway Bidirecional dos 4 CDIs:   http://127.0.0.1:${port}/api/cyberlab/partner-gateway`)
console.log("======================================================================")
console.log("")

const cliArgs = ["run", "--cwd", "packages/cli", "src/index.ts", "serve", "--hostname", host, "--port", port]
if (corsFlag) {
  cliArgs.push("--cors", corsFlag)
}

const child = spawn(bunExecutable, cliArgs, {
  cwd: repoRoot,
  stdio: "inherit",
  env: {
    ...process.env,
    ...(disableAuth ? { CYBERLAB_NO_SERVER_AUTH: "1" } : {}),
    CYBERLAB_CALLBACK_URL:
      process.env.CYBERLAB_CALLBACK_URL || `http://127.0.0.1:${port}/api/cyberlab/partner-gateway`,
  },
})

async function waitForServerAndOpenBrowser() {
  const deadline = Date.now() + 35_000
  const headers: Record<string, string> = {}
  if (explicitPassword) {
    headers["authorization"] = `Basic ${Buffer.from(`opencode:${explicitPassword}`, "utf-8").toString("base64")}`
  }

  while (Date.now() < deadline) {
    if (child.exitCode !== null) return
    try {
      const [rootRes, infoRes] = await Promise.all([
        fetch(`${primaryUrl}/`, { headers }),
        fetch(`${primaryUrl}/api/info`, { headers }),
      ])
      if (rootRes.ok && infoRes.ok) {
        console.log(`\n[CyberLab OS] Interface pronta em ${primaryUrl} (e ${localhostUrl})`)
        if (!noOpen) {
          try {
            if (process.platform === "win32") {
              spawn("cmd.exe", ["/c", "start", "", openUrl], { detached: true, stdio: "ignore" }).unref()
            } else if (process.platform === "darwin") {
              spawn("open", [openUrl], { detached: true, stdio: "ignore" }).unref()
            } else {
              spawn("xdg-open", [openUrl], { detached: true, stdio: "ignore" }).unref()
            }
          } catch {
            // Ignore browser auto-open errors on headless machines
          }
        }
        return
      }
    } catch {
      // Server still booting
    }
    await new Promise((resolve) => setTimeout(resolve, 400))
  }
}

void waitForServerAndOpenBrowser()

child.on("exit", (code) => {
  process.exit(code ?? 0)
})
