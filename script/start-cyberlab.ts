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
import { existsSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const distIndex = path.join(repoRoot, "packages", "app", "dist", "index.html")

const args = process.argv.slice(2)

function readFlag(name: string, fallback: string): string {
  const idx = args.indexOf(name)
  if (idx !== -1 && args[idx + 1]) return args[idx + 1]!
  const eq = args.find((a) => a.startsWith(`${name}=`))
  if (eq) return eq.slice(name.length + 1)
  return fallback
}

const host = readFlag("--host", readFlag("--hostname", process.env.CYBERLAB_HOST || "127.0.0.1"))
const port = readFlag("--port", process.env.CYBERLAB_PORT || "4096")
const rebuild = args.includes("--rebuild") || args.includes("--build")
const noOpen = args.includes("--no-open") || Boolean(process.env.CI)
const corsFlag = readFlag("--cors", "")

if (rebuild || !existsSync(distIndex)) {
  console.log("Construindo interface unificada do CyberLab OS (OpenCode V2 Web App)...")
  const buildRes = spawnSync("bun", ["--cwd", "packages/app", "build"], {
    cwd: repoRoot,
    stdio: "inherit",
    shell: process.platform === "win32",
  })
  if (buildRes.status !== 0) {
    process.exit(buildRes.status ?? 1)
  }
}

const isLoopback = host === "127.0.0.1" || host === "localhost" || host === "::1"
const explicitPassword = process.env.OPENCODE_SERVER_PASSWORD || process.env.OPENCODE_PASSWORD
const disableAuth =
  !explicitPassword &&
  (isLoopback || process.env.CYBERLAB_NO_SERVER_AUTH === "1" || process.env.CYBERLAB_NO_SERVER_AUTH === "true")

const displayHost = host === "0.0.0.0" || host === "127.0.0.1" ? "localhost" : host
const baseUrl = `http://${displayHost}:${port}`
const openUrl = explicitPassword
  ? `${baseUrl}/?auth_token=${Buffer.from(`opencode:${explicitPassword}`, "utf-8").toString("base64")}`
  : baseUrl

console.log("")
console.log("==================================================================")
console.log("  CyberLab OS — Aplicação Única Unificada (OpenCode V2)")
console.log("==================================================================")
console.log(`  App Completo (Chat + Ferramentas): ${baseUrl}`)
console.log(`  Configurações CyberLab & CDIs:     ${baseUrl}/settings?tab=cyberlab`)
console.log(`  Gateway Bidirecional dos 4 CDIs:   http://127.0.0.1:${port}/api/cyberlab/partner-gateway`)
console.log("==================================================================")
console.log("")

const cliArgs = ["run", "--cwd", "packages/cli", "src/index.ts", "serve", "--hostname", host, "--port", port]
if (corsFlag) {
  cliArgs.push("--cors", corsFlag)
}

const child = spawn("bun", cliArgs, {
  cwd: repoRoot,
  stdio: "inherit",
  shell: process.platform === "win32",
  env: {
    ...process.env,
    ...(disableAuth ? { CYBERLAB_NO_SERVER_AUTH: "1" } : {}),
    CYBERLAB_CALLBACK_URL:
      process.env.CYBERLAB_CALLBACK_URL || `http://127.0.0.1:${port}/api/cyberlab/partner-gateway`,
  },
})

if (!noOpen && isLoopback) {
  setTimeout(() => {
    try {
      if (process.platform === "win32") {
        spawn("cmd", ["/c", "start", "", openUrl], { detached: true, stdio: "ignore" }).unref()
      } else if (process.platform === "darwin") {
        spawn("open", [openUrl], { detached: true, stdio: "ignore" }).unref()
      } else {
        spawn("xdg-open", [openUrl], { detached: true, stdio: "ignore" }).unref()
      }
    } catch {
      // Ignore browser auto-open errors on headless machines
    }
  }, 1800)
}

child.on("exit", (code) => {
  process.exit(code ?? 0)
})
