#!/usr/bin/env bun
/**
 * CyberLab OS — `cyberlab up` (v6.5).
 *
 * Um único comando para ATUALIZAR e SUBIR tudo:
 *
 *   1. `git pull --ff-only` (pule com `--no-pull`)
 *   2. `bun install` se `node_modules` estiver ausente (force com `--install`)
 *   3. sobe a interface do CyberLab OS com `--lab <labId>`
 *
 * Resultado: **UM ÚNICO PROCESSO** — interface, API e alvo de treino juntos, como o
 * Burp Suite (que embute o próprio Chromium). A interface fica em
 * http://127.0.0.1:4096 e o alvo em http://127.0.0.1:19081; você navega no alvo pelo
 * painel "🌐 Navegador do alvo (embutido)" na visão "5 Labs de Treino".
 *
 * Use `--daemon` se quiser o comportamento antigo: laboratório em processo separado,
 * que CONTINUA no ar depois de fechar a interface (útil para apontar Burp/curl de
 * fora sem a interface aberta).
 */

import { spawn, spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const args = process.argv.slice(2)

const CYAN = "\x1b[36m"
const GREEN = "\x1b[32m"
const YELLOW = "\x1b[33m"
const RED = "\x1b[31m"
const DIM = "\x1b[2m"
const RESET = "\x1b[0m"
const BOLD = "\x1b[1m"

const DEFAULT_LAB = "lab-owasp-api-bola"
const DEFAULT_UI_PORT = 4096

function flag(name: string): string | null {
  const i = args.indexOf(name)
  if (i >= 0 && args[i + 1] && !args[i + 1]!.startsWith("--")) return args[i + 1]!
  const eq = args.find((a) => a.startsWith(`${name}=`))
  return eq ? eq.slice(name.length + 1) : null
}

const labId = args.find((a, i) => i === 0 && !a.startsWith("--")) ?? flag("--lab") ?? DEFAULT_LAB
const uiPort = flag("--port") ?? flag("--ui-port") ?? String(DEFAULT_UI_PORT)
const labPort = flag("--lab-port")
const noPull = args.includes("--no-pull")
const noInstall = args.includes("--no-install")
const forceInstall = args.includes("--install")
const noOpen = args.includes("--no-open")
const daemonLab = args.includes("--daemon") || args.includes("-d")

if (args.includes("--help") || args.includes("-h")) {
  console.log(
    [
      `${BOLD}cyberlab up${RESET} — atualiza o repositório e sobe interface + laboratório`,
      "",
      "Uso: bun run cyberlab up [labId] [opções]",
      "",
      `  labId                    Laboratório a subir (padrão: ${DEFAULT_LAB})`,
      `  --lab <labId>            Mesmo que passar o labId na primeira posição`,
      `  --port <n>               Porta da INTERFACE (padrão: ${DEFAULT_UI_PORT})`,
      `  --lab-port <n>           Porta do ALVO (padrão: hint do catálogo, 19081)`,
      `  --no-pull                Não roda git pull`,
      `  --install / --no-install Força / nunca roda bun install`,
      `  --no-open                Não abre o navegador`,
      `  --daemon, -d             Sobe o laboratório em processo SEPARADO (sobrevive ao fechar a interface)`,
      "",
      `Padrão: UM ÚNICO processo (interface + API + alvo), como o Burp Suite.`,
      "",
      "Exemplos:",
      "  bun run cyberlab up",
      `  bun run cyberlab up ${DEFAULT_LAB} --port 4099 --no-pull`,
      "",
    ].join("\n"),
  )
  process.exit(0)
}

function run(cmd: string[], opts: { cwd: string; quiet?: boolean }): { ok: boolean; output: string } {
  const res = spawnSync(cmd[0]!, cmd.slice(1), { cwd: opts.cwd, encoding: "utf8" })
  const output = `${res.stdout ?? ""}${res.stderr ?? ""}`.trim()
  return { ok: res.status === 0, output }
}

console.log(`${BOLD}CyberLab OS — up${RESET}`)
console.log(`${DIM}Interface em ${CYAN}http://127.0.0.1:${uiPort}${RESET}${DIM} · alvo de treino em ${CYAN}http://127.0.0.1:${labPort ?? "19081"}${RESET}`)
console.log("")

// ---------------------------------------------------------------- 1) git pull
if (noPull) {
  console.log(`${DIM}1/4  git pull ignorado (--no-pull).${RESET}`)
} else {
  const branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], { cwd: repoRoot })
  const dirty = run(["git", "status", "--porcelain"], { cwd: repoRoot })
  if (!branch.ok) {
    console.log(`${YELLOW}1/4  Não parece ser um clone git — pulando atualização.${RESET}`)
  } else if (dirty.output.length > 0) {
    console.log(`${YELLOW}1/4  Há alterações locais não commitadas — git pull NÃO executado.${RESET}`)
    console.log(`${DIM}     Commite ou descarte antes de atualizar: git status${RESET}`)
  } else {
    const pull = run(["git", "pull", "--ff-only"], { cwd: repoRoot })
    if (pull.ok) {
      console.log(`${GREEN}1/4  Repositório atualizado${RESET} ${DIM}(${branch.output.trim()})${RESET}`)
    } else {
      console.log(`${YELLOW}1/4  git pull falhou — continuando com o código atual.${RESET}`)
      console.log(`${DIM}     ${pull.output.split("\n").slice(0, 3).join("\n     ")}${RESET}`)
    }
  }
}

// ---------------------------------------------------------------- 2) bun install
const nodeModules = path.join(repoRoot, "node_modules")
if (noInstall) {
  console.log(`${DIM}2/4  bun install ignorado (--no-install).${RESET}`)
} else if (forceInstall || !existsSync(nodeModules)) {
  console.log(`${DIM}2/4  Instalando dependências (pode levar 1–2 min)...${RESET}`)
  const inst = run([process.execPath, "install"], { cwd: repoRoot })
  console.log(inst.ok ? `${GREEN}2/4  Dependências instaladas.${RESET}` : `${RED}2/4  bun install falhou.${RESET}`)
  if (!inst.ok) console.log(`${DIM}     ${inst.output.split("\n").slice(-5).join("\n     ")}${RESET}`)
} else {
  console.log(`${DIM}2/4  node_modules presente — nada a instalar (use --install para forçar).${RESET}`)
}

// ---------------------------------------------------------------- 3) laboratório + interface (1 processo)
const labsRoot = process.env.CYBERLAB_LABS_ROOT?.trim() || path.join(repoRoot, ".cyberlab", "labs")

if (daemonLab) {
  console.log(`${DIM}3/4  Subindo o laboratório "${labId}" em processo SEPARADO (--daemon)...${RESET}`)
  const labArgs = ["run", "script/cyberlab-lab.ts", "start", labId, "--daemon"]
  if (labPort) labArgs.push("--port", labPort)
  const lab = spawn(process.execPath, labArgs, { cwd: repoRoot, stdio: "inherit", env: { ...process.env, CYBERLAB_LABS_ROOT: labsRoot } })
  const labCode = await new Promise<number>((resolve) => lab.on("close", (c) => resolve(c ?? 1)))
  if (labCode !== 0) {
    console.log(`${YELLOW}     O laboratório não subiu (código ${labCode}). A interface abrirá mesmo assim.${RESET}`)
  }
} else {
  console.log(`${DIM}3/4  Laboratório "${labId}" sobe DENTRO da interface (processo único).${RESET}`)
  if (labPort) {
    console.log(`${YELLOW}     --lab-port só vale com --daemon; na interface a porta vem do catálogo.${RESET}`)
  }
}

console.log("")
console.log(`${BOLD}4/4  Subindo a interface do CyberLab OS em ${CYAN}http://127.0.0.1:${uiPort}${RESET}`)
if (daemonLab) {
  console.log(`${DIM}     Ctrl+C encerra a INTERFACE. O laboratório continua no ar; para derrubá-lo:${RESET}`)
  console.log(`${DIM}       bun run cyberlab lab stop ${labId}${RESET}`)
} else {
  console.log(`${DIM}     Ctrl+C encerra tudo (interface + laboratório), pois é um só processo.${RESET}`)
  console.log(`${DIM}     Para deixar o alvo no ar sem a interface: bun run cyberlab up ${labId} --daemon${RESET}`)
}
console.log(`${DIM}     Navegue no alvo pela visão "5 Labs de Treino" → "🌐 Navegador do alvo (embutido)".${RESET}`)
console.log("")

// Sem `--daemon`, o próprio servidor sobe o laboratório: interface + API + alvo
// no MESMO processo. Com `--daemon`, não passamos `--lab` para não abrir um segundo
// servidor do laboratório conflitando com o daemon do passo 3.
const uiArgs = ["run", "script/start-cyberlab.ts", "--port", uiPort]
if (noOpen) uiArgs.push("--no-open")
if (!daemonLab) uiArgs.push("--lab", labId)

const ui = spawn(process.execPath, uiArgs, {
  cwd: repoRoot,
  stdio: "inherit",
  env: { ...process.env, CYBERLAB_LABS_ROOT: labsRoot },
})
ui.on("close", (code) => process.exit(code ?? 0))
