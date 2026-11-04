#!/usr/bin/env bun
/**
 * CyberLab OS — Gerenciador de Laboratórios de Treino via linha de comando (v6.4).
 *
 * Resolve o item "servidor do lab inativo / memória investigativa vazia" apontado no
 * relatório de calibração da Fase A, permitindo preparar tudo sem abrir a interface:
 *
 *   bun run cyberlab lab list
 *   bun run cyberlab lab start lab-owasp-api-bola [--port 19081] [--reset]
 *   bun run cyberlab lab stop  lab-owasp-api-bola
 *   bun run cyberlab lab status [labId]
 *   bun run cyberlab lab kit   lab-owasp-api-bola        # gera Fases B/D/F
 *   bun run cyberlab lab seed  lab-owasp-api-bola        # grava na memória investigativa
 *   bun run cyberlab lab model lab-owasp-api-bola [--json]
 */

import { spawn } from "node:child_process"
import { existsSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import net from "node:net"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { BUILTIN_TRAINING_LABS, TrainingLabManager } from "../cyberlab/labs/training-labs.js"
import { CyberLabKnowledgeEngine } from "../cyberlab/knowledge/curated-library.js"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const args = process.argv.slice(2)

const CYAN = "\x1b[36m"
const GREEN = "\x1b[32m"
const YELLOW = "\x1b[33m"
const RED = "\x1b[31m"
const DIM = "\x1b[2m"
const RESET = "\x1b[0m"
const BOLD = "\x1b[1m"

function usage(): void {
  console.log(
    [
      `${BOLD}CyberLab OS — Laboratórios de Treino${RESET}`,
      "",
      "Uso: bun run cyberlab lab <comando> [labId] [opções]",
      "",
      "Comandos:",
      "  list                     Lista todos os labs com status (provisionado/rodando/porta)",
      "  start  <labId>           Provisiona e sobe o servidor do lab (gera o Kit de Investigação)",
      "  stop   <labId>           Derruba o servidor (funciona mesmo iniciado em outro terminal)",
      "  status [labId]           Mostra status detalhado (controles, requisições recentes)",
      "  kit    <labId>           Gera apenas os arquivos das Fases B/D/F (sem subir servidor)",
      "  seed   <labId>           Grava missão/escopo/modelo/hipóteses na memória investigativa",
      "  model  <labId> [--json]  Imprime o modelo do sistema (Fase B)",
      "",
      "Opções de start:",
      "  --daemon, -d             Segundo plano: o lab CONTINUA rodando após fechar o terminal",
      "  --port <n>               Porta preferida (padrão: hint do catálogo)",
      "  --reset                  Regrava os arquivos do lab antes de subir",
      "",
      "Fluxo recomendado (1 único terminal):",
      "  bun run cyberlab lab start lab-owasp-api-bola --daemon",
      "  bun run cyberlab lab seed  lab-owasp-api-bola",
      "  bun run cyberlab lab model lab-owasp-api-bola",
      "  bun run cyberlab lab status lab-owasp-api-bola",
      "  bun run cyberlab lab stop   lab-owasp-api-bola",
      "",
      "Labs disponíveis:",
      ...BUILTIN_TRAINING_LABS.map((l) => `  - ${l.labId}  ${DIM}(porta padrão ${l.defaultPortHint ?? "—"})${RESET}`),
    ].join("\n"),
  )
}

function resolveLabsRoot(): string {
  const explicit = process.env.CYBERLAB_LABS_ROOT?.trim()
  if (explicit) return path.resolve(explicit)
  return path.join(repoRoot, ".cyberlab", "labs")
}

function resolveWorkspaceRoot(): string {
  return path.resolve(process.env.CYBERLAB_WORKSPACE_ROOT?.trim() || process.cwd())
}

function readFlag(name: string): string | null {
  const i = args.indexOf(name)
  return i !== -1 && args[i + 1] ? args[i + 1]! : null
}

// ---------------------------------------------------------------------------
// Daemon (v6.4.1): o servidor do lab precisa sobreviver ao fechamento do terminal.
// ---------------------------------------------------------------------------

const labsRootForPid = resolveLabsRoot()

function pidFilePath(labId: string): string {
  return path.join(labsRootForPid, `.lab-${labId}.pid`)
}

function logFilePath(labId: string): string {
  return path.join(labsRootForPid, `lab-${labId}.log`)
}

function readPid(labId: string): number | null {
  try {
    if (!existsSync(pidFilePath(labId))) return null
    const raw = readFileSync(pidFilePath(labId), "utf8").trim()
    const pid = Number.parseInt(raw, 10)
    return Number.isFinite(pid) && pid > 0 ? pid : null
  } catch {
    return null
  }
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0) // sinal 0 apenas testa existência
    return true
  } catch {
    return false
  }
}

function clearPid(labId: string): void {
  try {
    rmSync(pidFilePath(labId), { force: true })
  } catch {
    // ignore
  }
}

/** Sonda TCP real: confirma que o servidor está de fato escutando. */
function isPortListening(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    const done = (ok: boolean) => {
      socket.destroy()
      resolve(ok)
    }
    socket.setTimeout(1200)
    socket.once("connect", () => done(true))
    socket.once("timeout", () => done(false))
    socket.once("error", () => done(false))
    socket.connect(port, "127.0.0.1")
  })
}

/**
 * Descobre a porta provável do lab: status em processo -> modelo em disco -> hint do catálogo.
 * Necessário porque o daemon roda em OUTRO processo (o manager local não conhece a porta).
 */
function resolveKnownPort(labId: string, inProcessPort?: number): number | null {
  if (inProcessPort && inProcessPort > 0) return inProcessPort
  try {
    const modelPath = path.join(labsRootForPid, labId, "lab-system-model.json")
    if (existsSync(modelPath)) {
      const parsed = JSON.parse(readFileSync(modelPath, "utf8")) as { baseUrl?: string }
      const m = /:(\d+)\s*\/?$/.exec(parsed.baseUrl ?? "")
      if (m) return Number.parseInt(m[1]!, 10)
    }
  } catch {
    // ignore
  }
  const def = BUILTIN_TRAINING_LABS.find((l) => l.labId === labId)
  return def?.defaultPortHint ?? null
}

/**
 * Sobe o lab em SEGUNDO PLANO: processo desanexado que sobrevive ao fechamento
 * do terminal, com PID e log gravados em disco para `lab stop` / `lab status`.
 */
async function startDaemon(labId: string, portRaw: string | null, reset: boolean): Promise<void> {
  const labsRoot = resolveLabsRoot()
  const existing = readPid(labId)
  if (existing && isPidAlive(existing)) {
    console.log(`${YELLOW}Já existe um daemon ativo para "${labId}" (PID ${existing}).${RESET}`)
    console.log(`Use ${BOLD}bun run cyberlab lab stop ${labId}${RESET} antes de subir outro.`)
    process.exit(0)
  }
  clearPid(labId)

  const logPath = logFilePath(labId)
  const outFd = openSync(logPath, "a")

  const childArgs = ["run", "script/cyberlab-lab.ts", "start", labId]
  if (portRaw) childArgs.push("--port", portRaw)
  if (reset) childArgs.push("--reset")

  const child = spawn(process.execPath, childArgs, {
    cwd: repoRoot,
    detached: true,
    stdio: ["ignore", outFd, outFd],
    env: { ...process.env, CYBERLAB_LABS_ROOT: labsRoot, CYBERLAB_LAB_DAEMON: "1" },
  })
  child.unref()

  writeFileSync(pidFilePath(labId), String(child.pid ?? ""), "utf8")
  console.log(`${GREEN}✔ Lab "${labId}" iniciado em SEGUNDO PLANO (PID ${child.pid}).${RESET}`)
  console.log(`  Log : ${logPath}`)
  console.log(`  PID : ${pidFilePath(labId)}`)
  console.log("")

  // Aguarda o servidor realmente escutar (até ~10s) e imprime a URL confirmada
  const hintPort = portRaw ? Number.parseInt(portRaw, 10) : null
  let confirmedPort: number | null = null
  for (let i = 0; i < 40; i++) {
    const probePort = hintPort ?? 19081
    if (await isPortListening(probePort)) {
      confirmedPort = probePort
      break
    }
    await new Promise((r) => setTimeout(r, 250))
  }
  if (confirmedPort) {
    console.log(`  URL : ${CYAN}http://127.0.0.1:${confirmedPort}${RESET}`)
    console.log(`  Smoke test: curl.exe -s http://127.0.0.1:${confirmedPort}/health`)
  } else {
    console.log(`  ${YELLOW}Ainda sem resposta TCP — aguarde alguns segundos e rode:${RESET}`)
    console.log(`  ${BOLD}bun run cyberlab lab status ${labId}${RESET}`)
  }
  console.log("")
  console.log(`${DIM}Este processo encerrou; o lab CONTINUA rodando em background.${RESET}`)
  console.log(`${DIM}Para parar: bun run cyberlab lab stop ${labId}${RESET}`)
  process.exit(0)
}

const command = (args[0] ?? "").toLowerCase()
const labIdArg = args.find((a, i) => i > 0 && !a.startsWith("--")) ?? ""

if (!command || command === "help" || command === "--help" || command === "-h") {
  usage()
  process.exit(0)
}

const manager = new TrainingLabManager(resolveLabsRoot())

function printStatus(
  status: ReturnType<TrainingLabManager["getLabStatus"]>,
  daemon?: { alive: boolean; pid: number | null },
): void {
  const state = daemon?.alive
    ? `${GREEN}RODANDO (2º plano, PID ${daemon.pid})${RESET}`
    : status.running
      ? `${GREEN}RODANDO (neste processo)${RESET}`
      : status.provisioned
        ? `${YELLOW}PROVISIONADO (servidor parado)${RESET}`
        : `${DIM}NÃO PROVISIONADO${RESET}`
  console.log(`${BOLD}${status.labId}${RESET} — ${state}`)
  console.log(`  Título     : ${status.title}`)
  console.log(`  Dificuldade: ${status.difficulty}`)
  console.log(`  Workspace  : ${status.workspaceRoot}`)
  if (status.baseUrl && !daemon?.alive) console.log(`  URL base   : ${CYAN}${status.baseUrl}${RESET}`)
  if (status.startedAt) console.log(`  Iniciado em: ${status.startedAt}`)
  console.log(`  Requisições: ${status.requestCount}`)
  if (status.recentRequests.length > 0) {
    console.log("  Últimas requisições:")
    for (const r of status.recentRequests.slice(-5)) {
      console.log(`    ${DIM}${r.timestamp}${RESET} ${r.method} ${r.url} -> ${r.statusCode}`)
    }
  }
  console.log(`  Desafios   : ${status.challenges.map((c) => c.id).join(", ")}`)
}

switch (command) {
  case "list": {
    for (const s of manager.listLabs()) {
      const state = s.running ? `${GREEN}● rodando${RESET}` : s.provisioned ? `${YELLOW}○ provisionado${RESET}` : `${DIM}· não provisionado${RESET}`
      console.log(`${BOLD}${s.labId.padEnd(32)}${RESET} ${state}${s.baseUrl ? `  ${CYAN}${s.baseUrl}${RESET}` : ""}`)
    }
    process.exit(0)
  }

  case "start": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId. Ex.: bun run cyberlab lab start lab-owasp-api-bola${RESET}`)
      process.exit(1)
    }
    const portRaw = readFlag("--port")
    if (args.includes("--daemon") || args.includes("-d") || args.includes("--background")) {
      await startDaemon(labIdArg, portRaw, args.includes("--reset"))
    }
    const status = await manager.startLab({
      labId: labIdArg,
      ...(portRaw ? { preferredPort: Number.parseInt(portRaw, 10) } : {}),
      resetFiles: args.includes("--reset"),
    })
    printStatus(status)
    const root = manager.getLabWorkspacePath(labIdArg)
    console.log("")
    if (manager.hasInvestigationKit(labIdArg)) {
      console.log(`${GREEN}✔ Kit de Investigação gerado (Fases B/D/F):${RESET}`)
      console.log(`    ${path.join(root, "LAB_SYSTEM_MODEL.md")}`)
      console.log(`    ${path.join(root, "HYPOTHESES.md")}`)
      console.log(`    ${path.join(root, "EXPERIMENTS.md")}`)
      console.log(`    ${path.join(root, "investigation-memory-seed.json")}`)
    }
    if (status.baseUrl) {
      console.log("")
      console.log(`${BOLD}Smoke test:${RESET} curl -s ${status.baseUrl}/health`)
      console.log(`${BOLD}Próximo passo (em OUTRO terminal):${RESET} bun run cyberlab lab seed ${labIdArg}`)
      console.log("")
      console.log(`${YELLOW}Servidor ativo neste processo. Pressione Ctrl+C para encerrar.${RESET}`)

      // Mantém o processo vivo (o servidor do lab morre com o processo).
      let stopping = false
      const shutdown = async (signal: string) => {
        if (stopping) return
        stopping = true
        console.log(`\n${DIM}${signal} recebido — encerrando laboratório(s)...${RESET}`)
        try {
          await manager.stopAll()
        } catch {
          // ignore
        }
        console.log(`${YELLOW}O servidor do lab foi ENCERRADO (ele vivia dentro deste processo).${RESET}`)
        console.log(`${BOLD}Para deixá-lo ativo em segundo plano, use:${RESET}`)
        console.log(`  bun run cyberlab lab start ${labIdArg} --daemon`)
        process.exit(0)
      }
      process.on("SIGINT", () => void shutdown("SIGINT"))
      process.on("SIGTERM", () => void shutdown("SIGTERM"))
      await new Promise<never>(() => {})
    }
    process.exit(0)
  }

  case "stop": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId.${RESET}`)
      process.exit(1)
    }
    // 1) Servidor rodando em SEGUNDO PLANO (outro processo) — mata pelo PID
    const pid = readPid(labIdArg)
    if (pid && isPidAlive(pid)) {
      try {
        process.kill(pid, "SIGTERM")
        console.log(`${GREEN}✔ Daemon do lab "${labIdArg}" (PID ${pid}) finalizado.${RESET}`)
      } catch (err) {
        console.error(`${RED}Não foi possível finalizar o PID ${pid}: ${err instanceof Error ? err.message : String(err)}${RESET}`)
      }
      clearPid(labIdArg)
      process.exit(0)
    }
    if (pid) clearPid(labIdArg) // PID obsoleto

    // 2) Servidor neste processo (ou nada rodando)
    printStatus(await manager.stopLab(labIdArg))
    console.log(`${DIM}Nenhum daemon em segundo plano estava ativo para este lab.${RESET}`)
    process.exit(0)
  }

  case "status": {
    const targets = labIdArg ? [labIdArg] : manager.listLabs().map((s) => s.labId)
    for (const id of targets) {
      const st = manager.getLabStatus(id)
      const pid = readPid(id)
      const daemonAlive = Boolean(pid && isPidAlive(pid))

      printStatus(st, { alive: daemonAlive, pid: daemonAlive ? pid : null })

      if (daemonAlive) {
        // O servidor vive em OUTRO processo: confirme por sonda TCP, não por estado em memória
        const port = resolveKnownPort(id, st.port)
        const listening = port ? await isPortListening(port) : false
        console.log(`  ${GREEN}Daemon de segundo plano: ATIVO (PID ${pid})${RESET}`)
        console.log(
          port
            ? `  URL base : ${CYAN}http://127.0.0.1:${port}${RESET} — ${listening ? `${GREEN}respondendo${RESET}` : `${RED}sem resposta TCP${RESET}`}`
            : `  ${YELLOW}Porta desconhecida (kit ainda não gerado).${RESET}`,
        )
        console.log(`  Log      : ${logFilePath(id)}`)
      } else if (pid) {
        console.log(`  ${DIM}PID ${pid} registrado mas o processo não existe — limpando.${RESET}`)
        clearPid(id)
        console.log(`  ${YELLOW}Servidor PARADO.${RESET} Para subir em segundo plano:`)
        console.log(`    ${BOLD}bun run cyberlab lab start ${id} --daemon${RESET}`)
      } else if (!st.running) {
        console.log(`  ${YELLOW}Servidor PARADO.${RESET} Para subir em segundo plano:`)
        console.log(`    ${BOLD}bun run cyberlab lab start ${id} --daemon${RESET}`)
        console.log(`  ${DIM}(sem --daemon o servidor morre quando você fecha o terminal/Ctrl+C)${RESET}`)
      }
      console.log("")
    }
    process.exit(0)
  }

  case "kit": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId.${RESET}`)
      process.exit(1)
    }
    const files = manager.ensureInvestigationKit(labIdArg)
    if (!files) {
      console.error(`${RED}O lab "${labIdArg}" ainda não possui Kit de Investigação (suportados: lab-owasp-api-bola).${RESET}`)
      process.exit(1)
    }
    console.log(`${GREEN}✔ Kit de Investigação gravado:${RESET}`)
    for (const f of files) console.log(`    ${f}`)
    process.exit(0)
  }

  case "seed": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId.${RESET}`)
      process.exit(1)
    }
    const seed = manager.buildInvestigationMemorySeed(labIdArg)
    if (!seed) {
      console.error(`${RED}O lab "${labIdArg}" não possui Kit de Investigação. Rode: bun run cyberlab lab kit ${labIdArg}${RESET}`)
      process.exit(1)
    }
    const engine = new CyberLabKnowledgeEngine({ workspaceRoot: resolveWorkspaceRoot() })
    const res = engine.updateInvestigationMemory(seed)
    console.log(`${GREEN}✔ Memória investigativa atualizada (${res.memory.investigationId})${RESET}`)
    console.log(`  Missão        : ${res.memory.mission}`)
    console.log(`  Escopo        : ${res.memory.authorizedScope}`)
    console.log(`  Hipóteses     : ${res.memory.hypotheses.map((h) => h.id).join(", ")}`)
    console.log(`  Experimentos  : ${res.memory.experiments.map((e) => e.id).join(", ")}`)
    console.log(`  Espelho no cofre: ${res.vaultMirrorPath}`)
    process.exit(0)
  }

  case "model": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId.${RESET}`)
      process.exit(1)
    }
    const seed = manager.buildInvestigationMemorySeed(labIdArg)
    if (!seed) {
      console.error(`${RED}O lab "${labIdArg}" não possui modelo. Rode: bun run cyberlab lab kit ${labIdArg}${RESET}`)
      process.exit(1)
    }
    if (args.includes("--json")) {
      console.log(JSON.stringify(seed, null, 2))
      process.exit(0)
    }
    console.log(`${BOLD}Modelo do Sistema — ${labIdArg}${RESET}`)
    console.log(`\n${CYAN}Componentes${RESET}`)
    for (const c of seed.systemModel.components) console.log(`  - ${c}`)
    console.log(`\n${CYAN}Tecnologias${RESET}`)
    for (const t of seed.systemModel.technologies) console.log(`  - ${t}`)
    console.log(`\n${CYAN}Fluxos de dados${RESET}`)
    for (const d of seed.systemModel.dataFlows) console.log(`  - ${d}`)
    console.log(`\n${CYAN}Fronteiras de confiança${RESET}`)
    for (const b of seed.systemModel.trustBoundaries) console.log(`  - ${b}`)
    console.log(`\n${CYAN}Identidades & permissões${RESET}`)
    for (const i of seed.systemModel.identitiesAndPermissions) console.log(`  - ${i}`)
    console.log(`\n${CYAN}Hipóteses${RESET}`)
    for (const h of seed.hypotheses) {
      console.log(`  ${BOLD}${h.id}${RESET} ${h.title}`)
      console.log(`      esperado : ${h.expectedBehavior}`)
      console.log(`      suspeito : ${h.suspectedBehavior}`)
    }
    process.exit(0)
  }

  default: {
    console.error(`${RED}Comando desconhecido: ${command}${RESET}`)
    usage()
    process.exit(1)
  }
}
