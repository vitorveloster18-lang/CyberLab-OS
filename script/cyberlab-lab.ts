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
 *   bun run cyberlab lab restart lab-owasp-api-bola        # para e sobe de novo
 *   bun run cyberlab lab status [labId]
 *   bun run cyberlab lab kit   lab-owasp-api-bola        # gera Fases B/D/F
 *   bun run cyberlab lab seed  lab-owasp-api-bola        # grava na memória investigativa
 *   bun run cyberlab lab model lab-owasp-api-bola [--json]
 *   bun run cyberlab lab evidence lab-owasp-api-bola      # E1–E7 + SHA-256
 *   bun run cyberlab lab tools [--missing] [--script]
 *   bun run cyberlab lab slots --health
 *   bun run cyberlab lab research lab-owasp-api-bola --register
 *   bun run cyberlab lab hypothesize lab-owasp-api-bola --register
 *   bun run cyberlab lab experiment lab-owasp-api-bola --run --register
 *   bun run cyberlab lab targets
 *   bun run cyberlab lab scope portswigger-wsa
 */

import { spawn } from "node:child_process"
import { existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import net from "node:net"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { BUILTIN_TRAINING_LABS, TrainingLabManager } from "../cyberlab/labs/training-labs.js"
import { CyberLabKnowledgeEngine } from "../cyberlab/knowledge/curated-library.js"
import { runBolaEvidenceSuite } from "../cyberlab/labs/evidence-recorder.js"
import { listTargetProfiles, writeTargetScope } from "../cyberlab/labs/target-profiles.js"
import { createDefaultCyberLabConfig } from "../cyberlab/config/config.js"
import { EvidenceStore } from "../cyberlab/evidence/store.js"
import { BUILTIN_EXTERNAL_TOOL_CATALOG, inspectExternalToolStatuses } from "../cyberlab/external/control-plane.js"
import { ArsenalSlotManager, normalizeSlotNameForComparison } from "../cyberlab/arsenal/slot-manager.js"
import { OFFICIAL_ARSENAL_SLOTS } from "../cyberlab/arsenal/catalog.js"
import { ScopeController } from "../cyberlab/policy/scope.js"
import { runLabResearch } from "../cyberlab/labs/research-phase.js"
import { runHypothesisPhase } from "../cyberlab/labs/hypothesis-phase.js"
import { runExperimentPhase } from "../cyberlab/labs/experiment-phase.js"

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
      "  restart <labId>          Para o daemon atual e sobe um novo (segundo plano)",
      "  status [labId]           Mostra status detalhado (controles, requisições recentes)",
      "  kit    <labId>           Gera apenas os arquivos das Fases B/D/F (sem subir servidor)",
      "  seed   <labId>           Grava missão/escopo/modelo/hipóteses na memória investigativa",
      "  model  <labId> [--json]  Imprime o modelo do sistema (Fase B)",
      "  evidence <labId>         Reexecuta E1–E7 e arquiva comando+resposta com SHA-256",
      "  tools [--missing] [--script]  Mostra as ferramentas externas e como instalar as que faltam",
      "  slots [--json] [--health]    Lista os slots do Arsenal, duplicatas e slots fantasmas",
      "  research <labId>         FASE C: pesquisa CyberLab-Knowledge + advisories (CVE/GHSA)",
      "  hypothesize <labId>     FASE D: hipóteses ancoradas na Fase C + priorização (Fase E)",
      "  experiment <labId>      FASE F: plano (padrão) ou execução (--run) dos experimentos",
      "  targets                  Lista alvos externos com AUTORIZAÇÃO declarada",
      "  scope <perfil>           Grava SCOPE.md + RULES-OF-ENGAGEMENT.md do alvo",
      "",
      "Opções de start:",
      "  --daemon, -d             Segundo plano: o lab CONTINUA rodando após fechar o terminal",
      "  --port <n>               Porta preferida (padrão: hint do catálogo)",
      "  --reset                  Regrava os arquivos do lab antes de subir",
      "  --restart, --force       Se já houver um daemon no ar, derruba e sobe um novo",
      "",
      "Opções de evidence:",
      "  --out <dir>              Pasta de saída (padrão: evidence/<labId>/<timestamp>)",
      "  --port <n>               Usa um lab JÁ ativo nessa porta em vez de subir um novo",
      "  --register               Registra o lote no EvidenceStore (o agente passa a vê-lo)",
      "",
      "Opções de scope:",
      "  --out <dir>              Pasta de saída (padrão: <labsRoot>/targets/<perfil>)",
      "",
      "Opções de research:",
      "  --out <dir>              Pasta de saída (padrão: <labsRoot>/research/<labId>/<timestamp>)",
      "  --offline                Não toca a rede: reusa só o cache em disco",
      "  --refresh                Ignora o cache (TTL 12h) e consulta a API de novo",
      "  --register               Registra os artefatos no EvidenceStore",
      "  --json                   Imprime o relatório em JSON",
      "",
      "Opções de slots:",
      "  --json                   Saída completa em JSON (slots, duplicatas, higiene)",
      "  --health                 Mostra só os problemas de higiene (fantasma/duplicado/sem binário)",
      "",
      "Opções de tools:",
      "  --missing                Mostra só o que NÃO está instalado",
      "  --script                 Imprime um script bash pronto p/ rodar no WSL2 Kali",
      "  --json                   Saída em JSON",
      "",
      "",
      "Nota: se o lab já estiver rodando, ‘start’ apenas informa a URL e os próximos",
      "comandos — use ‘restart’ para recomeçar do zero.",
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
  // v6.6: a interface (servidor) usa `.cyberlab/training-labs`. O CLI passa a preferir
  // essa raiz quando ela já existe, para que `lab status` / `lab evidence` enxerguem o
  // mesmo laboratório que aparece "rodando" na UI. Raiz legada continua funcionando.
  const serverRoot = path.join(repoRoot, ".cyberlab", "training-labs")
  const legacyRoot = path.join(repoRoot, ".cyberlab", "labs")
  if (existsSync(serverRoot)) return serverRoot
  if (existsSync(legacyRoot)) return legacyRoot
  return serverRoot
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
 * v6.6 — Detecta um lab rodando FORA deste processo (o caso normal quando ele foi
 * iniciado pela interface do CyberLab OS, que hospeda o alvo no mesmo processo da UI).
 * Antes o CLI dizia apenas "PROVISIONADO" e parecia que nada estava no ar.
 */
async function probeExternalLab(labId: string): Promise<{ baseUrl: string; pid: string } | null> {
  const port = resolveKnownPort(labId)
  if (!port) return null
  if (!(await isPortListening(port))) return null
  try {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 1500)
    const res = await fetch(`http://127.0.0.1:${port}/health`, { signal: ctrl.signal })
    clearTimeout(timer)
    if (!res.ok) return null
    const body = (await res.json()) as { labId?: string }
    if (body.labId !== labId) return null
    return { baseUrl: `http://127.0.0.1:${port}`, pid: "interface do CyberLab OS" }
  } catch {
    return null
  }
}

/**
 * Sobe o lab em SEGUNDO PLANO: processo desanexado que sobrevive ao fechamento
 * do terminal, com PID e log gravados em disco para `lab stop` / `lab status`.
 */
async function startDaemon(
  labId: string,
  portRaw: string | null,
  reset: boolean,
  forceRestart: boolean,
): Promise<void> {
  const labsRoot = resolveLabsRoot()
  const existing = readPid(labId)
  if (existing && isPidAlive(existing)) {
    // Confirma por sonda TCP: PID vivo não significa servidor de pé.
    const knownPort = resolveKnownPort(labId, portRaw ? Number.parseInt(portRaw, 10) : undefined)
    const listening = knownPort ? await isPortListening(knownPort) : false

    if (listening) {
      if (!forceRestart) {
        console.log(`${GREEN}\u2714 O lab "${labId}" J\u00c1 EST\u00c1 NO AR em segundo plano (PID ${existing}).${RESET}`)
        console.log(`  ${BOLD}Nada a fazer ${DIM}\u2014 n\u00e3o \u00e9 um erro, o servidor j\u00e1 est\u00e1 rodando e atendendo requisi\u00e7\u00f5es.${RESET}`)
        console.log("")
        console.log(`  Painel do lab : ${CYAN}http://127.0.0.1:${knownPort}${RESET}`)
        console.log(`  Smoke test    : curl.exe -s http://127.0.0.1:${knownPort}/health`)
        console.log("")
        console.log(`  ${BOLD}Pr\u00f3ximos passos:${RESET}`)
        console.log(`    bun run cyberlab lab status ${labId}    ${DIM}\u2192 confirma PID, porta e \u00faltimas requisi\u00e7\u00f5es${RESET}`)
        console.log(`    bun run cyberlab lab seed ${labId}      ${DIM}\u2192 grava o modelo na mem\u00f3ria investigativa${RESET}`)
        console.log("")
        console.log(`  ${BOLD}Quer recome\u00e7ar do zero?${RESET} (para, sobe de novo e regrava os arquivos)`)
        console.log(`    bun run cyberlab lab restart ${labId}`)
        console.log(`    bun run cyberlab lab stop ${labId}`)
        console.log("")
        console.log(`  ${DIM}Log: ${logFilePath(labId)}${RESET}`)
        process.exit(0)
      }
      // --restart: derruba o daemon atual antes de subir o novo
      try {
        process.kill(existing, "SIGTERM")
      } catch {
        // ignore
      }
      for (let i = 0; i < 20 && isPidAlive(existing); i++) {
        await new Promise((r) => setTimeout(r, 150))
      }
      if (isPidAlive(existing)) {
        try {
          process.kill(existing, "SIGKILL")
        } catch {
          // ignore
        }
        await new Promise((r) => setTimeout(r, 300))
      }
      console.log(`${DIM}Daemon anterior (PID ${existing}) encerrado \u2014 subindo um novo...${RESET}`)
    } else {
      // PID existe mas nada escuta: daemon zumbi. Limpa e recomeça.
      console.log(`${YELLOW}\u26a0 PID ${existing} est\u00e1 vivo mas nada responde em 127.0.0.1:${knownPort ?? "?"} (daemon zumbi).${RESET}`)
      console.log(`${DIM}Encerrando o processo \u00f3rf\u00e3o e subindo um novo...${RESET}`)
      try {
        process.kill(existing, "SIGTERM")
      } catch {
        // ignore
      }
      await new Promise((r) => setTimeout(r, 400))
      if (isPidAlive(existing)) {
        try {
          process.kill(existing, "SIGKILL")
        } catch {
          // ignore
        }
      }
    }
  } else if (existing) {
    console.log(`${DIM}PID ${existing} registrado mas o processo n\u00e3o existe mais \u2014 limpando registro obsoleto.${RESET}`)
  }
  clearPid(labId)

  // A raiz pode ainda não existir (primeiro uso) — o daemon não passa pelo provisionamento local.
  mkdirSync(labsRoot, { recursive: true })

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
      await startDaemon(
        labIdArg,
        portRaw,
        args.includes("--reset"),
        args.includes("--restart") || args.includes("--force"),
      )
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

  case "restart": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId.${RESET}`)
      process.exit(1)
    }
    await startDaemon(
      labIdArg,
      readFlag("--port"),
      args.includes("--reset"),
      true, // restart sempre força
    )
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
        // Pode estar rodando dentro da interface (processo único da v6.6).
        const external = await probeExternalLab(id)
        if (external) {
          console.log(`  ${GREEN}RODANDO em OUTRO processo${RESET} (${external.pid}) — este CLI não gerencia esse servidor.`)
          console.log(`  Painel do alvo : ${CYAN}${external.baseUrl}/${RESET}`)
          console.log(`  ${DIM}Para gerenciar daqui, pare na interface (ou feche-a) e use:${RESET}`)
          console.log(`    ${BOLD}bun run cyberlab lab start ${id} --daemon${RESET}`)
        } else {
          console.log(`  ${YELLOW}Servidor PARADO.${RESET} Para subir em segundo plano:`)
          console.log(`    ${BOLD}bun run cyberlab lab start ${id} --daemon${RESET}`)
          console.log(`  ${DIM}(sem --daemon o servidor morre quando você fecha o terminal/Ctrl+C)${RESET}`)
          console.log(`  ${DIM}Ou abra a interface com o alvo embutido: bun run cyberlab up ${id}${RESET}`)
        }
      }
      console.log("")
    }
    process.exit(0)
  }

  case "slots": {
    const asJson = args.includes("--json")
    const onlyHealth = args.includes("--health")
    const workspaceRoot = resolveWorkspaceRoot()
    const manager = new ArsenalSlotManager({
      projectId: "cyberlab-cli",
      workspaceRoot,
      scopes: new ScopeController(),
    })
    const overview = manager.getOverview(true)
    const custom = overview.slots.filter((s) => s.isCustom)

    // Um slot "instalado" só diz que o caminho configurado existe. Para saber se o
    // binário que o AGENTE invoca está de fato no PATH, é preciso cruzar com o
    // catálogo externo — é exatamente a junção que `lab tools` já fazia em separado.
    const slotToTool = new Map(
      OFFICIAL_ARSENAL_SLOTS.filter((d) => d.externalToolId).map((d) => [d.slotId, d.externalToolId!]),
    )
    const toolById = new Map(BUILTIN_EXTERNAL_TOOL_CATALOG.map((e) => [e.toolId, e]))
    const toolStatus = new Map(
      inspectExternalToolStatuses(workspaceRoot)
        .filter((t) => !t.toolId.startsWith("external:"))
        .map((t) => [t.toolId, t]),
    )
    const governed = [...slotToTool.keys()].map((slotId) => {
      const toolId = slotToTool.get(slotId)!
      const status = toolStatus.get(toolId)
      const entry = toolById.get(toolId)
      const candidates = entry?.posixBinaries ?? entry?.binaryCandidates ?? [toolId]
      return {
        slotId,
        toolId,
        available: status?.available ?? false,
        resolvedPath: status?.resolvedPath ?? null,
        candidates,
        installKaliWsl: status?.installHintWsl ?? entry?.installKaliWsl ?? null,
      }
    })
    const governedBySlot = new Map(governed.map((g) => [g.slotId, g]))
    const missing = governed.filter((g) => !g.available)

    // Duplicata "real" = mesmo nome normalizado em mais de um slot.
    const byName = new Map<string, string[]>()
    for (const slot of overview.slots) {
      const key = normalizeSlotNameForComparison(slot.name)
      byName.set(key, [...(byName.get(key) ?? []), slot.slotId])
    }
    const duplicates = [...byName.entries()].filter(([, ids]) => ids.length > 1)

    if (asJson) {
      console.log(
        JSON.stringify(
          {
            environment: overview.environment,
            total: overview.slots.length,
            builtin: overview.slots.length - custom.length,
            custom: custom.length,
            duplicates: duplicates.map(([name, slotIds]) => ({ name, slotIds })),
            health: overview.health,
            governedTools: {
              total: governed.length,
              available: governed.length - missing.length,
              missing: missing.map((g) => ({
                slotId: g.slotId,
                toolId: g.toolId,
                expectedBinaries: g.candidates,
                installKaliWsl: g.installKaliWsl,
              })),
            },
            slots: overview.slots.map((s) => {
              const g = governedBySlot.get(s.slotId)
              return {
                slotId: s.slotId,
                name: s.name,
                kind: s.kind,
                origin: s.isCustom ? "custom" : "catalogo",
                installed: s.installed,
                activeRuntime: s.activeRuntime,
                resolvedPath: s.resolvedPath,
                tool: g
                  ? {
                      toolId: g.toolId,
                      available: g.available,
                      expectedBinaries: g.candidates,
                      resolvedPath: g.resolvedPath,
                      installKaliWsl: g.installKaliWsl,
                    }
                  : null,
              }
            }),
          },
          null,
          2,
        ),
      )
      process.exit(0)
    }

    if (onlyHealth) {
      if (overview.health.length === 0) {
        console.log("Nenhum problema de higiene detectado no Arsenal.")
      } else {
        console.log(`${overview.health.length} problema(s) de higiene:`)
        for (const issue of overview.health) {
          console.log(`\n[${issue.severity.toUpperCase()}] ${issue.kind} — ${issue.slotId}`)
          console.log(`  ${issue.message}`)
          if (issue.configuredPath) console.log(`  caminho: ${issue.configuredPath}`)
          console.log(`  acao:    ${issue.recommendedAction}`)
        }
      }
      if (missing.length > 0) {
        console.log("")
        console.log(`${missing.length} binario(s) governado(s) ausente(s) — o slot existe, o binario nao:`)
        for (const g of missing) {
          console.log(`  ✘ ${g.slotId} (${g.toolId}): esperado ${g.candidates.join(" / ")}`)
          if (g.installKaliWsl) console.log(`     WSL2 Kali: ${g.installKaliWsl}`)
        }
      }
      process.exit(0)
    }

    console.log(
      `Arsenal — ${overview.slots.length} slot(s) (${overview.slots.length - custom.length} do catalogo, ${custom.length} personalizado(s))`,
    )
    console.log(
      `WSL: ${overview.environment.wslAvailable ? "sim" : "nao"} · distros: ${overview.environment.wslDistros.join(", ") || "(nenhuma)"}`,
    )
    console.log("")
    for (const slot of overview.slots) {
      const origin = slot.isCustom ? "custom  " : "catalogo"
      const g = governedBySlot.get(slot.slotId)
      // Só o primeiro candidato cabe na coluna; a lista completa sai no rodapé.
      const bin = !g
        ? "—".padEnd(28)
        : g.available
          ? `✔ ${g.toolId}`.slice(0, 28).padEnd(28)
          : `✘ ${g.candidates[0] ?? g.toolId}`.slice(0, 28).padEnd(28)
      console.log(
        `  ${origin} ${slot.slotId.padEnd(38)} ${(slot.installed ? "instalado" : "sem-binario").padEnd(12)} ${bin} ${slot.name}`,
      )
    }
    console.log("")
    if (duplicates.length === 0) {
      console.log("Duplicatas por nome normalizado: nenhuma.")
    } else {
      console.log(`Duplicatas por nome normalizado: ${duplicates.length}`)
      for (const [name, ids] of duplicates) console.log(`  "${name}" -> ${ids.join(", ")}`)
    }
    console.log("")
    console.log(
      `Binarios governados: ${governed.length} · disponiveis ${governed.length - missing.length} · faltando ${missing.length}`,
    )
    for (const g of missing) {
      console.log(`  ✘ ${g.slotId} -> ${g.toolId} (esperado: ${g.candidates.join(" / ")})`)
      if (g.installKaliWsl) console.log(`     WSL2 Kali: ${g.installKaliWsl}`)
    }
    if (overview.health.length > 0) {
      console.log(`\nHigiene: ${overview.health.length} problema(s). Rode: bun run cyberlab lab slots --health`)
    }
    process.exit(0)
  }

  case "research": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId. Ex.: bun run cyberlab lab research lab-owasp-api-bola${RESET}`)
      process.exit(1)
    }
    const asJson = args.includes("--json")
    const offline = args.includes("--offline")
    const refresh = args.includes("--refresh")
    const outFlag = readFlag("--out")
    const wsRoot = resolveWorkspaceRoot()

    const report = await runLabResearch({
      labId: labIdArg,
      workspaceRoot: wsRoot,
      ...(offline ? { offline: true } : {}),
      ...(refresh ? { refresh: true } : {}),
      ...(outFlag ? { outDir: outFlag } : {}),
    })

    if (asJson) {
      console.log(JSON.stringify(report, null, 2))
    } else {
      console.log(`${BOLD}Fase C — Pesquisa${RESET} ${CYAN}${report.labId}${RESET}`)
      console.log(
        `  Perfil: ${report.curated ? "curado" : "derivado do modelo (Fase B)"} · Modo: ${
          report.offline ? "offline (cache)" : "online"
        }`,
      )
      console.log(`  Alvo  : ${report.systemModel.title} — ${report.systemModel.baseUrl}`)
      console.log("")
      const docs = new Set<string>()
      let docCount = 0
      for (const k of report.knowledge) {
        for (const h of k.hits) {
          docs.add(h.docPath)
          docCount += 1
        }
      }
      console.log(`  Biblioteca curada : ${report.knowledge.length} consulta(s), ${docCount} hit(s), ${docs.size} documento(s) distinto(s)`)
      let advCount = 0
      for (const a of report.advisories) {
        advCount += a.advisories.length
        const tag =
          a.status === "error"
            ? `${RED}erro${RESET}`
            : a.status === "empty"
              ? `${DIM}vazio${RESET}`
              : a.status === "offline"
                ? `${YELLOW}cache${RESET}`
                : a.status === "cached"
                  ? `${CYAN}cache${RESET}`
                  : `${GREEN}ok${RESET}`
        console.log(
          `  ${a.target.ecosystem}/${a.target.package.padEnd(16)} ${tag} · ${String(a.advisories.length).padStart(3)} advisory(ies)`,
        )
        if (a.error) console.log(`      ${YELLOW}${a.error}${RESET}`)
      }
      console.log(`  Total de advisories: ${advCount}`)
      if (report.profile.weaknesses.length > 0) {
        console.log("")
        console.log("  Classes de fraqueza exercitadas:")
        for (const w of report.profile.weaknesses) {
          console.log(`    ${w.cwe} — ${w.name}${w.owasp ? `  (${w.owasp})` : ""}`)
        }
      }
      console.log("")
      console.log(`  ${GREEN}Relatório:${RESET} ${path.join(report.outputDir, "RESEARCH.md")}`)
      console.log(`  ${DIM}Lacre (SHA-256 do lote): ${report.seal}${RESET}`)
      console.log(`  ${DIM}Manifesto: ${path.join(report.outputDir, "research-manifest.json")}${RESET}`)
    }

    if (args.includes("--register")) {
      const cfg = createDefaultCyberLabConfig(wsRoot)
      const store = new EvidenceStore({
        databasePath: cfg.databaseFilename,
        artifactsDir: cfg.artifactsDirectory,
      })
      try {
        const executionId = `lab-research-${Date.now()}`
        let n = 0
        for (const f of report.files) {
          const abs = path.join(report.outputDir, f.name)
          const isJson = f.name.endsWith(".json")
          store.storeEvidence(
            labIdArg,
            {
              kind: isJson ? "json" : "file",
              title: `Fase C — ${labIdArg} — ${f.name}`,
              source: {
                toolId: "cyberlab-lab-research",
                toolVersion: "6.7.0",
                executorId: "operator",
                executionId,
              },
              content: {
                mediaType: isJson ? "application/json" : "text/markdown",
                inlineText: readFileSync(abs, "utf8"),
                sha256: f.sha256,
                byteLength: f.bytes,
              },
              observedAt: report.generatedAt,
              labels: ["lab", labIdArg, "fase-c", "research"],
            },
            { applyRedactionBeforeStore: false },
          )
          n += 1
        }
        console.log(`${GREEN}✔ ${n} artefato(s) da Fase C registrados no EvidenceStore${RESET} (projeto: ${labIdArg})`)
      } finally {
        store.close()
      }
    }
    process.exit(0)
  }

  case "hypothesize": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId. Ex.: bun run cyberlab lab hypothesize lab-owasp-api-bola${RESET}`)
      process.exit(1)
    }
    const asJson = args.includes("--json")
    const outFlag = readFlag("--out")
    const wsRoot = resolveWorkspaceRoot()

    let board
    try {
      board = runHypothesisPhase({
        labId: labIdArg,
        workspaceRoot: wsRoot,
        ...(outFlag ? { outDir: outFlag } : {}),
      })
    } catch (err) {
      console.error(`${RED}${err instanceof Error ? err.message : String(err)}${RESET}`)
      process.exit(1)
    }

    if (asJson) {
      console.log(JSON.stringify(board, null, 2))
    } else {
      console.log(`${BOLD}Fase D — Hipóteses & priorização (Fase E)${RESET} ${CYAN}${board.labId}${RESET}`)
      console.log(
        board.researchDir
          ? `  Ancorado na Fase C: ${board.researchDir}`
          : `  ${YELLOW}NÃO ancorado na Fase C — rode: bun run cyberlab lab research ${board.labId}${RESET}`,
      )
      console.log("")
      console.log("  #  Hipótese                                    Score  Plaus Imp Dif Evid Custo Risco  Ancoras")
      for (const [i, h] of board.hypotheses.entries()) {
        const s = h.scores
        console.log(
          `  ${String(i + 1).padStart(2)} ${h.id} ${h.title.slice(0, 36).padEnd(37)} ${String(h.priorityScore).padStart(5)}  ${s.plausibility}    ${s.impact}   ${s.discriminatingPower}   ${s.evidenceAvailable}    ${s.cost}     ${s.executionRisk}     ${h.anchors.length}`,
        )
      }
      console.log("")
      for (const h of board.hypotheses) {
        const adv = h.anchors.filter((a) => a.kind === "advisory")
        const cwe = h.anchors.filter((a) => a.kind === "weakness")
        const src = h.anchors.filter((a) => a.kind === "primary_source")
        console.log(`  ${BOLD}${h.id}${RESET} ${h.title}`)
        console.log(
          `     controle ${h.relatedControlFlag ?? "—"}: ${
            h.controlCurrentlyOff ? `${RED}DESLIGADO${RESET}` : "ligado"
          } · experimentos: ${h.experimentIds.join(", ") || "—"}`,
        )
        console.log(
          `     ancoras: ${adv.length} advisory(ies), ${cwe.length} CWE, ${src.length} fonte(s) primária(s)`,
        )
        for (const a of adv.slice(0, 4)) console.log(`       ${DIM}${a.ref} — ${a.detail.slice(0, 90)}${RESET}`)
        if (h.gap) console.log(`     ${YELLOW}${h.gap}${RESET}`)
        console.log("")
      }
      console.log(`  ${GREEN}Relatório:${RESET} ${path.join(board.outputDir, "HYPOTHESES-D.md")}`)
      console.log(`  ${DIM}Lacre: ${board.seal}${RESET}`)
    }

    if (args.includes("--register")) {
      const cfg = createDefaultCyberLabConfig(wsRoot)
      const store = new EvidenceStore({
        databasePath: cfg.databaseFilename,
        artifactsDir: cfg.artifactsDirectory,
      })
      try {
        const executionId = `lab-hypotheses-${Date.now()}`
        let n = 0
        for (const f of board.files) {
          const isJson = f.name.endsWith(".json")
          store.storeEvidence(
            labIdArg,
            {
              kind: isJson ? "json" : "file",
              title: `Fase D — ${labIdArg} — ${f.name}`,
              source: {
                toolId: "cyberlab-lab-hypotheses",
                toolVersion: "6.7.0",
                executorId: "operator",
                executionId,
              },
              content: {
                mediaType: isJson ? "application/json" : "text/markdown",
                inlineText: readFileSync(path.join(board.outputDir, f.name), "utf8"),
                sha256: f.sha256,
                byteLength: f.bytes,
              },
              observedAt: board.generatedAt,
              labels: ["lab", labIdArg, "fase-d", "hypotheses"],
            },
            { applyRedactionBeforeStore: false },
          )
          n += 1
        }
        console.log(`${GREEN}✔ ${n} artefato(s) da Fase D registrados no EvidenceStore${RESET} (projeto: ${labIdArg})`)
      } finally {
        store.close()
      }
    }
    process.exit(0)
  }

  case "experiment": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId. Ex.: bun run cyberlab lab experiment lab-owasp-api-bola${RESET}`)
      process.exit(1)
    }
    const doRun = args.includes("--run")
    const asJson = args.includes("--json")
    const portFlag = readFlag("--port")
    const onlyFlag = readFlag("--only")
    const outFlag = readFlag("--out")
    const wsRoot = resolveWorkspaceRoot()

    let board
    try {
      board = await runExperimentPhase({
        labId: labIdArg,
        workspaceRoot: wsRoot,
        ...(doRun ? { run: true } : {}),
        ...(portFlag ? { baseUrl: `http://127.0.0.1:${Number.parseInt(portFlag, 10)}` } : {}),
        ...(onlyFlag ? { only: onlyFlag.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
        ...(outFlag ? { outDir: outFlag } : {}),
      })
    } catch (err) {
      console.error(`${RED}${err instanceof Error ? err.message : String(err)}${RESET}`)
      process.exit(1)
    }

    if (asJson) {
      console.log(JSON.stringify(board, null, 2))
    } else {
      console.log(
        `${BOLD}Fase F — Experimentação${RESET} ${CYAN}${board.labId}${RESET} ${doRun ? "" : `${DIM}(plano — nada executado)${RESET}`}`,
      )
      console.log(`  Alvo : ${board.baseUrl ?? "—"}`)
      console.log(
        `  Ordem: ${board.orderSource === "fase-d" ? "prioridade da Fase D" : "ordem das sementes (rode 'lab hypothesize' para priorizar)"}`,
      )
      console.log("")
      for (const e of board.experiments) {
        const exec = e.requests.filter((r) => r.outcome === "executed").length
        const manual = e.requests.filter((r) => r.outcome === "manual").length
        const err = e.requests.filter((r) => r.outcome === "error").length
        const tag =
          e.indicator === "sustenta"
            ? `${GREEN}SUSTENTA${RESET}`
            : e.indicator === "nao_observado"
              ? `${DIM}nao observado${RESET}`
              : e.indicator === "sem_marcador"
                ? `${DIM}sem marcador${RESET}`
                : `${DIM}nao executado${RESET}`
        console.log(
          `  ${e.seed.id} ${e.hypothesisId.padEnd(4)} ${String(e.requests.length).padStart(2)} req  ${tag}`,
        )
        if (doRun) {
          for (const r of e.requests) {
            const mark =
              r.outcome === "executed"
                ? `${GREEN}HTTP ${r.httpStatus}${RESET}`
                : r.outcome === "manual"
                  ? `${YELLOW}manual${RESET}`
                  : r.outcome === "error"
                    ? `${RED}erro${RESET}`
                    : `${DIM}planejado${RESET}`
            console.log(`      ${String(r.index + 1).padStart(2)}. ${mark} ${r.intent ?? r.command.slice(0, 70)}`)
            if (r.error) console.log(`          ${YELLOW}${r.error}${RESET}`)
          }
          if (e.markersFound.length > 0) {
            console.log(`      ${GREEN}marcadores: ${e.markersFound.join(", ")}${RESET}`)
          }
        } else {
          for (const r of e.requests) {
            console.log(
              `      ${r.outcome === "manual" ? `${YELLOW}manual${RESET}` : `${DIM}$${RESET}`} ${r.command.slice(0, 100)}`,
            )
          }
        }
        if (exec + manual + err === 0) continue
        console.log(`      ${DIM}${exec} executada(s), ${manual} manual(is), ${err} erro(s)${RESET}`)
      }
      console.log("")
      console.log(
        doRun
          ? `  ${DIM}O indicador acima NÃO é veredito: diz só se o marcador apareceu. A decisão é da Fase G.${RESET}`
          : `  ${DIM}Para executar: bun run cyberlab lab experiment ${labIdArg} --run${RESET}`,
      )
      console.log(`  ${GREEN}Relatório:${RESET} ${path.join(board.outputDir, "EXPERIMENTS.md")}`)
      console.log(`  ${DIM}Lacre: ${board.seal}${RESET}`)
    }

    if (args.includes("--register")) {
      const cfg = createDefaultCyberLabConfig(wsRoot)
      const store = new EvidenceStore({
        databasePath: cfg.databaseFilename,
        artifactsDir: cfg.artifactsDirectory,
      })
      try {
        const executionId = `lab-experiments-${Date.now()}`
        let n = 0
        for (const f of board.files) {
          const isJson = f.name.endsWith(".json")
          store.storeEvidence(
            labIdArg,
            {
              kind: isJson ? "json" : "file",
              title: `Fase F — ${labIdArg} — ${f.name}`,
              source: {
                toolId: "cyberlab-lab-experiment",
                toolVersion: "6.7.0",
                executorId: "operator",
                executionId,
              },
              content: {
                mediaType: isJson ? "application/json" : "text/markdown",
                inlineText: readFileSync(path.join(board.outputDir, f.name), "utf8"),
                sha256: f.sha256,
                byteLength: f.bytes,
              },
              observedAt: board.generatedAt,
              labels: ["lab", labIdArg, "fase-f", "experiments"],
            },
            { applyRedactionBeforeStore: false },
          )
          n += 1
        }
        // Capturas brutas individuais: é o que torna o achado reproduzível.
        for (const e of board.experiments) {
          for (const r of e.requests) {
            if (r.outcome !== "executed" || !r.rawFile || !r.sha256) continue
            store.storeEvidence(
              labIdArg,
              {
                kind: "http_exchange",
                title: `${e.seed.id} #${r.index + 1} — ${r.intent ?? "requisição"}`,
                source: {
                  toolId: "cyberlab-lab-experiment",
                  toolVersion: "6.7.0",
                  executorId: "operator",
                  executionId,
                },
                content: {
                  mediaType: "text/plain",
                  inlineText: readFileSync(path.join(board.outputDir, r.rawFile), "utf8"),
                  sha256: r.sha256,
                  byteLength: r.bytes,
                },
                observedAt: board.generatedAt,
                labels: ["lab", labIdArg, "fase-f", e.seed.id, `http-${r.httpStatus}`],
              },
              { applyRedactionBeforeStore: false },
            )
            n += 1
          }
        }
        console.log(`${GREEN}✔ ${n} evidência(s) da Fase F registradas no EvidenceStore${RESET} (projeto: ${labIdArg})`)
      } finally {
        store.close()
      }
    }
    process.exit(0)
  }

  case "tools": {
    const onlyMissing = args.includes("--missing")
    const asScript = args.includes("--script")
    const asJson = args.includes("--json")
    const all = inspectExternalToolStatuses(resolveWorkspaceRoot())
    // O catálogo expõe a ferramenta e o alias `external:*` da capability; manter só
    // a entrada canônica evita mostrar o mesmo binário duas vezes.
    const seen = new Set<string>()
    const tools = all.filter((t) => {
      if (t.toolId.startsWith("external:")) return false
      if (seen.has(t.toolId)) return false
      seen.add(t.toolId)
      return true
    })
    const shown = onlyMissing ? tools.filter((t) => !t.available) : tools

    if (asJson) {
      console.log(JSON.stringify(shown, null, 2))
      process.exit(0)
    }

    if (asScript) {
      // Só entram comandos de verdade: o catálogo traz dicas como
      // "See slot installer (...)" e parenteses explicativos, que quebrariam o bash
      // (o script roda com `set -e`).
      const COMMAND_RE = /^(sudo|apt|apt-get|pipx|pip3?|go|cargo|gem|curl|wget|npm|bun|bash|sh)\b/
      const scriptable = tools
        .filter((t) => !t.available)
        .map((t) => ({ tool: t, cmd: (t.installHintWsl || "").split(" (")[0]!.trim() }))
        .filter((x) => COMMAND_RE.test(x.cmd))
      const notScriptable = tools.filter(
        (t) => !t.available && !scriptable.some((x) => x.tool.toolId === t.toolId),
      )

      console.log("#!/usr/bin/env bash")
      console.log("# Gerado por: bun run cyberlab lab tools --script")
      console.log("# Rode DENTRO do WSL2 Kali:")
      console.log("#   bun run cyberlab lab tools --script > install-faltantes.sh")
      console.log("#   wsl -d kali-linux -- bash -s < install-faltantes.sh")
      console.log("set -euo pipefail")
      console.log("")
      console.log("sudo apt update")
      console.log("")
      if (scriptable.length === 0) {
        console.log('echo "Nada do catálogo pode ser instalado por script (o que falta depende de licença ou de configuração)."')
      }
      for (const { tool, cmd } of scriptable) {
        console.log(`# ${tool.displayName}`)
        console.log(cmd)
        console.log("")
      }
      for (const t of notScriptable) {
        console.log(`# ${t.toolId}: NÃO é instalável por script — ${t.installHintWsl || t.installHint}`)
      }
      console.log("")
      console.log('echo "--- verificação ---"')
      for (const { tool } of scriptable) {
        const probe = tool.toolId.replace(/-headless$/, "")
        console.log(`command -v ${probe} >/dev/null 2>&1 && echo "OK    ${tool.toolId}" || echo "FALTA ${tool.toolId}"`)
      }
      process.exit(0)
    }

    console.log(`${BOLD}Ferramentas externas${RESET} ${DIM}(${tools.filter((t) => t.available).length}/${tools.length} disponíveis)${RESET}\n`)
    for (const t of shown) {
      const mark = t.available ? `${GREEN}✔${RESET}` : `${RED}✘${RESET}`
      console.log(`${mark} ${BOLD}${t.toolId}${RESET} ${DIM}— ${t.displayName}${RESET}`)
      if (!t.available) {
        console.log(`    ${DIM}origem esperada:${RESET} ${t.sourceLocation}`)
        console.log(`    ${BOLD}WSL2 Kali:${RESET} ${CYAN}${t.installHintWsl || t.installHint}${RESET}`)
      } else {
        console.log(`    ${DIM}${t.wslPath ?? t.resolvedPath}${RESET}`)
      }
    }
    if (shown.length === 0) {
      console.log(`${GREEN}Nada faltando — todas as ferramentas do catálogo estão resolvidas.${RESET}`)
    } else {
      console.log("")
      console.log(`${DIM}Para um script pronto: bun run cyberlab lab tools --script${RESET}`)
    }
    console.log("")
    console.log(`${YELLOW}Obs.:${RESET} nem tudo se resolve instalando.`)
    console.log(`${DIM}  - Burp Collaborator exige Burp Suite Professional (licença), não é instalável.${RESET}`)
    console.log(`${DIM}  - Slot de "payload list" aponta para wordlist, não para executável: é config, não instalação.${RESET}`)
    process.exit(0)
  }

  case "targets": {
    const profiles = listTargetProfiles()
    console.log(`${BOLD}Alvos externos com autorização declarada${RESET}\n`)
    if (profiles.length === 0) {
      console.log(`${YELLOW}Nenhum perfil cadastrado.${RESET}`)
      console.log(`${DIM}Perfil sem base de autorização explícita não entra nesta lista por decisão de projeto.${RESET}`)
      process.exit(0)
    }
    for (const p of profiles) {
      console.log(`  ${GREEN}${p.id}${RESET} — ${BOLD}${p.name}${RESET}`)
      console.log(`    ${DIM}Operador:${RESET} ${p.owner}`)
      console.log(`    ${DIM}Hosts   :${RESET} ${p.allowedHosts.join(", ")}`)
      console.log("")
      console.log(`    ${p.authorizationBasis}`)
      console.log("")
      for (const h of p.hypothesisBridge) {
        console.log(`    ${CYAN}${h.localHypothesisId}${RESET} ${DIM}${h.localHypothesis} →${RESET} ${h.targetTopic}`)
      }
      console.log("")
      console.log(`    ${BOLD}Gerar escopo:${RESET} bun run cyberlab lab scope ${p.id}`)
      console.log("")
    }
    process.exit(0)
  }

  case "scope": {
    const profileId = labIdArg
    if (!profileId) {
      console.error(`${RED}Informe o perfil (ex.: portswigger-wsa).${RESET}`)
      console.error(`${DIM}Perfis disponíveis: ${listTargetProfiles().map((p) => p.id).join(", ")}${RESET}`)
      process.exit(1)
    }
    const outDir = path.resolve(readFlag("--out") ?? path.join(resolveLabsRoot(), "targets", profileId))
    const result = writeTargetScope(profileId, outDir)
    if (!result) {
      console.error(`${RED}Perfil "${profileId}" não existe.${RESET}`)
      console.error(`${DIM}Perfis disponíveis: ${listTargetProfiles().map((p) => p.id).join(", ")}${RESET}`)
      process.exit(1)
    }
    console.log(`${GREEN}✔ Escopo do alvo gravado:${RESET}`)
    console.log(`    ${result.scopePath}`)
    console.log(`    ${result.rulesPath}`)
    console.log("")
    console.log(`${YELLOW}Antes de testar, confirme a autorização nos links de SCOPE.md.${RESET}`)
    console.log(`${DIM}Autorização presumida não existe — vale a que estiver escrita hoje.${RESET}`)
    process.exit(0)
  }

  case "evidence": {
    if (!labIdArg) {
      console.error(`${RED}Informe o labId.${RESET}`)
      process.exit(1)
    }
    if (labIdArg !== "lab-owasp-api-bola") {
      console.error(`${RED}O gravador de evidência cobre apenas "lab-owasp-api-bola" (recebido: ${labIdArg}).${RESET}`)
      process.exit(1)
    }

    const portFlag = readFlag("--port")
    const outFlag = readFlag("--out")
    let baseUrl = ""
    let workspaceRoot = manager.getLabWorkspacePath(labIdArg)
    let startedHere = false

    if (portFlag) {
      baseUrl = `http://127.0.0.1:${Number.parseInt(portFlag, 10)}`
      // Reaproveita o workspace do daemon (o kit precisa estar provisionado)
      if (!existsSync(path.join(workspaceRoot, "server-config.json"))) {
        console.error(`${RED}Nenhum lab provisionado em ${workspaceRoot}. Suba o lab antes (${BOLD}--daemon${RESET}) ou omita --port.${RESET}`)
        process.exit(1)
      }
    } else {
      // Sobe um servidor próprio em porta efêmera: nunca conflita com o daemon do operador.
      const status = await manager.startLab({ labId: labIdArg, preferredPort: 0, resetFiles: false })
      if (!status.baseUrl) {
        console.error(`${RED}Não foi possível subir o lab para coletar evidência.${RESET}`)
        process.exit(1)
      }
      baseUrl = status.baseUrl
      workspaceRoot = status.workspaceRoot ?? workspaceRoot
      startedHere = true
    }

    const stamp = new Date().toISOString().replace(/[:.]/g, "-")
    const outDir = path.resolve(outFlag ?? path.join(repoRoot, "evidence", labIdArg, stamp))

    console.log(`${BOLD}Coletando evidência E1–E7${RESET} em ${baseUrl}`)
    console.log(`${DIM}Saída: ${outDir}${RESET}\n`)

    const result = await runBolaEvidenceSuite({ baseUrl, outDir, workspaceRoot })

    const order = ["H1", "H2", "H3", "H4", "H1@remediado", "H2@remediado", "H3@remediado", "H4@remediado"]
    const icon: Record<string, string> = {
      vulneravel: `${RED}VULNERÁVEL${RESET}`,
      seguro: `${GREEN}SEGURO${RESET}`,
      remediado: `${GREEN}REMEDIADO${RESET}`,
      inconclusivo: `${YELLOW}INCONCLUSIVO${RESET}`,
    }
    for (const h of order) {
      const v = result.manifest.verdicts[h]
      if (v) console.log(`  ${BOLD}${h.padEnd(13)}${RESET} ${icon[v.verdict] ?? v.verdict}  ${DIM}${v.rationale}${RESET}`)
    }
    console.log("")
    console.log(`${GREEN}✔ ${result.manifest.cases.length} requisições arquivadas${RESET} em ${result.suiteDir}`)
    console.log(`  Manifesto : ${result.manifestPath}`)
    console.log(`  Relatório : ${result.reportPath}`)
    console.log(`  ${BOLD}Selo do lote (SHA-256 do manifest.json):${RESET}`)
    console.log(`    ${CYAN}${result.seal}${RESET}`)
    console.log("")
    console.log(`${DIM}Verificação (PowerShell): (Get-FileHash .\manifest.json -Algorithm SHA256).Hash.ToLower()${RESET}`)
    console.log(`${DIM}Verificação (WSL2/Linux): sha256sum manifest.json${RESET}`)

    if (args.includes("--register")) {
      const wsRoot = resolveWorkspaceRoot()
      const cfg = createDefaultCyberLabConfig(wsRoot)
      const store = new EvidenceStore({
        databasePath: cfg.databaseFilename,
        artifactsDir: cfg.artifactsDirectory,
      })
      try {
        const executionId = `lab-evidence-${stamp}`
        let n = 0
        for (const rec of result.manifest.cases) {
          store.storeEvidence(
            labIdArg,
            {
              kind: "http_exchange",
              title: `${rec.experimentId} — ${rec.label}`,
              source: { toolId: "cyberlab-lab-evidence", toolVersion: "6.7.0", executorId: "operator", executionId },
              content: {
                mediaType: "text/plain",
                inlineText: readFileSync(path.join(outDir, rec.file), "utf8"),
                sha256: rec.sha256,
                byteLength: rec.bytes,
              },
              observedAt: rec.capturedAt,
              labels: ["lab", labIdArg, rec.experimentId, `http-${rec.status}`],
            },
            { applyRedactionBeforeStore: false },
          )
          n += 1
        }
        console.log(`${GREEN}✔ ${n} evidências registradas no EvidenceStore${RESET} (projeto: ${labIdArg})`)
        console.log(`  ${DIM}Banco: ${cfg.databaseFilename}${RESET}`)
        console.log(`  ${DIM}O agente passa a enxergá-las via cyberlab_evidence_list.${RESET}`)
      } finally {
        store.close()
      }
      console.log("")
    }

    if (startedHere) await manager.stopLab(labIdArg)
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
