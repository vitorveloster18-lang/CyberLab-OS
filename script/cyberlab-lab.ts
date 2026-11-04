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
      "  stop   <labId>           Derruba o servidor do lab",
      "  status [labId]           Mostra status detalhado (controles, requisições recentes)",
      "  kit    <labId>           Gera apenas os arquivos das Fases B/D/F (sem subir servidor)",
      "  seed   <labId>           Grava missão/escopo/modelo/hipóteses na memória investigativa",
      "  model  <labId> [--json]  Imprime o modelo do sistema (Fase B)",
      "",
      "Opções de start:",
      "  --port <n>               Porta preferida (padrão: hint do catálogo)",
      "  --reset                  Regrava os arquivos do lab antes de subir",
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

const command = (args[0] ?? "").toLowerCase()
const labIdArg = args.find((a, i) => i > 0 && !a.startsWith("--")) ?? ""

if (!command || command === "help" || command === "--help" || command === "-h") {
  usage()
  process.exit(0)
}

const manager = new TrainingLabManager(resolveLabsRoot())

function printStatus(status: ReturnType<TrainingLabManager["getLabStatus"]>): void {
  const state = status.running
    ? `${GREEN}RODANDO${RESET}`
    : status.provisioned
      ? `${YELLOW}PROVISIONADO (servidor parado)${RESET}`
      : `${DIM}NÃO PROVISIONADO${RESET}`
  console.log(`${BOLD}${status.labId}${RESET} — ${state}`)
  console.log(`  Título     : ${status.title}`)
  console.log(`  Dificuldade: ${status.difficulty}`)
  console.log(`  Workspace  : ${status.workspaceRoot}`)
  if (status.baseUrl) console.log(`  URL base   : ${CYAN}${status.baseUrl}${RESET}`)
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
    printStatus(await manager.stopLab(labIdArg))
    process.exit(0)
  }

  case "status": {
    const targets = labIdArg ? [labIdArg] : manager.listLabs().map((s) => s.labId)
    for (const id of targets) {
      printStatus(manager.getLabStatus(id))
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
