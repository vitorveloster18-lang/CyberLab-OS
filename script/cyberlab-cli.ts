#!/usr/bin/env bun

import { spawnSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const cliDir = path.join(repoRoot, "packages", "cli")
const args = process.argv.slice(2)

const CLI_SUBCOMMANDS = new Set([
  "status",
  "capabilities",
  "run",
  "exec",
  "scope",
  "evidence",
  "findings",
  "report",
  "partner",
])

/** Subcomandos de laboratório (v6.4) — tratados pelo script/cyberlab-lab.ts. */
const LAB_SUBCOMMANDS = new Set(["lab", "labs", "laboratorio"])

const KNOWLEDGE_SUBCOMMANDS = new Set(["knowledge", "conhecimento", "vault", "cofre"])

const firstArg = args[0] ?? ""

if (KNOWLEDGE_SUBCOMMANDS.has(firstArg)) {
  const res = spawnSync(process.execPath, ["run", "script/cyberlab-knowledge.ts", ...args.slice(1)], {
    cwd: repoRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      CYBERLAB_WORKSPACE_ROOT: process.env.CYBERLAB_WORKSPACE_ROOT || process.cwd(),
    },
  })
  process.exit(res.status ?? 1)
} else if (LAB_SUBCOMMANDS.has(firstArg)) {
  const labArgs = args.slice(1)
  const res = spawnSync(process.execPath, ["run", "script/cyberlab-lab.ts", ...labArgs], {
    cwd: repoRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      CYBERLAB_WORKSPACE_ROOT: process.env.CYBERLAB_WORKSPACE_ROOT || process.cwd(),
    },
  })
  process.exit(res.status ?? 1)
} else {
  // Sem argumentos o CyberLab mostra a propria ajuda no terminal: nada de subir
  // servidor web a escondidas.
  const res = spawnSync(process.execPath, ["run", "src/index.ts", "cyberlab", ...args], {
    cwd: cliDir,
    stdio: "inherit",
    env: {
      ...process.env,
      CYBERLAB_WORKSPACE_ROOT: process.env.CYBERLAB_WORKSPACE_ROOT || process.cwd(),
    },
  })

  process.exit(res.status ?? 1)
}
