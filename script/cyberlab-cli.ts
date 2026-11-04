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
  "evidence",
  "findings",
  "report",
  "partner",
  "external",
])

const APP_SUBCOMMANDS = new Set(["start", "app", "up", "serve", "studio"])

/** Subcomandos de laboratório (v6.4) — tratados pelo script/start-cyberlab.ts / script/cyberlab-lab.ts. */
const LAB_SUBCOMMANDS = new Set(["lab", "labs", "laboratorio"])

const firstArg = args[0] ?? ""
const isHelp = firstArg === "--help" || firstArg === "-h" || firstArg === "help"
const shouldLaunchUnifiedApp =
  !isHelp &&
  (args.length === 0 ||
    APP_SUBCOMMANDS.has(firstArg) ||
    (!CLI_SUBCOMMANDS.has(firstArg) && firstArg.startsWith("-")))

if (LAB_SUBCOMMANDS.has(firstArg)) {
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
} else if (shouldLaunchUnifiedApp) {
  if (APP_SUBCOMMANDS.has(firstArg)) {
    process.argv = [process.argv[0]!, process.argv[1]!, ...args.slice(1)]
  }
  await import("./start-cyberlab.js")
} else {
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
