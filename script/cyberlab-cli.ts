#!/usr/bin/env bun

import { spawnSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const cliDir = path.join(repoRoot, "packages", "cli")
const args = process.argv.slice(2)

const res = spawnSync(process.execPath, ["run", "src/index.ts", "cyberlab", ...args], {
  cwd: cliDir,
  stdio: "inherit",
  env: {
    ...process.env,
    CYBERLAB_WORKSPACE_ROOT: process.env.CYBERLAB_WORKSPACE_ROOT || process.cwd(),
  },
})

process.exit(res.status ?? 1)
