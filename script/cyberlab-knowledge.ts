#!/usr/bin/env bun
/**
 * CyberLab OS — `cyberlab knowledge` (v6.7).
 *
 * Mostra o plano de sincronização da biblioteca curada (padrão) e só escreve com
 * `--apply`. Nunca toca em arquivo do operador.
 *
 *   bun run cyberlab knowledge                 # plano (não escreve nada)
 *   bun run cyberlab knowledge --apply         # aplica, com .bak antes de cada troca
 *   bun run cyberlab knowledge --json          # plano em JSON
 */

import { existsSync, mkdirSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { ensureKnowledgeLibrarySeeded } from "../cyberlab/knowledge/curated-library.js"
import {
  applyKnowledgeLibrarySync,
  planKnowledgeLibrarySync,
  renderSyncPlan,
} from "../cyberlab/knowledge/library-sync.js"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const args = process.argv.slice(2)

const GREEN = "\x1b[32m"
const YELLOW = "\x1b[33m"
const RED = "\x1b[31m"
const DIM = "\x1b[2m"
const RESET = "\x1b[0m"
const BOLD = "\x1b[1m"

/**
 * A semeadura (`ensureKnowledgeLibrarySeeded`) e o plano (`planKnowledgeLibrarySync`)
 * esperam a pasta que CONTÉM `CyberLab-Knowledge/`, não a pasta interna. Aceitamos
 * os dois jeitos para não punir quem apontar direto para dentro.
 */
function normalizeVaultRoot(dir: string): string {
  const abs = path.resolve(dir)
  if (existsSync(path.join(abs, "CyberLab-Knowledge"))) return abs
  if (path.basename(abs) === "CyberLab-Knowledge") return path.dirname(abs)
  return abs
}

function resolveVaultRoot(): string {
  const explicit = process.env.CYBERLAB_VAULT_ROOT?.trim()
  if (explicit) return normalizeVaultRoot(explicit)
  const ws = path.resolve(process.env.CYBERLAB_WORKSPACE_ROOT?.trim() || process.cwd())
  return path.join(ws, "vault")
}

const vaultRoot = resolveVaultRoot()
const apply = args.includes("--apply")
const asJson = args.includes("--json")

if (args.includes("--help") || args.includes("-h")) {
  console.log(
    [
      `${BOLD}cyberlab knowledge${RESET} — sincroniza os documentos curados no cofre`,
      "",
      "Uso: bun run cyberlab knowledge [--apply] [--json]",
      "",
      "  (padrão)   Mostra o PLANO. Não escreve nada.",
      "  --apply    Aplica. Cada arquivo substituído ganha um .bak antes.",
      "  --json     Plano em JSON.",
      "",
      "Nunca toca em: _drafts/, Investigações do operador, ou qualquer arquivo",
      "cujo frontmatter não seja `tier: curated`.",
      "",
    ].join("\n"),
  )
  process.exit(0)
}

if (!existsSync(path.join(vaultRoot, "CyberLab-Knowledge"))) {
  // Sem a interface web, o cofre é semeado aqui mesmo: idempotente, nunca sobrescreve
  // uma nota que o operador já tenha editado.
  mkdirSync(vaultRoot, { recursive: true })
  ensureKnowledgeLibrarySeeded(vaultRoot)
  console.log(`${GREEN}Cofre semeado:${RESET} ${vaultRoot}`)
}

const plan = planKnowledgeLibrarySync(vaultRoot)

if (asJson) {
  console.log(JSON.stringify(plan, null, 2))
  process.exit(0)
}

if (!apply) {
  console.log(renderSyncPlan(plan))
  console.log("")
  if (plan.counts.update + plan.counts.create === 0) {
    console.log(`${GREEN}✔ Nada a sincronizar — o cofre já reflete a versão do código.${RESET}`)
  } else {
    console.log(
      `${YELLOW}Nada foi escrito.${RESET} Para aplicar: ${BOLD}bun run cyberlab knowledge --apply${RESET}`,
    )
  }
  process.exit(0)
}

const result = applyKnowledgeLibrarySync(plan)
console.log(`${BOLD}Aplicando sincronização da biblioteca curada${RESET}`)
console.log(`  Cofre    : ${result.vaultRoot}`)
console.log(`  Criados  : ${GREEN}${result.applied.length}${RESET}`)
console.log(`  Backups  : ${result.backups.length}`)
console.log(`  Protegidos (do operador, intocados): ${result.blocked.length}`)
console.log("")
for (const f of result.applied) console.log(`  ${GREEN}✓${RESET} ${f}`)
for (const b of result.backups) console.log(`  ${DIM}backup: ${b}${RESET}`)
if (result.blocked.length > 0) {
  console.log("")
  console.log(
    `${RED}NÃO foram alterados (são do operador ou não foi possível fazer backup):${RESET}`,
  )
  for (const b of result.blocked) console.log(`  ${YELLOW}!${RESET} ${b}`)
}
console.log("")
if (result.backups.length > 0) {
  console.log(
    `${DIM}Para desfazer: renomeie os .bak de volta (estão ao lado de cada arquivo).${RESET}`,
  )
}
process.exit(0)
