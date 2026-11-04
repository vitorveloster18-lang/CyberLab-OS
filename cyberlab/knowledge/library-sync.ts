/**
 * CyberLab OS — Sincronização do Cofre Curado (v6.7).
 *
 * Problema que isto resolve: `ensureKnowledgeLibrarySeeded()` só escreve quando o
 * arquivo NÃO existe (`if (!existsSync(dest))`). Consequência medida em campo:
 * o operador tinha 39 arquivos no cofre (os docs novos entraram), mas o
 * `00-Index.md` continuava sendo a cópia da v6.2 — o agente lia um mapa
 * desatualizado e subestimava a própria biblioteca.
 *
 * Política desta sincronização:
 *  - **Só toca em documento curado** (`tier: curated`). O que é do operador
 *    (`_drafts/`, `Investigacoes/`, notas pessoais, qualquer `tier` diferente)
 *    nunca é lido, quanto mais escrito.
 *  - Compara `version` + `last_reviewed` do frontmatter. Status, não palpite.
 *  - Antes de substituir, grava um backup `.bak` ao lado.
 *  - `--apply` é obrigatório para escrever. Sem ele, devolve só o PLANO.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import { CURATED_KNOWLEDGE_FILES } from "./curated-library.js"

export type SyncAction = "create" | "update" | "skip" | "protected"

export interface SyncPlanItem {
  /** Caminho relativo dentro de `CyberLab-Knowledge/`. */
  relativePath: string
  action: SyncAction
  /** Versão que está no cofre do operador. */
  currentVersion?: string
  currentLastReviewed?: string
  /** Versão que o código traz. */
  incomingVersion?: string
  incomingLastReviewed?: string
  /** Motivo em linguagem direta (mostrado ao operador). */
  reason: string
  /** Caminho do backup que será criado (apenas em `update`). */
  backupPath?: string
}

export interface SyncPlan {
  vaultRoot: string
  generatedAt: string
  items: SyncPlanItem[]
  counts: Record<SyncAction, number>
}

export interface SyncApplyResult extends SyncPlan {
  applied: string[]
  backups: string[]
  skipped: string[]
  blocked: string[]
}

/** Lê os campos que interessam do frontmatter YAML sem dependências externas. */
export function parseFrontmatterFields(content: string): {
  tier?: string
  version?: string
  last_reviewed?: string
  status?: string
} {
  const out: Record<string, string> = {}
  if (!content.startsWith("---")) return out
  const end = content.indexOf("\n---", 3)
  if (end < 0) return out
  const block = content.slice(3, end)
  for (const line of block.split("\n")) {
    const m = /^([a-z_]+)\s*:\s*(.*)$/.exec(line.trim())
    if (!m) continue
    const key = m[1]!
    const raw = m[2]!.trim().replace(/^["']|["']$/g, "")
    if (["tier", "version", "last_reviewed", "status"].includes(key) && raw) out[key] = raw
  }
  return out
}

/**
 * Calcula o plano. Não escreve nada.
 * `protectedReason` marca arquivos que parecem editados pelo operador: se o arquivo
 * no cofre NÃO é `tier: curated`, ele está fora do alcance desta sincronização.
 */
export function planKnowledgeLibrarySync(vaultRoot: string): SyncPlan {
  // `vaultRoot` é a pasta que CONTÉM `CyberLab-Knowledge/` — mesma convenção de
  // `ensureKnowledgeLibrarySeeded()` (ex.: `<workspace>/vault`).
  const items: SyncPlanItem[] = []

  for (const doc of CURATED_KNOWLEDGE_FILES) {
    const dest = path.join(vaultRoot, ...doc.relativePath.split("/"))
    const incoming = parseFrontmatterFields(doc.content)
    const rel = doc.relativePath.replace(/^CyberLab-Knowledge\//, "")

    if (!existsSync(dest)) {
      items.push({
        relativePath: rel,
        action: "create",
        incomingVersion: incoming.version,
        incomingLastReviewed: incoming.last_reviewed,
        reason: "Arquivo ausente no cofre — será criado (comportamento padrão da semeadura).",
      })
      continue
    }

    let onDisk = ""
    try {
      onDisk = readFileSync(dest, "utf8")
    } catch {
      items.push({
        relativePath: rel,
        action: "skip",
        reason: "Não foi possível ler o arquivo existente — nada será feito.",
      })
      continue
    }

    const current = parseFrontmatterFields(onDisk)

    // Regra de segurança: só mexo em documento que se declara curado.
    if (current.tier && current.tier !== "curated") {
      items.push({
        relativePath: rel,
        action: "protected",
        currentVersion: current.version,
        reason: `Arquivo do operador (tier: ${current.tier}) — preservado, esta sincronização não o toca.`,
      })
      continue
    }

    const sameVersion = current.version === incoming.version
    const sameReview = current.last_reviewed === incoming.last_reviewed

    if (sameVersion && sameReview) {
      items.push({
        relativePath: rel,
        action: "skip",
        currentVersion: current.version,
        currentLastReviewed: current.last_reviewed,
        incomingVersion: incoming.version,
        incomingLastReviewed: incoming.last_reviewed,
        reason: "Já está na versão do código.",
      })
      continue
    }

    items.push({
      relativePath: rel,
      action: "update",
      currentVersion: current.version,
      currentLastReviewed: current.last_reviewed,
      incomingVersion: incoming.version,
      incomingLastReviewed: incoming.last_reviewed,
      reason: `Desatualizado: cofre tem v${current.version ?? "?"} (rev ${current.last_reviewed ?? "?"}) e o código traz v${incoming.version ?? "?"} (rev ${incoming.last_reviewed ?? "?"}).`,
      backupPath: `${dest}.bak`,
    })
  }

  const counts: Record<SyncAction, number> = { create: 0, update: 0, skip: 0, protected: 0 }
  for (const it of items) counts[it.action] += 1

  return {
    vaultRoot,
    generatedAt: new Date().toISOString(),
    items,
    counts,
  }
}

/** Aplica o plano, sempre com backup antes de substituir. */
export function applyKnowledgeLibrarySync(plan: SyncPlan): SyncApplyResult {
  const applied: string[] = []
  const backups: string[] = []
  const skipped: string[] = []
  const blocked: string[] = []

  for (const item of plan.items) {
    if (item.action === "skip") {
      skipped.push(item.relativePath)
      continue
    }
    if (item.action === "protected") {
      blocked.push(item.relativePath)
      continue
    }

    const doc = CURATED_KNOWLEDGE_FILES.find(
      (d) => d.relativePath.replace(/^CyberLab-Knowledge\//, "") === item.relativePath,
    )
    if (!doc) continue

    const dest = path.join(plan.vaultRoot, ...doc.relativePath.split("/"))

    if (item.action === "update" && existsSync(dest)) {
      try {
        writeFileSync(`${dest}.bak`, readFileSync(dest), "utf8")
        backups.push(`${item.relativePath}.bak`)
      } catch {
        // Se não conseguir fazer backup, NÃO arrisca sobrescrever.
        blocked.push(item.relativePath)
        continue
      }
    }

    mkdirSync(path.dirname(dest), { recursive: true })
    writeFileSync(dest, doc.content, "utf8")
    applied.push(item.relativePath)
  }

  return { ...plan, applied, backups, skipped, blocked }
}

export function renderSyncPlan(plan: SyncPlan): string {
  const lines: string[] = []
  lines.push("# Sincronização da Biblioteca Curada — PLANO (nada foi escrito)")
  lines.push("")
  lines.push(`- **Cofre**: \`${plan.vaultRoot}\``)
  lines.push(`- **Gerado em**: ${plan.generatedAt}`)
  lines.push(
    `- **Resumo**: ${plan.counts.create} criar, ${plan.counts.update} atualizar, ` +
      `${plan.counts.skip} já em dia, ${plan.counts.protected} protegidos (do operador)`,
  )
  lines.push("")

  for (const action of ["update", "create", "protected", "skip"] as SyncAction[]) {
    const group = plan.items.filter((i) => i.action === action)
    if (group.length === 0) continue
    const title: Record<SyncAction, string> = {
      update: "🔄 Serão ATUALIZADOS (com backup .bak)",
      create: "➕ Serão CRIADOS",
      protected: "🛡️ PROTEGIDOS — são do operador, não serão tocados",
      skip: "✅ Já estão na versão do código",
    }
    lines.push(`## ${title[action]} (${group.length})`)
    for (const it of group) {
      const ver =
        it.currentVersion && it.incomingVersion
          ? `  \`v${it.currentVersion}\` → \`v${it.incomingVersion}\``
          : it.incomingVersion
            ? `  \`v${it.incomingVersion}\``
            : ""
      lines.push(`- \`${it.relativePath}\`${ver}`)
      lines.push(`  - ${it.reason}`)
    }
    lines.push("")
  }

  lines.push("> Para aplicar: `bun run cyberlab knowledge --apply`")
  lines.push("> Cada arquivo atualizado ganha um `.bak` antes de ser substituído.")
  return lines.join("\n")
}
