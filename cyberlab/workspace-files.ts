import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import path from "node:path"

import { isPathInsideRoot } from "./policy/scope.js"

export interface WorkspaceFileEntry {
  name: string
  relativePath: string
  kind: "directory" | "file"
  sizeBytes: number
  modifiedAt: string
}

/**
 * Navegação de arquivos do workspace.
 *
 * Estas duas funções viviam dentro do ArsenalSlotManager, mas nunca foram
 * sobre ferramentas: são só listagem e preview de arquivo, usadas pela API de
 * navegador de arquivos. Com o arsenal removido, elas ficam aqui — porque
 * continuam sendo necessárias e não dependem de nada do arsenal.
 *
 * Ambas validam o caminho contra a raiz do workspace antes de tocar no disco.
 */

export function listWorkspaceFiles(
  workspaceRoot: string,
  relativeDir = ".",
): { currentDir: string; entries: WorkspaceFileEntry[] } {
  const cleanRel = relativeDir.trim() || "."
  if (!isPathInsideRoot(cleanRel, workspaceRoot)) {
    throw new Error(`Diretório fora do escopo do projeto: ${cleanRel}`)
  }
  const absDir = path.resolve(workspaceRoot, cleanRel)
  if (!existsSync(absDir)) {
    return { currentDir: cleanRel.replace(/\\/g, "/"), entries: [] }
  }
  const rawEntries = readdirSync(absDir, { withFileTypes: true })
  const entries: WorkspaceFileEntry[] = []
  for (const ent of rawEntries) {
    if (ent.name === "node_modules" || ent.name === ".git") continue
    const full = path.join(absDir, ent.name)
    const st = statSync(full, { throwIfNoEntry: false })
    if (!st) continue
    entries.push({
      name: ent.name,
      relativePath: path.relative(workspaceRoot, full).replace(/\\/g, "/"),
      kind: ent.isDirectory() ? "directory" : "file",
      sizeBytes: ent.isDirectory() ? 0 : st.size,
      modifiedAt: st.mtime.toISOString(),
    })
  }
  entries.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === "directory" ? -1 : 1
    return a.name.localeCompare(b.name)
  })
  return {
    currentDir: path.relative(workspaceRoot, absDir).replace(/\\/g, "/") || ".",
    entries: entries.slice(0, 300),
  }
}

export function readWorkspaceFilePreview(
  workspaceRoot: string,
  relativeFilePath: string,
  maxBytes = 128 * 1024,
): { relativePath: string; sizeBytes: number; truncated: boolean; content: string } {
  if (!isPathInsideRoot(relativeFilePath, workspaceRoot)) {
    throw new Error(`Arquivo fora do escopo autorizado: ${relativeFilePath}`)
  }
  const abs = path.resolve(workspaceRoot, relativeFilePath)
  if (!existsSync(abs)) {
    throw new Error(`Arquivo não encontrado: ${relativeFilePath}`)
  }
  const st = statSync(abs)
  if (st.isDirectory()) {
    throw new Error(`O caminho é um diretório: ${relativeFilePath}`)
  }
  const raw = readFileSync(abs)
  const slice = raw.byteLength > maxBytes ? raw.subarray(0, maxBytes) : raw
  return {
    relativePath: path.relative(workspaceRoot, abs).replace(/\\/g, "/"),
    sizeBytes: st.size,
    truncated: raw.byteLength > maxBytes,
    content: slice.toString("utf8"),
  }
}
