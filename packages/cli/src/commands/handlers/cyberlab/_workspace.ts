import { CyberLabWorkspaceManager } from "@cyberlab/core"
import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"

/**
 * Resolve o projectId do workspace local.
 *
 * ANTES: `proj-<basename do cwd>` (ex.: `proj-cli`). O servidor/TUI usa o ID
 * do projeto OpenCode (hash do remoto git), então o CLI e o MCP partiam o
 * MESMO banco SQLite em duas partições: evidência do `cyberlab exec` ficava
 * invisível para `cyberlab_evidence_list`/`finding_propose` do MCP.
 *
 * AGORA: replica a resolução do OpenCode (packages/core/src/project.ts),
 * na mesma ordem — remoto git, cache `.git/opencode`, root commit, hash do
 * diretório — para CLI e servidor concordarem no ID sem configuração.
 *
 * Fica separado de `openLocalCyberLabWorkspace` porque os comandos de execução
 * precisam do ID para falar com o ScopeController e o EvidenceStore — antes
 * essa informação era calculada e descartada dentro do helper.
 */
export function resolveLocalCyberLabProjectId(
  cwd = process.env.CYBERLAB_WORKSPACE_ROOT?.trim() || process.cwd(),
): string {
  const envOverride = process.env.CYBERLAB_PROJECT_ID?.trim()
  if (envOverride) return envOverride

  const resolved = path.resolve(cwd)

  // 1. Repositório git: remoto → cache → root commit (mesma ordem do servidor).
  const gitId = resolveGitProjectId(resolved)
  if (gitId) return gitId

  // 2. Repositório hg: cache `.hg/opencode`.
  const hgId = resolveHgProjectId(resolved)
  if (hgId) return hgId

  // 3. Sem VCS: hash do diretório (igual ao fallback do servidor).
  return sha1Hex(`directory:${resolved}`)
}

function sha1Hex(input: string): string {
  return createHash("sha1").update(input).digest("hex")
}

function gitOut(cwd: string, args: string[]): string | undefined {
  try {
    const out = execFileSync("git", ["-C", cwd, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5_000,
    })
    return out.trim() || undefined
  } catch {
    return undefined
  }
}

/** Normaliza URL de remoto igual ao OpenCode: `host/path` sem `.git` final. */
function normalizeRemoteUrl(raw: string): string | undefined {
  const value = raw.trim()
  if (!value) return undefined
  const parsed = URL.parse(value)
  if (parsed) {
    if (parsed.protocol === "file:") return undefined
    return parts(parsed.hostname, parsed.pathname)
  }
  const scp = value.match(/^([^@/:]+@)?([^/:]+):(.+)$/)
  if (scp) return parts(scp[2]!, scp[3]!)
  return undefined
}

function parts(host: string, name: string): string | undefined {
  const pathname = name
    .replace(/^\/+/, "")
    .replace(/\.git\/?$/, "")
    .replace(/\/+$/, "")
  if (!host || !pathname) return undefined
  return `${host.toLowerCase()}/${pathname}`
}

function resolveGitProjectId(cwd: string): string | undefined {
  // Só tenta se houver um `.git` em algum ancestral (evita spawnar git à toa).
  if (!findUp(cwd, ".git")) return undefined

  // a) Remoto origin → sha1("git-remote:<host>/<path>")
  const origin = gitOut(cwd, ["remote", "get-url", "origin"])
  if (origin) {
    const normalized = normalizeRemoteUrl(origin)
    if (normalized) return sha1Hex(`git-remote:${normalized}`)
  }

  // b) Cache gravado pelo servidor em <git-common-dir>/opencode.
  const commonDir = gitOut(cwd, ["rev-parse", "--git-common-dir"])
  if (commonDir) {
    const cached = readCachedProjectId(path.resolve(cwd, commonDir))
    if (cached) return cached
  }

  // c) Root commit do repositório.
  const roots = gitOut(cwd, ["rev-list", "--max-parents=0", "HEAD"])
  if (roots) {
    const root = roots.split("\n").map((l) => l.trim()).filter(Boolean).sort()[0]
    if (root) return root
  }

  return undefined
}

function resolveHgProjectId(cwd: string): string | undefined {
  const hgDir = findUp(cwd, ".hg")
  if (!hgDir) return undefined
  return readCachedProjectId(hgDir)
}

function readCachedProjectId(dir: string): string | undefined {
  try {
    const file = path.join(dir, "opencode")
    if (!existsSync(file)) return undefined
    const value = readFileSync(file, "utf8").trim()
    return value || undefined
  } catch {
    return undefined
  }
}

/** Sobe a árvore procurando `name` (arquivo ou diretório). */
function findUp(start: string, name: string): string | undefined {
  let current = path.resolve(start)
  for (;;) {
    const candidate = path.join(current, name)
    if (existsSync(candidate)) return candidate
    const parent = path.dirname(current)
    if (parent === current) return undefined
    current = parent
  }
}

export async function openLocalCyberLabWorkspace(
  cwd = process.env.CYBERLAB_WORKSPACE_ROOT?.trim() || process.cwd(),
) {
  const resolved = path.resolve(cwd)
  return CyberLabWorkspaceManager.global.forProject(resolveLocalCyberLabProjectId(resolved), resolved)
}
