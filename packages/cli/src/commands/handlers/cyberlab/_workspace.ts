import { CyberLabWorkspaceManager } from "@cyberlab/core"
import path from "node:path"

/**
 * Resolve o projectId do workspace local.
 *
 * Fica separado de `openLocalCyberLabWorkspace` porque os comandos de execução
 * precisam do ID para falar com o ScopeController e o EvidenceStore — antes
 * essa informação era calculada e descartada dentro do helper.
 */
export function resolveLocalCyberLabProjectId(
  cwd = process.env.CYBERLAB_WORKSPACE_ROOT?.trim() || process.cwd(),
): string {
  const resolved = path.resolve(cwd)
  return (
    process.env.CYBERLAB_PROJECT_ID?.trim() ||
    `proj-${path.basename(resolved).replace(/[^a-zA-Z0-9._-]/g, "-") || "workspace"}`
  )
}

export async function openLocalCyberLabWorkspace(
  cwd = process.env.CYBERLAB_WORKSPACE_ROOT?.trim() || process.cwd(),
) {
  const resolved = path.resolve(cwd)
  return CyberLabWorkspaceManager.global.forProject(resolveLocalCyberLabProjectId(resolved), resolved)
}
