import { CyberLabWorkspaceManager } from "@cyberlab/core"
import path from "node:path"

export async function openLocalCyberLabWorkspace(cwd = process.cwd()) {
  const resolved = path.resolve(cwd)
  const projectId = `proj-${path.basename(resolved).replace(/[^a-zA-Z0-9._-]/g, "-") || "workspace"}`
  return CyberLabWorkspaceManager.global.forProject(projectId, resolved)
}
