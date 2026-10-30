import { existsSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import type { CapabilityDefinition, CapabilityRegistry } from "../contracts/capability.js"

export interface CyberLabSkillDescriptor {
  id: string
  name: string
  description: string
  skillFilePath: string
  companionFiles: string[]
  content: string
  /** Skills are strictly guidance; grantsExecutionPrivileges is always false. */
  readonly grantsExecutionPrivileges: false
}

function parseSimpleFrontmatter(raw: string): { data: Record<string, string>; body: string } {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(raw)
  if (!match) {
    return { data: {}, body: raw }
  }
  const front = match[1] ?? ""
  const body = match[2] ?? ""
  const data: Record<string, string> = {}
  for (const line of front.split(/\r?\n/)) {
    const colon = line.indexOf(":")
    if (colon <= 0) continue
    const key = line.slice(0, colon).trim()
    const val = line
      .slice(colon + 1)
      .trim()
      .replace(/^["']|["']$/g, "")
    if (key) data[key] = val
  }
  return { data, body }
}

export class CyberLabSkillCatalog {
  private readonly skills = new Map<string, CyberLabSkillDescriptor>()

  loadFromDirectory(skillsRoot: string): CyberLabSkillDescriptor[] {
    const root = path.resolve(skillsRoot)
    if (!existsSync(root)) return []

    const loaded: CyberLabSkillDescriptor[] = []
    for (const entry of readdirSync(root, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) continue
      const dirPath = path.join(root, entry.name)
      const skillMd = path.join(dirPath, "SKILL.md")
      if (!existsSync(skillMd)) continue

      const raw = readFileSync(skillMd, "utf8")
      const parsed = parseSimpleFrontmatter(raw)
      const companionFiles = readdirSync(dirPath, { withFileTypes: true })
        .filter((f) => f.isFile() && f.name !== "SKILL.md" && !f.name.startsWith("."))
        .map((f) => path.join(dirPath, f.name))
        .sort()

      const descriptor: CyberLabSkillDescriptor = {
        id: entry.name,
        name: parsed.data["name"] || entry.name,
        description: parsed.data["description"] || `CyberLab operational skill: ${entry.name}`,
        skillFilePath: skillMd,
        companionFiles,
        content: parsed.body.trim(),
        grantsExecutionPrivileges: false,
      }
      this.skills.set(descriptor.id, descriptor)
      loaded.push(descriptor)
    }

    return loaded.sort((a, b) => a.id.localeCompare(b.id))
  }

  list(): CyberLabSkillDescriptor[] {
    return Array.from(this.skills.values()).sort((a, b) => a.id.localeCompare(b.id))
  }

  get(skillId: string): CyberLabSkillDescriptor | undefined {
    return this.skills.get(skillId)
  }

  async capabilitiesForSkill(skillId: string, registry: CapabilityRegistry): Promise<CapabilityDefinition[]> {
    const all = await registry.list()
    return all.filter((cap) => cap.skillIds.includes(skillId))
  }
}
