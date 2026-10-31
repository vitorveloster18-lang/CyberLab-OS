import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs"
import os from "node:os"
import path from "node:path"
import { isPathInsideRoot } from "../policy/scope.js"

export interface VaultNoteSummary {
  relativePath: string
  title: string
  folder: string
  tags: string[]
  wikiLinks: string[]
  snippet: string
  sizeBytes: number
  updatedAt: string
}

export interface VaultOverview {
  vaultRootDir: string
  isCustomPath: boolean
  notes: VaultNoteSummary[]
  allTags: string[]
}

export interface VaultNoteDocument {
  relativePath: string
  title: string
  content: string
  tags: string[]
  wikiLinks: string[]
  backlinks: string[]
  updatedAt: string
}

interface PersistedVaultConfig {
  customVaultRootByProject: Record<string, string>
}

const MAX_VAULT_FILES = 600
const MAX_NOTE_BYTES = 1_048_576 // 1 MB per markdown note

function normalizeVaultRelPath(raw: string): string {
  const cleaned = raw
    .replace(/\\/g, "/")
    .trim()
    .replace(/^\/+/, "")
    .replace(/\/+/g, "/")
  if (!cleaned) {
    throw new Error("O caminho da nota não pode ser vazio.")
  }
  if (cleaned.includes("\0") || cleaned.split("/").some((seg) => seg === "." || seg === "..")) {
    throw new Error(`Caminho de nota inválido: ${raw}`)
  }
  const withExt = cleaned.toLowerCase().endsWith(".md") ? cleaned : `${cleaned}.md`
  const parts = withExt.split("/").map((seg) => {
    const trimmed = seg.trim()
    if (!trimmed || /[<>:"|?*]/.test(trimmed)) {
      throw new Error(`Segmento inválido no nome da nota: ${seg}`)
    }
    return trimmed
  })
  return parts.join("/")
}

export function extractMarkdownTags(markdown: string): string[] {
  // Strip fenced code blocks before scanning hashtags so bash comments `# comment` aren't treated as tags
  const withoutCode = markdown.replace(/```[\s\S]*?```/g, "")
  const tags = new Set<string>()
  const regex = /(?:^|[\s(])#([a-zA-ZÀ-ÿ0-9_-]{2,40})\b/g
  let m: RegExpExecArray | null
  while ((m = regex.exec(withoutCode)) !== null) {
    if (m[1]) tags.add(m[1].toLowerCase())
  }
  return Array.from(tags).sort()
}

export function extractWikiLinks(markdown: string): string[] {
  const withoutCode = markdown.replace(/```[\s\S]*?```/g, "")
  const links = new Set<string>()
  const regex = /\[\[([^\]|#\n]+)(?:[|#][^\]]*)?\]\]/g
  let m: RegExpExecArray | null
  while ((m = regex.exec(withoutCode)) !== null) {
    const target = m[1]?.trim()
    if (target) links.add(target)
  }
  return Array.from(links)
}

function deriveNoteTitle(relativePath: string, content: string): string {
  const h1 = content.match(/^#\s+(.+)$/m)
  if (h1?.[1]?.trim()) return h1[1].trim().slice(0, 120)
  const base = path.posix.basename(relativePath, ".md")
  return base
}

function buildSnippet(content: string): string {
  const plain = content
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/^#+\s+/gm, "")
    .replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, (_all, a, b) => String(b || a))
    .replace(/\s+/g, " ")
    .trim()
  return plain.slice(0, 160)
}

function wikiTargetMatchesNote(wikiTarget: string, noteRelPath: string): boolean {
  const normTarget = wikiTarget.replace(/\\/g, "/").trim().replace(/\.md$/i, "").toLowerCase()
  const normRelNoExt = noteRelPath.replace(/\.md$/i, "").toLowerCase()
  const normBase = path.posix.basename(normRelNoExt)
  return normTarget === normRelNoExt || normTarget === normBase
}

const STARTER_VAULT_NOTES: Array<{ relativePath: string; content: string }> = [
  {
    relativePath: "00-Indice-CyberLab.md",
    content: `# Cofre CyberLab OS (Obsidian Vault)

#cyberlab #indice #workflow

Bem-vindo ao seu **Cofre de Notas & Comandos** integrado ao **CyberLab OS**!
Todas as notas são arquivos \`.md\` reais compatíveis 100% com o **Obsidian** — você pode usar \`[[WikiLinks]]\`, \`#tags\`, listas \`- [ ]\` clicáveis e blocos de comando com **injeção em 1 clique** direto no Slot CLI ativo sem sair da ferramenta aberta no centro.

## Atalhos Principais do Cofre
- [[Comandos-Rapidos]] — Biblioteca de comandos prontos (\`ncat\`, \`dirsearch\`, \`nuclei\`, \`ffuf\`, \`nmap\`, \`sqlmap\`)
- [[Checklist-Bug-Bounty]] — Metodologia prática de recon, API/BOLA, OAuth e custódia \`SHA-256\`
- [[Diario-Labs]] — Registro de portas, tokens de treino e anotações dos 5 Laboratórios Internos

## Como usar os blocos de comando
Em qualquer bloco \`\`\`bash abaixo ou nas suas notas, clique em **⚡ Injetar no CLI** na visualização para enviar o comando direto para a ferramenta correspondente sem fechar sua tela central!
`,
  },
  {
    relativePath: "Comandos/Comandos-Rapidos.md",
    content: `# Biblioteca de Comandos Rápidos

#comandos #cheatsheet #cli #kali

Use \`{target}\` e \`{workspace}\` nos argumentos para aproveitar a substituição automática do CyberLab OS. Relacionado a [[00-Indice-CyberLab]] e [[Checklist-Bug-Bounty]].

## Netcat / Ncat (Diagnóstico TCP & SSL)
\`\`\`bash
ncat -zv -w 4 {target}
\`\`\`

\`\`\`bash
ncat --ssl -zv -w 5 {target}
\`\`\`

## Dirsearch (Descoberta de Rotas & Diretórios Web)
\`\`\`bash
dirsearch -u {target} -e php,html,js,json,txt,bak --max-rate 20 --no-color
\`\`\`

## Nuclei (Templates Críticos & Exposições)
\`\`\`bash
nuclei -u {target} -as -severity critical,high,medium -silent
\`\`\`

## ffuf (Fuzzing Rápido de Endpoints API)
\`\`\`bash
ffuf -u {target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,204,301,302,401,403 -t 25
\`\`\`

## Nmap (Serviços & Scripts Seguros)
\`\`\`bash
nmap -sV -sC -Pn -T4 {target}
\`\`\`
`,
  },
  {
    relativePath: "Checklists/Checklist-Bug-Bounty.md",
    content: `# Checklist Operacional — Bug Bounty & Pentest Web

#bugbounty #checklist #escopo #owasp

Voltar ao [[00-Indice-CyberLab]] | Ver [[Comandos-Rapidos]]

## 1. Pré-Voo & Governança
- [x] Importar escopo autorizado (\`*.alvo.com\` e exclusões) na aba **Escopo Bug Bounty**
- [ ] Configurar header de identificação do pesquisador (HackerOne / Bugcrowd)
- [ ] Abrir navegador isolado em 1 clique apontado para o proxy (\`:8080\`)

## 2. Mapeamento de Superfície
- [ ] Enumerar subdomínios passivos (\`subfinder\` + \`dnsx\` + \`httpx\`)
- [ ] Mapear diretórios e rotas de API (\`dirsearch\` / \`katana\` / \`ffuf\`)
- [ ] Verificar plugins/componentes conhecidos e CVEs (\`nuclei\` / \`trivy\`)

## 3. Autorização, Sessão & Lógica de Negócio
- [ ] Testar BOLA / IDOR trocando IDs entre duas contas de teste legítimas
- [ ] Inspecionar fluxos OAuth2 / OIDC (\`state\`, \`PKCE S256\`, \`redirect_uri\`)
- [ ] Verificar introspecção e batching em endpoints GraphQL

## 4. Evidência & Relatório
- [ ] Salvar evidência bruta com redação automática no cofre **SHA-256**
- [ ] Gerar relatório Markdown reproduzível para submissão
`,
  },
  {
    relativePath: "Labs/Diario-Labs.md",
    content: `# Diário de Laboratórios & Anotações de Estudo

#labs #treino #notas

Conectado ao [[00-Indice-CyberLab]] e [[Comandos-Rapidos]].

## Anotações Rápidas da Sessão
- **Alvo / Lab ativo**: \`http://127.0.0.1:4101\`
- **Hipótese atual**: Testar controle de acesso por objeto (BOLA) nos endpoints \`/api/v1/invoices/:id\` e validar correção ao vivo (*Live Patch*).

## Rascunho de Achados
1. Endpoint respondeu \`200 OK\` para objeto pertencente a outro tenant de laboratório.
2. Registrar evidência em \`SHA-256\` antes de aplicar o patch e re-auditar.
`,
  },
]

export class CyberLabObsidianVault {
  private readonly projectId: string
  private readonly workspaceRoot: string
  private readonly configFilePath: string
  private config: PersistedVaultConfig

  constructor(options: {
    projectId: string
    workspaceRoot: string
    globalConfigDir?: string
  }) {
    this.projectId = options.projectId
    this.workspaceRoot = path.resolve(options.workspaceRoot)
    const baseCfgDir =
      options.globalConfigDir ??
      process.env.CYBERLAB_GLOBAL_CONFIG_DIR ??
      path.join(os.homedir(), ".cyberlab")
    this.configFilePath = path.join(baseCfgDir, "vault-config.json")
    this.config = this.loadConfig()
  }

  private loadConfig(): PersistedVaultConfig {
    if (!existsSync(this.configFilePath)) {
      return { customVaultRootByProject: {} }
    }
    try {
      const parsed = JSON.parse(readFileSync(this.configFilePath, "utf8")) as Partial<PersistedVaultConfig>
      return {
        customVaultRootByProject:
          parsed.customVaultRootByProject && typeof parsed.customVaultRootByProject === "object"
            ? parsed.customVaultRootByProject
            : {},
      }
    } catch {
      return { customVaultRootByProject: {} }
    }
  }

  private saveConfig(): void {
    try {
      mkdirSync(path.dirname(this.configFilePath), { recursive: true })
      writeFileSync(this.configFilePath, `${JSON.stringify(this.config, null, 2)}\n`, "utf8")
    } catch {
      // Non-fatal in read-only test sandboxes
    }
  }

  getVaultRoot(): { vaultRootDir: string; isCustomPath: boolean } {
    const custom = this.config.customVaultRootByProject[this.projectId]?.trim()
    if (custom) {
      return { vaultRootDir: path.resolve(custom), isCustomPath: true }
    }
    return {
      vaultRootDir: path.join(this.workspaceRoot, "vault"),
      isCustomPath: false,
    }
  }

  setCustomVaultRoot(customDir?: string | null): VaultOverview {
    const trimmed = customDir?.trim() ?? ""
    if (!trimmed) {
      delete this.config.customVaultRootByProject[this.projectId]
    } else {
      const resolved = path.resolve(trimmed)
      mkdirSync(resolved, { recursive: true })
      this.config.customVaultRootByProject[this.projectId] = resolved
    }
    this.saveConfig()
    return this.getOverview()
  }

  private ensureVaultInitialized(): string {
    const { vaultRootDir } = this.getVaultRoot()
    mkdirSync(vaultRootDir, { recursive: true })

    // Create minimal .obsidian config hint if absent so opening `vault/` in Obsidian Desktop works seamlessly
    const obsidianMetaDir = path.join(vaultRootDir, ".obsidian")
    if (!existsSync(obsidianMetaDir)) {
      try {
        mkdirSync(obsidianMetaDir, { recursive: true })
        writeFileSync(
          path.join(obsidianMetaDir, "app.json"),
          `${JSON.stringify({ strictLineBreaks: false, showFrontmatter: true }, null, 2)}\n`,
          "utf8",
        )
      } catch {
        // Ignore
      }
    }

    // Seed starter notes only if zero .md files exist anywhere in vaultRootDir
    const existingMd = this.scanMarkdownFiles(vaultRootDir)
    if (existingMd.length === 0) {
      for (const seed of STARTER_VAULT_NOTES) {
        const dest = path.join(vaultRootDir, ...seed.relativePath.split("/"))
        mkdirSync(path.dirname(dest), { recursive: true })
        writeFileSync(dest, seed.content, "utf8")
      }
    }

    return vaultRootDir
  }

  private resolveSafeNotePath(vaultRoot: string, relativePath: string): { normRel: string; absPath: string } {
    const normRel = normalizeVaultRelPath(relativePath)
    const realRoot = existsSync(vaultRoot) ? realpathSync(vaultRoot) : path.resolve(vaultRoot)
    const candidate = path.resolve(realRoot, ...normRel.split("/"))
    if (!isPathInsideRoot(candidate, realRoot)) {
      throw new Error(`Acesso fora do Vault bloqueado: ${relativePath}`)
    }
    if (existsSync(candidate)) {
      const lst = lstatSync(candidate)
      if (lst.isSymbolicLink()) {
        throw new Error(`Links simbólicos não são permitidos dentro do Vault: ${normRel}`)
      }
      const realCandidate = realpathSync(candidate)
      if (!isPathInsideRoot(realCandidate, realRoot)) {
        throw new Error(`Escape por caminho real bloqueado: ${normRel}`)
      }
    }
    return { normRel, absPath: candidate }
  }

  private scanMarkdownFiles(vaultRoot: string): string[] {
    const realRoot = existsSync(vaultRoot) ? realpathSync(vaultRoot) : path.resolve(vaultRoot)
    const results: string[] = []

    const walk = (dir: string, relPrefix: string) => {
      if (results.length >= MAX_VAULT_FILES) return
      let entries
      try {
        entries = readdirSync(dir, { withFileTypes: true })
      } catch {
        return
      }
      for (const ent of entries) {
        if (results.length >= MAX_VAULT_FILES) break
        if (ent.name.startsWith(".")) continue
        if (ent.name === "node_modules") continue
        const full = path.join(dir, ent.name)
        try {
          const lst = lstatSync(full)
          if (lst.isSymbolicLink()) continue
          const rel = relPrefix ? `${relPrefix}/${ent.name}` : ent.name
          if (lst.isDirectory()) {
            walk(full, rel)
          } else if (lst.isFile() && ent.name.toLowerCase().endsWith(".md")) {
            if (isPathInsideRoot(full, realRoot)) {
              results.push(rel)
            }
          }
        } catch {
          // Skip unreadable entry
        }
      }
    }

    walk(realRoot, "")
    return results.sort((a, b) => a.localeCompare(b))
  }

  getOverview(): VaultOverview {
    const vaultRootDir = this.ensureVaultInitialized()
    const { isCustomPath } = this.getVaultRoot()
    const mdRelPaths = this.scanMarkdownFiles(vaultRootDir)
    const allTagsSet = new Set<string>()
    const notes: VaultNoteSummary[] = []

    for (const rel of mdRelPaths) {
      const full = path.join(vaultRootDir, ...rel.split("/"))
      try {
        const st = statSync(full)
        const raw =
          st.size <= MAX_NOTE_BYTES
            ? readFileSync(full, "utf8")
            : readFileSync(full, "utf8").slice(0, MAX_NOTE_BYTES)
        const tags = extractMarkdownTags(raw)
        for (const t of tags) allTagsSet.add(t)
        const wikiLinks = extractWikiLinks(raw)
        const slashIdx = rel.lastIndexOf("/")
        const folder = slashIdx >= 0 ? rel.slice(0, slashIdx) : ""
        notes.push({
          relativePath: rel,
          title: deriveNoteTitle(rel, raw),
          folder,
          tags,
          wikiLinks,
          snippet: buildSnippet(raw),
          sizeBytes: st.size,
          updatedAt: st.mtime.toISOString(),
        })
      } catch {
        // Ignore transient read error
      }
    }

    return {
      vaultRootDir,
      isCustomPath,
      notes,
      allTags: Array.from(allTagsSet).sort(),
    }
  }

  readNote(relativePath: string): VaultNoteDocument {
    const vaultRootDir = this.ensureVaultInitialized()
    const { normRel, absPath } = this.resolveSafeNotePath(vaultRootDir, relativePath)
    if (!existsSync(absPath)) {
      throw new Error(`Nota não encontrada no Vault: ${normRel}`)
    }
    const st = statSync(absPath)
    if (st.size > MAX_NOTE_BYTES) {
      throw new Error(`A nota ${normRel} excede o limite de 1 MB.`)
    }
    const content = readFileSync(absPath, "utf8")
    const tags = extractMarkdownTags(content)
    const wikiLinks = extractWikiLinks(content)

    // Compute backlinks across all other notes in the vault
    const backlinks: string[] = []
    for (const otherRel of this.scanMarkdownFiles(vaultRootDir)) {
      if (otherRel === normRel) continue
      try {
        const otherRaw = readFileSync(path.join(vaultRootDir, ...otherRel.split("/")), "utf8")
        const otherLinks = extractWikiLinks(otherRaw)
        if (otherLinks.some((lnk) => wikiTargetMatchesNote(lnk, normRel))) {
          backlinks.push(otherRel)
        }
      } catch {
        // Ignore
      }
    }

    return {
      relativePath: normRel,
      title: deriveNoteTitle(normRel, content),
      content,
      tags,
      wikiLinks,
      backlinks,
      updatedAt: st.mtime.toISOString(),
    }
  }

  writeNote(relativePath: string, content: string): { note: VaultNoteDocument; overview: VaultOverview } {
    if (Buffer.byteLength(content, "utf8") > MAX_NOTE_BYTES) {
      throw new Error("Conteúdo da nota excede 1 MB.")
    }
    const vaultRootDir = this.ensureVaultInitialized()
    const { normRel, absPath } = this.resolveSafeNotePath(vaultRootDir, relativePath)
    mkdirSync(path.dirname(absPath), { recursive: true })
    writeFileSync(absPath, content, "utf8")
    const overview = this.getOverview()
    const note = this.readNote(normRel)
    return { note, overview }
  }

  deleteNote(relativePath: string): VaultOverview {
    const vaultRootDir = this.ensureVaultInitialized()
    const { absPath } = this.resolveSafeNotePath(vaultRootDir, relativePath)
    if (existsSync(absPath)) {
      rmSync(absPath, { force: true })
    }
    return this.getOverview()
  }
}
