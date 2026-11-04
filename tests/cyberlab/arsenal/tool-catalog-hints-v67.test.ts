import { describe, expect, it } from "bun:test"
import { BUILTIN_EXTERNAL_TOOL_CATALOG } from "../../../cyberlab/external/control-plane.js"

/**
 * v6.7 — `bun run cyberlab lab tools --script` transforma a dica de instalação
 * do WSL2 em uma linha de um script bash com `set -euo pipefail`. Isso só é
 * seguro se o catálogo separar claramente:
 *
 *   - dicas que SÃO comandos (apt / pipx / cargo / ...) — entram no script;
 *   - dicas que NÃO SÃO comandos ("See slot installer (...)") — viram comentário.
 *
 * Sem essa distinção o operador recebe um script que quebra na primeira linha
 * não-executável e instala nada.
 */

/** Mesma heurística usada por `script/cyberlab-lab.ts` (case "tools", --script). */
const SHELL_COMMAND_RE = /^(sudo|apt|apt-get|pipx|pip3?|go|cargo|gem|curl|wget|npm|bun|bash|sh)\b/

const CANONICAL_TOOLS = BUILTIN_EXTERNAL_TOOL_CATALOG.filter((t) => !t.toolId.startsWith("external:"))

describe("Catálogo de ferramentas externas — dicas de instalação (v6.7)", () => {
  it("expõe um catálogo canônico não vazio e sem ids duplicados", () => {
    expect(CANONICAL_TOOLS.length).toBeGreaterThan(0)
    const ids = CANONICAL_TOOLS.map((t) => t.toolId)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it("toda ferramenta do catálogo documenta licença e instalação no WSL2 Kali", () => {
    for (const tool of CANONICAL_TOOLS) {
      expect(tool.licenseSpdx.length).toBeGreaterThan(0)
      expect(tool.installHint.length).toBeGreaterThan(0)
      expect(tool.installKaliWsl.length).toBeGreaterThan(0)
    }
  })

  it("toda dica apt do Kali é executável de verdade (sem parênteses explicativos soltos)", () => {
    for (const tool of CANONICAL_TOOLS) {
      const cmd = tool.installKaliWsl.split(" (")[0]!.trim()
      if (!SHELL_COMMAND_RE.test(cmd)) continue
      // Depois de remover o parêntese explicativo não pode sobrar parêntese aberto.
      expect(cmd.includes("(")).toBe(false)
      // E a linha precisa efetivamente instalar algo, não só atualizar o apt.
      expect(cmd).toMatch(/(install|update-templates|cargo install|pipx install)/)
    }
  })

  it("as dicas que não são comandos ficam fora do script e são reconhecíveis", () => {
    const notShell = CANONICAL_TOOLS.filter((t) => !SHELL_COMMAND_RE.test(t.installKaliWsl.split(" (")[0]!.trim()))
    for (const tool of notShell) {
      // Precisa ser legível pelo operador: é virada em comentário pelo CLI.
      expect(tool.installKaliWsl.length).toBeGreaterThan(10)
    }
  })
})
