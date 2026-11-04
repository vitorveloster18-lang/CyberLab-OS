import { describe, expect, it } from "bun:test"
import { BUILTIN_EXTERNAL_TOOL_CATALOG, isProbeablePosix } from "../../../cyberlab/external/control-plane.js"

/**
 * v6.7 — Detecção de binários instalados FORA do PATH.
 *
 * Caso real: no Debian/Kali o pacote `ghidra` só põe o launcher gráfico em
 * `/usr/bin/ghidra`. O `analyzeHeadless` — que é o binário que o agente invoca —
 * fica em `/usr/share/ghidra/support/analyzeHeadless`, fora do PATH. O probe só
 * sabia procurar por nome (`command -v`), então a ferramenta aparecia como
 * "faltando" mesmo estando instalada, e o operador recebia a sugestão inútil de
 * reinstalar um pacote que já estava lá.
 */

describe("Caminhos POSIX conhecidos (v6.7)", () => {
  it("aceita nomes simples e caminhos absolutos", () => {
    expect(isProbeablePosix("nmap")).toBe(true)
    expect(isProbeablePosix("analyzeHeadless")).toBe(true)
    expect(isProbeablePosix("/usr/share/ghidra/support/analyzeHeadless")).toBe(true)
    expect(isProbeablePosix("/opt/ghidra/support/analyzeHeadless")).toBe(true)
  })

  it("rejeita tudo que possa virar injeção dentro do script bash do probe", () => {
    for (const bad of [
      "..",
      "/usr/share/../../etc/passwd",
      "nmap; rm -rf /",
      "nmap && echo pwned",
      "$(whoami)",
      "`whoami`",
      "nmap\necho hi",
      "relative/path/nmap",
      "/usr/bin/nmap | cat",
      "nmap'",
    ]) {
      expect(isProbeablePosix(bad)).toBe(false)
    }
  })

  it("o ghidra headless declara os caminhos fora do PATH do Debian/Kali", () => {
    const ghidra = BUILTIN_EXTERNAL_TOOL_CATALOG.find((e) => e.toolId === "ghidra-headless")
    expect(ghidra).toBeDefined()
    expect(ghidra!.posixKnownPaths ?? []).toContain("/usr/share/ghidra/support/analyzeHeadless")
  })

  it("todo posixKnownPaths declarado é um caminho absoluto e seguro", () => {
    for (const entry of BUILTIN_EXTERNAL_TOOL_CATALOG) {
      for (const candidate of entry.posixKnownPaths ?? []) {
        expect(candidate.startsWith("/")).toBe(true)
        expect(isProbeablePosix(candidate)).toBe(true)
      }
    }
  })
})
