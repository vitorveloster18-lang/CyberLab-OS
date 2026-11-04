import { describe, expect, it } from "bun:test"
import { OFFICIAL_ARSENAL_SLOTS } from "../../../cyberlab/arsenal/catalog.js"
import { BUILTIN_EXTERNAL_TOOL_CATALOG } from "../../../cyberlab/external/control-plane.js"

/**
 * v6.7 — `lab slots` cruza cada slot com o status do binário do catálogo externo
 * usando `ArsenalSlotDefinition.externalToolId`. Esse vínculo é digitado à mão no
 * catálogo, então um `toolId` errado não quebra o build: ele só faz o slot exibir
 * "✘ faltando" para sempre (ou pior, apontar para a ferramenta de outro slot).
 * Estes testes são o freio disso.
 */

const CATALOG_TOOL_IDS = new Set(BUILTIN_EXTERNAL_TOOL_CATALOG.map((e) => e.toolId))
const BOUND_SLOTS = OFFICIAL_ARSENAL_SLOTS.filter((d) => d.externalToolId)

describe("Vínculo slot -> ferramenta do catálogo externo (v6.7)", () => {
  it("vincula pelo menos os 12 slots que governam binário", () => {
    expect(BOUND_SLOTS.length).toBeGreaterThanOrEqual(12)
  })

  it("todo externalToolId existe de verdade no catálogo externo", () => {
    for (const slot of BOUND_SLOTS) {
      expect(CATALOG_TOOL_IDS.has(slot.externalToolId!)).toBe(true)
    }
  })

  it("nenhuma ferramenta é reivindicada por dois slots diferentes", () => {
    const seen = new Map<string, string[]>()
    for (const slot of BOUND_SLOTS) {
      const key = slot.externalToolId!
      seen.set(key, [...(seen.get(key) ?? []), slot.slotId])
    }
    const shared = [...seen.entries()].filter(([, slotIds]) => slotIds.length > 1)
    expect(shared).toEqual([])
  })

  it("cobre os binários que o agente realmente invoca", () => {
    const bySlot = new Map(BOUND_SLOTS.map((d) => [d.slotId, d.externalToolId!]))
    const expected: Array<[string, string]> = [
      ["nmap", "nmap"],
      ["nuclei", "nuclei"],
      ["ffuf", "ffuf"],
      ["wireshark", "tshark"],
      ["opentrap", "opentrap"],
      ["mvt", "mvt-android"],
      ["ghidra", "ghidra-headless"],
      ["jadx", "jadx"],
      ["hayabusa-yarax", "yarax"],
      ["dalfox", "dalfox"],
      ["trivy", "trivy"],
      ["keyhunter", "keyhunter"],
    ]
    for (const [slotId, toolId] of expected) {
      expect(bySlot.get(slotId)).toBe(toolId)
    }
  })

  it("slots que não governam binário seguem sem externalToolId (sem falso positivo)", () => {
    const notBound = OFFICIAL_ARSENAL_SLOTS.filter((d) => !d.externalToolId).map((d) => d.slotId)
    // GUI pura, embed web ou configuração: não há binário de catálogo para checar.
    for (const slotId of ["cyberchef", "kali-desktop-stream", "pentagi", "burp-suite"]) {
      expect(notBound).toContain(slotId)
    }
  })
})
