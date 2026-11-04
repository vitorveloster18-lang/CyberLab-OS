import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
  AUTHORIZED_TARGET_PROFILES,
  getTargetProfile,
  listTargetProfiles,
  renderRulesOfEngagementMd,
  renderScopeMd,
  writeTargetScope,
} from "../../../cyberlab/labs/target-profiles.js"

const tempDirs: string[] = []
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 })
})

describe("CyberLab OS v6.5 — Perfis de Alvo Externo Autorizado", () => {
  test("todo perfil declara base de autorização, hosts permitidos e proibições", () => {
    expect(listTargetProfiles().length).toBeGreaterThan(0)
    for (const p of AUTHORIZED_TARGET_PROFILES) {
      // Autorização não é opcional: sem ela o alvo não entra na lista.
      expect(p.authorizationBasis.length).toBeGreaterThan(40)
      expect(p.allowedHosts.length).toBeGreaterThan(0)
      expect(p.forbidden.length).toBeGreaterThan(0)
      expect(p.rateLimits.length).toBeGreaterThan(0)
      expect(p.evidenceRules.length).toBeGreaterThan(0)
      expect(p.verifyAt.length).toBeGreaterThan(0)
      // Honestidade: o que o alvo NÃO treina precisa estar escrito.
      expect(p.honestLimits.length).toBeGreaterThan(0)
    }
  })

  test("perfil da Web Security Academy cobre H1–H4 e o domínio do laboratório", () => {
    const p = getTargetProfile("portswigger-wsa")
    expect(p).toBeDefined()
    expect(p!.name).toContain("Web Security Academy")
    // A autorização é POR INSTÂNCIA: o domínio da plataforma não é o alvo.
    expect(p!.allowedHosts).toContain("*.web-security-academy.net")
    expect(p!.allowedHosts).toContain("*.h1-web-security-academy.net")
    expect(p!.authorizationBasis).toContain("SOMENTE")
    // Ponte com o método calibrado no laboratório local
    expect(p!.hypothesisBridge.map((b) => b.localHypothesisId)).toEqual(["H1", "H2", "H3", "H4"])
    for (const b of p!.hypothesisBridge) {
      expect(b.targetTopic.length).toBeGreaterThan(3)
      expect(b.method.length).toBeGreaterThan(20)
    }
    // Escada de dificuldade reconhece os três níveis oficiais
    const ladder = p!.difficultyLadder.join(" ")
    expect(ladder).toContain("Apprentice")
    expect(ladder).toContain("Practitioner")
    expect(ladder).toContain("Expert")
  })

  test("o perfil avisa que OAST próprio não funciona no laboratório (firewall de saída)", () => {
    const p = getTargetProfile("portswigger-wsa")!
    const joined = p.tooling.join(" ")
    expect(joined).toContain("Collaborator")
    expect(joined).toContain("FORA DE ESCOPO")
  })

  test("SCOPE.md e RULES-OF-ENGAGEMENT.md trazem autorização, hosts e regras de evidência", () => {
    const p = getTargetProfile("portswigger-wsa")!
    const scope = renderScopeMd(p)
    const rules = renderRulesOfEngagementMd(p)

    for (const doc of [scope, rules]) {
      expect(doc).toContain(p.name)
      expect(doc).toContain(p.authorizationBasis)
      for (const h of p.allowedHosts) expect(doc).toContain(h)
    }
    expect(scope).toContain("## Ponte com o método calibrado")
    expect(scope).toContain("| Hip. local | Classe | Tópico no alvo | Método |")
    // ROE é checklist imprimível
    expect(rules).toContain("## 3. Parada imediata")
    expect(rules).toContain("- [ ] NÃO ")
    expect(rules).toContain("## 6. Limites honestos")
  })

  test("writeTargetScope grava os dois arquivos; perfil inexistente retorna null", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "cyberlab-target-"))
    tempDirs.push(root)

    const result = writeTargetScope("portswigger-wsa", root)
    expect(result).not.toBeNull()
    expect(existsSync(result!.scopePath)).toBe(true)
    expect(existsSync(result!.rulesPath)).toBe(true)
    expect(readFileSync(result!.scopePath, "utf8")).toContain("Escopo autorizado")

    expect(writeTargetScope("nao-existe", root)).toBeNull()
  })
})
