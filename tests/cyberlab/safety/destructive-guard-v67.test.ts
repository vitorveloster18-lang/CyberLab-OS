import { describe, expect, test } from "bun:test"
import {
  assertNotBlocked,
  DESTRUCTIVE_OPERATIONS,
  evaluateDestructiveOperation,
  listProtectedOperations,
} from "../../../cyberlab/safety/destructive-guard.js"

describe("CyberLab OS v6.7 — Guarda de Ações Destrutivas (agente não destrói sem perguntar)", () => {
  test("toda operação destrutiva conhecida é bloqueada sem confirmação", () => {
    const ops = listProtectedOperations()
    expect(ops.length).toBeGreaterThanOrEqual(6)
    for (const op of ops) {
      const verdict = evaluateDestructiveOperation(op, { slotId: "custom-x", labId: "lab-owasp-api-bola" })
      expect(verdict.allowed).toBe(false)
      if (!verdict.allowed) {
        expect(verdict.approval.operation).toBe(op)
        expect(verdict.approval.message).toContain("AÇÃO DESTRUTIVA BLOQUEADA")
        expect(verdict.approval.message).toContain("não confirma em nome do operador")
      }
    }
  })

  test("operação fora do catálogo é liberada (a guarda falha fechada só no que conhece)", () => {
    expect(evaluateDestructiveOperation("cyberlab.status", {}).allowed).toBe(true)
    expect(evaluateDestructiveOperation("cyberlab.arsenal.overview", {}).allowed).toBe(true)
  })

  test("prune exige apenas confirm:true e libera quando ele vem", () => {
    const blocked = evaluateDestructiveOperation("cyberlab.arsenal.prune", {})
    expect(blocked.allowed).toBe(false)
    if (!blocked.allowed) expect(blocked.approval.requirement).toBe("confirm:true")

    expect(evaluateDestructiveOperation("cyberlab.arsenal.prune", { confirm: true }).allowed).toBe(true)
  })

  test("apagar nota do cofre é irreversível: exige confirm E a frase exata", () => {
    const args = { relativePath: "CyberLab-Knowledge/minha-nota.md" }

    const semNada = evaluateDestructiveOperation("cyberlab.vault.delete", args)
    expect(semNada.allowed).toBe(false)

    const soConfirm = evaluateDestructiveOperation("cyberlab.vault.delete", { ...args, confirm: true })
    expect(soConfirm.allowed).toBe(false)

    const fraseErrada = evaluateDestructiveOperation("cyberlab.vault.delete", {
      ...args,
      confirm: true,
      confirmPhrase: "outra-coisa",
    })
    expect(fraseErrada.allowed).toBe(false)
    if (!fraseErrada.allowed) expect(fraseErrada.approval.confirmPhrase).toBe(args.relativePath)

    const ok = evaluateDestructiveOperation("cyberlab.vault.delete", {
      ...args,
      confirm: true,
      confirmPhrase: args.relativePath,
    })
    expect(ok.allowed).toBe(true)
  })

  test("labs.control bloqueia reset e stop; start segue livre", () => {
    const base = { labId: "lab-owasp-api-bola" }
    expect(evaluateDestructiveOperation("cyberlab.labs.control.start", base).allowed).toBe(true)
    expect(evaluateDestructiveOperation("cyberlab.labs.control.reset", base).allowed).toBe(false)
    expect(evaluateDestructiveOperation("cyberlab.labs.control.stop", base).allowed).toBe(false)
    expect(evaluateDestructiveOperation("cyberlab.labs.control.stop", { ...base, confirm: true }).allowed).toBe(true)
  })

  test("o plano diz o que se perde e marca o que não tem volta", () => {
    const v = evaluateDestructiveOperation("cyberlab.vault.delete", { relativePath: "nota.md" })
    expect(v.allowed).toBe(false)
    if (v.allowed) return
    expect(v.approval.risk).toBe("irreversible")
    expect(v.approval.consequences.some((c) => !c.recoverable)).toBe(true)
    expect(v.approval.message).toContain("sem volta")
    // O alvo aparece para o operador saber exatamente o que está em jogo
    expect(v.approval.target).toBe("nota.md")
  })

  test("knowledge.sync avisa que notas do operador ficam intocadas", () => {
    const v = evaluateDestructiveOperation("cyberlab.knowledge.sync", {})
    expect(v.allowed).toBe(false)
    if (v.allowed) return
    expect(v.approval.message).toContain("NUNCA são tocadas")
    expect(evaluateDestructiveOperation("cyberlab.knowledge.sync", { confirm: true }).allowed).toBe(true)
  })

  test("assertNotBlocked lança erro identificável e não executa nada", () => {
    expect(() => assertNotBlocked("cyberlab.arsenal.prune", {})).toThrow(/AÇÃO DESTRUTIVA BLOQUEADA/)
    try {
      assertNotBlocked("cyberlab.arsenal.prune", {})
      expect.unreachable("deveria ter lançado")
    } catch (err) {
      expect((err as Error).name).toBe("DestructiveActionBlockedError")
    }
    expect(() => assertNotBlocked("cyberlab.arsenal.prune", { confirm: true })).not.toThrow()
  })

  test("todo spec declara verbo, alvo e consequências (nada de entrada vazia)", () => {
    for (const [op, spec] of Object.entries(DESTRUCTIVE_OPERATIONS)) {
      expect(spec.verb.length, op).toBeGreaterThan(5)
      expect(spec.targetOf({ slotId: "s", labId: "l", relativePath: "p" }).length, op).toBeGreaterThan(0)
      expect(spec.consequences({ slotId: "s" }).length, op).toBeGreaterThan(0)
      expect(["destructive", "irreversible"], op).toContain(spec.risk)
    }
  })
})
