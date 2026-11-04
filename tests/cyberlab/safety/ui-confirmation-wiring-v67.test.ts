import { describe, expect, test } from "bun:test"
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs"
import path from "node:path"
import { listProtectedOperations } from "../../../cyberlab/safety/destructive-guard.js"

const APP_SRC = path.resolve(import.meta.dir, "../../../packages/app/src")

function walk(dir: string): string[] {
  const out: string[] = []
  if (!existsSync(dir)) return out
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry)
    if (statSync(full).isDirectory()) {
      if (entry === "node_modules" || entry === "dist") continue
      out.push(...walk(full))
    } else if (/\.(ts|tsx)$/.test(entry)) {
      out.push(full)
    }
  }
  return out
}

/** Endpoints protegidos e o caminho HTTP correspondente. */
const PROTECTED_ROUTES: Array<{ operation: string; route: string; label: string }> = [
  { operation: "cyberlab.arsenal.prune", route: "/api/cyberlab/arsenal/prune", label: "Limpar Fantasmas & Duplicatas" },
  {
    operation: "cyberlab.arsenal.custom.remove",
    route: "/api/cyberlab/arsenal/custom/remove",
    label: "Remover slot personalizado",
  },
  { operation: "cyberlab.vault.delete", route: "/api/cyberlab/vault/delete", label: "Apagar nota do cofre" },
  { operation: "cyberlab.labs.control.reset", route: "/api/cyberlab/labs/control", label: "Resetar laboratório" },
  { operation: "cyberlab.labs.control.stop", route: "/api/cyberlab/labs/control", label: "Parar laboratório" },
]

describe("CyberLab OS v6.7 — a interface não pode ser pega pela própria guarda", () => {
  const files = walk(APP_SRC)
  const sources = files.map((f) => ({ file: path.relative(APP_SRC, f), text: readFileSync(f, "utf8") }))

  test("o app foi encontrado (senão o teste a seguir não vale nada)", () => {
    expect(sources.length).toBeGreaterThan(20)
  })

  test("toda operação protegida existe no catálogo da guarda", () => {
    const protectedOps = listProtectedOperations()
    for (const r of PROTECTED_ROUTES) {
      // labs.control.reset/stop são derivados de labs.control.<action>
      const base = r.operation.replace(/\.(reset|stop)$/, "")
      expect(protectedOps.some((op) => op === base || op === r.operation), r.operation).toBe(true)
    }
  })

  test("toda chamada da interface a um endpoint protegido envia a confirmação", () => {
    const problems: string[] = []

    for (const route of PROTECTED_ROUTES) {
      for (const src of sources) {
        let idx = src.text.indexOf(`"${route.route}"`)
        while (idx >= 0) {
          // Janela: o corpo da chamada vem logo depois da URL
          const window = src.text.slice(idx, idx + 700)
          const isLabsControl = route.route.endsWith("/labs/control")

          if (isLabsControl) {
            // start não é destrutivo; reset/stop precisam de confirmação.
            // A UI envia confirm condicionalmente — exigimos que ela AO MENOS cite confirm.
            if (!/\bconfirm\b/.test(window)) {
              problems.push(`${src.file} → ${route.label}: sem nenhuma menção a "confirm"`)
            }
          } else if (!/\bconfirm\b/.test(window)) {
            problems.push(`${src.file} → ${route.label}: corpo sem "confirm"`)
          }

          idx = src.text.indexOf(`"${route.route}"`, idx + 1)
        }
      }
    }

    // Se isto quebrar: você adicionou uma operação à guarda (ou um botão novo na UI)
    // e esqueceu de mandar `confirm`. O sintoma em campo é erro vermelho na interface.
    expect(problems).toEqual([])
  })

  test("a remoção de nota do cofre avisa que não há lixeira antes de apagar", () => {
    const withDelete = sources.filter((s) => s.text.includes("/api/cyberlab/vault/delete"))
    expect(withDelete.length).toBeGreaterThan(0)
    for (const src of withDelete) {
      expect(src.text, src.file).toContain("window.confirm")
      expect(src.text, src.file).toContain("confirmPhrase")
    }
  })
})
