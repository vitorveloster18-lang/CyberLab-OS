import type { ScopeTargetRule } from "@cyberlab/core/contracts/policy"
import { Effect } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace, resolveLocalCyberLabProjectId } from "./_workspace"

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/
const CIDR = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/\d{1,2}$/
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i

/**
 * Classifica o que o operador digitou em uma regra de escopo.
 *
 * Existe porque o operador vai digitar `10.0.0.0/24` e não
 * `{ kind: "cidr", value: "10.0.0.0/24" }`. O que não for reconhecido é
 * REJEITADO em vez de aceito como domínio genérico — um escopo com lixo
 * silencioso daria falsa sensação de autorização.
 */
export function classifyTarget(raw: string): ScopeTargetRule {
  const value = raw.trim()
  if (value.length === 0) throw new Error("Alvo vazio.")
  if (CIDR.test(value)) return { kind: "cidr", value }
  if (IPV4.test(value)) return { kind: "ip", value }
  if (DOMAIN.test(value)) return { kind: "domain", value }
  throw new Error(
    `Não reconheci "${value}" como IP, CIDR ou domínio. ` +
      "Exemplos válidos: 10.0.0.5 · 10.0.0.0/24 · exemplo.com",
  )
}

/**
 * `cyberlab scope` — mostra, define ou limpa o escopo autorizado.
 *
 * Sem escopo definido, `cyberlab exec` recusa tudo (falha fechada, de propósito).
 * Antes este ajuste só era possível pela interface web; sem este comando, o
 * CyberLab rodando só no terminal ficaria inutilizável.
 */
export default Runtime.handler(
  Commands.commands.cyberlab.commands.scope,
  Effect.fn("cli.cyberlab.scope")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.scope>,
  ) {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
    const projectId = resolveLocalCyberLabProjectId()
    const current = ws.scopes.getProjectScope(projectId)

    // --- limpar ---
    if (input.clear) {
      yield* Effect.promise(() => ws.updateScope({ allowedTargets: [], active: false }))
      if (input.json) {
        process.stdout.write(JSON.stringify({ cleared: true, projectId }, null, 2) + EOL)
        return
      }
      process.stdout.write(
        [
          "Escopo removido.",
          "",
          "  Com o escopo inativo, `cyberlab exec` recusa qualquer comando que",
          "  contenha alvo de rede. Isso é falha fechada, e é intencional.",
          "",
          "  Para reativar: cyberlab scope --set <alvos...>",
        ].join(EOL) + EOL,
      )
      return
    }

    // --- definir ---
    const targets = input.targets ?? []
    if (targets.length > 0) {
      const rules: ScopeTargetRule[] = []
      const errors: string[] = []
      for (const raw of targets) {
        try {
          rules.push(classifyTarget(raw))
        } catch (e) {
          errors.push(e instanceof Error ? e.message : String(e))
        }
      }
      if (errors.length > 0) {
        // Não aplica parcialmente: um escopo meio-definido é pior que nenhum,
        // porque o operador acharia que autorizou algo que não autorizou.
        process.stderr.write(errors.map((m) => `  ✗ ${m}`).join(EOL) + EOL)
        process.exitCode = 1
        return
      }

      const updated = yield* Effect.promise(() =>
        ws.updateScope({
          allowedTargets: rules,
          allowExternalTargets: input.external,
          active: true,
        }),
      )

      if (input.json) {
        process.stdout.write(JSON.stringify(updated, null, 2) + EOL)
        return
      }
      process.stdout.write(
        [
          `Escopo definido para ${projectId}:`,
          ...rules.map((r) => `  + ${r.kind.padEnd(8)} ${r.value}`),
          `  alvos externos: ${updated.allowExternalTargets ? "PERMITIDOS" : "bloqueados"}`,
          "",
          "Gravado em .cyberlab/scope.json",
        ].join(EOL) + EOL,
      )
      return
    }

    // --- mostrar ---
    if (input.json) {
      process.stdout.write(JSON.stringify(current ?? { active: false, projectId }, null, 2) + EOL)
      return
    }

    if (!current || !current.active || current.allowedTargets.length === 0) {
      process.stdout.write(
        [
          `Nenhum escopo ativo para ${projectId}.`,
          "",
          "  `cyberlab exec` vai recusar comandos com alvo de rede até você definir:",
          "",
          "    cyberlab scope --set 10.0.0.0/24 exemplo.com",
        ].join(EOL) + EOL,
      )
      return
    }

    const lines = [
      `Escopo ativo (${projectId}):`,
      ...current.allowedTargets.map((t) => `  + ${t.kind.padEnd(8)} ${t.value}`),
    ]
    if (current.blockedTargets.length > 0) {
      lines.push("  bloqueados:")
      for (const t of current.blockedTargets) lines.push(`    - ${t.kind.padEnd(8)} ${t.value}`)
    }
    lines.push(`  alvos externos: ${current.allowExternalTargets ? "PERMITIDOS" : "bloqueados"}`)
    process.stdout.write(lines.join(EOL) + EOL)
  }),
)
