import { Effect, Option } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

const DECISIONS = ["accept", "reject", "needs_more_evidence"] as const

export default Runtime.handler(
  Commands.commands.cyberlab.commands.findings,
  Effect.fn("cli.cyberlab.findings")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.findings>,
  ) {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())

    // --- revisar ---
    // Sem isto, o review só era possível pela interface/MCP. O finding fica
    // "unreviewed" para sempre no fluxo só-terminal, e o report sai com
    // findings sem decisão registrada.
    const reviewId = Option.getOrUndefined(input.review)
    if (reviewId) {
      const decision = (Option.getOrUndefined(input.decision) ?? "").trim()
      if (!(DECISIONS as readonly string[]).includes(decision)) {
        process.stderr.write(
          `Decisão inválida: "${decision}". Use accept | reject | needs_more_evidence.${EOL}`,
        )
        process.exitCode = 1
        return
      }
      const reviewedBy = (Option.getOrUndefined(input.by) ?? "").trim() || "operator"
      const notes = Option.getOrUndefined(input.notes)
      const updated = yield* Effect.promise(() =>
        ws.reviewFinding({
          findingId: reviewId,
          reviewedBy,
          decision: decision as (typeof DECISIONS)[number],
          ...(notes ? { notes } : {}),
        }),
      )
      if (input.json) {
        process.stdout.write(JSON.stringify(updated, null, 2) + EOL)
        return
      }
      process.stdout.write(
        [
          `Finding ${updated.findingId} revisado: ${updated.status} (decisão: ${decision}, por ${reviewedBy})`,
          ...(notes ? [`  notas: ${notes}`] : []),
        ].join(EOL) + EOL,
      )
      return
    }

    const list = yield* Effect.promise(() => ws.listFindings())
    if (input.json) {
      process.stdout.write(JSON.stringify(list, null, 2) + EOL)
      return
    }
    const lines = list.map(
      (f) => `${f.findingId} [${f.severity.toUpperCase()} | ${f.status}] ${f.title} (evidence: ${f.evidenceIds.join(", ")})`,
    )
    process.stdout.write((lines.length > 0 ? lines.join(EOL) : "No findings recorded.") + EOL)
  }),
)
