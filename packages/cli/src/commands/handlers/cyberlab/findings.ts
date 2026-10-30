import { Effect } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.findings,
  Effect.fn("cli.cyberlab.findings")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.findings>,
  ) {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
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
