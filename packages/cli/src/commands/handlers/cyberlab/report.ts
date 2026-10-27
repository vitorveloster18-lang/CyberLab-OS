import { Effect } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.report,
  Effect.fn("cli.cyberlab.report")(function* () {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
    const report = yield* Effect.promise(() => ws.generateMarkdownReport())
    process.stdout.write(report + EOL)
  }),
)
