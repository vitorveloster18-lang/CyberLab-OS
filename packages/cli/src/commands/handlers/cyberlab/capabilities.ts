import { Effect } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.capabilities,
  Effect.fn("cli.cyberlab.capabilities")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.capabilities>,
  ) {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
    const caps = yield* Effect.promise(() => ws.listCapabilities())
    if (input.json) {
      process.stdout.write(JSON.stringify(caps, null, 2) + EOL)
      return
    }
    const lines = caps.map(
      (c) => `${c.id} (v${c.version}) [risk=${c.risk}, executor=${c.executorId}] - ${c.title}`,
    )
    if (lines.length > 0) process.stdout.write(lines.join(EOL) + EOL)
  }),
)
