import { Effect, Option } from "effect"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { startCyberLabStudioServer } from "../../../../../../cyberlab/studio/server.js"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.studio,
  Effect.fn("cli.cyberlab.studio")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.studio>,
  ) {
    const port = Option.getOrUndefined(input.port)
    const host = Option.getOrUndefined(input.host)
    if (port !== undefined) {
      process.env.CYBERLAB_STUDIO_PORT = String(port)
    }
    if (host) {
      process.env.CYBERLAB_STUDIO_HOST = host
    }
    if (input.demoLab && !process.argv.includes("--demo-lab")) {
      process.argv.push("--demo-lab")
    }
    yield* Effect.promise(async () => {
      await startCyberLabStudioServer()
      await new Promise(() => {})
    })
  }),
)
