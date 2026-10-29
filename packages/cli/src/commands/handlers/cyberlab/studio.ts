import { Console, Effect, Option } from "effect"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.studio,
  Effect.fn("cli.cyberlab.studio")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.studio>,
  ) {
    const port = Option.getOrUndefined(input.port) ?? 4096
    const host = Option.getOrUndefined(input.host) ?? "127.0.0.1"
    yield* Console.log(
      `CyberLab OS v5.0 runs unified inside the OpenCode V2 web app. Start with: bun start -- --host ${host} --port ${port}`,
    )
  }),
)
