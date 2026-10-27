import { Effect, Option } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.evidence,
  Effect.fn("cli.cyberlab.evidence")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.evidence>,
  ) {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
    const verifyId = Option.getOrUndefined(input.verify)
    if (verifyId) {
      const check = yield* Effect.promise(() => ws.verifyEvidence(verifyId, "cli-operator"))
      if (input.json) {
        process.stdout.write(JSON.stringify(check, null, 2) + EOL)
      } else {
        process.stdout.write(
          `Integrity ${check.valid ? "VALID" : "FAILED"} for ${check.evidenceId} (sha256=${check.expectedSha256})` +
            EOL,
        )
      }
      return
    }
    const list = yield* Effect.promise(() => ws.listEvidence())
    if (input.json) {
      process.stdout.write(JSON.stringify(list, null, 2) + EOL)
      return
    }
    const lines = list.map(
      (ev) => `${ev.evidenceId} [${ev.kind}] sha256:${ev.integrity.sha256} (${ev.title})`,
    )
    process.stdout.write((lines.length > 0 ? lines.join(EOL) : "No evidence recorded.") + EOL)
  }),
)
