import { Effect } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.run,
  Effect.fn("cli.cyberlab.run")(function* (input: Runtime.Input<typeof Commands.commands.cyberlab.commands.run>) {
    const parsedInput = yield* Effect.try({
      try: () => JSON.parse(input.input) as unknown,
      catch: (e) => new Error(`Invalid --input JSON: ${e instanceof Error ? e.message : String(e)}`),
    })
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
    const record = yield* Effect.promise(() =>
      ws.submitExecution({
        capabilityId: input.capability,
        input: parsedInput,
        mode: "manual",
        requestedBy: { type: "user", id: "cli-operator" },
      }),
    )
    if (input.json) {
      process.stdout.write(JSON.stringify(record, null, 2) + EOL)
      return
    }
    const summary = record.policyDecision?.reason ?? record.error?.message ?? "Completed"
    process.stdout.write(
      `[${record.status}] ${record.executionId} (${record.request.capabilityId}) — ${summary}` +
        EOL +
        `Evidence IDs: ${record.resultEvidenceIds.join(", ") || "none"}` +
        EOL,
    )
  }),
)
