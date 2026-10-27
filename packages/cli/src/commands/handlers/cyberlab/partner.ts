import { Effect, Option } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.partner,
  Effect.fn("cli.cyberlab.partner")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.partner>,
  ) {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
    const partnerId = Option.getOrUndefined(input.partnerId)
    const endpointUrl = Option.getOrUndefined(input.endpoint)
    const rawEvidence = Option.getOrUndefined(input.evidence)
    const evidenceIds = rawEvidence
      ? rawEvidence
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : []

    const outcome = yield* Effect.promise(() =>
      ws.delegateToPartner({
        objective: input.objective,
        ...(partnerId !== undefined ? { partnerId } : {}),
        ...(endpointUrl !== undefined ? { endpointUrl } : {}),
        evidenceIds,
      }),
    )

    if (input.json) {
      process.stdout.write(JSON.stringify(outcome, null, 2) + EOL)
      return
    }

    const lines = [
      `Partner Task Outcome [${outcome.result?.status ?? "no_result"}]`,
      `  Summary: ${outcome.result?.summary ?? "(none)"}`,
      `  Unreviewed Findings Recorded: ${outcome.createdFindings.length}`,
      `  Proposed Executions Queued for Approval: ${outcome.proposedExecutions.length}`,
      `  Limitations: ${(outcome.result?.limitations ?? []).join(" | ") || "none"}`,
    ]
    process.stdout.write(lines.join(EOL) + EOL)
  }),
)
