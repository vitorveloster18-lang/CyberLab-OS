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
    const customSecret = Option.getOrUndefined(input.setSecret)

    if (input.generateSecret || customSecret !== undefined) {
      const updated = ws.cdiHub.configureSecretAndGateway(
        input.generateSecret
          ? { mode: "generate" }
          : { mode: "custom", customSecret: customSecret! },
      )
      if (input.json) {
        process.stdout.write(JSON.stringify(updated, null, 2) + EOL)
        return
      }
      process.stdout.write(
        [
          `CYBERLAB_PARTNER_SECRET saved to ${ws.cdiHub.getOverview().configFilePath}`,
          `  CYBERLAB_PARTNER_SECRET=${updated.sharedSecret}`,
          `  CYBERLAB_CALLBACK_URL=${updated.cyberlabCallbackUrl}`,
        ].join(EOL) + EOL,
      )
      if (!input.preset4 && !input.list && !Option.isSome(input.objective)) return
    }

    if (input.preset4) {
      ws.cdiHub.loadFourCdiPreset()
    }

    const objective = Option.getOrUndefined(input.objective)
    if (input.list || input.preset4 || !objective) {
      const overview = ws.cdiHub.getOverview()
      if (input.json) {
        process.stdout.write(JSON.stringify(overview, null, 2) + EOL)
        return
      }
      const lines = [
        `CyberLab CDI Partner Hub (${overview.partners.length} registered)`,
        `  Config File: ${overview.configFilePath}`,
        `  Shared Secret: ${overview.secretPreview}`,
        `  Bidirectional Callback URL: ${overview.cyberlabCallbackUrl}`,
        ...overview.partners.map(
          (p) =>
            `  - [${p.enabled ? "ON " : "OFF"}] ${p.partnerId} (${p.displayName}) -> ${p.endpointUrl} | initiate=${p.permissions.initiateActions}`,
        ),
      ]
      process.stdout.write(lines.join(EOL) + EOL)
      return
    }

    const partnerId = Option.getOrUndefined(input.partnerId)
    const partnersCsv = Option.getOrUndefined(input.partners)
    const endpointUrl = Option.getOrUndefined(input.endpoint)
    const rawEvidence = Option.getOrUndefined(input.evidence)
    const evidenceIds = rawEvidence
      ? rawEvidence
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : []

    if (partnersCsv) {
      const partnerIds = partnersCsv
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
      const report = yield* Effect.promise(() =>
        ws.delegateToMultiplePartners({
          partnerIds,
          objective,
          evidenceIds,
        }),
      )
      if (input.json) {
        process.stdout.write(JSON.stringify(report, null, 2) + EOL)
        return
      }
      const lines = [
        `Multi-CDI Dispatch [${report.mode}] (${report.succeededCount}/${report.totalDispatched} succeeded)`,
        ...report.results.map((r) =>
          r.ok
            ? `  [${r.displayName} ${r.durationMs}ms] ${r.outcome?.result?.summary ?? "ok"} (findings=${r.outcome?.createdFindings.length ?? 0})`
            : `  [${r.displayName} FAILED] ${r.error}`,
        ),
      ]
      process.stdout.write(lines.join(EOL) + EOL)
      return
    }

    const outcome = yield* Effect.promise(() =>
      ws.delegateToPartner({
        objective,
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
