import { Effect, Option } from "effect"
import { readFileSync } from "node:fs"
import { EOL } from "node:os"
import path from "node:path"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.external,
  Effect.fn("cli.cyberlab.external")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.external>,
  ) {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
    const action = (Option.getOrUndefined(input.action) ?? "tools").trim().toLowerCase()

    if (action === "tools") {
      const tools = yield* Effect.promise(() => ws.listExternalTools())
      const pendingInbox = ws.externalControl.countPendingInboxFiles()
      if (input.json) {
        process.stdout.write(
          JSON.stringify(
            {
              pendingInboxCount: pendingInbox,
              inboxDirectory: ws.externalControl.inboxDir,
              tools,
            },
            null,
            2,
          ) + EOL,
        )
        return
      }

      const lines = [
        `CyberLab OS — External Tool & Manual Action Control Plane`,
        `  Inbox Drop Folder: ${ws.externalControl.inboxDir} (${pendingInbox} pending file(s))`,
        "",
        ...tools.map((t) => {
          const badge = t.available ? `READY (${t.resolvedPath})` : `MISSING — hint: ${t.installHint}`
          const cap = t.governedCapabilityId ? ` | capability=${t.governedCapabilityId}` : ""
          return `  - ${t.toolId} [${t.licenseSpdx}, ${t.integrationMode}${cap}]: ${badge}`
        }),
      ]
      process.stdout.write(lines.join(EOL) + EOL)
      return
    }

    if (action === "sync") {
      const res = yield* Effect.promise(() => ws.syncExternalInbox("cli-operator"))
      if (input.json) {
        process.stdout.write(JSON.stringify(res, null, 2) + EOL)
        return
      }
      const lines = [
        `Synced .cyberlab/inbox: ${res.ingested.length} artifact(s) ingested (${res.scannedCount} scanned)`,
        ...res.ingested.map(
          (i) => `  + ${i.fileName} -> ${i.evidenceId} (sha256:${i.sha256.slice(0, 16)}...) archived to ${i.archivedTo}`,
        ),
        ...res.skippedReasons.map((s) => `  ! ${s}`),
      ]
      process.stdout.write(lines.join(EOL) + EOL)
      return
    }

    if (action === "ingest") {
      const toolId = Option.getOrUndefined(input.tool) ?? "manual-external"
      const target = Option.getOrUndefined(input.target)
      const fileOpt = Option.getOrUndefined(input.file)
      if (!fileOpt) {
        process.stderr.write(`--file <path> is required when --action ingest is used.${EOL}`)
        process.exitCode = 1
        return
      }
      const resolvedFile = path.resolve(ws.workspaceRoot, fileOpt)
      const rawOutput = readFileSync(resolvedFile, "utf8")
      const ingested = yield* Effect.promise(() =>
        ws.ingestExternalAction({
          toolId,
          ...(target !== undefined ? { target } : {}),
          rawOutput,
          origin: "manual_external",
          actor: "cli-operator",
        }),
      )
      if (input.json) {
        process.stdout.write(JSON.stringify(ingested, null, 2) + EOL)
        return
      }
      process.stdout.write(
        `Ingested external action [${ingested.toolId}] -> ${ingested.evidenceId} (sha256:${ingested.sha256.slice(0, 16)}..., scope=${ingested.scopeAuditStatus}, redaction=${ingested.redactionStatus})${EOL}`,
      )
      return
    }

    if (action === "wrap") {
      const toolId = Option.getOrUndefined(input.tool) ?? Option.getOrUndefined(input.binary) ?? "external-cli"
      const binary = Option.getOrUndefined(input.binary) ?? toolId
      const target = Option.getOrUndefined(input.target)
      if (!target) {
        process.stderr.write(`--target <host|url|path> is required for supervised --action wrap.${EOL}`)
        process.exitCode = 1
        return
      }
      const rawArgs = Option.getOrUndefined(input.args)
      let parsedArgs: string[] = []
      if (rawArgs) {
        const decoded = JSON.parse(rawArgs) as unknown
        if (!Array.isArray(decoded) || !decoded.every((x) => typeof x === "string")) {
          process.stderr.write(`--args must be a JSON array of strings (e.g. '["-sV","-p","8080","127.0.0.1"]').${EOL}`)
          process.exitCode = 1
          return
        }
        parsedArgs = decoded
      }

      const wrapped = yield* Effect.promise(() =>
        ws.runSupervisedExternalCommand({
          toolId,
          binary,
          args: parsedArgs,
          target,
          onStdoutChunk: (chunk) => process.stdout.write(chunk),
          onStderrChunk: (chunk) => process.stderr.write(chunk),
        }),
      )

      if (wrapped.blocked) {
        process.stderr.write(`${EOL}[CyberLab Control Plane BLOCKED] ${wrapped.reason}${EOL}`)
        process.exitCode = 2
        return
      }

      process.stdout.write(
        `${EOL}[CyberLab Control Plane] Recorded ${wrapped.ingested?.evidenceId} (sha256:${wrapped.ingested?.sha256.slice(0, 16)}..., exit=${wrapped.exitCode})${EOL}`,
      )
      if (wrapped.exitCode && wrapped.exitCode !== 0) {
        process.exitCode = wrapped.exitCode
      }
      return
    }

    process.stderr.write(`Unknown --action "${action}". Expected tools | sync | ingest | wrap.${EOL}`)
    process.exitCode = 1
  }),
)
