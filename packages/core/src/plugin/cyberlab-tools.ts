export * as CyberLabToolsPlugin from "./cyberlab-tools.js"

import { CyberLabWorkspaceManager } from "@cyberlab/core"
import { ToolFailure } from "@opencode/ai/effect"
import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { Location } from "../location.js"
import { Permission } from "../permission.js"

const StatusInput = Schema.Struct({})
const StatusOutput = Schema.Struct({
  projectId: Schema.String,
  platform: Schema.String,
  capabilityIds: Schema.Array(Schema.String),
  evidenceCount: Schema.Number,
  findingCount: Schema.Number,
  summary: Schema.String,
})

const ExecuteInput = Schema.Struct({
  capabilityId: Schema.String.annotate({
    description: "Registered CyberLab capability ID (e.g. code-analysis.workspace-audit)",
  }),
  input: Schema.Record(Schema.String, Schema.Unknown).annotate({
    description: "Structured capability parameters (never raw shell command strings)",
  }),
  mode: Schema.optionalKey(
    Schema.Literals(["proposed", "approved", "lab_automation"]).annotate({
      description: "Execution mode for assistant invocation (defaults to approved for passive read-only checks)",
    }),
  ),
})

const ExecuteOutput = Schema.Struct({
  executionId: Schema.String,
  status: Schema.String,
  evidenceIds: Schema.Array(Schema.String),
  summary: Schema.String,
})

const EvidenceListInput = Schema.Struct({
  executionId: Schema.optionalKey(Schema.String),
})

const EvidenceListOutput = Schema.Struct({
  count: Schema.Number,
  output: Schema.String,
})

const ProposeFindingInput = Schema.Struct({
  title: Schema.String,
  description: Schema.String,
  severity: Schema.Literals(["info", "low", "medium", "high", "critical"]),
  confidence: Schema.Number,
  evidenceIds: Schema.Array(Schema.String),
  affectedAssets: Schema.Array(Schema.String),
  proposedRemediation: Schema.optionalKey(Schema.String),
})

const ProposeFindingOutput = Schema.Struct({
  findingId: Schema.String,
  status: Schema.String,
  output: Schema.String,
})

const failTool = (label: string, error?: unknown) =>
  new ToolFailure({
    message: `CyberLab tool ${label} failed: ${error instanceof Error ? error.message : String(error ?? "unknown")}`,
    error,
  })

export const Plugin = {
  id: "cyberlab.tools",
  effect: Effect.fn("CyberLabToolsPlugin.Plugin")(function* (ctx: Context) {
    const location = yield* Location.Service
    const permission = yield* Permission.Service

    const getWorkspace = () =>
      Effect.tryPromise({
        try: () => CyberLabWorkspaceManager.global.forProject(String(location.project.id), String(location.directory)),
        catch: (error) => failTool("workspace", error),
      })

    yield* ctx.tool
      .transform((editor) => {
        editor.add({
          name: "cyberlab_status",
          options: { codemode: false },
          description:
            "Inspect the unified CyberLab workspace scope, registered capabilities, evidence count, and security findings.",
          input: StatusInput,
          output: StatusOutput,
          execute: () =>
            Effect.gen(function* () {
              const ws = yield* getWorkspace()
              const status = yield* Effect.tryPromise({
                try: () => ws.getStatus(),
                catch: (e) => failTool("cyberlab_status", e),
              })
              const caps = yield* Effect.tryPromise({
                try: () => ws.listCapabilities(),
                catch: (e) => failTool("cyberlab_status", e),
              })
              const capabilityIds = caps.map((c) => c.id)
              const platform = `${status.environment.platform}/${status.environment.arch}`
              const summary = `CyberLab [${platform}] project=${status.projectId} capabilities=${capabilityIds.join(", ")} evidence=${status.evidenceCount} findings=${status.findingCount}`
              const output = {
                projectId: status.projectId,
                platform,
                capabilityIds,
                evidenceCount: status.evidenceCount,
                findingCount: status.findingCount,
                summary,
              }
              return { output, content: summary }
            }),
        })

        editor.add({
          name: "cyberlab_execute",
          options: { codemode: false },
          description:
            "Submit a structured CyberLab capability execution through PolicyEngine and ScopeController. Never accepts raw shell strings.",
          input: ExecuteInput,
          output: ExecuteOutput,
          execute: (input, context) =>
            Effect.gen(function* () {
              yield* permission
                .assert({
                  action: "cyberlab_execute",
                  resources: [input.capabilityId],
                  save: [input.capabilityId],
                  sessionID: context.sessionID,
                  agent: context.agent,
                  source: { type: "tool", messageID: context.messageID, id: context.id },
                })
                .pipe(Effect.mapError((e) => failTool("cyberlab_execute", e)))

              const ws = yield* getWorkspace()
              const record = yield* Effect.tryPromise({
                try: () =>
                  ws.submitExecution({
                    capabilityId: input.capabilityId,
                    input: input.input,
                    mode: input.mode ?? "approved",
                    requestedBy: { type: "assistant", id: String(context.agent) },
                  }),
                catch: (e) => failTool("cyberlab_execute", e),
              })
              const summary =
                record.policyDecision?.reason ??
                record.error?.message ??
                `Execution ${record.executionId} transitioned to ${record.status}`
              const output = {
                executionId: record.executionId,
                status: record.status,
                evidenceIds: record.resultEvidenceIds,
                summary,
              }
              return {
                output,
                content: `[${record.status}] ${summary} (evidence: ${record.resultEvidenceIds.join(", ") || "none"})`,
              }
            }),
        })

        editor.add({
          name: "cyberlab_evidence_list",
          options: { codemode: false },
          description: "List SHA-256 verified evidence records stored in the unified CyberLab workspace.",
          input: EvidenceListInput,
          output: EvidenceListOutput,
          execute: (input) =>
            Effect.gen(function* () {
              const ws = yield* getWorkspace()
              const records = yield* Effect.tryPromise({
                try: () => ws.listEvidence(input.executionId),
                catch: (e) => failTool("cyberlab_evidence_list", e),
              })
              const text = records
                .map((r) => `- ${r.evidenceId} [${r.kind}] sha256:${r.integrity.sha256.slice(0, 16)}... (${r.title})`)
                .join("\n")
              const output = { count: records.length, output: text || "No evidence recorded yet." }
              return { output, content: output.output }
            }),
        })

        editor.add({
          name: "cyberlab_finding_propose",
          options: { codemode: false },
          description:
            "Propose an unreviewed SecurityFinding backed by verified evidence IDs with distinct severity and confidence.",
          input: ProposeFindingInput,
          output: ProposeFindingOutput,
          execute: (input, context) =>
            Effect.gen(function* () {
              const ws = yield* getWorkspace()
              const finding = yield* Effect.tryPromise({
                try: () =>
                  ws.createFinding({
                    title: input.title,
                    description: input.description,
                    severity: input.severity,
                    confidence: input.confidence,
                    evidenceIds: [...input.evidenceIds],
                    affectedAssets: [...input.affectedAssets],
                    ...(input.proposedRemediation !== undefined
                      ? { proposedRemediation: input.proposedRemediation }
                      : {}),
                    createdBy: `assistant:${String(context.agent)}`,
                  }),
                catch: (e) => failTool("cyberlab_finding_propose", e),
              })
              const summary = `Proposed finding ${finding.findingId} [${finding.severity}, status=${finding.status}]`
              return {
                output: { findingId: finding.findingId, status: finding.status, output: summary },
                content: summary,
              }
            }),
        })
      })
      .pipe(Effect.orDie)
  }),
}
