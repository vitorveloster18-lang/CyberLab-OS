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

const DelegatePartnerInput = Schema.Struct({
  objective: Schema.String.annotate({
    description: "Analysis objective sent to one CDI specialist or multiple CDIs in parallel",
  }),
  evidenceIds: Schema.optionalKey(Schema.Array(Schema.String)),
  partnerId: Schema.optionalKey(Schema.String),
  partnerIds: Schema.optionalKey(
    Schema.Array(Schema.String).annotate({
      description: "Optional list of CDI IDs (e.g. ['salem','kairos','naia']) to call in parallel",
    }),
  ),
})

const DelegatePartnerOutput = Schema.Struct({
  status: Schema.String,
  summary: Schema.String,
  unreviewedFindingCount: Schema.Number,
})

const ExternalControlInput = Schema.Struct({
  operation: Schema.Literals(["list_tools", "list_arsenal_slots", "sync_inbox"]).annotate({
    description:
      "Inspect externally installed tools & v5.0 Real Arsenal Slots (Windows PowerShell + WSL2 Kali + Web UIs) or sync manual external tool outputs from .cyberlab/inbox/",
  }),
})

const ExternalControlOutput = Schema.Struct({
  availableTools: Schema.Array(Schema.String),
  ingestedEvidenceIds: Schema.Array(Schema.String),
  summary: Schema.String,
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

        editor.add({
          name: "cyberlab_partner_delegate",
          options: { codemode: false },
          description:
            "Delegate a redacted analysis task to one CDI partner specialist (e.g. salem) or to multiple CDI partners in parallel (e.g. ['salem', 'kairos', 'naia']).",
          input: DelegatePartnerInput,
          output: DelegatePartnerOutput,
          execute: (input, context) =>
            Effect.gen(function* () {
              const multiTargets =
                input.partnerIds && input.partnerIds.length > 0
                  ? [...input.partnerIds]
                  : [input.partnerId ?? "chat-py-agent"]

              yield* permission
                .assert({
                  action: "cyberlab_partner_delegate",
                  resources: multiTargets,
                  save: multiTargets,
                  sessionID: context.sessionID,
                  agent: context.agent,
                  source: { type: "tool", messageID: context.messageID, id: context.id },
                })
                .pipe(Effect.mapError((e) => failTool("cyberlab_partner_delegate", e)))

              const ws = yield* getWorkspace()
              if (multiTargets.length > 1) {
                const report = yield* Effect.tryPromise({
                  try: () =>
                    ws.delegateToMultiplePartners({
                      partnerIds: multiTargets,
                      objective: input.objective,
                      evidenceIds: input.evidenceIds ? [...input.evidenceIds] : [],
                    }),
                  catch: (e) => failTool("cyberlab_partner_delegate", e),
                })
                const totalFindings = report.results.reduce(
                  (acc, r) => acc + (r.outcome?.createdFindings.length ?? 0),
                  0,
                )
                const mergedSummary = report.results
                  .map((r) =>
                    r.ok
                      ? `[${r.displayName} (${r.durationMs}ms)]: ${r.outcome?.result?.summary ?? "ok"}`
                      : `[${r.displayName} FAILED]: ${r.error}`,
                  )
                  .join("\n\n")
                const status = report.failedCount === 0 ? "completed" : report.succeededCount > 0 ? "partial" : "failed"
                return {
                  output: {
                    status,
                    summary: mergedSummary,
                    unreviewedFindingCount: totalFindings,
                  },
                  content: `[parallel CDIs (${report.succeededCount}/${report.totalDispatched}) ${status}]\n${mergedSummary}`,
                }
              }

              const targetPartner = multiTargets[0]!
              const outcome = yield* Effect.tryPromise({
                try: () =>
                  ws.delegateToPartner({
                    objective: input.objective,
                    partnerId: targetPartner,
                    evidenceIds: input.evidenceIds ? [...input.evidenceIds] : [],
                  }),
                catch: (e) => failTool("cyberlab_partner_delegate", e),
              })
              const status = outcome.result?.status ?? "no_result"
              const summary = outcome.result?.summary ?? "No partner summary returned."
              return {
                output: {
                  status,
                  summary,
                  unreviewedFindingCount: outcome.createdFindings.length,
                },
                content: `[partner:${targetPartner} ${status}] ${summary} (unreviewed findings: ${outcome.createdFindings.length})`,
              }
            }),
        })

        editor.add({
          name: "cyberlab_external_control",
          options: { codemode: false },
          description:
            "Unified Control Plane for external security tools and manual operator runs: inspect installed external tools or synchronize .cyberlab/inbox/ artifacts into SHA-256 evidence.",
          input: ExternalControlInput,
          output: ExternalControlOutput,
          execute: (input) =>
            Effect.gen(function* () {
              const ws = yield* getWorkspace()
              const tools = yield* Effect.tryPromise({
                try: () => ws.listExternalTools(),
                catch: (e) => failTool("cyberlab_external_control", e),
              })
              const availableTools = tools.filter((t) => t.available).map((t) => t.toolId)

              if (input.operation === "sync_inbox") {
                const synced = yield* Effect.tryPromise({
                  try: () => ws.syncExternalInbox("assistant:external-control"),
                  catch: (e) => failTool("cyberlab_external_control", e),
                })
                const ids = synced.ingested.map((i) => i.evidenceId)
                const summary = `Synced .cyberlab/inbox: ${ids.length} artifact(s) ingested [${ids.join(", ") || "none"}]; available external tools: ${availableTools.join(", ") || "none"}.`
                return {
                  output: { availableTools, ingestedEvidenceIds: ids, summary },
                  content: summary,
                }
              }

              const summary = tools
                .map(
                  (t) =>
                    `${t.toolId}: ${t.available ? `READY (${t.resolvedPath})` : "not installed"}${t.governedCapabilityId ? ` -> ${t.governedCapabilityId}` : ""}`,
                )
                .join("\n")
              return {
                output: { availableTools, ingestedEvidenceIds: [], summary },
                content: summary,
              }
            }),
        })
      })
      .pipe(Effect.orDie)
  }),
}
