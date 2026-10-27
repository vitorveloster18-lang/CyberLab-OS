import {
  CyberLabWorkspaceManager,
  type CapabilityDefinition,
  type EvidenceRecord,
  type ExecutionRecord,
  type SecurityFinding,
} from "@cyberlab/core"
import { Location } from "@opencode/core/location"
import { InvalidRequestError } from "@opencode/protocol/errors"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/http-api"
import { Api } from "../api"
import { response } from "../location"

function toCapabilityInfo(cap: CapabilityDefinition) {
  return {
    id: cap.id,
    version: cap.version,
    title: cap.title,
    description: cap.description,
    risk: cap.risk,
    requiresScope: Boolean(cap.requiredScope && cap.requiredScope.length > 0),
    executorId: cap.executorId,
    skillIds: cap.skillIds,
    enabled: cap.enabled,
  }
}

function toExecutionInfo(rec: ExecutionRecord) {
  return {
    executionId: rec.executionId,
    requestId: rec.request.requestId,
    projectId: rec.request.projectId,
    capabilityId: rec.request.capabilityId,
    status: rec.status,
    ...(rec.startedAt !== undefined ? { startedAt: rec.startedAt } : {}),
    ...(rec.finishedAt !== undefined ? { finishedAt: rec.finishedAt } : {}),
    ...(rec.policyDecision?.reason !== undefined ? { policyReason: rec.policyDecision.reason } : {}),
    evidenceIds: rec.resultEvidenceIds,
    ...(rec.error !== undefined ? { error: rec.error } : {}),
  }
}

function toEvidenceInfo(rec: EvidenceRecord) {
  return {
    evidenceId: rec.evidenceId,
    projectId: rec.projectId,
    kind: rec.kind,
    title: rec.title,
    sha256: rec.integrity.sha256,
    sizeBytes: rec.content.byteLength ?? 0,
    mediaType: rec.content.mediaType,
    observedAt: rec.observedAt,
    createdAt: rec.createdAt,
    executionId: rec.source.executionId,
    redactionStatus: rec.redactionStatus,
  }
}

function toFindingInfo(f: SecurityFinding) {
  return {
    findingId: f.findingId,
    projectId: f.projectId,
    title: f.title,
    description: f.description,
    severity: f.severity,
    ...(f.confidence !== undefined ? { confidence: f.confidence } : {}),
    status: f.status,
    evidenceIds: f.evidenceIds,
    affectedAssets: f.affectedAssets,
    ...(f.proposedRemediation !== undefined ? { proposedRemediation: f.proposedRemediation } : {}),
    createdAt: f.createdAt,
    updatedAt: f.updatedAt,
  }
}

const resolveWorkspace = Effect.gen(function* () {
  const location = yield* Location.Service
  return yield* Effect.promise(() =>
    CyberLabWorkspaceManager.global.forProject(String(location.project.id), String(location.directory)),
  )
})

const runBadRequest = <A>(fn: () => Promise<A>) =>
  Effect.tryPromise({
    try: fn,
    catch: (error) =>
      new InvalidRequestError({
        message: error instanceof Error ? error.message : String(error),
      }),
  })

export const CyberLabHandler = HttpApiBuilder.group(Api, "server.cyberlab", (handlers) =>
  handlers
    .handle("cyberlab.status", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* Effect.promise(() => ws.getStatus())
        }),
      ),
    )
    .handle("cyberlab.capabilities", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const caps = yield* Effect.promise(() => ws.listCapabilities())
          return caps.map(toCapabilityInfo)
        }),
      ),
    )
    .handle("cyberlab.scope.get", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const scope = yield* Effect.promise(() => ws.getScope())
          if (!scope) {
            return yield* Effect.fail(new InvalidRequestError({ message: "No active scope configured" }))
          }
          return scope
        }),
      ),
    )
    .handle("cyberlab.scope.set", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(() =>
            ws.updateScope({
              ...(payload.name !== undefined ? { name: payload.name } : {}),
              ...(payload.allowedTargets !== undefined
                ? {
                    allowedTargets: payload.allowedTargets.map((r) => ({
                      kind: r.kind,
                      value: r.value,
                      ...(r.notes !== undefined ? { notes: r.notes } : {}),
                    })),
                  }
                : {}),
              ...(payload.blockedTargets !== undefined
                ? {
                    blockedTargets: payload.blockedTargets.map((r) => ({
                      kind: r.kind,
                      value: r.value,
                      ...(r.notes !== undefined ? { notes: r.notes } : {}),
                    })),
                  }
                : {}),
              ...(payload.allowExternalTargets !== undefined
                ? { allowExternalTargets: payload.allowExternalTargets }
                : {}),
              ...(payload.active !== undefined ? { active: payload.active } : {}),
            }),
          )
        }),
      ),
    )
    .handle("cyberlab.executions.list", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const list = yield* Effect.promise(() => ws.listExecutions())
          return list.map(toExecutionInfo)
        }),
      ),
    )
    .handle("cyberlab.executions.submit", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const rec = yield* runBadRequest(() =>
            ws.submitExecution({
              capabilityId: payload.capabilityId,
              input: payload.input,
              ...(payload.mode !== undefined ? { mode: payload.mode } : {}),
              ...(payload.idempotencyKey !== undefined ? { idempotencyKey: payload.idempotencyKey } : {}),
            }),
          )
          return toExecutionInfo(rec)
        }),
      ),
    )
    .handle("cyberlab.approvals.list", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const pending = yield* Effect.promise(() => ws.listPendingApprovals())
          return pending.map((t) => ({
            approvalId: t.approvalId,
            projectId: t.projectId,
            executionId: t.executionId,
            capabilityId: t.capabilityId,
            targetSummary: t.targetSummary,
            status: t.status,
            createdAt: t.createdAt,
            expiresAt: t.expiresAt,
          }))
        }),
      ),
    )
    .handle("cyberlab.executions.approve", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const rec = yield* runBadRequest(() =>
            ws.approveExecution({
              approvalId: payload.approvalId,
              decidedBy: payload.decidedBy,
              ...(payload.reason !== undefined ? { reason: payload.reason } : {}),
            }),
          )
          return toExecutionInfo(rec)
        }),
      ),
    )
    .handle("cyberlab.executions.cancel", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          yield* runBadRequest(() => ws.cancelExecution(payload.executionId, payload.reason))
          return { cancelled: true }
        }),
      ),
    )
    .handle("cyberlab.evidence.list", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const evs = yield* Effect.promise(() => ws.listEvidence())
          return evs.map(toEvidenceInfo)
        }),
      ),
    )
    .handle("cyberlab.evidence.verify", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* Effect.promise(() => ws.verifyEvidence(payload.evidenceId, "http-api"))
        }),
      ),
    )
    .handle("cyberlab.findings.list", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const list = yield* Effect.promise(() => ws.listFindings())
          return list.map(toFindingInfo)
        }),
      ),
    )
    .handle("cyberlab.findings.create", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const created = yield* runBadRequest(() =>
            ws.createFinding({
              title: payload.title,
              description: payload.description,
              severity: payload.severity,
              ...(payload.confidence !== undefined ? { confidence: payload.confidence } : {}),
              evidenceIds: [...payload.evidenceIds],
              affectedAssets: [...payload.affectedAssets],
              ...(payload.proposedRemediation !== undefined
                ? { proposedRemediation: payload.proposedRemediation }
                : {}),
              createdBy: "http-operator",
            }),
          )
          return toFindingInfo(created)
        }),
      ),
    )
    .handle("cyberlab.findings.review", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const reviewed = yield* runBadRequest(() =>
            ws.reviewFinding({
              findingId: payload.findingId,
              reviewedBy: payload.reviewedBy,
              decision: payload.decision,
              ...(payload.notes !== undefined ? { notes: payload.notes } : {}),
            }),
          )
          return toFindingInfo(reviewed)
        }),
      ),
    )
    .handle("cyberlab.report", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const markdown = yield* Effect.promise(() => ws.generateMarkdownReport())
          return { markdown }
        }),
      ),
    )
    .handle("cyberlab.external.tools", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const tools = yield* Effect.promise(() => ws.listExternalTools())
          return {
            pendingInboxCount: ws.externalControl.countPendingInboxFiles(),
            inboxDirectory: ws.externalControl.inboxDir,
            tools,
          }
        }),
      ),
    )
    .handle("cyberlab.external.ingest", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(() =>
            ws.ingestExternalAction({
              toolId: payload.toolId,
              ...(payload.title !== undefined ? { title: payload.title } : {}),
              ...(payload.origin !== undefined ? { origin: payload.origin } : {}),
              ...(payload.target !== undefined ? { target: payload.target } : {}),
              ...(payload.commandSummary !== undefined ? { commandSummary: payload.commandSummary } : {}),
              rawOutput: payload.rawOutput,
              ...(payload.mediaType !== undefined ? { mediaType: payload.mediaType } : {}),
              actor: "http-control-plane",
            }),
          )
        }),
      ),
    )
    .handle("cyberlab.external.sync", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(() => ws.syncExternalInbox("http-control-plane"))
        }),
      ),
    )
    .handle("cyberlab.evidence.read", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(() => ws.readEvidenceContent(payload.evidenceId, "http-workbench"))
        }),
      ),
    )
    .handle("cyberlab.proxy.overview", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* Effect.promise(() => ws.getProxyOverview())
        }),
      ),
    )
    .handle("cyberlab.proxy.control", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(() =>
            ws.controlProxy({
              action: payload.action,
              ...(payload.port !== undefined ? { port: payload.port } : {}),
              ...(payload.scopeOnly !== undefined ? { scopeOnly: payload.scopeOnly } : {}),
            }),
          )
        }),
      ),
    )
    .handle("cyberlab.proxy.persist", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(() => ws.persistProxyEntry(payload.entryId, "http-workbench"))
        }),
      ),
    )
    .handle("cyberlab.partners.overview", () =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return ws.cdiHub.getOverview()
        }),
      ),
    )
    .handle("cyberlab.partners.manage", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(async () => {
            if (payload.operation === "preset_4") {
              ws.cdiHub.loadFourCdiPreset(payload.baseHost)
            } else if (payload.operation === "remove") {
              if (!payload.partnerId) throw new Error("partnerId is required for remove")
              ws.cdiHub.removePartner(payload.partnerId)
            } else {
              if (!payload.partnerId) throw new Error("partnerId is required for upsert")
              ws.cdiHub.upsertPartner({
                partnerId: payload.partnerId,
                displayName: payload.displayName ?? payload.partnerId,
                ...(payload.specialty !== undefined ? { specialty: payload.specialty } : {}),
                endpointUrl: payload.endpointUrl ?? "http://127.0.0.1:8788/cyberlab/partner",
                ...(payload.enabled !== undefined ? { enabled: payload.enabled } : {}),
                ...(payload.secretOverride !== undefined ? { secretOverride: payload.secretOverride } : {}),
                ...(payload.permissions !== undefined ? { permissions: payload.permissions } : {}),
              })
            }
            return ws.cdiHub.getOverview()
          })
        }),
      ),
    )
    .handle("cyberlab.partners.secret", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(async () => {
            if (payload.operation === "reveal") {
              return ws.cdiHub.revealSharedSecret()
            }
            const res = ws.cdiHub.configureSecretAndGateway({
              mode: payload.operation,
              ...(payload.customSecret !== undefined ? { customSecret: payload.customSecret } : {}),
              ...(payload.cyberlabCallbackUrl !== undefined ? { cyberlabCallbackUrl: payload.cyberlabCallbackUrl } : {}),
            })
            return { sharedSecret: res.sharedSecret, cyberlabCallbackUrl: res.cyberlabCallbackUrl }
          })
        }),
      ),
    )
    .handle("cyberlab.partners.dispatch", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          return yield* runBadRequest(() =>
            ws.delegateToMultiplePartners({
              partnerIds: [...payload.partnerIds],
              objective: payload.objective,
              ...(payload.evidenceIds !== undefined ? { evidenceIds: [...payload.evidenceIds] } : {}),
              ...(payload.contextText !== undefined ? { contextText: payload.contextText } : {}),
              ...(payload.timeoutMs !== undefined ? { timeoutMs: payload.timeoutMs } : {}),
            }),
          )
        }),
      ),
    )
    .handle("cyberlab.partners.gateway", ({ payload }) =>
      response(
        Effect.gen(function* () {
          const ws = yield* resolveWorkspace
          const res = yield* Effect.promise(() => ws.cdiHub.handleInboundGatewayRequest(payload))
          return res.body
        }),
      ),
    ),
)

