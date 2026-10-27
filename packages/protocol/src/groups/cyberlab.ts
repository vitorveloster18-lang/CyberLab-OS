import { CyberLab } from "@opencode/schema/cyberlab"
import { Location } from "@opencode/schema/location"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { InvalidRequestError } from "../errors.js"
import { LocationQuery, locationQueryOpenApi } from "./location.js"

export const CyberLabGroup = HttpApiGroup.make("server.cyberlab")
  .add(
    HttpApiEndpoint.get("cyberlab.status", "/api/cyberlab/status", {
      query: LocationQuery,
      success: Location.response(CyberLab.WorkspaceStatus),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.status",
          summary: "Get CyberLab workspace status",
          description: "Retrieve current scope, capability count, execution count, evidence count, and finding count.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.capabilities", "/api/cyberlab/capabilities", {
      query: LocationQuery,
      success: Location.response(Schema.Array(CyberLab.CapabilityInfo)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.capabilities",
          summary: "List CyberLab capabilities",
          description: "List registered local CyberLab capabilities and risk profiles.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.scope.get", "/api/cyberlab/scope", {
      query: LocationQuery,
      success: Location.response(CyberLab.Scope),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.scope.get",
          summary: "Get CyberLab project scope",
          description: "Retrieve active project target scope.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.put("cyberlab.scope.set", "/api/cyberlab/scope", {
      query: LocationQuery,
      payload: CyberLab.ScopePatch,
      success: Location.response(CyberLab.Scope),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.scope.set",
          summary: "Update CyberLab project scope",
          description: "Update allowed/blocked targets and external target setting for the project scope.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.executions.list", "/api/cyberlab/executions", {
      query: LocationQuery,
      success: Location.response(Schema.Array(CyberLab.ExecutionInfo)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.executions.list",
          summary: "List CyberLab executions",
          description: "List all manual, proposed, approved, and completed executions for the workspace.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.executions.submit", "/api/cyberlab/executions", {
      query: LocationQuery,
      payload: CyberLab.SubmitExecutionInput,
      success: Location.response(CyberLab.ExecutionInfo),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.executions.submit",
          summary: "Submit CyberLab execution",
          description: "Submit a structured capability execution through PolicyEngine and ScopeController.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.approvals.list", "/api/cyberlab/approvals", {
      query: LocationQuery,
      success: Location.response(Schema.Array(CyberLab.ApprovalInfo)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.approvals.list",
          summary: "List pending CyberLab approvals",
          description: "List pending single-use human approval tickets.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.executions.approve", "/api/cyberlab/executions/approve", {
      query: LocationQuery,
      payload: CyberLab.ApproveExecutionInput,
      success: Location.response(CyberLab.ExecutionInfo),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.executions.approve",
          summary: "Approve and run queued CyberLab execution",
          description: "Approve a pending ticket and re-authorize execution against current scope.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.executions.cancel", "/api/cyberlab/executions/cancel", {
      query: LocationQuery,
      payload: CyberLab.CancelExecutionInput,
      success: Location.response(Schema.Struct({ cancelled: Schema.Boolean })),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.executions.cancel",
          summary: "Cancel CyberLab execution",
          description: "Abort a running or queued CyberLab execution.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.evidence.list", "/api/cyberlab/evidence", {
      query: LocationQuery,
      success: Location.response(Schema.Array(CyberLab.EvidenceInfo)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.evidence.list",
          summary: "List CyberLab evidence records",
          description: "List persisted SHA-256 evidence records for the project.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.evidence.verify", "/api/cyberlab/evidence/verify", {
      query: LocationQuery,
      payload: CyberLab.VerifyEvidenceInput,
      success: Location.response(CyberLab.VerifyEvidenceResult),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.evidence.verify",
          summary: "Verify CyberLab evidence SHA-256 custody",
          description: "Recompute SHA-256 hash of persisted evidence bytes and record custody audit entry.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.findings.list", "/api/cyberlab/findings", {
      query: LocationQuery,
      success: Location.response(Schema.Array(CyberLab.FindingInfo)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.findings.list",
          summary: "List CyberLab security findings",
          description: "List security findings with independent severity, confidence, and analyst review status.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.findings.create", "/api/cyberlab/findings", {
      query: LocationQuery,
      payload: CyberLab.CreateFindingInput,
      success: Location.response(CyberLab.FindingInfo),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.findings.create",
          summary: "Create unreviewed CyberLab finding",
          description: "Record a security finding linked to verified evidence IDs.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.findings.review", "/api/cyberlab/findings/review", {
      query: LocationQuery,
      payload: CyberLab.ReviewFindingInput,
      success: Location.response(CyberLab.FindingInfo),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.findings.review",
          summary: "Review CyberLab security finding",
          description: "Record a non-destructive human analyst review decision on a finding.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.report", "/api/cyberlab/report", {
      query: LocationQuery,
      success: Location.response(CyberLab.ReportOutput),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.report",
          summary: "Generate Markdown CyberLab assessment report",
          description: "Render reproducible Markdown assessment report backed by SHA-256 evidence references.",
        }),
      ),
  )
  .annotateMerge(
    OpenApi.annotations({
      title: "cyberlab",
      description: "Unified CyberLab OS operations, scope enforcement, and SHA-256 evidence management routes.",
    }),
  )
