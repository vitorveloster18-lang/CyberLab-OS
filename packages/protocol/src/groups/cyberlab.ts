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
          description: "Update allowed/blocked targets, engagement profile, and external target setting for the project scope.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.scope.import", "/api/cyberlab/scope/import", {
      query: LocationQuery,
      payload: CyberLab.ScopeImportInput,
      success: Location.response(CyberLab.ScopeImportOutput),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.scope.import",
          summary: "Import HackerOne / Bugcrowd / wildcard Bug Bounty scope",
          description: "Parses HackerOne JSON, Bugcrowd JSON, or plaintext wildcard/exclusion rules into ProjectScope.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.artifacts.list", "/api/cyberlab/artifacts", {
      query: LocationQuery,
      success: Location.response(Schema.Array(CyberLab.ImportedArtifactInfo)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.artifacts.list",
          summary: "List external files uploaded/imported into .cyberlab/imports",
          description: "List local APKs, binaries, PCAPs, HARs, OpenAPI specs, and logs imported into the project workspace.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.artifacts.upload", "/api/cyberlab/artifacts/upload", {
      query: LocationQuery,
      payload: CyberLab.ArtifactUploadInput,
      success: Location.response(CyberLab.ArtifactUploadOutput),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.artifacts.upload",
          summary: "Import an external file from the operator's computer into .cyberlab/imports",
          description: "Saves an APK, ELF/PE, PCAP, HAR, OpenAPI spec, or log inside the workspace so any tool can inspect it.",
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
  .add(
    HttpApiEndpoint.get("cyberlab.external.tools", "/api/cyberlab/external/tools", {
      query: LocationQuery,
      success: Location.response(CyberLab.ExternalToolsOverview),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.external.tools",
          summary: "List external tools & inbox status in CyberLab Control Plane",
          description:
            "Inspect externally installed tools (nmap, nuclei, ffuf, tshark, opentrap, mvt, ghidra) and .cyberlab/inbox pending files.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.external.ingest", "/api/cyberlab/external/ingest", {
      query: LocationQuery,
      payload: CyberLab.IngestExternalActionInput,
      success: Location.response(CyberLab.IngestExternalActionOutput),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.external.ingest",
          summary: "Ingest an action executed outside CyberLab OS into the unified EvidenceStore",
          description:
            "Validates target against ScopeController, redacts secrets, computes SHA-256, and stores external manual/MCP/plugin output.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.external.sync", "/api/cyberlab/external/sync", {
      query: LocationQuery,
      success: Location.response(CyberLab.InboxSyncOutput),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.external.sync",
          summary: "Synchronize .cyberlab/inbox external tool outputs into EvidenceStore",
          description: "Ingest and archive all artifacts dropped by external tools into .cyberlab/inbox/.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.evidence.read", "/api/cyberlab/evidence/read", {
      query: LocationQuery,
      payload: CyberLab.ReadEvidenceInput,
      success: Location.response(CyberLab.ReadEvidenceOutput),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.evidence.read",
          summary: "Read redacted content of an EvidenceRecord for visual workbench rendering",
          description: "Returns redacted payload text and SHA-256 metadata confined to the active project.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.arsenal.overview", "/api/cyberlab/arsenal", {
      query: LocationQuery,
      success: Location.response(CyberLab.ArsenalOverview),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.overview",
          summary: "Get CyberLab OS v5.0 Real External Arsenal overview",
          description: "Returns Windows + WSL2 Kali slots, custom slots, live CLI/installer runs, and companion browsers.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.arsenal.probe", "/api/cyberlab/arsenal/probe", {
      query: LocationQuery,
      success: Location.response(CyberLab.ArsenalOverview),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.probe",
          summary: "Force fresh Windows PowerShell + WSL2 Kali binary & web detection",
          description: "Refreshes WSL2 distros, external binaries, and CyberChef local web directory.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.put("cyberlab.arsenal.config", "/api/cyberlab/arsenal/config", {
      query: LocationQuery,
      payload: CyberLab.ArsenalConfigPatchInput,
      success: Location.response(CyberLab.ArsenalOverview),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.config",
          summary: "Update external tools root, WSL2 distro, or individual slot overrides",
          description: "Persists global Arsenal configuration in ~/.cyberlab/arsenal-config.json.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.arsenal.custom.upsert", "/api/cyberlab/arsenal/custom", {
      query: LocationQuery,
      payload: CyberLab.ArsenalCustomSlotInput,
      success: Location.response(CyberLab.ArsenalOverview),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.custom.upsert",
          summary: "Create or update a Custom User Arsenal Slot",
          description: "Adds any new CLI tool, local Web UI, or Desktop/WSL2 GUI tool into the CyberLab OS Arsenal.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.arsenal.custom.remove", "/api/cyberlab/arsenal/custom/remove", {
      query: LocationQuery,
      payload: CyberLab.ArsenalCustomSlotRemoveInput,
      success: Location.response(CyberLab.ArsenalOverview),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.custom.remove",
          summary: "Remove a Custom User Arsenal Slot",
          description: "Removes a custom slot from ~/.cyberlab/arsenal-config.json.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.arsenal.launch", "/api/cyberlab/arsenal/launch", {
      query: LocationQuery,
      payload: CyberLab.ArsenalLaunchInput,
      success: Location.response(CyberLab.ArsenalLaunchResult),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.launch",
          summary: "Launch or run a Real External Arsenal Slot (Web UI, CLI Runner, Desktop/WSL2 GUI, or Installer)",
          description: "Starts local web embed, streams Windows/WSL2 CLI run, opens desktop GUI, or runs installer.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.arsenal.stop", "/api/cyberlab/arsenal/stop", {
      query: LocationQuery,
      payload: CyberLab.ArsenalStopRunInput,
      success: Location.response(Schema.Struct({ stopped: Schema.Boolean })),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.stop",
          summary: "Terminate a running Arsenal CLI or installer process",
          description: "Sends SIGTERM/taskkill to a running external process.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.arsenal.browser", "/api/cyberlab/arsenal/browser", {
      query: LocationQuery,
      payload: CyberLab.ArsenalProxyBrowserInput,
      success: Location.response(CyberLab.ProxyBrowserLaunchResult),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.browser",
          summary: "Launch isolated Chrome/Edge/Brave routed through external proxy (Burp, OpenTRAP, mitmweb, Caido, ZAP)",
          description: "Spawns an isolated browser profile pointed at 127.0.0.1:<proxyPort>.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.arsenal.persist", "/api/cyberlab/arsenal/persist", {
      query: LocationQuery,
      payload: CyberLab.ArsenalPersistOutputInput,
      success: Location.response(CyberLab.ArsenalPersistOutputResult),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.arsenal.persist",
          summary: "Persist tool output into SHA-256 EvidenceStore with automatic secret redaction",
          description: "Records tool output in cryptographic chain-of-custody.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.files.list", "/api/cyberlab/files/list", {
      query: LocationQuery,
      payload: CyberLab.WorkspaceFilesListInput,
      success: Location.response(CyberLab.WorkspaceFilesListOutput),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.files.list",
          summary: "List files and folders inside the active project workspace (including .cyberlab/outputs & imports)",
          description: "Powers the Antigravity-style collapsible Files & Outputs sidebar.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.files.preview", "/api/cyberlab/files/preview", {
      query: LocationQuery,
      payload: CyberLab.WorkspaceFilePreviewInput,
      success: Location.response(CyberLab.WorkspaceFilePreviewOutput),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.files.preview",
          summary: "Preview a workspace or tool output file safely",
          description: "Returns UTF-8 text preview or binary hex summary for a selected file.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.partners.overview", "/api/cyberlab/partners", {
      query: LocationQuery,
      success: Location.response(CyberLab.CdiHubOverview),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.partners.overview",
          summary: "Get registered CDI partner agents, secret status, and bidirectional activity",
          description: "Inspect registered external CDI agents (e.g. Salem, Kairos, Naia) and inbound gateway logs.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.partners.manage", "/api/cyberlab/partners/manage", {
      query: LocationQuery,
      payload: CyberLab.CdiPartnerManageInput,
      success: Location.response(CyberLab.CdiHubOverview),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.partners.manage",
          summary: "Register, update, remove, or load 4-CDI preset in CyberLab OS",
          description: "Manage external CDI partner agents and their bidirectional permissions.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.partners.secret", "/api/cyberlab/partners/secret", {
      query: LocationQuery,
      payload: CyberLab.CdiSecretManageInput,
      success: Location.response(CyberLab.CdiSecretManageOutput),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.partners.secret",
          summary: "Generate, set, or reveal CYBERLAB_PARTNER_SECRET and callback URL",
          description: "Manage the shared HMAC-SHA256 secret used by external CDI agents.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.partners.dispatch", "/api/cyberlab/partners/dispatch", {
      query: LocationQuery,
      payload: CyberLab.CdiMultiDispatchInput,
      success: Location.response(Schema.Unknown),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.partners.dispatch",
          summary: "Dispatch an analysis task to 1 CDI or multiple CDIs in parallel",
          description: "Supports both single-specialist routing and parallel multi-CDI collaboration.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.partners.gateway.info", "/api/cyberlab/partner-gateway", {
      query: LocationQuery,
      success: Location.response(Schema.Unknown),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.partners.gateway.info",
          summary: "Bidirectional CDI Gateway discovery & healthcheck (GET)",
          description: "Returns protocol metadata, supported actions, secret configuration state, and registered partner IDs.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.partners.gateway", "/api/cyberlab/partner-gateway", {
      query: LocationQuery,
      payload: Schema.Unknown,
      success: Location.response(Schema.Unknown),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.partners.gateway",
          summary: "Bidirectional CDI -> CyberLab OS HMAC-SHA256 Gateway",
          description: "Allows external CDI agents to read project state, read evidence/files, create artifacts, and initiate governed actions.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.partners.gateway.action", "/api/cyberlab/partner-gateway/:action", {
      params: { action: Schema.String },
      query: LocationQuery,
      payload: Schema.Unknown,
      success: Location.response(Schema.Unknown),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.partners.gateway.action",
          summary: "Bidirectional CDI -> CyberLab OS HMAC-SHA256 Gateway (subpath action alias)",
          description: "Subpath alias supporting POST /api/cyberlab/partner-gateway/<action>.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.partners.gateway.alias.api.info", "/api/partner-gateway", {
      query: LocationQuery,
      success: Location.response(Schema.Unknown),
    }),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.partners.gateway.alias.api.post", "/api/partner-gateway", {
      query: LocationQuery,
      payload: Schema.Unknown,
      success: Location.response(Schema.Unknown),
      error: [InvalidRequestError],
    }),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.partners.gateway.alias.root.info", "/cyberlab/partner-gateway", {
      query: LocationQuery,
      success: Location.response(Schema.Unknown),
    }),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.partners.gateway.alias.root.post", "/cyberlab/partner-gateway", {
      query: LocationQuery,
      payload: Schema.Unknown,
      success: Location.response(Schema.Unknown),
      error: [InvalidRequestError],
    }),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.labs.list", "/api/cyberlab/labs", {
      query: LocationQuery,
      success: Location.response(Schema.Array(CyberLab.TrainingLabInfo)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.labs.list",
          summary: "List interactive CyberLab OS Training Laboratories and their live status",
          description: "Returns all built-in training laboratories, ports, URLs, and remediation challenges.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.labs.control", "/api/cyberlab/labs/control", {
      query: LocationQuery,
      payload: CyberLab.TrainingLabControlInput,
      success: Location.response(CyberLab.TrainingLabInfo),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.labs.control",
          summary: "Start, reset, or stop an interactive Training Laboratory",
          description: "Provisions workspace fixtures, launches the loopback server, and syncs project scope.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("cyberlab.projects.list", "/api/cyberlab/projects", {
      query: LocationQuery,
      success: Location.response(CyberLab.ProjectsAndLabsOverview),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.projects.list",
          summary: "List managed CyberLab OS projects, runtimeRoot, and training laboratories",
          description: "Includes projects created by curator or autonomous CDIs plus active training labs.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("cyberlab.projects.manage", "/api/cyberlab/projects/manage", {
      query: LocationQuery,
      payload: CyberLab.ProjectManageInput,
      success: Location.response(CyberLab.ProjectsAndLabsOverview),
      error: [InvalidRequestError],
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "cyberlab.projects.manage",
          summary: "Create or select a CyberLab OS project and register it in OpenCode V2",
          description: "Creates or switches active projects and syncs with OpenCode Project.Service.",
        }),
      ),
  )
  .annotateMerge(
    OpenApi.annotations({
      title: "cyberlab",
      description: "Unified CyberLab OS operations, scope enforcement, and SHA-256 evidence management routes.",
    }),
  )

export const CYBERLAB_PARTNER_GATEWAY_PATH = "/api/cyberlab/partner-gateway"

const PARTNER_GATEWAY_EXACT_PATHS = new Set([
  "/api/cyberlab/partner-gateway",
  "/api/partner-gateway",
  "/cyberlab/partner-gateway",
])

export function isCyberLabPartnerGatewayPath(pathname: string): boolean {
  return PARTNER_GATEWAY_EXACT_PATHS.has(pathname) || pathname.startsWith("/api/cyberlab/partner-gateway/")
}

export function isCyberLabPartnerGatewayPublicProbe(method: string, url: URL): boolean {
  return (method === "GET" || method === "HEAD") && PARTNER_GATEWAY_EXACT_PATHS.has(url.pathname)
}

export function hasCyberLabPartnerGatewaySignature(
  headers: Readonly<Record<string, string | undefined>>,
  url: URL,
): boolean {
  if (!isCyberLabPartnerGatewayPath(url.pathname)) return false
  return Boolean(headers["x-cyberlab-signature"] && headers["x-cyberlab-partner-id"])
}

