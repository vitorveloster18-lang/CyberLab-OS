import { createResource, createSignal, For, Show } from "solid-js"
import { usePlugin, type MountedSession } from "@opencode/plugin/gui"
import type CyberLabPlugin from "./index"

interface WorkspaceStatusDto {
  projectId: string
  workspaceRoot: string
  environment: { platform: string; arch: string; isLinux: boolean; isWsl2: boolean }
  activeScope?: {
    name: string
    allowExternalTargets: boolean
    allowedTargets: Array<{ kind: string; value: string }>
  }
  capabilityCount: number
  skillCount: number
  executionCount: number
  pendingApprovalCount: number
  evidenceCount: number
  findingCount: number
}

interface CapabilityDto {
  id: string
  version: string
  title: string
  risk: string
}

interface ApprovalDto {
  approvalId: string
  executionId: string
  capabilityId: string
  targetSummary: string
  status: string
}

interface ExecutionDto {
  executionId: string
  capabilityId: string
  status: string
  evidenceIds: string[]
  policyReason?: string
}

interface EvidenceDto {
  evidenceId: string
  kind: string
  title: string
  sha256: string
  sizeBytes: number
  redactionStatus: string
}

interface FindingDto {
  findingId: string
  title: string
  severity: string
  confidence?: number
  status: string
  evidenceIds: string[]
}

interface ExternalToolsOverviewDto {
  pendingInboxCount: number
  inboxDirectory: string
  tools: Array<{
    toolId: string
    displayName: string
    available: boolean
    resolvedPath: string | null
    licenseSpdx: string
    integrationMode: string
    governedCapabilityId: string | null
    installHint: string
  }>
}

function buildAuthHeaders(password?: string): HeadersInit {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (password) {
    headers.Authorization = `Basic ${btoa(`opencode:${password}`)}`
  }
  return headers
}

async function fetchCyberLabJson<T>(session: MountedSession, endpointPath: string, init?: RequestInit): Promise<T> {
  const url = new URL(endpointPath, session.server.url)
  url.searchParams.set("directory", session.directory)
  const res = await fetch(url.toString(), {
    ...init,
    headers: {
      ...buildAuthHeaders(session.server.password),
      ...(init?.headers ?? {}),
    },
  })
  if (!res.ok) {
    throw new Error(`CyberLab HTTP ${res.status}`)
  }
  const body = (await res.json()) as { data: T }
  return body.data
}

export default function CyberLabPanel(props: { session: MountedSession }) {
  const ctx = usePlugin<typeof CyberLabPlugin>()
  const [notice, setNotice] = createSignal<string>("")
  const [busy, setBusy] = createSignal(false)

  // Unified Capability Launcher state (internal + governed external tools)
  const [selectedCapability, setSelectedCapability] = createSignal("code-analysis.workspace-audit")
  const [launcherJson, setLauncherJson] = createSignal('{"subpath": ".", "maxFiles": 100}')

  // External manual action ingestion state
  const [extToolId, setExtToolId] = createSignal("opentrap")
  const [extTarget, setExtTarget] = createSignal("http://127.0.0.1:8080")
  const [extRawOutput, setExtRawOutput] = createSignal("")

  const [bundle, { refetch }] = createResource(
    () => `${props.session.server.url}::${props.session.directory}`,
    async () => {
      const [status, capabilities, approvals, executions, evidence, findings, externalOverview] = await Promise.all([
        fetchCyberLabJson<WorkspaceStatusDto>(props.session, "/api/cyberlab/status"),
        fetchCyberLabJson<CapabilityDto[]>(props.session, "/api/cyberlab/capabilities"),
        fetchCyberLabJson<ApprovalDto[]>(props.session, "/api/cyberlab/approvals"),
        fetchCyberLabJson<ExecutionDto[]>(props.session, "/api/cyberlab/executions"),
        fetchCyberLabJson<EvidenceDto[]>(props.session, "/api/cyberlab/evidence"),
        fetchCyberLabJson<FindingDto[]>(props.session, "/api/cyberlab/findings"),
        fetchCyberLabJson<ExternalToolsOverviewDto>(props.session, "/api/cyberlab/external/tools"),
      ])
      return { status, capabilities, approvals, executions, evidence, findings, externalOverview }
    },
  )

  const launchCapability = async (capabilityId: string, rawInput: unknown) => {
    setBusy(true)
    setNotice("")
    try {
      const rec = await fetchCyberLabJson<ExecutionDto>(props.session, "/api/cyberlab/executions", {
        method: "POST",
        body: JSON.stringify({
          capabilityId,
          input: rawInput,
          mode: "manual",
        }),
      })
      setNotice(`Execution ${rec.executionId} [${capabilityId}] -> ${rec.status}`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const runLauncherForm = async () => {
    try {
      const parsed = JSON.parse(launcherJson()) as unknown
      await launchCapability(selectedCapability(), parsed)
    } catch (err) {
      setNotice(`Invalid JSON input: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  const toggleExternalScope = async (currentAllow: boolean) => {
    setBusy(true)
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/scope", {
        method: "PUT",
        body: JSON.stringify({ allowExternalTargets: !currentAllow }),
      })
      setNotice(`Scope allowExternalTargets set to ${String(!currentAllow)}`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const approvePendingTicket = async (approvalId: string) => {
    setBusy(true)
    try {
      const rec = await fetchCyberLabJson<ExecutionDto>(props.session, "/api/cyberlab/executions/approve", {
        method: "POST",
        body: JSON.stringify({
          approvalId,
          decidedBy: "gui-operator",
          reason: "Approved from CyberLab Unified Control Plane",
        }),
      })
      setNotice(`Approved ${approvalId} -> Execution ${rec.status}`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const cancelActiveExecution = async (executionId: string) => {
    setBusy(true)
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/executions/cancel", {
        method: "POST",
        body: JSON.stringify({
          executionId,
          reason: "Terminated by operator via Unified Control Plane kill-switch",
        }),
      })
      setNotice(`Sent kill/cancel signal to ${executionId}`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const syncInboxNow = async () => {
    setBusy(true)
    try {
      const res = await fetchCyberLabJson<{ ingested: Array<{ evidenceId: string }> }>(
        props.session,
        "/api/cyberlab/external/sync",
        { method: "POST" },
      )
      setNotice(`Synced .cyberlab/inbox: ${res.ingested.length} external artifact(s) imported into SHA-256 custody`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const submitManualExternalIngest = async () => {
    if (!extRawOutput().trim()) {
      setNotice("Paste or enter external tool output to ingest.")
      return
    }
    setBusy(true)
    try {
      const res = await fetchCyberLabJson<{ evidenceId: string; scopeAuditStatus: string }>(
        props.session,
        "/api/cyberlab/external/ingest",
        {
          method: "POST",
          body: JSON.stringify({
            toolId: extToolId(),
            target: extTarget(),
            rawOutput: extRawOutput(),
            origin: "manual_external",
          }),
        },
      )
      setExtRawOutput("")
      setNotice(`Ingested external action -> ${res.evidenceId} (scope=${res.scopeAuditStatus})`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const verifyCustody = async (evidenceId: string) => {
    try {
      const res = await fetchCyberLabJson<{ valid: boolean; expectedSha256: string }>(
        props.session,
        "/api/cyberlab/evidence/verify",
        {
          method: "POST",
          body: JSON.stringify({ evidenceId }),
        },
      )
      setNotice(
        res.valid
          ? `Verified ${evidenceId} (${res.expectedSha256.slice(0, 16)}...)`
          : `Integrity check FAILED for ${evidenceId}`,
      )
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    }
  }

  const reviewFinding = async (findingId: string, decision: "accept" | "reject") => {
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/findings/review", {
        method: "POST",
        body: JSON.stringify({
          findingId,
          reviewedBy: "gui-analyst",
          decision,
        }),
      })
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <div class="flex h-full min-h-0 flex-col bg-v2-background-bg-base text-xs" data-slot="session-cyberlab-panel">
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-v2-border-weak px-3 py-2">
        <span class="font-medium text-v2-text-strong">{ctx.t("panel.heading")}</span>
        <div class="flex items-center gap-1.5">
          <button
            type="button"
            disabled={busy()}
            onClick={() => void launchCapability("code-analysis.workspace-audit", { subpath: ".", maxFiles: 100 })}
            class="rounded border border-v2-border-weak px-2 py-1 hover:bg-v2-surface-hover"
          >
            {ctx.t("panel.runAudit")}
          </button>
          <button
            type="button"
            disabled={busy()}
            onClick={() => void syncInboxNow()}
            class="rounded border border-v2-border-weak px-2 py-1 hover:bg-v2-surface-hover"
          >
            {ctx.t("panel.syncInbox")}
          </button>
          <button
            type="button"
            onClick={() => void refetch()}
            class="rounded border border-v2-border-weak px-2 py-1 hover:bg-v2-surface-hover"
          >
            {ctx.t("panel.refresh")}
          </button>
        </div>
      </div>

      <Show when={notice()}>
        <div class="border-b border-v2-border-weak bg-v2-surface-base px-3 py-1.5 text-v2-text-base">{notice()}</div>
      </Show>

      <div class="min-h-0 flex-1 space-y-4 overflow-y-auto p-3" data-scrollable>
        <Show when={bundle()} keyed>
          {(data) => (
            <>
              {/* 1. Scope & Target Guard Control */}
              <section class="space-y-1.5 rounded border border-v2-border-weak p-2.5">
                <div class="flex items-center justify-between">
                  <span class="font-medium text-v2-text-strong">{ctx.t("panel.scopeTitle")}</span>
                  <button
                    type="button"
                    disabled={busy()}
                    onClick={() => void toggleExternalScope(data.status.activeScope?.allowExternalTargets ?? false)}
                    class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                  >
                    {ctx.t("panel.toggleExternal")}
                  </button>
                </div>
                <div class="text-v2-text-weak">
                  {data.status.activeScope?.name ?? "None"} · External Allowed:{" "}
                  {String(data.status.activeScope?.allowExternalTargets ?? false)} · Skills: {data.status.skillCount}
                </div>
              </section>

              {/* 2. Pending Human Approvals */}
              <Show when={data.approvals.length > 0}>
                <section class="space-y-1.5">
                  <div class="font-medium text-v2-text-strong">
                    {ctx.t("panel.approvalsTitle")} ({data.approvals.length})
                  </div>
                  <For each={data.approvals}>
                    {(ticket) => (
                      <div class="flex items-center justify-between rounded border border-v2-border-weak p-2">
                        <div class="min-w-0 truncate pr-2">
                          <div class="font-mono text-v2-text-strong">{ticket.capabilityId}</div>
                          <div class="truncate text-v2-text-weak">{ticket.targetSummary}</div>
                        </div>
                        <button
                          type="button"
                          disabled={busy()}
                          onClick={() => void approvePendingTicket(ticket.approvalId)}
                          class="shrink-0 rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                        >
                          {ctx.t("panel.approve")}
                        </button>
                      </div>
                    )}
                  </For>
                </section>
              </Show>

              {/* 3. Unified Capability Launcher (Internal + Governed External Plugins) */}
              <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                <div class="font-medium text-v2-text-strong">{ctx.t("panel.launcherTitle")}</div>
                <select
                  value={selectedCapability()}
                  onChange={(e) => setSelectedCapability(e.currentTarget.value)}
                  class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                >
                  <For each={data.capabilities}>
                    {(cap) => (
                      <option value={cap.id}>
                        {cap.id} (risk={cap.risk})
                      </option>
                    )}
                  </For>
                </select>
                <textarea
                  rows={2}
                  value={launcherJson()}
                  onInput={(e) => setLauncherJson(e.currentTarget.value)}
                  class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base p-1.5 font-mono"
                />
                <button
                  type="button"
                  disabled={busy()}
                  onClick={() => void runLauncherForm()}
                  class="rounded border border-v2-border-weak px-2.5 py-1 hover:bg-v2-surface-hover"
                >
                  {ctx.t("panel.launch")}
                </button>
              </section>

              {/* 4. External Tools Radar & Manual External Action Ingestion */}
              <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                <div class="flex items-center justify-between">
                  <span class="font-medium text-v2-text-strong">{ctx.t("panel.externalToolsTitle")}</span>
                  <span class="font-mono text-v2-text-weak">
                    Inbox pending: {data.externalOverview.pendingInboxCount}
                  </span>
                </div>
                <div class="space-y-1">
                  <For each={data.externalOverview.tools}>
                    {(tool) => (
                      <div class="flex items-center justify-between rounded border border-v2-border-weak px-2 py-1">
                        <div class="min-w-0 truncate pr-2">
                          <span class="font-mono text-v2-text-strong">{tool.toolId}</span>{" "}
                          <span class="text-v2-text-weak">({tool.licenseSpdx})</span>
                        </div>
                        <span class="shrink-0 font-mono text-v2-text-weak">
                          {tool.available ? "READY" : "NOT INSTALLED"}
                        </span>
                      </div>
                    )}
                  </For>
                </div>

                <div class="space-y-1.5 border-t border-v2-border-weak pt-2">
                  <div class="flex gap-1.5">
                    <input
                      type="text"
                      value={extToolId()}
                      onInput={(e) => setExtToolId(e.currentTarget.value)}
                      placeholder="tool (opentrap, burp, nmap...)"
                      class="w-1/2 rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                    />
                    <input
                      type="text"
                      value={extTarget()}
                      onInput={(e) => setExtTarget(e.currentTarget.value)}
                      placeholder="target (http://127.0.0.1:8080)"
                      class="w-1/2 rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                    />
                  </div>
                  <textarea
                    rows={2}
                    value={extRawOutput()}
                    onInput={(e) => setExtRawOutput(e.currentTarget.value)}
                    placeholder="Paste manual output from OpenTRAP, Burp, Wireshark, Nmap, or Ghidra..."
                    class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base p-1.5 font-mono"
                  />
                  <button
                    type="button"
                    disabled={busy()}
                    onClick={() => void submitManualExternalIngest()}
                    class="rounded border border-v2-border-weak px-2.5 py-1 hover:bg-v2-surface-hover"
                  >
                    {ctx.t("panel.ingestAction")}
                  </button>
                </div>
              </section>

              {/* 5. Active & Recent Executions (with real-time Kill/Cancel button) */}
              <Show when={data.executions.length > 0}>
                <section class="space-y-1">
                  <div class="font-medium text-v2-text-strong">
                    {ctx.t("panel.executionsTitle")} ({data.executions.length})
                  </div>
                  <For each={data.executions}>
                    {(ex) => (
                      <div class="flex items-center justify-between rounded border border-v2-border-weak p-2">
                        <div class="min-w-0 truncate pr-2">
                          <div class="truncate font-mono text-v2-text-strong">{ex.capabilityId}</div>
                          <div class="truncate font-mono text-v2-text-weak">
                            {ex.executionId.slice(0, 13)}… · {ex.status}
                          </div>
                        </div>
                        <Show when={ex.status === "running" || ex.status === "queued" || ex.status === "awaiting_approval"}>
                          <button
                            type="button"
                            disabled={busy()}
                            onClick={() => void cancelActiveExecution(ex.executionId)}
                            class="shrink-0 rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                          >
                            {ctx.t("panel.cancel")}
                          </button>
                        </Show>
                      </div>
                    )}
                  </For>
                </section>
              </Show>

              {/* 6. SHA-256 Chain of Custody */}
              <section class="space-y-1">
                <div class="font-medium text-v2-text-strong">
                  {ctx.t("panel.evidenceTitle")} ({data.evidence.length})
                </div>
                <For each={data.evidence}>
                  {(ev) => (
                    <div class="flex items-center justify-between rounded border border-v2-border-weak p-2">
                      <div class="min-w-0 truncate pr-2">
                        <div class="truncate font-medium">{ev.title}</div>
                        <div class="truncate font-mono text-v2-text-weak">
                          {ev.kind} · sha256:{ev.sha256.slice(0, 16)}…
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => void verifyCustody(ev.evidenceId)}
                        class="shrink-0 rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                      >
                        {ctx.t("panel.verify")}
                      </button>
                    </div>
                  )}
                </For>
              </section>

              {/* 7. Security Findings Review */}
              <section class="space-y-1">
                <div class="font-medium text-v2-text-strong">
                  {ctx.t("panel.findingsTitle")} ({data.findings.length})
                </div>
                <For each={data.findings}>
                  {(f) => (
                    <div class="space-y-1 rounded border border-v2-border-weak p-2">
                      <div class="flex items-center justify-between">
                        <span class="font-medium">{f.title}</span>
                        <span class="font-mono uppercase text-v2-text-weak">
                          {f.severity} · {f.status}
                        </span>
                      </div>
                      <div class="flex gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => void reviewFinding(f.findingId, "accept")}
                          class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                        >
                          {ctx.t("panel.accept")}
                        </button>
                        <button
                          type="button"
                          onClick={() => void reviewFinding(f.findingId, "reject")}
                          class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                        >
                          {ctx.t("panel.reject")}
                        </button>
                      </div>
                    </div>
                  )}
                </For>
              </section>
            </>
          )}
        </Show>
      </div>
    </div>
  )
}
