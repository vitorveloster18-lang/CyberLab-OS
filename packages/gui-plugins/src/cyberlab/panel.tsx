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

interface ExecutionDto {
  executionId: string
  capabilityId: string
  status: string
  evidenceIds: string[]
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

  const [bundle, { refetch }] = createResource(
    () => `${props.session.server.url}::${props.session.directory}`,
    async () => {
      const [status, capabilities, executions, evidence, findings] = await Promise.all([
        fetchCyberLabJson<WorkspaceStatusDto>(props.session, "/api/cyberlab/status"),
        fetchCyberLabJson<CapabilityDto[]>(props.session, "/api/cyberlab/capabilities"),
        fetchCyberLabJson<ExecutionDto[]>(props.session, "/api/cyberlab/executions"),
        fetchCyberLabJson<EvidenceDto[]>(props.session, "/api/cyberlab/evidence"),
        fetchCyberLabJson<FindingDto[]>(props.session, "/api/cyberlab/findings"),
      ])
      return { status, capabilities, executions, evidence, findings }
    },
  )

  const triggerWorkspaceAudit = async () => {
    setBusy(true)
    setNotice("")
    try {
      const rec = await fetchCyberLabJson<ExecutionDto>(props.session, "/api/cyberlab/executions", {
        method: "POST",
        body: JSON.stringify({
          capabilityId: "code-analysis.workspace-audit",
          input: { subpath: ".", maxFiles: 100 },
          mode: "manual",
        }),
      })
      setNotice(`Execution ${rec.executionId}: ${rec.status}`)
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
      <div class="flex items-center justify-between border-b border-v2-border-weak px-3 py-2">
        <span class="font-medium text-v2-text-strong">{ctx.t("panel.heading")}</span>
        <div class="flex items-center gap-2">
          <button
            type="button"
            disabled={busy()}
            onClick={() => void triggerWorkspaceAudit()}
            class="rounded border border-v2-border-weak px-2 py-1 hover:bg-v2-surface-hover"
          >
            {ctx.t("panel.runAudit")}
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
              <section class="space-y-1">
                <div class="font-medium text-v2-text-strong">{ctx.t("panel.scopeTitle")}</div>
                <div class="text-v2-text-weak">
                  {data.status.activeScope?.name ?? "None"} · External:{" "}
                  {String(data.status.activeScope?.allowExternalTargets ?? false)} · Skills: {data.status.skillCount}
                </div>
              </section>

              <section class="space-y-1">
                <div class="font-medium text-v2-text-strong">
                  {ctx.t("panel.capabilitiesTitle")} ({data.capabilities.length})
                </div>
                <For each={data.capabilities}>
                  {(cap) => (
                    <div class="rounded border border-v2-border-weak p-2">
                      <div class="font-mono text-v2-text-strong">{cap.id}</div>
                      <div class="text-v2-text-weak">
                        {cap.title} · risk={cap.risk}
                      </div>
                    </div>
                  )}
                </For>
              </section>

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
