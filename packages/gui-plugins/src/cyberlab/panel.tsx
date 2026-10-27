import { createResource, createSignal, For, Show } from "solid-js"
import { usePlugin, type MountedSession } from "@opencode/plugin/gui"
import type CyberLabPlugin from "./index"
import type {
  ApprovalDto,
  CapabilityDto,
  EvidenceDto,
  ExecutionDto,
  ExternalToolsOverviewDto,
  FindingDto,
  HeaderRow,
  ProxyHistoryEntryDto,
  ProxyOverviewDto,
  ReadEvidenceDto,
  ScopeRuleDto,
  StudioTabId,
  WorkspaceStatusDto,
} from "./types"

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
    const errText = await res.text().catch(() => "")
    throw new Error(`CyberLab HTTP ${res.status}${errText ? `: ${errText.slice(0, 140)}` : ""}`)
  }
  const body = (await res.json()) as { data: T }
  return body.data
}

function tryParseJsonRecord(raw: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(raw) as unknown
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null
  } catch {
    return null
  }
}

export default function CyberLabPanel(props: { session: MountedSession }) {
  const ctx = usePlugin<typeof CyberLabPlugin>()
  const [activeTab, setActiveTab] = createSignal<StudioTabId>("repeater")
  const [notice, setNotice] = createSignal<string>("")
  const [busy, setBusy] = createSignal(false)
  const [lastStructuredResult, setLastStructuredResult] = createSignal<Record<string, unknown> | null>(null)
  const [lastRawResultText, setLastRawResultText] = createSignal<string>("")

  // === Tab 1: Proxy & HTTP Repeater / Comparer Manual Controls ===
  const [proxyPort, setProxyPort] = createSignal(8899)
  const [repMethod, setRepMethod] = createSignal("GET")
  const [repUrl, setRepUrl] = createSignal("http://127.0.0.1:8080/")
  const [repHeaders, setRepHeaders] = createSignal<HeaderRow[]>([
    { id: "h1", enabled: true, name: "Accept", value: "application/json, text/html" },
    { id: "h2", enabled: false, name: "Authorization", value: "Bearer replace_me" },
  ])
  const [repBody, setRepBody] = createSignal("")
  const [repTimeoutMs, setRepTimeoutMs] = createSignal(6000)
  const [repCompareEnabled, setRepCompareEnabled] = createSignal(false)
  const [repBaselineUrl, setRepBaselineUrl] = createSignal("")

  // === Tab 2: Decoder, JWT & Token Sequencer Controls ===
  const [decInput, setDecInput] = createSignal("")
  const [decSteps, setDecSteps] = createSignal<string[]>([])
  const [decInspectJwt, setDecInspectJwt] = createSignal(true)
  const [seqTokensText, setSeqTokensText] = createSignal("")

  // === Tab 3: Web Scanner & Fuzzer Controls (Native | External Nuclei | External ffuf) ===
  const [webEngine, setWebEngine] = createSignal<"surface" | "headers" | "nuclei" | "ffuf">("surface")
  const [webBaseUrl, setWebBaseUrl] = createSignal("http://127.0.0.1:8080")
  const [webConcurrency, setWebConcurrency] = createSignal(3)
  const [webRateLimit, setWebRateLimit] = createSignal(10)
  const [webCustomPaths, setWebCustomPaths] = createSignal("/api/v1/health, /graphql, /metrics")
  const [webNucleiTags, setWebNucleiTags] = createSignal("misconfig,exposure")
  const [webWordlistPath, setWebWordlistPath] = createSignal("wordlist.txt")

  // === Tab 4: Network & TLS Controls (Native TCP | Native TLS | External Nmap) ===
  const [netEngine, setNetEngine] = createSignal<"tcp" | "tls" | "nmap">("tls")
  const [netHost, setNetHost] = createSignal("127.0.0.1")
  const [netPort, setNetPort] = createSignal(443)
  const [netPortsRange, setNetPortsRange] = createSignal("80,443,8080,8443")
  const [netSni, setNetSni] = createSignal("localhost")
  const [netServiceVersion, setNetServiceVersion] = createSignal(true)
  const [netBannerWaitMs, setNetBannerWaitMs] = createSignal(400)

  // === Tab 5: Packet Capture (.pcap) Controls (Native | External tshark) ===
  const [pcapEngine, setPcapEngine] = createSignal<"native" | "tshark">("native")
  const [pcapPath, setPcapPath] = createSignal("capture.pcap")
  const [pcapMaxPackets, setPcapMaxPackets] = createSignal(5000)

  // === Tab 6: Reverse Engineering & Mobile Forensics Controls ===
  const [revMode, setRevMode] = createSignal<"binary" | "mobile">("binary")
  const [revPath, setRevPath] = createSignal("sample.elf")
  const [revMinStrLen, setRevMinStrLen] = createSignal(5)
  const [revMaxStrings, setRevMaxStrings] = createSignal(200)
  const [revIocDomains, setRevIocDomains] = createSignal("")

  // === Tab 7: Scope Builder, Manual Ingest & Report Preview ===
  const [newRuleKind, setNewRuleKind] = createSignal<ScopeRuleDto["kind"]>("url_origin")
  const [newRuleValue, setNewRuleValue] = createSignal("http://127.0.0.1:8080")
  const [extToolId, setExtToolId] = createSignal("burp-or-opentrap")
  const [extTarget, setExtTarget] = createSignal("http://127.0.0.1:8080")
  const [extRawOutput, setExtRawOutput] = createSignal("")
  const [inspectedEvidence, setInspectedEvidence] = createSignal<ReadEvidenceDto | null>(null)
  const [markdownReport, setMarkdownReport] = createSignal<string>("")

  const [bundle, { refetch }] = createResource(
    () => `${props.session.server.url}::${props.session.directory}`,
    async () => {
      const [status, capabilities, approvals, executions, evidence, findings, externalOverview, proxyOverview] =
        await Promise.all([
          fetchCyberLabJson<WorkspaceStatusDto>(props.session, "/api/cyberlab/status"),
          fetchCyberLabJson<CapabilityDto[]>(props.session, "/api/cyberlab/capabilities"),
          fetchCyberLabJson<ApprovalDto[]>(props.session, "/api/cyberlab/approvals"),
          fetchCyberLabJson<ExecutionDto[]>(props.session, "/api/cyberlab/executions"),
          fetchCyberLabJson<EvidenceDto[]>(props.session, "/api/cyberlab/evidence"),
          fetchCyberLabJson<FindingDto[]>(props.session, "/api/cyberlab/findings"),
          fetchCyberLabJson<ExternalToolsOverviewDto>(props.session, "/api/cyberlab/external/tools"),
          fetchCyberLabJson<ProxyOverviewDto>(props.session, "/api/cyberlab/proxy"),
        ])
      return { status, capabilities, approvals, executions, evidence, findings, externalOverview, proxyOverview }
    },
  )

  const executeAndLoadVisualResult = async (capabilityId: string, inputPayload: Record<string, unknown>) => {
    setBusy(true)
    setNotice("")
    setLastStructuredResult(null)
    setLastRawResultText("")
    try {
      const rec = await fetchCyberLabJson<ExecutionDto>(props.session, "/api/cyberlab/executions", {
        method: "POST",
        body: JSON.stringify({
          capabilityId,
          input: inputPayload,
          mode: "manual",
        }),
      })
      setNotice(`[${rec.status}] ${capabilityId} (${rec.executionId.slice(0, 12)})`)

      if (rec.evidenceIds.length > 0) {
        const readItems = await Promise.all(
          rec.evidenceIds.map((evidenceId) =>
            fetchCyberLabJson<ReadEvidenceDto>(props.session, "/api/cyberlab/evidence/read", {
              method: "POST",
              body: JSON.stringify({ evidenceId }),
            }),
          ),
        )
        const jsonEv = readItems.find((e) => e.kind === "json") ?? readItems[readItems.length - 1]
        const textEv = readItems.find((e) => e.kind !== "json") ?? jsonEv
        if (jsonEv) {
          setLastStructuredResult(tryParseJsonRecord(jsonEv.text))
        }
        if (textEv) {
          setLastRawResultText(textEv.text)
        }
      } else if (rec.error?.message || rec.policyReason) {
        setLastRawResultText(rec.error?.message ?? rec.policyReason ?? "")
      }
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  // === Proxy & Repeater Handlers ===
  const addRepeaterHeader = (name = "", value = "") => {
    setRepHeaders((prev) => [...prev, { id: `h-${Date.now()}-${prev.length}`, enabled: true, name, value }])
  }

  const updateHeaderRow = (id: string, patch: Partial<HeaderRow>) => {
    setRepHeaders((prev) => prev.map((row) => (row.id === id ? { ...row, ...patch } : row)))
  }

  const removeHeaderRow = (id: string) => {
    setRepHeaders((prev) => prev.filter((row) => row.id !== id))
  }

  const sendProxyEntryToRepeater = (entry: ProxyHistoryEntryDto, asBaseline = false) => {
    if (asBaseline) {
      setRepCompareEnabled(true)
      setRepBaselineUrl(entry.url)
      setNotice(`Loaded ${entry.url} into Comparer Baseline`)
      return
    }
    setRepMethod(entry.method)
    setRepUrl(entry.url)
    setRepBody(entry.requestBody)
    setRepHeaders(
      Object.entries(entry.requestHeaders).map(([name, value], idx) => ({
        id: `pxh-${idx}`,
        enabled: !value.includes("[REDACTED"),
        name,
        value,
      })),
    )
    setNotice(`Loaded ${entry.method} ${entry.url} into HTTP Repeater`)
  }

  const runHttpRepeater = async () => {
    const headersObj: Record<string, string> = {}
    for (const h of repHeaders()) {
      if (h.enabled && h.name.trim()) {
        headersObj[h.name.trim()] = h.value
      }
    }
    await executeAndLoadVisualResult("web-assessment.http-repeater", {
      url: repUrl().trim(),
      method: repMethod(),
      headers: headersObj,
      ...(repBody().length > 0 ? { body: repBody() } : {}),
      timeoutMs: repTimeoutMs(),
      ...(repCompareEnabled() && repBaselineUrl().trim() ? { baselineUrl: repBaselineUrl().trim() } : {}),
    })
  }

  const controlProxy = async (action: "start" | "stop" | "clear" | "set_scope_only", scopeOnly?: boolean) => {
    setBusy(true)
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/proxy/control", {
        method: "POST",
        body: JSON.stringify({
          action,
          port: proxyPort(),
          ...(scopeOnly !== undefined ? { scopeOnly } : {}),
        }),
      })
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const persistProxyRow = async (entryId: string) => {
    setBusy(true)
    try {
      const saved = await fetchCyberLabJson<{ evidenceId: string }>(props.session, "/api/cyberlab/proxy/persist", {
        method: "POST",
        body: JSON.stringify({ entryId }),
      })
      setNotice(`Saved proxy capture to SHA-256 Evidence ${saved.evidenceId}`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  // === Decoder & Sequencer Handler ===
  const runDecoderSequencer = async () => {
    const samples = seqTokensText()
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
    await executeAndLoadVisualResult("web-assessment.decoder-sequencer", {
      ...(decInput().trim() ? { value: decInput() } : {}),
      ...(decSteps().length > 0 ? { transforms: decSteps() } : {}),
      inspectJwt: decInspectJwt(),
      ...(samples.length > 0 ? { tokenSamples: samples } : {}),
    })
  }

  // === Web Scanner & Fuzzer Handler ===
  const runWebScanner = async () => {
    const engine = webEngine()
    if (engine === "headers") {
      await executeAndLoadVisualResult("web-assessment.http-security-headers", {
        url: webBaseUrl().trim(),
        method: "GET",
      })
      return
    }
    if (engine === "surface") {
      const customPaths = webCustomPaths()
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
      await executeAndLoadVisualResult("web-assessment.surface-discovery", {
        baseUrl: webBaseUrl().trim(),
        concurrency: webConcurrency(),
        ...(customPaths.length > 0 ? { customPaths } : {}),
      })
      return
    }
    if (engine === "nuclei") {
      await executeAndLoadVisualResult("external.nuclei-template-scan", {
        url: webBaseUrl().trim(),
        rateLimit: webRateLimit(),
        ...(webNucleiTags().trim() ? { tags: webNucleiTags().trim() } : {}),
      })
      return
    }
    await executeAndLoadVisualResult("external.ffuf-endpoint-probe", {
      baseUrl: webBaseUrl().trim(),
      wordlistPath: webWordlistPath().trim(),
      rateLimit: webRateLimit(),
    })
  }

  // === Network & TLS Handler ===
  const runNetworkStudio = async () => {
    const engine = netEngine()
    if (engine === "tcp") {
      await executeAndLoadVisualResult("network-assessment.tcp-surface-probe", {
        host: netHost().trim(),
        port: netPort(),
        bannerWaitMs: netBannerWaitMs(),
      })
      return
    }
    if (engine === "tls") {
      await executeAndLoadVisualResult("network-assessment.tls-inspector", {
        host: netHost().trim(),
        port: netPort(),
        ...(netSni().trim() ? { servername: netSni().trim() } : {}),
      })
      return
    }
    await executeAndLoadVisualResult("external.nmap-service-probe", {
      host: netHost().trim(),
      ports: netPortsRange().trim(),
      serviceVersion: netServiceVersion(),
    })
  }

  // === Packet Dissector Handler ===
  const runPacketStudio = async () => {
    if (pcapEngine() === "native") {
      await executeAndLoadVisualResult("network-assessment.pcap-analyzer", {
        pcapPath: pcapPath().trim(),
        maxPackets: pcapMaxPackets(),
      })
      return
    }
    await executeAndLoadVisualResult("external.tshark-pcap-summary", {
      pcapPath: pcapPath().trim(),
      maxPackets: Math.min(pcapMaxPackets(), 5000),
    })
  }

  // === Reverse & Mobile Handler ===
  const runForensicsStudio = async () => {
    if (revMode() === "binary") {
      await executeAndLoadVisualResult("reverse-engineering.binary-triage", {
        binaryPath: revPath().trim(),
        minStringLength: revMinStrLen(),
        maxStrings: revMaxStrings(),
      })
      return
    }
    const domains = revIocDomains()
      .split(/[\r\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    await executeAndLoadVisualResult("mobile-forensics.artifact-triage", {
      artifactPath: revPath().trim(),
      ...(domains.length > 0 ? { iocDomains: domains } : {}),
    })
  }

  // === Cockpit Scope, Approvals, Kill-Switch & Custody ===
  const addScopeRule = async (existing: ScopeRuleDto[]) => {
    if (!newRuleValue().trim()) return
    setBusy(true)
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/scope", {
        method: "PUT",
        body: JSON.stringify({
          allowedTargets: [...existing, { kind: newRuleKind(), value: newRuleValue().trim() }],
        }),
      })
      setNotice(`Added scope rule ${newRuleKind()}:${newRuleValue().trim()}`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const removeScopeRule = async (existing: ScopeRuleDto[], idx: number) => {
    setBusy(true)
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/scope", {
        method: "PUT",
        body: JSON.stringify({
          allowedTargets: existing.filter((_, i) => i !== idx),
        }),
      })
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const toggleExternalScope = async (currentAllow: boolean) => {
    setBusy(true)
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/scope", {
        method: "PUT",
        body: JSON.stringify({ allowExternalTargets: !currentAllow }),
      })
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const approveTicket = async (approvalId: string) => {
    setBusy(true)
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/executions/approve", {
        method: "POST",
        body: JSON.stringify({ approvalId, decidedBy: "studio-operator" }),
      })
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const cancelExecution = async (executionId: string) => {
    setBusy(true)
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/executions/cancel", {
        method: "POST",
        body: JSON.stringify({ executionId, reason: "Killed from CyberLab Studio" }),
      })
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
      setNotice(`Synced .cyberlab/inbox: ${res.ingested.length} artifact(s) imported`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const submitManualIngest = async () => {
    if (!extRawOutput().trim()) return
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
      setNotice(`Ingested -> ${res.evidenceId} (scope=${res.scopeAuditStatus})`)
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const inspectEvidenceRecord = async (evidenceId: string) => {
    try {
      const detail = await fetchCyberLabJson<ReadEvidenceDto>(props.session, "/api/cyberlab/evidence/read", {
        method: "POST",
        body: JSON.stringify({ evidenceId }),
      })
      setInspectedEvidence(detail)
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    }
  }

  const verifyCustody = async (evidenceId: string) => {
    try {
      const res = await fetchCyberLabJson<{ valid: boolean; expectedSha256: string }>(
        props.session,
        "/api/cyberlab/evidence/verify",
        { method: "POST", body: JSON.stringify({ evidenceId }) },
      )
      setNotice(res.valid ? `SHA-256 OK: ${res.expectedSha256.slice(0, 20)}...` : `TAMPER DETECTED on ${evidenceId}!`)
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    }
  }

  const reviewFinding = async (findingId: string, decision: "accept" | "reject") => {
    try {
      await fetchCyberLabJson(props.session, "/api/cyberlab/findings/review", {
        method: "POST",
        body: JSON.stringify({ findingId, reviewedBy: "studio-analyst", decision }),
      })
      await refetch()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    }
  }

  const loadMarkdownReport = async () => {
    try {
      const res = await fetchCyberLabJson<{ markdown: string }>(props.session, "/api/cyberlab/report")
      setMarkdownReport(res.markdown)
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err))
    }
  }

  const navTabs: Array<{ id: StudioTabId; labelKey: Parameters<typeof ctx.t>[0] }> = [
    { id: "repeater", labelKey: "nav.repeater" },
    { id: "decoder", labelKey: "nav.decoder" },
    { id: "webscan", labelKey: "nav.webscan" },
    { id: "network", labelKey: "nav.network" },
    { id: "packets", labelKey: "nav.packets" },
    { id: "forensics", labelKey: "nav.forensics" },
    { id: "cockpit", labelKey: "nav.cockpit" },
  ]

  return (
    <div class="flex h-full min-h-0 flex-col bg-v2-background-bg-base text-xs" data-slot="session-cyberlab-panel">
      {/* Header Bar */}
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-v2-border-weak px-3 py-2">
        <span class="font-medium text-v2-text-strong">{ctx.t("panel.heading")}</span>
        <div class="flex items-center gap-1.5">
          <button
            type="button"
            disabled={busy()}
            onClick={() => void syncInboxNow()}
            class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
          >
            {ctx.t("panel.syncInbox")}
          </button>
          <button
            type="button"
            onClick={() => void refetch()}
            class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
          >
            {ctx.t("panel.refresh")}
          </button>
        </div>
      </div>

      {/* Multi-Tool Visual Navigation Bar (No need to leave CyberLab OS for Burp/Wireshark/Zenmap/MobSF) */}
      <div class="flex flex-wrap gap-1 border-b border-v2-border-weak bg-v2-surface-base px-2 py-1.5">
        <For each={navTabs}>
          {(tab) => (
            <button
              type="button"
              onClick={() => {
                setActiveTab(tab.id)
                setLastStructuredResult(null)
                setLastRawResultText("")
              }}
              class={`rounded px-2 py-1 font-medium ${
                activeTab() === tab.id
                  ? "border border-v2-border-base bg-v2-background-bg-base text-v2-text-strong"
                  : "text-v2-text-weak hover:bg-v2-surface-hover"
              }`}
            >
              {ctx.t(tab.labelKey)}
            </button>
          )}
        </For>
      </div>

      <Show when={notice()}>
        <div class="border-b border-v2-border-weak bg-v2-surface-base px-3 py-1 font-mono text-v2-text-base">
          {notice()}
        </div>
      </Show>

      <div class="min-h-0 flex-1 space-y-3 overflow-y-auto p-3" data-scrollable>
        <Show when={bundle()} keyed>
          {(data) => (
            <>
              {/* ===================================================================== */}
              {/* TAB 1: PROXY HISTORY + HTTP REPEATER & COMPARER (BURP / OPENTRAP UI) */}
              {/* ===================================================================== */}
              <Show when={activeTab() === "repeater"}>
                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <span class="font-medium text-v2-text-strong">
                      Local HTTP Capture Proxy (
                      {data.proxyOverview.status.running
                        ? `RUNNING 127.0.0.1:${data.proxyOverview.status.listenPort}`
                        : "STOPPED"}
                      )
                    </span>
                    <div class="flex items-center gap-1.5">
                      <input
                        type="number"
                        value={proxyPort()}
                        onInput={(e) => setProxyPort(Number(e.currentTarget.value) || 8899)}
                        class="w-16 rounded border border-v2-border-weak bg-v2-background-bg-base px-1.5 py-0.5 font-mono"
                      />
                      <Show
                        when={data.proxyOverview.status.running}
                        fallback={
                          <button
                            type="button"
                            disabled={busy()}
                            onClick={() => void controlProxy("start")}
                            class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                          >
                            Start Proxy
                          </button>
                        }
                      >
                        <button
                          type="button"
                          disabled={busy()}
                          onClick={() => void controlProxy("stop")}
                          class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                        >
                          Stop Proxy
                        </button>
                      </Show>
                      <label class="flex items-center gap-1 text-v2-text-weak">
                        <input
                          type="checkbox"
                          checked={data.proxyOverview.status.scopeOnly}
                          onChange={(e) => void controlProxy("set_scope_only", e.currentTarget.checked)}
                        />
                        Scope-Only
                      </label>
                      <button
                        type="button"
                        onClick={() => void controlProxy("clear")}
                        class="rounded border border-v2-border-weak px-1.5 py-0.5 text-v2-text-weak hover:bg-v2-surface-hover"
                      >
                        Clear
                      </button>
                    </div>
                  </div>

                  <Show when={data.proxyOverview.history.length > 0}>
                    <div class="max-h-36 space-y-1 overflow-y-auto border-t border-v2-border-weak pt-2">
                      <For each={data.proxyOverview.history}>
                        {(entry) => (
                          <div class="flex items-center justify-between gap-1 rounded border border-v2-border-weak px-2 py-1">
                            <div class="min-w-0 truncate font-mono">
                              <span class="font-bold">{entry.method}</span> {entry.host}
                              {entry.path} · HTTP {entry.statusCode} ({entry.elapsedMs}ms)
                            </div>
                            <div class="flex shrink-0 gap-1">
                              <button
                                type="button"
                                onClick={() => sendProxyEntryToRepeater(entry, false)}
                                class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                              >
                                → Repeater
                              </button>
                              <button
                                type="button"
                                onClick={() => sendProxyEntryToRepeater(entry, true)}
                                class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                              >
                                → Baseline
                              </button>
                              <button
                                type="button"
                                onClick={() => void persistProxyRow(entry.entryId)}
                                class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                              >
                                Save
                              </button>
                            </div>
                          </div>
                        )}
                      </For>
                    </div>
                  </Show>
                </section>

                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">HTTP Repeater & Response Comparer</div>
                  <div class="flex gap-1.5">
                    <select
                      value={repMethod()}
                      onChange={(e) => setRepMethod(e.currentTarget.value)}
                      class="rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono font-bold"
                    >
                      <For each={["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]}>
                        {(m) => <option value={m}>{m}</option>}
                      </For>
                    </select>
                    <input
                      type="text"
                      value={repUrl()}
                      onInput={(e) => setRepUrl(e.currentTarget.value)}
                      placeholder="http://127.0.0.1:8080/api/endpoint"
                      class="min-w-0 flex-1 rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                    />
                    <button
                      type="button"
                      disabled={busy()}
                      onClick={() => void runHttpRepeater()}
                      class="rounded border border-v2-border-base px-3 py-1 font-medium text-v2-text-strong hover:bg-v2-surface-hover"
                    >
                      Send
                    </button>
                  </div>

                  {/* Visual Headers Builder */}
                  <div class="space-y-1">
                    <div class="flex items-center justify-between">
                      <span class="text-v2-text-weak">Request Headers</span>
                      <div class="flex gap-1">
                        <button
                          type="button"
                          onClick={() => addRepeaterHeader("Content-Type", "application/json")}
                          class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                        >
                          + JSON
                        </button>
                        <button
                          type="button"
                          onClick={() => addRepeaterHeader("X-Forwarded-For", "127.0.0.1")}
                          class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                        >
                          + XFF
                        </button>
                        <button
                          type="button"
                          onClick={() => addRepeaterHeader()}
                          class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                        >
                          + Header
                        </button>
                      </div>
                    </div>
                    <For each={repHeaders()}>
                      {(row) => (
                        <div class="flex items-center gap-1">
                          <input
                            type="checkbox"
                            checked={row.enabled}
                            onChange={(e) => updateHeaderRow(row.id, { enabled: e.currentTarget.checked })}
                          />
                          <input
                            type="text"
                            value={row.name}
                            onInput={(e) => updateHeaderRow(row.id, { name: e.currentTarget.value })}
                            placeholder="Header-Name"
                            class="w-1/3 rounded border border-v2-border-weak bg-v2-background-bg-base px-1.5 py-0.5 font-mono"
                          />
                          <input
                            type="text"
                            value={row.value}
                            onInput={(e) => updateHeaderRow(row.id, { value: e.currentTarget.value })}
                            placeholder="Value"
                            class="min-w-0 flex-1 rounded border border-v2-border-weak bg-v2-background-bg-base px-1.5 py-0.5 font-mono"
                          />
                          <button
                            type="button"
                            onClick={() => removeHeaderRow(row.id)}
                            class="px-1 text-v2-text-weak hover:text-v2-text-strong"
                          >
                            ×
                          </button>
                        </div>
                      )}
                    </For>
                  </div>

                  <Show when={repMethod() !== "GET" && repMethod() !== "HEAD"}>
                    <textarea
                      rows={3}
                      value={repBody()}
                      onInput={(e) => setRepBody(e.currentTarget.value)}
                      placeholder="Request Body (JSON, form-urlencoded, XML...)"
                      class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base p-1.5 font-mono"
                    />
                  </Show>

                  <div class="flex flex-wrap items-center justify-between gap-2 pt-1">
                    <label class="flex items-center gap-1.5">
                      <input
                        type="checkbox"
                        checked={repCompareEnabled()}
                        onChange={(e) => setRepCompareEnabled(e.currentTarget.checked)}
                      />
                      <span>Compare vs Baseline URL</span>
                    </label>
                    <div class="flex items-center gap-1 text-v2-text-weak">
                      <span>Timeout (ms):</span>
                      <input
                        type="number"
                        value={repTimeoutMs()}
                        onInput={(e) => setRepTimeoutMs(Number(e.currentTarget.value) || 6000)}
                        class="w-20 rounded border border-v2-border-weak bg-v2-background-bg-base px-1.5 py-0.5 font-mono"
                      />
                    </div>
                  </div>

                  <Show when={repCompareEnabled()}>
                    <input
                      type="text"
                      value={repBaselineUrl()}
                      onInput={(e) => setRepBaselineUrl(e.currentTarget.value)}
                      placeholder="Baseline URL (e.g. http://127.0.0.1:8080/api/guest)"
                      class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                    />
                  </Show>
                </section>
              </Show>

              {/* ===================================================================== */}
              {/* TAB 2: DECODER, JWT AUDITOR & TOKEN SEQUENCER (BURP DECODER + SEQ)    */}
              {/* ===================================================================== */}
              <Show when={activeTab() === "decoder"}>
                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">Chained Payload Decoder & JWT Security Auditor</div>
                  <textarea
                    rows={3}
                    value={decInput()}
                    onInput={(e) => setDecInput(e.currentTarget.value)}
                    placeholder="Paste URL/Base64/Hex payload or JWT token (eyJ...)..."
                    class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base p-1.5 font-mono"
                  />
                  <div class="flex flex-wrap gap-1">
                    <For
                      each={[
                        "url_decode",
                        "url_encode",
                        "base64_decode",
                        "base64_encode",
                        "base64url_decode",
                        "hex_decode",
                        "hex_encode",
                        "html_decode",
                        "sha256",
                      ]}
                    >
                      {(step) => (
                        <button
                          type="button"
                          onClick={() => setDecSteps((prev) => [...prev, step])}
                          class="rounded border border-v2-border-weak px-1.5 py-0.5 font-mono hover:bg-v2-surface-hover"
                        >
                          + {step}
                        </button>
                      )}
                    </For>
                    <button
                      type="button"
                      onClick={() => setDecSteps([])}
                      class="rounded border border-v2-border-weak px-1.5 py-0.5 text-v2-text-weak hover:bg-v2-surface-hover"
                    >
                      Clear Steps
                    </button>
                  </div>
                  <div class="font-mono text-v2-text-weak">
                    Pipeline: {decSteps().length > 0 ? decSteps().join(" → ") : "(direct inspect)"}
                  </div>
                  <label class="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={decInspectJwt()}
                      onChange={(e) => setDecInspectJwt(e.currentTarget.checked)}
                    />
                    <span>Inspect JWT Header, Claims & Signature Weaknesses (alg:none / exp / jku)</span>
                  </label>

                  <div class="border-t border-v2-border-weak pt-2">
                    <div class="mb-1 font-medium text-v2-text-strong">
                      Session Token Entropy Sequencer (1 token per line)
                    </div>
                    <textarea
                      rows={3}
                      value={seqTokensText()}
                      onInput={(e) => setSeqTokensText(e.currentTarget.value)}
                      placeholder={"session_id_sample_1\nsession_id_sample_2\nsession_id_sample_3"}
                      class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base p-1.5 font-mono"
                    />
                  </div>
                  <button
                    type="button"
                    disabled={busy()}
                    onClick={() => void runDecoderSequencer()}
                    class="rounded border border-v2-border-base px-3 py-1 font-medium text-v2-text-strong hover:bg-v2-surface-hover"
                  >
                    Run Decoder / JWT / Sequencer
                  </button>
                </section>
              </Show>

              {/* ===================================================================== */}
              {/* TAB 3: WEB SCANNER & FUZZER (NATIVE + NUCLEI + FFUF UNIFIED UI)       */}
              {/* ===================================================================== */}
              <Show when={activeTab() === "webscan"}>
                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">
                    Web Security Headers, Exposure Scanner & Fuzzer
                  </div>
                  <div class="flex flex-wrap gap-1">
                    <For
                      each={[
                        { id: "surface" as const, label: "Native Exposure Templates" },
                        { id: "headers" as const, label: "Passive Headers / CORS / Cookies" },
                        { id: "nuclei" as const, label: "External Nuclei Engine" },
                        { id: "ffuf" as const, label: "External ffuf Fuzzer" },
                      ]}
                    >
                      {(item) => (
                        <button
                          type="button"
                          onClick={() => setWebEngine(item.id)}
                          class={`rounded border px-2 py-0.5 ${
                            webEngine() === item.id
                              ? "border-v2-border-base font-medium text-v2-text-strong"
                              : "border-v2-border-weak text-v2-text-weak"
                          }`}
                        >
                          {item.label}
                        </button>
                      )}
                    </For>
                  </div>

                  <input
                    type="text"
                    value={webBaseUrl()}
                    onInput={(e) => setWebBaseUrl(e.currentTarget.value)}
                    placeholder="http://127.0.0.1:8080"
                    class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                  />

                  <Show when={webEngine() === "surface"}>
                    <div class="space-y-1">
                      <div class="text-v2-text-weak">
                        Additional Custom Paths (checked alongside /.git/HEAD, /.env, /openapi.json, /actuator/health)
                      </div>
                      <input
                        type="text"
                        value={webCustomPaths()}
                        onInput={(e) => setWebCustomPaths(e.currentTarget.value)}
                        class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                      />
                      <div class="flex items-center gap-2">
                        <span>Concurrency (1–4):</span>
                        <input
                          type="range"
                          min="1"
                          max="4"
                          value={webConcurrency()}
                          onInput={(e) => setWebConcurrency(Number(e.currentTarget.value))}
                        />
                        <span class="font-mono">{webConcurrency()}</span>
                      </div>
                    </div>
                  </Show>

                  <Show when={webEngine() === "nuclei"}>
                    <div class="space-y-1">
                      <div class="text-v2-text-weak">Nuclei Template Tags (comma-separated)</div>
                      <input
                        type="text"
                        value={webNucleiTags()}
                        onInput={(e) => setWebNucleiTags(e.currentTarget.value)}
                        class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                      />
                      <div class="flex items-center gap-2">
                        <span>Rate Limit (req/s):</span>
                        <input
                          type="range"
                          min="1"
                          max="50"
                          value={webRateLimit()}
                          onInput={(e) => setWebRateLimit(Number(e.currentTarget.value))}
                        />
                        <span class="font-mono">{webRateLimit()}</span>
                      </div>
                    </div>
                  </Show>

                  <Show when={webEngine() === "ffuf"}>
                    <div class="space-y-1">
                      <div class="text-v2-text-weak">Workspace Wordlist File</div>
                      <input
                        type="text"
                        value={webWordlistPath()}
                        onInput={(e) => setWebWordlistPath(e.currentTarget.value)}
                        class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                      />
                      <div class="flex items-center gap-2">
                        <span>Rate Limit (req/s):</span>
                        <input
                          type="range"
                          min="1"
                          max="25"
                          value={webRateLimit()}
                          onInput={(e) => setWebRateLimit(Number(e.currentTarget.value))}
                        />
                        <span class="font-mono">{webRateLimit()}</span>
                      </div>
                    </div>
                  </Show>

                  <button
                    type="button"
                    disabled={busy()}
                    onClick={() => void runWebScanner()}
                    class="rounded border border-v2-border-base px-3 py-1 font-medium text-v2-text-strong hover:bg-v2-surface-hover"
                  >
                    Launch Web Assessment
                  </button>
                </section>
              </Show>

              {/* ===================================================================== */}
              {/* TAB 4: NETWORK & TLS STUDIO (ZENMAP / NMAP + SSL LABS MANUAL UI)      */}
              {/* ===================================================================== */}
              <Show when={activeTab() === "network"}>
                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">Network Surface, Banners & X.509 TLS Studio</div>
                  <div class="flex flex-wrap gap-1">
                    <For
                      each={[
                        { id: "tls" as const, label: "Native TLS & X.509 Inspector" },
                        { id: "tcp" as const, label: "Native TCP Banner Probe" },
                        { id: "nmap" as const, label: "External Nmap (-sV)" },
                      ]}
                    >
                      {(item) => (
                        <button
                          type="button"
                          onClick={() => setNetEngine(item.id)}
                          class={`rounded border px-2 py-0.5 ${
                            netEngine() === item.id
                              ? "border-v2-border-base font-medium text-v2-text-strong"
                              : "border-v2-border-weak text-v2-text-weak"
                          }`}
                        >
                          {item.label}
                        </button>
                      )}
                    </For>
                  </div>

                  <div class="flex gap-1.5">
                    <input
                      type="text"
                      value={netHost()}
                      onInput={(e) => setNetHost(e.currentTarget.value)}
                      placeholder="Host / IP (e.g. 127.0.0.1)"
                      class="min-w-0 flex-1 rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                    />
                    <Show when={netEngine() !== "nmap"}>
                      <input
                        type="number"
                        value={netPort()}
                        onInput={(e) => setNetPort(Number(e.currentTarget.value) || 443)}
                        class="w-20 rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                      />
                    </Show>
                  </div>

                  <Show when={netEngine() === "tls"}>
                    <input
                      type="text"
                      value={netSni()}
                      onInput={(e) => setNetSni(e.currentTarget.value)}
                      placeholder="SNI Servername (e.g. localhost)"
                      class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                    />
                  </Show>

                  <Show when={netEngine() === "tcp"}>
                    <div class="flex flex-wrap items-center gap-1">
                      <span class="text-v2-text-weak">Quick Ports:</span>
                      <For each={[22, 80, 443, 3306, 5432, 6379, 8080]}>
                        {(p) => (
                          <button
                            type="button"
                            onClick={() => setNetPort(p)}
                            class="rounded border border-v2-border-weak px-1.5 py-0.5 font-mono hover:bg-v2-surface-hover"
                          >
                            {p}
                          </button>
                        )}
                      </For>
                      <span class="ml-2 text-v2-text-weak">Wait(ms):</span>
                      <input
                        type="number"
                        value={netBannerWaitMs()}
                        onInput={(e) => setNetBannerWaitMs(Number(e.currentTarget.value) || 400)}
                        class="w-16 rounded border border-v2-border-weak bg-v2-background-bg-base px-1 py-0.5 font-mono"
                      />
                    </div>
                  </Show>

                  <Show when={netEngine() === "nmap"}>
                    <div class="space-y-1.5">
                      <div class="flex flex-wrap gap-1">
                        <button
                          type="button"
                          onClick={() => setNetPortsRange("80,443,8080,8443")}
                          class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                        >
                          Web Ports
                        </button>
                        <button
                          type="button"
                          onClick={() => setNetPortsRange("22,25,53,3389")}
                          class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                        >
                          Infra Ports
                        </button>
                        <button
                          type="button"
                          onClick={() => setNetPortsRange("3306,5432,6379,27017")}
                          class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                        >
                          DB Ports
                        </button>
                      </div>
                      <input
                        type="text"
                        value={netPortsRange()}
                        onInput={(e) => setNetPortsRange(e.currentTarget.value)}
                        placeholder="80,443,8000-8100"
                        class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                      />
                      <label class="flex items-center gap-1.5">
                        <input
                          type="checkbox"
                          checked={netServiceVersion()}
                          onChange={(e) => setNetServiceVersion(e.currentTarget.checked)}
                        />
                        <span>Service & Version Detection (-sV --version-light)</span>
                      </label>
                    </div>
                  </Show>

                  <button
                    type="button"
                    disabled={busy()}
                    onClick={() => void runNetworkStudio()}
                    class="rounded border border-v2-border-base px-3 py-1 font-medium text-v2-text-strong hover:bg-v2-surface-hover"
                  >
                    Run Network Inspection
                  </button>
                </section>
              </Show>

              {/* ===================================================================== */}
              {/* TAB 5: PACKET CAPTURE (.PCAP) STUDIO (WIRESHARK / TSHARK UI)          */}
              {/* ===================================================================== */}
              <Show when={activeTab() === "packets"}>
                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">Packet Dissector Studio (.pcap)</div>
                  <div class="flex gap-1">
                    <button
                      type="button"
                      onClick={() => setPcapEngine("native")}
                      class={`rounded border px-2 py-0.5 ${
                        pcapEngine() === "native"
                          ? "border-v2-border-base font-medium text-v2-text-strong"
                          : "border-v2-border-weak text-v2-text-weak"
                      }`}
                    >
                      Native Pure-TS Dissector (DNS / TLS SNI / HTTP / Flows)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPcapEngine("tshark")}
                      class={`rounded border px-2 py-0.5 ${
                        pcapEngine() === "tshark"
                          ? "border-v2-border-base font-medium text-v2-text-strong"
                          : "border-v2-border-weak text-v2-text-weak"
                      }`}
                    >
                      External Wireshark tshark
                    </button>
                  </div>
                  <input
                    type="text"
                    value={pcapPath()}
                    onInput={(e) => setPcapPath(e.currentTarget.value)}
                    placeholder="Workspace .pcap path (e.g. capture.pcap)"
                    class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                  />
                  <div class="flex items-center gap-2">
                    <span>Max Packets:</span>
                    <input
                      type="range"
                      min="100"
                      max="25000"
                      step="100"
                      value={pcapMaxPackets()}
                      onInput={(e) => setPcapMaxPackets(Number(e.currentTarget.value))}
                    />
                    <span class="font-mono">{pcapMaxPackets()}</span>
                  </div>
                  <button
                    type="button"
                    disabled={busy()}
                    onClick={() => void runPacketStudio()}
                    class="rounded border border-v2-border-base px-3 py-1 font-medium text-v2-text-strong hover:bg-v2-surface-hover"
                  >
                    Dissect Packet Capture
                  </button>
                </section>
              </Show>

              {/* ===================================================================== */}
              {/* TAB 6: REVERSE ENGINEERING & MOBILE FORENSICS STUDIO                  */}
              {/* ===================================================================== */}
              <Show when={activeTab() === "forensics"}>
                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">
                    Static Binary Reverse Engineering & Mobile Forensics
                  </div>
                  <div class="flex gap-1">
                    <button
                      type="button"
                      onClick={() => {
                        setRevMode("binary")
                        setRevPath("sample.elf")
                      }}
                      class={`rounded border px-2 py-0.5 ${
                        revMode() === "binary"
                          ? "border-v2-border-base font-medium text-v2-text-strong"
                          : "border-v2-border-weak text-v2-text-weak"
                      }`}
                    >
                      ELF / PE / Mach-O Binary Triage
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setRevMode("mobile")
                        setRevPath("suspect.apk")
                      }}
                      class={`rounded border px-2 py-0.5 ${
                        revMode() === "mobile"
                          ? "border-v2-border-base font-medium text-v2-text-strong"
                          : "border-v2-border-weak text-v2-text-weak"
                      }`}
                    >
                      APK / IPA / Mobile Backup Forensics
                    </button>
                  </div>

                  <input
                    type="text"
                    value={revPath()}
                    onInput={(e) => setRevPath(e.currentTarget.value)}
                    placeholder="Workspace artifact path"
                    class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-1 font-mono"
                  />

                  <Show
                    when={revMode() === "binary"}
                    fallback={
                      <textarea
                        rows={2}
                        value={revIocDomains()}
                        onInput={(e) => setRevIocDomains(e.currentTarget.value)}
                        placeholder="Optional IoC domains to hunt inside package (comma or newline separated)..."
                        class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base p-1.5 font-mono"
                      />
                    }
                  >
                    <div class="flex flex-wrap items-center gap-3">
                      <label class="flex items-center gap-1">
                        <span>Min String Len:</span>
                        <input
                          type="number"
                          value={revMinStrLen()}
                          onInput={(e) => setRevMinStrLen(Number(e.currentTarget.value) || 5)}
                          class="w-14 rounded border border-v2-border-weak bg-v2-background-bg-base px-1 py-0.5 font-mono"
                        />
                      </label>
                      <label class="flex items-center gap-1">
                        <span>Max Strings:</span>
                        <input
                          type="number"
                          value={revMaxStrings()}
                          onInput={(e) => setRevMaxStrings(Number(e.currentTarget.value) || 200)}
                          class="w-16 rounded border border-v2-border-weak bg-v2-background-bg-base px-1 py-0.5 font-mono"
                        />
                      </label>
                    </div>
                  </Show>

                  <button
                    type="button"
                    disabled={busy()}
                    onClick={() => void runForensicsStudio()}
                    class="rounded border border-v2-border-base px-3 py-1 font-medium text-v2-text-strong hover:bg-v2-surface-hover"
                  >
                    Run Offline Forensics Triage
                  </button>
                </section>
              </Show>

              {/* ===================================================================== */}
              {/* SHARED FORMATTED RESULT VIEWER FOR TABS 1–6                           */}
              {/* ===================================================================== */}
              <Show when={activeTab() !== "cockpit" && (lastStructuredResult() || lastRawResultText())}>
                <section class="space-y-2 rounded border border-v2-border-weak bg-v2-surface-base p-2.5">
                  <div class="font-medium text-v2-text-strong">Execution Result & Formatted Telemetry</div>
                  <Show when={lastStructuredResult()} keyed>
                    {(structured) => (
                      <pre class="max-h-72 overflow-auto rounded border border-v2-border-weak bg-v2-background-bg-base p-2 font-mono text-[11px]">
                        {JSON.stringify(structured, null, 2)}
                      </pre>
                    )}
                  </Show>
                  <Show when={lastRawResultText() && !lastStructuredResult()}>
                    <pre class="max-h-72 overflow-auto rounded border border-v2-border-weak bg-v2-background-bg-base p-2 font-mono text-[11px]">
                      {lastRawResultText()}
                    </pre>
                  </Show>
                </section>
              </Show>

              {/* ===================================================================== */}
              {/* TAB 7: SCOPE BUILDER, APPROVALS, KILL-SWITCH, CUSTODY & FINDINGS      */}
              {/* ===================================================================== */}
              <Show when={activeTab() === "cockpit"}>
                {/* Visual Scope Rule Builder */}
                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="flex items-center justify-between">
                    <span class="font-medium text-v2-text-strong">Scope & Target Authorization Rules</span>
                    <button
                      type="button"
                      disabled={busy()}
                      onClick={() => void toggleExternalScope(data.status.activeScope?.allowExternalTargets ?? false)}
                      class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                    >
                      External Targets: {String(data.status.activeScope?.allowExternalTargets ?? false)}
                    </button>
                  </div>
                  <div class="space-y-1">
                    <For each={data.status.activeScope?.allowedTargets ?? []}>
                      {(rule, idx) => (
                        <div class="flex items-center justify-between rounded border border-v2-border-weak px-2 py-0.5 font-mono">
                          <span>
                            [{rule.kind}] {rule.value}
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              void removeScopeRule(data.status.activeScope?.allowedTargets ?? [], idx())
                            }
                            class="text-v2-text-weak hover:text-v2-text-strong"
                          >
                            ×
                          </button>
                        </div>
                      )}
                    </For>
                  </div>
                  <div class="flex gap-1">
                    <select
                      value={newRuleKind()}
                      onChange={(e) => setNewRuleKind(e.currentTarget.value as ScopeRuleDto["kind"])}
                      class="rounded border border-v2-border-weak bg-v2-background-bg-base px-1.5 py-0.5 font-mono"
                    >
                      <For each={["ip", "cidr", "domain", "url_origin", "workspace_path"]}>
                        {(k) => <option value={k}>{k}</option>}
                      </For>
                    </select>
                    <input
                      type="text"
                      value={newRuleValue()}
                      onInput={(e) => setNewRuleValue(e.currentTarget.value)}
                      placeholder="10.10.0.0/24 or http://127.0.0.1:8080"
                      class="min-w-0 flex-1 rounded border border-v2-border-weak bg-v2-background-bg-base px-2 py-0.5 font-mono"
                    />
                    <button
                      type="button"
                      disabled={busy()}
                      onClick={() => void addScopeRule(data.status.activeScope?.allowedTargets ?? [])}
                      class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                    >
                      + Add
                    </button>
                  </div>
                </section>

                {/* Approvals Queue */}
                <Show when={data.approvals.length > 0}>
                  <section class="space-y-1.5 rounded border border-v2-border-weak p-2.5">
                    <div class="font-medium text-v2-text-strong">
                      Pending Human Approvals ({data.approvals.length})
                    </div>
                    <For each={data.approvals}>
                      {(ticket) => (
                        <div class="flex items-center justify-between rounded border border-v2-border-weak p-2">
                          <div class="min-w-0 truncate pr-2 font-mono">
                            <div>{ticket.capabilityId}</div>
                            <div class="text-v2-text-weak">{ticket.targetSummary}</div>
                          </div>
                          <button
                            type="button"
                            onClick={() => void approveTicket(ticket.approvalId)}
                            class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                          >
                            Approve & Run
                          </button>
                        </div>
                      )}
                    </For>
                  </section>
                </Show>

                {/* Active & Recent Jobs with Kill-Switch */}
                <section class="space-y-1 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">Executions & Kill-Switch ({data.executions.length})</div>
                  <For each={data.executions.slice(-8).reverse()}>
                    {(ex) => (
                      <div class="flex items-center justify-between rounded border border-v2-border-weak px-2 py-1">
                        <span class="truncate font-mono">
                          {ex.capabilityId} · {ex.status}
                        </span>
                        <Show
                          when={
                            ex.status === "running" || ex.status === "queued" || ex.status === "awaiting_approval"
                          }
                        >
                          <button
                            type="button"
                            onClick={() => void cancelExecution(ex.executionId)}
                            class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                          >
                            Kill
                          </button>
                        </Show>
                      </div>
                    )}
                  </For>
                </section>

                {/* External Tools Radar & Manual Ingest */}
                <section class="space-y-2 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">
                    External Tools Radar (Inbox pending: {data.externalOverview.pendingInboxCount})
                  </div>
                  <div class="grid grid-cols-2 gap-1">
                    <For each={data.externalOverview.tools}>
                      {(t) => (
                        <div class="rounded border border-v2-border-weak px-2 py-1 font-mono">
                          <span class="font-bold">{t.toolId}</span>: {t.available ? "READY" : "MISSING"}
                        </div>
                      )}
                    </For>
                  </div>
                  <div class="flex gap-1 pt-1">
                    <input
                      type="text"
                      value={extToolId()}
                      onInput={(e) => setExtToolId(e.currentTarget.value)}
                      placeholder="tool"
                      class="w-1/3 rounded border border-v2-border-weak bg-v2-background-bg-base px-1.5 py-0.5 font-mono"
                    />
                    <input
                      type="text"
                      value={extTarget()}
                      onInput={(e) => setExtTarget(e.currentTarget.value)}
                      placeholder="target"
                      class="flex-1 rounded border border-v2-border-weak bg-v2-background-bg-base px-1.5 py-0.5 font-mono"
                    />
                  </div>
                  <textarea
                    rows={2}
                    value={extRawOutput()}
                    onInput={(e) => setExtRawOutput(e.currentTarget.value)}
                    placeholder="Paste manual external session output to store with SHA-256..."
                    class="w-full rounded border border-v2-border-weak bg-v2-background-bg-base p-1.5 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => void submitManualIngest()}
                    class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                  >
                    Ingest External Output
                  </button>
                </section>

                {/* SHA-256 Evidence Custody & Inspector */}
                <section class="space-y-1 rounded border border-v2-border-weak p-2.5">
                  <div class="font-medium text-v2-text-strong">
                    SHA-256 Evidence Custody ({data.evidence.length})
                  </div>
                  <For each={data.evidence.slice(-10).reverse()}>
                    {(ev) => (
                      <div class="flex items-center justify-between gap-1 rounded border border-v2-border-weak px-2 py-1">
                        <div class="min-w-0 truncate">
                          <div class="truncate font-medium">{ev.title}</div>
                          <div class="truncate font-mono text-v2-text-weak">sha256:{ev.sha256.slice(0, 16)}…</div>
                        </div>
                        <div class="flex shrink-0 gap-1">
                          <button
                            type="button"
                            onClick={() => void inspectEvidenceRecord(ev.evidenceId)}
                            class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                          >
                            View
                          </button>
                          <button
                            type="button"
                            onClick={() => void verifyCustody(ev.evidenceId)}
                            class="rounded border border-v2-border-weak px-1.5 py-0.5 hover:bg-v2-surface-hover"
                          >
                            {ctx.t("panel.verify")}
                          </button>
                        </div>
                      </div>
                    )}
                  </For>
                  <Show when={inspectedEvidence()} keyed>
                    {(detail) => (
                      <pre class="max-h-48 overflow-auto rounded border border-v2-border-weak bg-v2-background-bg-base p-2 font-mono text-[11px]">
                        {detail.text}
                      </pre>
                    )}
                  </Show>
                </section>

                {/* Findings & Markdown Report */}
                <section class="space-y-1.5 rounded border border-v2-border-weak p-2.5">
                  <div class="flex items-center justify-between">
                    <span class="font-medium text-v2-text-strong">Findings ({data.findings.length})</span>
                    <button
                      type="button"
                      onClick={() => void loadMarkdownReport()}
                      class="rounded border border-v2-border-weak px-2 py-0.5 hover:bg-v2-surface-hover"
                    >
                      Render Report
                    </button>
                  </div>
                  <For each={data.findings}>
                    {(f) => (
                      <div class="rounded border border-v2-border-weak p-2">
                        <div class="flex justify-between">
                          <span class="font-medium">{f.title}</span>
                          <span class="font-mono uppercase text-v2-text-weak">
                            {f.severity} · {f.status}
                          </span>
                        </div>
                        <div class="flex gap-1.5 pt-1">
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
                  <Show when={markdownReport()}>
                    <pre class="max-h-56 overflow-auto rounded border border-v2-border-weak bg-v2-background-bg-base p-2 font-mono text-[11px]">
                      {markdownReport()}
                    </pre>
                  </Show>
                </section>
              </Show>
            </>
          )}
        </Show>
      </div>
    </div>
  )
}
