import { Button } from "@opencode/ui/button"
import { Icon } from "@opencode/ui/icon"
import { usePlugin, type MountedSession } from "@opencode/plugin/gui"
import { createResource, createSignal, For, Show } from "solid-js"
import { cyberlabRequest } from "./api"
import type CyberLabPlugin from "./index"
import type {
  ApprovalDto,
  DispatchPartnersResultDto,
  EvidenceDto,
  ExecutionDto,
  FindingDto,
  HeaderRow,
  MultiCdiDispatchItemDto,
  NetworkToolId,
  PartnersOverviewDto,
  ProxyHistoryEntryDto,
  ProxyOverviewDto,
  ReadEvidenceDto,
  WebToolId,
  WorkspaceSectionId,
  WorkspaceStatusDto,
} from "./types"

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

  const [section, setSection] = createSignal<WorkspaceSectionId>("web")
  const [webTool, setWebTool] = createSignal<WebToolId>("repeater")
  const [networkTool, setNetworkTool] = createSignal<NetworkToolId>("tls")

  const [busy, setBusy] = createSignal(false)
  const [notice, setNotice] = createSignal("")
  const [errorMsg, setErrorMsg] = createSignal("")

  // Collapsible last result drawer
  const [resultTitle, setResultTitle] = createSignal("")
  const [resultText, setResultText] = createSignal("")
  const [resultSummary, setResultSummary] = createSignal<Record<string, unknown> | null>(null)
  const [showRawJson, setShowRawJson] = createSignal(false)

  // === 1. Web & API Controls ===
  const [repMethod, setRepMethod] = createSignal("GET")
  const [repUrl, setRepUrl] = createSignal("http://127.0.0.1:8080/")
  const [repHeaders, setRepHeaders] = createSignal<HeaderRow[]>([
    { id: "h1", enabled: true, name: "Accept", value: "application/json, text/html" },
  ])
  const [repBody, setRepBody] = createSignal("")
  const [repCompareUrl, setRepCompareUrl] = createSignal("")

  const [proxyPort, setProxyPort] = createSignal(8899)

  const [scanEngine, setScanEngine] = createSignal<"surface" | "headers" | "nuclei" | "ffuf">("surface")
  const [scanUrl, setScanUrl] = createSignal("http://127.0.0.1:8080")
  const [scanPathsOrTags, setScanPathsOrTags] = createSignal("/api/v1/health, /graphql, /metrics")

  const [decInput, setDecInput] = createSignal("")
  const [decSteps, setDecSteps] = createSignal<string[]>([])
  const [seqTokens, setSeqTokens] = createSignal("")

  // === 2. Rede & Arquivos Controls ===
  const [netHost, setNetHost] = createSignal("127.0.0.1")
  const [netPort, setNetPort] = createSignal(443)
  const [portsEngine, setPortsEngine] = createSignal<"tcp" | "nmap">("tcp")
  const [portsList, setPortsList] = createSignal("80,443,8080,8443")
  const [pcapPath, setPcapPath] = createSignal("sample.pcap")
  const [artifactKind, setArtifactKind] = createSignal<"binary" | "apk">("binary")
  const [artifactPath, setArtifactPath] = createSignal("artifact.bin")

  // === 3. Agentes CDI Controls ===
  const [selectedCdis, setSelectedCdis] = createSignal<string[]>(["salem", "kairos", "naia", "cdi-4"])
  const [cdiPrompt, setCdiPrompt] = createSignal("")
  const [cdiResults, setCdiResults] = createSignal<MultiCdiDispatchItemDto[]>([])

  // === 4. Evidências & Relatório Controls ===
  const [selectedEvidence, setSelectedEvidence] = createSignal<ReadEvidenceDto | null>(null)
  const [verifyMsg, setVerifyMsg] = createSignal("")
  const [showFindingForm, setShowFindingForm] = createSignal(false)
  const [findingTitle, setFindingTitle] = createSignal("")
  const [findingSeverity, setFindingSeverity] = createSignal<"critical" | "high" | "medium" | "low" | "info">("medium")
  const [findingDesc, setFindingDesc] = createSignal("")
  const [reportMd, setReportMd] = createSignal("")

  const apiCall = <T,>(endpoint: string, init?: RequestInit) =>
    cyberlabRequest<T>(props.session.server, props.session.directory, endpoint, init)

  const sessionKey = () => `${props.session.server.id}::${props.session.directory}`

  const [status, { refetch: refetchStatus }] = createResource(sessionKey, () =>
    apiCall<WorkspaceStatusDto>("/api/cyberlab/status"),
  )
  const [approvals, { refetch: refetchApprovals }] = createResource(sessionKey, () =>
    apiCall<ApprovalDto[]>("/api/cyberlab/approvals"),
  )
  const [executions, { refetch: refetchExecutions }] = createResource(sessionKey, () =>
    apiCall<ExecutionDto[]>("/api/cyberlab/executions"),
  )
  const [evidences, { refetch: refetchEvidences }] = createResource(sessionKey, () =>
    apiCall<EvidenceDto[]>("/api/cyberlab/evidence"),
  )
  const [findings, { refetch: refetchFindings }] = createResource(sessionKey, () =>
    apiCall<FindingDto[]>("/api/cyberlab/findings"),
  )
  const [proxyOverview, { refetch: refetchProxy }] = createResource(sessionKey, () =>
    apiCall<ProxyOverviewDto>("/api/cyberlab/proxy"),
  )
  const [partnersData, { refetch: refetchPartners }] = createResource(sessionKey, () =>
    apiCall<PartnersOverviewDto>("/api/cyberlab/partners"),
  )

  const refreshAll = () => {
    void refetchStatus()
    void refetchApprovals()
    void refetchExecutions()
    void refetchEvidences()
    void refetchFindings()
    void refetchProxy()
    void refetchPartners()
  }

  const attachToChat = (label: string, text: string) => {
    const screen = ctx.screen.current()
    if (!screen || !screen.composer.quotable()) {
      void ctx.system.copy(text)
      setNotice("Copiado para a área de transferência!")
      return
    }
    screen.composer.attach({
      type: "quote",
      commentID: `cyberlab-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      text: text.slice(0, 6000),
      source: {
        label,
        icon: "shield",
        subject: `CyberLab OS (${label})`,
      },
    })
    screen.composer.focus()
    setNotice(`"${label}" anexado direto no Chat da IA!`)
  }

  const readEvidenceById = (evidenceId: string) =>
    apiCall<ReadEvidenceDto>("/api/cyberlab/evidence/read", {
      method: "POST",
      body: JSON.stringify({ evidenceId }),
    })

  const executeCapability = async (label: string, capabilityId: string, input: Record<string, unknown>) => {
    setBusy(true)
    setErrorMsg("")
    setNotice("")
    try {
      const exec = await apiCall<ExecutionDto>("/api/cyberlab/executions", {
        method: "POST",
        body: JSON.stringify({
          capabilityId,
          input,
          mode: "manual",
        }),
      })
      refreshAll()
      if (exec.status === "awaiting_approval") {
        setNotice(`"${label}" aguarda sua aprovação no topo deste painel.`)
        return
      }
      if (exec.status !== "succeeded") {
        setErrorMsg(
          exec.error?.message ?? exec.policyReason ?? `Execução terminou com status "${exec.status}". Verifique o escopo em Configurar.`,
        )
        return
      }
      setNotice(`"${label}" concluído com evidência SHA-256 gravada.`)
      const firstEv = exec.evidenceIds?.[0]
      if (firstEv) {
        const read = await readEvidenceById(firstEv)
        setResultTitle(label)
        setResultText(read.text)
        setResultSummary(tryParseJsonRecord(read.text))
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  // === Handlers: Approvals & Active Runs ===
  const approvePendingTicket = async (approvalId: string) => {
    setBusy(true)
    setErrorMsg("")
    try {
      await apiCall("/api/cyberlab/executions/approve", {
        method: "POST",
        body: JSON.stringify({ approvalId, decidedBy: "operator" }),
      })
      setNotice("Ação aprovada e executada!")
      refreshAll()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const cancelExecution = async (executionId: string) => {
    setBusy(true)
    try {
      await apiCall("/api/cyberlab/executions/cancel", {
        method: "POST",
        body: JSON.stringify({ executionId, reason: "Cancelado pelo operador no painel CyberLab" }),
      })
      setNotice(`Execução ${executionId} interrompida.`)
      refreshAll()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  // === Handlers: Web & API ===
  const sendHttpRepeater = () => {
    const headersObj: Record<string, string> = {}
    for (const row of repHeaders()) {
      if (row.enabled && row.name.trim()) headersObj[row.name.trim()] = row.value
    }
    const compare = repCompareUrl().trim()
    void executeCapability(`HTTP ${repMethod()} ${repUrl().trim()}`, "web-assessment.http-repeater", {
      url: repUrl().trim(),
      method: repMethod(),
      headers: headersObj,
      ...(repBody().trim() ? { body: repBody() } : {}),
      timeoutMs: 8000,
      ...(compare ? { baselineUrl: compare } : {}),
    })
  }

  const toggleProxy = async (start: boolean) => {
    setBusy(true)
    setErrorMsg("")
    try {
      await apiCall("/api/cyberlab/proxy/control", {
        method: "POST",
        body: JSON.stringify(start ? { action: "start", port: proxyPort() } : { action: "stop" }),
      })
      setNotice(start ? `Proxy HTTP local escutando em 127.0.0.1:${proxyPort()}` : "Proxy HTTP local parado.")
      void refetchProxy()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const loadProxyEntryIntoRepeater = (entry: ProxyHistoryEntryDto) => {
    setRepMethod(entry.method)
    setRepUrl(entry.url)
    setRepBody(entry.requestBody || "")
    const rows = Object.entries(entry.requestHeaders ?? {}).map(([name, value], idx) => ({
      id: `ph-${idx}`,
      enabled: true,
      name,
      value,
    }))
    setRepHeaders(rows.length > 0 ? rows : [{ id: "h1", enabled: true, name: "Accept", value: "*/*" }])
    setWebTool("repeater")
    setNotice("Requisição carregada no HTTP Repeater.")
  }

  const runWebScanner = () => {
    const engine = scanEngine()
    const target = scanUrl().trim()
    if (engine === "surface") {
      const customPaths = scanPathsOrTags()
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean)
      void executeCapability("Descoberta de Rotas Web", "web-assessment.surface-discovery", {
        baseUrl: target,
        concurrency: 3,
        customPaths,
      })
      return
    }
    if (engine === "headers") {
      void executeCapability("Auditoria de Headers HTTP", "web-assessment.http-security-headers", {
        url: target,
        timeoutMs: 6000,
      })
      return
    }
    if (engine === "nuclei") {
      const tags = scanPathsOrTags().trim()
      void executeCapability("Nuclei Scanner", "external.nuclei-template-scan", {
        url: target,
        ...(tags ? { tags } : {}),
        rateLimit: 15,
      })
      return
    }
    void executeCapability("ffuf Fuzzer", "external.ffuf-endpoint-probe", {
      baseUrl: target,
      wordlistPath: scanPathsOrTags().trim() || "wordlist.txt",
      rateLimit: 10,
    })
  }

  const runDecoder = () => {
    const tokens = seqTokens()
      .split(/\r?\n/)
      .map((t) => t.trim())
      .filter(Boolean)
    void executeCapability("Decoder, JWT & Entropia", "web-assessment.decoder-sequencer", {
      ...(decInput().trim() ? { value: decInput() } : {}),
      transforms: decSteps(),
      inspectJwt: true,
      ...(tokens.length >= 2 ? { tokenSamples: tokens } : {}),
    })
  }

  // === Handlers: Rede & Arquivos ===
  const runTlsCheck = () => {
    void executeCapability(`Inspeção TLS (${netHost().trim()}:${netPort()})`, "network-assessment.tls-inspector", {
      host: netHost().trim(),
      port: netPort(),
      timeoutMs: 6000,
    })
  }

  const runPortsCheck = () => {
    const firstPort =
      portsList()
        .split(",")
        .map((s) => Number(s.trim()))
        .find((n) => Number.isInteger(n) && n >= 1 && n <= 65535) ?? 80
    if (portsEngine() === "tcp") {
      void executeCapability(`Teste TCP (${netHost().trim()}:${firstPort})`, "network-assessment.tcp-surface-probe", {
        host: netHost().trim(),
        port: firstPort,
        connectTimeoutMs: 2500,
      })
    } else {
      void executeCapability(`Nmap Service Scan (${netHost().trim()})`, "external.nmap-service-probe", {
        host: netHost().trim(),
        ports: portsList().trim() || "80,443",
        serviceVersion: true,
      })
    }
  }

  const runPcapInspect = () => {
    void executeCapability(`Análise de Pacotes (${pcapPath().trim()})`, "network-assessment.pcap-analyzer", {
      pcapPath: pcapPath().trim(),
      maxPackets: 5000,
    })
  }

  const runBinaryOrApkInspect = () => {
    if (artifactKind() === "binary") {
      void executeCapability(`Triagem de Binário (${artifactPath().trim()})`, "reverse-engineering.binary-triage", {
        binaryPath: artifactPath().trim(),
      })
    } else {
      void executeCapability(`Triagem Mobile APK (${artifactPath().trim()})`, "mobile-forensics.artifact-triage", {
        artifactPath: artifactPath().trim(),
      })
    }
  }

  // === Handlers: Agentes CDI ===
  const toggleCdiChoice = (id: string) => {
    const cur = selectedCdis()
    setSelectedCdis(cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id])
  }

  const quickSetupFourCdis = async () => {
    setBusy(true)
    setErrorMsg("")
    try {
      await apiCall("/api/cyberlab/partners/manage", {
        method: "POST",
        body: JSON.stringify({ operation: "preset_4" }),
      })
      setNotice("4 CDIs (Salem :8788, Kairós :8789, Naia :8790, CDI-04 :8791) configurados!")
      void refetchPartners()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const dispatchToCdis = async () => {
    const objective = cdiPrompt().trim()
    const ids = selectedCdis()
    if (!objective || ids.length === 0) return
    setBusy(true)
    setErrorMsg("")
    setNotice("")
    try {
      const res = await apiCall<DispatchPartnersResultDto>("/api/cyberlab/partners/dispatch", {
        method: "POST",
        body: JSON.stringify({
          partnerIds: ids,
          objective,
          contextText: `Workspace: ${status()?.workspaceRoot ?? props.session.directory}`,
        }),
      })
      setCdiResults(res.results)
      setNotice(`Tarefa enviada para ${res.totalDispatched} CDI(s): ${res.succeededCount} responderam.`)
      refreshAll()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  // === Handlers: Evidências & Relatório ===
  const openEvidence = async (evidenceId: string) => {
    setBusy(true)
    setVerifyMsg("")
    try {
      const read = await readEvidenceById(evidenceId)
      setSelectedEvidence(read)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const verifyEvidenceHash = async (evidenceId: string) => {
    try {
      const check = await apiCall<{ valid: boolean; ok?: boolean; expectedSha256?: string }>(
        "/api/cyberlab/evidence/verify",
        {
          method: "POST",
          body: JSON.stringify({ evidenceId }),
        },
      )
      const isValid = check.valid ?? check.ok ?? false
      setVerifyMsg(
        isValid
          ? `Integridade SHA-256 confirmada (${(check.expectedSha256 ?? "").slice(0, 16)}...)`
          : "Falha na verificação SHA-256!",
      )
    } catch (err) {
      setVerifyMsg(err instanceof Error ? err.message : String(err))
    }
  }

  const createFinding = async () => {
    const title = findingTitle().trim()
    if (!title) return
    setBusy(true)
    setErrorMsg("")
    try {
      const evIds = selectedEvidence()
        ? [selectedEvidence()!.evidenceId]
        : evidences()?.[0]?.evidenceId
          ? [evidences()![0]!.evidenceId]
          : []
      await apiCall("/api/cyberlab/findings", {
        method: "POST",
        body: JSON.stringify({
          title,
          description: findingDesc().trim() || title,
          severity: findingSeverity(),
          confidence: 0.9,
          evidenceIds: evIds,
          affectedAssets: [repUrl().trim() || netHost().trim() || "local"],
        }),
      })
      setFindingTitle("")
      setFindingDesc("")
      setShowFindingForm(false)
      setNotice("Finding registrado no projeto!")
      refreshAll()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const generateReport = async () => {
    setBusy(true)
    setErrorMsg("")
    try {
      const res = await apiCall<{ markdown: string }>("/api/cyberlab/report")
      setReportMd(res.markdown)
      setNotice("Relatório Markdown gerado com hashes SHA-256!")
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const pendingApprovals = () => (approvals() ?? []).filter((a) => a.status === "pending")
  const runningExecutions = () => (executions() ?? []).filter((e) => e.status === "running")

  const inputClass =
    "h-8 w-full rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2.5 text-12-regular text-v2-text-text-base outline-none focus:border-v2-text-text-muted"
  const pillClass = (active: boolean) =>
    `rounded-[6px] px-2.5 py-1 text-11-medium transition-colors ${
      active
        ? "bg-v2-text-text-base text-v2-background-bg-base font-medium"
        : "bg-v2-background-bg-deep text-v2-text-text-muted hover:text-v2-text-text-base"
    }`

  return (
    <div class="flex h-full min-h-0 flex-col bg-v2-background-bg-base text-v2-text-text-base">
      {/* Top Header Strip */}
      <div class="flex shrink-0 items-center justify-between gap-2 border-b border-v2-border-border-base px-3 py-2">
        <div class="flex min-w-0 items-center gap-2">
          <Icon name="shield" class="size-4 shrink-0 text-v2-text-text-base" />
          <div class="flex min-w-0 flex-col">
            <span class="truncate text-12-medium font-medium">CyberLab OS</span>
            <span class="truncate text-11-regular text-v2-text-text-muted">
              Escopo: {status()?.activeScope?.allowExternalTargets ? "Local + Externo" : "Local seguro"} ·{" "}
              {status()?.evidenceCount ?? 0} evidências · {status()?.findingCount ?? 0} findings
            </span>
          </div>
        </div>
        <div class="flex shrink-0 items-center gap-1">
          <Button variant="ghost" size="small" icon="refresh" disabled={busy()} onClick={refreshAll} title="Atualizar" />
          <Button
            variant="neutral"
            size="small"
            icon="settings-gear"
            onClick={() => ctx.layout.settings("cyberlab")}
          >
            Configurar
          </Button>
        </div>
      </div>

      {/* Main 4-Category Navigation */}
      <div class="grid shrink-0 grid-cols-4 gap-1 border-b border-v2-border-border-base bg-v2-background-bg-deep/60 p-1.5">
        <button type="button" class={pillClass(section() === "web")} onClick={() => setSection("web")}>
          Web & API
        </button>
        <button type="button" class={pillClass(section() === "network")} onClick={() => setSection("network")}>
          Rede & Arquivos
        </button>
        <button type="button" class={pillClass(section() === "cdi")} onClick={() => setSection("cdi")}>
          Agentes CDI
        </button>
        <button type="button" class={pillClass(section() === "evidence")} onClick={() => setSection("evidence")}>
          Evidências ({status()?.evidenceCount ?? 0})
        </button>
      </div>

      {/* Scrollable Body */}
      <div class="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
        {/* Feedback Notices */}
        <Show when={notice()}>
          <div class="flex items-center justify-between gap-2 rounded-[6px] border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1.5 text-11-regular text-emerald-400">
            <span>{notice()}</span>
            <button type="button" class="text-emerald-300 hover:underline" onClick={() => setNotice("")}>
              ×
            </button>
          </div>
        </Show>
        <Show when={errorMsg()}>
          <div class="flex items-center justify-between gap-2 rounded-[6px] border border-red-500/30 bg-red-500/10 px-2.5 py-1.5 text-11-regular text-red-400">
            <span>{errorMsg()}</span>
            <button type="button" class="text-red-300 hover:underline" onClick={() => setErrorMsg("")}>
              ×
            </button>
          </div>
        </Show>

        {/* Automatic Pending Approvals Banner */}
        <Show when={pendingApprovals().length > 0}>
          <div class="flex flex-col gap-2 rounded-[8px] border border-amber-500/40 bg-amber-500/10 p-2.5">
            <div class="text-12-medium font-medium text-amber-300">
              Aprovação Humana Necessária ({pendingApprovals().length})
            </div>
            <For each={pendingApprovals()}>
              {(item) => (
                <div class="flex flex-wrap items-center justify-between gap-2 rounded-[6px] bg-v2-background-bg-base p-2 text-11-regular">
                  <div class="flex flex-col">
                    <span class="font-medium text-v2-text-text-base">{item.capabilityId}</span>
                    <span class="text-v2-text-text-muted">{item.targetSummary}</span>
                  </div>
                  <div class="flex items-center gap-1.5">
                    <Button
                      variant="submit"
                      size="small"
                      disabled={busy()}
                      onClick={() => void approvePendingTicket(item.approvalId)}
                    >
                      Aprovar
                    </Button>
                    <Button
                      variant="danger"
                      size="small"
                      disabled={busy()}
                      onClick={() => void cancelExecution(item.executionId)}
                    >
                      Rejeitar
                    </Button>
                  </div>
                </div>
              )}
            </For>
          </div>
        </Show>

        {/* Active Running Tools Banner */}
        <Show when={runningExecutions().length > 0}>
          <div class="flex flex-col gap-1.5 rounded-[8px] border border-v2-border-border-base bg-v2-background-bg-deep p-2.5">
            <For each={runningExecutions()}>
              {(exec) => (
                <div class="flex items-center justify-between gap-2 text-11-regular">
                  <span>
                    Executando <strong>{exec.capabilityId}</strong>...
                  </span>
                  <Button
                    variant="danger"
                    size="small"
                    onClick={() => void cancelExecution(exec.executionId)}
                  >
                    Parar
                  </Button>
                </div>
              )}
            </For>
          </div>
        </Show>

        {/* ========================================================= */}
        {/* SEÇÃO 1: WEB & API                                        */}
        {/* ========================================================= */}
        <Show when={section() === "web"}>
          <div class="flex flex-wrap gap-1">
            <button type="button" class={pillClass(webTool() === "repeater")} onClick={() => setWebTool("repeater")}>
              HTTP Repeater
            </button>
            <button type="button" class={pillClass(webTool() === "proxy")} onClick={() => setWebTool("proxy")}>
              Proxy Local {proxyOverview()?.status?.running ? "●" : ""}
            </button>
            <button type="button" class={pillClass(webTool() === "scanner")} onClick={() => setWebTool("scanner")}>
              Scanner Web
            </button>
            <button type="button" class={pillClass(webTool() === "decoder")} onClick={() => setWebTool("decoder")}>
              Decoder & JWT
            </button>
          </div>

          <Show when={webTool() === "repeater"}>
            <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
              <div class="flex flex-col gap-0.5">
                <span class="text-12-medium font-medium">Testar Requisição HTTP (Repeater & Comparer)</span>
                <span class="text-11-regular text-v2-text-text-muted">
                  Envia uma requisição controlada dentro do escopo e grava a resposta com hash SHA-256.
                </span>
              </div>

              <div class="flex gap-1.5">
                <select
                  class="h-8 rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2 text-12-medium"
                  value={repMethod()}
                  onChange={(e) => setRepMethod(e.currentTarget.value)}
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="PATCH">PATCH</option>
                  <option value="DELETE">DELETE</option>
                  <option value="HEAD">HEAD</option>
                </select>
                <input
                  type="text"
                  class={`${inputClass} font-mono`}
                  placeholder="http://127.0.0.1:8080/api/health"
                  value={repUrl()}
                  onInput={(e) => setRepUrl(e.currentTarget.value)}
                />
              </div>

              <div class="flex flex-col gap-1.5">
                <div class="flex items-center justify-between">
                  <span class="text-11-regular text-v2-text-text-muted">Cabeçalhos HTTP</span>
                  <button
                    type="button"
                    class="text-11-regular text-v2-text-text-muted hover:text-v2-text-text-base"
                    onClick={() =>
                      setRepHeaders([
                        ...repHeaders(),
                        { id: `h-${Date.now()}`, enabled: true, name: "", value: "" },
                      ])
                    }
                  >
                    + Cabeçalho
                  </button>
                </div>
                <For each={repHeaders()}>
                  {(row, idx) => (
                    <div class="flex items-center gap-1.5">
                      <input
                        type="checkbox"
                        checked={row.enabled}
                        onChange={(e) =>
                          setRepHeaders(
                            repHeaders().map((r, i) => (i === idx() ? { ...r, enabled: e.currentTarget.checked } : r)),
                          )
                        }
                      />
                      <input
                        type="text"
                        class={`${inputClass} w-1/3 font-mono`}
                        placeholder="Header"
                        value={row.name}
                        onInput={(e) =>
                          setRepHeaders(
                            repHeaders().map((r, i) => (i === idx() ? { ...r, name: e.currentTarget.value } : r)),
                          )
                        }
                      />
                      <input
                        type="text"
                        class={`${inputClass} flex-1 font-mono`}
                        placeholder="Valor"
                        value={row.value}
                        onInput={(e) =>
                          setRepHeaders(
                            repHeaders().map((r, i) => (i === idx() ? { ...r, value: e.currentTarget.value } : r)),
                          )
                        }
                      />
                      <button
                        type="button"
                        class="px-1 text-v2-text-text-muted hover:text-red-400"
                        onClick={() => setRepHeaders(repHeaders().filter((_, i) => i !== idx()))}
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
                  class="w-full rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep p-2 font-mono text-11-regular text-v2-text-text-base outline-none"
                  placeholder='Corpo JSON ou texto (ex.: {"email":"teste@local"})'
                  value={repBody()}
                  onInput={(e) => setRepBody(e.currentTarget.value)}
                />
              </Show>

              <input
                type="text"
                class={`${inputClass} font-mono`}
                placeholder="Opcional: URL base para comparar resposta (IDOR / bypass)"
                value={repCompareUrl()}
                onInput={(e) => setRepCompareUrl(e.currentTarget.value)}
              />

              <Button variant="submit" disabled={busy() || !repUrl().trim()} onClick={sendHttpRepeater}>
                Enviar Requisição HTTP
              </Button>
            </div>
          </Show>

          <Show when={webTool() === "proxy"}>
            <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
              <div class="flex items-center justify-between gap-2">
                <div class="flex flex-col gap-0.5">
                  <span class="text-12-medium font-medium">Proxy HTTP Local de Captura</span>
                  <span class="text-11-regular text-v2-text-text-muted">
                    {proxyOverview()?.status?.running
                      ? `Ativo em 127.0.0.1:${proxyOverview()?.status?.listenPort} (${proxyOverview()?.status?.capturedCount ?? 0} capturadas)`
                      : "Desligado — inicie para capturar tráfego HTTP local e enviar para o Repeater."}
                  </span>
                </div>
                <Show
                  when={proxyOverview()?.status?.running}
                  fallback={
                    <div class="flex items-center gap-1.5">
                      <input
                        type="number"
                        class="h-8 w-20 rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2 font-mono text-12-regular"
                        value={proxyPort()}
                        onInput={(e) => setProxyPort(Number(e.currentTarget.value) || 8899)}
                      />
                      <Button variant="submit" size="small" disabled={busy()} onClick={() => void toggleProxy(true)}>
                        Iniciar Proxy
                      </Button>
                    </div>
                  }
                >
                  <Button variant="danger" size="small" disabled={busy()} onClick={() => void toggleProxy(false)}>
                    Parar Proxy
                  </Button>
                </Show>
              </div>

              <Show
                when={(proxyOverview()?.history?.length ?? 0) > 0}
                fallback={
                  <div class="rounded-[6px] bg-v2-background-bg-deep p-2.5 text-11-regular text-v2-text-text-muted">
                    Configure seu navegador ou curl com <code class="font-mono">--proxy http://127.0.0.1:{proxyPort()}</code> para ver as requisições aqui.
                  </div>
                }
              >
                <div class="flex max-h-56 flex-col gap-1 overflow-y-auto">
                  <For each={proxyOverview()?.history ?? []}>
                    {(entry) => (
                      <div class="flex items-center justify-between gap-2 rounded-[6px] bg-v2-background-bg-deep px-2.5 py-1.5 text-11-regular">
                        <span class="truncate font-mono">
                          <strong>{entry.method}</strong> [{entry.statusCode}] {entry.url}
                        </span>
                        <Button
                          variant="neutral"
                          size="small"
                          onClick={() => loadProxyEntryIntoRepeater(entry)}
                        >
                          Repeater
                        </Button>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </div>
          </Show>

          <Show when={webTool() === "scanner"}>
            <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
              <div class="flex flex-col gap-0.5">
                <span class="text-12-medium font-medium">Scanner Web & Auditoria de Superfície</span>
                <span class="text-11-regular text-v2-text-text-muted">
                  Use os motores nativos integrados ou acione Nuclei / ffuf se estiverem instalados.
                </span>
              </div>

              <select
                class={inputClass}
                value={scanEngine()}
                onChange={(e) => setScanEngine(e.currentTarget.value as "surface" | "headers" | "nuclei" | "ffuf")}
              >
                <option value="surface">Descoberta de Rotas & Superfície (Nativo)</option>
                <option value="headers">Auditoria de Headers de Segurança CSP/HSTS/CORS (Nativo)</option>
                <option value="nuclei">Nuclei Vulnerability Templates (Motor Externo)</option>
                <option value="ffuf">ffuf Content Fuzzing (Motor Externo)</option>
              </select>

              <input
                type="text"
                class={`${inputClass} font-mono`}
                placeholder="URL alvo (ex.: http://127.0.0.1:8080)"
                value={scanUrl()}
                onInput={(e) => setScanUrl(e.currentTarget.value)}
              />

              <Show when={scanEngine() !== "headers"}>
                <input
                  type="text"
                  class={`${inputClass} font-mono`}
                  placeholder={
                    scanEngine() === "surface"
                      ? "Rotas extras separadas por vírgula"
                      : scanEngine() === "nuclei"
                        ? "Tags Nuclei (ex.: misconfig,exposure)"
                        : "Caminho da wordlist (ex.: wordlist.txt)"
                  }
                  value={scanPathsOrTags()}
                  onInput={(e) => setScanPathsOrTags(e.currentTarget.value)}
                />
              </Show>

              <Button variant="submit" disabled={busy() || !scanUrl().trim()} onClick={runWebScanner}>
                Executar Scanner Web
              </Button>
            </div>
          </Show>

          <Show when={webTool() === "decoder"}>
            <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
              <div class="flex flex-col gap-0.5">
                <span class="text-12-medium font-medium">Decoder, Inspetor JWT & Entropia de Tokens</span>
                <span class="text-11-regular text-v2-text-text-muted">
                  100% local e passivo — decodifica payloads, audita tokens JWT e mede previsibilidade de sessões.
                </span>
              </div>

              <textarea
                rows={3}
                class="w-full rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep p-2 font-mono text-11-regular text-v2-text-text-base outline-none"
                placeholder="Cole um token JWT (eyJ...) ou texto codificado..."
                value={decInput()}
                onInput={(e) => setDecInput(e.currentTarget.value)}
              />

              <div class="flex flex-wrap gap-1">
                <For
                  each={[
                    ["base64_decode", "Base64 → Texto"],
                    ["base64_encode", "Texto → Base64"],
                    ["url_decode", "URL Decode"],
                    ["hex_decode", "Hex → Texto"],
                    ["sha256", "Gerar SHA-256"],
                  ]}
                >
                  {([op, label]) => (
                    <button
                      type="button"
                      class="rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1 text-11-regular hover:border-v2-text-text-muted"
                      onClick={() => setDecSteps([...decSteps(), op!])}
                    >
                      + {label}
                    </button>
                  )}
                </For>
                <Show when={decSteps().length > 0}>
                  <button
                    type="button"
                    class="px-2 py-1 text-11-regular text-v2-text-text-muted hover:text-red-400"
                    onClick={() => setDecSteps([])}
                  >
                    Limpar ({decSteps().join(" → ")})
                  </button>
                </Show>
              </div>

              <textarea
                rows={2}
                class="w-full rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep p-2 font-mono text-11-regular text-v2-text-text-base outline-none"
                placeholder="Opcional: cole 2 ou mais tokens de sessão (1 por linha) para medir entropia Shannon"
                value={seqTokens()}
                onInput={(e) => setSeqTokens(e.currentTarget.value)}
              />

              <Button variant="submit" disabled={busy() || (!decInput().trim() && !seqTokens().trim())} onClick={runDecoder}>
                Analisar Payload / JWT
              </Button>
            </div>
          </Show>
        </Show>

        {/* ========================================================= */}
        {/* SEÇÃO 2: REDE & ARQUIVOS                                  */}
        {/* ========================================================= */}
        <Show when={section() === "network"}>
          <div class="flex flex-wrap gap-1">
            <button type="button" class={pillClass(networkTool() === "tls")} onClick={() => setNetworkTool("tls")}>
              Certificado TLS
            </button>
            <button type="button" class={pillClass(networkTool() === "ports")} onClick={() => setNetworkTool("ports")}>
              Portas / Nmap
            </button>
            <button type="button" class={pillClass(networkTool() === "pcap")} onClick={() => setNetworkTool("pcap")}>
              Pacotes .pcap
            </button>
            <button type="button" class={pillClass(networkTool() === "binary")} onClick={() => setNetworkTool("binary")}>
              Binário / APK
            </button>
          </div>

          <Show when={networkTool() === "tls"}>
            <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
              <span class="text-12-medium font-medium">Inspecionar Certificado TLS / X.509</span>
              <div class="flex gap-2">
                <input
                  type="text"
                  class={`${inputClass} flex-1 font-mono`}
                  placeholder="Host (ex.: 127.0.0.1)"
                  value={netHost()}
                  onInput={(e) => setNetHost(e.currentTarget.value)}
                />
                <input
                  type="number"
                  class="h-8 w-24 rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2.5 font-mono text-12-regular"
                  value={netPort()}
                  onInput={(e) => setNetPort(Number(e.currentTarget.value) || 443)}
                />
              </div>
              <Button variant="submit" disabled={busy() || !netHost().trim()} onClick={runTlsCheck}>
                Inspecionar Certificado
              </Button>
            </div>
          </Show>

          <Show when={networkTool() === "ports"}>
            <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
              <span class="text-12-medium font-medium">Conectividade TCP & Descoberta de Serviços</span>
              <select
                class={inputClass}
                value={portsEngine()}
                onChange={(e) => setPortsEngine(e.currentTarget.value as "tcp" | "nmap")}
              >
                <option value="tcp">Teste TCP Rápido + Banner (Motor Nativo)</option>
                <option value="nmap">Nmap Service Version Scan (Motor Externo)</option>
              </select>
              <input
                type="text"
                class={`${inputClass} font-mono`}
                placeholder="Host ou IP em escopo (ex.: 127.0.0.1)"
                value={netHost()}
                onInput={(e) => setNetHost(e.currentTarget.value)}
              />
              <input
                type="text"
                class={`${inputClass} font-mono`}
                placeholder="Portas (ex.: 22,80,443,8080)"
                value={portsList()}
                onInput={(e) => setPortsList(e.currentTarget.value)}
              />
              <Button variant="submit" disabled={busy() || !netHost().trim()} onClick={runPortsCheck}>
                Testar Portas
              </Button>
            </div>
          </Show>

          <Show when={networkTool() === "pcap"}>
            <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
              <div class="flex flex-col gap-0.5">
                <span class="text-12-medium font-medium">Análise Offline de Captura .pcap</span>
                <span class="text-11-regular text-v2-text-text-muted">
                  Extrai conversas IP/TCP/UDP, consultas DNS, TLS SNI e alertas de credenciais em texto claro.
                </span>
              </div>
              <input
                type="text"
                class={`${inputClass} font-mono`}
                placeholder="Caminho no workspace (ex.: captures/trafego.pcap)"
                value={pcapPath()}
                onInput={(e) => setPcapPath(e.currentTarget.value)}
              />
              <Button variant="submit" disabled={busy() || !pcapPath().trim()} onClick={runPcapInspect}>
                Analisar Arquivo .pcap
              </Button>
            </div>
          </Show>

          <Show when={networkTool() === "binary"}>
            <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
              <span class="text-12-medium font-medium">Triagem Estática de Executável ou App Android</span>
              <select
                class={inputClass}
                value={artifactKind()}
                onChange={(e) => setArtifactKind(e.currentTarget.value as "binary" | "apk")}
              >
                <option value="binary">Executável ELF / PE / Mach-O (Entropia & Strings)</option>
                <option value="apk">Aplicativo Android .apk (Permissões & Segredos)</option>
              </select>
              <input
                type="text"
                class={`${inputClass} font-mono`}
                placeholder="Caminho no workspace (ex.: samples/app.apk)"
                value={artifactPath()}
                onInput={(e) => setArtifactPath(e.currentTarget.value)}
              />
              <Button variant="submit" disabled={busy() || !artifactPath().trim()} onClick={runBinaryOrApkInspect}>
                Executar Triagem Estática
              </Button>
            </div>
          </Show>
        </Show>

        {/* ========================================================= */}
        {/* SEÇÃO 3: AGENTES CDI BIDIRECIONAIS                        */}
        {/* ========================================================= */}
        <Show when={section() === "cdi"}>
          <div class="flex flex-col gap-2.5 rounded-[8px] border border-v2-border-border-base p-3">
            <div class="flex flex-col gap-0.5">
              <span class="text-12-medium font-medium">Despacho Individual ou Paralelo para CDIs</span>
              <span class="text-11-regular text-v2-text-text-muted">
                Chame 1 especialista ou vários ao mesmo tempo. Configure portas e segredo em Configurar.
              </span>
            </div>

            <Show
              when={(partnersData()?.partners?.length ?? 0) > 0}
              fallback={
                <div class="flex flex-col gap-2 rounded-[6px] bg-v2-background-bg-deep p-3 text-11-regular text-v2-text-text-muted">
                  <span>Nenhum agente CDI cadastrado ainda neste projeto.</span>
                  <div class="flex gap-2">
                    <Button variant="submit" size="small" disabled={busy()} onClick={() => void quickSetupFourCdis()}>
                      Ativar 4 CDIs Padrão (8788–8791)
                    </Button>
                    <Button variant="neutral" size="small" onClick={() => ctx.layout.settings("cyberlab")}>
                      Abrir Configurações
                    </Button>
                  </div>
                </div>
              }
            >
              <div class="grid grid-cols-2 gap-1.5">
                <For each={partnersData()?.partners ?? []}>
                  {(partner) => {
                    const checked = () => selectedCdis().includes(partner.partnerId)
                    return (
                      <label
                        class={`flex cursor-pointer items-center gap-2 rounded-[6px] border px-2.5 py-2 text-11-regular ${
                          checked()
                            ? "border-v2-text-text-muted bg-v2-background-bg-deep text-v2-text-text-base"
                            : "border-v2-border-border-base text-v2-text-text-muted"
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked()}
                          onChange={() => toggleCdiChoice(partner.partnerId)}
                        />
                        <div class="flex min-w-0 flex-col">
                          <span class="truncate font-medium">{partner.displayName}</span>
                          <span class="truncate text-[10px] opacity-75">{partner.endpointUrl.replace("http://", "")}</span>
                        </div>
                      </label>
                    )
                  }}
                </For>
              </div>

              <textarea
                rows={3}
                class="w-full rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep p-2 text-12-regular text-v2-text-text-base outline-none"
                placeholder="Descreva a análise para os CDIs marcados (ex.: Correlacionar evidências recentes e propor próximos testes dentro do escopo)..."
                value={cdiPrompt()}
                onInput={(e) => setCdiPrompt(e.currentTarget.value)}
              />

              <Button
                variant="submit"
                disabled={busy() || !cdiPrompt().trim() || selectedCdis().length === 0}
                onClick={() => void dispatchToCdis()}
              >
                Enviar para {selectedCdis().length} CDI(s) {selectedCdis().length > 1 ? "em Paralelo" : ""}
              </Button>
            </Show>
          </div>

          <Show when={cdiResults().length > 0}>
            <div class="flex flex-col gap-2">
              <span class="text-11-medium font-medium text-v2-text-text-muted">Respostas dos CDIs</span>
              <For each={cdiResults()}>
                {(entry) => {
                  const summary = () => entry.outcome?.result?.summary ?? ""
                  return (
                    <div class="flex flex-col gap-1.5 rounded-[8px] border border-v2-border-border-base bg-v2-background-bg-deep p-2.5 text-11-regular">
                      <div class="flex items-center justify-between gap-2">
                        <span class="font-medium">
                          {entry.displayName} · {entry.durationMs}ms
                        </span>
                        <Show when={summary()}>
                          <Button
                            variant="ghost"
                            size="small"
                            onClick={() => attachToChat(`CDI ${entry.displayName}`, summary())}
                          >
                            Anexar ao Chat
                          </Button>
                        </Show>
                      </div>
                      <pre class="max-h-40 overflow-auto whitespace-pre-wrap font-sans text-v2-text-text-base">
                        {entry.ok ? summary() || "Concluído." : `Erro: ${entry.error ?? "Sem resposta"}`}
                      </pre>
                    </div>
                  )
                }}
              </For>
            </div>
          </Show>

          <Show when={(partnersData()?.inboundActivity?.length ?? 0) > 0}>
            <div class="flex flex-col gap-1.5 rounded-[8px] border border-v2-border-border-base p-2.5">
              <span class="text-11-medium font-medium text-v2-text-text-muted">
                Atividade Bidirecional Recente (CDI → CyberLab OS)
              </span>
              <div class="flex max-h-40 flex-col gap-1 overflow-y-auto">
                <For each={(partnersData()?.inboundActivity ?? []).slice(0, 10)}>
                  {(act) => (
                    <div class="rounded bg-v2-background-bg-deep px-2 py-1 text-[11px]">
                      <span class="font-mono text-v2-text-text-muted">[{act.outcome}]</span>{" "}
                      <strong>{act.partnerId}</strong> · {act.action}: {act.summary}
                    </div>
                  )}
                </For>
              </div>
            </div>
          </Show>
        </Show>

        {/* ========================================================= */}
        {/* SEÇÃO 4: EVIDÊNCIAS SHA-256, FINDINGS & RELATÓRIO         */}
        {/* ========================================================= */}
        <Show when={section() === "evidence"}>
          <div class="flex flex-wrap items-center justify-between gap-1.5">
            <Button variant="neutral" size="small" icon="plus" onClick={() => setShowFindingForm(!showFindingForm())}>
              {showFindingForm() ? "Fechar Finding" : "Registrar Finding"}
            </Button>
            <Button variant="contrast" size="small" icon="file-document" disabled={busy()} onClick={() => void generateReport()}>
              Gerar Relatório .md
            </Button>
          </div>

          <Show when={showFindingForm()}>
            <div class="flex flex-col gap-2 rounded-[8px] border border-v2-border-border-base p-3">
              <span class="text-12-medium font-medium">Novo Finding de Segurança</span>
              <input
                type="text"
                class={inputClass}
                placeholder="Título (ex.: Header HSTS ausente em produção)"
                value={findingTitle()}
                onInput={(e) => setFindingTitle(e.currentTarget.value)}
              />
              <select
                class={inputClass}
                value={findingSeverity()}
                onChange={(e) =>
                  setFindingSeverity(e.currentTarget.value as "critical" | "high" | "medium" | "low" | "info")
                }
              >
                <option value="critical">Crítica (Critical)</option>
                <option value="high">Alta (High)</option>
                <option value="medium">Média (Medium)</option>
                <option value="low">Baixa (Low)</option>
                <option value="info">Informativa (Info)</option>
              </select>
              <textarea
                rows={2}
                class="w-full rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep p-2 text-12-regular outline-none"
                placeholder="Descrição técnica e recomendação de correção..."
                value={findingDesc()}
                onInput={(e) => setFindingDesc(e.currentTarget.value)}
              />
              <Button variant="submit" size="small" disabled={busy() || !findingTitle().trim()} onClick={() => void createFinding()}>
                Salvar Finding
              </Button>
            </div>
          </Show>

          <Show when={(findings()?.length ?? 0) > 0}>
            <div class="flex flex-col gap-1.5">
              <span class="text-11-medium font-medium text-v2-text-text-muted">Findings Registrados ({findings()?.length})</span>
              <For each={findings() ?? []}>
                {(f) => (
                  <div class="flex items-center justify-between gap-2 rounded-[6px] border border-v2-border-border-base px-2.5 py-1.5 text-11-regular">
                    <span class="truncate font-medium">{f.title}</span>
                    <span class="shrink-0 uppercase text-v2-text-text-muted">{f.severity}</span>
                  </div>
                )}
              </For>
            </div>
          </Show>

          <div class="flex flex-col gap-1.5">
            <span class="text-11-medium font-medium text-v2-text-text-muted">
              Cadeia de Custódia SHA-256 ({evidences()?.length ?? 0})
            </span>
            <Show
              when={(evidences()?.length ?? 0) > 0}
              fallback={
                <div class="rounded-[6px] bg-v2-background-bg-deep p-3 text-11-regular text-v2-text-text-muted">
                  Nenhuma evidência gravada ainda. Execute qualquer ferramenta nas abas acima para registrar evidências com hash SHA-256.
                </div>
              }
            >
              <div class="flex max-h-52 flex-col gap-1 overflow-y-auto">
                <For each={evidences() ?? []}>
                  {(ev) => (
                    <button
                      type="button"
                      class="flex items-center justify-between gap-2 rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep/50 px-2.5 py-1.5 text-left text-11-regular hover:border-v2-text-text-muted"
                      onClick={() => void openEvidence(ev.evidenceId)}
                    >
                      <span class="truncate font-medium">{ev.title}</span>
                      <code class="shrink-0 font-mono text-[10px] text-v2-text-text-muted">{ev.sha256.slice(0, 10)}</code>
                    </button>
                  )}
                </For>
              </div>
            </Show>
          </div>

          <Show when={selectedEvidence()}>
            {(ev) => (
              <div class="flex flex-col gap-2 rounded-[8px] border border-v2-border-border-base bg-v2-background-bg-deep p-2.5 text-11-regular">
                <div class="flex flex-wrap items-center justify-between gap-1.5">
                  <span class="font-medium">{ev().title}</span>
                  <div class="flex items-center gap-1">
                    <Button
                      variant="neutral"
                      size="small"
                      onClick={() => void verifyEvidenceHash(ev().evidenceId)}
                    >
                      Verificar SHA-256
                    </Button>
                    <Button
                      variant="contrast"
                      size="small"
                      onClick={() => attachToChat(ev().title, ev().text)}
                    >
                      Anexar ao Chat
                    </Button>
                  </div>
                </div>
                <Show when={verifyMsg()}>
                  <div class="text-emerald-400">{verifyMsg()}</div>
                </Show>
                <pre class="max-h-48 overflow-auto whitespace-pre-wrap font-mono text-[11px]">{ev().text}</pre>
              </div>
            )}
          </Show>

          <Show when={reportMd()}>
            <div class="flex flex-col gap-2 rounded-[8px] border border-v2-border-border-base bg-v2-background-bg-deep p-2.5">
              <div class="flex items-center justify-between gap-2">
                <span class="text-11-medium font-medium">Relatório Markdown</span>
                <div class="flex gap-1.5">
                  <Button variant="neutral" size="small" icon="copy" onClick={() => void ctx.system.copy(reportMd())}>
                    Copiar
                  </Button>
                  <Button
                    variant="submit"
                    size="small"
                    icon="download"
                    onClick={() =>
                      void ctx.system.save({
                        name: "relatorio-cyberlab-os.md",
                        content: reportMd(),
                      })
                    }
                  >
                    Salvar .md
                  </Button>
                </div>
              </div>
              <pre class="max-h-52 overflow-auto whitespace-pre-wrap font-mono text-[11px]">{reportMd()}</pre>
            </div>
          </Show>
        </Show>

        {/* ========================================================= */}
        {/* GAVETA DE RESULTADO DA ÚLTIMA FERRAMENTA                  */}
        {/* ========================================================= */}
        <Show when={resultText()}>
          <div class="mt-auto flex flex-col gap-2 rounded-[8px] border border-v2-border-border-base bg-v2-background-bg-deep p-2.5 text-11-regular">
            <div class="flex flex-wrap items-center justify-between gap-1.5">
              <span class="font-medium">Resultado: {resultTitle()}</span>
              <div class="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="small"
                  onClick={() => setShowRawJson(!showRawJson())}
                >
                  {showRawJson() ? "Resumo" : "JSON Bruto"}
                </Button>
                <Button
                  variant="contrast"
                  size="small"
                  onClick={() => attachToChat(resultTitle(), resultText())}
                >
                  Anexar ao Chat
                </Button>
                <button
                  type="button"
                  class="px-1 text-v2-text-text-muted hover:text-v2-text-text-base"
                  onClick={() => {
                    setResultText("")
                    setResultSummary(null)
                  }}
                >
                  ×
                </button>
              </div>
            </div>

            <Show
              when={!showRawJson() && resultSummary()}
              fallback={
                <pre class="max-h-52 overflow-auto whitespace-pre-wrap font-mono text-[11px]">{resultText()}</pre>
              }
            >
              <div class="flex max-h-52 flex-col gap-1 overflow-auto font-mono text-[11px]">
                <For each={Object.entries(resultSummary() ?? {}).slice(0, 14)}>
                  {([k, v]) => (
                    <div>
                      <span class="text-v2-text-text-muted">{k}: </span>
                      <span>{typeof v === "string" || typeof v === "number" || typeof v === "boolean" ? String(v) : JSON.stringify(v)}</span>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </Show>
      </div>
    </div>
  )
}
