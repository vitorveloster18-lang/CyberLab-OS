import { batch, createContext, createEffect, createMemo, onCleanup, onMount, useContext, type ParentProps } from "solid-js"
import { createStore, reconcile } from "solid-js/store"
import type { ComposerModel } from "@/composer/model"
import { useServers, ServerConnection } from "@/runtime/server/registry"
import { useTabs } from "@/shell/tabs/tabs"
import { useCurrentRoute } from "@/shell/state/layout"
import { cyberlabFetch, type CyberLabServerTarget } from "./api"
import {
  buildCapabilityInput,
  createDefaultToolDrafts,
  DEFAULT_QUICK_TOOLS,
  findSuiteAndFunctionForTool,
  getSuiteMeta,
  getToolMeta,
  MANUAL_TOOLS,
  TOOL_SUITES,
} from "./catalog"
import type {
  ApprovalDto,
  DispatchPartnersResultDto,
  EvidenceDto,
  ExecutionDto,
  ExternalToolsOverviewDto,
  FindingDto,
  KeyValueHeaderRow,
  ManualToolDraftMap,
  ManualToolId,
  PartnersOverviewDto,
  ProxyHistoryEntryDto,
  ProxyOverviewDto,
  ReadEvidenceDto,
  ScopeRuleDto,
  ToolHistoryEntry,
  ToolSuiteId,
  WorkbenchLayoutMode,
  WorkspaceStatusDto,
} from "./types"

const UI_STORAGE_KEY = "cyberlab.manual.ui.v1"
const DRAFTS_STORAGE_KEY = "cyberlab.manual.drafts.v1"
const HISTORY_STORAGE_KEY = "cyberlab.manual.history.v1"
const MAX_HISTORY_PER_TOOL = 40

type StoredUiPrefs = {
  open: boolean
  layoutMode: WorkbenchLayoutMode
  splitWidthPct: number
  activeSuiteId?: ToolSuiteId
  activeFunctionBySuite?: Partial<Record<ToolSuiteId, string>>
  activeEngineByFunction?: Record<string, ManualToolId>
  historyScope?: "function" | "suite"
  activeToolId: ManualToolId
  quickToolIds: ManualToolId[]
  showHistoryColumn: boolean
  directoryOverride: string
}

function safeReadJson<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback
  try {
    const raw = window.localStorage.getItem(key)
    if (!raw) return fallback
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

function safeWriteJson(key: string, value: unknown): void {
  if (typeof window === "undefined") return
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Ignore storage quota errors
  }
}

function createEmptyHistories(): Record<ManualToolId, ToolHistoryEntry[]> {
  return {
    "http-repeater": [],
    "http-proxy": [],
    "http-intruder": [],
    "param-audit": [],
    dalfox: [],
    "api-security-lab": [],
    "http-headers": [],
    "web-surface": [],
    nuclei: [],
    ffuf: [],
    "decoder-jwt": [],
    "tls-inspector": [],
    "tcp-probe": [],
    nmap: [],
    "dns-recon": [],
    "ad-smb-ldap": [],
    "pcap-analyzer": [],
    tshark: [],
    "workspace-audit": [],
    "sca-sbom-iac": [],
    trivy: [],
    "binary-triage": [],
    "binary-disasm": [],
    ghidra: [],
    "entropy-recipe": [],
    "mobile-triage": [],
    jadx: [],
    "yara-scan": [],
    yarax: [],
    "dfir-sigma": [],
    "cdi-hub": [],
    "external-ingest": [],
    "scope-governance": [],
  }
}

function isValidToolId(value: string): value is ManualToolId {
  return MANUAL_TOOLS.some((t) => t.id === value)
}

function createWorkbenchService() {
  const servers = useServers()
  const tabs = useTabs()
  const currentRoute = useCurrentRoute()

  const savedUi = safeReadJson<Partial<StoredUiPrefs>>(UI_STORAGE_KEY, {})
  const defaultDrafts = createDefaultToolDrafts()
  const savedDrafts = safeReadJson<Partial<ManualToolDraftMap>>(DRAFTS_STORAGE_KEY, {})
  const mergedDrafts: ManualToolDraftMap = {
    "http-repeater": { ...defaultDrafts["http-repeater"], ...(savedDrafts["http-repeater"] ?? {}) },
    "http-proxy": { ...defaultDrafts["http-proxy"], ...(savedDrafts["http-proxy"] ?? {}) },
    "http-intruder": { ...defaultDrafts["http-intruder"], ...(savedDrafts["http-intruder"] ?? {}) },
    "param-audit": { ...defaultDrafts["param-audit"], ...(savedDrafts["param-audit"] ?? {}) },
    dalfox: { ...defaultDrafts.dalfox, ...(savedDrafts.dalfox ?? {}) },
    "api-security-lab": { ...defaultDrafts["api-security-lab"], ...(savedDrafts["api-security-lab"] ?? {}) },
    "http-headers": { ...defaultDrafts["http-headers"], ...(savedDrafts["http-headers"] ?? {}) },
    "web-surface": { ...defaultDrafts["web-surface"], ...(savedDrafts["web-surface"] ?? {}) },
    nuclei: { ...defaultDrafts.nuclei, ...(savedDrafts.nuclei ?? {}) },
    ffuf: { ...defaultDrafts.ffuf, ...(savedDrafts.ffuf ?? {}) },
    "decoder-jwt": { ...defaultDrafts["decoder-jwt"], ...(savedDrafts["decoder-jwt"] ?? {}) },
    "tls-inspector": { ...defaultDrafts["tls-inspector"], ...(savedDrafts["tls-inspector"] ?? {}) },
    "tcp-probe": { ...defaultDrafts["tcp-probe"], ...(savedDrafts["tcp-probe"] ?? {}) },
    nmap: { ...defaultDrafts.nmap, ...(savedDrafts.nmap ?? {}) },
    "dns-recon": { ...defaultDrafts["dns-recon"], ...(savedDrafts["dns-recon"] ?? {}) },
    "ad-smb-ldap": { ...defaultDrafts["ad-smb-ldap"], ...(savedDrafts["ad-smb-ldap"] ?? {}) },
    "pcap-analyzer": { ...defaultDrafts["pcap-analyzer"], ...(savedDrafts["pcap-analyzer"] ?? {}) },
    tshark: { ...defaultDrafts.tshark, ...(savedDrafts.tshark ?? {}) },
    "workspace-audit": { ...defaultDrafts["workspace-audit"], ...(savedDrafts["workspace-audit"] ?? {}) },
    "sca-sbom-iac": { ...defaultDrafts["sca-sbom-iac"], ...(savedDrafts["sca-sbom-iac"] ?? {}) },
    trivy: { ...defaultDrafts.trivy, ...(savedDrafts.trivy ?? {}) },
    "binary-triage": { ...defaultDrafts["binary-triage"], ...(savedDrafts["binary-triage"] ?? {}) },
    "binary-disasm": { ...defaultDrafts["binary-disasm"], ...(savedDrafts["binary-disasm"] ?? {}) },
    ghidra: { ...defaultDrafts.ghidra, ...(savedDrafts.ghidra ?? {}) },
    "entropy-recipe": { ...defaultDrafts["entropy-recipe"], ...(savedDrafts["entropy-recipe"] ?? {}) },
    "mobile-triage": { ...defaultDrafts["mobile-triage"], ...(savedDrafts["mobile-triage"] ?? {}) },
    jadx: { ...defaultDrafts.jadx, ...(savedDrafts.jadx ?? {}) },
    "yara-scan": { ...defaultDrafts["yara-scan"], ...(savedDrafts["yara-scan"] ?? {}) },
    yarax: { ...defaultDrafts.yarax, ...(savedDrafts.yarax ?? {}) },
    "dfir-sigma": { ...defaultDrafts["dfir-sigma"], ...(savedDrafts["dfir-sigma"] ?? {}) },
    "cdi-hub": { ...defaultDrafts["cdi-hub"], ...(savedDrafts["cdi-hub"] ?? {}) },
    "external-ingest": { ...defaultDrafts["external-ingest"], ...(savedDrafts["external-ingest"] ?? {}) },
    "scope-governance": { ...defaultDrafts["scope-governance"], ...(savedDrafts["scope-governance"] ?? {}) },
  }

  const savedHistories = safeReadJson<Partial<Record<ManualToolId, ToolHistoryEntry[]>>>(HISTORY_STORAGE_KEY, {})
  const initialHistories = createEmptyHistories()
  for (const tool of MANUAL_TOOLS) {
    const arr = savedHistories[tool.id]
    if (Array.isArray(arr)) {
      initialHistories[tool.id] = arr.slice(0, MAX_HISTORY_PER_TOOL)
    }
  }

  const initialQuickTools = Array.isArray(savedUi.quickToolIds)
    ? savedUi.quickToolIds.filter((id): id is ManualToolId => typeof id === "string" && isValidToolId(id))
    : []

  const initialToolId: ManualToolId =
    typeof savedUi.activeToolId === "string" && isValidToolId(savedUi.activeToolId)
      ? savedUi.activeToolId
      : "http-repeater"

  const inferredSuite = findSuiteAndFunctionForTool(initialToolId)
  const initialSuiteId: ToolSuiteId =
    savedUi.activeSuiteId && TOOL_SUITES.some((s) => s.id === savedUi.activeSuiteId)
      ? savedUi.activeSuiteId
      : inferredSuite.suiteId

  const defaultFnBySuite: Record<ToolSuiteId, string> = {
    "web-suite": "repeater",
    "network-suite": "ports",
    "packet-suite": "pcap",
    "reversing-suite": "binary",
    "dfir-suite": "sigma-triage",
    "code-suite": "audit",
    "cdi-suite": "dispatch",
    "governance-suite": "scope",
    ...(savedUi.activeFunctionBySuite ?? {}),
  }

  const [ui, setUi] = createStore<{
    open: boolean
    layoutMode: WorkbenchLayoutMode
    splitWidthPct: number
    activeSuiteId: ToolSuiteId
    activeFunctionBySuite: Record<ToolSuiteId, string>
    activeEngineByFunction: Record<string, ManualToolId>
    historyScope: "function" | "suite"
    activeToolId: ManualToolId
    quickToolIds: ManualToolId[]
    showHistoryColumn: boolean
    directoryOverride: string
    selectedHistoryByTool: Partial<Record<ManualToolId, string>>
    runningToolId: ManualToolId | null
    runningExecutionId: string | null
    notice: string
    error: string
  }>({
    open: Boolean(savedUi.open),
    layoutMode: savedUi.layoutMode === "fullscreen" ? "fullscreen" : "split",
    splitWidthPct:
      typeof savedUi.splitWidthPct === "number" ? Math.min(72, Math.max(38, savedUi.splitWidthPct)) : 54,
    activeSuiteId: initialSuiteId,
    activeFunctionBySuite: defaultFnBySuite,
    activeEngineByFunction: savedUi.activeEngineByFunction ?? {},
    historyScope: savedUi.historyScope === "suite" ? "suite" : "function",
    activeToolId: initialToolId,
    quickToolIds: initialQuickTools.length > 0 ? initialQuickTools : [...DEFAULT_QUICK_TOOLS],
    showHistoryColumn: savedUi.showHistoryColumn !== false,
    directoryOverride: typeof savedUi.directoryOverride === "string" ? savedUi.directoryOverride : "",
    selectedHistoryByTool: {},
    runningToolId: null,
    runningExecutionId: null,
    notice: "",
    error: "",
  })

  const [drafts, setDrafts] = createStore<ManualToolDraftMap>(mergedDrafts)
  const [histories, setHistories] = createStore<Record<ManualToolId, ToolHistoryEntry[]>>(initialHistories)

  const [backend, setBackend] = createStore<{
    loading: boolean
    status: WorkspaceStatusDto | null
    approvals: ApprovalDto[]
    executions: ExecutionDto[]
    evidence: EvidenceDto[]
    findings: FindingDto[]
    proxy: ProxyOverviewDto | null
    partners: PartnersOverviewDto | null
    external: ExternalToolsOverviewDto | null
    reportMarkdown: string
    inspectedEvidence: ReadEvidenceDto | null
    revealedSecret: string
  }>({
    loading: false,
    status: null,
    approvals: [],
    executions: [],
    evidence: [],
    findings: [],
    proxy: null,
    partners: null,
    external: null,
    reportMarkdown: "",
    inspectedEvidence: null,
    revealedSecret: "",
  })

  let activeComposer: ComposerModel | undefined

  const registerComposer = (composer: ComposerModel) => {
    activeComposer = composer
    return () => {
      if (activeComposer === composer) activeComposer = undefined
    }
  }

  const persistUi = () => {
    safeWriteJson(UI_STORAGE_KEY, {
      open: ui.open,
      layoutMode: ui.layoutMode,
      splitWidthPct: ui.splitWidthPct,
      activeSuiteId: ui.activeSuiteId,
      activeFunctionBySuite: { ...ui.activeFunctionBySuite },
      activeEngineByFunction: { ...ui.activeEngineByFunction },
      historyScope: ui.historyScope,
      activeToolId: ui.activeToolId,
      quickToolIds: [...ui.quickToolIds],
      showHistoryColumn: ui.showHistoryColumn,
      directoryOverride: ui.directoryOverride,
    } satisfies StoredUiPrefs)
  }

  const persistDrafts = () => {
    safeWriteJson(DRAFTS_STORAGE_KEY, JSON.parse(JSON.stringify(drafts)))
  }

  const persistHistories = () => {
    safeWriteJson(HISTORY_STORAGE_KEY, JSON.parse(JSON.stringify(histories)))
  }

  const resolvedDirectory = createMemo(() => {
    if (ui.directoryOverride.trim()) return ui.directoryOverride.trim()
    const route = currentRoute()
    if (route.type === "draft") {
      const tab = tabs.store.find((t): t is Extract<typeof t, { type: "draft" }> => t.type === "draft" && t.draftID === route.draftID)
      if (tab?.directory) return tab.directory
    }
    const anyDraft = tabs.store.find((t): t is Extract<typeof t, { type: "draft" }> => t.type === "draft")
    if (anyDraft?.directory) return anyDraft.directory
    return backend.status?.workspaceRoot || undefined
  })

  const serverTarget = createMemo<CyberLabServerTarget>(() => {
    const conn =
      servers.list.find((item) => ServerConnection.local(item)) ??
      servers.list.find((item) => item.type === "http") ??
      servers.list[0]
    const baseUrl = conn?.type === "http" ? conn.http.url : undefined
    const password = conn?.type === "http" ? conn.http.password : undefined
    return {
      baseUrl,
      password,
      directory: resolvedDirectory(),
    }
  })

  const setNotice = (msg: string) => {
    batch(() => {
      setUi("error", "")
      setUi("notice", msg)
    })
  }

  const setError = (msg: string) => {
    batch(() => {
      setUi("notice", "")
      setUi("error", msg)
    })
  }

  const applySuiteAndFunction = (suiteId: ToolSuiteId, functionId?: string, engineToolId?: ManualToolId) => {
    const suite = getSuiteMeta(suiteId)
    const fn =
      suite.functions.find((f) => f.id === (functionId ?? ui.activeFunctionBySuite[suiteId])) ?? suite.functions[0]!
    const fnKey = `${suiteId}:${fn.id}`
    const rememberedEngine = ui.activeEngineByFunction[fnKey]
    const resolvedEngine =
      (engineToolId && fn.engines.some((e) => e.toolId === engineToolId) ? engineToolId : undefined) ??
      (rememberedEngine && fn.engines.some((e) => e.toolId === rememberedEngine) ? rememberedEngine : undefined) ??
      fn.engines[0]!.toolId

    batch(() => {
      setUi("activeSuiteId", suiteId)
      setUi("activeFunctionBySuite", suiteId, fn.id)
      setUi("activeEngineByFunction", fnKey, resolvedEngine)
      setUi("activeToolId", resolvedEngine)
      setUi("open", true)
      if (fn.governanceSubTab) {
        setDrafts("scope-governance", "subTab", fn.governanceSubTab)
      }
      if (fn.cdiSubTab) {
        setDrafts("cdi-hub", "cdiSubTab", fn.cdiSubTab)
      }
    })
    persistUi()
    persistDrafts()
  }

  const selectSuite = (suiteId: ToolSuiteId, functionId?: string, engineToolId?: ManualToolId) => {
    applySuiteAndFunction(suiteId, functionId, engineToolId)
  }

  const selectSuiteFunction = (functionId: string) => {
    applySuiteAndFunction(ui.activeSuiteId, functionId)
  }

  const selectSuiteEngine = (toolId: ManualToolId) => {
    const fnId = ui.activeFunctionBySuite[ui.activeSuiteId]
    applySuiteAndFunction(ui.activeSuiteId, fnId, toolId)
  }

  const setHistoryScope = (scope: "function" | "suite") => {
    setUi("historyScope", scope)
    persistUi()
  }

  const selectTool = (toolId: ManualToolId, opts?: { openWorkbench?: boolean }) => {
    const loc = findSuiteAndFunctionForTool(toolId)
    batch(() => {
      setUi("activeSuiteId", loc.suiteId)
      setUi("activeFunctionBySuite", loc.suiteId, loc.functionId)
      setUi("activeEngineByFunction", `${loc.suiteId}:${loc.functionId}`, toolId)
      setUi("activeToolId", toolId)
      if (opts?.openWorkbench !== false) {
        setUi("open", true)
      }
    })
    persistUi()
  }

  const sendUrlAcrossWebSuite = (url: string, targetFunction: "headers" | "scanner" | "intruder" | "params") => {
    const clean = url.trim()
    if (!clean) return
    if (targetFunction === "headers") {
      updateDraft("http-headers", (p) => ({ ...p, url: clean }))
      applySuiteAndFunction("web-suite", "headers", "http-headers")
      setNotice(`URL enviada para Headers & Cookies (${clean}).`)
      return
    }
    if (targetFunction === "intruder") {
      const templated = clean.includes("§") ? clean : clean.includes("=") ? clean.replace(/=([^&]*)/, "=§$1§") : `${clean.replace(/\/$/, "")}/§payload§`
      updateDraft("http-intruder", (p) => ({ ...p, url: templated, useRawJson: false }))
      applySuiteAndFunction("web-suite", "intruder", "http-intruder")
      setNotice(`URL enviada para HTTP Intruder (${templated}).`)
      return
    }
    if (targetFunction === "params") {
      updateDraft("param-audit", (p) => ({ ...p, url: clean, useRawJson: false }))
      updateDraft("dalfox", (p) => ({ ...p, url: clean, useRawJson: false }))
      applySuiteAndFunction("web-suite", "params")
      setNotice(`URL enviada para Auditor de Parâmetros (${clean}).`)
      return
    }
    try {
      const parsed = new URL(clean)
      const originUrl = parsed.origin
      updateDraft("web-surface", (p) => ({ ...p, baseUrl: originUrl }))
      updateDraft("nuclei", (p) => ({ ...p, url: clean }))
      updateDraft("ffuf", (p) => ({ ...p, baseUrl: originUrl }))
    } catch {
      updateDraft("web-surface", (p) => ({ ...p, baseUrl: clean }))
    }
    applySuiteAndFunction("web-suite", "scanner")
    setNotice(`URL enviada para Scanner & Fuzzer (${clean}).`)
  }

  const sendTextToDecoder = (value: string) => {
    updateDraft("decoder-jwt", (p) => ({ ...p, value: value.slice(0, 65000) }))
    applySuiteAndFunction("web-suite", "decoder", "decoder-jwt")
    setNotice("Conteúdo enviado para o Decoder / JWT Inspector.")
  }

  const toggleWorkbench = (force?: boolean) => {
    const next = force ?? !ui.open
    setUi("open", next)
    persistUi()
  }

  const setLayoutMode = (mode: WorkbenchLayoutMode) => {
    setUi("layoutMode", mode)
    if (!ui.open) setUi("open", true)
    persistUi()
  }

  const setSplitWidthPct = (pct: number) => {
    setUi("splitWidthPct", Math.min(72, Math.max(38, pct)))
    persistUi()
  }

  const setShowHistoryColumn = (show: boolean) => {
    setUi("showHistoryColumn", show)
    persistUi()
  }

  const setDirectoryOverride = (dir: string) => {
    setUi("directoryOverride", dir)
    persistUi()
    void refreshBackend()
  }

  function updateDraft<K extends ManualToolId>(
    toolId: K,
    updater: (prev: ManualToolDraftMap[K]) => ManualToolDraftMap[K],
  ): void {
    const next = updater(JSON.parse(JSON.stringify(drafts[toolId])) as ManualToolDraftMap[K])
    setDrafts(toolId, reconcile(next))
    persistDrafts()
  }

  function resetToolDraft(toolId: ManualToolId): void {
    const defaults = createDefaultToolDrafts()
    setDrafts(toolId, reconcile(defaults[toolId]))
    persistDrafts()
    setNotice(`Configurações padrão restauradas para ${getToolMeta(toolId).shortTitle}.`)
  }

  function recordHistoryEntry(toolId: ManualToolId, entry: ToolHistoryEntry): void {
    const current = histories[toolId] ?? []
    const next = [entry, ...current.filter((item) => item.id !== entry.id)].slice(0, MAX_HISTORY_PER_TOOL)
    batch(() => {
      setHistories(toolId, next)
      setUi("selectedHistoryByTool", toolId, entry.id)
    })
    persistHistories()
  }

  function updateHistoryEntry(
    toolId: ManualToolId,
    entryId: string,
    patch: Partial<ToolHistoryEntry>,
  ): void {
    const current = histories[toolId] ?? []
    const next = current.map((item) => (item.id === entryId ? { ...item, ...patch } : item))
    setHistories(toolId, next)
    persistHistories()
  }

  function deleteHistoryEntry(toolId: ManualToolId, entryId: string): void {
    const current = histories[toolId] ?? []
    const next = current.filter((item) => item.id !== entryId)
    batch(() => {
      setHistories(toolId, next)
      if (ui.selectedHistoryByTool[toolId] === entryId) {
        setUi("selectedHistoryByTool", toolId, next[0]?.id)
      }
    })
    persistHistories()
  }

  function clearToolHistory(toolId: ManualToolId): void {
    batch(() => {
      setHistories(toolId, [])
      setUi("selectedHistoryByTool", toolId, undefined)
    })
    persistHistories()
    setNotice(`Histórico de ${getToolMeta(toolId).shortTitle} limpo.`)
  }

  function restoreHistoryDraft(entry: ToolHistoryEntry): void {
    if (!entry.draftSnapshot) return
    const defaults = createDefaultToolDrafts()[entry.toolId]
    const merged = { ...defaults, ...entry.draftSnapshot }
    const loc = findSuiteAndFunctionForTool(entry.toolId)
    batch(() => {
      setDrafts(entry.toolId, reconcile(merged as never))
      setUi("activeSuiteId", loc.suiteId)
      setUi("activeFunctionBySuite", loc.suiteId, loc.functionId)
      setUi("activeEngineByFunction", `${loc.suiteId}:${loc.functionId}`, entry.toolId)
      setUi("activeToolId", entry.toolId)
      setUi("selectedHistoryByTool", entry.toolId, entry.id)
    })
    persistUi()
    persistDrafts()
    setNotice(`Parâmetros de "${entry.targetSummary}" carregados na ferramenta.`)
  }

  async function refreshBackend(): Promise<void> {
    setBackend("loading", true)
    const target = serverTarget()
    try {
      const [status, approvals, executions, evidence, findings, proxy, partners, external] = await Promise.all([
        cyberlabFetch<WorkspaceStatusDto>(target, "/api/cyberlab/status").catch(() => null),
        cyberlabFetch<ApprovalDto[]>(target, "/api/cyberlab/approvals").catch(() => []),
        cyberlabFetch<ExecutionDto[]>(target, "/api/cyberlab/executions").catch(() => []),
        cyberlabFetch<EvidenceDto[]>(target, "/api/cyberlab/evidence").catch(() => []),
        cyberlabFetch<FindingDto[]>(target, "/api/cyberlab/findings").catch(() => []),
        cyberlabFetch<ProxyOverviewDto>(target, "/api/cyberlab/proxy").catch(() => null),
        cyberlabFetch<PartnersOverviewDto>(target, "/api/cyberlab/partners").catch(() => null),
        cyberlabFetch<ExternalToolsOverviewDto>(target, "/api/cyberlab/external/tools").catch(() => null),
      ])
      batch(() => {
        if (status) setBackend("status", reconcile(status))
        setBackend("approvals", reconcile(approvals))
        setBackend("executions", reconcile(executions))
        setBackend("evidence", reconcile(evidence))
        setBackend("findings", reconcile(findings))
        if (proxy) setBackend("proxy", reconcile(proxy))
        if (partners) setBackend("partners", reconcile(partners))
        if (external) setBackend("external", reconcile(external))
      })
    } finally {
      setBackend("loading", false)
    }
  }

  async function readEvidenceText(evidenceIds: string[]): Promise<{ combinedText: string; firstSha256?: string }> {
    const target = serverTarget()
    const chunks: string[] = []
    let firstSha256: string | undefined
    for (const evId of evidenceIds) {
      try {
        const ev = await cyberlabFetch<ReadEvidenceDto>(target, "/api/cyberlab/evidence/read", {
          method: "POST",
          body: JSON.stringify({ evidenceId: evId }),
        })
        if (!firstSha256) firstSha256 = ev.sha256
        chunks.push(
          evidenceIds.length > 1
            ? `=== Evidência ${ev.evidenceId} (${ev.title}) [SHA-256: ${ev.sha256}] ===\n${ev.text}`
            : ev.text,
        )
      } catch (err) {
        chunks.push(`Erro ao ler evidência ${evId}: ${err instanceof Error ? err.message : String(err)}`)
      }
    }
    return { combinedText: chunks.join("\n\n"), firstSha256 }
  }

  async function runCapabilityTool(toolId: ManualToolId): Promise<void> {
    setUi("error", "")
    setUi("notice", "")
    const snapshot = JSON.parse(JSON.stringify(drafts[toolId])) as Record<string, unknown>

    // Special multi-port sequential convenience mode for Sonda TCP
    if (toolId === "tcp-probe" && drafts["tcp-probe"].useMultiPort && !drafts["tcp-probe"].useRawJson) {
      const d = drafts["tcp-probe"]
      const ports = d.multiPortList
        .split(/[\s,;]+/)
        .map((p) => Number.parseInt(p.trim(), 10))
        .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
        .slice(0, 25)
      if (ports.length === 0) {
        setError("Informe ao menos uma porta válida (1–65535) na lista multi-portas.")
        return
      }
      const startedAt = Date.now()
      const entryId = `hist-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      recordHistoryEntry(toolId, {
        id: entryId,
        toolId,
        capabilityId: "network-assessment.tcp-surface-probe",
        timestamp: new Date().toISOString(),
        targetSummary: `TCP Multi ${d.host.trim()} [${ports.join(",")}]`,
        status: "running",
        evidenceIds: [],
        summaryText: `Sondando ${ports.length} portas em ${d.host.trim()}...`,
        outputText: "",
        draftSnapshot: snapshot,
      })
      setUi("runningToolId", toolId)
      try {
        const target = serverTarget()
        const lines: string[] = []
        const allEvIds: string[] = []
        let firstSha: string | undefined
        for (const p of ports) {
          const exec = await cyberlabFetch<ExecutionDto>(target, "/api/cyberlab/executions", {
            method: "POST",
            body: JSON.stringify({
              capabilityId: "network-assessment.tcp-surface-probe",
              mode: d.executionMode,
              input: {
                host: d.host.trim(),
                port: p,
                connectTimeoutMs: Math.min(5000, Math.max(100, Math.trunc(Number(d.connectTimeoutMs) || 1500))),
                bannerWaitMs: Math.min(1000, Math.max(20, Math.trunc(Number(d.bannerWaitMs) || 250))),
              },
            }),
          })
          allEvIds.push(...exec.evidenceIds)
          if (exec.evidenceIds.length > 0) {
            const { combinedText, firstSha256 } = await readEvidenceText(exec.evidenceIds)
            if (!firstSha && firstSha256) firstSha = firstSha256
            lines.push(`--- Porta ${p} (${exec.status}) ---\n${combinedText}`)
          } else {
            lines.push(
              `--- Porta ${p} (${exec.status}) ---\n${exec.error?.message || exec.policyReason || "Sem evidência gerada"}`,
            )
          }
        }
        updateHistoryEntry(toolId, entryId, {
          status: "succeeded",
          durationMs: Date.now() - startedAt,
          evidenceIds: allEvIds,
          sha256: firstSha,
          summaryText: `${ports.length} portas testadas (${allEvIds.length} evidências SHA-256)`,
          outputText: lines.join("\n\n"),
        })
        setNotice(`Varredura TCP concluída (${ports.length} portas).`)
        await refreshBackend()
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        updateHistoryEntry(toolId, entryId, {
          status: "failed",
          durationMs: Date.now() - startedAt,
          summaryText: msg,
          outputText: msg,
        })
        setError(msg)
      } finally {
        setUi("runningToolId", null)
      }
      return
    }

    let built: ReturnType<typeof buildCapabilityInput>
    try {
      built = buildCapabilityInput(toolId, drafts)
    } catch (err) {
      setError(`Parâmetros inválidos: ${err instanceof Error ? err.message : String(err)}`)
      return
    }

    const startedAt = Date.now()
    const entryId = `hist-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
    recordHistoryEntry(toolId, {
      id: entryId,
      toolId,
      capabilityId: built.capabilityId,
      timestamp: new Date().toISOString(),
      targetSummary: built.targetSummary,
      status: "running",
      evidenceIds: [],
      summaryText: "Executando...",
      outputText: "",
      draftSnapshot: snapshot,
      rawInputPayload: built.input,
    })

    setUi("runningToolId", toolId)
    try {
      const target = serverTarget()
      const exec = await cyberlabFetch<ExecutionDto>(target, "/api/cyberlab/executions", {
        method: "POST",
        body: JSON.stringify({
          capabilityId: built.capabilityId,
          mode: built.mode,
          input: built.input,
        }),
      })
      setUi("runningExecutionId", exec.executionId)
      await refreshBackend()

      if (exec.status === "queued") {
        const matchingApproval = backend.approvals.find((a) => a.executionId === exec.executionId)
        updateHistoryEntry(toolId, entryId, {
          status: "queued",
          durationMs: Date.now() - startedAt,
          executionId: exec.executionId,
          approvalId: matchingApproval?.approvalId,
          evidenceIds: exec.evidenceIds,
          summaryText: exec.policyReason || "Aguardando aprovação humana em 1 clique",
          outputText: JSON.stringify(
            {
              status: "queued_for_human_approval",
              executionId: exec.executionId,
              approvalId: matchingApproval?.approvalId,
              reason: exec.policyReason,
              input: built.input,
            },
            null,
            2,
          ),
        })
        setNotice("Execução enfileirada para confirmação humana. Clique em 'Aprovar & Executar Agora' no resultado.")
        return
      }

      if (exec.status !== "succeeded") {
        const reason = exec.error?.message || exec.policyReason || `Execução terminou com status: ${exec.status}`
        updateHistoryEntry(toolId, entryId, {
          status: exec.status === "cancelled" ? "cancelled" : "failed",
          durationMs: Date.now() - startedAt,
          executionId: exec.executionId,
          evidenceIds: exec.evidenceIds,
          summaryText: reason,
          outputText: JSON.stringify(exec, null, 2),
        })
        setError(reason)
        return
      }

      const { combinedText, firstSha256 } = await readEvidenceText(exec.evidenceIds)
      updateHistoryEntry(toolId, entryId, {
        status: "succeeded",
        durationMs: Date.now() - startedAt,
        executionId: exec.executionId,
        evidenceIds: exec.evidenceIds,
        sha256: firstSha256,
        summaryText: `Concluído (${exec.evidenceIds.length} evidência(s) SHA-256)`,
        outputText: combinedText || JSON.stringify(exec, null, 2),
      })
      setNotice(`Execução concluída com sucesso em ${Date.now() - startedAt} ms.`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      updateHistoryEntry(toolId, entryId, {
        status: "failed",
        durationMs: Date.now() - startedAt,
        summaryText: msg,
        outputText: msg,
      })
      setError(msg)
    } finally {
      setUi("runningToolId", null)
      setUi("runningExecutionId", null)
    }
  }

  async function approvePendingExecution(approvalId: string, relatedHistory?: ToolHistoryEntry): Promise<void> {
    setUi("error", "")
    const startedAt = Date.now()
    try {
      const target = serverTarget()
      const exec = await cyberlabFetch<ExecutionDto>(target, "/api/cyberlab/executions/approve", {
        method: "POST",
        body: JSON.stringify({
          approvalId,
          decidedBy: "manual-workbench-operator",
          reason: "Aprovado manualmente pelo operador na Bancada CyberLab OS",
        }),
      })
      const { combinedText, firstSha256 } = await readEvidenceText(exec.evidenceIds)
      if (relatedHistory) {
        updateHistoryEntry(relatedHistory.toolId, relatedHistory.id, {
          status: exec.status === "succeeded" ? "succeeded" : "failed",
          durationMs: Date.now() - startedAt,
          executionId: exec.executionId,
          evidenceIds: exec.evidenceIds,
          sha256: firstSha256,
          summaryText:
            exec.status === "succeeded"
              ? `Aprovado e concluído (${exec.evidenceIds.length} evidência(s))`
              : exec.error?.message || exec.policyReason || exec.status,
          outputText: combinedText || JSON.stringify(exec, null, 2),
        })
      }
      setNotice(`Ticket ${approvalId.slice(0, 8)} aprovado e executado (${exec.status}).`)
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function cancelExecution(executionId: string): Promise<void> {
    try {
      await cyberlabFetch(serverTarget(), "/api/cyberlab/executions/cancel", {
        method: "POST",
        body: JSON.stringify({ executionId, reason: "Cancelado pelo operador na Bancada Manual" }),
      })
      setNotice(`Execução ${executionId.slice(0, 8)} cancelada.`)
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function controlProxy(
    action: "start" | "stop" | "clear" | "set_scope_only" | "set_https_mode",
    overrideHttpsMode?: "tls_intercept" | "tunnel_passthrough",
  ): Promise<void> {
    const d = drafts["http-proxy"]
    const nextHttpsMode = overrideHttpsMode ?? d.httpsMode
    try {
      const res = await cyberlabFetch<ProxyOverviewDto>(serverTarget(), "/api/cyberlab/proxy/control", {
        method: "POST",
        body: JSON.stringify({
          action,
          port: Math.min(65535, Math.max(1024, Math.trunc(Number(d.port) || 8899))),
          scopeOnly: action === "set_scope_only" ? !backend.proxy?.status.scopeOnly : d.scopeOnly,
          httpsMode: nextHttpsMode,
          allowSelfSignedUpstream: d.allowSelfSignedUpstream,
        }),
      })
      setBackend("proxy", reconcile(res))
      if (res.status.httpsMode) {
        updateDraft("http-proxy", (prev) => ({ ...prev, httpsMode: res.status.httpsMode! }))
      }
      recordHistoryEntry("http-proxy", {
        id: `proxy-${Date.now()}`,
        toolId: "http-proxy",
        timestamp: new Date().toISOString(),
        targetSummary: `Proxy ${action.toUpperCase()} (${res.status.listenHost}:${res.status.listenPort ?? d.port})`,
        status: "succeeded",
        evidenceIds: [],
        summaryText: res.status.running
          ? `Ativo em http://${res.status.listenHost}:${res.status.listenPort} [${res.status.httpsMode ?? "tls_intercept"}] (${res.history.length} capturas)`
          : "Proxy parado",
        outputText: JSON.stringify(res.status, null, 2),
        draftSnapshot: JSON.parse(JSON.stringify(d)) as Record<string, unknown>,
      })
      setNotice(
        res.status.running
          ? `Proxy HTTP/HTTPS/WS ativo em http://${res.status.listenHost}:${res.status.listenPort} (${res.status.httpsMode === "tunnel_passthrough" ? "Túnel CONNECT" : "TLS MITM c/ Root CA"})`
          : "Proxy HTTP/HTTPS atualizado.",
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  function downloadProxyRootCaCert(): void {
    const pem = backend.proxy?.status.caCertPem
    if (!pem) {
      setError("Inicie o Proxy ao menos uma vez ou atualize o painel para gerar a Root CA local.")
      return
    }
    const blob = new Blob([pem], { type: "application/x-x509-ca-cert" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = "cyberlab-root-ca.crt"
    a.click()
    URL.revokeObjectURL(url)
    setNotice("Certificado cyberlab-root-ca.crt exportado! Importe no navegador/sistema para inspecionar HTTPS.")
  }

  async function persistProxyCapture(entry: ProxyHistoryEntryDto): Promise<void> {
    try {
      const res = await cyberlabFetch<{ evidenceId: string; sha256: string }>(
        serverTarget(),
        "/api/cyberlab/proxy/persist",
        {
          method: "POST",
          body: JSON.stringify({ entryId: entry.entryId }),
        },
      )
      recordHistoryEntry("http-proxy", {
        id: `proxy-ev-${Date.now()}`,
        toolId: "http-proxy",
        timestamp: new Date().toISOString(),
        targetSummary: `${entry.method} ${entry.url} → ${entry.statusCode}`,
        status: "succeeded",
        evidenceIds: [res.evidenceId],
        sha256: res.sha256,
        summaryText: `Evidência gravada (${res.evidenceId.slice(0, 12)})`,
        outputText: JSON.stringify(entry, null, 2),
        draftSnapshot: JSON.parse(JSON.stringify(drafts["http-proxy"])) as Record<string, unknown>,
      })
      setNotice(`Captura gravada no cofre SHA-256 (${res.sha256.slice(0, 16)}…).`)
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  function sendProxyCaptureToRepeater(entry: ProxyHistoryEntryDto): void {
    const headerRows: KeyValueHeaderRow[] = Object.entries(entry.requestHeaders ?? {}).map(([name, value], idx) => ({
      id: `px-h-${idx}-${Date.now()}`,
      enabled: name.toLowerCase() !== "host" && name.toLowerCase() !== "content-length",
      name,
      value,
    }))
    const allowedMethods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const
    const upper = entry.method.toUpperCase()
    const method = (allowedMethods.find((m) => m === upper) ?? "GET")
    updateDraft("http-repeater", (prev) => ({
      ...prev,
      method,
      url: entry.url,
      headers: headerRows.length > 0 ? headerRows : prev.headers,
      body: entry.requestBody || "",
      useRawJson: false,
    }))
    selectTool("http-repeater")
    setNotice(`Requisição ${method} ${entry.url} enviada para o HTTP Repeater!`)
  }

  function sendProxyCaptureToIntruder(entry: ProxyHistoryEntryDto): void {
    const headerRows: KeyValueHeaderRow[] = Object.entries(entry.requestHeaders ?? {}).map(([name, value], idx) => ({
      id: `px-i-${idx}-${Date.now()}`,
      enabled: name.toLowerCase() !== "host" && name.toLowerCase() !== "content-length",
      name,
      value,
    }))
    const allowedMethods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const
    const upper = entry.method.toUpperCase()
    const method = allowedMethods.find((m) => m === upper) ?? "GET"
    const templatedUrl = entry.url.includes("=")
      ? entry.url.replace(/=([^&]*)/, "=§$1§")
      : `${entry.url.replace(/\/$/, "")}/§payload§`
    updateDraft("http-intruder", (prev) => ({
      ...prev,
      method,
      url: templatedUrl,
      headers: headerRows.length > 0 ? headerRows : prev.headers,
      bodyTemplate: entry.requestBody || "",
      useRawJson: false,
    }))
    selectTool("http-intruder")
    setNotice(`Captura enviada para o HTTP Intruder (${templatedUrl})!`)
  }

  async function dispatchCdiMission(): Promise<void> {
    const d = drafts["cdi-hub"]
    if (d.selectedPartnerIds.length === 0) {
      setError("Selecione ao menos um Agente CDI (ex.: Kairós, Naia, Salem ou Nova).")
      return
    }
    if (!d.objective.trim()) {
      setError("Informe o objetivo da missão para os Agentes CDI.")
      return
    }
    const startedAt = Date.now()
    const entryId = `cdi-${Date.now()}`
    const snapshot = JSON.parse(JSON.stringify(d)) as Record<string, unknown>
    recordHistoryEntry("cdi-hub", {
      id: entryId,
      toolId: "cdi-hub",
      timestamp: new Date().toISOString(),
      targetSummary: `${d.selectedPartnerIds.join(", ")} — ${d.objective.trim().slice(0, 60)}`,
      status: "running",
      evidenceIds: [],
      summaryText: "Aguardando resposta assinada HMAC-SHA256 dos CDIs...",
      outputText: "",
      draftSnapshot: snapshot,
    })
    setUi("runningToolId", "cdi-hub")
    try {
      const res = await cyberlabFetch<DispatchPartnersResultDto>(serverTarget(), "/api/cyberlab/partners/dispatch", {
        method: "POST",
        body: JSON.stringify({
          partnerIds: d.selectedPartnerIds,
          objective: d.objective.trim(),
          evidenceIds: d.selectedEvidenceIds.length > 0 ? d.selectedEvidenceIds : undefined,
          contextText: d.contextText.trim() || undefined,
          timeoutMs: Math.min(120000, Math.max(1000, Math.trunc(Number(d.timeoutMs) || 30000))),
        }),
      })
      const evIds = res.results.map((r) => r.outcome?.rawEvidenceId).filter((x): x is string => Boolean(x))
      const formatted = res.results
        .map(
          (r) =>
            `### ${r.displayName} (${r.partnerId}) — ${r.ok ? "OK" : "FALHA"} (${r.durationMs} ms)\n${
              r.ok ? r.outcome?.result?.summary || "(sem resumo textual)" : r.error || "Falha de conexão"
            }`,
        )
        .join("\n\n")
      updateHistoryEntry("cdi-hub", entryId, {
        status: res.succeededCount > 0 ? "succeeded" : "failed",
        durationMs: Date.now() - startedAt,
        evidenceIds: evIds,
        summaryText: `${res.succeededCount}/${res.totalDispatched} CDI(s) responderam (${res.mode})`,
        outputText: formatted || JSON.stringify(res, null, 2),
      })
      setNotice(`Despacho CDI concluído: ${res.succeededCount}/${res.totalDispatched} com sucesso.`)
      await refreshBackend()
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      updateHistoryEntry("cdi-hub", entryId, {
        status: "failed",
        durationMs: Date.now() - startedAt,
        summaryText: msg,
        outputText: msg,
      })
      setError(msg)
    } finally {
      setUi("runningToolId", null)
    }
  }

  async function ingestManualExternal(): Promise<void> {
    const d = drafts["external-ingest"]
    if (!d.rawOutput.trim()) {
      setError("Cole a saída da ferramenta externa ou carregue um arquivo antes de ingerir.")
      return
    }
    const startedAt = Date.now()
    const snapshot = JSON.parse(JSON.stringify(d)) as Record<string, unknown>
    try {
      const res = await cyberlabFetch<{
        evidenceId: string
        sha256: string
        targetInScope: boolean
        scopeReason: string
      }>(serverTarget(), "/api/cyberlab/external/ingest", {
        method: "POST",
        body: JSON.stringify({
          toolId: d.toolId.trim() || "custom",
          title: d.title.trim() || undefined,
          origin: d.origin.trim() || "manual_gui_export",
          target: d.target.trim() || undefined,
          commandSummary: d.commandSummary.trim() || undefined,
          mediaType: d.mediaType.trim() || "text/plain",
          rawOutput: d.rawOutput,
        }),
      })
      recordHistoryEntry("external-ingest", {
        id: `ing-${Date.now()}`,
        toolId: "external-ingest",
        timestamp: new Date().toISOString(),
        targetSummary: `${d.toolId}: ${d.title || d.target || "Artefato externo"}`,
        status: "succeeded",
        durationMs: Date.now() - startedAt,
        evidenceIds: [res.evidenceId],
        sha256: res.sha256,
        summaryText: `Gravado no EvidenceStore (SHA-256: ${res.sha256.slice(0, 16)}…)`,
        outputText: JSON.stringify(res, null, 2),
        draftSnapshot: snapshot,
      })
      setNotice(`Saída externa ingerida com custódia SHA-256 (${res.evidenceId.slice(0, 12)}).`)
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function syncExternalInbox(): Promise<void> {
    try {
      const res = await cyberlabFetch<{ ingestedCount: number; evidenceIds: string[] }>(
        serverTarget(),
        "/api/cyberlab/external/sync",
        { method: "POST", body: JSON.stringify({}) },
      )
      recordHistoryEntry("external-ingest", {
        id: `sync-${Date.now()}`,
        toolId: "external-ingest",
        timestamp: new Date().toISOString(),
        targetSummary: "Sincronização .cyberlab/inbox",
        status: "succeeded",
        evidenceIds: res.evidenceIds ?? [],
        summaryText: `${res.ingestedCount} arquivo(s) sincronizado(s) da inbox`,
        outputText: JSON.stringify(res, null, 2),
        draftSnapshot: JSON.parse(JSON.stringify(drafts["external-ingest"])) as Record<string, unknown>,
      })
      setNotice(`Inbox sincronizada: ${res.ingestedCount} arquivo(s) importado(s).`)
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function updateScopeRules(patch: {
    allowExternalTargets?: boolean
    allowedTargets?: ScopeRuleDto[]
    blockedTargets?: ScopeRuleDto[]
  }): Promise<void> {
    try {
      await cyberlabFetch(serverTarget(), "/api/cyberlab/scope", {
        method: "PUT",
        body: JSON.stringify(patch),
      })
      setNotice("Escopo do projeto atualizado com sucesso.")
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function verifyEvidenceCustody(evidenceId: string): Promise<void> {
    try {
      const res = await cyberlabFetch<{ valid: boolean; expectedSha256: string; computedSha256: string }>(
        serverTarget(),
        "/api/cyberlab/evidence/verify",
        { method: "POST", body: JSON.stringify({ evidenceId }) },
      )
      if (res.valid) {
        setNotice(`Integridade SHA-256 ÍNTEGRA (${res.computedSha256.slice(0, 20)}…).`)
      } else {
        setError(`ALERTA DE ADULTERAÇÃO: esperado ${res.expectedSha256}, calculado ${res.computedSha256}`)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function inspectEvidenceById(evidenceId: string): Promise<void> {
    try {
      const res = await cyberlabFetch<ReadEvidenceDto>(serverTarget(), "/api/cyberlab/evidence/read", {
        method: "POST",
        body: JSON.stringify({ evidenceId }),
      })
      setBackend("inspectedEvidence", reconcile(res))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function createManualFinding(): Promise<void> {
    const d = drafts["scope-governance"]
    if (!d.findingTitle.trim() || !d.findingDescription.trim()) {
      setError("Preencha o título e a descrição técnica do Finding.")
      return
    }
    const assets = d.findingAssetsText
      .split(/[\r\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    try {
      const created = await cyberlabFetch<FindingDto>(serverTarget(), "/api/cyberlab/findings", {
        method: "POST",
        body: JSON.stringify({
          title: d.findingTitle.trim(),
          description: d.findingDescription.trim(),
          severity: d.findingSeverity,
          confidence: Math.min(1, Math.max(0, Number(d.findingConfidence) || 0.85)),
          evidenceIds: d.findingEvidenceIds,
          affectedAssets: assets.length > 0 ? assets : ["workspace"],
          proposedRemediation: d.findingRemediation.trim() || undefined,
        }),
      })
      recordHistoryEntry("scope-governance", {
        id: `find-${Date.now()}`,
        toolId: "scope-governance",
        timestamp: new Date().toISOString(),
        targetSummary: `Finding [${created.severity.toUpperCase()}] ${created.title}`,
        status: "succeeded",
        evidenceIds: created.evidenceIds,
        summaryText: `Finding registrado (${created.findingId.slice(0, 10)})`,
        outputText: JSON.stringify(created, null, 2),
        draftSnapshot: JSON.parse(JSON.stringify(d)) as Record<string, unknown>,
      })
      updateDraft("scope-governance", (prev) => ({
        ...prev,
        findingTitle: "",
        findingDescription: "",
        findingRemediation: "",
      }))
      setNotice(`Finding "${created.title}" registrado com sucesso.`)
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function reviewFindingDecision(
    findingId: string,
    decision: "confirmed" | "rejected" | "needs_more_evidence",
  ): Promise<void> {
    try {
      await cyberlabFetch(serverTarget(), "/api/cyberlab/findings/review", {
        method: "POST",
        body: JSON.stringify({
          findingId,
          reviewedBy: "manual-workbench-analyst",
          decision,
        }),
      })
      setNotice(`Finding revisado como "${decision}".`)
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function generateReportMarkdown(): Promise<void> {
    try {
      const res = await cyberlabFetch<{ markdown: string }>(serverTarget(), "/api/cyberlab/report")
      setBackend("reportMarkdown", res.markdown)
      recordHistoryEntry("scope-governance", {
        id: `rep-${Date.now()}`,
        toolId: "scope-governance",
        timestamp: new Date().toISOString(),
        targetSummary: "Relatório Técnico Markdown (.md)",
        status: "succeeded",
        evidenceIds: [],
        summaryText: `Relatório gerado (${res.markdown.length} caracteres)`,
        outputText: res.markdown,
        draftSnapshot: JSON.parse(JSON.stringify(drafts["scope-governance"])) as Record<string, unknown>,
      })
      setNotice("Relatório Markdown gerado com referências SHA-256.")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function loadFourCdiPreset(): Promise<void> {
    try {
      const res = await cyberlabFetch<PartnersOverviewDto>(serverTarget(), "/api/cyberlab/partners/manage", {
        method: "POST",
        body: JSON.stringify({ operation: "preset_4" }),
      })
      setBackend("partners", reconcile(res))
      setNotice("Preset dos 4 CDIs (Kairós 8788, Naia 8789, Salem 8790, Nova 8791) ativado!")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function manageCdiSecret(operation: "generate" | "set" | "reveal"): Promise<void> {
    try {
      const customSecret = drafts["cdi-hub"].customSecretInput.trim()
      const res = await cyberlabFetch<{ sharedSecret: string; cyberlabCallbackUrl: string }>(
        serverTarget(),
        "/api/cyberlab/partners/secret",
        {
          method: "POST",
          body: JSON.stringify({
            operation,
            customSecret: operation === "set" ? customSecret : undefined,
          }),
        },
      )
      setBackend("revealedSecret", res.sharedSecret)
      setNotice(
        operation === "reveal"
          ? "Segredo compartilhado exibido abaixo."
          : "CYBERLAB_PARTNER_SECRET atualizado com sucesso!",
      )
      await refreshBackend()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  function attachToComposer(title: string, textContent: string, filename = "cyberlab-evidencia.txt"): void {
    const formatted = `# ${title}\n${textContent}`
    if (activeComposer) {
      const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, "-")
      const file = new File([formatted], safeName, { type: "text/plain" })
      activeComposer.addAttachments([file])
      activeComposer.restoreFocus()
      setNotice(`Resultado anexado na caixa de diálogo (${safeName}).`)
      return
    }
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(formatted)
      setNotice("Resultado copiado para a área de transferência (abra uma sessão para anexar direto).")
    }
  }

  onMount(() => {
    void refreshBackend()
    const timer = window.setInterval(() => {
      if (ui.open) void refreshBackend()
    }, 8000)
    onCleanup(() => window.clearInterval(timer))
  })

  createEffect(() => {
    // Refresh whenever active project directory changes while workbench is open
    const _dir = resolvedDirectory()
    if (ui.open && _dir !== undefined) {
      void refreshBackend()
    }
  })

  return {
    ui,
    drafts,
    histories,
    backend,
    resolvedDirectory,
    registerComposer,
    selectSuite,
    selectSuiteFunction,
    selectSuiteEngine,
    setHistoryScope,
    sendUrlAcrossWebSuite,
    sendTextToDecoder,
    selectTool,
    toggleWorkbench,
    setLayoutMode,
    setSplitWidthPct,
    setShowHistoryColumn,
    setDirectoryOverride,
    updateDraft,
    resetToolDraft,
    deleteHistoryEntry,
    clearToolHistory,
    restoreHistoryDraft,
    refreshBackend,
    runCapabilityTool,
    approvePendingExecution,
    cancelExecution,
    controlProxy,
    downloadProxyRootCaCert,
    persistProxyCapture,
    sendProxyCaptureToRepeater,
    sendProxyCaptureToIntruder,
    dispatchCdiMission,
    ingestManualExternal,
    syncExternalInbox,
    updateScopeRules,
    verifyEvidenceCustody,
    inspectEvidenceById,
    createManualFinding,
    reviewFindingDecision,
    generateReportMarkdown,
    loadFourCdiPreset,
    manageCdiSecret,
    attachToComposer,
    setNotice,
    setError,
    selectHistoryItem(toolId: ManualToolId, entryId: string) {
      setUi("selectedHistoryByTool", toolId, entryId)
    },
  }
}

export type CyberLabWorkbenchService = ReturnType<typeof createWorkbenchService>

const CyberLabWorkbenchContext = createContext<CyberLabWorkbenchService>()

export function CyberLabWorkbenchProvider(props: ParentProps) {
  const service = createWorkbenchService()
  return <CyberLabWorkbenchContext.Provider value={service}>{props.children}</CyberLabWorkbenchContext.Provider>
}

export function useCyberLabWorkbench(): CyberLabWorkbenchService | undefined {
  return useContext(CyberLabWorkbenchContext)
}
