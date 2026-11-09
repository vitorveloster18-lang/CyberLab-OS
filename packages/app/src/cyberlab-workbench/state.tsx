import {
  batch,
  createContext,
  createEffect,
  createMemo,
  onCleanup,
  onMount,
  useContext,
  type ParentProps,
} from "solid-js"
import { createStore, reconcile } from "solid-js/store"
import type { ComposerModel } from "@/composer/model"
import { ServerConnection, useServers } from "@/runtime/server/registry"
import { useCurrentRoute } from "@/shell/state/layout"
import { useTabs } from "@/shell/tabs/tabs"
import { cyberlabFetch, type CyberLabServerTarget } from "./api"
import type {
  ApprovalDto,
  ArsenalLaunchResultDto,
  ArsenalLiveRunDto,
  ArsenalOverviewDto,
  ArsenalRuntimePrefDto,
  ArsenalSlotKindDto,
  ArsenalSlotStatusDto,
  CenterViewMode,
  EvidenceDto,
  FindingDto,
  LeftSidebarTab,
  PartnersOverviewDto,
  ProjectsAndLabsOverviewDto,
  ProxyBrowserLaunchResultDto,
  ReadEvidenceDto,
  ScopeDto,
  VaultNoteDocumentDto,
  VaultOverviewDto,
  WorkspaceFileEntryDto,
  WorkspaceFilePreviewDto,
  WorkspaceFilesListDto,
  WorkspaceStatusDto,
} from "./types"

const UI_STORAGE_KEY = "cyberlab.v5.antigravity.ui"

interface StoredUiPrefs {
  open: boolean
  topControlsOpen: boolean
  vaultOpen: boolean
  vaultActiveNotePath: string
  leftSidebarOpen: boolean
  leftSidebarTab: LeftSidebarTab
  leftSidebarWidth: number
  rightAgentOpen: boolean
  rightAgentWidth: number
  centerView: CenterViewMode
  activeSlotId: string
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

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const res = String(reader.result ?? "")
      const idx = res.indexOf(",")
      resolve(idx >= 0 ? res.slice(idx + 1) : res)
    }
    reader.onerror = () => reject(reader.error ?? new Error("Falha ao ler arquivo"))
    reader.readAsDataURL(file)
  })
}

function createWorkbenchService() {
  const servers = useServers()
  const tabs = useTabs()
  const currentRoute = useCurrentRoute()
  const saved = safeReadJson<Partial<StoredUiPrefs>>(UI_STORAGE_KEY, {})

  const [ui, setUi] = createStore<{
    open: boolean
    topControlsOpen: boolean
    vaultOpen: boolean
    vaultActiveNotePath: string
    leftSidebarOpen: boolean
    leftSidebarTab: LeftSidebarTab
    leftSidebarWidth: number
    rightAgentOpen: boolean
    rightAgentWidth: number
    centerView: CenterViewMode
    activeSlotId: string
    slotSearch: string
    categoryFilter: string
    cliTargetBySlot: Record<string, string>
    cliArgsBySlot: Record<string, string>
    cliRuntimeBySlot: Record<string, "auto" | "windows" | "wsl" | "linux_mac">
    selectedRunIdBySlot: Record<string, string>
    iframeReloadNonce: number
    currentFilesDir: string
    directoryOverride: string
    busy: boolean
    probing: boolean
    notice: string
    error: string
  }>({
    open: Boolean(saved.open),
    topControlsOpen: saved.topControlsOpen !== false,
    vaultOpen: Boolean(saved.vaultOpen),
    vaultActiveNotePath: saved.vaultActiveNotePath || "00-Indice-CyberLab.md",
    leftSidebarOpen: saved.leftSidebarOpen !== false,
    leftSidebarTab: saved.leftSidebarTab === "files" ? "files" : "slots",
    leftSidebarWidth:
      typeof saved.leftSidebarWidth === "number"
        ? Math.min(440, Math.max(210, saved.leftSidebarWidth))
        : 278,
    rightAgentOpen: saved.rightAgentOpen !== false,
    rightAgentWidth:
      typeof saved.rightAgentWidth === "number"
        ? Math.min(620, Math.max(300, saved.rightAgentWidth))
        : 388,
    centerView: saved.centerView ?? "tool",
    activeSlotId: saved.activeSlotId || "burp-suite",
    slotSearch: "",
    categoryFilter: "all",
    cliTargetBySlot: {},
    cliArgsBySlot: {},
    cliRuntimeBySlot: {},
    selectedRunIdBySlot: {},
    iframeReloadNonce: 1,
    currentFilesDir: ".",
    directoryOverride: typeof saved.directoryOverride === "string" ? saved.directoryOverride : "",
    busy: false,
    probing: false,
    notice: "",
    error: "",
  })

  const [backend, setBackend] = createStore<{
    loading: boolean
    status: WorkspaceStatusDto | null
    arsenal: ArsenalOverviewDto | null
    vault: VaultOverviewDto | null
    activeVaultNote: VaultNoteDocumentDto | null
    files: WorkspaceFileEntryDto[]
    filePreview: WorkspaceFilePreviewDto | null
    approvals: ApprovalDto[]
    evidence: EvidenceDto[]
    inspectedEvidence: ReadEvidenceDto | null
    findings: FindingDto[]
    partners: PartnersOverviewDto | null
    projectsAndLabs: ProjectsAndLabsOverviewDto | null
    lastBrowserLaunch: ProxyBrowserLaunchResultDto | null
    lastCdiDispatchSummary: string
    revealedSecret: string
    reportMarkdown: string
  }>({
    loading: false,
    status: null,
    arsenal: null,
    vault: null,
    activeVaultNote: null,
    files: [],
    filePreview: null,
    approvals: [],
    evidence: [],
    inspectedEvidence: null,
    findings: [],
    partners: null,
    projectsAndLabs: null,
    lastBrowserLaunch: null,
    lastCdiDispatchSummary: "",
    revealedSecret: "",
    reportMarkdown: "",
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
      topControlsOpen: ui.topControlsOpen,
      vaultOpen: ui.vaultOpen,
      vaultActiveNotePath: ui.vaultActiveNotePath,
      leftSidebarOpen: ui.leftSidebarOpen,
      leftSidebarTab: ui.leftSidebarTab,
      leftSidebarWidth: ui.leftSidebarWidth,
      rightAgentOpen: ui.rightAgentOpen,
      rightAgentWidth: ui.rightAgentWidth,
      centerView: ui.centerView,
      activeSlotId: ui.activeSlotId,
      directoryOverride: ui.directoryOverride,
    } satisfies StoredUiPrefs)
  }

  const resolvedDirectory = createMemo(() => {
    if (ui.directoryOverride.trim()) return ui.directoryOverride.trim()
    const route = currentRoute()
    if (route.type === "draft") {
      const tab = tabs.store.find(
        (t): t is Extract<typeof t, { type: "draft" }> => t.type === "draft" && t.draftID === route.draftID,
      )
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

  const activeSlot = createMemo<ArsenalSlotStatusDto | null>(() => {
    const slots = backend.arsenal?.slots ?? []
    return slots.find((s) => s.slotId === ui.activeSlotId) ?? slots[0] ?? null
  })

  const activeSlotRuns = createMemo<ArsenalLiveRunDto[]>(() => {
    const slot = activeSlot()
    if (!slot) return []
    return (backend.arsenal?.runs ?? []).filter((r) => r.slotId === slot.slotId)
  })

  const selectedRunForActiveSlot = createMemo<ArsenalLiveRunDto | null>(() => {
    const slot = activeSlot()
    const runs = activeSlotRuns()
    if (!slot || runs.length === 0) return null
    const chosenId = ui.selectedRunIdBySlot[slot.slotId]
    return (chosenId ? runs.find((r) => r.runId === chosenId) : undefined) ?? runs[0] ?? null
  })

  const hasRunningJobs = createMemo(() =>
    Boolean(backend.arsenal?.runs?.some((r) => r.status === "running")),
  )

  async function refreshArsenalOnly(forceProbe = false): Promise<void> {
    if (forceProbe) setUi("probing", true)
    try {
      const target = serverTarget()
      const data = await cyberlabFetch<ArsenalOverviewDto>(
        target,
        forceProbe ? "/api/cyberlab/arsenal/probe" : "/api/cyberlab/arsenal",
        forceProbe ? { method: "POST", body: "{}" } : undefined,
      )
      setBackend("arsenal", reconcile(data))
      if (forceProbe) {
        const installedCount = data.slots.filter((s) => s.installed).length
        const winCount = data.slots.filter((s) => Boolean(s.windowsPath)).length
        const wslCount = data.slots.filter((s) => Boolean(s.wslPath)).length
        const nowStr = new Date().toLocaleTimeString("pt-BR")
        setNotice(
          `[${nowStr}] Varredura concluída: ${installedCount} de ${data.slots.length} slots prontos (${winCount} Windows · ${wslCount} Kali WSL2).`,
        )
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      if (forceProbe) setUi("probing", false)
    }
  }

  async function browseFiles(subpath = ui.currentFilesDir): Promise<void> {
    try {
      const res = await cyberlabFetch<WorkspaceFilesListDto>(serverTarget(), "/api/cyberlab/files/list", {
        method: "POST",
        body: JSON.stringify({ subpath }),
      })
      batch(() => {
        setUi("currentFilesDir", res.currentDir)
        setBackend("files", reconcile(res.entries))
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function previewFile(relativePath: string): Promise<void> {
    try {
      const res = await cyberlabFetch<WorkspaceFilePreviewDto>(serverTarget(), "/api/cyberlab/files/preview", {
        method: "POST",
        body: JSON.stringify({ relativePath }),
      })
      setBackend("filePreview", res)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function refreshAll(): Promise<void> {
    setBackend("loading", true)
    try {
      const target = serverTarget()
      const [status, arsenal, filesRes, approvals, evidence, findings, partners, projectsAndLabs] =
        await Promise.all([
          cyberlabFetch<WorkspaceStatusDto>(target, "/api/cyberlab/status").catch(() => null),
          cyberlabFetch<ArsenalOverviewDto>(target, "/api/cyberlab/arsenal").catch(() => null),
          cyberlabFetch<WorkspaceFilesListDto>(target, "/api/cyberlab/files/list", {
            method: "POST",
            body: JSON.stringify({ subpath: ui.currentFilesDir || "." }),
          }).catch(() => null),
          cyberlabFetch<ApprovalDto[]>(target, "/api/cyberlab/approvals").catch(() => []),
          cyberlabFetch<EvidenceDto[]>(target, "/api/cyberlab/evidence").catch(() => []),
          cyberlabFetch<FindingDto[]>(target, "/api/cyberlab/findings").catch(() => []),
          cyberlabFetch<PartnersOverviewDto>(target, "/api/cyberlab/partners").catch(() => null),
          cyberlabFetch<ProjectsAndLabsOverviewDto>(target, "/api/cyberlab/projects").catch(() => null),
        ])

      batch(() => {
        if (status) setBackend("status", reconcile(status))
        if (arsenal) {
          setBackend("arsenal", reconcile(arsenal))
          // Seed default args for CLI slots on first load
          for (const slot of arsenal.slots) {
            if (!ui.cliArgsBySlot[slot.slotId] && slot.presets[0]?.argsTemplate) {
              setUi("cliArgsBySlot", slot.slotId, slot.presets[0].argsTemplate)
            }
          }
        }
        if (filesRes) {
          setUi("currentFilesDir", filesRes.currentDir)
          setBackend("files", reconcile(filesRes.entries))
        }
        setBackend("approvals", reconcile(approvals))
        setBackend("evidence", reconcile(evidence))
        setBackend("findings", reconcile(findings))
        if (partners) setBackend("partners", reconcile(partners))
        if (projectsAndLabs) setBackend("projectsAndLabs", reconcile(projectsAndLabs))
      })
    } finally {
      setBackend("loading", false)
    }
  }

  function openWorkspace(options?: { slotId?: string; view?: CenterViewMode; leftTab?: LeftSidebarTab }) {
    batch(() => {
      setUi("open", true)
      if (options?.slotId) {
        setUi("activeSlotId", options.slotId)
        setUi("centerView", "tool")
      }
      if (options?.view) setUi("centerView", options.view)
      if (options?.leftTab) {
        setUi("leftSidebarOpen", true)
        setUi("leftSidebarTab", options.leftTab)
      }
    })
    persistUi()
    void refreshAll()
  }

  function toggleWorkbench(next?: boolean) {
    setUi("open", next ?? !ui.open)
    persistUi()
    if (ui.open) void refreshAll()
  }

  function toggleLeftSidebar(next?: boolean) {
    setUi("leftSidebarOpen", next ?? !ui.leftSidebarOpen)
    persistUi()
  }

  function setLeftSidebarTab(tab: LeftSidebarTab) {
    batch(() => {
      setUi("leftSidebarOpen", true)
      setUi("leftSidebarTab", tab)
    })
    persistUi()
  }

  function setLeftSidebarWidth(width: number) {
    setUi("leftSidebarWidth", Math.min(440, Math.max(210, Math.round(width))))
    persistUi()
  }

  function toggleTopControls(next?: boolean) {
    setUi("topControlsOpen", next ?? !ui.topControlsOpen)
    persistUi()
  }

  function toggleRightAgent(next?: boolean) {
    setUi("rightAgentOpen", next ?? !ui.rightAgentOpen)
    persistUi()
  }

  function setRightAgentWidth(width: number) {
    setUi("rightAgentWidth", Math.min(620, Math.max(300, Math.round(width))))
    persistUi()
  }

  function setCenterView(view: CenterViewMode) {
    setUi("centerView", view)
    persistUi()
  }

  function selectSlot(slotId: string) {
    batch(() => {
      setUi("open", true)
      setUi("activeSlotId", slotId)
      setUi("centerView", "tool")
      const slot = backend.arsenal?.slots.find((s) => s.slotId === slotId)
      if (slot && !ui.cliArgsBySlot[slotId] && slot.presets[0]?.argsTemplate) {
        setUi("cliArgsBySlot", slotId, slot.presets[0].argsTemplate)
      }
      if (slot) {
        if (slot.embedUrl) {
          setUi("topControlsOpen", false)
        } else if (!slot.installed || slot.kind === "cli_runner") {
          setUi("topControlsOpen", true)
        }
      }
    })
    persistUi()
  }

  async function launchSlot(params: {
    slotId: string
    action: "run_cli" | "launch_desktop" | "start_web" | "stop_web" | "install_tool"
    target?: string
    rawArgs?: string
    runtimeOverride?: "windows" | "wsl" | "linux_mac"
  }): Promise<void> {
    setUi("busy", true)
    try {
      const res = await cyberlabFetch<ArsenalLaunchResultDto>(serverTarget(), "/api/cyberlab/arsenal/launch", {
        method: "POST",
        body: JSON.stringify(params),
      })
      batch(() => {
        setBackend("arsenal", reconcile(res.overview))
        if (res.run) {
          setUi("selectedRunIdBySlot", params.slotId, res.run.runId)
        }
        if (res.embedUrl) {
          setUi("iframeReloadNonce", (n) => n + 1)
          setUi("topControlsOpen", false)
        } else if (params.action === "stop_web") {
          setUi("topControlsOpen", true)
        }
        if (res.ok) setNotice(res.message)
        else setError(res.message)
      })
      persistUi()
      void browseFiles(ui.currentFilesDir)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function stopRun(runId: string): Promise<void> {
    try {
      await cyberlabFetch<{ stopped: boolean }>(serverTarget(), "/api/cyberlab/arsenal/stop", {
        method: "POST",
        body: JSON.stringify({ runId }),
      })
      setNotice(`Execução ${runId} interrompida.`)
      await refreshArsenalOnly(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function configureArsenal(patch: {
    toolsRootDir?: string
    preferredWslDistro?: string
    enforceScopeOnCliRuns?: boolean
    slotId?: string
    slotOverride?: {
      customExecutablePath?: string
      customEmbedUrl?: string
      preferredRuntime?: ArsenalRuntimePrefDto
      defaultArgs?: string
      companionProxyPort?: number
    }
  }): Promise<void> {
    setUi("busy", true)
    try {
      const updated = await cyberlabFetch<ArsenalOverviewDto>(serverTarget(), "/api/cyberlab/arsenal/config", {
        method: "PUT",
        body: JSON.stringify(patch),
      })
      setBackend("arsenal", reconcile(updated))
      setNotice("Configuração do Arsenal salva com sucesso.")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function upsertCustomSlot(input: {
    slotId?: string
    name: string
    shortLabel?: string
    kind: ArsenalSlotKindDto
    tagline?: string
    description?: string
    executableOrUrl: string
    preferredRuntime?: ArsenalRuntimePrefDto
    companionProxyPort?: number
    defaultArgsTemplate?: string
  }): Promise<void> {
    setUi("busy", true)
    try {
      const updated = await cyberlabFetch<ArsenalOverviewDto>(serverTarget(), "/api/cyberlab/arsenal/custom", {
        method: "POST",
        body: JSON.stringify(input),
      })
      const newest = updated.slots.filter((s) => s.isCustom).at(-1)
      batch(() => {
        setBackend("arsenal", reconcile(updated))
        if (newest) {
          setUi("activeSlotId", newest.slotId)
          setUi("centerView", "tool")
        }
        setNotice(`Slot personalizado "${input.name}" salvo no Arsenal!`)
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function removeCustomSlot(slotId: string): Promise<void> {
    setUi("busy", true)
    try {
      const updated = await cyberlabFetch<ArsenalOverviewDto>(
        serverTarget(),
        "/api/cyberlab/arsenal/custom/remove",
        {
          method: "POST",
          body: JSON.stringify({ slotId, confirm: true }),
        },
      )
      batch(() => {
        setBackend("arsenal", reconcile(updated))
        if (ui.activeSlotId === slotId) {
          setUi("activeSlotId", updated.slots[0]?.slotId ?? "burp-suite")
        }
        setNotice("Slot personalizado removido.")
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  /** Remove slots personalizados fantasmas (sem binário) e duplicatas — nunca remove slots oficiais. */
  async function pruneBrokenCustomSlots(): Promise<void> {
    setUi("busy", true)
    try {
      const updated = await cyberlabFetch<ArsenalOverviewDto>(
        serverTarget(),
        "/api/cyberlab/arsenal/prune",
        {
          method: "POST",
          // v6.7: o clique do operador no botão da interface É a confirmação exigida
          // pela guarda de ações destrutivas (o agente não tem como ter este token).
          body: JSON.stringify({ removeGhosts: true, removeDuplicates: true, confirm: true }),
        },
      )
      batch(() => {
        setBackend("arsenal", reconcile(updated))
        setNotice(
          updated.health && updated.health.length > 0
            ? `Limpeza concluída — ainda restam ${updated.health.length} aviso(s).`
            : "Limpeza concluída — nenhum slot personalizado quebrado restante.",
        )
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function launchProxyBrowser(params: {
    proxyPort?: number
    startUrl?: string
    preferredBrowserId?: string
  }): Promise<void> {
    setUi("busy", true)
    try {
      const res = await cyberlabFetch<ProxyBrowserLaunchResultDto>(
        serverTarget(),
        "/api/cyberlab/arsenal/browser",
        {
          method: "POST",
          body: JSON.stringify(params),
        },
      )
      setBackend("lastBrowserLaunch", res)
      // Abriu o navegador mas não há proxy ouvindo: é o caso que gerava o
      // ERR_PROXY_CONNECTION_FAILED sem explicação. Mostra como erro para o
      // diagnóstico não passar despercebido no meio dos avisos.
      if (res.launched && res.proxyReachable !== false) setNotice(res.message)
      else setError(res.message)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function persistOutputToEvidence(title: string, content: string, slotId?: string): Promise<void> {
    if (!content.trim()) {
      setError("Não há conteúdo para registrar em custódia SHA-256.")
      return
    }
    setUi("busy", true)
    try {
      const savedEv = await cyberlabFetch<{ evidenceId: string; sha256: string }>(
        serverTarget(),
        "/api/cyberlab/arsenal/persist",
        {
          method: "POST",
          body: JSON.stringify({ title, content, ...(slotId ? { slotId } : {}) }),
        },
      )
      setNotice(`Registrado em Custódia SHA-256 (${savedEv.evidenceId} · ${savedEv.sha256.slice(0, 14)}…).`)
      await refreshAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function uploadExternalFile(file: File): Promise<void> {
    setUi("busy", true)
    try {
      const contentBase64 = await fileToBase64(file)
      const res = await cyberlabFetch<{ relativePath: string }>(
        serverTarget(),
        "/api/cyberlab/artifacts/upload",
        {
          method: "POST",
          body: JSON.stringify({ fileName: file.name, contentBase64 }),
        },
      )
      setNotice(`Arquivo "${file.name}" importado em ${res.relativePath}!`)
      await browseFiles(".cyberlab/imports")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function importScope(params: {
    rawInput: string
    platformHint?: "custom" | "hackerone" | "bugcrowd" | "intigriti" | "yeswehack"
    researcherHandle?: string
    headerName?: string
    headerValue?: string
    maxRequestsPerSecond?: number
  }): Promise<void> {
    setUi("busy", true)
    try {
      const res = await cyberlabFetch<{
        scope: ScopeDto
        detectedFormat: string
        importedAllowedCount: number
        importedBlockedCount: number
      }>(serverTarget(), "/api/cyberlab/scope/import", {
        method: "POST",
        body: JSON.stringify(params),
      })
      setNotice(
        `Escopo importado (${res.detectedFormat}): +${res.importedAllowedCount} em escopo, +${res.importedBlockedCount} exclusões.`,
      )
      await refreshAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function updateScope(patch: Partial<ScopeDto>): Promise<void> {
    setUi("busy", true)
    try {
      await cyberlabFetch<ScopeDto>(serverTarget(), "/api/cyberlab/scope", {
        method: "PUT",
        body: JSON.stringify(patch),
      })
      setNotice("Escopo do projeto atualizado.")
      await refreshAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function controlTrainingLab(action: "start" | "reset" | "stop", labId: string): Promise<void> {
    setUi("busy", true)
    try {
      const lab = await cyberlabFetch<{ title: string; baseUrl?: string; workspaceRoot: string }>(
        serverTarget(),
        "/api/cyberlab/labs/control",
        {
          method: "POST",
          // v6.7: o clique do operador no botão da interface É a confirmação exigida
          // pela guarda de ações destrutivas (reset/stop são destrutivos; start não é).
          body: JSON.stringify({
            action,
            labId,
            setActive: action === "start",
            ...(action === "start" ? {} : { confirm: true }),
          }),
        },
      )
      if (action === "start") {
        setUi("directoryOverride", lab.workspaceRoot)
        persistUi()
      }
      setNotice(
        action === "start"
          ? `Lab "${lab.title}" ativo${lab.baseUrl ? ` em ${lab.baseUrl}` : ""}!`
          : `Lab "${lab.title}" (${action}).`,
      )
      await refreshAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function manageCdiPreset4(baseHost = "http://127.0.0.1"): Promise<void> {
    setUi("busy", true)
    try {
      const ov = await cyberlabFetch<PartnersOverviewDto>(serverTarget(), "/api/cyberlab/partners/manage", {
        method: "POST",
        body: JSON.stringify({ operation: "preset_4", baseHost }),
      })
      setBackend("partners", reconcile(ov))
      setNotice("Preset dos 4 CDIs carregado (Kairós:8788, Naia:8789, Salem:8790, Nova:8791)!")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function manageCdiSecret(
    operation: "reveal" | "generate" | "custom",
    customSecret?: string,
  ): Promise<void> {
    setUi("busy", true)
    try {
      const res = await cyberlabFetch<{ sharedSecret: string; cyberlabCallbackUrl: string }>(
        serverTarget(),
        "/api/cyberlab/partners/secret",
        {
          method: "POST",
          body: JSON.stringify({
            operation,
            ...(customSecret ? { customSecret } : {}),
          }),
        },
      )
      setBackend("revealedSecret", res.sharedSecret)
      setNotice(operation === "reveal" ? "Segredo HMAC exibido abaixo." : "CYBERLAB_PARTNER_SECRET atualizado!")
      await refreshAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function dispatchToCdis(params: {
    partnerIds: string[]
    objective: string
    contextText?: string
  }): Promise<void> {
    setUi("busy", true)
    try {
      const res = await cyberlabFetch<{
        succeededCount?: number
        totalDispatched?: number
        results?: Array<{ partnerId: string; ok: boolean; error?: string; outcome?: { result?: { summary?: string } } }>
      }>(serverTarget(), "/api/cyberlab/partners/dispatch", {
        method: "POST",
        body: JSON.stringify(params),
      })
      const lines = (res.results ?? []).map(
        (r) => `[${r.partnerId}] ${r.ok ? r.outcome?.result?.summary ?? "OK" : `ERRO: ${r.error ?? "falha"}`}`,
      )
      setBackend("lastCdiDispatchSummary", lines.join("\n\n"))
      setNotice(`Disparo CDI concluído (${res.succeededCount ?? 0}/${res.totalDispatched ?? params.partnerIds.length}).`)
      await refreshAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function readEvidence(evidenceId: string): Promise<void> {
    try {
      const data = await cyberlabFetch<ReadEvidenceDto>(serverTarget(), "/api/cyberlab/evidence/read", {
        method: "POST",
        body: JSON.stringify({ evidenceId }),
      })
      setBackend("inspectedEvidence", data)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function verifyEvidence(evidenceId: string): Promise<void> {
    try {
      const res = await cyberlabFetch<{ valid: boolean; expectedSha256: string }>(
        serverTarget(),
        "/api/cyberlab/evidence/verify",
        {
          method: "POST",
          body: JSON.stringify({ evidenceId }),
        },
      )
      if (res.valid) setNotice(`Integridade SHA-256 ÍNTEGRA (${res.expectedSha256.slice(0, 16)}…).`)
      else setError(`ALERTA: Falha na verificação SHA-256 de ${evidenceId}!`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function createFinding(input: {
    title: string
    description: string
    severity: "info" | "low" | "medium" | "high" | "critical"
    evidenceIds: string[]
    affectedAssets: string[]
    proposedRemediation?: string
  }): Promise<void> {
    setUi("busy", true)
    try {
      await cyberlabFetch(serverTarget(), "/api/cyberlab/findings", {
        method: "POST",
        body: JSON.stringify(input),
      })
      setNotice(`Finding "${input.title}" registrado!`)
      await refreshAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  async function generateReport(): Promise<void> {
    setUi("busy", true)
    try {
      const res = await cyberlabFetch<{ markdown: string }>(serverTarget(), "/api/cyberlab/report")
      setBackend("reportMarkdown", res.markdown)
      setNotice("Relatório Markdown gerado com hashes SHA-256!")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setUi("busy", false)
    }
  }

  function sendToAgent(title: string, textContent: string, filename = "arsenal-output.txt"): void {
    // Ensure Right Agent Panel is expanded so the user sees the attachment right away!
    if (!ui.rightAgentOpen) {
      setUi("rightAgentOpen", true)
      persistUi()
    }
    const formatted = `# ${title}\n${textContent}`
    if (activeComposer) {
      const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, "-")
      const file = new File([formatted], safeName, { type: "text/plain" })
      activeComposer.addAttachments([file])
      activeComposer.restoreFocus()
      setNotice(`Anexado ao Agente OpenCode na barra direita (${safeName}).`)
      return
    }
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(formatted)
      setNotice("Copiado para a área de transferência — cole na conversa com o Agente OpenCode à direita.")
    }
  }

  async function refreshVault(openDefaultIfNone = false): Promise<VaultOverviewDto | null> {
    try {
      const overview = await cyberlabFetch<VaultOverviewDto>(serverTarget(), "/api/cyberlab/vault")
      setBackend("vault", reconcile(overview))
      if (openDefaultIfNone && (!backend.activeVaultNote || !overview.notes.some((n) => n.relativePath === backend.activeVaultNote?.relativePath))) {
        const candidate =
          overview.notes.find((n) => n.relativePath === ui.vaultActiveNotePath)?.relativePath ??
          overview.notes[0]?.relativePath
        if (candidate) {
          await openVaultNote(candidate)
        }
      }
      return overview
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      return null
    }
  }

  async function openVaultNote(relativePathOrWikiTarget: string, autoCreateIfMissing = false): Promise<VaultNoteDocumentDto | null> {
    const raw = relativePathOrWikiTarget.trim()
    if (!raw) return null
    let targetPath = raw
    const existingList = backend.vault?.notes ?? []
    const normRawNoExt = raw.replace(/\\/g, "/").replace(/\.md$/i, "").toLowerCase()
    const matched = existingList.find((n) => {
      const relNoExt = n.relativePath.replace(/\.md$/i, "").toLowerCase()
      const baseNoExt = relNoExt.split("/").at(-1) ?? relNoExt
      return relNoExt === normRawNoExt || baseNoExt === normRawNoExt
    })
    if (matched) {
      targetPath = matched.relativePath
    } else if (!targetPath.toLowerCase().endsWith(".md")) {
      targetPath = `${targetPath}.md`
    }

    try {
      const doc = await cyberlabFetch<VaultNoteDocumentDto>(serverTarget(), "/api/cyberlab/vault/read", {
        method: "POST",
        body: JSON.stringify({ relativePath: targetPath }),
      })
      batch(() => {
        setBackend("activeVaultNote", reconcile(doc))
        setUi("vaultActiveNotePath", doc.relativePath)
      })
      persistUi()
      return doc
    } catch (err) {
      if (autoCreateIfMissing) {
        const baseTitle = targetPath.replace(/\.md$/i, "").split("/").at(-1) ?? targetPath
        return await saveVaultNote(
          targetPath,
          `# ${baseTitle}\n\n#notas\n\nRelacionado a [[00-Indice-CyberLab]].\n`,
        )
      }
      setError(err instanceof Error ? err.message : String(err))
      return null
    }
  }

  async function saveVaultNote(relativePath: string, content: string, silent = false): Promise<VaultNoteDocumentDto | null> {
    try {
      const res = await cyberlabFetch<{ note: VaultNoteDocumentDto; overview: VaultOverviewDto }>(
        serverTarget(),
        "/api/cyberlab/vault/write",
        {
          method: "POST",
          body: JSON.stringify({ relativePath, content }),
        },
      )
      batch(() => {
        setBackend("vault", reconcile(res.overview))
        setBackend("activeVaultNote", reconcile(res.note))
        setUi("vaultActiveNotePath", res.note.relativePath)
        if (!silent) setNotice(`Nota salva em vault/${res.note.relativePath}`)
      })
      persistUi()
      return res.note
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      return null
    }
  }

  async function deleteVaultNote(relativePath: string): Promise<void> {
    // v6.7: apagar nota não tem volta. A guarda exige `confirm` + `confirmPhrase`;
    // aqui quem confirma é o humano, numa caixa de diálogo, antes de a chamada sair.
    if (typeof window !== "undefined") {
      const ok = window.confirm(
        `Apagar a nota "${relativePath}"?\n\nNÃO HÁ LIXEIRA — o arquivo é removido do disco e sai do Obsidian.`,
      )
      if (!ok) return
    }
    try {
      const updated = await cyberlabFetch<VaultOverviewDto>(serverTarget(), "/api/cyberlab/vault/delete", {
        method: "POST",
        body: JSON.stringify({ relativePath, confirm: true, confirmPhrase: relativePath }),
      })
      batch(() => {
        setBackend("vault", reconcile(updated))
        if (backend.activeVaultNote?.relativePath === relativePath) {
          setBackend("activeVaultNote", null)
        }
        setNotice(`Nota "${relativePath}" removida do Vault.`)
      })
      const nextRel = updated.notes[0]?.relativePath
      if (nextRel) await openVaultNote(nextRel)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function configureVaultPath(customVaultRootDir?: string | null): Promise<void> {
    try {
      const updated = await cyberlabFetch<VaultOverviewDto>(serverTarget(), "/api/cyberlab/vault/config", {
        method: "PUT",
        body: JSON.stringify({ customVaultRootDir: customVaultRootDir?.trim() ? customVaultRootDir.trim() : null }),
      })
      setBackend("vault", reconcile(updated))
      setNotice(`Pasta do Vault configurada: ${updated.vaultRootDir}`)
      if (updated.notes[0]?.relativePath) {
        await openVaultNote(updated.notes[0].relativePath)
      } else {
        setBackend("activeVaultNote", null)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  function toggleVault(next?: boolean): void {
    const targetOpen = next ?? !ui.vaultOpen
    setUi("vaultOpen", targetOpen)
    persistUi()
    if (targetOpen) {
      void refreshVault(true)
    }
  }

  function injectCommandIntoCli(rawCommand: string, runNow = false): void {
    const firstLine = rawCommand
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l.length > 0 && !l.startsWith("#"))
    if (!firstLine) return

    const binToSlotMap: Record<string, string> = {
      ncat: "netcat-ncat",
      nc: "netcat-ncat",
      netcat: "netcat-ncat",
      dirsearch: "dirsearch",
      nuclei: "nuclei",
      ffuf: "ffuf",
      katana: "katana",
      httpx: "httpx",
      subfinder: "subfinder",
      nmap: "nmap",
      dalfox: "dalfox",
      sqlmap: "sqlmap",
      trivy: "trivy",
      semgrep: "semgrep",
      opengrep: "semgrep",
      betterleaks: "betterleaks",
      wpprobe: "wpprobe",
      keyhunter: "keyhunter",
      "gdb-gef": "gef",
      "atomic-operator": "atomic-operator",
      nxc: "netexec",
      netexec: "netexec",
    }

    const parts = firstLine.match(/^([a-zA-Z0-9._-]+)(?:\s+(.*))?$/)
    const leadBin = parts?.[1]?.toLowerCase() ?? ""
    const restArgs = parts?.[2]?.trim() ?? ""
    const mappedSlotId = binToSlotMap[leadBin]

    const curSlot = activeSlot()
    const targetSlotId =
      mappedSlotId ??
      (curSlot?.kind === "cli_runner" ? curSlot.slotId : "nuclei")
    const argsToSet = mappedSlotId ? restArgs : firstLine

    batch(() => {
      setUi("open", true)
      setUi("activeSlotId", targetSlotId)
      setUi("centerView", "tool")
      setUi("topControlsOpen", true)
      setUi("cliArgsBySlot", targetSlotId, argsToSet)
    })
    persistUi()

    if (runNow) {
      void launchSlot({
        slotId: targetSlotId,
        action: "run_cli",
        target: ui.cliTargetBySlot[targetSlotId] ?? "",
        rawArgs: argsToSet,
      })
    } else {
      setNotice(`Comando injetado no slot "${targetSlotId}" (${argsToSet || "sem argumentos"}).`)
    }
  }

  onMount(() => {
    void refreshAll()
    if (ui.vaultOpen) {
      void refreshVault(true)
    }
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.altKey && (ev.key === "n" || ev.key === "N")) {
        ev.preventDefault()
        toggleVault()
      }
    }
    window.addEventListener("keydown", onKeyDown)
    const fastPoll = window.setInterval(() => {
      if (ui.open && hasRunningJobs()) {
        void refreshArsenalOnly(false)
      }
    }, 1200)
    const slowPoll = window.setInterval(() => {
      if (ui.open) {
        void refreshArsenalOnly(false)
      }
    }, 8000)
    onCleanup(() => {
      window.removeEventListener("keydown", onKeyDown)
      window.clearInterval(fastPoll)
      window.clearInterval(slowPoll)
    })
  })

  createEffect(() => {
    const _dir = resolvedDirectory()
    if (_dir && ui.open) {
      void refreshAll()
      if (ui.vaultOpen) void refreshVault(true)
    }
  })

  return {
    ui,
    setUi,
    backend,
    activeSlot,
    activeSlotRuns,
    selectedRunForActiveSlot,
    hasRunningJobs,
    registerComposer,
    openWorkspace,
    toggleWorkbench,
    toggleTopControls,
    toggleVault,
    refreshVault,
    openVaultNote,
    saveVaultNote,
    deleteVaultNote,
    configureVaultPath,
    injectCommandIntoCli,
    toggleLeftSidebar,
    setLeftSidebarTab,
    setLeftSidebarWidth,
    toggleRightAgent,
    setRightAgentWidth,
    setCenterView,
    selectSlot,
    refreshAll,
    refreshArsenalOnly,
    browseFiles,
    previewFile,
    launchSlot,
    stopRun,
    configureArsenal,
    upsertCustomSlot,
    removeCustomSlot,
    pruneBrokenCustomSlots,
    launchProxyBrowser,
    persistOutputToEvidence,
    uploadExternalFile,
    importScope,
    updateScope,
    controlTrainingLab,
    manageCdiPreset4,
    manageCdiSecret,
    dispatchToCdis,
    readEvidence,
    verifyEvidence,
    createFinding,
    generateReport,
    sendToAgent,
    setNotice,
    setError,
  }
}

export type CyberLabWorkbenchService = ReturnType<typeof createWorkbenchService>

const CyberLabWorkbenchContext = createContext<CyberLabWorkbenchService>()

export function CyberLabWorkbenchProvider(props: ParentProps) {
  const service = createWorkbenchService()
  return (
    <CyberLabWorkbenchContext.Provider value={service}>
      {props.children}
    </CyberLabWorkbenchContext.Provider>
  )
}

export function useCyberLabWorkbench(): CyberLabWorkbenchService | undefined {
  return useContext(CyberLabWorkbenchContext)
}
