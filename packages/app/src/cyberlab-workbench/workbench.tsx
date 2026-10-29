import { createMemo, createSignal, For, Show } from "solid-js"
import { Icon } from "@opencode/ui/icon"
import { getSuiteAllToolIds, getSuiteMeta, getToolMeta } from "./catalog"
import { VerticalSuitesPickerDialog } from "./composer-bar"
import { useCyberLabWorkbench } from "./state"
import { ManualToolConfigForm } from "./tool-forms"
import type { ManualToolId, ToolHistoryEntry, ToolSuiteFunctionTab } from "./types"

const EXTERNAL_BINARY_TOOLS = new Set<ManualToolId>([
  "nuclei",
  "ffuf",
  "nmap",
  "tshark",
  "dalfox",
  "ghidra",
  "jadx",
  "yarax",
  "trivy",
  "keyhunter-cli",
])

interface EntropyBlockDto {
  offsetHex: string
  entropy: number
  classification: "null_padding" | "plaintext_or_code" | "structured_binary" | "compressed_or_encrypted"
}

function StructuredResultVisualizer(props: { outputText: string }) {
  const parsed = createMemo<Record<string, unknown> | null>(() => {
    const txt = props.outputText?.trim()
    if (!txt || !txt.startsWith("{")) return null
    try {
      const obj = JSON.parse(txt) as unknown
      return obj && typeof obj === "object" && !Array.isArray(obj) ? (obj as Record<string, unknown>) : null
    } catch {
      return null
    }
  })

  const entropyBlocks = createMemo<EntropyBlockDto[]>(() => {
    const obj = parsed()
    const prof = obj?.entropyProfile as Record<string, unknown> | undefined
    const blocks = prof?.buckets
    return Array.isArray(blocks) ? (blocks as EntropyBlockDto[]) : []
  })

  const tlsDeepAudit = createMemo<Record<string, unknown> | null>(() => {
    const obj = parsed()
    const da = obj?.deepAudit
    return da && typeof da === "object" ? (da as Record<string, unknown>) : null
  })

  const dfirTimeline = createMemo<Array<Record<string, unknown>>>(() => {
    const obj = parsed()
    const tl = obj?.incidentTimeline
    return Array.isArray(tl) ? (tl as Array<Record<string, unknown>>) : []
  })

  const keyHunterMatches = createMemo<Array<Record<string, unknown>>>(() => {
    const obj = parsed()
    if (obj?.tool !== "CyberLab Key Hunter") return []
    const m = obj?.matches
    return Array.isArray(m) ? (m as Array<Record<string, unknown>>) : []
  })

  const barColor = (cls: EntropyBlockDto["classification"]) => {
    switch (cls) {
      case "compressed_or_encrypted":
        return "bg-rose-500"
      case "structured_binary":
        return "bg-amber-500"
      case "plaintext_or_code":
        return "bg-sky-500"
      default:
        return "bg-emerald-500"
    }
  }

  return (
    <>
      <Show when={entropyBlocks().length > 0}>
        <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-2.5 flex flex-col gap-1.5">
          <div class="flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <strong class="text-v2-text-text-strong">
              Espectro Visual de Entropia de Shannon (Byte 0 → EOF · {entropyBlocks().length} faixas)
            </strong>
            <div class="flex flex-wrap items-center gap-2 text-[10px] text-v2-text-text-muted">
              <span class="inline-flex items-center gap-1"><span class="size-2 rounded-full bg-emerald-500" /> Padding/Zeros</span>
              <span class="inline-flex items-center gap-1"><span class="size-2 rounded-full bg-sky-500" /> Texto/Código</span>
              <span class="inline-flex items-center gap-1"><span class="size-2 rounded-full bg-amber-500" /> Binário Estruturado</span>
              <span class="inline-flex items-center gap-1"><span class="size-2 rounded-full bg-rose-500" /> Cifrado/Comprimido (&ge;7.2)</span>
            </div>
          </div>
          <div class="flex h-16 items-end gap-[1px] rounded bg-v2-background-bg-deep/70 p-1.5 overflow-hidden">
            <For each={entropyBlocks()}>
              {(blk) => (
                <div
                  title={`${blk.offsetHex} · Entropia ${blk.entropy.toFixed(2)}/8.00 (${blk.classification})`}
                  class={`flex-1 min-w-[2px] rounded-t-[1px] transition-opacity hover:opacity-80 ${barColor(blk.classification)}`}
                  style={{ height: `${Math.max(8, Math.round((blk.entropy / 8) * 100))}%` }}
                />
              )}
            </For>
          </div>
        </div>
      </Show>

      <Show when={tlsDeepAudit()}>
        {(() => {
          const da = () => tlsDeepAudit() ?? {}
          const grade = () => String(da().securityGrade ?? "?")
          const matrix = () =>
            Array.isArray(da().protocolSupportMatrix)
              ? (da().protocolSupportMatrix as Array<Record<string, unknown>>)
              : []
          return (
            <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-2.5 flex flex-wrap items-center justify-between gap-2 text-[11px]">
              <div class="flex items-center gap-2">
                <span class="rounded-md border border-emerald-500/50 bg-emerald-500/15 px-2 py-0.5 font-mono text-[13px] font-bold text-emerald-400">
                  Nota TLS: {grade()}
                </span>
                <span class="text-v2-text-text-muted">
                  Forward Secrecy: {da().forwardSecrecy ? "Sim (ECDHE/TLS1.3)" : "Ausente"} · AEAD:{" "}
                  {da().aeadAuthenticated ? "Sim" : "CBC/Stream"}
                </span>
              </div>
              <div class="flex flex-wrap items-center gap-1">
                <For each={matrix()}>
                  {(m) => (
                    <span
                      class={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${
                        m.supported
                          ? String(m.version) === "TLSv1" || String(m.version) === "TLSv1.1"
                            ? "border-red-500/40 bg-red-500/15 text-red-400"
                            : "border-emerald-500/40 bg-emerald-500/15 text-emerald-400"
                          : "border-v2-border-border-base bg-v2-background-bg-deep text-v2-text-text-muted"
                      }`}
                    >
                      {String(m.version)}: {m.supported ? "ON" : "OFF"}
                    </span>
                  )}
                </For>
              </div>
            </div>
          )
        })()}
      </Show>

      <Show when={dfirTimeline().length > 0}>
        <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-2.5 flex flex-col gap-1">
          <div class="text-[11px] font-medium text-v2-text-text-strong">
            Timeline Forense de Incidente ({dfirTimeline().length} alerta(s) correlacionado(s))
          </div>
          <div class="max-h-32 overflow-y-auto flex flex-col gap-1" data-scrollable>
            <For each={dfirTimeline().slice(0, 12)}>
              {(ev) => (
                <div class="flex items-center justify-between gap-2 rounded bg-v2-background-bg-deep/50 px-2 py-1 text-[11px]">
                  <span class="truncate text-v2-text-text-strong">
                    <strong class="uppercase text-amber-400">[{String(ev.level ?? ev.severity ?? "alert")}]</strong>{" "}
                    {String(ev.ruleTitle)} — {String(ev.rawLine ?? ev.summary ?? "")}
                  </span>
                  <span class="shrink-0 font-mono text-[10px] text-v2-text-text-muted">
                    #{String(ev.lineNumber ?? "")}
                  </span>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>

      <Show when={keyHunterMatches().length > 0}>
        <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-2.5 flex flex-col gap-1.5">
          <div class="flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <strong class="text-v2-text-text-strong">
              Key Hunter — {keyHunterMatches().length} Segredo(s) / Chave(s) Identificada(s) (Mascarados + SHA-256)
            </strong>
            <span class="text-[10px] text-v2-text-text-muted">
              Custódia automática: segredos ofuscados no log com receita KeyHacks somente-leitura
            </span>
          </div>
          <div class="max-h-44 overflow-y-auto flex flex-col gap-1.5" data-scrollable>
            <For each={keyHunterMatches().slice(0, 25)}>
              {(m) => (
                <div class="rounded border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2 flex flex-col gap-1 text-[11px]">
                  <div class="flex flex-wrap items-center justify-between gap-1.5">
                    <div class="flex items-center gap-1.5 min-w-0">
                      <span
                        class={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                          String(m.severity) === "critical"
                            ? "bg-red-500/20 text-red-400 border border-red-500/40"
                            : String(m.severity) === "high"
                              ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                              : "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                        }`}
                      >
                        {String(m.severity ?? "high")}
                      </span>
                      <strong class="text-v2-text-text-strong truncate">{String(m.provider)}</strong>
                      <span class="text-v2-text-text-muted truncate">— {String(m.description)}</span>
                    </div>
                    <span class="font-mono text-[10px] text-v2-text-text-muted">
                      {String(m.location)}:{String(m.line)} · H={String(m.shannonEntropy)}
                    </span>
                  </div>
                  <div class="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px]">
                    <span class="text-emerald-400">
                      Key: {String(m.maskedSecret)} <span class="text-v2-text-text-muted">(fp:{String(m.fingerprintSha256)})</span>
                    </span>
                    <Show when={String(m.verificationStatus) !== "not_checked"}>
                      <span
                        class={`rounded px-1.5 py-0.5 ${
                          String(m.verificationStatus) === "active_confirmed"
                            ? "bg-red-500/25 text-red-300 font-semibold"
                            : "bg-v2-background-bg-base text-v2-text-text-muted"
                        }`}
                      >
                        {String(m.verificationStatus)}
                      </span>
                    </Show>
                  </div>
                  <div class="font-mono text-[10px] text-v2-text-text-muted truncate" title={String(m.verificationRecipe ?? "")}>
                    KeyHacks: {String(m.verificationRecipe ?? "")}
                  </div>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>
    </>
  )
}

export function CyberLabWorkbenchSurface() {
  const wb = useCyberLabWorkbench()
  if (!wb) return null

  const [suitePickerOpen, setSuitePickerOpen] = createSignal(false)

  const activeSuite = createMemo(() => getSuiteMeta(wb.ui.activeSuiteId))
  const activeFunction = createMemo<ToolSuiteFunctionTab>(() => {
    const fnId = wb.ui.activeFunctionBySuite[wb.ui.activeSuiteId]
    return activeSuite().functions.find((f) => f.id === fnId) ?? activeSuite().functions[0]!
  })
  const activeMeta = createMemo(() => getToolMeta(wb.ui.activeToolId))

  const functionHistoryCount = (fn: ToolSuiteFunctionTab): number => {
    const uniqueIds = Array.from(new Set<ManualToolId>(fn.engines.map((e) => e.toolId)))
    return uniqueIds.reduce((acc, tid) => acc + (wb.histories[tid]?.length ?? 0), 0)
  }

  const functionDynamicBadge = (fn: ToolSuiteFunctionTab): string | undefined => {
    if (fn.governanceSubTab === "approvals" && wb.backend.approvals.length > 0) {
      return String(wb.backend.approvals.length)
    }
    if (fn.governanceSubTab === "evidence" && wb.backend.evidence.length > 0) {
      return String(wb.backend.evidence.length)
    }
    if (fn.governanceSubTab === "findings" && wb.backend.findings.length > 0) {
      return String(wb.backend.findings.length)
    }
    const hCount = functionHistoryCount(fn)
    return hCount > 0 ? String(hCount) : undefined
  }

  const suiteToolIdList = createMemo<ManualToolId[]>(() => getSuiteAllToolIds(activeSuite().id))

  const visibleHistory = createMemo<ToolHistoryEntry[]>(() => {
    if (wb.ui.historyScope === "suite") {
      const merged = suiteToolIdList().flatMap((tid) => wb.histories[tid] ?? [])
      return merged.sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    }
    return wb.histories[wb.ui.activeToolId] ?? []
  })

  const selectedEntry = createMemo<ToolHistoryEntry | undefined>(() => {
    const toolList = wb.histories[wb.ui.activeToolId] ?? []
    const id = wb.ui.selectedHistoryByTool[wb.ui.activeToolId]
    const direct = toolList.find((item) => item.id === id) ?? toolList[0]
    if (direct) return direct
    return visibleHistory()[0]
  })

  const matchingPendingApproval = createMemo(() => {
    const entry = selectedEntry()
    if (!entry) return undefined
    if (entry.approvalId) {
      const found = wb.backend.approvals.find((a) => a.approvalId === entry.approvalId)
      if (found) return found
    }
    if (entry.executionId) {
      return wb.backend.approvals.find((a) => a.executionId === entry.executionId)
    }
    return undefined
  })

  const isExternalToolInstalled = (toolId: ManualToolId): boolean => {
    if (!EXTERNAL_BINARY_TOOLS.has(toolId)) return true
    const backendId = toolId === "ghidra" ? "ghidra-headless" : toolId
    const list = wb.backend.external?.tools ?? []
    const found = list.find((t) => t.toolId === backendId)
    return Boolean(found?.available)
  }

  const statusBadgeClass = (status: ToolHistoryEntry["status"]) => {
    switch (status) {
      case "succeeded":
        return "bg-emerald-500/15 text-emerald-500 border-emerald-500/40"
      case "queued":
        return "bg-amber-500/15 text-amber-500 border-amber-500/40"
      case "running":
        return "bg-sky-500/15 text-sky-400 border-sky-500/40"
      default:
        return "bg-red-500/15 text-red-500 border-red-500/40"
    }
  }

  return (
    <>
      <section
        data-slot="cyberlab-manual-workbench"
        class="flex h-full min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-[10px] border border-v2-border-border-base bg-v2-background-bg-base shadow-[var(--v2-elevation-raised)] select-text"
      >
        {/* Top Bar: Single Suite Switcher Button + Scope & Layout Controls */}
        <header class="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-v2-border-border-base bg-v2-background-bg-deep/60 px-3.5 py-2">
          <div class="flex flex-wrap items-center gap-2 min-w-0">
            <button
              type="button"
              title="Trocar para outra suíte de ferramentas (lista vertical)"
              class="inline-flex items-center gap-2 rounded-lg border border-emerald-600/50 bg-emerald-600/15 px-2.5 py-1 text-[13px] font-medium text-v2-text-text-strong hover:bg-emerald-600/25 cursor-pointer transition-colors"
              onClick={() => setSuitePickerOpen(true)}
            >
              <Icon name={activeSuite().icon} class="size-4 text-emerald-500 shrink-0" />
              <span class="truncate">{activeSuite().title}</span>
              <Icon name="chevron-down" class="size-3.5 text-v2-text-text-muted shrink-0" />
            </button>

            <button
              type="button"
              title="Ajustar escopo de alvos autorizados"
              class={`rounded-full border px-2 py-0.5 text-[11px] font-medium cursor-pointer ${
                wb.backend.status?.activeScope?.allowExternalTargets
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-500"
                  : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-muted"
              }`}
              onClick={() => wb.selectSuite("governance-suite", "scope")}
            >
              {wb.backend.status?.activeScope?.allowExternalTargets
                ? "Escopo: Externo Liberado"
                : "Escopo: Localhost / Projeto"}
            </button>

            <Show when={wb.backend.approvals.length > 0}>
              <button
                type="button"
                class="rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-500 cursor-pointer"
                onClick={() => wb.selectSuite("governance-suite", "approvals")}
              >
                {wb.backend.approvals.length} Aprovação(ões)
              </button>
            </Show>
          </div>

          <div class="flex items-center gap-1">
            <button
              type="button"
              title="Mostrar ou ocultar a coluna de histórico persistente"
              class={`rounded-md border px-2 py-1 text-[11px] font-medium cursor-pointer ${
                wb.ui.showHistoryColumn
                  ? "border-emerald-600/50 bg-emerald-600/15 text-v2-text-text-strong"
                  : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-muted"
              }`}
              onClick={() => wb.setShowHistoryColumn(!wb.ui.showHistoryColumn)}
            >
              Histórico ({visibleHistory().length})
            </button>

            <Show when={wb.ui.layoutMode === "split"}>
              <div class="hidden xl:flex items-center rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-0.5 text-[11px]">
                <For each={[45, 55, 65]}>
                  {(pct) => (
                    <button
                      type="button"
                      class={`rounded px-1.5 py-0.5 cursor-pointer ${
                        Math.abs(wb.ui.splitWidthPct - pct) <= 4
                          ? "bg-v2-background-bg-deep font-medium text-v2-text-text-strong"
                          : "text-v2-text-text-muted"
                      }`}
                      onClick={() => wb.setSplitWidthPct(pct)}
                    >
                      {pct}%
                    </button>
                  )}
                </For>
              </div>
            </Show>

            <button
              type="button"
              title={
                wb.ui.layoutMode === "fullscreen"
                  ? "Dividir tela: Chat + Ferramenta lado a lado"
                  : "Expandir ferramenta em tela cheia"
              }
              class="inline-flex items-center gap-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 text-[11px] font-medium text-v2-text-text-strong hover:bg-v2-background-bg-deep cursor-pointer"
              onClick={() =>
                wb.setLayoutMode(wb.ui.layoutMode === "fullscreen" ? "split" : "fullscreen")
              }
            >
              <Icon name={wb.ui.layoutMode === "fullscreen" ? "split" : "expand"} class="size-3.5" />
              <span>{wb.ui.layoutMode === "fullscreen" ? "Dividir c/ Chat" : "Tela Cheia"}</span>
            </button>

            <button
              type="button"
              title="Fechar bancada manual e voltar somente ao chat"
              class="inline-flex items-center justify-center rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-1 text-v2-text-text-muted hover:text-v2-text-text-strong cursor-pointer"
              onClick={() => wb.toggleWorkbench(false)}
            >
              <Icon name="close" class="size-3.5" />
            </button>
          </div>
        </header>

        {/* Burp-Suite-Style Internal Function Tabs (flex-wrap, zero horizontal scroll!) */}
        <Show when={activeSuite().functions.length > 1}>
          <nav
            aria-label="Funções internas da suíte"
            class="flex shrink-0 flex-wrap items-center gap-1.5 border-b border-v2-border-border-base bg-v2-background-bg-deep/30 px-3.5 py-2"
          >
            <For each={activeSuite().functions}>
              {(fn) => {
                const isSelected = () => activeFunction().id === fn.id
                const badge = () => functionDynamicBadge(fn)
                return (
                  <button
                    type="button"
                    title={fn.description}
                    class={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[12px] cursor-pointer transition-colors ${
                      isSelected()
                        ? "border-emerald-600 bg-emerald-600 text-white font-medium shadow-xs"
                        : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-base hover:bg-v2-background-bg-deep hover:text-v2-text-text-strong"
                    }`}
                    onClick={() => wb.selectSuiteFunction(fn.id)}
                  >
                    <span>{fn.label}</span>
                    <Show when={badge()}>
                      {(b) => (
                        <span
                          class={`rounded-full px-1.5 text-[10px] ${
                            isSelected()
                              ? "bg-white/20 text-white"
                              : "bg-v2-background-bg-deep text-v2-text-text-muted"
                          }`}
                        >
                          {b()}
                        </span>
                      )}
                    </Show>
                  </button>
                )
              }}
            </For>
          </nav>
        </Show>

        {/* Notices / Errors */}
        <Show when={wb.ui.notice || wb.ui.error}>
          <div
            class={`shrink-0 border-b px-3.5 py-1.5 text-[12px] flex items-center justify-between gap-2 ${
              wb.ui.error
                ? "border-red-500/40 bg-red-500/10 text-red-500"
                : "border-emerald-500/40 bg-emerald-500/10 text-emerald-500"
            }`}
          >
            <span class="truncate">{wb.ui.error || wb.ui.notice}</span>
            <button
              type="button"
              class="text-[11px] underline cursor-pointer shrink-0"
              onClick={() => {
                wb.setError("")
                wb.setNotice("")
              }}
            >
              Fechar
            </button>
          </div>
        </Show>

        {/* Main Body: Function Config + Output Inspector + Persistent History */}
        <div class="flex min-h-0 flex-1 flex-col lg:flex-row overflow-hidden">
          <div class="flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto p-3.5 gap-4" data-scrollable>
            {/* Active Function Header + Segmented Engine Switcher (when multiple engines exist) */}
            <div class="flex flex-col gap-2.5 border-b border-v2-border-border-base pb-3">
              <div class="flex flex-wrap items-start justify-between gap-2">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <h2 class="text-[15px] font-medium leading-[var(--line-height-base)] text-v2-text-text-strong">
                      {activeFunction().label}
                    </h2>
                    <span class="rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-0.5 text-[11px] text-v2-text-text-muted">
                      {activeMeta().badge}
                    </span>
                    <span class="rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-0.5 text-[11px] text-v2-text-text-muted">
                      {activeMeta().riskLabel}
                    </span>
                  </div>
                  <p class="mt-0.5 text-[12px] leading-[var(--line-height-base)] text-v2-text-text-muted">
                    {activeMeta().subtitle}
                  </p>
                </div>

                <Show when={wb.ui.runningExecutionId}>
                  {(execId) => (
                    <button
                      type="button"
                      class="rounded-md bg-red-600 px-2.5 py-1 text-[12px] font-medium text-white hover:bg-red-500 cursor-pointer"
                      onClick={() => void wb.cancelExecution(execId())}
                    >
                      Cancelar Execução (Kill)
                    </button>
                  )}
                </Show>
              </div>

              {/* Segmented Engine Selector inside the same function */}
              <Show when={activeFunction().engines.length > 1}>
                <div class="flex flex-wrap items-center gap-2 rounded-lg border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2">
                  <span class="px-1 text-[11px] font-medium uppercase tracking-wide text-v2-text-text-muted">
                    Motor de Execução:
                  </span>
                  <div class="flex flex-wrap items-center gap-1.5">
                    <For each={activeFunction().engines}>
                      {(eng) => {
                        const selected = () => wb.ui.activeToolId === eng.toolId
                        const isExt = () => EXTERNAL_BINARY_TOOLS.has(eng.toolId)
                        const ready = () => isExternalToolInstalled(eng.toolId)
                        return (
                          <button
                            type="button"
                            title={eng.description}
                            class={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[12px] cursor-pointer transition-colors ${
                              selected()
                                ? "border-emerald-600 bg-v2-background-bg-base font-medium text-v2-text-text-strong shadow-xs"
                                : "border-transparent text-v2-text-text-muted hover:bg-v2-background-bg-base/60 hover:text-v2-text-text-strong"
                            }`}
                            onClick={() => wb.selectSuiteEngine(eng.toolId)}
                          >
                            <span>{eng.label}</span>
                            <span
                              class={`rounded px-1.5 py-0.2 text-[10px] ${
                                !isExt()
                                  ? "bg-emerald-500/15 text-emerald-500"
                                  : ready()
                                    ? "bg-emerald-500/15 text-emerald-500"
                                    : "bg-amber-500/15 text-amber-500"
                              }`}
                            >
                              {!isExt() ? "Integrado" : ready() ? "Instalado" : "Externo"}
                            </span>
                          </button>
                        )
                      }}
                    </For>
                  </div>
                </div>
              </Show>
            </div>

            {/* Dedicated Full Configuration Form for Active Function/Engine */}
            <ManualToolConfigForm wb={wb} />

            {/* Active / Selected Execution Output Inspector */}
            <Show when={selectedEntry()}>
              {(entry) => {
                const entryMeta = () => getToolMeta(entry().toolId)
                return (
                  <div class="rounded-lg border border-v2-border-border-base bg-v2-background-bg-deep/50 p-3 flex flex-col gap-2.5">
                    <div class="flex flex-wrap items-center justify-between gap-2">
                      <div class="flex flex-wrap items-center gap-2 min-w-0">
                        <span
                          class={`rounded border px-2 py-0.5 text-[11px] font-medium uppercase ${statusBadgeClass(
                            entry().status,
                          )}`}
                        >
                          {entry().status}
                        </span>
                        <span class="rounded bg-v2-background-bg-base px-1.5 py-0.5 text-[11px] text-v2-text-text-muted">
                          {entryMeta().shortTitle}
                        </span>
                        <span class="font-mono text-[12px] font-medium text-v2-text-text-strong truncate">
                          {entry().targetSummary}
                        </span>
                        <Show when={entry().durationMs !== undefined}>
                          <span class="text-[11px] text-v2-text-text-muted">
                            ({entry().durationMs} ms)
                          </span>
                        </Show>
                      </div>

                      <div class="flex flex-wrap items-center gap-1.5">
                        <Show when={matchingPendingApproval()}>
                          {(ticket) => (
                            <button
                              type="button"
                              class="rounded-md bg-amber-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-amber-500 cursor-pointer"
                              onClick={() =>
                                void wb.approvePendingExecution(ticket().approvalId, entry())
                              }
                            >
                              Aprovar & Executar Agora
                            </button>
                          )}
                        </Show>
                        <button
                          type="button"
                          class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 text-[11px] text-v2-text-text-strong hover:bg-v2-background-bg-deep cursor-pointer"
                          onClick={() => wb.restoreHistoryDraft(entry())}
                        >
                          Restaurar Configs
                        </button>
                        <Show when={entry().evidenceIds[0]}>
                          {(evId) => (
                            <button
                              type="button"
                              class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 text-[11px] text-v2-text-text-strong hover:bg-v2-background-bg-deep cursor-pointer"
                              onClick={() => void wb.verifyEvidenceCustody(evId())}
                            >
                              Verificar SHA-256
                            </button>
                          )}
                        </Show>
                        <Show when={entry().outputText}>
                          <button
                            type="button"
                            class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 text-[11px] text-v2-text-text-strong hover:bg-v2-background-bg-deep cursor-pointer"
                            onClick={() => wb.sendTextToDecoder(entry().outputText)}
                          >
                            → Decoder
                          </button>
                          <button
                            type="button"
                            class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 text-[11px] text-v2-text-text-strong hover:bg-v2-background-bg-deep cursor-pointer"
                            onClick={() => {
                              if (navigator.clipboard) {
                                void navigator.clipboard.writeText(entry().outputText)
                                wb.setNotice("Saída copiada para a área de transferência.")
                              }
                            }}
                          >
                            Copiar Saída
                          </button>
                          <button
                            type="button"
                            class="rounded border border-emerald-600/50 bg-emerald-600/15 px-2 py-1 text-[11px] font-medium text-emerald-500 hover:bg-emerald-600/25 cursor-pointer"
                            onClick={() =>
                              wb.attachToComposer(
                                `${entryMeta().shortTitle} — ${entry().targetSummary}`,
                                `Suíte: ${activeSuite().title}\nFunção: ${entryMeta().title}\nAlvo: ${entry().targetSummary}\nData: ${entry().timestamp}${
                                  entry().sha256 ? `\nSHA-256: ${entry().sha256}` : ""
                                }\n\n${entry().outputText}`,
                                `${entry().toolId}-resultado.txt`,
                              )
                            }
                          >
                            Anexar na Caixa de Diálogo
                          </button>
                        </Show>
                      </div>
                    </div>

                    <Show when={entry().sha256}>
                      <div class="font-mono text-[11px] text-v2-text-text-muted break-all">
                        Custódia Criptográfica SHA-256: {entry().sha256}
                      </div>
                    </Show>

                    <StructuredResultVisualizer outputText={entry().outputText} />

                    <pre
                      class="max-h-72 overflow-auto rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-2.5 font-mono text-[11px] leading-[var(--line-height-compact)] text-v2-text-text-strong select-text"
                      data-scrollable
                    >
                      {entry().outputText || entry().summaryText}
                    </pre>
                  </div>
                )
              }}
            </Show>
          </div>

          {/* Right Column: Persistent History (Current Function OR Entire Suite) */}
          <Show when={wb.ui.showHistoryColumn}>
            <aside class="flex w-full shrink-0 flex-col border-t border-v2-border-border-base bg-v2-background-bg-deep/30 lg:w-[280px] lg:border-l lg:border-t-0 max-h-60 lg:max-h-none">
              <div class="flex flex-col gap-1.5 border-b border-v2-border-border-base px-3 py-2">
                <div class="flex items-center justify-between gap-1">
                  <span class="text-[11px] font-medium uppercase tracking-wide text-v2-text-text-muted">
                    Histórico ({visibleHistory().length})
                  </span>
                  <Show when={wb.ui.historyScope === "function" && visibleHistory().length > 0}>
                    <button
                      type="button"
                      class="text-[11px] text-v2-text-text-muted hover:text-red-500 cursor-pointer"
                      onClick={() => wb.clearToolHistory(wb.ui.activeToolId)}
                    >
                      Limpar
                    </button>
                  </Show>
                </div>

                <Show when={suiteToolIdList().length > 1}>
                  <div class="grid grid-cols-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-0.5 text-[11px]">
                    <button
                      type="button"
                      class={`rounded py-0.5 cursor-pointer ${
                        wb.ui.historyScope === "function"
                          ? "bg-v2-background-bg-deep font-medium text-v2-text-text-strong"
                          : "text-v2-text-text-muted"
                      }`}
                      onClick={() => wb.setHistoryScope("function")}
                    >
                      Desta função
                    </button>
                    <button
                      type="button"
                      class={`rounded py-0.5 cursor-pointer ${
                        wb.ui.historyScope === "suite"
                          ? "bg-v2-background-bg-deep font-medium text-v2-text-text-strong"
                          : "text-v2-text-text-muted"
                      }`}
                      onClick={() => wb.setHistoryScope("suite")}
                    >
                      Toda a suíte
                    </button>
                  </div>
                </Show>
              </div>

              <div class="min-h-0 flex-1 overflow-y-auto p-2 flex flex-col gap-1.5" data-scrollable>
                <Show
                  when={visibleHistory().length > 0}
                  fallback={
                    <div class="p-3 text-center text-[12px] leading-[var(--line-height-base)] text-v2-text-text-muted">
                      Nenhuma execução salva aqui ainda. Cada uso manual fica persistido automaticamente para você alternar de suíte ou função sem perder nada.
                    </div>
                  }
                >
                  <For each={visibleHistory()}>
                    {(item) => {
                      const active = () => selectedEntry()?.id === item.id
                      const itemMeta = () => getToolMeta(item.toolId)
                      return (
                        <div
                          class={`group rounded-md border p-2 text-[12px] cursor-pointer transition-colors ${
                            active()
                              ? "border-emerald-600/60 bg-v2-background-bg-base"
                              : "border-v2-border-border-base bg-v2-background-bg-deep/40 hover:bg-v2-background-bg-base"
                          }`}
                          onClick={() => {
                            wb.selectTool(item.toolId)
                            wb.selectHistoryItem(item.toolId, item.id)
                          }}
                        >
                          <div class="flex items-center justify-between gap-1">
                            <div class="flex items-center gap-1 min-w-0">
                              <span
                                class={`rounded border px-1.5 py-0.2 text-[10px] uppercase shrink-0 ${statusBadgeClass(
                                  item.status,
                                )}`}
                              >
                                {item.status}
                              </span>
                              <Show when={wb.ui.historyScope === "suite"}>
                                <span class="truncate text-[10px] text-v2-text-text-muted">
                                  {itemMeta().shortTitle}
                                </span>
                              </Show>
                            </div>
                            <span class="text-[10px] text-v2-text-text-muted shrink-0">
                              {new Date(item.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          <div class="mt-1 truncate font-mono text-[11px] font-medium text-v2-text-text-strong">
                            {item.targetSummary}
                          </div>
                          <div class="mt-0.5 truncate text-[11px] text-v2-text-text-muted">
                            {item.summaryText}
                          </div>
                          <div class="mt-1.5 flex items-center justify-between gap-1">
                            <button
                              type="button"
                              class="rounded border border-v2-border-border-base px-1.5 py-0.5 text-[10px] text-v2-text-text-base hover:bg-v2-background-bg-deep cursor-pointer"
                              onClick={(e) => {
                                e.stopPropagation()
                                wb.restoreHistoryDraft(item)
                              }}
                            >
                              Carregar Configs
                            </button>
                            <button
                              type="button"
                              title="Remover do histórico"
                              class="rounded p-0.5 text-v2-text-text-muted hover:text-red-500 cursor-pointer"
                              onClick={(e) => {
                                e.stopPropagation()
                                wb.deleteHistoryEntry(item.toolId, item.id)
                              }}
                            >
                              <Icon name="trash" class="size-3" />
                            </button>
                          </div>
                        </div>
                      )
                    }}
                  </For>
                </Show>
              </div>
            </aside>
          </Show>
        </div>
      </section>

      <VerticalSuitesPickerDialog
        open={suitePickerOpen()}
        onClose={() => setSuitePickerOpen(false)}
        wb={wb}
      />
    </>
  )
}
