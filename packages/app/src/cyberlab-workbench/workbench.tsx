import { createMemo, For, Show } from "solid-js"
import { Icon } from "@opencode/ui/icon"
import { getToolMeta, MANUAL_TOOL_CATEGORIES, MANUAL_TOOLS } from "./catalog"
import { useCyberLabWorkbench } from "./state"
import { ManualToolConfigForm } from "./tool-forms"
import type { ToolHistoryEntry } from "./types"

export function CyberLabWorkbenchSurface() {
  const wb = useCyberLabWorkbench()
  if (!wb) return null

  const activeMeta = createMemo(() => getToolMeta(wb.ui.activeToolId))
  const categoryTools = createMemo(() =>
    MANUAL_TOOLS.filter((tool) => tool.category === activeMeta().category),
  )

  const toolHistory = createMemo(() => wb.histories[wb.ui.activeToolId] ?? [])
  const selectedEntry = createMemo<ToolHistoryEntry | undefined>(() => {
    const list = toolHistory()
    const id = wb.ui.selectedHistoryByTool[wb.ui.activeToolId]
    return list.find((item) => item.id === id) ?? list[0]
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
    <section
      data-slot="cyberlab-manual-workbench"
      class="flex h-full min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-[10px] border border-v2-border-border-base bg-v2-background-bg-base shadow-[var(--v2-elevation-raised)] select-text"
    >
      {/* Top Header: Title + Scope Pill + Layout Controls */}
      <header class="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-v2-border-border-base bg-v2-background-bg-deep/60 px-3.5 py-2">
        <div class="flex items-center gap-2 min-w-0">
          <span class="inline-flex size-6 shrink-0 items-center justify-center rounded-md bg-emerald-600/15 text-emerald-500">
            <Icon name="shield" class="size-4" />
          </span>
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <span class="truncate text-[13px] font-medium leading-[var(--line-height-compact)] text-v2-text-text-strong">
                Bancada Manual CyberLab OS
              </span>
              <button
                type="button"
                title="Clique para ajustar o escopo de alvos autorizados"
                class={`rounded-full border px-2 py-0.5 text-[11px] font-medium cursor-pointer ${
                  wb.backend.status?.activeScope?.allowExternalTargets
                    ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-500"
                    : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-muted"
                }`}
                onClick={() => {
                  wb.updateDraft("scope-governance", (p) => ({ ...p, subTab: "scope" }))
                  wb.selectTool("scope-governance")
                }}
              >
                {wb.backend.status?.activeScope?.allowExternalTargets
                  ? "Escopo: Externo Liberado"
                  : "Escopo: Localhost / Projeto"}
              </button>
              <Show when={wb.backend.approvals.length > 0}>
                <button
                  type="button"
                  class="rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-500 cursor-pointer"
                  onClick={() => {
                    wb.updateDraft("scope-governance", (p) => ({ ...p, subTab: "approvals" }))
                    wb.selectTool("scope-governance")
                  }}
                >
                  {wb.backend.approvals.length} Aprovação(ões)
                </button>
              </Show>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-1">
          <button
            type="button"
            title="Mostrar/ocultar coluna de histórico da ferramenta"
            class={`rounded-md border px-2 py-1 text-[11px] font-medium cursor-pointer ${
              wb.ui.showHistoryColumn
                ? "border-emerald-600/50 bg-emerald-600/15 text-v2-text-text-strong"
                : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-muted"
            }`}
            onClick={() => wb.setShowHistoryColumn(!wb.ui.showHistoryColumn)}
          >
            Histórico ({toolHistory().length})
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
            onClick={() => wb.setLayoutMode(wb.ui.layoutMode === "fullscreen" ? "split" : "fullscreen")}
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

      {/* Category Strip + Tool Tabs inside Category */}
      <div class="flex shrink-0 flex-col gap-1.5 border-b border-v2-border-border-base bg-v2-background-bg-deep/30 px-3 py-2">
        <div class="flex items-center gap-1 overflow-x-auto no-scrollbar" data-scrollable>
          <For each={MANUAL_TOOL_CATEGORIES}>
            {(cat) => {
              const active = () => activeMeta().category === cat.id
              return (
                <button
                  type="button"
                  class={`shrink-0 rounded-md px-2.5 py-1 text-[12px] font-medium cursor-pointer transition-colors ${
                    active()
                      ? "bg-v2-background-bg-deep text-v2-text-text-strong border border-v2-border-border-base"
                      : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                  }`}
                  onClick={() => {
                    const firstInCat = MANUAL_TOOLS.find((t) => t.category === cat.id)
                    if (firstInCat) wb.selectTool(firstInCat.id)
                  }}
                >
                  {cat.label}
                </button>
              )
            }}
          </For>
        </div>

        <div class="flex items-center gap-1.5 overflow-x-auto no-scrollbar" data-scrollable>
          <For each={categoryTools()}>
            {(tool) => {
              const isSelected = () => wb.ui.activeToolId === tool.id
              const histCount = () => (wb.histories[tool.id] ?? []).length
              return (
                <button
                  type="button"
                  class={`inline-flex shrink-0 items-center gap-1.5 rounded-md border px-2.5 py-1 text-[12px] cursor-pointer transition-colors ${
                    isSelected()
                      ? "border-emerald-600 bg-emerald-600 text-white font-medium"
                      : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-base hover:bg-v2-background-bg-deep"
                  }`}
                  onClick={() => wb.selectTool(tool.id)}
                >
                  <Icon name={tool.icon} class="size-3.5" />
                  <span>{tool.shortTitle}</span>
                  <Show when={histCount() > 0}>
                    <span
                      class={`rounded-full px-1.5 text-[10px] ${
                        isSelected() ? "bg-white/20 text-white" : "bg-v2-background-bg-deep text-v2-text-text-muted"
                      }`}
                    >
                      {histCount()}
                    </span>
                  </Show>
                </button>
              )
            }}
          </For>
        </div>
      </div>

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

      {/* Main Body: Tool Config + Output Inspector + Per-Tool Persistent History */}
      <div class="flex min-h-0 flex-1 flex-col lg:flex-row overflow-hidden">
        {/* Left/Center: Active Tool Header + Full Config Form + Selected Output */}
        <div class="flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto p-3.5 gap-4" data-scrollable>
          <div class="flex flex-wrap items-start justify-between gap-2 border-b border-v2-border-border-base pb-2.5">
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-2">
                <h2 class="text-[15px] font-medium leading-[var(--line-height-base)] text-v2-text-text-strong">
                  {activeMeta().title}
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

          {/* Dedicated Full Configuration Form for Active Tool */}
          <ManualToolConfigForm wb={wb} />

          {/* Active / Selected Execution Output Inspector */}
          <Show when={selectedEntry()}>
            {(entry) => (
              <div class="rounded-lg border border-v2-border-border-base bg-v2-background-bg-deep/50 p-3 flex flex-col gap-2.5">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <div class="flex flex-wrap items-center gap-2 min-w-0">
                    <span class={`rounded border px-2 py-0.5 text-[11px] font-medium uppercase ${statusBadgeClass(entry().status)}`}>
                      {entry().status}
                    </span>
                    <span class="font-mono text-[12px] font-medium text-v2-text-text-strong truncate">
                      {entry().targetSummary}
                    </span>
                    <Show when={entry().durationMs !== undefined}>
                      <span class="text-[11px] text-v2-text-text-muted">({entry().durationMs} ms)</span>
                    </Show>
                  </div>

                  <div class="flex flex-wrap items-center gap-1.5">
                    <Show when={matchingPendingApproval()}>
                      {(ticket) => (
                        <button
                          type="button"
                          class="rounded-md bg-amber-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-amber-500 cursor-pointer"
                          onClick={() => void wb.approvePendingExecution(ticket().approvalId, entry())}
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
                            `${activeMeta().shortTitle} — ${entry().targetSummary}`,
                            `Ferramenta: ${activeMeta().title}\nAlvo: ${entry().targetSummary}\nData: ${entry().timestamp}${
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

                <pre
                  class="max-h-72 overflow-auto rounded-md border border-v2-border-border-base bg-v2-background-bg-base p-2.5 font-mono text-[11px] leading-[var(--line-height-compact)] text-v2-text-text-strong select-text"
                  data-scrollable
                >
                  {entry().outputText || entry().summaryText}
                </pre>
              </div>
            )}
          </Show>
        </div>

        {/* Right Column: Persistent Per-Tool History */}
        <Show when={wb.ui.showHistoryColumn}>
          <aside class="flex w-full shrink-0 flex-col border-t border-v2-border-border-base bg-v2-background-bg-deep/30 lg:w-[270px] lg:border-l lg:border-t-0 max-h-60 lg:max-h-none">
            <div class="flex items-center justify-between border-b border-v2-border-border-base px-3 py-2">
              <span class="text-[11px] font-medium uppercase tracking-wide text-v2-text-text-muted">
                Histórico · {activeMeta().shortTitle} ({toolHistory().length})
              </span>
              <Show when={toolHistory().length > 0}>
                <button
                  type="button"
                  class="text-[11px] text-v2-text-text-muted hover:text-red-500 cursor-pointer"
                  onClick={() => wb.clearToolHistory(wb.ui.activeToolId)}
                >
                  Limpar
                </button>
              </Show>
            </div>

            <div class="min-h-0 flex-1 overflow-y-auto p-2 flex flex-col gap-1.5" data-scrollable>
              <Show
                when={toolHistory().length > 0}
                fallback={
                  <div class="p-3 text-center text-[12px] leading-[var(--line-height-base)] text-v2-text-text-muted">
                    Nenhuma execução salva para <strong>{activeMeta().shortTitle}</strong> ainda. Cada uso manual desta ferramenta fica salvo aqui automaticamente.
                  </div>
                }
              >
                <For each={toolHistory()}>
                  {(item) => {
                    const active = () => selectedEntry()?.id === item.id
                    return (
                      <div
                        class={`group rounded-md border p-2 text-[12px] cursor-pointer transition-colors ${
                          active()
                            ? "border-emerald-600/60 bg-v2-background-bg-base"
                            : "border-v2-border-border-base bg-v2-background-bg-deep/40 hover:bg-v2-background-bg-base"
                        }`}
                        onClick={() => wb.selectHistoryItem(wb.ui.activeToolId, item.id)}
                      >
                        <div class="flex items-center justify-between gap-1">
                          <span class={`rounded border px-1.5 py-0.2 text-[10px] uppercase ${statusBadgeClass(item.status)}`}>
                            {item.status}
                          </span>
                          <span class="text-[10px] text-v2-text-text-muted">
                            {new Date(item.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <div class="mt-1 truncate font-mono text-[11px] font-medium text-v2-text-text-strong">
                          {item.targetSummary}
                        </div>
                        <div class="mt-0.5 truncate text-[11px] text-v2-text-text-muted">{item.summaryText}</div>
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
                              wb.deleteHistoryEntry(wb.ui.activeToolId, item.id)
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
  )
}
