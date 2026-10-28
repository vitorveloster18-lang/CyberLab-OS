import { createMemo, For, onCleanup, onMount, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Portal } from "solid-js/web"
import { Icon } from "@opencode/ui/icon"
import type { ComposerModel } from "@/composer/model"
import { getToolMeta, MANUAL_TOOL_CATEGORIES, MANUAL_TOOLS } from "./catalog"
import { useCyberLabWorkbench } from "./state"
import type { ManualToolId } from "./types"

function AllToolsPickerModal(props: {
  open: boolean
  query: string
  onQuery: (q: string) => void
  onSelect: (toolId: ManualToolId) => void
  onClose: () => void
  historiesCount: (toolId: ManualToolId) => number
  activeToolId: ManualToolId
}) {
  const filteredByCategory = createMemo(() => {
    const q = props.query.trim().toLowerCase()
    return MANUAL_TOOL_CATEGORIES.map((cat) => ({
      ...cat,
      tools: MANUAL_TOOLS.filter(
        (t) =>
          t.category === cat.id &&
          (!q ||
            t.title.toLowerCase().includes(q) ||
            t.shortTitle.toLowerCase().includes(q) ||
            t.subtitle.toLowerCase().includes(q) ||
            (t.capabilityId ?? "").toLowerCase().includes(q)),
      ),
    })).filter((group) => group.tools.length > 0)
  })

  return (
    <Show when={props.open}>
      <Portal>
        <div
          class="fixed inset-0 z-[120] flex items-center justify-center bg-black/50 p-4 backdrop-blur-[1px]"
          onClick={props.onClose}
        >
          <div
            data-slot="cyberlab-all-tools-modal"
            class="flex max-h-[82vh] w-full max-w-[780px] flex-col overflow-hidden rounded-xl border border-v2-border-border-base bg-v2-background-bg-base shadow-[var(--v2-elevation-floating)] select-text"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="flex items-center justify-between gap-3 border-b border-v2-border-border-base bg-v2-background-bg-deep/60 px-4 py-3">
              <div class="flex items-center gap-2">
                <span class="inline-flex size-6 items-center justify-center rounded-md bg-emerald-600/15 text-emerald-500">
                  <Icon name="shield" class="size-4" />
                </span>
                <div>
                  <div class="text-[14px] font-medium leading-[var(--line-height-compact)] text-v2-text-text-strong">
                    Selecionar Ferramenta Manual — CyberLab OS ({MANUAL_TOOLS.length} Ferramentas)
                  </div>
                  <div class="text-[11px] text-v2-text-text-muted">
                    Clique em qualquer ferramenta para abrir sua interface manual completa com configurações e histórico persistente
                  </div>
                </div>
              </div>
              <button
                type="button"
                class="rounded-md p-1 text-v2-text-text-muted hover:text-v2-text-text-strong cursor-pointer"
                onClick={props.onClose}
              >
                <Icon name="close" class="size-4" />
              </button>
            </div>

            <div class="border-b border-v2-border-border-base px-4 py-2.5">
              <input
                type="text"
                autofocus
                value={props.query}
                placeholder="Buscar ferramenta manual (ex.: Repeater, Proxy, Nmap, Nuclei, ffuf, JWT, TLS, PCAP, Binário, APK, CDI)..."
                class="w-full rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-3 py-1.5 text-[13px] text-v2-text-text-strong outline-none focus:border-emerald-500"
                onInput={(e) => props.onQuery(e.currentTarget.value)}
              />
            </div>

            <div class="min-h-0 flex-1 overflow-y-auto p-4 flex flex-col gap-4" data-scrollable>
              <For each={filteredByCategory()}>
                {(group) => (
                  <div class="flex flex-col gap-2">
                    <div class="flex items-baseline justify-between gap-2">
                      <span class="text-[12px] font-medium uppercase tracking-wide text-emerald-500">
                        {group.label}
                      </span>
                      <span class="text-[11px] text-v2-text-text-muted">{group.description}</span>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      <For each={group.tools}>
                        {(tool) => {
                          const count = () => props.historiesCount(tool.id)
                          const isCurrent = () => props.activeToolId === tool.id
                          return (
                            <button
                              type="button"
                              class={`flex items-start gap-2.5 rounded-lg border p-2.5 text-left cursor-pointer transition-colors ${
                                isCurrent()
                                  ? "border-emerald-600 bg-emerald-600/10"
                                  : "border-v2-border-border-base bg-v2-background-bg-deep/40 hover:bg-v2-background-bg-deep"
                              }`}
                              onClick={() => {
                                props.onSelect(tool.id)
                                props.onClose()
                              }}
                            >
                              <span class="mt-0.5 inline-flex size-7 shrink-0 items-center justify-center rounded-md border border-v2-border-border-base bg-v2-background-bg-base text-emerald-500">
                                <Icon name={tool.icon} class="size-4" />
                              </span>
                              <div class="min-w-0 flex-1">
                                <div class="flex items-center justify-between gap-1.5">
                                  <span class="truncate text-[13px] font-medium text-v2-text-text-strong">
                                    {tool.title}
                                  </span>
                                  <Show when={count() > 0}>
                                    <span class="shrink-0 rounded-full bg-emerald-600/20 px-1.5 py-0.5 text-[10px] font-medium text-emerald-500">
                                      {count()} salvo(s)
                                    </span>
                                  </Show>
                                </div>
                                <p class="mt-0.5 line-clamp-2 text-[11px] leading-[var(--line-height-compact)] text-v2-text-text-muted">
                                  {tool.subtitle}
                                </p>
                                <div class="mt-1 flex items-center gap-1.5 text-[10px] text-v2-text-text-muted">
                                  <span class="rounded border border-v2-border-border-base px-1.5 py-0.2">
                                    {tool.badge}
                                  </span>
                                  <span>· {tool.riskLabel}</span>
                                </div>
                              </div>
                            </button>
                          )
                        }}
                      </For>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </div>
        </div>
      </Portal>
    </Show>
  )
}

/**
 * Barra de Ferramentas Manuais posicionada imediatamente abaixo da Caixa de Diálogo (Composer).
 * Permite abrir o catálogo completo das 18 ferramentas ou alternar com 1 clique mantendo estado + histórico individual.
 */
export function CyberLabComposerToolbar(props: { model?: ComposerModel }) {
  const wb = useCyberLabWorkbench()
  const [picker, setPicker] = createStore({ open: false, query: "" })

  onMount(() => {
    if (!wb || !props.model) return
    const unregister = wb.registerComposer(props.model)
    onCleanup(unregister)
  })

  if (!wb) return null

  const totalSavedRuns = createMemo(() =>
    MANUAL_TOOLS.reduce((acc, t) => acc + (wb.histories[t.id]?.length ?? 0), 0),
  )

  return (
    <>
      <div
        data-slot="cyberlab-composer-toolbar"
        class="flex flex-wrap items-center justify-between gap-1.5 rounded-lg border border-v2-border-border-base bg-v2-background-bg-deep/55 px-2.5 py-1.5"
      >
        <div class="flex min-w-0 flex-1 items-center gap-1.5 overflow-x-auto no-scrollbar" data-scrollable>
          {/* Botão principal com ícone que abre todas as 18 ferramentas */}
          <button
            type="button"
            data-action="open-cyberlab-tools-catalog"
            title="Abrir catálogo completo das 18 ferramentas manuais do CyberLab OS"
            class="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-emerald-600/50 bg-emerald-600/15 px-2.5 py-1 text-[12px] font-medium text-emerald-500 hover:bg-emerald-600/25 cursor-pointer transition-colors"
            onClick={() => setPicker({ open: true, query: "" })}
          >
            <Icon name="shield" class="size-3.5" />
            <span>Ferramentas ({MANUAL_TOOLS.length})</span>
            <Show when={totalSavedRuns() > 0}>
              <span class="rounded-full bg-emerald-600/25 px-1.5 text-[10px]">{totalSavedRuns()}</span>
            </Show>
            <Icon name="chevron-down" class="size-3" />
          </button>

          {/* Pílulas de alternância rápida com 1 clique abaixo da caixa de diálogo */}
          <For each={wb.ui.quickToolIds}>
            {(toolId) => {
              const meta = () => getToolMeta(toolId)
              const active = () => wb.ui.open && wb.ui.activeToolId === toolId
              const histCount = () => wb.histories[toolId]?.length ?? 0
              return (
                <button
                  type="button"
                  title={`${meta().title} — clique para abrir/alternar`}
                  class={`inline-flex shrink-0 items-center gap-1 rounded-md border px-2 py-1 text-[11px] cursor-pointer transition-colors ${
                    active()
                      ? "border-emerald-600 bg-emerald-600 text-white font-medium"
                      : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-base hover:bg-v2-background-bg-deep"
                  }`}
                  onClick={() => {
                    if (wb.ui.open && wb.ui.activeToolId === toolId) {
                      wb.toggleWorkbench(false)
                    } else {
                      wb.selectTool(toolId)
                    }
                  }}
                >
                  <Icon name={meta().icon} class="size-3" />
                  <span>{meta().shortTitle}</span>
                  <Show when={histCount() > 0}>
                    <span
                      class={`rounded-full px-1 text-[10px] ${
                        active() ? "bg-white/20 text-white" : "bg-v2-background-bg-deep text-v2-text-text-muted"
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

        <Show when={wb.ui.open}>
          <div class="flex shrink-0 items-center gap-1">
            <button
              type="button"
              title="Alternar entre Modo Dividido (Chat + Ferramenta) e Tela Cheia Manual"
              class="inline-flex items-center gap-1 rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-0.5 text-[11px] text-v2-text-text-strong hover:bg-v2-background-bg-deep cursor-pointer"
              onClick={() => wb.setLayoutMode(wb.ui.layoutMode === "fullscreen" ? "split" : "fullscreen")}
            >
              <Icon name={wb.ui.layoutMode === "fullscreen" ? "split" : "expand"} class="size-3" />
              <span>{wb.ui.layoutMode === "fullscreen" ? "Dividir" : "Expandir"}</span>
            </button>
            <button
              type="button"
              title="Ocultar bancada manual"
              class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-1.5 py-0.5 text-[11px] text-v2-text-text-muted hover:text-v2-text-text-strong cursor-pointer"
              onClick={() => wb.toggleWorkbench(false)}
            >
              Ocultar
            </button>
          </div>
        </Show>
      </div>

      <AllToolsPickerModal
        open={picker.open}
        query={picker.query}
        onQuery={(q) => setPicker("query", q)}
        onSelect={(toolId) => wb.selectTool(toolId)}
        onClose={() => setPicker("open", false)}
        historiesCount={(toolId) => wb.histories[toolId]?.length ?? 0}
        activeToolId={wb.ui.activeToolId}
      />
    </>
  )
}

/**
 * Barra rápida na tela inicial (Home `/`) caso o usuário ainda não tenha aberto uma sessão/rascunho.
 */
export function CyberLabHomeQuickBar() {
  const wb = useCyberLabWorkbench()
  if (!wb) return null

  return (
    <div class="mx-auto w-full max-w-[1080px] px-3 pt-3 lg:px-6 shrink-0">
      <CyberLabComposerToolbar />
    </div>
  )
}
