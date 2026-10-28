import { createMemo, For, onCleanup, onMount, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Portal } from "solid-js/web"
import { Icon } from "@opencode/ui/icon"
import type { ComposerModel } from "@/composer/model"
import { getSuiteAllToolIds, getSuiteMeta, TOOL_SUITES } from "./catalog"
import { useCyberLabWorkbench, type CyberLabWorkbenchService } from "./state"
import type { ToolSuiteId } from "./types"

export function VerticalSuitesPickerDialog(props: {
  open: boolean
  wb: CyberLabWorkbenchService
  onClose: () => void
}) {
  const [search, setSearch] = createStore({ query: "" })

  const filteredSuites = createMemo(() => {
    const q = search.query.trim().toLowerCase()
    if (!q) return TOOL_SUITES
    return TOOL_SUITES.filter(
      (suite) =>
        suite.title.toLowerCase().includes(q) ||
        suite.subtitle.toLowerCase().includes(q) ||
        suite.keywords.some((k) => k.includes(q)) ||
        suite.functions.some(
          (fn) =>
            fn.label.toLowerCase().includes(q) ||
            fn.engines.some((eng) => eng.label.toLowerCase().includes(q)),
        ),
    )
  })

  const suiteHistoryCount = (suiteId: ToolSuiteId) =>
    getSuiteAllToolIds(suiteId).reduce((sum, toolId) => sum + (props.wb.histories[toolId]?.length ?? 0), 0)

  return (
    <Show when={props.open}>
      <Portal>
        <div
          class="fixed inset-0 z-[130] flex items-center justify-center bg-black/50 p-4 backdrop-blur-[1px]"
          onClick={props.onClose}
        >
          <div
            data-slot="cyberlab-suites-vertical-box"
            class="flex max-h-[80vh] w-full max-w-[560px] flex-col overflow-hidden rounded-xl border border-v2-border-border-base bg-v2-background-bg-base shadow-[var(--v2-elevation-floating)] select-text"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div class="flex items-center justify-between gap-3 border-b border-v2-border-border-base bg-v2-background-bg-deep/60 px-4 py-3">
              <div class="flex items-center gap-2.5">
                <span class="inline-flex size-7 items-center justify-center rounded-lg bg-emerald-600/15 text-emerald-500">
                  <Icon name="shield" class="size-4" />
                </span>
                <div>
                  <div class="text-[14px] font-medium leading-[var(--line-height-compact)] text-v2-text-text-strong">
                    Ferramentas Manuais do CyberLab OS
                  </div>
                  <div class="text-[11px] text-v2-text-text-muted">
                    Escolha a suíte desejada — dentro de cada uma você alterna entre suas funções
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

            {/* Busca rápida opcional */}
            <div class="border-b border-v2-border-border-base px-4 py-2">
              <input
                type="text"
                autofocus
                value={search.query}
                placeholder="Filtrar (ex.: Repeater, Proxy, Nuclei, Nmap, TLS, PCAP, APK, CDI, Escopo)..."
                class="w-full rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-3 py-1.5 text-[12px] text-v2-text-text-strong outline-none focus:border-emerald-500"
                onInput={(e) => setSearch("query", e.currentTarget.value)}
              />
            </div>

            {/* Lista em Rolagem Vertical Única — Apenas Ferramentas Distintas */}
            <div class="min-h-0 flex-1 overflow-y-auto p-3 flex flex-col gap-2" data-scrollable>
              <For each={filteredSuites()}>
                {(suite) => {
                  const isCurrent = () => props.wb.ui.open && props.wb.ui.activeSuiteId === suite.id
                  const savedCount = () => suiteHistoryCount(suite.id)

                  return (
                    <div
                      class={`rounded-lg border p-3 transition-colors cursor-pointer ${
                        isCurrent()
                          ? "border-emerald-600 bg-emerald-600/10"
                          : "border-v2-border-border-base bg-v2-background-bg-deep/35 hover:bg-v2-background-bg-deep/75"
                      }`}
                      onClick={() => {
                        props.wb.selectSuite(suite.id)
                        props.onClose()
                      }}
                    >
                      <div class="flex items-start gap-3">
                        <span class="mt-0.5 inline-flex size-8 shrink-0 items-center justify-center rounded-lg border border-v2-border-border-base bg-v2-background-bg-base text-emerald-500">
                          <Icon name={suite.icon} class="size-4" />
                        </span>

                        <div class="min-w-0 flex-1">
                          <div class="flex items-center justify-between gap-2">
                            <span class="text-[13px] font-medium text-v2-text-text-strong">{suite.title}</span>
                            <div class="flex items-center gap-1.5 shrink-0">
                              <Show when={savedCount() > 0}>
                                <span class="rounded-full bg-emerald-600/20 px-2 py-0.5 text-[10px] font-medium text-emerald-500">
                                  {savedCount()} no histórico
                                </span>
                              </Show>
                              <Show when={isCurrent()}>
                                <span class="rounded bg-emerald-600 px-1.5 py-0.5 text-[10px] font-medium text-white">
                                  Ativa
                                </span>
                              </Show>
                            </div>
                          </div>

                          <p class="mt-0.5 text-[11px] leading-[var(--line-height-compact)] text-v2-text-text-muted">
                            {suite.subtitle}
                          </p>

                          {/* Atalhos diretos para abrir já na função interna específica, se desejar */}
                          <Show when={suite.functions.length > 1}>
                            <div class="mt-2 flex flex-wrap gap-1">
                              <For each={suite.functions}>
                                {(fn) => (
                                  <button
                                    type="button"
                                    class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-0.5 text-[10px] text-v2-text-text-base hover:border-emerald-500/60 hover:text-emerald-500 cursor-pointer"
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      props.wb.selectSuite(suite.id, fn.id)
                                      props.onClose()
                                    }}
                                  >
                                    {fn.label}
                                  </button>
                                )}
                              </For>
                            </div>
                          </Show>
                        </div>
                      </div>
                    </div>
                  )
                }}
              </For>
            </div>
          </div>
        </div>
      </Portal>
    </Show>
  )
}

/**
 * Único botão limpo posicionado abaixo da caixa de diálogo (sem barra de rolagem lateral).
 * Abre a caixa vertical das suítes de ferramentas e permite alternar/expandir/ocultar.
 */
export function CyberLabComposerToolbar(props: { model?: ComposerModel }) {
  const wb = useCyberLabWorkbench()
  const [box, setBox] = createStore({ open: false })

  onMount(() => {
    if (!wb || !props.model) return
    const unregister = wb.registerComposer(props.model)
    onCleanup(unregister)
  })

  if (!wb) return null

  const activeSuite = createMemo(() => getSuiteMeta(wb.ui.activeSuiteId))
  const totalHistory = createMemo(() =>
    TOOL_SUITES.reduce(
      (sum, s) =>
        sum + getSuiteAllToolIds(s.id).reduce((acc, toolId) => acc + (wb.histories[toolId]?.length ?? 0), 0),
      0,
    ),
  )

  return (
    <>
      <div
        data-slot="cyberlab-composer-toolbar"
        class="flex flex-wrap items-center justify-between gap-2 pt-0.5"
      >
        {/* UM ÚNICO BOTÃO LIMPO para abrir a caixa vertical de ferramentas */}
        <button
          type="button"
          data-action="open-cyberlab-tools-catalog"
          title="Escolher ou alternar ferramenta manual do CyberLab OS"
          class={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[12px] font-medium cursor-pointer transition-colors ${
            wb.ui.open
              ? "border-emerald-600/60 bg-emerald-600/15 text-emerald-500 hover:bg-emerald-600/25"
              : "border-v2-border-border-base bg-v2-background-bg-deep/65 text-v2-text-text-strong hover:border-emerald-600/50 hover:bg-v2-background-bg-deep"
          }`}
          onClick={() => setBox("open", true)}
        >
          <Icon name={wb.ui.open ? activeSuite().icon : "shield"} class="size-3.5 text-emerald-500" />
          <span>
            {wb.ui.open ? `Ferramenta: ${activeSuite().title}` : "Ferramentas Manuais"}
          </span>
          <Show when={totalHistory() > 0}>
            <span class="rounded-full bg-emerald-600/20 px-1.5 py-0.2 text-[10px] font-medium text-emerald-500">
              {totalHistory()}
            </span>
          </Show>
          <Show when={wb.backend.approvals.length > 0}>
            <span class="rounded-full bg-amber-500/20 px-1.5 py-0.2 text-[10px] font-medium text-amber-500">
              {wb.backend.approvals.length} pendente
            </span>
          </Show>
          <Icon name="chevron-down" class="size-3 text-v2-text-text-muted" />
        </button>

        {/* Controles discretos quando uma ferramenta está aberta na tela */}
        <Show when={wb.ui.open}>
          <div class="flex items-center gap-1.5">
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/60 px-2.5 py-1 text-[11px] text-v2-text-text-base hover:text-v2-text-text-strong cursor-pointer"
              onClick={() => wb.setLayoutMode(wb.ui.layoutMode === "fullscreen" ? "split" : "fullscreen")}
            >
              <Icon name={wb.ui.layoutMode === "fullscreen" ? "split" : "expand"} class="size-3" />
              <span>{wb.ui.layoutMode === "fullscreen" ? "Dividir c/ Chat" : "Tela Cheia"}</span>
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/60 px-2.5 py-1 text-[11px] text-v2-text-text-muted hover:text-v2-text-text-strong cursor-pointer"
              onClick={() => wb.toggleWorkbench(false)}
            >
              <Icon name="close" class="size-3" />
              <span>Fechar Bancada</span>
            </button>
          </div>
        </Show>
      </div>

      <VerticalSuitesPickerDialog open={box.open} wb={wb} onClose={() => setBox("open", false)} />
    </>
  )
}

export function CyberLabHomeQuickBar() {
  const wb = useCyberLabWorkbench()
  if (!wb) return null

  return (
    <div class="mx-auto w-full max-w-[1080px] px-3 pt-3 lg:px-6 shrink-0">
      <CyberLabComposerToolbar />
    </div>
  )
}
