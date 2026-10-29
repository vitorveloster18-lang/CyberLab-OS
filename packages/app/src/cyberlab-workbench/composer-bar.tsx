import { createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js"
import { Portal } from "solid-js/web"
import { Icon } from "@opencode/ui/icon"
import type { ComposerModel } from "@/composer/model"
import { useCyberLabWorkbench, type CyberLabWorkbenchService } from "./state"

export function ArsenalQuickPickerDialog(props: {
  open: boolean
  wb: CyberLabWorkbenchService
  onClose: () => void
}) {
  const [query, setQuery] = createSignal("")

  const filteredSlots = createMemo(() => {
    const slots = props.wb.backend.arsenal?.slots ?? []
    const q = query().trim().toLowerCase()
    if (!q) return slots
    return slots.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.shortLabel.toLowerCase().includes(q) ||
        s.tagline.toLowerCase().includes(q) ||
        s.slotId.toLowerCase().includes(q),
    )
  })

  return (
    <Show when={props.open}>
      <Portal>
        <div
          class="fixed inset-0 z-[130] flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
          onClick={props.onClose}
        >
          <div
            data-slot="cyberlab-arsenal-picker"
            class="flex max-h-[82vh] w-full max-w-[640px] flex-col overflow-hidden rounded-xl border border-v2-border-border-base bg-v2-background-bg-base shadow-[var(--v2-elevation-floating)] select-text"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="flex items-center justify-between gap-3 border-b border-v2-border-border-base bg-v2-background-bg-deep/70 px-4 py-3">
              <div class="flex items-center gap-2.5">
                <span class="inline-flex size-8 items-center justify-center rounded-lg bg-emerald-600/15 text-emerald-500">
                  <Icon name="shield" class="size-4" />
                </span>
                <div>
                  <div class="text-[14px] font-semibold text-v2-text-text-strong">
                    Arsenal Real CyberLab OS v5.0 (Modo Antigravity)
                  </div>
                  <div class="text-[11px] text-v2-text-text-muted">
                    Pastas/Outputs retráteis à esquerda · Ferramenta Real no centro · Agente OpenCode retrátil à direita
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

            {/* Atalhos Rápidos de Visão */}
            <div class="flex flex-wrap gap-1.5 border-b border-v2-border-border-base bg-v2-background-bg-deep/35 px-4 py-2">
              <button
                type="button"
                class="rounded-md bg-emerald-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                onClick={() => {
                  props.wb.openWorkspace({ view: "tool" })
                  props.onClose()
                }}
              >
                ⚡ Abrir Bancada 3 Colunas
              </button>
              <button
                type="button"
                class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                onClick={() => {
                  props.wb.openWorkspace({ view: "scope" })
                  props.onClose()
                }}
              >
                🎯 Escopo Bug Bounty
              </button>
              <button
                type="button"
                class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                onClick={() => {
                  props.wb.openWorkspace({ view: "labs" })
                  props.onClose()
                }}
              >
                🧪 5 Labs de Treino
              </button>
              <button
                type="button"
                class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                onClick={() => {
                  props.wb.openWorkspace({ view: "cdi" })
                  props.onClose()
                }}
              >
                🤝 4 CDIs Autônomos
              </button>
              <button
                type="button"
                class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-sky-400 hover:border-sky-400 cursor-pointer"
                onClick={() => {
                  props.wb.openWorkspace({ view: "guide" })
                  props.onClose()
                }}
              >
                📦 Guia PowerShell + WSL2
              </button>
            </div>

            <div class="border-b border-v2-border-border-base px-4 py-2">
              <input
                type="text"
                autofocus
                value={query()}
                placeholder="Filtrar ferramenta real (Burp Suite, OpenTRAP, CyberChef, Nuclei, ffuf, Nmap, Ghidra, JADX, KeyHunter, Kali)..."
                class="w-full rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-3 py-1.5 text-[12px] text-v2-text-text-strong outline-none focus:border-emerald-500"
                onInput={(e) => setQuery(e.currentTarget.value)}
              />
            </div>

            <div class="min-h-0 flex-1 overflow-y-auto p-3 grid grid-cols-1 sm:grid-cols-2 gap-2" data-scrollable>
              <For each={filteredSlots()}>
                {(slot) => (
                  <button
                    type="button"
                    class="flex flex-col gap-1 rounded-lg border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 text-left hover:border-emerald-500 hover:bg-v2-background-bg-deep/80 cursor-pointer transition-colors"
                    onClick={() => {
                      props.wb.selectSlot(slot.slotId)
                      props.onClose()
                    }}
                  >
                    <div class="flex items-center justify-between gap-2">
                      <span class="truncate text-[12.5px] font-semibold text-v2-text-text-strong">
                        {slot.name}
                      </span>
                      <span
                        class={`shrink-0 rounded px-1.5 py-0.5 text-[9.5px] font-medium ${
                          slot.installed
                            ? "bg-emerald-600/20 text-emerald-400"
                            : "bg-zinc-500/15 text-v2-text-text-muted"
                        }`}
                      >
                        {slot.installed ? "Instalado" : "Slot pronto"}
                      </span>
                    </div>
                    <span class="line-clamp-2 text-[11px] text-v2-text-text-muted">{slot.tagline}</span>
                  </button>
                )}
              </For>
            </div>
          </div>
        </div>
      </Portal>
    </Show>
  )
}

export function CyberLabComposerToolbar(props: { model?: ComposerModel }) {
  const wb = useCyberLabWorkbench()
  const [pickerOpen, setPickerOpen] = createSignal(false)

  onMount(() => {
    if (!wb || !props.model) return
    const unregister = wb.registerComposer(props.model)
    onCleanup(unregister)
  })

  if (!wb) return null

  const installedCount = createMemo(
    () => (wb.backend.arsenal?.slots ?? []).filter((s) => s.installed).length,
  )

  return (
    <>
      <div
        data-slot="cyberlab-composer-toolbar"
        class="flex flex-wrap items-center justify-between gap-2 pt-0.5"
      >
        <button
          type="button"
          data-action="open-cyberlab-tools-catalog"
          title="Abrir Arsenal Real CyberLab OS (Modo Antigravity 3 Colunas)"
          class={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[12px] font-medium cursor-pointer transition-colors ${
            wb.ui.open
              ? "border-emerald-600/60 bg-emerald-600/15 text-emerald-500 hover:bg-emerald-600/25"
              : "border-v2-border-border-base bg-v2-background-bg-deep/65 text-v2-text-text-strong hover:border-emerald-600/50 hover:bg-v2-background-bg-deep"
          }`}
          onClick={() => setPickerOpen(true)}
        >
          <Icon name="shield" class="size-3.5 text-emerald-500" />
          <span>
            {wb.ui.open
              ? `Arsenal: ${wb.activeSlot()?.shortLabel ?? "Ativo"}`
              : "Arsenal Real (Modo Antigravity)"}
          </span>
          <Show when={(wb.backend.arsenal?.slots.length ?? 0) > 0}>
            <span class="rounded-full bg-emerald-600/20 px-1.5 py-0.2 text-[10px] font-medium text-emerald-500">
              {installedCount()}/{wb.backend.arsenal?.slots.length}
            </span>
          </Show>
          <Icon name="chevron-down" class="size-3 text-v2-text-text-muted" />
        </button>

        <Show when={!wb.ui.open}>
          <button
            type="button"
            class="inline-flex items-center gap-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/60 px-2.5 py-1 text-[11px] text-emerald-500 hover:border-emerald-500 cursor-pointer"
            onClick={() => wb.toggleWorkbench(true)}
          >
            <Icon name="split" class="size-3" />
            <span>Abrir 3 Colunas</span>
          </button>
        </Show>
      </div>

      <ArsenalQuickPickerDialog open={pickerOpen()} wb={wb} onClose={() => setPickerOpen(false)} />
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
