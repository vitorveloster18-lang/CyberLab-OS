import { createMemo, createSignal, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Icon } from "@opencode/ui/icon"
import { useCyberLabWorkbench, type CyberLabWorkbenchService } from "./state"
import type { ArsenalRuntimePrefDto, ArsenalSlotKindDto, ArsenalSlotStatusDto, CenterViewMode } from "./types"
import { CyberLabVaultOverlay } from "./vault-overlay"

function copyText(wb: CyberLabWorkbenchService, text: string, label = "Comando") {
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    void navigator.clipboard.writeText(text)
    wb.setNotice(`${label} copiado para a área de transferência!`)
  }
}

function runtimeBadgeLabel(rt: ArsenalSlotStatusDto["activeRuntime"]) {
  if (rt === "windows") return "Win Nativo"
  if (rt === "wsl") return "WSL2 Kali"
  if (rt === "linux_mac") return "Linux/Host"
  if (rt === "web") return "Web Local"
  return "Não instalado"
}

function kindBadgeLabel(kind: ArsenalSlotKindDto) {
  if (kind === "web_embed") return "WEB UI EMBUTIDA"
  if (kind === "desktop_gui") return "DESKTOP / WSLg"
  return "CLI AO VIVO"
}

/**
 * COLUNA ESQUERDA (ESTILO ANTIGRAVITY):
 * Pastas/Arquivos do Projeto + Outputs (.cyberlab/outputs) + Slots do Arsenal Real + Custom Slots.
 * Recolhe para uma barra vertical estreita de 38px quando não usada!
 */
export function CyberLabLeftExplorer() {
  const wb = useCyberLabWorkbench()
  const [showCustomModal, setShowCustomModal] = createSignal(false)
  const [customDraft, setCustomDraft] = createStore<{
    name: string
    shortLabel: string
    kind: ArsenalSlotKindDto
    executableOrUrl: string
    preferredRuntime: ArsenalRuntimePrefDto
    defaultArgsTemplate: string
    companionProxyPort: string
    tagline: string
  }>({
    name: "",
    shortLabel: "",
    kind: "cli_runner",
    executableOrUrl: "",
    preferredRuntime: "auto",
    defaultArgsTemplate: "{target}",
    companionProxyPort: "",
    tagline: "",
  })

  if (!wb) return null

  const filteredSlots = createMemo(() => {
    const slots = wb.backend.arsenal?.slots ?? []
    const q = wb.ui.slotSearch.trim().toLowerCase()
    const cat = wb.ui.categoryFilter
    return slots.filter((s) => {
      if (cat !== "all" && s.category !== cat) return false
      if (!q) return true
      return (
        s.name.toLowerCase().includes(q) ||
        s.shortLabel.toLowerCase().includes(q) ||
        s.tagline.toLowerCase().includes(q) ||
        s.slotId.toLowerCase().includes(q)
      )
    })
  })

  const groupedSlots = createMemo(() => {
    const cats = wb.backend.arsenal?.categories ?? []
    const list = filteredSlots()
    const groups: Array<{ id: string; title: string; items: ArsenalSlotStatusDto[] }> = []
    for (const c of cats) {
      const items = list.filter((s) => s.category === c.id)
      if (items.length > 0) groups.push({ id: c.id, title: c.title, items })
    }
    const customItems = list.filter((s) => s.category === "custom")
    if (customItems.length > 0 && !groups.some((g) => g.id === "custom")) {
      groups.push({ id: "custom", title: "Meus Slots Personalizados", items: customItems })
    }
    return groups
  })

  return (
    <Show
      when={wb.ui.leftSidebarOpen}
      fallback={
        <aside
          data-slot="cyberlab-left-rail-collapsed"
          class="flex h-full w-[38px] shrink-0 flex-col items-center justify-between border-r border-v2-border-border-base bg-v2-background-bg-deep/80 py-2 select-none"
        >
          <div class="flex flex-col items-center gap-2">
            <button
              type="button"
              title="Expandir Pastas & Arsenal (Esquerda)"
              class="inline-flex size-7 items-center justify-center rounded-md border border-v2-border-border-base bg-v2-background-bg-base text-emerald-500 hover:border-emerald-500 cursor-pointer"
              onClick={() => wb.toggleLeftSidebar(true)}
            >
              <Icon name="chevron-right" class="size-3.5" />
            </button>
            <button
              type="button"
              title="Abrir Slots do Arsenal Real"
              class="inline-flex size-7 items-center justify-center rounded-md text-v2-text-text-muted hover:bg-v2-background-bg-base hover:text-emerald-500 cursor-pointer"
              onClick={() => wb.setLeftSidebarTab("slots")}
            >
              <Icon name="shield" class="size-3.5" />
            </button>
            <button
              type="button"
              title="Abrir Pastas, Outputs e Imports"
              class="inline-flex size-7 items-center justify-center rounded-md text-v2-text-text-muted hover:bg-v2-background-bg-base hover:text-emerald-500 cursor-pointer"
              onClick={() => wb.setLeftSidebarTab("files")}
            >
              <Icon name="folder" class="size-3.5" />
            </button>
          </div>
          <div class="text-[9px] font-medium tracking-widest text-v2-text-text-muted [writing-mode:vertical-rl] rotate-180">
            PASTAS & ARSENAL
          </div>
        </aside>
      }
    >
      <aside
        data-slot="cyberlab-left-explorer"
        style={{ width: `${wb.ui.leftSidebarWidth}px` }}
        class="flex h-full max-h-full min-h-0 shrink-0 flex-col overflow-hidden border-r border-v2-border-border-base bg-v2-background-bg-deep/55 select-text"
      >
        {/* Cabeçalho Compacto c/ Abas Slots | Pastas + Botão Recolher */}
        <div class="flex items-center justify-between gap-1 border-b border-v2-border-border-base px-2.5 py-2">
          <div class="flex items-center gap-1 rounded-lg bg-v2-background-bg-base p-0.5 border border-v2-border-border-base">
            <button
              type="button"
              class={`rounded-md px-2.5 py-1 text-[11px] font-medium cursor-pointer transition-colors ${
                wb.ui.leftSidebarTab === "slots"
                  ? "bg-emerald-600 text-white"
                  : "text-v2-text-text-muted hover:text-v2-text-text-strong"
              }`}
              onClick={() => wb.setLeftSidebarTab("slots")}
            >
              Arsenal ({wb.backend.arsenal?.slots.length ?? 0})
            </button>
            <button
              type="button"
              class={`rounded-md px-2.5 py-1 text-[11px] font-medium cursor-pointer transition-colors ${
                wb.ui.leftSidebarTab === "files"
                  ? "bg-emerald-600 text-white"
                  : "text-v2-text-text-muted hover:text-v2-text-text-strong"
              }`}
              onClick={() => {
                wb.setLeftSidebarTab("files")
                void wb.browseFiles(wb.ui.currentFilesDir)
              }}
            >
              Pastas & Outputs
            </button>
          </div>

          <button
            type="button"
            title="Recolher barra esquerda"
            class="inline-flex size-6 items-center justify-center rounded-md text-v2-text-text-muted hover:bg-v2-background-bg-base hover:text-v2-text-text-strong cursor-pointer"
            onClick={() => wb.toggleLeftSidebar(false)}
          >
            <Icon name="chevron-left" class="size-3.5" />
          </button>
        </div>

        {/* ABA 1: SLOTS DO ARSENAL REAL + CUSTOM SLOTS */}
        <Show when={wb.ui.leftSidebarTab === "slots"}>
          <div class="flex flex-col gap-1.5 border-b border-v2-border-border-base p-2">
            <div class="flex items-center gap-1">
              <input
                type="text"
                value={wb.ui.slotSearch}
                placeholder="Buscar (Burp, OpenTRAP, Nuclei, CyberChef, Kali)..."
                class="min-w-0 flex-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-strong outline-none focus:border-emerald-500"
                onInput={(e) => wb.setUi("slotSearch", e.currentTarget.value)}
              />
              <button
                type="button"
                disabled={wb.ui.probing}
                title="Re-escanear Windows + WinGet + WSL2 Kali agora"
                class={`inline-flex shrink-0 items-center gap-1 rounded-md border px-2 py-1 text-[10.5px] font-medium cursor-pointer transition-colors ${
                  wb.ui.probing
                    ? "border-emerald-500 bg-emerald-600/20 text-emerald-400"
                    : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-base hover:border-emerald-500 hover:text-emerald-400"
                }`}
                onClick={() => void wb.refreshArsenalOnly(true)}
              >
                <Icon name="refresh" class={`size-3.5 ${wb.ui.probing ? "animate-spin text-emerald-400" : ""}`} />
                <span>{wb.ui.probing ? "Lendo..." : "Atualizar"}</span>
              </button>
            </div>

            <div class="flex items-center justify-between gap-1">
              <select
                value={wb.ui.categoryFilter}
                class="min-w-0 flex-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 text-[10.5px] text-v2-text-text-base outline-none"
                onChange={(e) => wb.setUi("categoryFilter", e.currentTarget.value)}
              >
                <option value="all">Todas as Categorias</option>
                <For each={wb.backend.arsenal?.categories ?? []}>
                  {(cat) => <option value={cat.id}>{cat.title}</option>}
                </For>
              </select>

              <button
                type="button"
                class="inline-flex shrink-0 items-center gap-1 rounded-md border border-emerald-600/50 bg-emerald-600/15 px-2 py-1 text-[10.5px] font-medium text-emerald-500 hover:bg-emerald-600/25 cursor-pointer"
                onClick={() => setShowCustomModal((v) => !v)}
              >
                <Icon name="plus" class="size-3" />
                <span>Slot</span>
              </button>
            </div>

            {/* Botão de 1 Clique para instalar automaticamente todas as ferramentas faltantes */}
            <Show
              when={(wb.backend.arsenal?.slots.filter((s) => !s.installed && !s.isCustom).length ?? 0) > 0}
            >
              <button
                type="button"
                disabled={wb.ui.busy}
                class="flex w-full items-center justify-center gap-1.5 rounded-md bg-emerald-600 px-2.5 py-1.5 text-[11px] font-semibold text-white hover:bg-emerald-500 cursor-pointer disabled:opacity-60"
                onClick={() =>
                  void wb.launchSlot({
                    slotId: "__all_missing__",
                    action: "install_tool",
                  })
                }
              >
                <span>
                  ⚡ Instalar Faltantes (
                  {wb.backend.arsenal?.slots.filter((s) => !s.installed && !s.isCustom).length ?? 0}
                  ) em 1 Clique
                </span>
              </button>
            </Show>

            {/* Diagnóstico de Higiene do Arsenal (v6.3.1) — slots personalizados quebrados/duplicados */}
            <Show when={(wb.backend.arsenal?.health?.length ?? 0) > 0}>
              <div class="mt-1 rounded-lg border border-amber-500/50 bg-amber-500/10 p-2.5 text-[11px]">
                <div class="mb-1.5 flex items-center justify-between gap-2">
                  <span class="font-semibold text-amber-400">
                    ⚠️ {wb.backend.arsenal?.health?.length ?? 0} problema(s) de slot personalizado
                  </span>
                  <button
                    type="button"
                    disabled={wb.ui.busy}
                    class="rounded bg-amber-500/25 px-2 py-0.5 text-[10px] font-semibold text-amber-200 hover:bg-amber-500/40 cursor-pointer disabled:opacity-60"
                    onClick={() => void wb.pruneBrokenCustomSlots()}
                  >
                    🧹 Limpar Fantasmas & Duplicatas
                  </button>
                </div>
                <div class="flex flex-col gap-1.5">
                  <For each={wb.backend.arsenal?.health ?? []}>
                    {(issue) => (
                      <div class="rounded border border-amber-500/25 bg-zinc-950/70 p-1.5">
                        <div class="flex items-start justify-between gap-2">
                          <div class="min-w-0 flex-1">
                            <div class="truncate font-medium text-v2-text-text-strong">
                              {issue.kind === "ghost_custom_slot"
                                ? "👻"
                                : issue.kind === "duplicate_custom_slot"
                                  ? "👥"
                                  : issue.kind === "non_executable_target"
                                    ? "📄"
                                    : "⚙️"}{" "}
                              {issue.name}{" "}
                              <span class="font-mono text-[10px] text-v2-text-text-weak">
                                ({issue.slotId})
                              </span>
                            </div>
                            <div class="mt-0.5 text-[10.5px] text-v2-text-text-base">{issue.message}</div>
                            <Show when={issue.configuredPath}>
                              <div class="mt-0.5 truncate font-mono text-[10px] text-v2-text-text-weak">
                                {issue.configuredPath}
                              </div>
                            </Show>
                            <div class="mt-0.5 text-[10.5px] text-amber-300">→ {issue.suggestion}</div>
                          </div>
                          <button
                            type="button"
                            title="Remover este slot personalizado"
                            disabled={wb.ui.busy}
                            class="shrink-0 rounded border border-red-500/40 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 cursor-pointer disabled:opacity-60"
                            onClick={() => void wb.removeCustomSlot(issue.slotId)}
                          >
                            Remover
                          </button>
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </div>
            </Show>

            {/* Formulário Rápido p/ Criar Novo Slot Custom */}
            <Show when={showCustomModal()}>
              <div class="mt-1 flex flex-col gap-1.5 rounded-lg border border-emerald-600/40 bg-v2-background-bg-base p-2.5 text-[11px]">
                <div class="font-medium text-emerald-500">Novo Slot Personalizado</div>
                <input
                  type="text"
                  placeholder="Nome (ex.: Feroxbuster / BloodHound)"
                  value={customDraft.name}
                  class="rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1 text-[11px] text-v2-text-text-strong"
                  onInput={(e) => setCustomDraft("name", e.currentTarget.value)}
                />
                <div class="grid grid-cols-2 gap-1">
                  <select
                    value={customDraft.kind}
                    class="rounded border border-v2-border-border-base bg-v2-background-bg-deep px-1.5 py-1 text-[10.5px] text-v2-text-text-strong"
                    onChange={(e) => setCustomDraft("kind", e.currentTarget.value as ArsenalSlotKindDto)}
                  >
                    <option value="cli_runner">CLI Runner</option>
                    <option value="web_embed">Web UI (iframe)</option>
                    <option value="desktop_gui">Desktop / WSLg</option>
                  </select>
                  <select
                    value={customDraft.preferredRuntime}
                    class="rounded border border-v2-border-border-base bg-v2-background-bg-deep px-1.5 py-1 text-[10.5px] text-v2-text-text-strong"
                    onChange={(e) =>
                      setCustomDraft("preferredRuntime", e.currentTarget.value as ArsenalRuntimePrefDto)
                    }
                  >
                    <option value="auto">Auto (Win/WSL2)</option>
                    <option value="windows">Windows Nativo</option>
                    <option value="wsl">WSL2 Kali Linux</option>
                  </select>
                </div>
                <input
                  type="text"
                  placeholder={
                    customDraft.kind === "web_embed"
                      ? "URL Local (ex.: http://127.0.0.1:8085)"
                      : "Binário ou caminho (ex.: feroxbuster ou C:\\Tools\\app.exe)"
                  }
                  value={customDraft.executableOrUrl}
                  class="rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1 text-[11px] text-v2-text-text-strong"
                  onInput={(e) => setCustomDraft("executableOrUrl", e.currentTarget.value)}
                />
                <Show when={customDraft.kind === "cli_runner"}>
                  <input
                    type="text"
                    placeholder="Args padrão (ex.: -u {target} -w wordlist.txt)"
                    value={customDraft.defaultArgsTemplate}
                    class="rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1 text-[11px] text-v2-text-text-strong"
                    onInput={(e) => setCustomDraft("defaultArgsTemplate", e.currentTarget.value)}
                  />
                </Show>
                <div class="flex items-center justify-end gap-1.5 pt-1">
                  <button
                    type="button"
                    class="rounded px-2 py-0.5 text-[10.5px] text-v2-text-text-muted hover:text-v2-text-text-strong cursor-pointer"
                    onClick={() => setShowCustomModal(false)}
                  >
                    Cancelar
                  </button>
                  <button
                    type="button"
                    class="rounded bg-emerald-600 px-2.5 py-1 text-[10.5px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                    onClick={() => {
                      if (!customDraft.name.trim() || !customDraft.executableOrUrl.trim()) return
                      const portNum = Number.parseInt(customDraft.companionProxyPort, 10)
                      void wb.upsertCustomSlot({
                        name: customDraft.name.trim(),
                        shortLabel: customDraft.shortLabel.trim() || customDraft.name.trim().slice(0, 14),
                        kind: customDraft.kind,
                        executableOrUrl: customDraft.executableOrUrl.trim(),
                        preferredRuntime: customDraft.preferredRuntime,
                        defaultArgsTemplate: customDraft.defaultArgsTemplate,
                        ...(Number.isFinite(portNum) && portNum > 0 ? { companionProxyPort: portNum } : {}),
                        ...(customDraft.tagline.trim() ? { tagline: customDraft.tagline.trim() } : {}),
                      })
                      setShowCustomModal(false)
                    }}
                  >
                    Salvar Slot
                  </button>
                </div>
              </div>
            </Show>
          </div>

          <div
            class="min-h-0 flex-1 overflow-y-scroll overscroll-contain p-2 pr-1.5 pb-8 flex flex-col gap-3 [scrollbar-width:thin] [scrollbar-color:#10b981_transparent]"
            data-scrollable
          >
            <For each={groupedSlots()}>
              {(group) => (
                <div class="flex flex-col gap-1">
                  <div class="px-1.5 text-[10px] font-semibold uppercase tracking-wider text-v2-text-text-muted">
                    {group.title}
                  </div>
                  <For each={group.items}>
                    {(slot) => {
                      const selected = () =>
                        wb.ui.centerView === "tool" && wb.activeSlot()?.slotId === slot.slotId
                      const runningHere = () =>
                        wb.backend.arsenal?.runs.some(
                          (r) => r.slotId === slot.slotId && r.status === "running",
                        )

                      return (
                        <button
                          type="button"
                          class={`flex w-full flex-col gap-0.5 rounded-lg border px-2.5 py-1.5 text-left transition-colors cursor-pointer ${
                            selected()
                              ? "border-emerald-500 bg-emerald-600/15"
                              : "border-transparent hover:border-v2-border-border-base hover:bg-v2-background-bg-base/75"
                          }`}
                          onClick={() => wb.selectSlot(slot.slotId)}
                        >
                          <div class="flex items-center justify-between gap-1.5">
                            <span class="truncate text-[12px] font-medium text-v2-text-text-strong">
                              {slot.shortLabel}
                            </span>
                            <div class="flex items-center gap-1 shrink-0">
                              <Show when={runningHere()}>
                                <span class="size-2 rounded-full bg-amber-400 animate-pulse" />
                              </Show>
                              <Show when={slot.mcpCapable}>
                                <span
                                  title={
                                    slot.mcpConnected
                                      ? `MCP conectado ao Agente OpenCode (${slot.mcpLabel ?? slot.shortLabel})`
                                      : `Conexão MCP disponível (${slot.mcpLabel ?? slot.shortLabel}) — clique no slot p/ conectar`
                                  }
                                  class={`rounded border px-1.5 py-0.2 text-[9px] font-semibold tracking-tight ${
                                    slot.mcpConnected
                                      ? "border-emerald-500/60 bg-emerald-500/20 text-emerald-300"
                                      : "border-violet-500/40 bg-violet-500/15 text-violet-300"
                                  }`}
                                >
                                  {slot.mcpConnected ? "🟢 MCP" : "🔌 MCP"}
                                </span>
                              </Show>
                              <span
                                class={`rounded px-1.5 py-0.2 text-[9.5px] font-medium ${
                                  slot.installed
                                    ? "bg-emerald-600/20 text-emerald-500"
                                    : "bg-zinc-500/15 text-v2-text-text-muted"
                                }`}
                              >
                                {runtimeBadgeLabel(slot.activeRuntime)}
                              </span>
                            </div>
                          </div>
                          <div class="truncate text-[10.5px] text-v2-text-text-muted">{slot.tagline}</div>
                        </button>
                      )
                    }}
                  </For>
                </div>
              )}
            </For>
          </div>
        </Show>

        {/* ABA 2: PASTAS, ARQUIVOS DO PROJETO, .cyberlab/outputs E UPLOAD */}
        <Show when={wb.ui.leftSidebarTab === "files"}>
          <div class="flex flex-col gap-1.5 border-b border-v2-border-border-base p-2">
            <div class="flex flex-wrap items-center gap-1">
              <button
                type="button"
                class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-0.5 text-[10px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                onClick={() => void wb.browseFiles(".")}
              >
                Raiz (.)
              </button>
              <button
                type="button"
                class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-0.5 text-[10px] text-emerald-500 hover:border-emerald-500 cursor-pointer"
                onClick={() => void wb.browseFiles(".cyberlab/outputs")}
              >
                Outputs
              </button>
              <button
                type="button"
                class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-0.5 text-[10px] text-sky-400 hover:border-sky-400 cursor-pointer"
                onClick={() => void wb.browseFiles(".cyberlab/imports")}
              >
                Imports
              </button>
              <Show when={wb.ui.currentFilesDir !== "."}>
                <button
                  type="button"
                  class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-0.5 text-[10px] text-v2-text-text-muted hover:text-v2-text-text-strong cursor-pointer"
                  onClick={() => {
                    const parts = wb.ui.currentFilesDir.split("/").filter(Boolean)
                    parts.pop()
                    void wb.browseFiles(parts.length ? parts.join("/") : ".")
                  }}
                >
                  ↑ Subir
                </button>
              </Show>
            </div>

            <div class="flex items-center justify-between gap-1 text-[10.5px] text-v2-text-text-muted">
              <span class="truncate font-mono">{wb.ui.currentFilesDir}</span>
              <label class="inline-flex shrink-0 items-center gap-1 rounded border border-emerald-600/50 bg-emerald-600/15 px-2 py-0.5 text-[10px] font-medium text-emerald-500 hover:bg-emerald-600/25 cursor-pointer">
                <span>+ Importar PC</span>
                <input
                  type="file"
                  class="hidden"
                  onChange={(e) => {
                    const f = e.currentTarget.files?.[0]
                    if (f) void wb.uploadExternalFile(f)
                    e.currentTarget.value = ""
                  }}
                />
              </label>
            </div>
          </div>

          <div class="min-h-0 flex-1 overflow-y-auto p-2 flex flex-col gap-1" data-scrollable>
            <For
              each={wb.backend.files}
              fallback={
                <div class="p-3 text-center text-[11px] text-v2-text-text-muted">Pasta vazia.</div>
              }
            >
              {(entry) => (
                <div class="flex items-center justify-between gap-1 rounded-md px-2 py-1 hover:bg-v2-background-bg-base">
                  <button
                    type="button"
                    class="flex min-w-0 flex-1 items-center gap-1.5 text-left cursor-pointer"
                    onClick={() => {
                      if (entry.kind === "directory") {
                        void wb.browseFiles(entry.relativePath)
                      } else {
                        void wb.previewFile(entry.relativePath)
                      }
                    }}
                  >
                    <Icon
                      name={entry.kind === "directory" ? "folder" : "code"}
                      class={`size-3.5 shrink-0 ${entry.kind === "directory" ? "text-amber-400" : "text-v2-text-text-muted"}`}
                    />
                    <span class="truncate text-[11.5px] text-v2-text-text-strong">{entry.name}</span>
                  </button>
                  <Show when={entry.kind === "file"}>
                    <button
                      type="button"
                      title="Usar este arquivo como {target} na ferramenta ativa"
                      class="rounded border border-v2-border-border-base px-1.5 py-0.2 text-[9.5px] text-emerald-500 hover:border-emerald-500 cursor-pointer"
                      onClick={() => {
                        const slot = wb.activeSlot()
                        if (slot) {
                          wb.setUi("cliTargetBySlot", slot.slotId, entry.relativePath)
                          wb.setCenterView("tool")
                          wb.setNotice(`Alvo definido: ${entry.relativePath}`)
                        }
                      }}
                    >
                      Usar
                    </button>
                  </Show>
                </div>
              )}
            </For>

            {/* Preview rápido do arquivo selecionado */}
            <Show when={wb.backend.filePreview}>
              {(prev) => (
                <div class="mt-2 flex flex-col gap-1.5 rounded-lg border border-v2-border-border-base bg-v2-background-bg-base p-2">
                  <div class="flex items-center justify-between gap-1">
                    <span class="truncate font-mono text-[10.5px] font-medium text-emerald-500">
                      {prev().relativePath}
                    </span>
                    <button
                      type="button"
                      class="rounded bg-emerald-600/20 px-1.5 py-0.5 text-[9.5px] font-medium text-emerald-500 hover:bg-emerald-600/30 cursor-pointer"
                      onClick={() =>
                        wb.sendToAgent(
                          `Arquivo ${prev().relativePath}`,
                          prev().content,
                          prev().relativePath.split("/").pop() || "arquivo.txt",
                        )
                      }
                    >
                      Enviar p/ Agente →
                    </button>
                  </div>
                  <pre class="max-h-48 overflow-auto rounded bg-zinc-950 p-2 font-mono text-[10px] text-zinc-200 whitespace-pre-wrap">
                    {prev().content}
                  </pre>
                </div>
              )}
            </Show>
          </div>
        </Show>

        {/* Rodapé da barra esquerda: Pasta Raiz Externa & WSL2 */}
        <div class="border-t border-v2-border-border-base bg-v2-background-bg-base/60 px-2.5 py-1.5 text-[10px] text-v2-text-text-muted flex items-center justify-between gap-2">
          <span class="truncate" title={wb.backend.arsenal?.environment.toolsRootDir}>
            Tools: {wb.backend.arsenal?.environment.toolsRootDir ?? "C:\\CyberLab-Tools"}
          </span>
          <span class="shrink-0 text-emerald-500 font-medium">
            {wb.backend.arsenal?.environment.wslAvailable
              ? `WSL2: ${wb.backend.arsenal.environment.preferredWslDistro}`
              : "Host Nativo"}
          </span>
        </div>
      </aside>
    </Show>
  )
}

/**
 * COLUNA CENTRAL (PALCO PRINCIPAL TELA CHEIA ESTILO ANTIGRAVITY):
 * Ocupa 100% do centro com a Ferramenta Real (Web Embed iframe / Console CLI ao vivo / Bridge Desktop+Browser)
 * ou as visões rápidas de Governança (Escopo Bug Bounty, 5 Labs, 4 CDIs, Custódia SHA-256, Guia PowerShell+WSL2).
 */
export function CyberLabCenterStage() {
  const wb = useCyberLabWorkbench()
  const [scopeRawText, setScopeRawText] = createSignal("")
  const [scopeHandle, setScopeHandle] = createSignal("")
  const [scopeHeaderName, setScopeHeaderName] = createSignal("X-Bug-Bounty")
  const [scopeHeaderVal, setScopeHeaderVal] = createSignal("")
  const [cdiObjective, setCdiObjective] = createSignal("")
  const [cdiCustomSecret, setCdiCustomSecret] = createSignal("")
  const [selectedCdis, setSelectedCdis] = createSignal<string[]>(["kairos", "naia", "salem", "nova"])
  const [findingTitle, setFindingTitle] = createSignal("")
  const [findingDesc, setFindingDesc] = createSignal("")
  const [findingSev, setFindingSev] = createSignal<"info" | "low" | "medium" | "high" | "critical">("high")
  const [desktopIngestText, setDesktopIngestText] = createSignal("")
  const [showDesktopIngestDrawer, setShowDesktopIngestDrawer] = createSignal(false)
  const [dismissedInstallerRunIds, setDismissedInstallerRunIds] = createSignal<string[]>([])
  const [showSlotSettings, setShowSlotSettings] = createSignal(false)
  const [customPathInput, setCustomPathInput] = createSignal("")
  const [customUrlInput, setCustomUrlInput] = createSignal("")
  const [toolsRootInput, setToolsRootInput] = createSignal("")
  const [burpQuickPath, setBurpQuickPath] = createSignal("")
  // v6.6 — navegador do alvo embutido (estilo Burp): { labId: nonce de recarga }
  const [labBrowser, setLabBrowser] = createSignal<Record<string, number>>({})
  const [framingBySlot, setFramingBySlot] = createStore<Record<string, "fit" | "scroll" | "native">>({})
  const [zoomBySlot, setZoomBySlot] = createStore<Record<string, number>>({})
  let activeToolIframeRef: HTMLIFrameElement | undefined

  if (!wb) return null

  const getSlotFraming = (slot: ArsenalSlotStatusDto): "fit" | "scroll" | "native" => {
    const savedMode = framingBySlot[slot.slotId]
    if (savedMode) return savedMode
    if (slot.kind === "web_embed" && slot.slotId !== "kali-desktop-stream") {
      return "scroll"
    }
    return "native"
  }

  const getSlotZoom = (slot: ArsenalSlotStatusDto): number => {
    const savedZoom = zoomBySlot[slot.slotId]
    if (typeof savedZoom === "number") return savedZoom
    return 100
  }

  const syncCanvasControl = (slot: ArsenalSlotStatusDto, nextMode?: "fit" | "scroll" | "native", nextZoom?: number) => {
    const mode = nextMode ?? getSlotFraming(slot)
    const zoom = nextZoom ?? getSlotZoom(slot)
    if (nextMode) setFramingBySlot(slot.slotId, nextMode)
    if (typeof nextZoom === "number") setZoomBySlot(slot.slotId, nextZoom)
    try {
      activeToolIframeRef?.contentWindow?.postMessage(
        { type: "cyberlab-canvas-control", mode, zoom },
        "*",
      )
    } catch {
      // Ignore cross-origin postMessage errors
    }
  }

  const triggerCanvasResizeSync = () => {
    if (typeof window === "undefined") return
    window.requestAnimationFrame(() => {
      const s = wb.activeSlot()
      if (s) syncCanvasControl(s)
      window.setTimeout(() => {
        const s2 = wb.activeSlot()
        if (s2) syncCanvasControl(s2)
      }, 110)
    })
  }

  const toggleTopDrawer = (next?: boolean) => {
    wb.toggleTopControls(next)
    triggerCanvasResizeSync()
  }

  const toggleMaximizeCenter = () => {
    const allCollapsed = !wb.ui.leftSidebarOpen && !wb.ui.rightAgentOpen && !wb.ui.topControlsOpen
    if (allCollapsed) {
      wb.toggleLeftSidebar(true)
      wb.toggleRightAgent(true)
      wb.toggleTopControls(true)
    } else {
      wb.toggleLeftSidebar(false)
      wb.toggleRightAgent(false)
      wb.toggleTopControls(false)
    }
    triggerCanvasResizeSync()
  }

  const navItems: Array<{ id: CenterViewMode; label: string }> = [
    { id: "tool", label: "Ferramenta Ativa" },
    { id: "scope", label: "Escopo Bug Bounty" },
    { id: "labs", label: "5 Labs de Treino" },
    { id: "cdi", label: "4 CDIs Autônomos" },
    { id: "custody", label: "Custódia SHA-256" },
    { id: "guide", label: "Guia PowerShell + WSL2" },
  ]

  const activeNavLabel = createMemo(
    () => navItems.find((i) => i.id === wb.ui.centerView)?.label ?? "Ferramenta Ativa",
  )

  return (
    <section
      data-slot="cyberlab-center-stage"
      class="flex h-full min-h-0 min-w-0 flex-1 flex-col bg-v2-background-bg-base select-text overflow-hidden"
    >
      {/* ABA HORIZONTAL RETRÁTIL NA VERTICAL: quando recolhida, vira uma fita fina de 28px sem quebrar linha */}
      <Show
        when={wb.ui.topControlsOpen}
        fallback={
          <div
            data-slot="cyberlab-top-rail-collapsed"
            class="flex h-[28px] shrink-0 items-center justify-between gap-2 border-b border-v2-border-border-base bg-v2-background-bg-deep/90 px-2 text-[10.5px] select-none overflow-x-auto [scrollbar-width:none]"
          >
            <div class="flex items-center gap-1.5 whitespace-nowrap min-w-0">
              <button
                type="button"
                title="Expandir aba superior com todas as abas, MCP, Proxy, configuração e controles"
                class="inline-flex items-center gap-1 rounded border border-emerald-600/60 bg-emerald-600/15 px-2 py-0.5 text-[10px] font-semibold text-emerald-400 hover:bg-emerald-600/25 cursor-pointer"
                onClick={() => toggleTopDrawer(true)}
              >
                <span>▼ Controles & Abas</span>
              </button>

              <Show when={!wb.ui.leftSidebarOpen}>
                <button
                  type="button"
                  title="Expandir coluna esquerda (Slots & Pastas)"
                  class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-1.5 py-0.5 text-[10px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                  onClick={() => {
                    wb.toggleLeftSidebar(true)
                    triggerCanvasResizeSync()
                  }}
                >
                  » Slots
                </button>
              </Show>

              <Show
                when={wb.ui.centerView === "tool" && wb.activeSlot()}
                fallback={
                  <span class="rounded bg-emerald-600/20 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
                    {activeNavLabel()}
                  </span>
                }
              >
                {(s) => (
                  <div class="flex items-center gap-1.5 min-w-0">
                    <span
                      class={`inline-block size-1.5 rounded-full shrink-0 ${
                        s().embedUrl || s().installed ? "bg-emerald-500" : "bg-amber-400"
                      }`}
                    />
                    <span class="truncate max-w-[180px] font-semibold text-v2-text-text-strong">
                      {s().shortLabel}
                    </span>

                    <Show when={s().mcpCapable}>
                      <button
                        type="button"
                        disabled={wb.ui.busy}
                        title={
                          s().mcpConnected
                            ? `MCP Ativo (${s().mcpLabel ?? s().shortLabel}) — clique p/ desconectar`
                            : `Conectar ${s().shortLabel} ao Agente IA via MCP`
                        }
                        class={`rounded border px-1.5 py-0 text-[9.5px] font-semibold cursor-pointer ${
                          s().mcpConnected
                            ? "border-emerald-500/50 bg-emerald-600/20 text-emerald-300"
                            : "border-violet-500/40 bg-violet-600/15 text-violet-300"
                        }`}
                        onClick={() =>
                          void wb.launchSlot({
                            slotId: s().slotId,
                            action: "run_cli",
                            rawArgs: "__toggle_mcp__",
                          })
                        }
                      >
                        {s().mcpConnected ? "🟢 MCP" : "🔌 MCP"}
                      </button>
                    </Show>

                    <Show when={s().companionProxyPort}>
                      {(proxyPort) => (
                        <button
                          type="button"
                          title={`Abrir Navegador Isolado no Proxy :${proxyPort()}`}
                          class="rounded bg-sky-600/80 px-1.5 py-0 text-[9.5px] font-medium text-white hover:bg-sky-500 cursor-pointer"
                          onClick={() =>
                            void wb.launchProxyBrowser({
                              proxyPort: proxyPort(),
                              startUrl: "https://example.com",
                            })
                          }
                        >
                          🌐 :{proxyPort()}
                        </button>
                      )}
                    </Show>
                  </div>
                )}
              </Show>
            </div>

            <div class="flex items-center gap-1 whitespace-nowrap shrink-0">
              <Show when={wb.ui.centerView === "tool" && wb.activeSlot()}>
                {(s) => (
                  <Show when={s().embedUrl}>
                    <div class="flex items-center gap-0.5 rounded border border-v2-border-border-base bg-v2-background-bg-base px-1 py-0">
                      <button
                        type="button"
                        title="Nitidez 1:1 nativa sem deslocar cursor"
                        class={`rounded px-1 text-[9.5px] cursor-pointer ${
                          getSlotFraming(s()) === "native"
                            ? "bg-emerald-600 text-white"
                            : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                        }`}
                        onClick={() => syncCanvasControl(s(), "native")}
                      >
                        1:1
                      </button>
                      <button
                        type="button"
                        title="Ajustar tudo na janela"
                        class={`rounded px-1 text-[9.5px] cursor-pointer ${
                          getSlotFraming(s()) === "fit"
                            ? "bg-emerald-600 text-white"
                            : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                        }`}
                        onClick={() => syncCanvasControl(s(), "fit")}
                      >
                        Ajustar
                      </button>
                      <button
                        type="button"
                        title="Rolagem mantendo precisão de mouse"
                        class={`rounded px-1 text-[9.5px] cursor-pointer ${
                          getSlotFraming(s()) === "scroll"
                            ? "bg-emerald-600 text-white"
                            : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                        }`}
                        onClick={() => syncCanvasControl(s(), "scroll")}
                      >
                        ↕
                      </button>
                      <button
                        type="button"
                        title="Diminuir zoom (-10%)"
                        class="px-1 font-bold text-v2-text-text-base hover:text-emerald-400 cursor-pointer"
                        onClick={() => {
                          const cur = getSlotFraming(s())
                          syncCanvasControl(s(), cur === "fit" ? "native" : cur, Math.max(60, getSlotZoom(s()) - 10))
                        }}
                      >
                        −
                      </button>
                      <button
                        type="button"
                        title="Restaurar 100%"
                        class="px-0.5 font-mono text-[9.5px] text-emerald-400 cursor-pointer"
                        onClick={() => syncCanvasControl(s(), getSlotFraming(s()), 100)}
                      >
                        {getSlotZoom(s())}%
                      </button>
                      <button
                        type="button"
                        title="Aumentar zoom (+10%)"
                        class="px-1 font-bold text-v2-text-text-base hover:text-emerald-400 cursor-pointer"
                        onClick={() => {
                          const cur = getSlotFraming(s())
                          syncCanvasControl(s(), cur === "fit" ? "native" : cur, Math.min(160, getSlotZoom(s()) + 10))
                        }}
                      >
                        +
                      </button>
                    </div>

                    <Show when={s().kind === "desktop_gui"}>
                      <button
                        type="button"
                        title="Gravar evidência em SHA-256 ou enviar trecho p/ Agente IA"
                        class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-1.5 py-0 text-[9.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                        onClick={() => setShowDesktopIngestDrawer((v) => !v)}
                      >
                        📋 SHA-256
                      </button>
                    </Show>

                    <button
                      type="button"
                      title="Reconectar / recarregar canvas da ferramenta"
                      class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-1.5 py-0 text-[9.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                      onClick={() => wb.setUi("iframeReloadNonce", (n) => n + 1)}
                    >
                      ↻
                    </button>

                    <button
                      type="button"
                      title="Fechar instância gráfica ativa"
                      class="rounded border border-red-500/40 bg-red-500/10 px-1.5 py-0 text-[9.5px] text-red-400 hover:bg-red-500/20 cursor-pointer"
                      onClick={() =>
                        void wb.launchSlot({
                          slotId: s().slotId,
                          action: "stop_web",
                        })
                      }
                    >
                      ⏹
                    </button>
                  </Show>
                )}
              </Show>

              <button
                type="button"
                title="Abrir ou fechar Cofre Flutuante de Notas & Comandos compatível com Obsidian (.md) — Atalho: Alt+N"
                class={`rounded border px-1.5 py-0 text-[9.5px] font-semibold cursor-pointer ${
                  wb.ui.vaultOpen
                    ? "border-violet-500 bg-violet-600/25 text-violet-300"
                    : "border-violet-500/40 bg-violet-600/10 text-violet-300 hover:bg-violet-600/20"
                }`}
                onClick={() => wb.toggleVault()}
              >
                📓 Notas
              </button>

              <button
                type="button"
                title="Ampliar ferramenta ocultando/restaurando painéis laterais e topo"
                class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-1.5 py-0 text-[9.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                onClick={toggleMaximizeCenter}
              >
                {!wb.ui.leftSidebarOpen && !wb.ui.rightAgentOpen ? "◫ Painéis" : "⛶ Ampliar"}
              </button>

              <button
                type="button"
                title={wb.ui.rightAgentOpen ? "Recolher Agente IA à direita" : "Abrir Agente IA à direita"}
                class={`rounded border px-1.5 py-0 text-[9.5px] font-medium cursor-pointer ${
                  wb.ui.rightAgentOpen
                    ? "border-emerald-600/50 bg-emerald-600/15 text-emerald-400"
                    : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-base hover:border-emerald-500"
                }`}
                onClick={() => {
                  wb.toggleRightAgent()
                  triggerCanvasResizeSync()
                }}
              >
                {wb.ui.rightAgentOpen ? "IA »" : "« IA"}
              </button>
            </div>
          </div>
        }
      >
        <header
          data-slot="cyberlab-top-drawer"
          class="flex flex-wrap items-center justify-between gap-2 border-b border-v2-border-border-base bg-v2-background-bg-deep/75 px-3 py-1.5 shrink-0"
        >
          <div class="flex items-center gap-1.5 overflow-x-auto">
            <Show when={!wb.ui.leftSidebarOpen}>
              <button
                type="button"
                class="inline-flex items-center gap-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 text-[11px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                onClick={() => {
                  wb.toggleLeftSidebar(true)
                  triggerCanvasResizeSync()
                }}
              >
                <Icon name="chevron-right" class="size-3 text-emerald-500" />
                <span>Pastas & Slots</span>
              </button>
            </Show>

            <For each={navItems}>
              {(item) => (
                <button
                  type="button"
                  class={`rounded-md px-2.5 py-1 text-[11.5px] font-medium transition-colors cursor-pointer whitespace-nowrap ${
                    wb.ui.centerView === item.id
                      ? "bg-emerald-600 text-white"
                      : "text-v2-text-text-muted hover:bg-v2-background-bg-base hover:text-v2-text-text-strong"
                  }`}
                  onClick={() => wb.setCenterView(item.id)}
                >
                  {item.label}
                </button>
              )}
            </For>
          </div>

          <div class="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              title="Abrir Cofre Flutuante de Notas & Comandos compatível com Obsidian (.md) por cima da ferramenta sem perder espaço (Atalho: Alt+N)"
              class={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-[11px] font-semibold cursor-pointer ${
                wb.ui.vaultOpen
                  ? "border-violet-400 bg-violet-600 text-white"
                  : "border-violet-500/50 bg-violet-600/15 text-violet-300 hover:bg-violet-600/25"
              }`}
              onClick={() => wb.toggleVault()}
            >
              <span>📓 Notas & Comandos</span>
            </button>

            <button
              type="button"
              title="Recolher todas as barras superiores na vertical para liberar espaço máximo para a ferramenta"
              class="inline-flex items-center gap-1 rounded-md border border-emerald-600/50 bg-emerald-600/15 px-2 py-1 text-[11px] font-semibold text-emerald-400 hover:bg-emerald-600/25 cursor-pointer"
              onClick={() => toggleTopDrawer(false)}
            >
              <span>▲ Recolher Topo</span>
            </button>

            <button
              type="button"
              disabled={wb.ui.probing}
              title="Re-escanear todas as ferramentas do Windows + WinGet + Kali WSL2"
              class="inline-flex items-center gap-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 text-[11px] text-v2-text-text-base hover:border-emerald-500 hover:text-emerald-400 cursor-pointer"
              onClick={() => void wb.refreshArsenalOnly(true)}
            >
              <Icon name="refresh" class={`size-3.5 ${wb.ui.probing ? "animate-spin text-emerald-400" : ""}`} />
              <span>{wb.ui.probing ? "Escaneando..." : "Atualizar Slots"}</span>
            </button>

            <button
              type="button"
              title={
                wb.ui.rightAgentOpen
                  ? "Recolher painel estreito do Agente OpenCode à direita"
                  : "Abrir painel estreito do Agente OpenCode à direita"
              }
              class={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-[11px] font-medium cursor-pointer ${
                wb.ui.rightAgentOpen
                  ? "border-emerald-600/50 bg-emerald-600/15 text-emerald-500"
                  : "border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-base hover:border-emerald-500"
              }`}
              onClick={() => {
                wb.toggleRightAgent()
                triggerCanvasResizeSync()
              }}
            >
              <span>{wb.ui.rightAgentOpen ? "Agente IA »" : "« Agente IA"}</span>
            </button>

            <button
              type="button"
              title="Fechar modo Antigravity e voltar ao chat tela cheia"
              class="inline-flex size-6 items-center justify-center rounded-md border border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-muted hover:text-v2-text-text-strong cursor-pointer"
              onClick={() => wb.toggleWorkbench(false)}
            >
              <Icon name="close" class="size-3.5" />
            </button>
          </div>
        </header>
      </Show>

      {/* Banner discreto de feedback */}
      <Show when={wb.ui.notice || wb.ui.error}>
        <div
          class={`flex items-center justify-between gap-2 border-b px-3 py-1 text-[11px] shrink-0 ${
            wb.ui.error
              ? "border-red-500/40 bg-red-500/15 text-red-400"
              : "border-emerald-500/40 bg-emerald-500/15 text-emerald-400"
          }`}
        >
          <span class="truncate">{wb.ui.error || wb.ui.notice}</span>
          <button
            type="button"
            class="text-[10px] underline cursor-pointer shrink-0"
            onClick={() => {
              wb.setUi("error", "")
              wb.setUi("notice", "")
            }}
          >
            ocultar
          </button>
        </div>
      </Show>

      {/* Console ao vivo de Instalação Automática (visível quando há um instalador rodando ou recém-concluído) */}
      <Show
        when={(wb.backend.arsenal?.runs ?? []).find(
          (r) => r.runtime === "installer" && !dismissedInstallerRunIds().includes(r.runId),
        )}
      >
        {(instRun) => (
          <div class="border-b border-emerald-600/40 bg-zinc-950 px-3 py-2 shrink-0">
            <div class="mb-1 flex items-center justify-between gap-2 text-[11px]">
              <div class="flex items-center gap-2 font-medium text-emerald-400">
                <span>
                  {instRun().status === "running"
                    ? `⏳ ${instRun().slotName} em andamento...`
                    : `✅ ${instRun().slotName} finalizado (${instRun().status})`}
                </span>
              </div>
              <div class="flex items-center gap-1.5">
                <Show when={instRun().status === "running"}>
                  <button
                    type="button"
                    class="rounded border border-red-500/40 bg-red-500/15 px-2 py-0.5 text-[10px] text-red-300 hover:bg-red-500/25 cursor-pointer"
                    onClick={() => void wb.stopRun(instRun().runId)}
                  >
                    ⏹ Cancelar
                  </button>
                </Show>
                <button
                  type="button"
                  class="rounded border border-zinc-700 bg-zinc-900 px-2.5 py-0.5 text-[10.5px] font-medium text-zinc-200 hover:border-emerald-500 hover:text-white cursor-pointer"
                  onClick={() => {
                    const allInstIds = (wb.backend.arsenal?.runs ?? [])
                      .filter((r) => r.runtime === "installer")
                      .map((r) => r.runId)
                    setDismissedInstallerRunIds((prev) => Array.from(new Set([...prev, ...allInstIds])))
                  }}
                >
                  ✕ Fechar Console
                </button>
              </div>
            </div>
            <pre class="max-h-36 overflow-auto rounded border border-zinc-800 bg-black/70 p-2 font-mono text-[10.5px] leading-snug text-emerald-200 whitespace-pre-wrap">
              {instRun().outputTail}
            </pre>
          </div>
        )}
      </Show>

      {/* ===================================================================== */}
      {/* VISÃO 1: FERRAMENTA REAL ATIVA OCUPANDO O CENTRO INTEIRO              */}
      {/* ===================================================================== */}
      <Show when={wb.ui.centerView === "tool" && wb.activeSlot()}>
        {(slot) => (
          <div class="flex min-h-0 flex-1 flex-col overflow-hidden">
            {/* Sub-barra da ferramenta ativa + painel de configuração (recolhem junto com a aba vertical superior!) */}
            <Show when={wb.ui.topControlsOpen}>
              <div class="flex flex-wrap items-center justify-between gap-2 border-b border-v2-border-border-base bg-v2-background-bg-deep/40 px-3 py-2 shrink-0">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="rounded bg-emerald-600/20 px-2 py-0.5 text-[10px] font-semibold text-emerald-500">
                    {kindBadgeLabel(slot().kind)}
                  </span>
                  <h2 class="truncate text-[13.5px] font-semibold text-v2-text-text-strong">
                    {slot().name}
                  </h2>
                  <span
                    class={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                      slot().installed
                        ? "bg-emerald-600/20 text-emerald-400"
                        : "bg-amber-500/20 text-amber-400"
                    }`}
                  >
                    {slot().installed
                      ? `Pronto (${runtimeBadgeLabel(slot().activeRuntime)})`
                      : "Aguardando instalação externa"}
                  </span>
                </div>

                <div class="flex flex-wrap items-center gap-1.5">
                  <Show when={slot().mcpCapable}>
                    <button
                      type="button"
                      disabled={wb.ui.busy}
                      title={
                        slot().mcpConnected
                          ? `Servidor MCP "${slot().mcpLabel ?? slot().shortLabel}" ativo no opencode.json — clique p/ desconectar`
                          : `Conectar "${slot().mcpLabel ?? slot().shortLabel}" via MCP diretamente ao Agente OpenCode`
                      }
                      class={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-[11px] font-semibold cursor-pointer transition-colors ${
                        slot().mcpConnected
                          ? "border-emerald-500/60 bg-emerald-600/20 text-emerald-300 hover:bg-emerald-600/30"
                          : "border-violet-500/50 bg-violet-600/20 text-violet-200 hover:bg-violet-600/35"
                      }`}
                      onClick={() =>
                        void wb.launchSlot({
                          slotId: slot().slotId,
                          action: "run_cli",
                          rawArgs: "__toggle_mcp__",
                        })
                      }
                    >
                      <span>
                        {slot().mcpConnected
                          ? `🟢 MCP Ativo (${slot().mcpLabel ?? "OpenCode"})`
                          : `🔌 Conectar MCP`}
                      </span>
                    </button>
                  </Show>

                  <Show when={slot().companionProxyPort}>
                    {(proxyPort) => (
                      <button
                        type="button"
                        class="inline-flex items-center gap-1 rounded-md bg-sky-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-sky-500 cursor-pointer"
                        onClick={() =>
                          void wb.launchProxyBrowser({
                            proxyPort: proxyPort(),
                            startUrl: "https://example.com",
                          })
                        }
                      >
                        <span>🌐 Navegador Proxy (:{proxyPort()})</span>
                      </button>
                    )}
                  </Show>

                  <button
                    type="button"
                    class="rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                    onClick={() => {
                      setCustomPathInput(slot().override.customExecutablePath ?? slot().resolvedPath ?? "")
                      setCustomUrlInput(slot().override.customEmbedUrl ?? slot().embedUrl ?? "")
                      setToolsRootInput(wb.backend.arsenal?.environment.toolsRootDir ?? "C:\\CyberLab-Tools")
                      setShowSlotSettings((v) => !v)
                    }}
                  >
                    ⚙ Configurar / Instalar
                  </button>

                  <Show when={slot().isCustom}>
                    <button
                      type="button"
                      class="rounded-md border border-red-500/40 bg-red-500/10 px-2 py-1 text-[11px] text-red-400 hover:bg-red-500/20 cursor-pointer"
                      onClick={() => void wb.removeCustomSlot(slot().slotId)}
                    >
                      Remover Slot
                    </button>
                  </Show>
                </div>
              </div>

              {/* Painel retrátil de Configuração / Instalação Rápida (PowerShell + WSL2 Kali) */}
              <Show when={showSlotSettings() || !slot().installed}>
              <div class="border-b border-v2-border-border-base bg-v2-background-bg-deep/65 px-3.5 py-2.5 text-[11.5px] shrink-0">
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div class="min-w-0 flex-1 space-y-2">
                    <p class="text-v2-text-text-base">{slot().description}</p>
                    <div class="grid grid-cols-1 gap-2 lg:grid-cols-2">
                      {/* Comando PowerShell */}
                      <div class="rounded-lg border border-v2-border-border-base bg-zinc-950 p-2">
                        <div class="mb-1 flex items-center justify-between text-[10.5px] text-sky-400 font-medium">
                          <span>Windows PowerShell</span>
                          <button
                            type="button"
                            class="rounded bg-sky-500/20 px-2 py-0.5 text-[10px] hover:bg-sky-500/30 cursor-pointer"
                            onClick={() => copyText(wb, slot().installPowerShell, "Comando PowerShell")}
                          >
                            Copiar PowerShell
                          </button>
                        </div>
                        <pre class="overflow-x-auto font-mono text-[10.5px] text-zinc-200 whitespace-pre-wrap">
                          {slot().installPowerShell}
                        </pre>
                      </div>

                      {/* Comando WSL2 Kali Linux */}
                      <div class="rounded-lg border border-v2-border-border-base bg-zinc-950 p-2">
                        <div class="mb-1 flex items-center justify-between text-[10.5px] text-emerald-400 font-medium">
                          <span>WSL2 Kali Linux (`wsl -d kali-linux`)</span>
                          <div class="flex items-center gap-1">
                            <button
                              type="button"
                              class="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] hover:bg-emerald-500/30 cursor-pointer"
                              onClick={() => copyText(wb, slot().installKaliWsl, "Comando WSL2 Kali")}
                            >
                              Copiar Kali
                            </button>
                            <button
                              type="button"
                              class="rounded bg-emerald-600 px-2 py-0.5 text-[10px] text-white hover:bg-emerald-500 cursor-pointer"
                              onClick={() =>
                                void wb.launchSlot({
                                  slotId: slot().slotId,
                                  action: "install_tool",
                                })
                              }
                            >
                              Auto-Instalar Agora
                            </button>
                          </div>
                        </div>
                        <pre class="overflow-x-auto font-mono text-[10.5px] text-zinc-200 whitespace-pre-wrap">
                          {slot().installKaliWsl}
                        </pre>
                      </div>
                    </div>

                    {/* Override manual de caminho/URL ou pasta C:\CyberLab-Tools */}
                    <div class="flex flex-wrap items-center gap-2 pt-1">
                      <input
                        type="text"
                        placeholder="Caminho customizado do executável (opcional)"
                        value={customPathInput()}
                        class="min-w-[220px] flex-1 rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-strong"
                        onInput={(e) => setCustomPathInput(e.currentTarget.value)}
                      />
                      <Show when={slot().kind === "web_embed"}>
                        <input
                          type="text"
                          placeholder="URL Web Embed (ex.: http://127.0.0.1:8081)"
                          value={customUrlInput()}
                          class="min-w-[210px] flex-1 rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-strong"
                          onInput={(e) => setCustomUrlInput(e.currentTarget.value)}
                        />
                      </Show>
                      <input
                        type="text"
                        placeholder="Pasta global (ex.: C:\CyberLab-Tools)"
                        value={toolsRootInput()}
                        class="w-[190px] rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-strong"
                        onInput={(e) => setToolsRootInput(e.currentTarget.value)}
                      />
                      <button
                        type="button"
                        class="rounded bg-emerald-600 px-3 py-1 text-[11px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                        onClick={() => {
                          void wb.configureArsenal({
                            ...(toolsRootInput().trim() ? { toolsRootDir: toolsRootInput().trim() } : {}),
                            slotId: slot().slotId,
                            slotOverride: {
                              ...(customPathInput().trim()
                                ? { customExecutablePath: customPathInput().trim() }
                                : {}),
                              ...(customUrlInput().trim() ? { customEmbedUrl: customUrlInput().trim() } : {}),
                            },
                          })
                          setShowSlotSettings(false)
                        }}
                      >
                        Salvar Caminho/URL
                      </button>
                    </div>
                  </div>
                </div>
              </div>
              </Show>
            </Show>

            {/* MODO A: WEB TOOL EMBUTIDA EM TELA CHEIA NO CENTRO (CyberChef, mitmweb, Caido, Kali Desktop Web) */}
            <Show when={slot().kind === "web_embed"}>
              <div class="flex min-h-0 flex-1 flex-col overflow-hidden">
                <Show when={wb.ui.topControlsOpen}>
                  <div class="flex flex-wrap items-center justify-between gap-2 border-b border-v2-border-border-base bg-v2-background-bg-base px-3 py-1.5 text-[11px] shrink-0">
                    <div class="flex flex-wrap items-center gap-1.5 min-w-0">
                      <button
                        type="button"
                        disabled={wb.ui.busy}
                        class="rounded bg-emerald-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-emerald-500 cursor-pointer disabled:opacity-50"
                        onClick={() =>
                          void wb.launchSlot({ slotId: slot().slotId, action: "start_web" })
                        }
                      >
                        {wb.ui.busy ? "⏳ Iniciando..." : "▶ Abrir Aqui no Centro"}
                      </button>
                      <Show when={slot().daemonRunning}>
                        <button
                          type="button"
                          class="rounded border border-red-500/40 bg-red-500/10 px-2 py-1 text-[11px] text-red-400 hover:bg-red-500/20 cursor-pointer"
                          onClick={() =>
                            void wb.launchSlot({ slotId: slot().slotId, action: "stop_web" })
                          }
                        >
                          ⏹ Parar
                        </button>
                      </Show>

                      {/* Controles de Dimensionamento Preciso (Sem Deslocamento de Cursor!) e Rolagem */}
                      <div class="flex items-center gap-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-1.5 py-0.5">
                        <Show when={slot().slotId === "kali-desktop-stream"}>
                          <button
                            type="button"
                            title="Nitidez 1:1 nativa com redimensionamento dinâmico X11 e clique exato"
                            class={`rounded px-1.5 py-0.5 text-[10px] font-medium cursor-pointer ${
                              getSlotFraming(slot()) === "native"
                                ? "bg-emerald-600 text-white"
                                : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                            }`}
                            onClick={() => syncCanvasControl(slot(), "native")}
                          >
                            🖥 1:1 Nitidez
                          </button>
                        </Show>
                        <button
                          type="button"
                          title="Enquadrar na tela sem cortar"
                          class={`rounded px-1.5 py-0.5 text-[10px] font-medium cursor-pointer ${
                            getSlotFraming(slot()) === "fit"
                              ? "bg-emerald-600 text-white"
                              : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                          }`}
                          onClick={() => syncCanvasControl(slot(), "fit")}
                        >
                          📐 Ajustar
                        </button>
                        <button
                          type="button"
                          title="Ativar barra de rolagem vertical com precisão 1:1 do mouse"
                          class={`rounded px-1.5 py-0.5 text-[10px] font-medium cursor-pointer ${
                            getSlotFraming(slot()) === "scroll"
                              ? "bg-emerald-600 text-white"
                              : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                          }`}
                          onClick={() => syncCanvasControl(slot(), "scroll")}
                        >
                          ↕ Rolagem
                        </button>
                        <button
                          type="button"
                          title="Diminuir escala (-10% com precisão exata de clique)"
                          class="rounded px-1.5 py-0.5 text-[10.5px] font-bold text-v2-text-text-base hover:bg-v2-background-bg-base cursor-pointer"
                          onClick={() => {
                            const curMode = getSlotFraming(slot())
                            const targetMode = curMode === "fit" ? "native" : curMode
                            const next = Math.max(60, getSlotZoom(slot()) - 10)
                            syncCanvasControl(slot(), targetMode, next)
                          }}
                        >
                          −
                        </button>
                        <button
                          type="button"
                          title="Restaurar zoom 100%"
                          class="rounded px-1 py-0.5 font-mono text-[10px] text-emerald-400 hover:bg-v2-background-bg-base cursor-pointer"
                          onClick={() => syncCanvasControl(slot(), getSlotFraming(slot()), 100)}
                        >
                          {getSlotZoom(slot())}%
                        </button>
                        <button
                          type="button"
                          title="Aumentar escala (+10% com precisão exata de clique)"
                          class="rounded px-1.5 py-0.5 text-[10.5px] font-bold text-v2-text-text-base hover:bg-v2-background-bg-base cursor-pointer"
                          onClick={() => {
                            const curMode = getSlotFraming(slot())
                            const targetMode = curMode === "fit" ? "native" : curMode
                            const next = Math.min(160, getSlotZoom(slot()) + 10)
                            syncCanvasControl(slot(), targetMode, next)
                          }}
                        >
                          +
                        </button>
                      </div>
                    </div>

                    <div class="flex items-center gap-1.5">
                      <button
                        type="button"
                        title="Recolher todas as barras superiores na vertical"
                        class="rounded border border-emerald-600/50 bg-emerald-600/15 px-2 py-1 text-[10.5px] font-medium text-emerald-400 hover:bg-emerald-600/25 cursor-pointer"
                        onClick={() => toggleTopDrawer(false)}
                      >
                        ▲ Recolher Topo
                      </button>
                      <button
                        type="button"
                        title="Recolher/restaurar barras laterais e topo para ampliar o espaço central"
                        class="rounded border border-v2-border-border-base px-2 py-1 text-[10.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                        onClick={toggleMaximizeCenter}
                      >
                        {!wb.ui.leftSidebarOpen && !wb.ui.rightAgentOpen ? "◫ Painéis" : "⛶ Ampliar"}
                      </button>
                      <button
                        type="button"
                        class="rounded border border-v2-border-border-base px-2 py-1 text-[10.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                        onClick={() => wb.setUi("iframeReloadNonce", (n) => n + 1)}
                      >
                        ↻ Recarregar
                      </button>
                      <Show when={slot().embedUrl}>
                        {(url) => (
                          <a
                            href={url()}
                            target="_blank"
                            rel="noreferrer"
                            class="rounded border border-v2-border-border-base px-2 py-1 text-[10.5px] text-emerald-500 hover:border-emerald-500"
                          >
                            ↗ Nova Aba
                          </a>
                        )}
                      </Show>
                    </div>
                  </div>
                </Show>

                <Show
                  when={slot().embedUrl}
                  fallback={
                    <div class="flex min-h-0 flex-1 flex-col overflow-hidden">
                      <div class="flex flex-1 flex-col items-center justify-center gap-3 p-6 text-center">
                        <div class="text-[14px] font-semibold text-v2-text-text-strong">
                          {slot().name} pronto para abrir no palco central
                        </div>
                        <p class="max-w-lg text-[12px] text-v2-text-text-muted">
                          Clique no botão abaixo para iniciar a interface real no palco central (o topo recolherá automaticamente para maximizar a janela da ferramenta).
                        </p>
                        <button
                          type="button"
                          disabled={wb.ui.busy}
                          class="mt-1 inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-[12.5px] font-semibold text-white hover:bg-emerald-500 cursor-pointer disabled:opacity-50"
                          onClick={() =>
                            void wb.launchSlot({ slotId: slot().slotId, action: "start_web" })
                          }
                        >
                          <span>{wb.ui.busy ? "⏳ Iniciando..." : `▶ Abrir ${slot().shortLabel} Aqui no Centro`}</span>
                        </button>
                      </div>
                      <Show when={wb.selectedRunForActiveSlot()}>
                        {(run) => (
                          <div class="border-t border-zinc-800 bg-zinc-950 p-3 text-left shrink-0 max-h-[48%] overflow-auto">
                            <div class="mb-1 flex items-center justify-between text-[11px] font-semibold text-emerald-400">
                              <span>📦 Console de Instalação / Inicialização ao Vivo ({run().status})</span>
                              <span class="font-mono text-[10px] text-zinc-400">{run().runtime}</span>
                            </div>
                            <pre class="font-mono text-[11px] leading-relaxed text-emerald-100/95 whitespace-pre-wrap">
                              {`$ ${run().commandPreview}\n\n${run().outputTail || "(executando pacotes no Kali WSL2...)"}`}
                            </pre>
                          </div>
                        )}
                      </Show>
                    </div>
                  }
                >
                  {(url) => {
                    const isVncCanvas = () => url().includes("cyberlab_canvas.html")
                    const scrollActive = () => !isVncCanvas() && getSlotFraming(slot()) === "scroll"
                    return (
                      <div
                        class={`min-h-0 flex-1 bg-zinc-950 [scrollbar-width:thin] [scrollbar-color:#10b981_#18181b] ${
                          scrollActive() ? "overflow-auto" : "overflow-hidden"
                        }`}
                      >
                        <iframe
                          ref={(el) => {
                            activeToolIframeRef = el
                          }}
                          data-slot="cyberlab-real-tool-iframe"
                          src={`${url()}${url().includes("?") ? "&" : "?"}_cb=${wb.ui.iframeReloadNonce}`}
                          title={slot().name}
                          onLoad={() => syncCanvasControl(slot())}
                          style={{ width: "100%", height: "100%" }}
                          class="h-full w-full border-0 bg-zinc-950"
                          allow="clipboard-read; clipboard-write; fullscreen"
                          allowfullscreen
                        />
                      </div>
                    )
                  }}
                </Show>
              </div>
            </Show>

            {/* MODO B: CLI RUNNER AO VIVO (Nuclei, ffuf, Katana, httpx, Dalfox, sqlmap, Nmap, KeyHunter, Semgrep, Trivy...) */}
            <Show when={slot().kind === "cli_runner"}>
              <div class="flex min-h-0 flex-1 flex-col overflow-hidden">
                {/* Barra de presets + Target + Argumentos + Executar (recolhe junto com a aba vertical superior!) */}
                <Show when={wb.ui.topControlsOpen}>
                  <div class="flex flex-col gap-2 border-b border-v2-border-border-base bg-v2-background-bg-base p-3 shrink-0">
                    <Show when={slot().presets.length > 0}>
                      <div class="flex flex-wrap items-center gap-1.5">
                        <span class="text-[10.5px] font-medium text-v2-text-text-muted">Presets rápidos:</span>
                        <For each={slot().presets}>
                          {(preset) => (
                            <button
                              type="button"
                              title={preset.description}
                              class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-0.5 text-[10.5px] text-v2-text-text-base hover:border-emerald-500 hover:text-emerald-400 cursor-pointer"
                              onClick={() => wb.setUi("cliArgsBySlot", slot().slotId, preset.argsTemplate)}
                            >
                              {preset.label}
                            </button>
                          )}
                        </For>
                      </div>
                    </Show>

                    <div class="flex flex-wrap items-center gap-2">
                      <input
                        type="text"
                        placeholder="Alvo {target} (URL em escopo, IP/domínio ou caminho de arquivo do workspace)"
                        value={wb.ui.cliTargetBySlot[slot().slotId] ?? ""}
                        class="min-w-[220px] flex-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-2.5 py-1.5 font-mono text-[11.5px] text-v2-text-text-strong outline-none focus:border-emerald-500"
                        onInput={(e) => wb.setUi("cliTargetBySlot", slot().slotId, e.currentTarget.value)}
                      />
                      <input
                        type="text"
                        placeholder="Argumentos da ferramenta real (usa {target} e {workspace})"
                        value={wb.ui.cliArgsBySlot[slot().slotId] ?? ""}
                        class="min-w-[260px] flex-[1.4] rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-2.5 py-1.5 font-mono text-[11.5px] text-v2-text-text-strong outline-none focus:border-emerald-500"
                        onInput={(e) => wb.setUi("cliArgsBySlot", slot().slotId, e.currentTarget.value)}
                      />
                      <select
                        value={wb.ui.cliRuntimeBySlot[slot().slotId] ?? "auto"}
                        class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1.5 text-[11px] text-v2-text-text-strong"
                        onChange={(e) =>
                          wb.setUi(
                            "cliRuntimeBySlot",
                            slot().slotId,
                            e.currentTarget.value as "auto" | "windows" | "wsl" | "linux_mac",
                          )
                        }
                      >
                        <option value="auto">Auto (Win / WSL2)</option>
                        <option value="windows">Windows PowerShell</option>
                        <option value="wsl">WSL2 Kali Linux</option>
                      </select>
                      <button
                        type="button"
                        disabled={wb.ui.busy}
                        class="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 px-3.5 py-1.5 text-[12px] font-semibold text-white hover:bg-emerald-500 disabled:opacity-50 cursor-pointer"
                        onClick={() => {
                          const rt = wb.ui.cliRuntimeBySlot[slot().slotId]
                          void wb.launchSlot({
                            slotId: slot().slotId,
                            action: "run_cli",
                            target: wb.ui.cliTargetBySlot[slot().slotId] ?? "",
                            rawArgs: wb.ui.cliArgsBySlot[slot().slotId] ?? "",
                            ...(rt && rt !== "auto" ? { runtimeOverride: rt } : {}),
                          })
                        }}
                      >
                        <span>▶ Executar Ferramenta Real</span>
                      </button>
                      <button
                        type="button"
                        title="Recolher barras superiores na vertical para ampliar o terminal"
                        class="rounded-md border border-emerald-600/50 bg-emerald-600/15 px-2.5 py-1.5 text-[11px] font-medium text-emerald-400 hover:bg-emerald-600/25 cursor-pointer"
                        onClick={() => toggleTopDrawer(false)}
                      >
                        ▲ Recolher Topo
                      </button>
                    </div>
                  </div>
                </Show>

                {/* Console de Saída em Tempo Real ocupando todo o centro */}
                <div class="flex min-h-0 flex-1 flex-col bg-zinc-950 text-zinc-100">
                  <div class="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 px-3 py-1.5 text-[11px]">
                    <div class="flex items-center gap-2 overflow-x-auto">
                      <For each={wb.activeSlotRuns()}>
                        {(run) => (
                          <button
                            type="button"
                            class={`rounded px-2 py-0.5 font-mono text-[10.5px] cursor-pointer ${
                              wb.selectedRunForActiveSlot()?.runId === run.runId
                                ? "bg-emerald-600 text-white"
                                : "bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
                            }`}
                            onClick={() => wb.setUi("selectedRunIdBySlot", slot().slotId, run.runId)}
                          >
                            {run.status === "running" ? "● " : ""}
                            {run.runId.slice(0, 10)} ({run.status})
                          </button>
                        )}
                      </For>
                    </div>

                    <Show when={wb.selectedRunForActiveSlot()}>
                      {(run) => (
                        <div class="flex items-center gap-1.5">
                          <Show when={run().status === "running"}>
                            <button
                              type="button"
                              class="rounded bg-red-600 px-2.5 py-0.5 text-[10.5px] font-medium text-white hover:bg-red-500 cursor-pointer"
                              onClick={() => void wb.stopRun(run().runId)}
                            >
                              ■ Parar Processo
                            </button>
                          </Show>
                          <button
                            type="button"
                            class="rounded bg-sky-600/25 px-2.5 py-0.5 text-[10.5px] font-medium text-sky-300 hover:bg-sky-600/40 cursor-pointer"
                            onClick={() =>
                              void wb.persistOutputToEvidence(
                                `${slot().name} (${run().commandPreview})`,
                                run().outputTail,
                                slot().slotId,
                              )
                            }
                          >
                            🔒 Salvar SHA-256
                          </button>
                          <button
                            type="button"
                            class="rounded bg-emerald-600/25 px-2.5 py-0.5 text-[10.5px] font-medium text-emerald-300 hover:bg-emerald-600/40 cursor-pointer"
                            onClick={() =>
                              wb.sendToAgent(
                                `Saída Real: ${slot().name}\nComando: ${run().commandPreview}`,
                                run().outputTail,
                                `${slot().slotId}-output.txt`,
                              )
                            }
                          >
                            🤖 Enviar p/ Agente OpenCode →
                          </button>
                        </div>
                      )}
                    </Show>
                  </div>

                  <pre class="min-h-0 flex-1 overflow-auto p-3.5 font-mono text-[11.5px] leading-relaxed text-emerald-100/95 whitespace-pre-wrap">
                    {wb.selectedRunForActiveSlot()
                      ? `$ ${wb.selectedRunForActiveSlot()!.commandPreview}\n` +
                        `[runtime=${wb.selectedRunForActiveSlot()!.runtime} | status=${wb.selectedRunForActiveSlot()!.status}${
                          wb.selectedRunForActiveSlot()!.outputLogPath
                            ? ` | arquivo=${wb.selectedRunForActiveSlot()!.outputLogPath}`
                            : ""
                        }]\n\n` +
                        (wb.selectedRunForActiveSlot()!.outputTail || "(aguardando saída do processo...)")
                      : `Pronto para executar ${slot().name}.\n` +
                        `• Todas as saídas são salvas automaticamente em .cyberlab/outputs/ (acessível na barra esquerda).\n` +
                        `• No Windows, binários instalados no Kali WSL2 são executados automaticamente com tradução C:\\ -> /mnt/c/!`}
                  </pre>
                </div>
              </div>
            </Show>

            {/* MODO C: DESKTOP GUI INTEGRADA AO PALCO CENTRAL (noVNC/X11) + JANELA NATIVA WINDOWS */}
            <Show when={slot().kind === "desktop_gui"}>
              <Show
                when={slot().embedUrl}
                fallback={
                  <div class="min-h-0 flex-1 overflow-y-auto p-4 space-y-4">
                    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
                      <div class="rounded-xl border border-emerald-600/40 bg-v2-background-bg-deep/65 p-4 space-y-3">
                        <div class="text-[14.5px] font-semibold text-v2-text-text-strong">
                          Palco Central Integrado — {slot().name}
                        </div>
                        <p class="text-[12px] text-v2-text-text-muted">
                          Você pode abrir a interface gráfica completa do <strong>{slot().shortLabel}</strong>{" "}
                          <strong>aqui dentro desta coluna central do CyberLab OS</strong> (via motor gráfico X11/noVNC do seu Kali WSL2, redimensionando automaticamente com as barras laterais) ou em uma janela solta do Windows.
                        </p>
                        <div class="flex flex-wrap gap-2 pt-1">
                          <button
                            type="button"
                            disabled={wb.ui.busy}
                            class="rounded-lg bg-emerald-600 px-4 py-2 text-[12px] font-semibold text-white hover:bg-emerald-500 cursor-pointer disabled:opacity-60"
                            onClick={() =>
                              void wb.launchSlot({
                                slotId: slot().slotId,
                                action: "start_web",
                              })
                            }
                          >
                            {wb.ui.busy
                              ? `⏳ Carregando ${slot().shortLabel} no Centro...`
                              : `🖥 Abrir ${slot().shortLabel} Aqui Dentro do CyberLab`}
                          </button>

                          <Show when={slot().slotId === "burp-suite"}>
                            <button
                              type="button"
                              disabled={wb.ui.busy}
                              class="rounded-lg border border-amber-500/60 bg-amber-600/20 px-3.5 py-2 text-[11.5px] font-semibold text-amber-300 hover:bg-amber-600/35 cursor-pointer disabled:opacity-50"
                              onClick={() =>
                                void wb.launchSlot({
                                  slotId: "burp-suite",
                                  action: "launch_desktop",
                                  rawArgs: "__clean_reinstall_burp__",
                                })
                              }
                            >
                              🧹 Limpar Versões Antigas + Baixar Burp Community Oficial
                            </button>
                          </Show>

                          <button
                            type="button"
                            class="rounded-lg border border-v2-border-border-base bg-v2-background-bg-base px-3.5 py-2 text-[12px] font-medium text-v2-text-text-strong hover:border-emerald-500 cursor-pointer"
                            onClick={() =>
                              void wb.launchSlot({
                                slotId: slot().slotId,
                                action: "launch_desktop",
                                target: wb.ui.cliTargetBySlot[slot().slotId] ?? "",
                              })
                            }
                          >
                            🪟 Abrir Janela Externa ({slot().shortLabel})
                          </button>

                          <Show when={slot().companionProxyPort}>
                            {(port) => (
                              <button
                                type="button"
                                class="rounded-lg bg-sky-600 px-3.5 py-2 text-[12px] font-semibold text-white hover:bg-sky-500 cursor-pointer"
                                onClick={() =>
                                  void wb.launchProxyBrowser({
                                    proxyPort: port(),
                                    startUrl: "https://example.com",
                                  })
                                }
                              >
                                🌐 Navegador Isolado no Proxy (:{port()})
                              </button>
                            )}
                          </Show>
                        </div>
                        <Show when={slot().resolvedPath}>
                          <div class="font-mono text-[10.5px] text-emerald-400">
                            Detectado em: {slot().resolvedPath}
                          </div>
                        </Show>

                        {/* Seletor rápido de outra versão (.jar ou .exe do PC) */}
                        <div class="mt-2 rounded-lg border border-v2-border-border-base bg-v2-background-bg-base/75 p-2.5 space-y-2">
                          <div class="flex flex-wrap items-center justify-between gap-2">
                            <span class="text-[11px] font-medium text-v2-text-text-strong">
                              📂 Tem outra versão instalada ou baixada (.jar ou .exe)?
                            </span>
                            <button
                              type="button"
                              disabled={wb.ui.busy}
                              class="rounded bg-emerald-600/20 border border-emerald-500/50 px-2.5 py-1 text-[10.5px] font-semibold text-emerald-400 hover:bg-emerald-600/30 cursor-pointer"
                              onClick={() =>
                                void wb.launchSlot({
                                  slotId: slot().slotId,
                                  action: "launch_desktop",
                                  rawArgs: "__pick_executable__",
                                })
                              }
                            >
                              📂 Procurar Arquivo (.jar / .exe) no Windows...
                            </button>
                          </div>
                          <div class="flex flex-wrap items-center gap-1.5">
                            <input
                              type="text"
                              placeholder={`Ou cole o caminho (ex.: C:\\Users\\Admin\\Downloads\\burpsuite_community.jar)`}
                              value={burpQuickPath()}
                              class="min-w-[210px] flex-1 rounded border border-v2-border-border-base bg-zinc-950 px-2 py-1 font-mono text-[10.5px] text-zinc-100"
                              onInput={(e) => setBurpQuickPath(e.currentTarget.value)}
                            />
                            <button
                              type="button"
                              class="rounded bg-emerald-600 px-2.5 py-1 text-[10.5px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                              onClick={() => {
                                if (!burpQuickPath().trim()) return
                                void wb.configureArsenal({
                                  slotId: slot().slotId,
                                  slotOverride: { customExecutablePath: burpQuickPath().trim() },
                                })
                                setBurpQuickPath("")
                              }}
                            >
                              Vincular Versão
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* Card Especial de Sinergia Burp Suite + OpenTRAP */}
                      <Show when={slot().slotId === "burp-suite" || slot().slotId === "opentrap"}>
                        <div class="rounded-xl border border-emerald-600/35 bg-emerald-950/20 p-4 space-y-2">
                          <div class="text-[13px] font-semibold text-emerald-400">
                            ⚡ Sinergia Real: Burp Suite Community + OpenTRAP
                          </div>
                          <ul class="list-disc pl-4 space-y-1 text-[11.5px] text-v2-text-text-base">
                            <li>
                              <strong>Burp Suite Community (`:8080`)</strong>: Melhor ergonomia manual para Proxy, Repeater multi-abas, Decoder, Comparer e extensões BApp (Autorize, Param Miner). Use <strong>"🧹 Limpar Versões Antigas + Baixar Burp Community Oficial"</strong> para instalar o <code>burpsuite.jar</code> oficial mais recente da PortSwigger CDN sem conflito com instaladores antigos!
                            </li>
                            <li>
                              <strong>OpenTRAP (Kali WSL2)</strong>: Entrega gratuitamente os 3 recursos bloqueados no Burp Community — <strong>Intruder sem limite de velocidade</strong>, <strong>Scanner Ativo real (OWASP ZAP)</strong> e <strong>Collaborator OAST nativo (Interactsh)</strong>!
                            </li>
                            <li>
                              <strong>Multitarefa Real</strong>: Você pode abrir ambos dentro do CyberLab OS e alternar entre eles na barra esquerda em 1 clique sem perder a sessão!
                            </li>
                          </ul>
                        </div>
                      </Show>
                    </div>

                    <Show when={wb.selectedRunForActiveSlot()}>
                      {(run) => (
                        <div class="rounded-xl border border-emerald-600/40 bg-zinc-950 p-3.5 text-left space-y-1.5">
                          <div class="flex items-center justify-between text-[11.5px] font-semibold text-emerald-400">
                            <span>📦 Console ao Vivo — {slot().shortLabel} ({run().status})</span>
                            <span class="font-mono text-[10.5px] text-zinc-400">{run().runtime}</span>
                          </div>
                          <pre class="max-h-60 overflow-auto font-mono text-[11px] leading-relaxed text-emerald-100/95 whitespace-pre-wrap">
                            {`$ ${run().commandPreview}\n\n${run().outputTail || "(aguardando saída do instalador...)"}`}
                          </pre>
                        </div>
                      )}
                    </Show>

                    {/* Ingestão de Exportações / Requests / Achados da GUI para SHA-256 + Agente IA */}
                    <div class="rounded-xl border border-v2-border-border-base bg-v2-background-bg-deep/40 p-4 space-y-2.5">
                      <div class="text-[12.5px] font-semibold text-v2-text-text-strong">
                        Ponte Rápida: Colar Request HTTP / Descompilação / Log da GUI para Custódia SHA-256 ou Agente OpenCode
                      </div>
                      <textarea
                        rows={5}
                        placeholder={`Cole aqui um request/response do ${slot().shortLabel}, código descompilado do Ghidra/JADX ou alerta do Scanner para gravar com hash SHA-256 ou analisar com o Agente IA à direita...`}
                        value={desktopIngestText()}
                        class="w-full rounded-lg border border-v2-border-border-base bg-zinc-950 p-2.5 font-mono text-[11.5px] text-zinc-100 outline-none focus:border-emerald-500"
                        onInput={(e) => setDesktopIngestText(e.currentTarget.value)}
                      />
                      <div class="flex flex-wrap gap-2">
                        <button
                          type="button"
                          class="rounded-md bg-sky-600 px-3 py-1.5 text-[11.5px] font-medium text-white hover:bg-sky-500 cursor-pointer"
                          onClick={() => {
                            void wb.persistOutputToEvidence(
                              `Captura Manual — ${slot().name}`,
                              desktopIngestText(),
                              slot().slotId,
                            )
                          }}
                        >
                          🔒 Gravar em Custódia SHA-256
                        </button>
                        <button
                          type="button"
                          class="rounded-md bg-emerald-600 px-3 py-1.5 text-[11.5px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                          onClick={() =>
                            wb.sendToAgent(
                              `Artefato de ${slot().name}`,
                              desktopIngestText(),
                              `${slot().slotId}-capture.txt`,
                            )
                          }
                        >
                          🤖 Enviar p/ Agente OpenCode →
                        </button>
                      </div>
                    </div>
                  </div>
                }
              >
                {(url) => (
                  <div class="flex min-h-0 flex-1 flex-col overflow-hidden">
                    <Show when={wb.ui.topControlsOpen}>
                      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-v2-border-border-base bg-v2-background-bg-base px-3 py-1 text-[11px] shrink-0">
                        <div class="flex flex-wrap items-center gap-2 min-w-0">
                          <span class="inline-block size-2 rounded-full bg-emerald-500" />
                          <span class="font-medium text-emerald-400">
                            {slot().shortLabel}
                          </span>

                          {/* Controles Ao Vivo de Nitidez 1:1 + Enquadramento + Rolagem + Zoom Sem Deslocar o Cursor */}
                          <div class="flex items-center gap-1 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-1.5 py-0.5">
                            <button
                              type="button"
                              title="Resolução X11 nativa 1:1 com zoom sem deslocamento de mouse (padrão recomendado)"
                              class={`rounded px-1.5 py-0.5 text-[10px] font-medium cursor-pointer ${
                                getSlotFraming(slot()) === "native"
                                  ? "bg-emerald-600 text-white"
                                  : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                              }`}
                              onClick={() => syncCanvasControl(slot(), "native")}
                            >
                              🖥 1:1 Nitidez
                            </button>
                            <button
                              type="button"
                              title="Enquadrar janela inteira na área central"
                              class={`rounded px-1.5 py-0.5 text-[10px] font-medium cursor-pointer ${
                                getSlotFraming(slot()) === "fit"
                                  ? "bg-emerald-600 text-white"
                                  : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                              }`}
                              onClick={() => syncCanvasControl(slot(), "fit")}
                            >
                              📐 Ajustar
                            </button>
                            <button
                              type="button"
                              title="Ativar barras de rolagem mantendo 100% de precisão do clique em qualquer zoom"
                              class={`rounded px-1.5 py-0.5 text-[10px] font-medium cursor-pointer ${
                                getSlotFraming(slot()) === "scroll"
                                  ? "bg-emerald-600 text-white"
                                  : "text-v2-text-text-muted hover:text-v2-text-text-strong"
                              }`}
                              onClick={() => syncCanvasControl(slot(), "scroll")}
                            >
                              ↕ Rolagem
                            </button>
                            <button
                              type="button"
                              title="Diminuir escala (-10% mantendo precisão exata do mouse)"
                              class="rounded px-1.5 py-0.5 text-[10.5px] font-bold text-v2-text-text-base hover:bg-v2-background-bg-base cursor-pointer"
                              onClick={() => {
                                const curMode = getSlotFraming(slot())
                                const targetMode = curMode === "fit" ? "native" : curMode
                                const next = Math.max(60, getSlotZoom(slot()) - 10)
                                syncCanvasControl(slot(), targetMode, next)
                              }}
                            >
                              −
                            </button>
                            <button
                              type="button"
                              title="Restaurar zoom 100%"
                              class="rounded px-1 py-0.5 font-mono text-[10px] text-emerald-400 hover:bg-v2-background-bg-base cursor-pointer"
                              onClick={() => syncCanvasControl(slot(), getSlotFraming(slot()), 100)}
                            >
                              {getSlotZoom(slot())}%
                            </button>
                            <button
                              type="button"
                              title="Aumentar escala (+10% mantendo precisão exata do mouse)"
                              class="rounded px-1.5 py-0.5 text-[10.5px] font-bold text-v2-text-text-base hover:bg-v2-background-bg-base cursor-pointer"
                              onClick={() => {
                                const curMode = getSlotFraming(slot())
                                const targetMode = curMode === "fit" ? "native" : curMode
                                const next = Math.min(160, getSlotZoom(slot()) + 10)
                                syncCanvasControl(slot(), targetMode, next)
                              }}
                            >
                              +
                            </button>
                          </div>
                        </div>
                        <div class="flex flex-wrap items-center gap-1.5">
                          <button
                            type="button"
                            title="Recolher todas as barras superiores na vertical para maximizar a altura da ferramenta"
                            class="rounded border border-emerald-600/50 bg-emerald-600/15 px-2 py-0.5 text-[10.5px] font-medium text-emerald-400 hover:bg-emerald-600/25 cursor-pointer"
                            onClick={() => toggleTopDrawer(false)}
                          >
                            ▲ Recolher Topo
                          </button>
                          <button
                            type="button"
                            title="Recolher/restaurar barras laterais e topo para dar espaço máximo à ferramenta"
                            class="rounded border border-v2-border-border-base px-2 py-0.5 text-[10.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                            onClick={toggleMaximizeCenter}
                          >
                            {!wb.ui.leftSidebarOpen && !wb.ui.rightAgentOpen ? "◫ Painéis" : "⛶ Ampliar"}
                          </button>
                          <button
                            type="button"
                            title="Escolher outro arquivo .jar ou .exe no Windows"
                            class="rounded border border-v2-border-border-base px-2 py-0.5 text-[10.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                            onClick={() =>
                              void wb.launchSlot({
                                slotId: slot().slotId,
                                action: "launch_desktop",
                                rawArgs: "__pick_executable__",
                              })
                            }
                          >
                            📂 Outra Versão
                          </button>
                          <button
                            type="button"
                            class="rounded border border-v2-border-border-base px-2 py-0.5 text-[10.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                            onClick={() => setShowDesktopIngestDrawer((v) => !v)}
                          >
                            📋 SHA-256 / IA
                          </button>
                          <button
                            type="button"
                            class="rounded border border-v2-border-border-base px-2 py-0.5 text-[10.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                            onClick={() => wb.setUi("iframeReloadNonce", (n) => n + 1)}
                          >
                            ↻ Reconectar
                          </button>
                          <button
                            type="button"
                            class="rounded border border-v2-border-border-base px-2 py-0.5 text-[10.5px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                            onClick={() =>
                              void wb.launchSlot({
                                slotId: slot().slotId,
                                action: "launch_desktop",
                              })
                            }
                          >
                            🪟 Janela Externa
                          </button>
                          <button
                            type="button"
                            class="rounded border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[10.5px] text-red-400 hover:bg-red-500/20 cursor-pointer"
                            onClick={() =>
                              void wb.launchSlot({
                                slotId: slot().slotId,
                                action: "stop_web",
                              })
                            }
                          >
                            ⏹ Fechar
                          </button>
                        </div>
                      </div>
                    </Show>

                    <Show when={showDesktopIngestDrawer()}>
                      <div class="border-b border-v2-border-border-base bg-v2-background-bg-deep/90 p-2.5 space-y-2 shrink-0">
                        <textarea
                          rows={3}
                          placeholder={`Cole aqui um request/response ou achado do ${slot().shortLabel} p/ gravar em SHA-256 ou enviar ao Agente OpenCode...`}
                          value={desktopIngestText()}
                          class="w-full rounded border border-v2-border-border-base bg-zinc-950 p-2 font-mono text-[11px] text-zinc-100 outline-none focus:border-emerald-500"
                          onInput={(e) => setDesktopIngestText(e.currentTarget.value)}
                        />
                        <div class="flex items-center gap-2">
                          <button
                            type="button"
                            class="rounded bg-sky-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-sky-500 cursor-pointer"
                            onClick={() => {
                              void wb.persistOutputToEvidence(
                                `Captura Manual — ${slot().name}`,
                                desktopIngestText(),
                                slot().slotId,
                              )
                            }}
                          >
                            🔒 Gravar SHA-256
                          </button>
                          <button
                            type="button"
                            class="rounded bg-emerald-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                            onClick={() =>
                              wb.sendToAgent(
                                `Artefato de ${slot().name}`,
                                desktopIngestText(),
                                `${slot().slotId}-capture.txt`,
                              )
                            }
                          >
                            🤖 Enviar p/ Agente IA →
                          </button>
                        </div>
                      </div>
                    </Show>

                    <iframe
                      ref={(el) => {
                        activeToolIframeRef = el
                      }}
                      data-slot="cyberlab-embedded-gui-iframe"
                      src={`${url()}${url().includes("?") ? "&" : "?"}_cb=${wb.ui.iframeReloadNonce}`}
                      title={slot().name}
                      onLoad={() => syncCanvasControl(slot())}
                      class="h-full w-full min-h-0 flex-1 border-0 bg-zinc-950"
                      allow="clipboard-read; clipboard-write; fullscreen"
                      allowfullscreen
                    />
                  </div>
                )}
              </Show>
            </Show>
          </div>
        )}
      </Show>

      {/* ===================================================================== */}
      {/* VISÃO 2: ESCOPO BUG BOUNTY & REGRAS DE ENGAJAMENTO                    */}
      {/* ===================================================================== */}
      <Show when={wb.ui.centerView === "scope"}>
        <div class="min-h-0 flex-1 overflow-y-auto p-4 space-y-4">
          <div class="rounded-xl border border-v2-border-border-base bg-v2-background-bg-deep/50 p-4 space-y-3">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-[14px] font-semibold text-v2-text-text-strong">
                  Importador de Escopo Real (HackerOne / Bugcrowd / Wildcards)
                </h3>
                <p class="text-[11.5px] text-v2-text-text-muted">
                  Trava automaticamente execuções CLI fora de escopo para proteger sua conta de pesquisador.
                </p>
              </div>
              <label class="inline-flex items-center gap-2 text-[11.5px] text-v2-text-text-strong cursor-pointer">
                <input
                  type="checkbox"
                  checked={wb.backend.arsenal?.environment.enforceScopeOnCliRuns !== false}
                  onChange={(e) =>
                    void wb.configureArsenal({ enforceScopeOnCliRuns: e.currentTarget.checked })
                  }
                />
                <span>Bloquear alvos fora de escopo nos Slots CLI</span>
              </label>
            </div>

            <textarea
              rows={5}
              placeholder={"Cole JSON do HackerOne/Bugcrowd ou linhas de escopo:\n*.alvo-autorizado.com\nhttps://api.alvo-autorizado.com\n!pagamentos.alvo-autorizado.com"}
              value={scopeRawText()}
              class="w-full rounded-lg border border-v2-border-border-base bg-zinc-950 p-2.5 font-mono text-[11.5px] text-zinc-100"
              onInput={(e) => setScopeRawText(e.currentTarget.value)}
            />

            <div class="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <input
                type="text"
                placeholder="Seu Handle (ex.: vitor)"
                value={scopeHandle()}
                class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1.5 text-[11.5px] text-v2-text-text-strong"
                onInput={(e) => setScopeHandle(e.currentTarget.value)}
              />
              <input
                type="text"
                placeholder="Header (ex.: X-Bug-Bounty)"
                value={scopeHeaderName()}
                class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1.5 text-[11.5px] text-v2-text-text-strong"
                onInput={(e) => setScopeHeaderName(e.currentTarget.value)}
              />
              <input
                type="text"
                placeholder="Valor do Header (ex.: HackerOne-vitor)"
                value={scopeHeaderVal()}
                class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1.5 text-[11.5px] text-v2-text-text-strong"
                onInput={(e) => setScopeHeaderVal(e.currentTarget.value)}
              />
            </div>

            <button
              type="button"
              class="rounded-lg bg-emerald-600 px-4 py-1.5 text-[12px] font-semibold text-white hover:bg-emerald-500 cursor-pointer"
              onClick={() =>
                void wb.importScope({
                  rawInput: scopeRawText(),
                  ...(scopeHandle().trim() ? { researcherHandle: scopeHandle().trim() } : {}),
                  ...(scopeHeaderName().trim() ? { headerName: scopeHeaderName().trim() } : {}),
                  ...(scopeHeaderVal().trim() ? { headerValue: scopeHeaderVal().trim() } : {}),
                })
              }
            >
              Importar & Ativar Escopo
            </button>
          </div>

          <Show when={wb.backend.status?.activeScope}>
            {(sc) => (
              <div class="rounded-xl border border-v2-border-border-base bg-v2-background-bg-deep/35 p-4 space-y-2 text-[11.5px]">
                <div class="font-semibold text-v2-text-text-strong">
                  Escopo Ativo: {sc().name} ({sc().allowExternalTargets ? "Alvos Externos Liberados" : "Apenas Loopback/Lab"})
                </div>
                <div class="text-emerald-400">
                  Em Escopo ({sc().allowedTargets.length}):{" "}
                  {sc().allowedTargets.map((r) => `${r.kind}:${r.value}`).join(", ")}
                </div>
                <Show when={sc().blockedTargets.length > 0}>
                  <div class="text-red-400">
                    Fora de Escopo ({sc().blockedTargets.length}):{" "}
                    {sc().blockedTargets.map((r) => `${r.kind}:${r.value}`).join(", ")}
                  </div>
                </Show>
              </div>
            )}
          </Show>
        </div>
      </Show>

      {/* ===================================================================== */}
      {/* VISÃO 3: 5 LABORATÓRIOS INTERATIVOS DE TREINAMENTO MANTIDOS           */}
      {/* ===================================================================== */}
      <Show when={wb.ui.centerView === "labs"}>
        <div class="min-h-0 flex-1 overflow-y-auto p-4 space-y-3">
          <div class="text-[14px] font-semibold text-v2-text-text-strong">
            5 Laboratórios Locais Interativos de Treinamento (Alvos Seguros p/ Testar o Arsenal Real)
          </div>
          <For each={wb.backend.projectsAndLabs?.labs ?? []}>
            {(lab) => (
              <div class="rounded-xl border border-v2-border-border-base bg-v2-background-bg-deep/45 p-4 space-y-2">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <span class="text-[13px] font-semibold text-v2-text-text-strong">{lab.title}</span>
                    <span class="ml-2 rounded bg-emerald-600/20 px-2 py-0.5 text-[10px] text-emerald-400">
                      {lab.difficulty}
                    </span>
                  </div>
                  <div class="flex items-center gap-1.5">
                    <button
                      type="button"
                      class="rounded bg-emerald-600 px-3 py-1 text-[11px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                      onClick={() => void wb.controlTrainingLab("start", lab.labId)}
                    >
                      {lab.running ? "Selecionar Lab" : "▶ Iniciar Lab"}
                    </button>
                    <button
                      type="button"
                      class="rounded border border-v2-border-border-base px-2.5 py-1 text-[11px] text-v2-text-text-base hover:border-amber-500 cursor-pointer"
                      onClick={() => void wb.controlTrainingLab("reset", lab.labId)}
                    >
                      Resetar
                    </button>
                    <Show when={lab.running}>
                      <button
                        type="button"
                        class="rounded border border-red-500/40 px-2.5 py-1 text-[11px] text-red-400 cursor-pointer"
                        onClick={() => void wb.controlTrainingLab("stop", lab.labId)}
                      >
                        Parar
                      </button>
                    </Show>
                  </div>
                </div>
                <p class="text-[11.5px] text-v2-text-text-muted">{lab.summary}</p>
                <Show when={lab.baseUrl}>
                  <div class="flex items-center gap-2 font-mono text-[11px] text-emerald-400">
                    <span>URL ao vivo: {lab.baseUrl}</span>
                    <button
                      type="button"
                      class="rounded bg-emerald-600/20 px-2 py-0.5 text-[10px] hover:bg-emerald-600/35 cursor-pointer"
                      onClick={() => copyText(wb, lab.baseUrl!, "URL do Lab")}
                    >
                      Copiar URL p/ Burp/OpenTRAP/Nuclei
                    </button>
                  </div>
                </Show>

                {/* v6.6 — NAVEGADOR DO ALVO EMBUTIDO (como o Chromium do Burp Suite) */}
                <Show when={lab.running && lab.baseUrl}>
                  <div class="mt-2 rounded-lg border border-emerald-600/30 bg-black/40">
                    <div class="flex flex-wrap items-center justify-between gap-2 border-b border-emerald-600/20 px-3 py-2">
                      <span class="text-[11px] font-semibold text-emerald-400">
                        🌐 Navegador do alvo (embutido)
                      </span>
                      <div class="flex items-center gap-1.5">
                        <Show when={labBrowser()[lab.labId]}>
                          <button
                            type="button"
                            class="rounded border border-v2-border-border-base px-2 py-0.5 text-[10px] text-v2-text-text-base hover:border-emerald-500 cursor-pointer"
                            onClick={() =>
                              setLabBrowser((prev) => ({ ...prev, [lab.labId]: (prev[lab.labId] ?? 0) + 1 }))
                            }
                          >
                            🔄 Recarregar
                          </button>
                          <button
                            type="button"
                            class="rounded border border-v2-border-border-base px-2 py-0.5 text-[10px] text-v2-text-text-muted hover:text-red-400 cursor-pointer"
                            onClick={() =>
                              setLabBrowser((prev) => {
                                const next = { ...prev }
                                delete next[lab.labId]
                                return next
                              })
                            }
                          >
                            Fechar
                          </button>
                        </Show>
                        <a
                          href={`${lab.baseUrl}/`}
                          target="_blank"
                          rel="noreferrer"
                          class="rounded border border-emerald-600/40 px-2 py-0.5 text-[10px] text-emerald-400 hover:bg-emerald-600/20"
                        >
                          ↗ Abrir no navegador do sistema
                        </a>
                      </div>
                    </div>

                    <Show
                      when={labBrowser()[lab.labId]}
                      fallback={
                        <div class="px-3 py-3">
                          <button
                            type="button"
                            class="rounded bg-emerald-600 px-3 py-1 text-[11px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                            onClick={() => setLabBrowser((prev) => ({ ...prev, [lab.labId]: 1 }))}
                          >
                            ▶ Abrir o alvo aqui dentro
                          </button>
                          <p class="mt-1.5 text-[10.5px] text-v2-text-text-muted">
                            Abre <code class="text-emerald-400">{lab.baseUrl}/</code> neste painel, do mesmo
                            jeito que o Burp Suite embute o Chromium para navegar no alvo.
                          </p>
                        </div>
                      }
                    >
                      {(nonce) => (
                        <iframe
                          data-slot="cyberlab-lab-target-browser"
                          src={`${lab.baseUrl}/?_cb=${nonce()}`}
                          title={`Alvo: ${lab.title}`}
                          class="h-[520px] w-full border-0 bg-zinc-950"
                          allow="clipboard-read; clipboard-write; fullscreen"
                          allowfullscreen
                        />
                      )}
                    </Show>

                    <p class="border-t border-emerald-600/20 px-3 py-1.5 text-[10px] leading-snug text-v2-text-text-muted">
                      Dica: se o painel ficar em branco, é porque o lab está com{" "}
                      <code class="text-amber-400">enableSecurityHeaders: true</code> — aí ele mesmo
                      proíbe ser embutido (<code>X-Frame-Options: DENY</code> +
                      <code> frame-ancestors &#39;none&#39;</code>). Isso é o header funcionando, não um
                      bug: use <span class="text-emerald-400">↗ Abrir no navegador do sistema</span>.
                    </p>
                  </div>
                </Show>
              </div>
            )}
          </For>
        </div>
      </Show>

      {/* ===================================================================== */}
      {/* VISÃO 4: 4 CDIs AUTÔNOMOS HORIZONTAIS (Kairós, Naia, Salem, Nova)     */}
      {/* ===================================================================== */}
      <Show when={wb.ui.centerView === "cdi"}>
        <div class="min-h-0 flex-1 overflow-y-auto p-4 space-y-4">
          <div class="rounded-xl border border-v2-border-border-base bg-v2-background-bg-deep/50 p-4 space-y-3">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 class="text-[14px] font-semibold text-v2-text-text-strong">
                  Hub de Parceria Horizontal — 4 CDIs Autônomos (`HMAC-SHA256`)
                </h3>
                <p class="text-[11.5px] text-v2-text-text-muted">
                  Kairós (:8788) · Naia (:8789) · Salem (:8790) · Nova (:8791) — Gateway:{" "}
                  <code class="text-emerald-400">{wb.backend.partners?.cyberlabCallbackUrl}</code>
                </p>
              </div>
              <div class="flex items-center gap-1.5">
                <button
                  type="button"
                  class="rounded bg-emerald-600 px-3 py-1 text-[11px] font-medium text-white hover:bg-emerald-500 cursor-pointer"
                  onClick={() => void wb.manageCdiPreset4()}
                >
                  Carregar Preset 4 CDIs
                </button>
                <button
                  type="button"
                  class="rounded border border-v2-border-border-base px-2.5 py-1 text-[11px] text-v2-text-text-base cursor-pointer"
                  onClick={() => void wb.manageCdiSecret("reveal")}
                >
                  Revelar Segredo
                </button>
                <button
                  type="button"
                  class="rounded border border-v2-border-border-base px-2.5 py-1 text-[11px] text-v2-text-text-base cursor-pointer"
                  onClick={() => void wb.manageCdiSecret("generate")}
                >
                  Gerar Novo Segredo
                </button>
              </div>
            </div>

            <Show when={wb.backend.revealedSecret}>
              <div class="rounded bg-zinc-950 p-2 font-mono text-[11px] text-amber-300">
                CYBERLAB_PARTNER_SECRET={wb.backend.revealedSecret}
              </div>
            </Show>

            <div class="flex items-center gap-2">
              <input
                type="text"
                placeholder="Ou defina seu próprio CYBERLAB_PARTNER_SECRET (>= 16 caracteres)"
                value={cdiCustomSecret()}
                class="flex-1 rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] text-v2-text-text-strong"
                onInput={(e) => setCdiCustomSecret(e.currentTarget.value)}
              />
              <button
                type="button"
                class="rounded border border-emerald-600/50 px-3 py-1 text-[11px] text-emerald-400 cursor-pointer"
                onClick={() => void wb.manageCdiSecret("custom", cdiCustomSecret())}
              >
                Salvar Segredo
              </button>
            </div>
          </div>

          <div class="rounded-xl border border-v2-border-border-base bg-v2-background-bg-deep/40 p-4 space-y-2.5">
            <div class="text-[12.5px] font-semibold text-v2-text-text-strong">
              Disparo Simultâneo / Individual aos CDIs
            </div>
            <div class="flex flex-wrap gap-2">
              <For each={wb.backend.partners?.partners ?? []}>
                {(p) => (
                  <label class="inline-flex items-center gap-1.5 rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11px] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedCdis().includes(p.partnerId)}
                      onChange={(e) => {
                        setSelectedCdis((prev) =>
                          e.currentTarget.checked
                            ? [...prev, p.partnerId]
                            : prev.filter((id) => id !== p.partnerId),
                        )
                      }}
                    />
                    <span class="font-medium text-v2-text-text-strong">{p.displayName}</span>
                    <span class="text-v2-text-text-muted">({p.endpointUrl})</span>
                  </label>
                )}
              </For>
            </div>
            <textarea
              rows={3}
              placeholder="Objetivo compartilhado para investigação paralela dos CDIs..."
              value={cdiObjective()}
              class="w-full rounded border border-v2-border-border-base bg-zinc-950 p-2 text-[11.5px] text-zinc-100"
              onInput={(e) => setCdiObjective(e.currentTarget.value)}
            />
            <button
              type="button"
              class="rounded bg-emerald-600 px-4 py-1.5 text-[11.5px] font-semibold text-white hover:bg-emerald-500 cursor-pointer"
              onClick={() =>
                void wb.dispatchToCdis({
                  partnerIds: selectedCdis(),
                  objective: cdiObjective(),
                })
              }
            >
              Disparar em Paralelo
            </button>
            <Show when={wb.backend.lastCdiDispatchSummary}>
              <pre class="rounded bg-zinc-950 p-2.5 font-mono text-[11px] text-emerald-200 whitespace-pre-wrap">
                {wb.backend.lastCdiDispatchSummary}
              </pre>
            </Show>
          </div>
        </div>
      </Show>

      {/* ===================================================================== */}
      {/* VISÃO 5: CUSTÓDIA SHA-256, FINDINGS & RELATÓRIO MARKDOWN              */}
      {/* ===================================================================== */}
      <Show when={wb.ui.centerView === "custody"}>
        <div class="min-h-0 flex-1 overflow-y-auto p-4 space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-[14px] font-semibold text-v2-text-text-strong">
              Cofre de Evidências SHA-256 ({wb.backend.evidence.length}) & Findings ({wb.backend.findings.length})
            </h3>
            <button
              type="button"
              class="rounded bg-emerald-600 px-3.5 py-1.5 text-[11.5px] font-semibold text-white hover:bg-emerald-500 cursor-pointer"
              onClick={() => void wb.generateReport()}
            >
              📄 Gerar Relatório Bug Bounty / Pentest (Markdown)
            </button>
          </div>

          <Show when={wb.backend.reportMarkdown}>
            <div class="rounded-xl border border-emerald-600/40 bg-zinc-950 p-3 space-y-2">
              <div class="flex items-center justify-between text-[11px] text-emerald-400">
                <span>Relatório Técnico Gerado</span>
                <button
                  type="button"
                  class="rounded bg-emerald-600/25 px-2 py-0.5 cursor-pointer"
                  onClick={() => copyText(wb, wb.backend.reportMarkdown, "Relatório Markdown")}
                >
                  Copiar Markdown
                </button>
              </div>
              <pre class="max-h-56 overflow-auto font-mono text-[11px] text-zinc-200 whitespace-pre-wrap">
                {wb.backend.reportMarkdown}
              </pre>
            </div>
          </Show>

          {/* Registro Rápido de Finding */}
          <div class="rounded-xl border border-v2-border-border-base bg-v2-background-bg-deep/45 p-3.5 space-y-2">
            <div class="text-[12px] font-semibold text-v2-text-text-strong">Novo Finding Estruturado</div>
            <div class="flex flex-wrap gap-2">
              <input
                type="text"
                placeholder="Título (ex.: IDOR em /api/v2/invoices/{id})"
                value={findingTitle()}
                class="flex-1 rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11.5px] text-v2-text-text-strong"
                onInput={(e) => setFindingTitle(e.currentTarget.value)}
              />
              <select
                value={findingSev()}
                class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1 text-[11.5px] text-v2-text-text-strong"
                onChange={(e) => setFindingSev(e.currentTarget.value as never)}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <textarea
              rows={2}
              placeholder="Descrição técnica e impacto reproduzível..."
              value={findingDesc()}
              class="w-full rounded border border-v2-border-border-base bg-v2-background-bg-base p-2 text-[11.5px] text-v2-text-text-strong"
              onInput={(e) => setFindingDesc(e.currentTarget.value)}
            />
            <button
              type="button"
              class="rounded bg-emerald-600 px-3 py-1 text-[11.5px] font-medium text-white cursor-pointer"
              onClick={() => {
                if (!findingTitle().trim()) return
                void wb.createFinding({
                  title: findingTitle().trim(),
                  description: findingDesc().trim() || findingTitle().trim(),
                  severity: findingSev(),
                  evidenceIds: wb.backend.evidence.slice(0, 1).map((e) => e.evidenceId),
                  affectedAssets: [],
                })
                setFindingTitle("")
                setFindingDesc("")
              }}
            >
              Salvar Finding
            </button>
          </div>

          {/* Lista de Evidências */}
          <div class="space-y-1.5">
            <For each={wb.backend.evidence}>
              {(ev) => (
                <div class="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-v2-border-border-base bg-v2-background-bg-deep/35 px-3 py-2 text-[11.5px]">
                  <div class="min-w-0 flex-1">
                    <div class="font-medium text-v2-text-text-strong truncate">{ev.title}</div>
                    <div class="font-mono text-[10px] text-v2-text-text-muted">
                      {ev.evidenceId} · SHA-256: {ev.sha256.slice(0, 20)}… · {ev.redactionStatus}
                    </div>
                  </div>
                  <div class="flex items-center gap-1.5">
                    <button
                      type="button"
                      class="rounded border border-v2-border-border-base px-2 py-0.5 text-[10.5px] text-v2-text-text-base cursor-pointer"
                      onClick={() => void wb.readEvidence(ev.evidenceId)}
                    >
                      Inspecionar
                    </button>
                    <button
                      type="button"
                      class="rounded border border-emerald-600/50 px-2 py-0.5 text-[10.5px] text-emerald-400 cursor-pointer"
                      onClick={() => void wb.verifyEvidence(ev.evidenceId)}
                    >
                      Verificar SHA-256
                    </button>
                  </div>
                </div>
              )}
            </For>
          </div>

          <Show when={wb.backend.inspectedEvidence}>
            {(ins) => (
              <pre class="max-h-60 overflow-auto rounded-lg bg-zinc-950 p-3 font-mono text-[11px] text-zinc-200 whitespace-pre-wrap">
                {ins().text}
              </pre>
            )}
          </Show>
        </div>
      </Show>

      {/* ===================================================================== */}
      {/* VISÃO 6: GUIA RÁPIDO WINDOWS POWERSHELL + WSL2 KALI LINUX             */}
      {/* ===================================================================== */}
      <Show when={wb.ui.centerView === "guide"}>
        <div class="min-h-0 flex-1 overflow-y-auto p-4 space-y-4 text-[12px]">
          <div class="rounded-xl border border-v2-border-border-base bg-v2-background-bg-deep/55 p-4 space-y-3">
            <h3 class="text-[14px] font-semibold text-v2-text-text-strong">
              Setup Mestre — Windows PowerShell + WSL2 Kali Linux (`C:\CyberLab-Tools`)
            </h3>
            <p class="text-v2-text-text-muted">
              Todas as ferramentas reais ficam instaladas fora do repositório para manter o CyberLab OS leve, rápido e 100% livre de conflitos de licença. Copie e cole no seu <strong>PowerShell (Administrador)</strong>:
            </p>
            <pre class="overflow-x-auto rounded-lg bg-zinc-950 p-3 font-mono text-[11px] text-sky-200 whitespace-pre-wrap">{`# 1. Criar pasta dedicada fora do repositório + instalar WSL2 Kali Linux
New-Item -ItemType Directory -Force -Path C:\\CyberLab-Tools | Out-Null
wsl --install -d kali-linux

# 2. Instalar ferramentas nativas Windows via Winget (PowerShell)
winget install --id PortSwigger.BurpSuite.Community -e
winget install --id Caido.Caido -e
winget install --id ZAP.ZAP -e
winget install --id Insecure.Nmap -e
winget install --id WiresharkFoundation.Wireshark -e
winget install --id ProjectDiscovery.Nuclei -e
winget install --id ProjectDiscovery.Subfinder -e
winget install --id ProjectDiscovery.Httpx -e
winget install --id ProjectDiscovery.Katana -e
winget install --id ffuf.ffuf -e
winget install --id Gitleaks.Gitleaks -e
winget install --id AquaSecurity.Trivy -e
winget install --id Skylot.Jadx -e

# 3. Baixar CyberChef Oficial (GCHQ) para embutir em tela cheia no centro do CyberLab OS!
Invoke-WebRequest -Uri "https://github.com/gchq/CyberChef/releases/latest/download/CyberChef_v10.19.4.zip" -OutFile "$env:TEMP\\cyberchef.zip"
Expand-Archive -Force "$env:TEMP\\cyberchef.zip" "C:\\CyberLab-Tools\\CyberChef"`}</pre>

            <p class="text-v2-text-text-muted pt-1">
              E dentro do <strong>Kali Linux no WSL2</strong> (<code>wsl -d kali-linux</code>), instale todo o arsenal Linux + OpenTRAP + Win-KeX:
            </p>
            <pre class="overflow-x-auto rounded-lg bg-zinc-950 p-3 font-mono text-[11px] text-emerald-200 whitespace-pre-wrap">{`sudo apt update && sudo apt install -y \\
  kali-win-kex mitmproxy sqlmap nmap wireshark tshark netexec \\
  ghidra jadx rizin-cutter apktool python3-frida-tools \\
  nuclei ffuf subfinder naabu dnsx interactsh-client \\
  gitleaks trivy semgrep yara libfuse2 curl jq

# Instalar KeyHunter (Rust CLI - fadidevv/keyhunter) + OpenTRAP AppImage em /opt/opentrap
cargo install github-keyhunter
sudo mkdir -p /opt/opentrap && cd /opt/opentrap
# Baixe a última release Linux x86_64 AppImage de https://github.com/opentrap/opentrap/releases e marque chmod +x!`}</pre>
          </div>
        </div>
      </Show>

      {/* Cofre Flutuante / Lateral Compatível com Obsidian (.md) — abre por cima da ferramenta sem encolher o Centro! */}
      <CyberLabVaultOverlay />
    </section>
  )
}

/** Mantido para compatibilidade caso importado isoladamente */
export function CyberLabWorkbenchSurface() {
  return (
    <div class="flex size-full min-h-0 min-w-0 flex-row overflow-hidden">
      <CyberLabLeftExplorer />
      <CyberLabCenterStage />
    </div>
  )
}
