import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js"
import { Icon } from "@opencode/ui/icon"
import { useCyberLabWorkbench } from "./state"
import type { VaultNoteSummaryDto } from "./types"

type VaultEditorMode = "split" | "preview" | "edit"
type VaultWindowLayout = "floating" | "docked_right" | "minimized"

interface ParsedMarkdownBlock {
  kind: "heading" | "checkbox" | "bullet" | "code" | "paragraph" | "blank"
  level?: number
  checked?: boolean
  lineIndex: number
  lang?: string
  text: string
}

function parseMarkdownBlocks(md: string): ParsedMarkdownBlock[] {
  const lines = md.split(/\r?\n/)
  const out: ParsedMarkdownBlock[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i] ?? ""
    const fence = line.match(/^```([a-zA-Z0-9_-]*)\s*$/)
    if (fence) {
      const lang = fence[1] || "cmd"
      const startLine = i
      i++
      const codeLines: string[] = []
      while (i < lines.length && !lines[i]!.startsWith("```")) {
        codeLines.push(lines[i]!)
        i++
      }
      if (i < lines.length && lines[i]!.startsWith("```")) i++
      out.push({
        kind: "code",
        lang,
        lineIndex: startLine,
        text: codeLines.join("\n"),
      })
      continue
    }

    const heading = line.match(/^(#{1,4})\s+(.+)$/)
    if (heading) {
      out.push({
        kind: "heading",
        level: heading[1]!.length,
        lineIndex: i,
        text: heading[2]!,
      })
      i++
      continue
    }

    const cb = line.match(/^\s*-\s*\[([ xX])\]\s+(.*)$/)
    if (cb) {
      out.push({
        kind: "checkbox",
        checked: cb[1]!.toLowerCase() === "x",
        lineIndex: i,
        text: cb[2]!,
      })
      i++
      continue
    }

    const bullet = line.match(/^\s*[-*]\s+(.+)$/)
    if (bullet) {
      out.push({
        kind: "bullet",
        lineIndex: i,
        text: bullet[1]!,
      })
      i++
      continue
    }

    if (!line.trim()) {
      out.push({ kind: "blank", lineIndex: i, text: "" })
      i++
      continue
    }

    out.push({
      kind: "paragraph",
      lineIndex: i,
      text: line,
    })
    i++
  }

  return out
}

function InlineObsidianTokens(props: {
  text: string
  onOpenWikiLink: (target: string) => void
  onSelectTag: (tag: string) => void
}) {
  const tokens = createMemo(() => {
    const raw = props.text
    const parts: Array<
      | { type: "text"; value: string }
      | { type: "wiki"; target: string; alias: string }
      | { type: "code"; value: string }
      | { type: "bold"; value: string }
      | { type: "tag"; value: string }
    > = []

    const regex = /\[\[([^\]|#]+)(?:\|([^\]]+))?\]\]|`([^`]+)`|\*\*([^*]+)\*\*|(?<=^|\s)#([a-zA-ZÀ-ÿ0-9_-]{2,40})\b/g
    let lastIdx = 0
    let m: RegExpExecArray | null
    while ((m = regex.exec(raw)) !== null) {
      if (m.index > lastIdx) {
        parts.push({ type: "text", value: raw.slice(lastIdx, m.index) })
      }
      if (m[1]) {
        parts.push({
          type: "wiki",
          target: m[1].trim(),
          alias: (m[2] || m[1]).trim(),
        })
      } else if (m[3]) {
        parts.push({ type: "code", value: m[3] })
      } else if (m[4]) {
        parts.push({ type: "bold", value: m[4] })
      } else if (m[5]) {
        parts.push({ type: "tag", value: m[5].toLowerCase() })
      }
      lastIdx = m.index + m[0].length
    }
    if (lastIdx < raw.length) {
      parts.push({ type: "text", value: raw.slice(lastIdx) })
    }
    return parts
  })

  return (
    <For each={tokens()}>
      {(tk) => {
        if (tk.type === "wiki") {
          return (
            <button
              type="button"
              title={`Abrir ou criar nota [[${tk.target}]] no Cofre`}
              class="mx-0.5 inline-flex items-center gap-0.5 rounded bg-violet-500/20 px-1.5 py-0 font-medium text-violet-300 underline decoration-violet-400/60 hover:bg-violet-500/35 cursor-pointer"
              onClick={() => props.onOpenWikiLink(tk.target)}
            >
              <span>[[{tk.alias}]]</span>
            </button>
          )
        }
        if (tk.type === "code") {
          return (
            <code class="rounded bg-zinc-800/90 px-1.5 py-0.5 font-mono text-[11px] text-emerald-300">
              {tk.value}
            </code>
          )
        }
        if (tk.type === "bold") {
          return <strong class="font-semibold text-zinc-100">{tk.value}</strong>
        }
        if (tk.type === "tag") {
          return (
            <button
              type="button"
              class="mx-0.5 inline-flex rounded-full bg-emerald-600/20 px-1.5 py-0 text-[10.5px] font-medium text-emerald-400 hover:bg-emerald-600/35 cursor-pointer"
              onClick={() => props.onSelectTag(tk.value)}
            >
              #{tk.value}
            </button>
          )
        }
        return <span>{tk.value}</span>
      }}
    </For>
  )
}

export function CyberLabVaultOverlay() {
  const wb = useCyberLabWorkbench()
  const [layout, setLayout] = createSignal<VaultWindowLayout>("floating")
  const [editorMode, setEditorMode] = createSignal<VaultEditorMode>("split")
  const [sidebarOpen, setSidebarOpen] = createSignal(true)
  const [searchQuery, setSearchQuery] = createSignal("")
  const [activeTag, setActiveTag] = createSignal<string | null>(null)
  const [draftContent, setDraftContent] = createSignal("")
  const [dirty, setDirty] = createSignal(false)
  const [saving, setSaving] = createSignal(false)
  const [showNewNoteInput, setShowNewNoteInput] = createSignal(false)
  const [newNotePath, setNewNotePath] = createSignal("")
  const [showVaultConfig, setShowVaultConfig] = createSignal(false)
  const [customVaultDirInput, setCustomVaultDirInput] = createSignal("")

  // Draggable window position & size
  const [winPos, setWinPos] = createSignal({ x: 120, y: 58 })
  const [winSize, setWinSize] = createSignal({ w: 860, h: 560 })
  const [dragging, setDragging] = createSignal(false)
  let dragOffset = { dx: 0, dy: 0 }
  let autoSaveTimer: number | undefined

  if (!wb) return null

  // Sync draft editor whenever backend.activeVaultNote switches to a different note
  let lastLoadedNotePath = ""
  createEffect(() => {
    const doc = wb.backend.activeVaultNote
    if (!doc) return
    if (doc.relativePath !== lastLoadedNotePath || !dirty()) {
      lastLoadedNotePath = doc.relativePath
      setDraftContent(doc.content)
      setDirty(false)
    }
  })

  onCleanup(() => {
    if (autoSaveTimer) window.clearTimeout(autoSaveTimer)
  })

  const scheduleAutoSave = (relPath: string, nextText: string) => {
    setDraftContent(nextText)
    setDirty(true)
    if (autoSaveTimer) window.clearTimeout(autoSaveTimer)
    autoSaveTimer = window.setTimeout(async () => {
      setSaving(true)
      await wb.saveVaultNote(relPath, nextText, true)
      setSaving(false)
      setDirty(false)
    }, 550)
  }

  const flushSaveNow = async () => {
    const doc = wb.backend.activeVaultNote
    if (!doc) return
    if (autoSaveTimer) window.clearTimeout(autoSaveTimer)
    setSaving(true)
    await wb.saveVaultNote(doc.relativePath, draftContent(), false)
    setSaving(false)
    setDirty(false)
  }

  const toggleCheckboxAtLine = (lineIdx: number) => {
    const doc = wb.backend.activeVaultNote
    if (!doc) return
    const lines = draftContent().split(/\r?\n/)
    const target = lines[lineIdx]
    if (target === undefined) return
    const updated = target.replace(/^(\s*-\s*\[)([ xX])(\]\s+.*)$/, (_all, pre, mark, post) => {
      const nextMark = String(mark).toLowerCase() === "x" ? " " : "x"
      return `${pre}${nextMark}${post}`
    })
    if (updated === target) return
    lines[lineIdx] = updated
    const joined = lines.join("\n")
    scheduleAutoSave(doc.relativePath, joined)
  }

  const insertSnippetTemplate = (snippet: string) => {
    const doc = wb.backend.activeVaultNote
    if (!doc) return
    const cur = draftContent()
    const next = cur.endsWith("\n") ? `${cur}\n${snippet}\n` : `${cur}\n\n${snippet}\n`
    scheduleAutoSave(doc.relativePath, next)
  }

  const filteredNotes = createMemo<VaultNoteSummaryDto[]>(() => {
    const list = wb.backend.vault?.notes ?? []
    const q = searchQuery().trim().toLowerCase()
    const tag = activeTag()
    return list.filter((n) => {
      if (tag && !n.tags.includes(tag)) return false
      if (!q) return true
      return (
        n.title.toLowerCase().includes(q) ||
        n.relativePath.toLowerCase().includes(q) ||
        n.snippet.toLowerCase().includes(q) ||
        n.tags.some((t) => t.includes(q))
      )
    })
  })

  const groupedByFolder = createMemo(() => {
    const map = new Map<string, VaultNoteSummaryDto[]>()
    for (const n of filteredNotes()) {
      const key = n.folder || "Raiz do Cofre"
      const arr = map.get(key) ?? []
      arr.push(n)
      map.set(key, arr)
    }
    return Array.from(map.entries())
  })

  const parsedBlocks = createMemo(() => parseMarkdownBlocks(draftContent()))

  const startHeaderDrag = (ev: PointerEvent) => {
    if (layout() !== "floating") return
    const targetEl = ev.target as HTMLElement | null
    if (targetEl?.closest("button, input, select, a")) return
    const pos = winPos()
    dragOffset = { dx: ev.clientX - pos.x, dy: ev.clientY - pos.y }
    setDragging(true)

    const onMove = (moveEv: PointerEvent) => {
      const maxX = Math.max(20, window.innerWidth - 180)
      const maxY = Math.max(20, window.innerHeight - 80)
      setWinPos({
        x: Math.min(maxX, Math.max(8, moveEv.clientX - dragOffset.dx)),
        y: Math.min(maxY, Math.max(8, moveEv.clientY - dragOffset.dy)),
      })
    }
    const onUp = () => {
      setDragging(false)
      window.removeEventListener("pointermove", onMove)
      window.removeEventListener("pointerup", onUp)
    }
    window.addEventListener("pointermove", onMove)
    window.addEventListener("pointerup", onUp)
  }

  const copyCommand = (cmd: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(cmd)
      wb.setNotice("Comando copiado do Cofre para a área de transferência!")
    }
  }

  return (
    <Show when={wb.ui.vaultOpen}>
      {/* Escudo transparente durante arrasto para iframes (noVNC / Web UI) não roubarem o mouse */}
      <Show when={dragging()}>
        <div class="fixed inset-0 z-[94] cursor-grabbing" />
      </Show>

      {/* MODO MINIMIZADO: Pílula discreta no canto inferior direito */}
      <Show
        when={layout() !== "minimized"}
        fallback={
          <div
            data-slot="cyberlab-vault-minimized"
            class="fixed right-4 bottom-4 z-[95] flex items-center gap-2 rounded-full border border-violet-500/60 bg-zinc-950/95 px-3.5 py-1.5 text-[11.5px] shadow-2xl"
          >
            <span class="font-semibold text-violet-300">
              📓 {wb.backend.activeVaultNote?.title ?? "Cofre Obsidian"}
            </span>
            <button
              type="button"
              class="rounded bg-violet-600 px-2 py-0.5 text-[10.5px] font-medium text-white hover:bg-violet-500 cursor-pointer"
              onClick={() => setLayout("floating")}
            >
              Expandir
            </button>
            <button
              type="button"
              class="text-zinc-400 hover:text-white cursor-pointer"
              onClick={() => wb.toggleVault(false)}
            >
              ✕
            </button>
          </div>
        }
      >
        {/* JANELA FLUTUANTE OU GAVETA LATERAL SOBREPOSTA (NÃO ENCOLHE O BURP / FERRAMENTA CENTRAL!) */}
        <aside
          data-slot="cyberlab-obsidian-vault"
          style={
            layout() === "floating"
              ? {
                  left: `${winPos().x}px`,
                  top: `${winPos().y}px`,
                  width: `${winSize().w}px`,
                  height: `${winSize().h}px`,
                }
              : undefined
          }
          class={
            layout() === "floating"
              ? "fixed z-[95] flex flex-col overflow-hidden rounded-xl border border-violet-500/50 bg-zinc-950/98 text-zinc-100 shadow-[0_24px_70px_rgba(0,0,0,0.85)] resize"
              : "fixed top-[28px] right-0 bottom-0 z-[95] flex w-[500px] max-w-[92vw] flex-col overflow-hidden border-l border-violet-500/50 bg-zinc-950/98 text-zinc-100 shadow-2xl"
          }
        >
          {/* BARRA DE TÍTULO ARRASTÁVEL DO COFRE */}
          <div
            onPointerDown={startHeaderDrag}
            class={`flex items-center justify-between gap-2 border-b border-zinc-800 bg-zinc-900/95 px-3 py-1.5 select-none shrink-0 ${
              layout() === "floating" ? "cursor-grab active:cursor-grabbing" : ""
            }`}
          >
            <div class="flex items-center gap-2 min-w-0">
              <button
                type="button"
                title="Mostrar/ocultar árvore de pastas e notas"
                class="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-200 hover:border-violet-400 cursor-pointer"
                onClick={() => setSidebarOpen((v) => !v)}
              >
                {sidebarOpen() ? "◀ Notas" : "▶ Notas"}
              </button>
              <span class="truncate text-[12px] font-semibold text-violet-300">
                📓 Cofre CyberLab (.md / Obsidian)
              </span>
              <span class="font-mono text-[10px] text-emerald-400">
                {saving() ? "salvando..." : dirty() ? "● editando" : "✓ salvo"}
              </span>
            </div>

            <div class="flex items-center gap-1 shrink-0">
              {/* Seletor de Modo: Editar | Dividido | Leitura Interativa */}
              <div class="flex items-center rounded border border-zinc-700 bg-zinc-950 p-0.5 text-[10px]">
                <button
                  type="button"
                  class={`rounded px-1.5 py-0.5 cursor-pointer ${
                    editorMode() === "edit" ? "bg-violet-600 text-white" : "text-zinc-400 hover:text-white"
                  }`}
                  onClick={() => setEditorMode("edit")}
                >
                  Editar
                </button>
                <button
                  type="button"
                  class={`rounded px-1.5 py-0.5 cursor-pointer ${
                    editorMode() === "split" ? "bg-violet-600 text-white" : "text-zinc-400 hover:text-white"
                  }`}
                  onClick={() => setEditorMode("split")}
                >
                  Dividido
                </button>
                <button
                  type="button"
                  class={`rounded px-1.5 py-0.5 cursor-pointer ${
                    editorMode() === "preview" ? "bg-violet-600 text-white" : "text-zinc-400 hover:text-white"
                  }`}
                  onClick={() => setEditorMode("preview")}
                >
                  Interativo
                </button>
              </div>

              {/* Presets rápidos de tamanho quando flutuante */}
              <Show when={layout() === "floating"}>
                <div class="hidden sm:flex items-center gap-0.5 rounded border border-zinc-800 bg-zinc-950 px-1 py-0.5 text-[9.5px] text-zinc-400">
                  <button
                    type="button"
                    title="Tamanho compacto"
                    class="px-1 hover:text-white cursor-pointer"
                    onClick={() => setWinSize({ w: 650, h: 450 })}
                  >
                    P
                  </button>
                  <button
                    type="button"
                    title="Tamanho médio"
                    class="px-1 hover:text-white cursor-pointer"
                    onClick={() => setWinSize({ w: 860, h: 560 })}
                  >
                    M
                  </button>
                  <button
                    type="button"
                    title="Tamanho amplo"
                    class="px-1 hover:text-white cursor-pointer"
                    onClick={() => setWinSize({ w: 1080, h: 680 })}
                  >
                    G
                  </button>
                </div>
              </Show>

              <button
                type="button"
                title={
                  layout() === "floating"
                    ? "Fixar como gaveta na borda direita"
                    : "Destacar como janela flutuante livre"
                }
                class="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-200 hover:border-violet-400 cursor-pointer"
                onClick={() => setLayout((l) => (l === "floating" ? "docked_right" : "floating"))}
              >
                {layout() === "floating" ? "📌 Lateral" : "🪟 Flutuante"}
              </button>

              <button
                type="button"
                title="Configurar pasta do Vault (ex.: apontar para seu Vault do Obsidian Desktop)"
                class="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-200 hover:border-violet-400 cursor-pointer"
                onClick={() => {
                  setCustomVaultDirInput(wb.backend.vault?.vaultRootDir ?? "")
                  setShowVaultConfig((v) => !v)
                }}
              >
                ⚙ Pasta
              </button>

              <button
                type="button"
                title="Minimizar para pílula no canto da tela"
                class="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-200 hover:border-violet-400 cursor-pointer"
                onClick={() => setLayout("minimized")}
              >
                ⎯
              </button>

              <button
                type="button"
                title="Fechar Cofre (Atalho: Alt+N)"
                class="inline-flex size-5 items-center justify-center rounded border border-zinc-700 bg-zinc-800 text-zinc-300 hover:border-red-500 hover:text-red-300 cursor-pointer"
                onClick={() => wb.toggleVault(false)}
              >
                <Icon name="close" class="size-3" />
              </button>
            </div>
          </div>

          {/* CONFIGURAÇÃO DE PASTA COMPARTILHADA COM OBSIDIAN DESKTOP */}
          <Show when={showVaultConfig()}>
            <div class="flex flex-wrap items-center gap-2 border-b border-violet-500/30 bg-zinc-900/90 px-3 py-2 text-[11px] shrink-0">
              <span class="text-violet-300 font-medium">Pasta do Vault (.md):</span>
              <input
                type="text"
                placeholder="Ex.: C:\Users\Voce\Documents\ObsidianVault (vazio = padrão vault/ do projeto)"
                value={customVaultDirInput()}
                class="min-w-[240px] flex-1 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-[10.5px] text-zinc-100 outline-none focus:border-violet-500"
                onInput={(e) => setCustomVaultDirInput(e.currentTarget.value)}
              />
              <button
                type="button"
                class="rounded bg-violet-600 px-2.5 py-1 text-[10.5px] font-medium text-white hover:bg-violet-500 cursor-pointer"
                onClick={() => {
                  void wb.configureVaultPath(customVaultDirInput())
                  setShowVaultConfig(false)
                }}
              >
                Usar Esta Pasta
              </button>
              <Show when={wb.backend.vault?.isCustomPath}>
                <button
                  type="button"
                  class="rounded border border-zinc-700 px-2 py-1 text-[10.5px] text-zinc-300 hover:text-white cursor-pointer"
                  onClick={() => {
                    void wb.configureVaultPath(null)
                    setShowVaultConfig(false)
                  }}
                >
                  Voltar ao Padrão
                </button>
              </Show>
            </div>
          </Show>

          {/* CORPO PRINCIPAL DO COFRE */}
          <div class="flex min-h-0 flex-1 overflow-hidden">
            {/* COLUNA ESQUERDA DE NOTAS, PASTAS E #TAGS */}
            <Show when={sidebarOpen()}>
              <div class="flex w-[215px] shrink-0 flex-col border-r border-zinc-800 bg-zinc-900/60 overflow-hidden">
                <div class="flex flex-col gap-1.5 border-b border-zinc-800 p-2">
                  <div class="flex items-center gap-1">
                    <input
                      type="text"
                      value={searchQuery()}
                      placeholder="Buscar nota ou comando..."
                      class="min-w-0 flex-1 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-[10.5px] text-zinc-100 outline-none focus:border-violet-500"
                      onInput={(e) => setSearchQuery(e.currentTarget.value)}
                    />
                    <button
                      type="button"
                      title="Criar nova nota .md (aceita pasta/nome)"
                      class="rounded bg-violet-600 px-2 py-1 text-[10.5px] font-semibold text-white hover:bg-violet-500 cursor-pointer"
                      onClick={() => setShowNewNoteInput((v) => !v)}
                    >
                      +
                    </button>
                  </div>

                  <Show when={showNewNoteInput()}>
                    <div class="flex items-center gap-1">
                      <input
                        type="text"
                        value={newNotePath()}
                        placeholder="Ex.: Comandos/SQLi.md"
                        class="min-w-0 flex-1 rounded border border-violet-500/50 bg-zinc-950 px-2 py-1 text-[10.5px] text-zinc-100 outline-none"
                        onInput={(e) => setNewNotePath(e.currentTarget.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && newNotePath().trim()) {
                            const p = newNotePath().trim()
                            const title = p.replace(/\.md$/i, "").split("/").at(-1) ?? "Nova Nota"
                            void wb.saveVaultNote(p, `# ${title}\n\n#notas\n\n`)
                            setNewNotePath("")
                            setShowNewNoteInput(false)
                          }
                        }}
                      />
                      <button
                        type="button"
                        class="rounded bg-emerald-600 px-2 py-1 text-[10px] font-semibold text-white cursor-pointer"
                        onClick={() => {
                          const p = newNotePath().trim()
                          if (!p) return
                          const title = p.replace(/\.md$/i, "").split("/").at(-1) ?? "Nova Nota"
                          void wb.saveVaultNote(p, `# ${title}\n\n#notas\n\n`)
                          setNewNotePath("")
                          setShowNewNoteInput(false)
                        }}
                      >
                        Criar
                      </button>
                    </div>
                  </Show>

                  <Show when={(wb.backend.vault?.allTags.length ?? 0) > 0}>
                    <div class="flex flex-wrap gap-1 pt-0.5 max-h-14 overflow-y-auto">
                      <Show when={activeTag()}>
                        <button
                          type="button"
                          class="rounded-full bg-zinc-700 px-1.5 py-0 text-[9.5px] text-white cursor-pointer"
                          onClick={() => setActiveTag(null)}
                        >
                          ✕ filtro
                        </button>
                      </Show>
                      <For each={wb.backend.vault?.allTags ?? []}>
                        {(tag) => (
                          <button
                            type="button"
                            class={`rounded-full px-1.5 py-0 text-[9.5px] cursor-pointer ${
                              activeTag() === tag
                                ? "bg-emerald-600 text-white"
                                : "bg-zinc-800 text-emerald-400 hover:bg-zinc-700"
                            }`}
                            onClick={() => setActiveTag((cur) => (cur === tag ? null : tag))}
                          >
                            #{tag}
                          </button>
                        )}
                      </For>
                    </div>
                  </Show>
                </div>

                <div class="min-h-0 flex-1 overflow-y-auto p-1.5 space-y-2.5 [scrollbar-width:thin]">
                  <For each={groupedByFolder()}>
                    {([folderName, items]) => (
                      <div class="space-y-0.5">
                        <div class="px-1.5 text-[9.5px] font-semibold uppercase tracking-wider text-zinc-500">
                          📁 {folderName}
                        </div>
                        <For each={items}>
                          {(item) => {
                            const isActive = () =>
                              wb.backend.activeVaultNote?.relativePath === item.relativePath
                            return (
                              <button
                                type="button"
                                class={`flex w-full flex-col rounded-md px-2 py-1 text-left transition-colors cursor-pointer ${
                                  isActive()
                                    ? "bg-violet-600/25 border border-violet-500/50 text-white"
                                    : "text-zinc-300 hover:bg-zinc-800/70"
                                }`}
                                onClick={() => void wb.openVaultNote(item.relativePath)}
                              >
                                <span class="truncate text-[11px] font-medium">{item.title}</span>
                                <span class="truncate font-mono text-[9.5px] text-zinc-500">
                                  {item.relativePath}
                                </span>
                              </button>
                            )
                          }}
                        </For>
                      </div>
                    )}
                  </For>
                </div>
              </div>
            </Show>

            {/* ÁREA DA NOTA ATIVA (TOOLBAR RÁPIDA + EDITOR / PREVIEW INTERATIVO + BACKLINKS) */}
            <div class="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
              <Show
                when={wb.backend.activeVaultNote}
                fallback={
                  <div class="flex flex-1 items-center justify-center p-6 text-center text-[12px] text-zinc-400">
                    Selecione ou crie uma nota `.md` na coluna à esquerda.
                  </div>
                }
              >
                {(note) => (
                  <>
                    {/* Barra de inserção rápida de blocos de comando / checklist / custódia */}
                    <div class="flex flex-wrap items-center justify-between gap-1.5 border-b border-zinc-800 bg-zinc-900/45 px-2.5 py-1 text-[10.5px] shrink-0">
                      <div class="flex items-center gap-1 min-w-0">
                        <span class="truncate font-mono text-[10.5px] text-violet-300">
                          {note().relativePath}
                        </span>
                        <button
                          type="button"
                          title="Inserir bloco de comando executável"
                          class="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[9.5px] text-zinc-200 hover:border-emerald-500 cursor-pointer"
                          onClick={() =>
                            insertSnippetTemplate("```bash\nnuclei -u {target} -silent\n```")
                          }
                        >
                          + Comando
                        </button>
                        <button
                          type="button"
                          title="Inserir tarefa interativa"
                          class="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[9.5px] text-zinc-200 hover:border-emerald-500 cursor-pointer"
                          onClick={() => insertSnippetTemplate("- [ ] Nova etapa de verificação")}
                        >
                          + Checklist
                        </button>
                        <button
                          type="button"
                          title="Inserir [[WikiLink]] estilo Obsidian"
                          class="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[9.5px] text-zinc-200 hover:border-violet-400 cursor-pointer"
                          onClick={() => insertSnippetTemplate("[[Comandos-Rapidos]]")}
                        >
                          + [[Link]]
                        </button>
                      </div>

                      <div class="flex items-center gap-1">
                        <button
                          type="button"
                          class="rounded bg-emerald-600/25 px-2 py-0.5 text-[10px] font-medium text-emerald-300 hover:bg-emerald-600/40 cursor-pointer"
                          onClick={() => void flushSaveNow()}
                        >
                          💾 Salvar
                        </button>
                        <button
                          type="button"
                          title="Registrar cópia desta nota na Custódia Criptográfica SHA-256"
                          class="rounded bg-sky-600/25 px-2 py-0.5 text-[10px] font-medium text-sky-300 hover:bg-sky-600/40 cursor-pointer"
                          onClick={() =>
                            void wb.persistOutputToEvidence(
                              `Nota Vault — ${note().title}`,
                              draftContent(),
                              "obsidian-vault",
                            )
                          }
                        >
                          🔒 SHA-256
                        </button>
                        <button
                          type="button"
                          title="Anexar nota completa ao Agente OpenCode na coluna direita"
                          class="rounded bg-violet-600/25 px-2 py-0.5 text-[10px] font-medium text-violet-200 hover:bg-violet-600/40 cursor-pointer"
                          onClick={() =>
                            wb.sendToAgent(
                              `Nota do Cofre: ${note().title} (${note().relativePath})`,
                              draftContent(),
                              note().relativePath.split("/").at(-1) ?? "nota.md",
                            )
                          }
                        >
                          🤖 Enviar p/ IA
                        </button>
                        <button
                          type="button"
                          title="Excluir esta nota do Vault"
                          class="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 cursor-pointer"
                          onClick={() => void wb.deleteVaultNote(note().relativePath)}
                        >
                          🗑
                        </button>
                      </div>
                    </div>

                    {/* EDITOR + PREVIEW INTERATIVO (SPLIT / EDIT / PREVIEW) */}
                    <div class="flex min-h-0 flex-1 overflow-hidden">
                      <Show when={editorMode() === "edit" || editorMode() === "split"}>
                        <textarea
                          value={draftContent()}
                          spellcheck={false}
                          placeholder="Escreva em Markdown compatível com Obsidian (#tags, [[WikiLinks]], - [ ] checklists e blocos ```bash)..."
                          class={`h-full min-h-0 flex-1 resize-none bg-zinc-950 p-3 font-mono text-[11.5px] leading-relaxed text-zinc-100 outline-none ${
                            editorMode() === "split" ? "border-r border-zinc-800" : ""
                          }`}
                          onInput={(e) => scheduleAutoSave(note().relativePath, e.currentTarget.value)}
                        />
                      </Show>

                      <Show when={editorMode() === "preview" || editorMode() === "split"}>
                        <div class="h-full min-h-0 flex-1 overflow-y-auto bg-zinc-950/75 p-3.5 space-y-2 text-[12px] leading-relaxed [scrollbar-width:thin]">
                          <For each={parsedBlocks()}>
                            {(blk) => {
                              if (blk.kind === "blank") {
                                return <div class="h-1" />
                              }
                              if (blk.kind === "heading") {
                                const cls =
                                  blk.level === 1
                                    ? "text-[15.5px] font-bold text-white border-b border-zinc-800 pb-1"
                                    : blk.level === 2
                                      ? "text-[13.5px] font-semibold text-violet-300 pt-1"
                                      : "text-[12.5px] font-semibold text-emerald-300"
                                return (
                                  <div class={cls}>
                                    <InlineObsidianTokens
                                      text={blk.text}
                                      onOpenWikiLink={(t) => void wb.openVaultNote(t, true)}
                                      onSelectTag={(tg) => setActiveTag(tg)}
                                    />
                                  </div>
                                )
                              }
                              if (blk.kind === "checkbox") {
                                return (
                                  <label class="flex items-start gap-2 rounded px-1 py-0.5 hover:bg-zinc-900/70 cursor-pointer">
                                    <input
                                      type="checkbox"
                                      checked={Boolean(blk.checked)}
                                      class="mt-1 accent-emerald-500 cursor-pointer"
                                      onChange={() => toggleCheckboxAtLine(blk.lineIndex)}
                                    />
                                    <span class={blk.checked ? "line-through text-zinc-500" : "text-zinc-200"}>
                                      <InlineObsidianTokens
                                        text={blk.text}
                                        onOpenWikiLink={(t) => void wb.openVaultNote(t, true)}
                                        onSelectTag={(tg) => setActiveTag(tg)}
                                      />
                                    </span>
                                  </label>
                                )
                              }
                              if (blk.kind === "bullet") {
                                return (
                                  <div class="flex items-start gap-2 pl-1 text-zinc-200">
                                    <span class="text-emerald-400">•</span>
                                    <div>
                                      <InlineObsidianTokens
                                        text={blk.text}
                                        onOpenWikiLink={(t) => void wb.openVaultNote(t, true)}
                                        onSelectTag={(tg) => setActiveTag(tg)}
                                      />
                                    </div>
                                  </div>
                                )
                              }
                              if (blk.kind === "code") {
                                return (
                                  <div class="rounded-lg border border-zinc-800 bg-black/80 overflow-hidden">
                                    <div class="flex flex-wrap items-center justify-between gap-1 border-b border-zinc-800 bg-zinc-900/90 px-2.5 py-1 text-[10px]">
                                      <span class="font-mono uppercase text-zinc-400">
                                        {blk.lang || "cmd"}
                                      </span>
                                      <div class="flex items-center gap-1">
                                        <button
                                          type="button"
                                          class="rounded bg-zinc-800 px-1.5 py-0.5 text-zinc-200 hover:bg-zinc-700 cursor-pointer"
                                          onClick={() => copyCommand(blk.text)}
                                        >
                                          📋 Copiar
                                        </button>
                                        <button
                                          type="button"
                                          title="Seleciona a ferramenta correspondente (ex.: ncat, dirsearch, nuclei, nmap) e preenche os argumentos sem fechar o Cofre!"
                                          class="rounded bg-emerald-600/25 px-1.5 py-0.5 font-medium text-emerald-300 hover:bg-emerald-600/40 cursor-pointer"
                                          onClick={() => wb.injectCommandIntoCli(blk.text, false)}
                                        >
                                          ⚡ Injetar no CLI
                                        </button>
                                        <button
                                          type="button"
                                          title="Injeta e já executa imediatamente no Slot CLI correspondente!"
                                          class="rounded bg-emerald-600 px-1.5 py-0.5 font-medium text-white hover:bg-emerald-500 cursor-pointer"
                                          onClick={() => wb.injectCommandIntoCli(blk.text, true)}
                                        >
                                          ▶ Executar
                                        </button>
                                        <button
                                          type="button"
                                          class="rounded bg-violet-600/25 px-1.5 py-0.5 text-violet-300 hover:bg-violet-600/40 cursor-pointer"
                                          onClick={() =>
                                            wb.sendToAgent(
                                              `Snippet do Cofre (${note().title})`,
                                              blk.text,
                                              "vault-command.sh",
                                            )
                                          }
                                        >
                                          🤖 IA
                                        </button>
                                      </div>
                                    </div>
                                    <pre class="overflow-x-auto p-2.5 font-mono text-[11px] text-emerald-200 whitespace-pre-wrap">
                                      {blk.text}
                                    </pre>
                                  </div>
                                )
                              }
                              return (
                                <p class="text-zinc-200">
                                  <InlineObsidianTokens
                                    text={blk.text}
                                    onOpenWikiLink={(t) => void wb.openVaultNote(t, true)}
                                    onSelectTag={(tg) => setActiveTag(tg)}
                                  />
                                </p>
                              )
                            }}
                          </For>
                        </div>
                      </Show>
                    </div>

                    {/* RODAPÉ COM BACKLINKS (ESTILO OBSIDIAN) + PASTA ATIVA */}
                    <div class="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-800 bg-zinc-900/80 px-2.5 py-1 text-[10px] text-zinc-400 shrink-0">
                      <div class="flex items-center gap-1.5 min-w-0 overflow-x-auto">
                        <span class="font-medium text-zinc-500 shrink-0">🔗 Backlinks:</span>
                        <Show
                          when={note().backlinks.length > 0}
                          fallback={<span class="text-zinc-600">nenhuma outra nota aponta para esta ainda</span>}
                        >
                          <For each={note().backlinks}>
                            {(bl) => (
                              <button
                                type="button"
                                class="rounded bg-zinc-800 px-1.5 py-0 text-violet-300 hover:bg-zinc-700 cursor-pointer whitespace-nowrap"
                                onClick={() => void wb.openVaultNote(bl)}
                              >
                                [[{bl.replace(/\.md$/i, "")}]]
                              </button>
                            )}
                          </For>
                        </Show>
                      </div>
                      <span class="truncate font-mono text-[9.5px] text-zinc-500" title={wb.backend.vault?.vaultRootDir}>
                        Atalho: Alt+N · {wb.backend.vault?.vaultRootDir}
                      </span>
                    </div>
                  </>
                )}
              </Show>
            </div>
          </div>
        </aside>
      </Show>
    </Show>
  )
}
