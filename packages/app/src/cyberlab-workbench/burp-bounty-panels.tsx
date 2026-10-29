import { createMemo, For, Show } from "solid-js"
import { Icon } from "@opencode/ui/icon"
import type { CyberLabWorkbenchService } from "./state"
import type {
  EngagementHeaderRuleDto,
  EngagementProfileDto,
  KeyValueHeaderRow,
  ManualToolId,
  ProxyInterceptItemDto,
  ScopeRuleKindDto,
} from "./types"

const INPUT_CLS =
  "w-full rounded-md border border-v2-border-border-base bg-v2-background-bg-deep px-2.5 py-1.5 text-[13px] leading-[var(--line-height-compact)] text-v2-text-text-strong outline-none focus:border-v2-icon-icon-accent"
const MONO_INPUT_CLS = `${INPUT_CLS} font-mono text-[12px]`
const LABEL_CLS = "text-[11px] font-medium uppercase tracking-wide text-v2-text-text-muted"
const CHIP_CLS =
  "rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-0.5 text-[11px] text-v2-text-text-base hover:bg-v2-background-bg-deep cursor-pointer transition-colors"
const BTN_PRIMARY =
  "inline-flex items-center justify-center gap-1.5 rounded-md bg-emerald-600 px-3.5 py-1.5 text-[12px] font-medium text-white hover:bg-emerald-500 disabled:opacity-50 cursor-pointer transition-colors"
const BTN_SECONDARY =
  "inline-flex items-center justify-center gap-1.5 rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2.5 py-1.5 text-[12px] font-medium text-v2-text-text-strong hover:bg-v2-background-bg-deep cursor-pointer transition-colors"

const STATIC_EXT_UI_RE = /\.(?:woff2?|ttf|otf|eot|png|jpe?g|gif|webp|avif|ico|svg|mp4|webm|mp3|wav|css)(?:\?|$)/i

export function LocalArtifactUploadButton(props: {
  wb: CyberLabWorkbenchService
  accept?: string
  label?: string
  onImported: (relativePath: string) => void
}) {
  let fileInputRef: HTMLInputElement | undefined
  const importedList = () => props.wb.backend.importedArtifacts ?? []

  return (
    <div class="flex flex-wrap items-center gap-1.5">
      <input
        ref={fileInputRef}
        type="file"
        accept={props.accept}
        class="hidden"
        onChange={(e) => {
          const file = e.currentTarget.files?.[0]
          e.currentTarget.value = ""
          if (!file) return
          void props.wb.uploadLocalArtifact(file).then((relPath) => {
            if (relPath) props.onImported(relPath)
          })
        }}
      />
      <button
        type="button"
        class={CHIP_CLS}
        title="Importar arquivo externo do seu computador para .cyberlab/imports/ e preencher automaticamente"
        onClick={() => fileInputRef?.click()}
      >
        + {props.label ?? "Importar Arquivo do PC"}
      </button>
      <Show when={importedList().length > 0}>
        <select
          class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-1.5 py-0.5 text-[11px] text-v2-text-text-muted max-w-[190px]"
          value=""
          onChange={(e) => {
            const val = e.currentTarget.value
            if (val) {
              props.onImported(val)
              e.currentTarget.value = ""
            }
          }}
        >
          <option value="">Arquivos importados ({importedList().length})...</option>
          <For each={importedList()}>
            {(art) => <option value={art.relativePath}>{art.fileName}</option>}
          </For>
        </select>
      </Show>
    </div>
  )
}

function SimpleHeaderTable(props: {
  title: string
  rows: KeyValueHeaderRow[]
  onChange: (rows: KeyValueHeaderRow[]) => void
}) {
  const addRow = () =>
    props.onChange([...props.rows, { id: `hdr-${Date.now()}`, enabled: true, name: "", value: "" }])
  const updateRow = (idx: number, patch: Partial<KeyValueHeaderRow>) =>
    props.onChange(props.rows.map((r, i) => (i === idx ? { ...r, ...patch } : r)))
  const removeRow = (idx: number) => props.onChange(props.rows.filter((_, i) => i !== idx))

  return (
    <div class="flex flex-col gap-1.5">
      <div class="flex items-center justify-between">
        <span class={LABEL_CLS}>{props.title}</span>
        <button type="button" class={CHIP_CLS} onClick={addRow}>
          + Header
        </button>
      </div>
      <For each={props.rows}>
        {(row, idx) => (
          <div class="grid grid-cols-[20px_minmax(110px,1fr)_minmax(140px,2fr)_24px] items-center gap-1.5">
            <input
              type="checkbox"
              checked={row.enabled}
              onChange={(e) => updateRow(idx(), { enabled: e.currentTarget.checked })}
            />
            <input
              type="text"
              value={row.name}
              placeholder="Cookie / Authorization"
              class={MONO_INPUT_CLS}
              onInput={(e) => updateRow(idx(), { name: e.currentTarget.value })}
            />
            <input
              type="text"
              value={row.value}
              placeholder="Valor"
              class={MONO_INPUT_CLS}
              onInput={(e) => updateRow(idx(), { value: e.currentTarget.value })}
            />
            <button
              type="button"
              class="text-v2-text-text-muted hover:text-red-500 cursor-pointer text-center"
              onClick={() => removeRow(idx())}
            >
              ×
            </button>
          </div>
        )}
      </For>
    </div>
  )
}

function buildRawHttpFromStructured(
  method: string,
  urlStr: string,
  headers: KeyValueHeaderRow[],
  body: string,
): string {
  try {
    const parsed = new URL(urlStr)
    const lines: string[] = [`${method} ${parsed.pathname}${parsed.search} HTTP/1.1`, `Host: ${parsed.host}`]
    for (const h of headers) {
      if (!h.enabled || !h.name.trim() || h.name.trim().toLowerCase() === "host") continue
      lines.push(`${h.name.trim()}: ${h.value}`)
    }
    lines.push("", body)
    return lines.join("\r\n")
  } catch {
    return `${method} / HTTP/1.1\r\nHost: localhost\r\n\r\n${body}`
  }
}

export function BurpRepeaterAndComparerPanel(props: {
  wb: CyberLabWorkbenchService
  isRunning: boolean
}) {
  const { wb } = props
  const d = () => wb.drafts["http-repeater"]
  const viewMode = () => d().viewMode ?? "repeater"
  const tabs = () => d().tabs ?? []

  const comparerDiff = createMemo(() => {
    const textA = d().comparerTextA ?? ""
    const textB = d().comparerTextB ?? ""
    const linesA = textA.split(/\r?\n/)
    const linesB = textB.split(/\r?\n/)
    const setA = new Set(linesA)
    const setB = new Set(linesB)
    const onlyInA = linesA.filter((l) => l.trim().length > 0 && !setB.has(l)).slice(0, 60)
    const onlyInB = linesB.filter((l) => l.trim().length > 0 && !setA.has(l)).slice(0, 60)
    const wordsA = textA.trim().split(/\s+/).filter(Boolean).length
    const wordsB = textB.trim().split(/\s+/).filter(Boolean).length
    return {
      bytesA: new TextEncoder().encode(textA).byteLength,
      bytesB: new TextEncoder().encode(textB).byteLength,
      linesCountA: linesA.length,
      linesCountB: linesB.length,
      wordsA,
      wordsB,
      onlyInA,
      onlyInB,
    }
  })

  const copyRepeaterAsCurl = () => {
    const cur = d()
    const parts = [`curl -i -k -X ${cur.method}`]
    for (const h of cur.headers) {
      if (h.enabled && h.name.trim()) {
        parts.push(`-H '${h.name.trim()}: ${h.value.replace(/'/g, "'\\''")}'`)
      }
    }
    if (cur.body && cur.method !== "GET" && cur.method !== "HEAD") {
      parts.push(`--data-raw '${cur.body.replace(/'/g, "'\\''")}'`)
    }
    parts.push(`'${cur.url.trim()}'`)
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(parts.join(" \\\n  "))
      wb.setNotice("Requisição do Repeater copiada como comando cURL!")
    }
  }

  return (
    <div class="flex flex-col gap-3">
      {/* Multi-Tab Bar + Mode Switcher (Repeater vs Dedicated Comparer) */}
      <div class="flex flex-wrap items-center justify-between gap-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 px-2.5 py-1.5">
        <div class="flex flex-wrap items-center gap-1">
          <button
            type="button"
            class={
              viewMode() === "repeater"
                ? "rounded bg-emerald-600 px-2.5 py-1 text-[11px] font-semibold text-white cursor-pointer"
                : CHIP_CLS
            }
            onClick={() => wb.updateDraft("http-repeater", (p) => ({ ...p, viewMode: "repeater" }))}
          >
            Repeater HTTP
          </button>
          <button
            type="button"
            class={
              viewMode() === "comparer"
                ? "rounded bg-emerald-600 px-2.5 py-1 text-[11px] font-semibold text-white cursor-pointer"
                : CHIP_CLS
            }
            onClick={() => wb.updateDraft("http-repeater", (p) => ({ ...p, viewMode: "comparer" }))}
          >
            Comparer (Item A vs B)
          </button>

          <Show when={viewMode() === "repeater"}>
            <div class="mx-1 h-4 w-px bg-v2-border-border-base" />
            <For each={tabs()}>
              {(tab) => (
                <div
                  class={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] cursor-pointer ${
                    d().activeTabId === tab.tabId
                      ? "border border-emerald-500/60 bg-emerald-500/15 text-emerald-300 font-medium"
                      : "border border-v2-border-border-base bg-v2-background-bg-base text-v2-text-text-muted"
                  }`}
                  onClick={() => wb.switchRepeaterTab(tab.tabId)}
                >
                  <span class="truncate max-w-[130px]">{tab.title}</span>
                  <button
                    type="button"
                    class="hover:text-red-400 cursor-pointer"
                    onClick={(e) => {
                      e.stopPropagation()
                      wb.closeRepeaterTab(tab.tabId)
                    }}
                  >
                    ×
                  </button>
                </div>
              )}
            </For>
            <button type="button" class={CHIP_CLS} onClick={() => wb.addRepeaterTab()}>
              + Nova Aba
            </button>
          </Show>
        </div>

        <Show when={viewMode() === "repeater"}>
          <div class="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              class={
                d().useRawHttp
                  ? "rounded border border-sky-500/60 bg-sky-500/15 px-2 py-0.5 text-[11px] text-sky-300 cursor-pointer"
                  : CHIP_CLS
              }
              onClick={() =>
                wb.updateDraft("http-repeater", (p) => ({
                  ...p,
                  useRawHttp: !p.useRawHttp,
                  rawHttpText:
                    !p.useRawHttp && !p.rawHttpText?.trim()
                      ? buildRawHttpFromStructured(p.method, p.url, p.headers, p.body)
                      : p.rawHttpText,
                }))
              }
            >
              {d().useRawHttp ? "Modo Raw HTTP/1.1 (Ativo)" : "Editar como Raw HTTP/1.1"}
            </button>
            <button type="button" class={CHIP_CLS} onClick={copyRepeaterAsCurl}>
              Copiar cURL
            </button>
          </div>
        </Show>
      </div>

      <Show
        when={viewMode() === "repeater"}
        fallback={
          /* DEDICATED VISUAL COMPARER (A vs B) */
          <div class="flex flex-col gap-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>
                  Item A {d().comparerLabelA ? `— ${d().comparerLabelA}` : "(Original / User A)"}
                </label>
                <textarea
                  rows={8}
                  value={d().comparerTextA ?? ""}
                  placeholder="Cole a Resposta/Requisição A aqui ou envie direto do Histórico do Proxy (→ Comparer A)..."
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("http-repeater", (p) => ({ ...p, comparerTextA: e.currentTarget.value }))
                  }
                />
              </div>
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>
                  Item B {d().comparerLabelB ? `— ${d().comparerLabelB}` : "(Modificado / User B)"}
                </label>
                <textarea
                  rows={8}
                  value={d().comparerTextB ?? ""}
                  placeholder="Cole a Resposta/Requisição B aqui ou envie direto do Histórico do Proxy (→ Comparer B)..."
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("http-repeater", (p) => ({ ...p, comparerTextB: e.currentTarget.value }))
                  }
                />
              </div>
            </div>

            <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-3 flex flex-col gap-2 text-[12px]">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <span class="font-semibold text-v2-text-text-strong">
                  Resumo Diferencial (Bytes · Palavras · Linhas)
                </span>
                <div class="flex flex-wrap items-center gap-3 font-mono text-[11px]">
                  <span>
                    Bytes: {comparerDiff().bytesA} vs {comparerDiff().bytesB} (Δ{" "}
                    {comparerDiff().bytesB - comparerDiff().bytesA})
                  </span>
                  <span>
                    Palavras: {comparerDiff().wordsA} vs {comparerDiff().wordsB} (Δ{" "}
                    {comparerDiff().wordsB - comparerDiff().wordsA})
                  </span>
                  <span>
                    Linhas: {comparerDiff().linesCountA} vs {comparerDiff().linesCountB}
                  </span>
                </div>
              </div>

              <div class="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-56 overflow-y-auto" data-scrollable>
                <div class="rounded bg-v2-background-bg-base p-2 font-mono text-[11px]">
                  <div class="text-red-400 font-semibold mb-1">
                    Exclusivo no Item A ({comparerDiff().onlyInA.length})
                  </div>
                  <Show
                    when={comparerDiff().onlyInA.length > 0}
                    fallback={<div class="text-v2-text-text-muted">Nenhuma linha exclusiva em A.</div>}
                  >
                    <For each={comparerDiff().onlyInA}>
                      {(line) => <div class="text-red-300/90 break-all">- {line}</div>}
                    </For>
                  </Show>
                </div>
                <div class="rounded bg-v2-background-bg-base p-2 font-mono text-[11px]">
                  <div class="text-emerald-400 font-semibold mb-1">
                    Exclusivo no Item B ({comparerDiff().onlyInB.length})
                  </div>
                  <Show
                    when={comparerDiff().onlyInB.length > 0}
                    fallback={<div class="text-v2-text-text-muted">Nenhuma linha exclusiva em B.</div>}
                  >
                    <For each={comparerDiff().onlyInB}>
                      {(line) => <div class="text-emerald-300/90 break-all">+ {line}</div>}
                    </For>
                  </Show>
                </div>
              </div>
            </div>
          </div>
        }
      >
        <div class="grid grid-cols-[110px_minmax(0,1fr)] gap-2">
          <div class="flex flex-col gap-1">
            <label class={LABEL_CLS}>Método HTTP</label>
            <select
              value={d().method}
              class={INPUT_CLS}
              onChange={(e) =>
                wb.updateDraft("http-repeater", (p) => ({
                  ...p,
                  method: e.currentTarget.value as typeof p.method,
                }))
              }
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
              <option value="HEAD">HEAD</option>
              <option value="OPTIONS">OPTIONS</option>
            </select>
          </div>
          <div class="flex flex-col gap-1">
            <div class="flex flex-wrap items-center justify-between gap-1.5">
              <label class={LABEL_CLS}>URL / Origem Alvo (dentro do escopo)</label>
              <div class="flex flex-wrap items-center gap-1">
                <button
                  type="button"
                  class={CHIP_CLS}
                  onClick={() => wb.sendUrlAcrossWebSuite(d().url, "headers")}
                >
                  → Headers
                </button>
                <button
                  type="button"
                  class={CHIP_CLS}
                  onClick={() => wb.sendUrlAcrossWebSuite(d().url, "intruder")}
                >
                  → Intruder (§slot§)
                </button>
                <button
                  type="button"
                  class={CHIP_CLS}
                  onClick={() => wb.sendUrlAcrossWebSuite(d().url, "params")}
                >
                  → Parâmetros
                </button>
                <button
                  type="button"
                  class={CHIP_CLS}
                  onClick={() => wb.sendUrlAcrossWebSuite(d().url, "scanner")}
                >
                  → Scanner
                </button>
                <Show when={d().body}>
                  <button type="button" class={CHIP_CLS} onClick={() => wb.sendTextToDecoder(d().body)}>
                    → Decoder
                  </button>
                </Show>
              </div>
            </div>
            <input
              type="text"
              value={d().url}
              placeholder="https://alvo-autorizado.exemplo.com/api/v1/profile"
              class={MONO_INPUT_CLS}
              onInput={(e) => wb.updateDraft("http-repeater", (p) => ({ ...p, url: e.currentTarget.value }))}
            />
          </div>
        </div>

        {/* Optional Import cURL quick bar */}
        <details class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/30 px-2.5 py-1.5 text-[11px]">
          <summary class="cursor-pointer font-medium text-v2-text-text-muted select-none">
            Importar requisição de comando cURL ("Copy as cURL" do DevTools / HackerOne)
          </summary>
          <div class="mt-2 flex items-center gap-1.5">
            <input
              type="text"
              value={d().curlImportText ?? ""}
              placeholder="Cole aqui: curl 'https://...' -H 'Cookie: ...' --data-raw '...'"
              class={MONO_INPUT_CLS}
              onInput={(e) =>
                wb.updateDraft("http-repeater", (p) => ({ ...p, curlImportText: e.currentTarget.value }))
              }
            />
            <button
              type="button"
              class={BTN_SECONDARY}
              onClick={() => wb.importCurlIntoRepeater(d().curlImportText ?? "")}
            >
              Importar
            </button>
          </div>
        </details>

        <Show
          when={d().useRawHttp}
          fallback={
            <>
              <SimpleHeaderTable
                title="Headers da Requisição (Engagement Headers de Escopo são injetados automaticamente)"
                rows={d().headers}
                onChange={(rows) => wb.updateDraft("http-repeater", (p) => ({ ...p, headers: rows }))}
              />
              <Show when={d().method !== "GET" && d().method !== "HEAD"}>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Corpo da Requisição (Raw / JSON / GraphQL / Form — até 256 KB)</label>
                  <textarea
                    rows={5}
                    value={d().body}
                    placeholder='{"username":"researcher"}'
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("http-repeater", (p) => ({ ...p, body: e.currentTarget.value }))}
                  />
                </div>
              </Show>
            </>
          }
        >
          <div class="flex flex-col gap-1">
            <div class="flex items-center justify-between">
              <label class={LABEL_CLS}>Editor Raw HTTP/1.1 (Estilo Burp Repeater)</label>
              <button
                type="button"
                class={CHIP_CLS}
                onClick={() =>
                  wb.updateDraft("http-repeater", (p) => ({
                    ...p,
                    rawHttpText: buildRawHttpFromStructured(p.method, p.url, p.headers, p.body),
                  }))
                }
              >
                Regerar do Estruturado
              </button>
            </div>
            <textarea
              rows={9}
              value={d().rawHttpText ?? ""}
              placeholder={"GET /api/v1/me HTTP/1.1\r\nHost: api.exemplo.com\r\nAccept: application/json\r\n\r\n"}
              class={MONO_INPUT_CLS}
              onInput={(e) =>
                wb.updateDraft("http-repeater", (p) => ({ ...p, rawHttpText: e.currentTarget.value }))
              }
            />
          </div>
        </Show>

        <div class="flex flex-wrap items-center gap-4 text-[12px] text-v2-text-text-strong">
          <label class="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={Boolean(d().followRedirects)}
              onChange={(e) =>
                wb.updateDraft("http-repeater", (p) => ({ ...p, followRedirects: e.currentTarget.checked }))
              }
            />
            <span>Seguir redirecionamentos HTTP 301/302 (mesma origem, até 5 saltos)</span>
          </label>
          <label class="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={d().enableBaseline}
              onChange={(e) =>
                wb.updateDraft("http-repeater", (p) => ({ ...p, enableBaseline: e.currentTarget.checked }))
              }
            />
            <span>Comparar automaticamente contra Baseline URL (A/B Diff)</span>
          </label>
        </div>

        <Show when={d().enableBaseline}>
          <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-col gap-2">
            <div class="flex flex-col gap-1">
              <label class={LABEL_CLS}>Baseline URL (ex.: sem autenticação ou conta secundária User B)</label>
              <input
                type="text"
                value={d().baselineUrl}
                placeholder="https://alvo-autorizado.exemplo.com/api/v1/profile"
                class={MONO_INPUT_CLS}
                onInput={(e) =>
                  wb.updateDraft("http-repeater", (p) => ({ ...p, baselineUrl: e.currentTarget.value }))
                }
              />
            </div>
            <SimpleHeaderTable
              title="Headers da Baseline"
              rows={d().baselineHeaders}
              onChange={(rows) => wb.updateDraft("http-repeater", (p) => ({ ...p, baselineHeaders: rows }))}
            />
          </div>
        </Show>

        <div class="grid grid-cols-3 gap-2">
          <div class="flex flex-col gap-1">
            <label class={LABEL_CLS}>Timeout (100–30000 ms)</label>
            <input
              type="number"
              min={100}
              max={30000}
              value={d().timeoutMs}
              class={INPUT_CLS}
              onInput={(e) =>
                wb.updateDraft("http-repeater", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
              }
            />
          </div>
          <div class="flex flex-col gap-1">
            <label class={LABEL_CLS}>Máx Bytes Corpo (até 256 KB)</label>
            <input
              type="number"
              min={256}
              max={262144}
              value={d().maxBodyBytes}
              class={INPUT_CLS}
              onInput={(e) =>
                wb.updateDraft("http-repeater", (p) => ({ ...p, maxBodyBytes: Number(e.currentTarget.value) }))
              }
            />
          </div>
          <div class="flex flex-col gap-1">
            <label class={LABEL_CLS}>Modo de Governança</label>
            <select
              value={d().executionMode}
              class={INPUT_CLS}
              onChange={(e) =>
                wb.updateDraft("http-repeater", (p) => ({
                  ...p,
                  executionMode: e.currentTarget.value as "manual" | "proposed",
                }))
              }
            >
              <option value="manual">Manual Direto</option>
              <option value="proposed">Exigir Aprovação</option>
            </select>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-2 pt-1">
          <button
            type="button"
            disabled={props.isRunning}
            class={BTN_PRIMARY}
            onClick={() => void wb.runCapabilityTool("http-repeater")}
          >
            <Icon name="globe" class="size-3.5" />
            {props.isRunning ? "Enviando Requisição..." : "Send (Enviar Requisição HTTP)"}
          </button>
          <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("http-repeater")}>
            Restaurar Padrão
          </button>
        </div>
      </Show>
    </div>
  )
}

export function BurpProxyCockpitPanel(props: { wb: CyberLabWorkbenchService }) {
  const { wb } = props
  const d = () => wb.drafts["http-proxy"]
  const proxy = () => wb.backend.proxy
  const subTab = () => d().proxySubTab ?? "history"
  const interceptQueue = () => proxy()?.interceptQueue ?? []
  const matchReplaceRules = () => proxy()?.matchReplaceRules ?? []
  const siteMapHosts = () => proxy()?.siteMap?.hosts ?? []
  const passiveAlerts = () => proxy()?.siteMap?.passiveAlerts ?? []
  const oastHits = () => proxy()?.oastHits ?? []
  const httpLogger = () => proxy()?.httpLogger ?? []

  const filteredEntries = createMemo(() => {
    const list = proxy()?.history ?? []
    const q = d().filterText.trim().toLowerCase()
    const methodFilter = (d().filterMethod ?? "ALL").toUpperCase()
    const statusGroup = d().filterStatusGroup ?? "ALL"
    const onlyInScope = Boolean(d().filterInScopeOnly)
    const hideStatic = Boolean(d().hideStaticAssets)

    return list.filter((item) => {
      if (onlyInScope && item.blockedByScope) return false
      if (hideStatic && STATIC_EXT_UI_RE.test(item.path)) return false
      if (methodFilter !== "ALL" && item.method.toUpperCase() !== methodFilter) return false
      if (statusGroup !== "ALL") {
        if (statusGroup === "BLOCKED" && !item.blockedByScope) return false
        if (statusGroup === "2xx" && (item.statusCode < 200 || item.statusCode >= 300)) return false
        if (statusGroup === "3xx" && (item.statusCode < 300 || item.statusCode >= 400)) return false
        if (statusGroup === "4xx" && (item.statusCode < 400 || item.statusCode >= 500)) return false
        if (statusGroup === "5xx" && item.statusCode < 500) return false
      }
      if (!q) return true
      return (
        item.url.toLowerCase().includes(q) ||
        item.method.toLowerCase().includes(q) ||
        item.responseBody.toLowerCase().includes(q) ||
        String(item.statusCode).includes(q)
      )
    })
  })

  const selectedEntry = () =>
    filteredEntries().find((e) => e.entryId === d().selectedEntryId) ?? filteredEntries()[0] ?? undefined

  const activeInterceptItem = (): ProxyInterceptItemDto | undefined => {
    const list = interceptQueue()
    if (list.length === 0) return undefined
    const found = list.find((i) => i.interceptId === d().editingInterceptId) ?? list[0]!
    return found
  }

  const loadInterceptIntoEditor = (item: ProxyInterceptItemDto) => {
    const hdrLines = Object.entries(item.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n")
    wb.updateDraft("http-proxy", (p) => ({
      ...p,
      editingInterceptId: item.interceptId,
      editInterceptMethod: item.method,
      editInterceptUrl: item.url,
      editInterceptHeadersText: hdrLines,
      editInterceptBody: item.body,
      editInterceptStatusCode: item.statusCode ?? 200,
    }))
  }

  const submitInterceptDecision = (item: ProxyInterceptItemDto, decision: "forward" | "drop") => {
    const isLoaded = d().editingInterceptId === item.interceptId
    const parsedHeaders: Record<string, string> = {}
    if (isLoaded && d().editInterceptHeadersText !== undefined) {
      for (const line of (d().editInterceptHeadersText ?? "").split(/\r?\n/)) {
        const idx = line.indexOf(":")
        if (idx > 0) {
          parsedHeaders[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
        }
      }
    }
    void wb.controlProxyAdvanced(
      {
        action: "resolve_intercept",
        interceptId: item.interceptId,
        decision,
        ...(isLoaded && d().editInterceptMethod ? { method: d().editInterceptMethod } : {}),
        ...(isLoaded && d().editInterceptUrl ? { url: d().editInterceptUrl } : {}),
        ...(isLoaded && Object.keys(parsedHeaders).length > 0 ? { headers: parsedHeaders } : {}),
        ...(isLoaded && d().editInterceptBody !== undefined ? { body: d().editInterceptBody } : {}),
        ...(isLoaded && item.phase === "response" && d().editInterceptStatusCode
          ? { statusCode: Number(d().editInterceptStatusCode) }
          : {}),
      },
      decision === "forward" ? "Requisição encaminhada (Forward)!" : "Requisição descartada (Drop)!",
    )
    wb.updateDraft("http-proxy", (p) => ({ ...p, editingInterceptId: "" }))
  }

  const addHostQuickToScope = (host: string, scheme: string, blocked: boolean) => {
    const scope = wb.backend.status?.activeScope
    if (!scope) return
    const cleanHost = host.split(":")[0] || host
    const rule = {
      kind: "domain" as const,
      value: cleanHost,
      notes: blocked ? "Excluído via Target Site Map" : `Adicionado via Target Site Map (${scheme})`,
    }
    if (blocked) {
      void wb.updateScopeRules({ blockedTargets: [...scope.blockedTargets, rule] })
    } else {
      const isExternal = cleanHost !== "localhost" && cleanHost !== "127.0.0.1"
      void wb.updateScopeRules({
        allowExternalTargets: scope.allowExternalTargets || isExternal,
        allowedTargets: [...scope.allowedTargets, rule],
      })
    }
  }

  return (
    <div class="flex flex-col gap-3">
      {/* Top Burp/OpenTRAP Listener + Pre-Configured Browser Launcher + Master Intercept Switch */}
      <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-3 flex flex-col gap-2.5">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex flex-wrap items-center gap-2">
            <div class="flex items-center gap-1.5">
              <span class={LABEL_CLS}>Porta:</span>
              <input
                type="number"
                min={1024}
                max={65535}
                value={d().port}
                class="w-24 rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 font-mono text-[12px] text-v2-text-text-strong"
                onInput={(e) => wb.updateDraft("http-proxy", (p) => ({ ...p, port: Number(e.currentTarget.value) }))}
              />
            </div>

            <Show
              when={proxy()?.status.running}
              fallback={
                <button type="button" class={BTN_PRIMARY} onClick={() => void wb.controlProxy("start")}>
                  Iniciar Proxy ({d().port})
                </button>
              }
            >
              <button
                type="button"
                class="rounded-md bg-red-600 px-3 py-1.5 text-[12px] font-medium text-white hover:bg-red-500 cursor-pointer"
                onClick={() => void wb.controlProxy("stop")}
              >
                Parar Proxy (:{proxy()?.status.listenPort})
              </button>
            </Show>

            {/* MASTER INTERCEPT TOGGLE (BURP STYLE) */}
            <button
              type="button"
              class={
                proxy()?.status.interceptEnabled
                  ? "inline-flex items-center gap-1.5 rounded-md bg-amber-500 px-3 py-1.5 text-[12px] font-semibold text-black hover:bg-amber-400 cursor-pointer"
                  : BTN_SECONDARY
              }
              onClick={() => {
                const next = !proxy()?.status.interceptEnabled
                void wb.controlProxyAdvanced(
                  { action: "configure_intercept", interceptEnabled: next },
                  next ? "Intercept is ON — requisições serão retidas para edição." : "Intercept is OFF — fila liberada.",
                )
                if (next) wb.updateDraft("http-proxy", (p) => ({ ...p, proxySubTab: "intercept" }))
              }}
            >
              <span>{proxy()?.status.interceptEnabled ? "● Intercept is ON" : "Intercept is OFF"}</span>
              <Show when={(proxy()?.status.pendingInterceptCount ?? 0) > 0}>
                <span class="rounded-full bg-black/80 px-1.5 py-0.2 text-[10px] text-amber-300">
                  {proxy()?.status.pendingInterceptCount}
                </span>
              </Show>
            </button>
          </div>

          {/* 1-CLICK PRE-CONFIGURED BROWSER LAUNCHER */}
          <div class="flex flex-wrap items-center gap-1.5">
            <input
              type="text"
              value={d().browserStartUrl ?? ""}
              placeholder="URL inicial (ex.: https://hackerone.com)"
              class="w-52 rounded-md border border-v2-border-border-base bg-v2-background-bg-base px-2 py-1 font-mono text-[11px] text-v2-text-text-strong"
              onInput={(e) =>
                wb.updateDraft("http-proxy", (p) => ({ ...p, browserStartUrl: e.currentTarget.value }))
              }
            />
            <button
              type="button"
              class="inline-flex items-center gap-1.5 rounded-md bg-sky-600 px-3 py-1.5 text-[12px] font-semibold text-white hover:bg-sky-500 cursor-pointer"
              onClick={() => void wb.launchProxyBrowser()}
            >
              <Icon name="globe" class="size-3.5" />
              Abrir Navegador Pré-Configurado
            </button>
            <button type="button" class={BTN_SECONDARY} onClick={() => wb.downloadProxyRootCaCert()}>
              Root CA (.crt)
            </button>
          </div>
        </div>

        {/* Browser Launch Feedback / Manual Command Helper */}
        <Show when={wb.backend.lastBrowserLaunch}>
          {(launch) => (
            <details
              open={!launch().launched}
              class="rounded border border-sky-500/40 bg-sky-500/10 px-2.5 py-1.5 text-[11px] text-v2-text-text-base"
            >
              <summary class="cursor-pointer font-medium text-sky-300">
                {launch().message} (clique para ver comandos manuais PowerShell / Bash ou certificado Firefox)
              </summary>
              <div class="mt-1.5 flex flex-col gap-1 font-mono text-[10px]">
                <div>
                  <strong class="text-v2-text-text-strong">Windows PowerShell (Edge/Chrome c/ HTTPS SPKI):</strong>
                  <pre class="mt-0.5 overflow-x-auto rounded bg-v2-background-bg-base p-1.5 select-text">
                    {launch().manualPowershellCommand}
                  </pre>
                </div>
                <div>
                  <strong class="text-v2-text-text-strong">Linux / macOS Bash:</strong>
                  <pre class="mt-0.5 overflow-x-auto rounded bg-v2-background-bg-base p-1.5 select-text">
                    {launch().manualBashCommand}
                  </pre>
                </div>
                <div class="text-v2-text-text-muted">
                  No Firefox ou celular conectado ao proxy, acesse{" "}
                  <code class="text-emerald-400">http://cyberlab.proxy/cert</code> para instalar a Root CA em 1 clique.
                </div>
              </div>
            </details>
          )}
        </Show>

        <div class="flex flex-wrap items-center justify-between gap-2 text-[11px] text-v2-text-text-muted">
          <div class="flex flex-wrap items-center gap-3">
            <label class="flex items-center gap-1.5 cursor-pointer text-v2-text-text-strong">
              <input
                type="checkbox"
                checked={proxy()?.status.scopeOnly ?? d().scopeOnly}
                onChange={(e) => {
                  wb.updateDraft("http-proxy", (p) => ({ ...p, scopeOnly: e.currentTarget.checked }))
                  if (proxy()?.status.running) void wb.controlProxy("set_scope_only")
                }}
              />
              <span>Bloquear Fora do Escopo (Scope-Only)</span>
            </label>
            <label class="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={d().allowSelfSignedUpstream}
                onChange={(e) =>
                  wb.updateDraft("http-proxy", (p) => ({ ...p, allowSelfSignedUpstream: e.currentTarget.checked }))
                }
              />
              <span>Aceitar TLS autoassinado upstream</span>
            </label>
          </div>
          <div class="flex items-center gap-1.5">
            <select
              value={proxy()?.status.httpsMode ?? d().httpsMode}
              class="rounded border border-v2-border-border-base bg-v2-background-bg-base px-2 py-0.5 text-[11px] text-v2-text-text-strong"
              onChange={(e) => {
                const mode = e.currentTarget.value as "tls_intercept" | "tunnel_passthrough"
                wb.updateDraft("http-proxy", (p) => ({ ...p, httpsMode: mode }))
                if (proxy()?.status.running) void wb.controlProxy("set_https_mode", mode)
              }}
            >
              <option value="tls_intercept">HTTPS MITM (Root CA)</option>
              <option value="tunnel_passthrough">Túnel CONNECT s/ MITM</option>
            </select>
            <button type="button" class={CHIP_CLS} onClick={() => void wb.controlProxy("clear")}>
              Limpar Tudo
            </button>
          </div>
        </div>
      </div>

      {/* 6 BURP SUITE / OPENTRAP SUB-TABS */}
      <div class="flex flex-wrap items-center gap-1 border-b border-v2-border-border-base pb-1.5">
        {(
          [
            {
              id: "intercept",
              label: `Intercept (${interceptQueue().length})`,
            },
            {
              id: "history",
              label: `HTTP / WS History (${proxy()?.history.length ?? 0})`,
            },
            {
              id: "target",
              label: `Target & Site Map (${siteMapHosts().length} hosts · ${passiveAlerts().length} alertas)`,
            },
            {
              id: "match_replace",
              label: `Match & Replace (${matchReplaceRules().length})`,
            },
            {
              id: "oast",
              label: `OAST / Callbacks (${oastHits().length})`,
            },
            {
              id: "logger",
              label: `HTTP Logger (${httpLogger().length})`,
            },
          ] as const
        ).map((tab) => (
          <button
            type="button"
            class={
              subTab() === tab.id
                ? "rounded-md bg-emerald-600 px-2.5 py-1 text-[11px] font-semibold text-white cursor-pointer"
                : CHIP_CLS
            }
            onClick={() => wb.updateDraft("http-proxy", (p) => ({ ...p, proxySubTab: tab.id }))}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* SUB-TAB 1: LIVE INTERCEPT QUEUE (HOLD / EDIT / FORWARD / DROP) */}
      <Show when={subTab() === "intercept"}>
        <div class="flex flex-col gap-2.5">
          <div class="flex flex-wrap items-center justify-between gap-2 rounded border border-v2-border-border-base bg-v2-background-bg-deep/40 px-2.5 py-1.5 text-[11px]">
            <div class="flex flex-wrap items-center gap-3">
              <label class="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={Boolean(proxy()?.status.interceptResponses)}
                  onChange={(e) =>
                    void wb.controlProxyAdvanced({
                      action: "configure_intercept",
                      interceptResponses: e.currentTarget.checked,
                    })
                  }
                />
                <span>Interceptar também Respostas HTTP</span>
              </label>
              <label class="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={proxy()?.status.interceptInScopeOnly !== false}
                  onChange={(e) =>
                    void wb.controlProxyAdvanced({
                      action: "configure_intercept",
                      interceptInScopeOnly: e.currentTarget.checked,
                    })
                  }
                />
                <span>Apenas alvos In-Scope</span>
              </label>
              <label class="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={proxy()?.status.skipStaticAssets !== false}
                  onChange={(e) =>
                    void wb.controlProxyAdvanced({
                      action: "configure_intercept",
                      skipStaticAssets: e.currentTarget.checked,
                    })
                  }
                />
                <span>Ignorar imagens/fontes/CSS</span>
              </label>
            </div>
            <Show when={interceptQueue().length > 1}>
              <div class="flex items-center gap-1">
                <button
                  type="button"
                  class={CHIP_CLS}
                  onClick={() =>
                    void wb.controlProxyAdvanced({ action: "forward_all_intercepts" }, "Toda a fila encaminhada!")
                  }
                >
                  Forward All ({interceptQueue().length})
                </button>
                <button
                  type="button"
                  class={CHIP_CLS}
                  onClick={() =>
                    void wb.controlProxyAdvanced({ action: "drop_all_intercepts" }, "Toda a fila descartada!")
                  }
                >
                  Drop All
                </button>
              </div>
            </Show>
          </div>

          <Show
            when={activeInterceptItem()}
            fallback={
              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/30 p-5 text-center text-[12px] text-v2-text-text-muted">
                {proxy()?.status.interceptEnabled
                  ? "Intercept is ON — aguardando tráfego do navegador para reter aqui em tempo real..."
                  : "Intercept está OFF. Clique em 'Intercept is OFF' no topo para ativar a retenção ao vivo de requisições."}
              </div>
            }
          >
            {(item) => {
              const isEditingThis = () => d().editingInterceptId === item().interceptId
              return (
                <div class="rounded-md border border-amber-500/50 bg-amber-500/5 p-3 flex flex-col gap-2.5">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <div class="flex items-center gap-2 font-mono text-[12px]">
                      <span class="rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-bold uppercase text-amber-300">
                        {item().phase === "request" ? "REQUEST RETIDA" : `RESPONSE RETIDA (${item().statusCode})`}
                      </span>
                      <span class="font-semibold text-v2-text-text-strong">
                        {item().method} {item().url}
                      </span>
                    </div>
                    <div class="flex flex-wrap items-center gap-1.5">
                      <Show when={!isEditingThis()}>
                        <button type="button" class={CHIP_CLS} onClick={() => loadInterceptIntoEditor(item())}>
                          Editar Antes de Enviar
                        </button>
                      </Show>
                      <button
                        type="button"
                        class={BTN_PRIMARY}
                        onClick={() => submitInterceptDecision(item(), "forward")}
                      >
                        Forward (Encaminhar)
                      </button>
                      <button
                        type="button"
                        class="rounded-md bg-red-600 px-3 py-1.5 text-[12px] font-medium text-white hover:bg-red-500 cursor-pointer"
                        onClick={() => submitInterceptDecision(item(), "drop")}
                      >
                        Drop (Bloquear)
                      </button>
                    </div>
                  </div>

                  <Show
                    when={isEditingThis()}
                    fallback={
                      <pre
                        class="max-h-52 overflow-auto rounded bg-v2-background-bg-base p-2 font-mono text-[11px] text-v2-text-text-base select-text"
                        data-scrollable
                      >
                        {`${Object.entries(item().headers)
                          .map(([k, v]) => `${k}: ${v}`)
                          .join("\n")}\n\n${item().body || "(corpo vazio)"}`}
                      </pre>
                    }
                  >
                    <div class="flex flex-col gap-2">
                      <Show when={item().phase === "request"}>
                        <div class="grid grid-cols-[100px_1fr] gap-1.5">
                          <input
                            type="text"
                            value={d().editInterceptMethod ?? item().method}
                            class={MONO_INPUT_CLS}
                            onInput={(e) =>
                              wb.updateDraft("http-proxy", (p) => ({
                                ...p,
                                editInterceptMethod: e.currentTarget.value,
                              }))
                            }
                          />
                          <input
                            type="text"
                            value={d().editInterceptUrl ?? item().url}
                            class={MONO_INPUT_CLS}
                            onInput={(e) =>
                              wb.updateDraft("http-proxy", (p) => ({ ...p, editInterceptUrl: e.currentTarget.value }))
                            }
                          />
                        </div>
                      </Show>
                      <textarea
                        rows={4}
                        value={d().editInterceptHeadersText ?? ""}
                        class={MONO_INPUT_CLS}
                        placeholder="Header: Valor"
                        onInput={(e) =>
                          wb.updateDraft("http-proxy", (p) => ({
                            ...p,
                            editInterceptHeadersText: e.currentTarget.value,
                          }))
                        }
                      />
                      <textarea
                        rows={5}
                        value={d().editInterceptBody ?? ""}
                        class={MONO_INPUT_CLS}
                        placeholder="Corpo editado..."
                        onInput={(e) =>
                          wb.updateDraft("http-proxy", (p) => ({ ...p, editInterceptBody: e.currentTarget.value }))
                        }
                      />
                    </div>
                  </Show>
                </div>
              )
            }}
          </Show>
        </div>
      </Show>

      {/* SUB-TAB 2: HTTP & WEBSOCKET HISTORY */}
      <Show when={subTab() === "history"}>
        <div class="flex flex-col gap-2.5">
          <div class="grid grid-cols-1 md:grid-cols-[1fr_105px_115px] gap-1.5">
            <input
              type="text"
              value={d().filterText}
              placeholder="Filtrar URL, corpo da resposta, método ou status..."
              class={INPUT_CLS}
              onInput={(e) => wb.updateDraft("http-proxy", (p) => ({ ...p, filterText: e.currentTarget.value }))}
            />
            <select
              value={d().filterMethod ?? "ALL"}
              class={INPUT_CLS}
              onChange={(e) => wb.updateDraft("http-proxy", (p) => ({ ...p, filterMethod: e.currentTarget.value }))}
            >
              <option value="ALL">Método: Todos</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
              <option value="WS_UPGRADE">WebSocket</option>
            </select>
            <select
              value={d().filterStatusGroup ?? "ALL"}
              class={INPUT_CLS}
              onChange={(e) =>
                wb.updateDraft("http-proxy", (p) => ({ ...p, filterStatusGroup: e.currentTarget.value }))
              }
            >
              <option value="ALL">Status: Todos</option>
              <option value="2xx">2xx OK</option>
              <option value="3xx">3xx Redirect</option>
              <option value="4xx">4xx Client</option>
              <option value="5xx">5xx Server</option>
              <option value="BLOCKED">Bloqueados</option>
            </select>
          </div>

          <div class="flex flex-wrap items-center gap-4 text-[11px] text-v2-text-text-muted">
            <label class="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(d().filterInScopeOnly)}
                onChange={(e) =>
                  wb.updateDraft("http-proxy", (p) => ({ ...p, filterInScopeOnly: e.currentTarget.checked }))
                }
              />
              <span>Apenas tráfego permitido no Escopo</span>
            </label>
            <label class="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(d().hideStaticAssets)}
                onChange={(e) =>
                  wb.updateDraft("http-proxy", (p) => ({ ...p, hideStaticAssets: e.currentTarget.checked }))
                }
              />
              <span>Ocultar assets estáticos (.png, .css, .woff2)</span>
            </label>
          </div>

          <div class="max-h-56 overflow-y-auto rounded-md border border-v2-border-border-base" data-scrollable>
            <Show
              when={filteredEntries().length > 0}
              fallback={
                <div class="p-4 text-center text-[12px] text-v2-text-text-muted">
                  Nenhuma captura corresponde aos filtros. Clique em "Abrir Navegador Pré-Configurado" acima para navegar no alvo!
                </div>
              }
            >
              <table class="w-full text-left text-[12px]">
                <thead class="bg-v2-background-bg-deep text-[11px] uppercase text-v2-text-text-muted">
                  <tr>
                    <th class="px-2 py-1.5">Método</th>
                    <th class="px-2 py-1.5">Host & Caminho</th>
                    <th class="px-2 py-1.5">Status</th>
                    <th class="px-2 py-1.5">Bytes</th>
                    <th class="px-2 py-1.5">Ações</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filteredEntries()}>
                    {(item) => (
                      <tr
                        class={`border-t border-v2-border-border-base cursor-pointer hover:bg-v2-background-bg-deep/60 ${
                          selectedEntry()?.entryId === item.entryId ? "bg-v2-background-bg-deep" : ""
                        }`}
                        onClick={() => wb.updateDraft("http-proxy", (p) => ({ ...p, selectedEntryId: item.entryId }))}
                      >
                        <td class="px-2 py-1.5 font-mono font-medium whitespace-nowrap">
                          <span class="mr-1 rounded bg-v2-background-bg-base px-1 py-0.5 text-[10px] uppercase text-emerald-500">
                            {item.protocol || "http"}
                          </span>
                          {item.method}
                        </td>
                        <td class="px-2 py-1.5 font-mono truncate max-w-[230px]" title={item.url}>
                          {item.host}
                          {item.path}
                        </td>
                        <td class="px-2 py-1.5 font-mono">
                          {item.blockedByScope ? (
                            <span class="text-red-400">BLOQ</span>
                          ) : (
                            <span>{item.statusCode}</span>
                          )}
                          <Show when={item.passiveAlertCount}>
                            <span class="ml-1 rounded bg-amber-500/20 px-1 text-[10px] text-amber-300">
                              !{item.passiveAlertCount}
                            </span>
                          </Show>
                        </td>
                        <td class="px-2 py-1.5 font-mono text-[11px] text-v2-text-text-muted">{item.responseBytes}B</td>
                        <td class="px-2 py-1.5 flex flex-wrap items-center gap-1">
                          <button
                            type="button"
                            class={CHIP_CLS}
                            onClick={(e) => {
                              e.stopPropagation()
                              wb.sendProxyCaptureToRepeater(item)
                            }}
                          >
                            → Repeater
                          </button>
                          <button
                            type="button"
                            class={CHIP_CLS}
                            onClick={(e) => {
                              e.stopPropagation()
                              wb.sendProxyCaptureToIntruder(item)
                            }}
                          >
                            → Intruder
                          </button>
                          <button
                            type="button"
                            class={CHIP_CLS}
                            onClick={(e) => {
                              e.stopPropagation()
                              void wb.copyProxyCaptureAsCurl(item)
                            }}
                          >
                            cURL
                          </button>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </Show>
          </div>

          <Show when={selectedEntry()}>
            {(sel) => (
              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep p-2.5 flex flex-col gap-2">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <span class="font-mono text-[12px] font-medium text-v2-text-text-strong truncate max-w-full">
                    {sel().method} {sel().url} → HTTP {sel().statusCode} ({sel().elapsedMs}ms · {sel().responseBytes}B)
                  </span>
                  <div class="flex flex-wrap items-center gap-1">
                    <button type="button" class={CHIP_CLS} onClick={() => wb.sendProxyCaptureToRepeater(sel())}>
                      → Repeater (c/ Sessão)
                    </button>
                    <button type="button" class={CHIP_CLS} onClick={() => wb.sendProxyCaptureToComparer(sel(), "A")}>
                      → Comparer A
                    </button>
                    <button type="button" class={CHIP_CLS} onClick={() => wb.sendProxyCaptureToComparer(sel(), "B")}>
                      → Comparer B
                    </button>
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() => wb.sendTextToDecoder(sel().responseBody || sel().requestBody || sel().url)}
                    >
                      → Decoder / JWT
                    </button>
                    <button type="button" class={CHIP_CLS} onClick={() => void wb.persistProxyCapture(sel())}>
                      Cofre SHA-256
                    </button>
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() =>
                        wb.attachToComposer(
                          `Proxy HTTP ${sel().method} ${sel().url}`,
                          JSON.stringify(sel(), null, 2),
                          "proxy-capture.json",
                        )
                      }
                    >
                      Anexar no Chat
                    </button>
                  </div>
                </div>
                <pre
                  class="max-h-48 overflow-auto rounded bg-v2-background-bg-base p-2 font-mono text-[11px] text-v2-text-text-base select-text"
                  data-scrollable
                >
                  {`=== REQUEST HEADERS ===\n${JSON.stringify(sel().requestHeaders, null, 2)}\n${
                    sel().requestBody ? `\n=== REQUEST BODY ===\n${sel().requestBody}\n` : ""
                  }\n=== RESPONSE HEADERS ===\n${JSON.stringify(sel().responseHeaders ?? {}, null, 2)}\n\n=== RESPONSE BODY (Auto-Decompressed) ===\n${sel().responseBody || "(vazio)"}`}
                </pre>
              </div>
            )}
          </Show>
        </div>
      </Show>

      {/* SUB-TAB 3: TARGET SITE MAP & PASSIVE SCANNER */}
      <Show when={subTab() === "target"}>
        <div class="flex flex-col gap-3">
          <div class="flex flex-col gap-1.5">
            <span class={LABEL_CLS}>Mapa Hierárquico de Hosts & Endpoints Descobertos ({siteMapHosts().length})</span>
            <Show
              when={siteMapHosts().length > 0}
              fallback={
                <div class="rounded border border-v2-border-border-base p-3 text-[12px] text-v2-text-text-muted">
                  Navegue pelo alvo usando o Proxy para construir automaticamente a árvore do Site Map e os alertas passivos.
                </div>
              }
            >
              <div class="max-h-56 overflow-y-auto flex flex-col gap-2" data-scrollable>
                <For each={siteMapHosts()}>
                  {(h) => (
                    <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-col gap-1.5 text-[12px]">
                      <div class="flex flex-wrap items-center justify-between gap-2">
                        <div class="flex items-center gap-2 font-mono font-semibold text-v2-text-text-strong">
                          <span>
                            {h.scheme}://{h.host}
                          </span>
                          <span
                            class={
                              h.inScope
                                ? "rounded bg-emerald-500/20 px-1.5 py-0.5 text-[10px] text-emerald-400"
                                : "rounded bg-zinc-500/20 px-1.5 py-0.5 text-[10px] text-v2-text-text-muted"
                            }
                          >
                            {h.inScope ? "IN-SCOPE" : "FORA DO ESCOPO"}
                          </span>
                          <span class="text-[11px] font-normal text-v2-text-text-muted">
                            {h.requestCount} reqs · {h.endpoints.length} rotas
                          </span>
                        </div>
                        <div class="flex items-center gap-1">
                          <Show when={!h.inScope}>
                            <button
                              type="button"
                              class={CHIP_CLS}
                              onClick={() => addHostQuickToScope(h.host, h.scheme, false)}
                            >
                              + Incluir no Escopo
                            </button>
                          </Show>
                          <button
                            type="button"
                            class={CHIP_CLS}
                            onClick={() => addHostQuickToScope(h.host, h.scheme, true)}
                          >
                            Excluir (Out-of-Scope)
                          </button>
                        </div>
                      </div>
                      <div class="max-h-32 overflow-y-auto flex flex-col gap-1 pl-2 border-l border-v2-border-border-base">
                        <For each={h.endpoints}>
                          {(ep) => (
                            <div class="flex flex-wrap items-center justify-between gap-1 font-mono text-[11px]">
                              <span class="truncate max-w-[340px]">
                                <span class="text-emerald-400">[{ep.methods.join(",")}]</span> {ep.path}
                                <Show when={ep.paramNames.length > 0}>
                                  <span class="text-sky-300"> ?({ep.paramNames.join(", ")})</span>
                                </Show>
                              </span>
                              <span class="text-v2-text-text-muted">HTTP {ep.statusCodes.join("/")}</span>
                            </div>
                          )}
                        </For>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>

          <div class="flex flex-col gap-1.5">
            <span class={LABEL_CLS}>Scanner Passivo em Tempo Real ({passiveAlerts().length} alertas)</span>
            <Show
              when={passiveAlerts().length > 0}
              fallback={
                <div class="rounded border border-v2-border-border-base p-2.5 text-[11px] text-v2-text-text-muted">
                  Nenhum alerta passivo disparado ainda (monitora Cookies, HSTS, CORS+Credentials, API Keys em JS, SourceMaps e erros SQL/Stack Trace).
                </div>
              }
            >
              <div class="max-h-48 overflow-y-auto flex flex-col gap-1.5" data-scrollable>
                <For each={passiveAlerts()}>
                  {(al) => (
                    <div class="rounded border border-amber-500/30 bg-amber-500/5 px-2.5 py-1.5 text-[11px] flex flex-col gap-0.5">
                      <div class="flex items-center justify-between gap-2">
                        <span class="font-semibold text-v2-text-text-strong">
                          [{al.severity.toUpperCase()}] {al.title}
                        </span>
                        <span class="font-mono text-[10px] text-v2-text-text-muted">{al.category}</span>
                      </div>
                      <div class="font-mono text-[10px] text-sky-300 truncate">{al.url}</div>
                      <div class="font-mono text-[10px] text-v2-text-text-muted">{al.evidenceSnippet}</div>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </div>
      </Show>

      {/* SUB-TAB 4: MATCH & REPLACE RULES */}
      <Show when={subTab() === "match_replace"}>
        <div class="flex flex-col gap-2.5">
          <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-col gap-2">
            <span class={LABEL_CLS}>Nova Regra Match & Replace Automática no Proxy</span>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-1.5">
              <select
                value={d().mrLocation ?? "request_header"}
                class={INPUT_CLS}
                onChange={(e) =>
                  wb.updateDraft("http-proxy", (p) => ({
                    ...p,
                    mrLocation: e.currentTarget.value as NonNullable<typeof p.mrLocation>,
                  }))
                }
              >
                <option value="request_header">Request Header</option>
                <option value="request_body">Request Body</option>
                <option value="url">Request URL</option>
                <option value="response_header">Response Header</option>
                <option value="response_body">Response Body</option>
              </select>
              <input
                type="text"
                value={d().mrHeaderName ?? ""}
                placeholder="Nome do Header (opcional, ex.: X-Role)"
                class={MONO_INPUT_CLS}
                onInput={(e) => wb.updateDraft("http-proxy", (p) => ({ ...p, mrHeaderName: e.currentTarget.value }))}
              />
              <label class="flex items-center gap-1.5 text-[12px] px-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={Boolean(d().mrIsRegex)}
                  onChange={(e) => wb.updateDraft("http-proxy", (p) => ({ ...p, mrIsRegex: e.currentTarget.checked }))}
                />
                <span>Expressão Regular (Regex)</span>
              </label>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-[1fr_1fr_auto] gap-1.5">
              <input
                type="text"
                value={d().mrMatchPattern ?? ""}
                placeholder="Procurar padrão (vazio em Header = definir/injetar)"
                class={MONO_INPUT_CLS}
                onInput={(e) => wb.updateDraft("http-proxy", (p) => ({ ...p, mrMatchPattern: e.currentTarget.value }))}
              />
              <input
                type="text"
                value={d().mrReplaceWith ?? ""}
                placeholder="Substituir por..."
                class={MONO_INPUT_CLS}
                onInput={(e) => wb.updateDraft("http-proxy", (p) => ({ ...p, mrReplaceWith: e.currentTarget.value }))}
              />
              <button
                type="button"
                class={BTN_PRIMARY}
                onClick={() => {
                  void wb.controlProxyAdvanced(
                    {
                      action: "upsert_match_replace",
                      matchReplaceRule: {
                        enabled: true,
                        location: d().mrLocation ?? "request_header",
                        ...(d().mrHeaderName?.trim() ? { headerName: d().mrHeaderName!.trim() } : {}),
                        matchPattern: d().mrMatchPattern ?? "",
                        replaceWith: d().mrReplaceWith ?? "",
                        isRegex: Boolean(d().mrIsRegex),
                      },
                    },
                    "Regra Match & Replace adicionada!",
                  )
                  wb.updateDraft("http-proxy", (p) => ({ ...p, mrMatchPattern: "", mrReplaceWith: "" }))
                }}
              >
                + Regra
              </button>
            </div>
          </div>

          <div class="flex flex-col gap-1 max-h-48 overflow-y-auto" data-scrollable>
            <For each={matchReplaceRules()}>
              {(rule) => (
                <div class="flex items-center justify-between gap-2 rounded border border-v2-border-border-base bg-v2-background-bg-deep/30 px-2.5 py-1.5 text-[11px] font-mono">
                  <span class="truncate">
                    [{rule.location}
                    {rule.headerName ? `:${rule.headerName}` : ""}] "{rule.matchPattern || "*"}" → "{rule.replaceWith}"
                  </span>
                  <button
                    type="button"
                    class="text-v2-text-text-muted hover:text-red-400 cursor-pointer"
                    onClick={() =>
                      void wb.controlProxyAdvanced({ action: "remove_match_replace", ruleId: rule.ruleId })
                    }
                  >
                    Remover
                  </button>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>

      {/* SUB-TAB 5: OAST / OUT-OF-BAND CALLBACK LISTENER */}
      <Show when={subTab() === "oast"}>
        <div class="flex flex-col gap-2.5">
          <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-3 flex flex-col gap-2 text-[12px]">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div class="font-semibold text-v2-text-text-strong">
                  Receptor OAST / Webhook Callback (SSRF, Blind XSS, XXE & Webhooks)
                </div>
                <div class="font-mono text-[11px] text-emerald-400">
                  {proxy()?.status.oastRunning
                    ? `ONLINE: ${proxy()?.status.oastCallbackBaseUrl}/callback-test`
                    : "Listener OAST local parado"}
                </div>
              </div>
              <div class="flex items-center gap-1.5">
                <Show
                  when={proxy()?.status.oastRunning}
                  fallback={
                    <button
                      type="button"
                      class={BTN_PRIMARY}
                      onClick={() =>
                        void wb.controlProxyAdvanced(
                          {
                            action: "start_oast",
                            oastPort: Number(d().oastPort) || 0,
                            ...(d().externalOastDomain?.trim()
                              ? { externalOastDomain: d().externalOastDomain!.trim() }
                              : {}),
                          },
                          "Receptor OAST iniciado!",
                        )
                      }
                    >
                      Iniciar OAST Listener
                    </button>
                  }
                >
                  <button
                    type="button"
                    class={BTN_SECONDARY}
                    onClick={() => {
                      const u = `${proxy()?.status.oastCallbackBaseUrl}/ssrf-${Date.now()}`
                      if (typeof navigator !== "undefined" && navigator.clipboard) {
                        void navigator.clipboard.writeText(u)
                        wb.setNotice(`Payload OAST copiado: ${u}`)
                      }
                    }}
                  >
                    Copiar Payload URL
                  </button>
                  <button
                    type="button"
                    class={CHIP_CLS}
                    onClick={() => void wb.controlProxyAdvanced({ action: "clear_oast" })}
                  >
                    Limpar Hits
                  </button>
                  <button
                    type="button"
                    class="rounded bg-red-600 px-2.5 py-1 text-[11px] text-white cursor-pointer"
                    onClick={() => void wb.controlProxyAdvanced({ action: "stop_oast" })}
                  >
                    Parar
                  </button>
                </Show>
              </div>
            </div>
          </div>

          <div class="max-h-48 overflow-y-auto flex flex-col gap-1.5" data-scrollable>
            <Show
              when={oastHits().length > 0}
              fallback={
                <div class="p-3 text-center text-[12px] text-v2-text-text-muted">
                  Nenhum callback OAST recebido ainda.
                </div>
              }
            >
              <For each={oastHits()}>
                {(hit) => (
                  <div class="rounded border border-emerald-500/30 bg-emerald-500/5 p-2 font-mono text-[11px]">
                    <div class="font-semibold text-emerald-300">
                      [{hit.timestamp}] {hit.method} {hit.path}
                      {hit.query} (origem: {hit.remoteAddress})
                    </div>
                    <Show when={hit.bodyPreview}>
                      <div class="text-v2-text-text-muted truncate">{hit.bodyPreview}</div>
                    </Show>
                  </div>
                )}
              </For>
            </Show>
          </div>
        </div>
      </Show>

      {/* SUB-TAB 6: GLOBAL HTTP LOGGER */}
      <Show when={subTab() === "logger"}>
        <div class="flex flex-col gap-2">
          <div class="flex items-center justify-between">
            <span class={LABEL_CLS}>
              Logger Global de Tráfego HTTP (Proxy · Repeater · Intruder · Scanner · API Lab · Key Hunter)
            </span>
            <button
              type="button"
              class={CHIP_CLS}
              onClick={() => void wb.controlProxyAdvanced({ action: "clear_http_logger" }, "Logger HTTP limpo.")}
            >
              Limpar Logger
            </button>
          </div>
          <div class="max-h-60 overflow-y-auto rounded border border-v2-border-border-base" data-scrollable>
            <Show
              when={httpLogger().length > 0}
              fallback={
                <div class="p-4 text-center text-[12px] text-v2-text-text-muted">
                  Nenhuma requisição registrada no Logger Global ainda.
                </div>
              }
            >
              <table class="w-full text-left text-[11px] font-mono">
                <thead class="bg-v2-background-bg-deep text-v2-text-text-muted uppercase">
                  <tr>
                    <th class="px-2 py-1">Origem</th>
                    <th class="px-2 py-1">Método & URL</th>
                    <th class="px-2 py-1">HTTP</th>
                    <th class="px-2 py-1">Tempo</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={httpLogger()}>
                    {(row) => (
                      <tr class="border-t border-v2-border-border-base">
                        <td class="px-2 py-1 text-emerald-400">{row.sourceTool}</td>
                        <td class="px-2 py-1 truncate max-w-[280px]" title={row.url}>
                          {row.method} {row.url}
                        </td>
                        <td class="px-2 py-1">{row.statusCode}</td>
                        <td class="px-2 py-1 text-v2-text-text-muted">{row.elapsedMs}ms</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </Show>
          </div>
        </div>
      </Show>
    </div>
  )
}

export function BugBountyScopePanel(props: { wb: CyberLabWorkbenchService }) {
  const { wb } = props
  const d = () => wb.drafts["scope-governance"]
  const scope = () => wb.backend.status?.activeScope
  const engagement = (): EngagementProfileDto =>
    scope()?.engagement ?? {
      mode: "lab_isolated",
      platform: "custom",
      maxRequestsPerSecond: 20,
      customHeaders: [],
    }

  const addScopeRule = () => {
    const val = d().newRuleValue.trim()
    if (!val || !scope()) return
    const rule = {
      kind: d().newRuleKind as ScopeRuleKindDto,
      value: val,
      ...(d().newRuleNotes.trim() ? { notes: d().newRuleNotes.trim() } : {}),
    }
    if (d().newRuleBlocked) {
      void wb.updateScopeRules({ blockedTargets: [...(scope()?.blockedTargets ?? []), rule] })
    } else {
      const autoEnableExternal =
        d().newRuleKind !== "workspace_path" && val !== "127.0.0.1" && val !== "localhost"
      void wb.updateScopeRules({
        ...(autoEnableExternal ? { allowExternalTargets: true } : {}),
        allowedTargets: [...(scope()?.allowedTargets ?? []), rule],
      })
    }
    wb.updateDraft("scope-governance", (p) => ({ ...p, newRuleValue: "", newRuleNotes: "" }))
  }

  const saveEngagementPatch = (patch: Partial<EngagementProfileDto>) => {
    const cur = engagement()
    void wb.updateScopeRules({
      ...(patch.mode && patch.mode !== "lab_isolated" ? { allowExternalTargets: true } : {}),
      engagement: {
        ...cur,
        ...patch,
      },
    })
  }

  const addCustomEngagementHeader = () => {
    const name = (d().newHeaderName ?? "").trim()
    const value = d().newHeaderValue ?? ""
    if (!name) return
    const cur = engagement()
    const nextHeaders: EngagementHeaderRuleDto[] = [
      ...cur.customHeaders.filter((h) => h.name.toLowerCase() !== name.toLowerCase()),
      { name, value, enabled: true },
    ]
    saveEngagementPatch({ customHeaders: nextHeaders })
    wb.updateDraft("scope-governance", (p) => ({ ...p, newHeaderName: "", newHeaderValue: "" }))
  }

  return (
    <div class="flex flex-col gap-3">
      {/* 1. External Network Master Switch + Persistence Status */}
      <label class="flex items-center justify-between gap-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2.5 text-[12px] cursor-pointer">
        <span>
          <strong class="text-v2-text-text-strong">
            Liberar Alvos de Produção / Bug Bounty / Redes Externas Autorizadas
          </strong>
          <span class="block text-[11px] text-v2-text-text-muted">
            Escopo persistido automaticamente em <code class="font-mono text-emerald-400">.cyberlab/scope.json</code>.
            Ative para operar no HackerOne, Bugcrowd, Intigriti ou pentests contratados.
          </span>
        </span>
        <input
          type="checkbox"
          checked={Boolean(scope()?.allowExternalTargets)}
          onChange={(e) => void wb.updateScopeRules({ allowExternalTargets: e.currentTarget.checked })}
        />
      </label>

      {/* 2. Engagement Profile (Mode + Rate-Limit RPS + Researcher Headers X-Bug-Bounty / Cookie Jar) */}
      <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-3 flex flex-col gap-2.5">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class={LABEL_CLS}>
            Perfil Global de Engajamento (Injetado em Proxy, Repeater, Intruder, Scanner, API Lab & Key Hunter)
          </span>
          <span class="font-mono text-[10px] text-emerald-400">
            Modo: {engagement().mode} · Limite: {engagement().maxRequestsPerSecond} req/s
          </span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-2">
          <div class="flex flex-col gap-1">
            <label class={LABEL_CLS}>Modo de Operação</label>
            <select
              value={engagement().mode}
              class={INPUT_CLS}
              onChange={(e) =>
                saveEngagementPatch({ mode: e.currentTarget.value as EngagementProfileDto["mode"] })
              }
            >
              <option value="lab_isolated">Laboratório Local Isolado</option>
              <option value="bug_bounty">Bug Bounty (HackerOne / Bugcrowd)</option>
              <option value="authorized_pentest">Pentest Corporativo Autorizado</option>
            </select>
          </div>
          <div class="flex flex-col gap-1">
            <label class={LABEL_CLS}>Rate-Limit Global (req/s)</label>
            <input
              type="number"
              min={1}
              max={200}
              value={engagement().maxRequestsPerSecond}
              class={MONO_INPUT_CLS}
              onChange={(e) =>
                saveEngagementPatch({ maxRequestsPerSecond: Math.max(1, Number(e.currentTarget.value) || 10) })
              }
            />
          </div>
          <div class="flex flex-col gap-1">
            <label class={LABEL_CLS}>User-Agent do Pesquisador</label>
            <input
              type="text"
              value={engagement().customUserAgent ?? ""}
              placeholder="Mozilla/5.0 CyberLab-BugBounty"
              class={MONO_INPUT_CLS}
              onChange={(e) => saveEngagementPatch({ customUserAgent: e.currentTarget.value })}
            />
          </div>
        </div>

        {/* Global Custom Headers (X-Bug-Bounty, Session Cookie, Authorization) */}
        <div class="flex flex-col gap-1.5">
          <span class={LABEL_CLS}>
            Headers Globais de Programa / Sessão (ex.: X-Bug-Bounty: HackerOne-usuario, Authorization, Cookie)
          </span>
          <div class="grid grid-cols-1 md:grid-cols-[170px_1fr_auto] gap-1.5">
            <input
              type="text"
              value={d().newHeaderName ?? ""}
              placeholder="X-Bug-Bounty"
              class={MONO_INPUT_CLS}
              onInput={(e) =>
                wb.updateDraft("scope-governance", (p) => ({ ...p, newHeaderName: e.currentTarget.value }))
              }
            />
            <input
              type="text"
              value={d().newHeaderValue ?? ""}
              placeholder="HackerOne-seuhandle"
              class={MONO_INPUT_CLS}
              onInput={(e) =>
                wb.updateDraft("scope-governance", (p) => ({ ...p, newHeaderValue: e.currentTarget.value }))
              }
            />
            <button type="button" class={BTN_SECONDARY} onClick={addCustomEngagementHeader}>
              + Header Global
            </button>
          </div>

          <For each={engagement().customHeaders}>
            {(hdr, idx) => (
              <div class="flex items-center justify-between gap-2 rounded bg-v2-background-bg-base px-2.5 py-1 font-mono text-[11px]">
                <span class="truncate">
                  {hdr.name}: {hdr.value}
                </span>
                <button
                  type="button"
                  class="text-v2-text-text-muted hover:text-red-400 cursor-pointer"
                  onClick={() =>
                    saveEngagementPatch({
                      customHeaders: engagement().customHeaders.filter((_, i) => i !== idx()),
                    })
                  }
                >
                  Remover
                </button>
              </div>
            )}
          </For>
        </div>
      </div>

      {/* 3. 1-Click HackerOne / Bugcrowd / Wildcard Scope Importer */}
      <details class="rounded-md border border-emerald-500/40 bg-emerald-500/5 p-3 text-[12px]">
        <summary class="cursor-pointer font-semibold text-emerald-300 select-none">
          Importar Escopo de Programa Bug Bounty (JSON HackerOne / Bugcrowd ou lista *.alvo.com + !exclusões)
        </summary>
        <div class="mt-2.5 flex flex-col gap-2">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-2">
            <select
              value={d().bountyPlatform ?? "hackerone"}
              class={INPUT_CLS}
              onChange={(e) =>
                wb.updateDraft("scope-governance", (p) => ({
                  ...p,
                  bountyPlatform: e.currentTarget.value as NonNullable<typeof p.bountyPlatform>,
                }))
              }
            >
              <option value="hackerone">HackerOne</option>
              <option value="bugcrowd">Bugcrowd</option>
              <option value="intigriti">Intigriti</option>
              <option value="yeswehack">YesWeHack</option>
              <option value="custom">Custom / Pentest</option>
            </select>
            <input
              type="text"
              value={d().bountyResearcherHandle ?? ""}
              placeholder="Seu handle (ex.: vitorsec)"
              class={MONO_INPUT_CLS}
              onInput={(e) =>
                wb.updateDraft("scope-governance", (p) => ({ ...p, bountyResearcherHandle: e.currentTarget.value }))
              }
            />
            <input
              type="number"
              min={1}
              max={100}
              value={d().bountyMaxRps ?? 5}
              placeholder="Máx RPS (ex.: 5)"
              class={MONO_INPUT_CLS}
              onInput={(e) =>
                wb.updateDraft("scope-governance", (p) => ({ ...p, bountyMaxRps: Number(e.currentTarget.value) }))
              }
            />
          </div>
          <textarea
            rows={4}
            value={d().bountyRawImportText ?? ""}
            placeholder={
              "Cole o JSON exportado do HackerOne (structured_scopes) / Bugcrowd OU regras por linha:\n*.exemplo.com\nhttps://api.exemplo.com/v2/\n!pagamentos.exemplo.com"
            }
            class={MONO_INPUT_CLS}
            onInput={(e) =>
              wb.updateDraft("scope-governance", (p) => ({ ...p, bountyRawImportText: e.currentTarget.value }))
            }
          />
          <div>
            <button type="button" class={BTN_PRIMARY} onClick={() => void wb.importBugBountyScope()}>
              Importar Escopo & Configurar Engajamento
            </button>
          </div>
        </div>
      </details>

      {/* 4. Manual In-Scope & Out-of-Scope Rule Builder */}
      <div class="flex flex-col gap-2">
        <span class={LABEL_CLS}>Adicionar Regra Manual In-Scope ou Exclusão Out-of-Scope</span>
        <div class="grid grid-cols-1 md:grid-cols-[135px_125px_1fr_auto] gap-1.5">
          <select
            value={d().newRuleBlocked ? "blocked" : "allowed"}
            class={INPUT_CLS}
            onChange={(e) =>
              wb.updateDraft("scope-governance", (p) => ({
                ...p,
                newRuleBlocked: e.currentTarget.value === "blocked",
              }))
            }
          >
            <option value="allowed">✓ In-Scope</option>
            <option value="blocked">✕ Out-of-Scope</option>
          </select>
          <select
            value={d().newRuleKind}
            class={INPUT_CLS}
            onChange={(e) =>
              wb.updateDraft("scope-governance", (p) => ({
                ...p,
                newRuleKind: e.currentTarget.value as ScopeRuleKindDto,
              }))
            }
          >
            <option value="domain">Domínio (*.x.com)</option>
            <option value="url_prefix">URL Prefix</option>
            <option value="url_origin">URL Origin</option>
            <option value="url_regex">URL Regex</option>
            <option value="ip">IP</option>
            <option value="cidr">CIDR</option>
            <option value="workspace_path">Pasta Externa PC</option>
          </select>
          <input
            type="text"
            value={d().newRuleValue}
            placeholder="ex.: *.hackerone-target.com, https://app.alvo.com/api/ ou C:\Downloads\Bounty"
            class={MONO_INPUT_CLS}
            onInput={(e) =>
              wb.updateDraft("scope-governance", (p) => ({ ...p, newRuleValue: e.currentTarget.value }))
            }
          />
          <button type="button" class={BTN_PRIMARY} onClick={addScopeRule}>
            + Regra
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
          <div class="flex flex-col gap-1 max-h-44 overflow-y-auto" data-scrollable>
            <span class="text-[11px] font-semibold text-emerald-400">
              In-Scope Autorizados ({(scope()?.allowedTargets ?? []).length})
            </span>
            <For each={scope()?.allowedTargets ?? []}>
              {(rule, idx) => (
                <div class="flex items-center justify-between rounded border border-v2-border-border-base bg-v2-background-bg-deep/40 px-2 py-1 text-[11px] font-mono">
                  <span class="truncate" title={rule.notes || rule.value}>
                    [{rule.kind}] {rule.value}
                  </span>
                  <button
                    type="button"
                    class="text-v2-text-text-muted hover:text-red-400 cursor-pointer ml-2"
                    onClick={() =>
                      void wb.updateScopeRules({
                        allowedTargets: (scope()?.allowedTargets ?? []).filter((_, i) => i !== idx()),
                      })
                    }
                  >
                    ×
                  </button>
                </div>
              )}
            </For>
          </div>

          <div class="flex flex-col gap-1 max-h-44 overflow-y-auto" data-scrollable>
            <span class="text-[11px] font-semibold text-red-400">
              Out-of-Scope Bloqueados ({(scope()?.blockedTargets ?? []).length})
            </span>
            <For each={scope()?.blockedTargets ?? []}>
              {(rule, idx) => (
                <div class="flex items-center justify-between rounded border border-red-500/30 bg-red-500/5 px-2 py-1 text-[11px] font-mono">
                  <span class="truncate" title={rule.notes || rule.value}>
                    [{rule.kind}] {rule.value}
                  </span>
                  <button
                    type="button"
                    class="text-v2-text-text-muted hover:text-red-400 cursor-pointer ml-2"
                    onClick={() =>
                      void wb.updateScopeRules({
                        blockedTargets: (scope()?.blockedTargets ?? []).filter((_, i) => i !== idx()),
                      })
                    }
                  >
                    ×
                  </button>
                </div>
              )}
            </For>
          </div>
        </div>
      </div>

      {/* 5. Local External Artifact Importer (.cyberlab/imports/) */}
      <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-wrap items-center justify-between gap-2 text-[12px]">
        <div>
          <span class="font-semibold text-v2-text-text-strong">
            Artefatos Externos Importados (.cyberlab/imports/)
          </span>
          <div class="text-[11px] text-v2-text-text-muted">
            Importe APKs, binários ELF/PE, capturas .pcap, specs OpenAPI/Swagger ou logs de qualquer pasta do seu PC.
          </div>
        </div>
        <LocalArtifactUploadButton
          wb={wb}
          label="Importar Arquivo p/ Projeto"
          onImported={(rel) => wb.setNotice(`Disponível em todas as ferramentas como: ${rel}`)}
        />
      </div>
    </div>
  )
}

export function QuickFileImportBar(props: { wb: CyberLabWorkbenchService; toolId: ManualToolId }) {
  const applyPath = (rel: string) => {
    const id = props.toolId
    if (id === "pcap-analyzer" || id === "tshark") {
      props.wb.updateDraft(id, (p) => ({ ...p, pcapPath: rel }))
    } else if (id === "binary-triage" || id === "binary-disasm" || id === "ghidra") {
      props.wb.updateDraft(id, (p) => ({ ...p, binaryPath: rel }))
    } else if (id === "mobile-triage" || id === "jadx") {
      props.wb.updateDraft(id, (p) => ({ ...p, artifactPath: rel }))
    } else if (
      id === "yara-scan" ||
      id === "yarax" ||
      id === "sca-sbom-iac" ||
      id === "trivy" ||
      id === "entropy-recipe"
    ) {
      props.wb.updateDraft(id, (p) => ({ ...p, targetPath: rel }))
    } else if (id === "api-security-lab") {
      props.wb.updateDraft("api-security-lab", (p) => ({ ...p, specPath: rel }))
    } else if (id === "dfir-sigma") {
      props.wb.updateDraft("dfir-sigma", (p) => ({ ...p, logPath: rel }))
    } else if (id === "workspace-audit" || id === "key-hunter") {
      props.wb.updateDraft(id, (p) => ({ ...p, subpath: rel }))
    } else if (id === "ffuf") {
      props.wb.updateDraft("ffuf", (p) => ({ ...p, wordlistPath: rel }))
    }
  }

  const isFileTool = () =>
    [
      "pcap-analyzer",
      "tshark",
      "binary-triage",
      "binary-disasm",
      "ghidra",
      "mobile-triage",
      "jadx",
      "yara-scan",
      "yarax",
      "sca-sbom-iac",
      "trivy",
      "entropy-recipe",
      "api-security-lab",
      "dfir-sigma",
      "workspace-audit",
      "key-hunter",
      "ffuf",
    ].includes(props.toolId)

  return (
    <Show when={isFileTool()}>
      <div class="mb-2.5 flex flex-wrap items-center justify-between gap-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 px-2.5 py-1.5 text-[11px]">
        <span class="text-v2-text-text-muted">
          <strong class="text-v2-text-text-strong">Modo Produção / Artefato Externo:</strong> importe qualquer arquivo do seu PC ou autorize uma pasta externa na aba Escopo.
        </span>
        <LocalArtifactUploadButton wb={props.wb} label="Carregar Arquivo do PC" onImported={applyPath} />
      </div>
    </Show>
  )
}

