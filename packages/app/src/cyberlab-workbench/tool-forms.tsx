import { For, Match, Show, Switch } from "solid-js"
import { Icon } from "@opencode/ui/icon"
import type { CyberLabWorkbenchService } from "./state"
import type { DecoderTransformStep, KeyValueHeaderRow } from "./types"

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

const DECODER_STEPS: Array<{ id: DecoderTransformStep; label: string }> = [
  { id: "base64_decode", label: "Base64 Decode" },
  { id: "base64_encode", label: "Base64 Encode" },
  { id: "base64url_decode", label: "Base64URL Decode" },
  { id: "url_decode", label: "URL Decode" },
  { id: "url_encode", label: "URL Encode" },
  { id: "hex_decode", label: "Hex Decode" },
  { id: "hex_encode", label: "Hex Encode" },
  { id: "html_decode", label: "HTML Decode" },
  { id: "sha256", label: "SHA-256 Hash" },
]

function HeaderEditorTable(props: {
  title: string
  rows: KeyValueHeaderRow[]
  onChange: (rows: KeyValueHeaderRow[]) => void
}) {
  const addRow = (name = "", value = "") => {
    props.onChange([
      ...props.rows,
      { id: `hdr-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, enabled: true, name, value },
    ])
  }

  return (
    <div class="flex flex-col gap-1.5 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2.5">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <span class={LABEL_CLS}>{props.title}</span>
        <div class="flex flex-wrap items-center gap-1">
          <button type="button" class={CHIP_CLS} onClick={() => addRow("Authorization", "Bearer ")}>
            + Authorization
          </button>
          <button type="button" class={CHIP_CLS} onClick={() => addRow("Cookie", "session=")}>
            + Cookie
          </button>
          <button type="button" class={CHIP_CLS} onClick={() => addRow("Content-Type", "application/json")}>
            + JSON
          </button>
          <button type="button" class={CHIP_CLS} onClick={() => addRow("", "")}>
            + Header
          </button>
        </div>
      </div>
      <div class="flex flex-col gap-1.5">
        <For each={props.rows}>
          {(row, idx) => (
            <div class="grid grid-cols-[auto_minmax(110px,1fr)_minmax(140px,2fr)_auto] items-center gap-1.5">
              <input
                type="checkbox"
                checked={row.enabled}
                onChange={(e) => {
                  const copy = [...props.rows]
                  copy[idx()] = { ...row, enabled: e.currentTarget.checked }
                  props.onChange(copy)
                }}
              />
              <input
                type="text"
                placeholder="Header (ex: X-Api-Key)"
                value={row.name}
                class={MONO_INPUT_CLS}
                onInput={(e) => {
                  const copy = [...props.rows]
                  copy[idx()] = { ...row, name: e.currentTarget.value }
                  props.onChange(copy)
                }}
              />
              <input
                type="text"
                placeholder="Valor"
                value={row.value}
                class={MONO_INPUT_CLS}
                onInput={(e) => {
                  const copy = [...props.rows]
                  copy[idx()] = { ...row, value: e.currentTarget.value }
                  props.onChange(copy)
                }}
              />
              <button
                type="button"
                title="Remover header"
                class="rounded p-1 text-v2-text-text-muted hover:text-red-500 cursor-pointer"
                onClick={() => props.onChange(props.rows.filter((_, i) => i !== idx()))}
              >
                <Icon name="trash" class="size-3.5" />
              </button>
            </div>
          )}
        </For>
      </div>
    </div>
  )
}

function RawJsonOverrideSection(props: {
  enabled: boolean
  rawJson: string
  onToggle: (v: boolean) => void
  onChange: (v: string) => void
}) {
  return (
    <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-col gap-2">
      <label class="flex items-center justify-between gap-2 text-[12px] text-v2-text-text-base cursor-pointer">
        <span>Modo Avançado: enviar payload JSON bruto diretamente ao executor</span>
        <input
          type="checkbox"
          checked={props.enabled}
          onChange={(e) => props.onToggle(e.currentTarget.checked)}
        />
      </label>
      <Show when={props.enabled}>
        <textarea
          rows={5}
          value={props.rawJson}
          class={MONO_INPUT_CLS}
          onInput={(e) => props.onChange(e.currentTarget.value)}
        />
      </Show>
    </div>
  )
}

function ExternalBinaryBadge(props: { wb: CyberLabWorkbenchService; toolId: string }) {
  const info = () => props.wb.backend.external?.tools.find((t) => t.toolId === props.toolId)
  return (
    <Show when={info()}>
      {(item) => (
        <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/60 px-3 py-2 text-[12px] flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span
              class={`inline-block size-2 rounded-full ${item().available ? "bg-emerald-500" : "bg-amber-500"}`}
            />
            <span class="font-medium text-v2-text-text-strong">{item().displayName}:</span>
            <span class="font-mono text-[11px] text-v2-text-text-muted">
              {item().available ? item().resolvedPath : "Não encontrado em .cyberlab/bin ou PATH"}
            </span>
          </div>
          <Show when={!item().available}>
            <code class="text-[11px] text-amber-500">{item().installHint}</code>
          </Show>
        </div>
      )}
    </Show>
  )
}

export function ManualToolConfigForm(props: { wb: CyberLabWorkbenchService }) {
  const { wb } = props
  const toolId = () => wb.ui.activeToolId
  const isRunning = () => wb.ui.runningToolId === toolId()

  return (
    <Switch>
      {/* 1. HTTP REPEATER & COMPARER */}
      <Match when={toolId() === "http-repeater"}>
        {(() => {
          const d = () => wb.drafts["http-repeater"]
          return (
            <div class="flex flex-col gap-3">
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
                  <label class={LABEL_CLS}>URL Alvo (dentro do escopo)</label>
                  <input
                    type="text"
                    value={d().url}
                    placeholder="http://127.0.0.1:4096/api/info"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("http-repeater", (p) => ({ ...p, url: e.currentTarget.value }))}
                  />
                </div>
              </div>

              <HeaderEditorTable
                title="Headers da Requisição Principal"
                rows={d().headers}
                onChange={(rows) => wb.updateDraft("http-repeater", (p) => ({ ...p, headers: rows }))}
              />

              <Show when={d().method !== "GET" && d().method !== "HEAD"}>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Corpo da Requisição (Raw / JSON / Form — até 64 KB)</label>
                  <textarea
                    rows={4}
                    value={d().body}
                    placeholder='{"username":"admin"}'
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("http-repeater", (p) => ({ ...p, body: e.currentTarget.value }))}
                  />
                </div>
              </Show>

              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-col gap-2">
                <label class="flex items-center justify-between gap-2 text-[12px] font-medium text-v2-text-text-strong cursor-pointer">
                  <span>Ativar Response Comparer (comparar Status, Tamanho, Tempo e Diff contra Baseline)</span>
                  <input
                    type="checkbox"
                    checked={d().enableBaseline}
                    onChange={(e) =>
                      wb.updateDraft("http-repeater", (p) => ({ ...p, enableBaseline: e.currentTarget.checked }))
                    }
                  />
                </label>
                <Show when={d().enableBaseline}>
                  <div class="flex flex-col gap-2 pt-1">
                    <div class="flex flex-col gap-1">
                      <label class={LABEL_CLS}>Baseline URL (ex.: endpoint sem autenticação ou perfil comum)</label>
                      <input
                        type="text"
                        value={d().baselineUrl}
                        placeholder="http://127.0.0.1:4096/api/health"
                        class={MONO_INPUT_CLS}
                        onInput={(e) =>
                          wb.updateDraft("http-repeater", (p) => ({ ...p, baselineUrl: e.currentTarget.value }))
                        }
                      />
                    </div>
                    <HeaderEditorTable
                      title="Headers da Baseline"
                      rows={d().baselineHeaders}
                      onChange={(rows) => wb.updateDraft("http-repeater", (p) => ({ ...p, baselineHeaders: rows }))}
                    />
                  </div>
                </Show>
              </div>

              <div class="grid grid-cols-3 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Timeout (100–15000 ms)</label>
                  <input
                    type="number"
                    min={100}
                    max={15000}
                    value={d().timeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-repeater", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Bytes Corpo (256–65536)</label>
                  <input
                    type="number"
                    min={256}
                    max={65536}
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

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("http-repeater", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("http-repeater", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex flex-wrap items-center gap-2 pt-1">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("http-repeater")}
                >
                  <Icon name="globe" class="size-3.5" />
                  {isRunning() ? "Enviando Requisição..." : "Enviar Requisição HTTP"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("http-repeater")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 2. PROXY HTTP LOCAL */}
      <Match when={toolId() === "http-proxy"}>
        {(() => {
          const d = () => wb.drafts["http-proxy"]
          const proxy = () => wb.backend.proxy
          const entries = () => {
            const list = proxy()?.history ?? []
            const q = d().filterText.trim().toLowerCase()
            if (!q) return list
            return list.filter(
              (item) =>
                item.url.toLowerCase().includes(q) ||
                item.method.toLowerCase().includes(q) ||
                String(item.statusCode).includes(q),
            )
          }
          const selected = () =>
            entries().find((e) => e.entryId === d().selectedEntryId) ?? entries()[0] ?? undefined

          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-1 md:grid-cols-[120px_1fr_auto] items-end gap-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-3">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Porta Local</label>
                  <input
                    type="number"
                    min={1024}
                    max={65535}
                    value={d().port}
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-proxy", (p) => ({ ...p, port: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <label class="flex items-center gap-2 pb-1.5 text-[12px] text-v2-text-text-strong cursor-pointer">
                  <input
                    type="checkbox"
                    checked={proxy()?.status.scopeOnly ?? d().scopeOnly}
                    onChange={(e) => {
                      wb.updateDraft("http-proxy", (p) => ({ ...p, scopeOnly: e.currentTarget.checked }))
                      if (proxy()?.status.running) void wb.controlProxy("set_scope_only")
                    }}
                  />
                  <span>Bloquear automaticamente requisições fora do Escopo (Scope-Only)</span>
                </label>
                <div class="flex flex-wrap items-center gap-1.5">
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
                      Parar Proxy ({proxy()?.status.listenPort})
                    </button>
                  </Show>
                  <button type="button" class={BTN_SECONDARY} onClick={() => void wb.refreshBackend()}>
                    <Icon name="refresh" class="size-3.5" />
                  </button>
                  <button type="button" class={BTN_SECONDARY} onClick={() => void wb.controlProxy("clear")}>
                    Limpar Capturas
                  </button>
                </div>
              </div>

              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 px-3 py-2 text-[11px] text-v2-text-text-muted flex flex-col gap-1">
                <span>Configure seu navegador/cliente HTTP para usar o proxy local ou teste direto no terminal:</span>
                <code class="font-mono text-v2-text-text-strong select-text">
                  curl -x http://127.0.0.1:{proxy()?.status.listenPort ?? d().port} http://127.0.0.1:4096/api/info
                </code>
              </div>

              <input
                type="text"
                value={d().filterText}
                placeholder="Filtrar tráfego capturado por URL, método ou status HTTP..."
                class={INPUT_CLS}
                onInput={(e) => wb.updateDraft("http-proxy", (p) => ({ ...p, filterText: e.currentTarget.value }))}
              />

              <div class="max-h-48 overflow-y-auto rounded-md border border-v2-border-border-base" data-scrollable>
                <Show
                  when={entries().length > 0}
                  fallback={
                    <div class="p-4 text-center text-[12px] text-v2-text-text-muted">
                      Nenhuma requisição interceptada ainda. Inicie o Proxy acima e envie tráfego pela porta{" "}
                      {proxy()?.status.listenPort ?? d().port}.
                    </div>
                  }
                >
                  <table class="w-full text-left text-[12px]">
                    <thead class="bg-v2-background-bg-deep text-[11px] uppercase text-v2-text-text-muted">
                      <tr>
                        <th class="px-2.5 py-1.5">Método</th>
                        <th class="px-2.5 py-1.5">URL</th>
                        <th class="px-2.5 py-1.5">Status</th>
                        <th class="px-2.5 py-1.5">Tempo</th>
                        <th class="px-2.5 py-1.5">Ações</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={entries()}>
                        {(item) => (
                          <tr
                            class={`border-t border-v2-border-border-base cursor-pointer hover:bg-v2-background-bg-deep/60 ${
                              selected()?.entryId === item.entryId ? "bg-v2-background-bg-deep" : ""
                            }`}
                            onClick={() =>
                              wb.updateDraft("http-proxy", (p) => ({ ...p, selectedEntryId: item.entryId }))
                            }
                          >
                            <td class="px-2.5 py-1.5 font-mono font-medium">{item.method}</td>
                            <td class="px-2.5 py-1.5 font-mono truncate max-w-[240px]">{item.url}</td>
                            <td class="px-2.5 py-1.5 font-mono">
                              {item.blockedByScope ? "BLOQUEADO" : item.statusCode}
                            </td>
                            <td class="px-2.5 py-1.5 text-v2-text-text-muted">{item.elapsedMs}ms</td>
                            <td class="px-2.5 py-1.5 flex items-center gap-1">
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
                                  void wb.persistProxyCapture(item)
                                }}
                              >
                                SHA-256
                              </button>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </Show>
              </div>

              <Show when={selected()}>
                {(sel) => (
                  <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep p-2.5 flex flex-col gap-2">
                    <div class="flex flex-wrap items-center justify-between gap-2">
                      <span class="font-mono text-[12px] font-medium text-v2-text-text-strong">
                        {sel().method} {sel().url} → HTTP {sel().statusCode} ({sel().responseBytes} bytes)
                      </span>
                      <div class="flex items-center gap-1.5">
                        <button
                          type="button"
                          class={CHIP_CLS}
                          onClick={() => wb.sendProxyCaptureToRepeater(sel())}
                        >
                          Enviar p/ Repeater
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
                      class="max-h-44 overflow-auto rounded bg-v2-background-bg-base p-2 font-mono text-[11px] text-v2-text-text-base select-text"
                      data-scrollable
                    >
                      {`=== REQUEST HEADERS ===\n${JSON.stringify(sel().requestHeaders, null, 2)}\n${
                        sel().requestBody ? `\n=== REQUEST BODY ===\n${sel().requestBody}\n` : ""
                      }\n=== RESPONSE BODY ===\n${sel().responseBody || "(vazio)"}`}
                    </pre>
                  </div>
                )}
              </Show>
            </div>
          )
        })()}
      </Match>

      {/* 3. HTTP SECURITY HEADERS */}
      <Match when={toolId() === "http-headers"}>
        {(() => {
          const d = () => wb.drafts["http-headers"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-[110px_minmax(0,1fr)] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Método</label>
                  <select
                    value={d().method}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("http-headers", (p) => ({
                        ...p,
                        method: e.currentTarget.value as "GET" | "HEAD",
                      }))
                    }
                  >
                    <option value="GET">GET</option>
                    <option value="HEAD">HEAD</option>
                  </select>
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>URL Alvo</label>
                  <input
                    type="text"
                    value={d().url}
                    placeholder="http://127.0.0.1:4096"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("http-headers", (p) => ({ ...p, url: e.currentTarget.value }))}
                  />
                </div>
              </div>
              <div class="grid grid-cols-3 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Timeout (100–15000 ms)</label>
                  <input
                    type="number"
                    min={100}
                    max={15000}
                    value={d().timeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-headers", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Bytes (256–65536)</label>
                  <input
                    type="number"
                    min={256}
                    max={65536}
                    value={d().maxBodyBytes}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-headers", (p) => ({ ...p, maxBodyBytes: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Governança</label>
                  <select
                    value={d().executionMode}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("http-headers", (p) => ({
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
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("http-headers", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("http-headers", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("http-headers")}
                >
                  {isRunning() ? "Inspecionando..." : "Auditar Headers, Cookies & CORS"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("http-headers")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 4. WEB SURFACE SCANNER */}
      <Match when={toolId() === "web-surface"}>
        {(() => {
          const d = () => wb.drafts["web-surface"]
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Base URL Alvo</label>
                <input
                  type="text"
                  value={d().baseUrl}
                  placeholder="http://127.0.0.1:4096"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("web-surface", (p) => ({ ...p, baseUrl: e.currentTarget.value }))}
                />
              </div>
              <div class="flex flex-col gap-1.5">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <label class={LABEL_CLS}>Rotas / Templates Customizados (até 25, 1 por linha — vazio usa lista padrão)</label>
                  <div class="flex flex-wrap gap-1">
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() =>
                        wb.updateDraft("web-surface", (p) => ({
                          ...p,
                          customPathsText: "/openapi.json\n/swagger.json\n/graphql\n/api/health\n/api/info\n/metrics",
                        }))
                      }
                    >
                      Preset API/Swagger
                    </button>
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() =>
                        wb.updateDraft("web-surface", (p) => ({
                          ...p,
                          customPathsText: "/robots.txt\n/.well-known/security.txt\n/admin\n/login\n/config.json\n/actuator/health",
                        }))
                      }
                    >
                      Preset Admin/Config
                    </button>
                  </div>
                </div>
                <textarea
                  rows={5}
                  value={d().customPathsText}
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("web-surface", (p) => ({ ...p, customPathsText: e.currentTarget.value }))
                  }
                />
              </div>
              <div class="grid grid-cols-3 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Concorrência (1–4)</label>
                  <input
                    type="number"
                    min={1}
                    max={4}
                    value={d().concurrency}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("web-surface", (p) => ({ ...p, concurrency: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Timeout (200–15000 ms)</label>
                  <input
                    type="number"
                    min={200}
                    max={15000}
                    value={d().timeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("web-surface", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Governança</label>
                  <select
                    value={d().executionMode}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("web-surface", (p) => ({
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
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("web-surface", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("web-surface", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("web-surface")}
                >
                  {isRunning() ? "Escaneando..." : "Executar Web Surface Discovery"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("web-surface")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 5. NUCLEI */}
      <Match when={toolId() === "nuclei"}>
        {(() => {
          const d = () => wb.drafts.nuclei
          const toggleTag = (tag: string) => {
            const parts = d()
              .tags.split(",")
              .map((s) => s.trim())
              .filter(Boolean)
            const next = parts.includes(tag) ? parts.filter((x) => x !== tag) : [...parts, tag]
            wb.updateDraft("nuclei", (p) => ({ ...p, tags: next.join(",") }))
          }
          return (
            <div class="flex flex-col gap-3">
              <ExternalBinaryBadge wb={wb} toolId="nuclei" />
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>URL Alvo</label>
                <input
                  type="text"
                  value={d().url}
                  placeholder="http://127.0.0.1:8080"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("nuclei", (p) => ({ ...p, url: e.currentTarget.value }))}
                />
              </div>
              <div class="flex flex-col gap-1.5">
                <label class={LABEL_CLS}>Tags de Templates Nuclei (separadas por vírgula)</label>
                <div class="flex flex-wrap gap-1">
                  <For each={["cve", "misconfig", "exposure", "tech", "panel", "default-login", "token"]}>
                    {(tag) => (
                      <button type="button" class={CHIP_CLS} onClick={() => toggleTag(tag)}>
                        + {tag}
                      </button>
                    )}
                  </For>
                </div>
                <input
                  type="text"
                  value={d().tags}
                  placeholder="misconfig,exposure,tech"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("nuclei", (p) => ({ ...p, tags: e.currentTarget.value }))}
                />
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Rate Limit (1–50 req/s)</label>
                  <input
                    type="number"
                    min={1}
                    max={50}
                    value={d().rateLimit}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("nuclei", (p) => ({ ...p, rateLimit: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Governança (Risco Moderado)</label>
                  <select
                    value={d().executionMode}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("nuclei", (p) => ({
                        ...p,
                        executionMode: e.currentTarget.value as "manual" | "proposed",
                      }))
                    }
                  >
                    <option value="manual">Manual Governado</option>
                    <option value="proposed">Proposto</option>
                  </select>
                </div>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("nuclei", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("nuclei", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("nuclei")}
                >
                  {isRunning() ? "Executando Nuclei..." : "Iniciar Scan Nuclei"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("nuclei")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 6. FFUF */}
      <Match when={toolId() === "ffuf"}>
        {(() => {
          const d = () => wb.drafts.ffuf
          return (
            <div class="flex flex-col gap-3">
              <ExternalBinaryBadge wb={wb} toolId="ffuf" />
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Base URL Alvo</label>
                <input
                  type="text"
                  value={d().baseUrl}
                  placeholder="http://127.0.0.1:8080"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("ffuf", (p) => ({ ...p, baseUrl: e.currentTarget.value }))}
                />
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Wordlist (caminho dentro do projeto)</label>
                  <input
                    type="text"
                    value={d().wordlistPath}
                    placeholder="wordlist.txt"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("ffuf", (p) => ({ ...p, wordlistPath: e.currentTarget.value }))}
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Rate Limit (1–25 req/s)</label>
                  <input
                    type="number"
                    min={1}
                    max={25}
                    value={d().rateLimit}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("ffuf", (p) => ({ ...p, rateLimit: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("ffuf", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("ffuf", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("ffuf")}
                >
                  {isRunning() ? "Executando ffuf..." : "Iniciar Fuzzing ffuf"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("ffuf")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 7. DECODER / JWT / SEQUENCER */}
      <Match when={toolId() === "decoder-jwt"}>
        {(() => {
          const d = () => wb.drafts["decoder-jwt"]
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Valor de Entrada / Token JWT (até 64 KB)</label>
                <textarea
                  rows={3}
                  value={d().value}
                  placeholder="Cole Base64, URL-encoded, Hex ou um token JWT..."
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("decoder-jwt", (p) => ({ ...p, value: e.currentTarget.value }))}
                />
              </div>

              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2.5 flex flex-col gap-2">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <span class={LABEL_CLS}>Pipeline Encadeada de Transformações ({d().transforms.length}/16 passos)</span>
                  <button
                    type="button"
                    class={CHIP_CLS}
                    onClick={() => wb.updateDraft("decoder-jwt", (p) => ({ ...p, transforms: [] }))}
                  >
                    Limpar Pipeline
                  </button>
                </div>
                <div class="flex flex-wrap gap-1">
                  <For each={DECODER_STEPS}>
                    {(step) => (
                      <button
                        type="button"
                        class={CHIP_CLS}
                        onClick={() =>
                          wb.updateDraft("decoder-jwt", (p) => ({
                            ...p,
                            transforms: p.transforms.length < 16 ? [...p.transforms, step.id] : p.transforms,
                          }))
                        }
                      >
                        + {step.label}
                      </button>
                    )}
                  </For>
                </div>
                <Show when={d().transforms.length > 0}>
                  <div class="flex flex-wrap items-center gap-1.5 pt-1">
                    <For each={d().transforms}>
                      {(step, idx) => (
                        <span class="inline-flex items-center gap-1 rounded bg-emerald-600/15 border border-emerald-600/40 px-2 py-0.5 font-mono text-[11px] text-v2-text-text-strong">
                          <span>
                            {idx() + 1}. {step}
                          </span>
                          <button
                            type="button"
                            class="text-v2-text-text-muted hover:text-red-500 cursor-pointer"
                            onClick={() =>
                              wb.updateDraft("decoder-jwt", (p) => ({
                                ...p,
                                transforms: p.transforms.filter((_, i) => i !== idx()),
                              }))
                            }
                          >
                            ×
                          </button>
                        </span>
                      )}
                    </For>
                  </div>
                </Show>
              </div>

              <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                <input
                  type="checkbox"
                  checked={d().inspectJwt}
                  onChange={(e) =>
                    wb.updateDraft("decoder-jwt", (p) => ({ ...p, inspectJwt: e.currentTarget.checked }))
                  }
                />
                <span>Inspecionar estrutura JWT (Header, Claims, Expiração e vulnerabilidade alg:none)</span>
              </label>

              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>
                  Token Entropy Sequencer — Amostras de Session IDs / Tokens (opcional, 1 por linha, até 500)
                </label>
                <textarea
                  rows={3}
                  value={d().tokenSamplesText}
                  placeholder={"a9f18c7d4e20b11983fa9012bc7788e1\nf4029d81bc77201948ea661209bc4410"}
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("decoder-jwt", (p) => ({ ...p, tokenSamplesText: e.currentTarget.value }))
                  }
                />
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("decoder-jwt", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("decoder-jwt", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("decoder-jwt")}
                >
                  {isRunning() ? "Processando..." : "Executar Decoder / JWT / Sequencer"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("decoder-jwt")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 8. TLS INSPECTOR */}
      <Match when={toolId() === "tls-inspector"}>
        {(() => {
          const d = () => wb.drafts["tls-inspector"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-[minmax(0,1fr)_120px] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Host / IP Alvo</label>
                  <input
                    type="text"
                    value={d().host}
                    placeholder="127.0.0.1"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("tls-inspector", (p) => ({ ...p, host: e.currentTarget.value }))}
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Porta TLS</label>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={d().port}
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("tls-inspector", (p) => ({ ...p, port: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>
              <div class="flex flex-wrap gap-1">
                <For each={[443, 8443, 9443, 465, 993, 636]}>
                  {(pNum) => (
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() => wb.updateDraft("tls-inspector", (p) => ({ ...p, port: pNum }))}
                    >
                      Porta {pNum}
                    </button>
                  )}
                </For>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>SNI ServerName Override (opcional)</label>
                  <input
                    type="text"
                    value={d().servername}
                    placeholder="ex.: api.interno.local"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("tls-inspector", (p) => ({ ...p, servername: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Timeout (200–10000 ms)</label>
                  <input
                    type="number"
                    min={200}
                    max={10000}
                    value={d().timeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("tls-inspector", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("tls-inspector", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("tls-inspector", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("tls-inspector")}
                >
                  {isRunning() ? "Negociando TLS..." : "Inspecionar Certificado TLS / X.509"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("tls-inspector")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 9. TCP PROBE */}
      <Match when={toolId() === "tcp-probe"}>
        {(() => {
          const d = () => wb.drafts["tcp-probe"]
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Host / IP Alvo</label>
                <input
                  type="text"
                  value={d().host}
                  placeholder="127.0.0.1"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("tcp-probe", (p) => ({ ...p, host: e.currentTarget.value }))}
                />
              </div>

              <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                <input
                  type="checkbox"
                  checked={d().useMultiPort}
                  onChange={(e) =>
                    wb.updateDraft("tcp-probe", (p) => ({ ...p, useMultiPort: e.currentTarget.checked }))
                  }
                />
                <span>Modo Multi-Portas Sequencial (testar várias portas em sequência e consolidar resultado)</span>
              </label>

              <Show
                when={d().useMultiPort}
                fallback={
                  <div class="flex flex-col gap-1.5">
                    <label class={LABEL_CLS}>Porta TCP (1–65535)</label>
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={d().port}
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("tcp-probe", (p) => ({ ...p, port: Number(e.currentTarget.value) }))
                      }
                    />
                    <div class="flex flex-wrap gap-1">
                      <For each={[21, 22, 80, 443, 3306, 4096, 5432, 6379, 8080, 8788]}>
                        {(pNum) => (
                          <button
                            type="button"
                            class={CHIP_CLS}
                            onClick={() => wb.updateDraft("tcp-probe", (p) => ({ ...p, port: pNum }))}
                          >
                            {pNum}
                          </button>
                        )}
                      </For>
                    </div>
                  </div>
                }
              >
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Lista de Portas TCP (até 25 portas separadas por vírgula)</label>
                  <input
                    type="text"
                    value={d().multiPortList}
                    placeholder="22,80,443,4096,8080,8788,8789,8790,8791"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("tcp-probe", (p) => ({ ...p, multiPortList: e.currentTarget.value }))
                    }
                  />
                </div>
              </Show>

              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Connect Timeout (100–5000 ms)</label>
                  <input
                    type="number"
                    min={100}
                    max={5000}
                    value={d().connectTimeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("tcp-probe", (p) => ({ ...p, connectTimeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Espera de Banner (20–1000 ms)</label>
                  <input
                    type="number"
                    min={20}
                    max={1000}
                    value={d().bannerWaitMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("tcp-probe", (p) => ({ ...p, bannerWaitMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("tcp-probe", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("tcp-probe", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("tcp-probe")}
                >
                  {isRunning() ? "Sondando TCP..." : "Executar Sonda TCP & Banner"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("tcp-probe")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 10. NMAP */}
      <Match when={toolId() === "nmap"}>
        {(() => {
          const d = () => wb.drafts.nmap
          return (
            <div class="flex flex-col gap-3">
              <ExternalBinaryBadge wb={wb} toolId="nmap" />
              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Host / IP Alvo</label>
                  <input
                    type="text"
                    value={d().host}
                    placeholder="127.0.0.1"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("nmap", (p) => ({ ...p, host: e.currentTarget.value }))}
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Portas / Faixas (ex.: 22,80,443,8000-8100)</label>
                  <input
                    type="text"
                    value={d().ports}
                    placeholder="22,80,443,4096,8080"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("nmap", (p) => ({ ...p, ports: e.currentTarget.value }))}
                  />
                </div>
              </div>
              <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                <input
                  type="checkbox"
                  checked={d().serviceVersion}
                  onChange={(e) =>
                    wb.updateDraft("nmap", (p) => ({ ...p, serviceVersion: e.currentTarget.checked }))
                  }
                />
                <span>Detectar versão de serviços ativos (-sV)</span>
              </label>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("nmap", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("nmap", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("nmap")}
                >
                  {isRunning() ? "Executando Nmap..." : "Iniciar Scan Nmap"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("nmap")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 11. PCAP ANALYZER */}
      <Match when={toolId() === "pcap-analyzer"}>
        {(() => {
          const d = () => wb.drafts["pcap-analyzer"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-[minmax(0,1fr)_160px] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Arquivo .pcap dentro do Projeto</label>
                  <input
                    type="text"
                    value={d().pcapPath}
                    placeholder="captura.pcap"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("pcap-analyzer", (p) => ({ ...p, pcapPath: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Pacotes (1–50000)</label>
                  <input
                    type="number"
                    min={1}
                    max={50000}
                    value={d().maxPackets}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("pcap-analyzer", (p) => ({ ...p, maxPackets: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("pcap-analyzer", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("pcap-analyzer", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("pcap-analyzer")}
                >
                  {isRunning() ? "Dissecando .pcap..." : "Analisar Captura .pcap (Nativo)"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("pcap-analyzer")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 12. TSHARK */}
      <Match when={toolId() === "tshark"}>
        {(() => {
          const d = () => wb.drafts.tshark
          return (
            <div class="flex flex-col gap-3">
              <ExternalBinaryBadge wb={wb} toolId="tshark" />
              <div class="grid grid-cols-[minmax(0,1fr)_160px] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Arquivo .pcap dentro do Projeto</label>
                  <input
                    type="text"
                    value={d().pcapPath}
                    placeholder="captura.pcap"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("tshark", (p) => ({ ...p, pcapPath: e.currentTarget.value }))}
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Pacotes (1–5000)</label>
                  <input
                    type="number"
                    min={1}
                    max={5000}
                    value={d().maxPackets}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("tshark", (p) => ({ ...p, maxPackets: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("tshark", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("tshark", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("tshark")}
                >
                  {isRunning() ? "Executando tshark..." : "Dissecar com Wireshark tshark"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("tshark")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 13. WORKSPACE AUDIT */}
      <Match when={toolId() === "workspace-audit"}>
        {(() => {
          const d = () => wb.drafts["workspace-audit"]
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1.5">
                <label class={LABEL_CLS}>Subpasta ou Arquivo dentro do Projeto</label>
                <input
                  type="text"
                  value={d().subpath}
                  placeholder="cyberlab"
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("workspace-audit", (p) => ({ ...p, subpath: e.currentTarget.value }))
                  }
                />
                <div class="flex flex-wrap gap-1">
                  <For each={[".", "cyberlab", "integrations", "packages", "script", "config"]}>
                    {(folder) => (
                      <button
                        type="button"
                        class={CHIP_CLS}
                        onClick={() => wb.updateDraft("workspace-audit", (p) => ({ ...p, subpath: folder }))}
                      >
                        {folder}
                      </button>
                    )}
                  </For>
                </div>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Arquivos (1–500)</label>
                  <input
                    type="number"
                    min={1}
                    max={500}
                    value={d().maxFiles}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("workspace-audit", (p) => ({ ...p, maxFiles: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Tamanho Máx por Arquivo (bytes, até 1 MiB)</label>
                  <input
                    type="number"
                    min={1024}
                    max={1048576}
                    value={d().maxFileBytes}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("workspace-audit", (p) => ({ ...p, maxFileBytes: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("workspace-audit", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("workspace-audit", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("workspace-audit")}
                >
                  {isRunning() ? "Auditando..." : "Executar Auditoria Estática de Código & Segredos"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("workspace-audit")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 14. BINARY TRIAGE */}
      <Match when={toolId() === "binary-triage"}>
        {(() => {
          const d = () => wb.drafts["binary-triage"]
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Caminho do Binário ELF / PE (.exe/.dll) / Mach-O no Projeto</label>
                <input
                  type="text"
                  value={d().binaryPath}
                  placeholder="amostra.elf ou binario.exe"
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("binary-triage", (p) => ({ ...p, binaryPath: e.currentTarget.value }))
                  }
                />
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Tamanho Mínimo de Strings (4–64)</label>
                  <input
                    type="number"
                    min={4}
                    max={64}
                    value={d().minStringLength}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("binary-triage", (p) => ({
                        ...p,
                        minStringLength: Number(e.currentTarget.value),
                      }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Strings Extraídas (10–500)</label>
                  <input
                    type="number"
                    min={10}
                    max={500}
                    value={d().maxStrings}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("binary-triage", (p) => ({ ...p, maxStrings: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("binary-triage", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("binary-triage", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("binary-triage")}
                >
                  {isRunning() ? "Analisando Binário..." : "Executar Triagem Reversa Offline"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("binary-triage")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 15. MOBILE TRIAGE */}
      <Match when={toolId() === "mobile-triage"}>
        {(() => {
          const d = () => wb.drafts["mobile-triage"]
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Caminho do Pacote Mobile (.apk / .ipa / .zip) no Projeto</label>
                <input
                  type="text"
                  value={d().artifactPath}
                  placeholder="aplicativo.apk"
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("mobile-triage", (p) => ({ ...p, artifactPath: e.currentTarget.value }))
                  }
                />
              </div>
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Domínios / Indicadores IoC para Cruzamento (opcional, até 200)</label>
                <textarea
                  rows={3}
                  value={d().iocDomainsText}
                  placeholder={"c2.exemplo.org\ntelemetry-suspect.net"}
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("mobile-triage", (p) => ({ ...p, iocDomainsText: e.currentTarget.value }))
                  }
                />
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("mobile-triage", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("mobile-triage", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("mobile-triage")}
                >
                  {isRunning() ? "Analisando Pacote..." : "Executar Forense Mobile (.apk/.ipa)"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("mobile-triage")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 16. HUB MULTI-CDI */}
      <Match when={toolId() === "cdi-hub"}>
        {(() => {
          const d = () => wb.drafts["cdi-hub"]
          const partners = () => wb.backend.partners?.partners ?? []
          const togglePartner = (id: string) => {
            const cur = d().selectedPartnerIds
            const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]
            wb.updateDraft("cdi-hub", (p) => ({ ...p, selectedPartnerIds: next }))
          }
          const toggleEv = (evId: string) => {
            const cur = d().selectedEvidenceIds
            const next = cur.includes(evId) ? cur.filter((x) => x !== evId) : [...cur, evId]
            wb.updateDraft("cdi-hub", (p) => ({ ...p, selectedEvidenceIds: next }))
          }

          return (
            <div class="flex flex-col gap-3">
              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2.5 flex flex-col gap-2">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <span class={LABEL_CLS}>
                    Agentes CDI Registrados ({partners().length}) — Secret:{" "}
                    {wb.backend.partners?.secretConfigured
                      ? wb.backend.partners.secretPreview
                      : "NÃO CONFIGURADO"}
                  </span>
                  <div class="flex flex-wrap items-center gap-1.5">
                    <button type="button" class={CHIP_CLS} onClick={() => void wb.loadFourCdiPreset()}>
                      Preset 4 CDIs (8788–8791)
                    </button>
                    <button type="button" class={CHIP_CLS} onClick={() => void wb.manageCdiSecret("generate")}>
                      Gerar Secret 256-bit
                    </button>
                    <button type="button" class={CHIP_CLS} onClick={() => void wb.manageCdiSecret("reveal")}>
                      Revelar Secret
                    </button>
                  </div>
                </div>

                <Show when={wb.backend.revealedSecret}>
                  <div class="rounded bg-v2-background-bg-base p-2 font-mono text-[11px] text-emerald-500 select-text break-all">
                    $env:CYBERLAB_PARTNER_SECRET="{wb.backend.revealedSecret}"{"\n"}
                    $env:CYBERLAB_CALLBACK_URL="{wb.backend.partners?.cyberlabCallbackUrl || "http://127.0.0.1:4096/api/cyberlab/partner-gateway"}"
                  </div>
                </Show>

                <div class="flex items-center gap-1.5">
                  <input
                    type="text"
                    value={d().customSecretInput}
                    placeholder="Ou defina seu próprio CYBERLAB_PARTNER_SECRET (mín. 16 caracteres)..."
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("cdi-hub", (p) => ({ ...p, customSecretInput: e.currentTarget.value }))
                    }
                  />
                  <button type="button" class={BTN_SECONDARY} onClick={() => void wb.manageCdiSecret("set")}>
                    Salvar Secret
                  </button>
                </div>

                <Show
                  when={partners().length > 0}
                  fallback={
                    <div class="text-[12px] text-v2-text-text-muted">
                      Clique em <strong>Preset 4 CDIs (8788–8791)</strong> acima para registrar Salem, Kairós, Naia e CDI-04.
                    </div>
                  }
                >
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1">
                    <For each={partners()}>
                      {(partner) => (
                        <label class="flex items-start gap-2 rounded border border-v2-border-border-base bg-v2-background-bg-base p-2 text-[12px] cursor-pointer">
                          <input
                            type="checkbox"
                            checked={d().selectedPartnerIds.includes(partner.partnerId)}
                            onChange={() => togglePartner(partner.partnerId)}
                          />
                          <div class="flex flex-col min-w-0">
                            <span class="font-medium text-v2-text-text-strong">
                              {partner.displayName} ({partner.partnerId})
                            </span>
                            <span class="font-mono text-[11px] text-v2-text-text-muted truncate">
                              {partner.endpointUrl}
                            </span>
                          </div>
                        </label>
                      )}
                    </For>
                  </div>
                </Show>
              </div>

              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Objetivo da Missão para os CDIs Selecionados</label>
                <input
                  type="text"
                  value={d().objective}
                  class={INPUT_CLS}
                  onInput={(e) => wb.updateDraft("cdi-hub", (p) => ({ ...p, objective: e.currentTarget.value }))}
                />
              </div>

              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Contexto / Instruções Detalhadas (redigido automaticamente antes do envio)</label>
                <textarea
                  rows={3}
                  value={d().contextText}
                  placeholder="Descreva a hipótese, endpoint ou contexto para análise especialista ou paralela..."
                  class={INPUT_CLS}
                  onInput={(e) => wb.updateDraft("cdi-hub", (p) => ({ ...p, contextText: e.currentTarget.value }))}
                />
              </div>

              <Show when={wb.backend.evidence.length > 0}>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Anexar Evidências SHA-256 do Projeto ({d().selectedEvidenceIds.length})</label>
                  <div class="max-h-28 overflow-y-auto rounded border border-v2-border-border-base p-2 flex flex-col gap-1" data-scrollable>
                    <For each={wb.backend.evidence.slice(0, 15)}>
                      {(ev) => (
                        <label class="flex items-center gap-2 text-[11px] cursor-pointer">
                          <input
                            type="checkbox"
                            checked={d().selectedEvidenceIds.includes(ev.evidenceId)}
                            onChange={() => toggleEv(ev.evidenceId)}
                          />
                          <span class="truncate text-v2-text-text-strong">{ev.title}</span>
                          <span class="font-mono text-v2-text-text-muted">({ev.sha256.slice(0, 10)}…)</span>
                        </label>
                      )}
                    </For>
                  </div>
                </div>
              </Show>

              <div class="flex items-center gap-2">
                <div class="w-44">
                  <label class={LABEL_CLS}>Timeout (ms)</label>
                  <input
                    type="number"
                    min={1000}
                    max={120000}
                    value={d().timeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("cdi-hub", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="pt-4 flex items-center gap-2">
                  <button
                    type="button"
                    disabled={isRunning()}
                    class={BTN_PRIMARY}
                    onClick={() => void wb.dispatchCdiMission()}
                  >
                    {isRunning()
                      ? "Consultando CDIs..."
                      : d().selectedPartnerIds.length > 1
                        ? `Disparar em Paralelo (${d().selectedPartnerIds.length} CDIs)`
                        : "Enviar Tarefa ao CDI"}
                  </button>
                </div>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 17. EXTERNAL INGEST & INBOX */}
      <Match when={toolId() === "external-ingest"}>
        {(() => {
          const d = () => wb.drafts["external-ingest"]
          return (
            <div class="flex flex-col gap-3">
              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2.5 flex flex-wrap items-center justify-between gap-2">
                <div class="text-[12px]">
                  <strong class="text-v2-text-text-strong">Drop-Folder .cyberlab/inbox:</strong>{" "}
                  <span class="text-v2-text-text-muted">
                    {wb.backend.external?.pendingInboxCount ?? 0} arquivo(s) pendente(s)
                  </span>
                </div>
                <button type="button" class={BTN_SECONDARY} onClick={() => void wb.syncExternalInbox()}>
                  Sincronizar .cyberlab/inbox Agora
                </button>
              </div>

              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Ferramenta de Origem</label>
                  <select
                    value={d().toolId}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("external-ingest", (p) => ({ ...p, toolId: e.currentTarget.value }))
                    }
                  >
                    <option value="opentrap">OpenTRAP (HTTP Replay / ZAP)</option>
                    <option value="burp">Burp Suite</option>
                    <option value="wireshark">Wireshark / tshark</option>
                    <option value="nmap">Nmap</option>
                    <option value="nuclei">Nuclei</option>
                    <option value="ffuf">ffuf</option>
                    <option value="ghidra">Ghidra</option>
                    <option value="mvt">MVT (Mobile Verification Toolkit)</option>
                    <option value="custom">Outra Ferramenta Externa</option>
                  </select>
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Alvo Avaliado (validado contra o Escopo)</label>
                  <input
                    type="text"
                    value={d().target}
                    placeholder="http://127.0.0.1:8080"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("external-ingest", (p) => ({ ...p, target: e.currentTarget.value }))
                    }
                  />
                </div>
              </div>

              <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Título da Evidência</label>
                  <input
                    type="text"
                    value={d().title}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("external-ingest", (p) => ({ ...p, title: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Carregar Arquivo Local (.txt, .json, .http, .xml)</label>
                  <input
                    type="file"
                    class="text-[12px] text-v2-text-text-muted"
                    onChange={(e) => {
                      const file = e.currentTarget.files?.[0]
                      if (!file) return
                      void file.text().then((txt) => {
                        wb.updateDraft("external-ingest", (p) => ({
                          ...p,
                          title: p.title || file.name,
                          rawOutput: txt,
                        }))
                      })
                    }}
                  />
                </div>
              </div>

              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Saída Bruta da Ferramenta Externa (credenciais serão redigidas + SHA-256)</label>
                <textarea
                  rows={5}
                  value={d().rawOutput}
                  placeholder="Cole aqui a saída exportada do OpenTRAP, Burp, Nmap, Wireshark, Ghidra..."
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("external-ingest", (p) => ({ ...p, rawOutput: e.currentTarget.value }))
                  }
                />
              </div>

              <div class="flex items-center gap-2">
                <button type="button" class={BTN_PRIMARY} onClick={() => void wb.ingestManualExternal()}>
                  Ingerir & Gravar no Cofre SHA-256
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 18. SCOPE, APPROVALS, EVIDENCE, FINDINGS & REPORT */}
      <Match when={toolId() === "scope-governance"}>
        {(() => {
          const d = () => wb.drafts["scope-governance"]
          const scope = () => wb.backend.status?.activeScope

          const addScopeRule = () => {
            const val = d().newRuleValue.trim()
            if (!val || !scope()) return
            const rule = {
              kind: d().newRuleKind,
              value: val,
              ...(d().newRuleNotes.trim() ? { notes: d().newRuleNotes.trim() } : {}),
            }
            if (d().newRuleBlocked) {
              void wb.updateScopeRules({ blockedTargets: [...(scope()?.blockedTargets ?? []), rule] })
            } else {
              void wb.updateScopeRules({ allowedTargets: [...(scope()?.allowedTargets ?? []), rule] })
            }
            wb.updateDraft("scope-governance", (p) => ({ ...p, newRuleValue: "", newRuleNotes: "" }))
          }

          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-wrap gap-1 border-b border-v2-border-border-base pb-2">
                <For
                  each={[
                    { id: "scope", label: "Escopo de Alvos" },
                    { id: "approvals", label: `Aprovações (${wb.backend.approvals.length})` },
                    { id: "evidence", label: `Evidências SHA-256 (${wb.backend.evidence.length})` },
                    { id: "findings", label: `Findings (${wb.backend.findings.length})` },
                    { id: "report", label: "Relatório .md" },
                  ] as const}
                >
                  {(tab) => (
                    <button
                      type="button"
                      class={`rounded-md px-2.5 py-1 text-[12px] font-medium cursor-pointer ${
                        d().subTab === tab.id
                          ? "bg-emerald-600 text-white"
                          : "bg-v2-background-bg-deep text-v2-text-text-base"
                      }`}
                      onClick={() => wb.updateDraft("scope-governance", (p) => ({ ...p, subTab: tab.id }))}
                    >
                      {tab.label}
                    </button>
                  )}
                </For>
              </div>

              <Show when={d().subTab === "scope"}>
                <div class="flex flex-col gap-2.5">
                  <label class="flex items-center justify-between gap-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2.5 text-[12px] cursor-pointer">
                    <span>
                      <strong class="text-v2-text-text-strong">Liberar Alvos Externos (LAN / Lab Remoto / Internet Autorizada)</strong>
                      <span class="block text-[11px] text-v2-text-text-muted">
                        Quando desmarcado, apenas 127.0.0.1 / localhost e arquivos do projeto são permitidos.
                      </span>
                    </span>
                    <input
                      type="checkbox"
                      checked={Boolean(scope()?.allowExternalTargets)}
                      onChange={(e) => void wb.updateScopeRules({ allowExternalTargets: e.currentTarget.checked })}
                    />
                  </label>

                  <div class="grid grid-cols-[120px_minmax(0,1fr)_auto] gap-1.5">
                    <select
                      value={d().newRuleKind}
                      class={INPUT_CLS}
                      onChange={(e) =>
                        wb.updateDraft("scope-governance", (p) => ({
                          ...p,
                          newRuleKind: e.currentTarget.value as typeof p.newRuleKind,
                        }))
                      }
                    >
                      <option value="url_origin">URL Origin</option>
                      <option value="domain">Domínio</option>
                      <option value="ip">IP</option>
                      <option value="cidr">CIDR</option>
                      <option value="workspace_path">Pasta</option>
                    </select>
                    <input
                      type="text"
                      value={d().newRuleValue}
                      placeholder="ex.: https://meu-lab.local:8443 ou 192.168.1.0/24"
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("scope-governance", (p) => ({ ...p, newRuleValue: e.currentTarget.value }))
                      }
                    />
                    <button type="button" class={BTN_PRIMARY} onClick={addScopeRule}>
                      + Regra
                    </button>
                  </div>

                  <div class="flex flex-col gap-1 max-h-44 overflow-y-auto" data-scrollable>
                    <For each={scope()?.allowedTargets ?? []}>
                      {(rule, idx) => (
                        <div class="flex items-center justify-between rounded border border-v2-border-border-base bg-v2-background-bg-deep/40 px-2.5 py-1 text-[12px]">
                          <span class="font-mono">
                            [{rule.kind}] {rule.value}
                          </span>
                          <button
                            type="button"
                            class="text-v2-text-text-muted hover:text-red-500 cursor-pointer"
                            onClick={() =>
                              void wb.updateScopeRules({
                                allowedTargets: (scope()?.allowedTargets ?? []).filter((_, i) => i !== idx()),
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
              </Show>

              <Show when={d().subTab === "approvals"}>
                <div class="flex flex-col gap-2">
                  <Show
                    when={wb.backend.approvals.length > 0}
                    fallback={
                      <div class="p-3 text-[12px] text-v2-text-text-muted">Nenhuma aprovação humana pendente.</div>
                    }
                  >
                    <For each={wb.backend.approvals}>
                      {(ticket) => (
                        <div class="flex flex-wrap items-center justify-between gap-2 rounded border border-amber-500/40 bg-amber-500/10 p-2.5 text-[12px]">
                          <div>
                            <div class="font-medium text-v2-text-text-strong">{ticket.capabilityId}</div>
                            <div class="font-mono text-[11px] text-v2-text-text-muted">{ticket.targetSummary}</div>
                          </div>
                          <div class="flex items-center gap-1.5">
                            <button
                              type="button"
                              class={BTN_PRIMARY}
                              onClick={() => void wb.approvePendingExecution(ticket.approvalId)}
                            >
                              Aprovar & Executar
                            </button>
                            <button
                              type="button"
                              class={BTN_SECONDARY}
                              onClick={() => void wb.cancelExecution(ticket.executionId)}
                            >
                              Cancelar
                            </button>
                          </div>
                        </div>
                      )}
                    </For>
                  </Show>
                </div>
              </Show>

              <Show when={d().subTab === "evidence"}>
                <div class="flex flex-col gap-2">
                  <div class="max-h-48 overflow-y-auto flex flex-col gap-1.5" data-scrollable>
                    <For each={wb.backend.evidence}>
                      {(ev) => (
                        <div class="flex flex-wrap items-center justify-between gap-2 rounded border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2 text-[12px]">
                          <div class="min-w-0 flex-1">
                            <div class="truncate font-medium text-v2-text-text-strong">{ev.title}</div>
                            <div class="font-mono text-[11px] text-v2-text-text-muted">
                              SHA-256: {ev.sha256.slice(0, 20)}… · {ev.sizeBytes} B
                            </div>
                          </div>
                          <div class="flex items-center gap-1">
                            <button
                              type="button"
                              class={CHIP_CLS}
                              onClick={() => void wb.inspectEvidenceById(ev.evidenceId)}
                            >
                              Ler Conteúdo
                            </button>
                            <button
                              type="button"
                              class={CHIP_CLS}
                              onClick={() => void wb.verifyEvidenceCustody(ev.evidenceId)}
                            >
                              Verificar SHA-256
                            </button>
                          </div>
                        </div>
                      )}
                    </For>
                  </div>
                  <Show when={wb.backend.inspectedEvidence}>
                    {(inspected) => (
                      <div class="rounded border border-v2-border-border-base bg-v2-background-bg-deep p-2.5 flex flex-col gap-1.5">
                        <div class="flex items-center justify-between">
                          <span class="font-medium text-[12px] text-v2-text-text-strong">{inspected().title}</span>
                          <button
                            type="button"
                            class={CHIP_CLS}
                            onClick={() =>
                              wb.attachToComposer(
                                inspected().title,
                                `SHA-256: ${inspected().sha256}\n\n${inspected().text}`,
                                `${inspected().evidenceId}.txt`,
                              )
                            }
                          >
                            Anexar na Caixa de Diálogo
                          </button>
                        </div>
                        <pre
                          class="max-h-48 overflow-auto rounded bg-v2-background-bg-base p-2 font-mono text-[11px] select-text"
                          data-scrollable
                        >
                          {inspected().text}
                        </pre>
                      </div>
                    )}
                  </Show>
                </div>
              </Show>

              <Show when={d().subTab === "findings"}>
                <div class="flex flex-col gap-2.5">
                  <div class="grid grid-cols-[minmax(0,1fr)_120px] gap-2">
                    <input
                      type="text"
                      placeholder="Título do Finding (ex.: Cookie de sessão sem HttpOnly)"
                      value={d().findingTitle}
                      class={INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("scope-governance", (p) => ({ ...p, findingTitle: e.currentTarget.value }))
                      }
                    />
                    <select
                      value={d().findingSeverity}
                      class={INPUT_CLS}
                      onChange={(e) =>
                        wb.updateDraft("scope-governance", (p) => ({
                          ...p,
                          findingSeverity: e.currentTarget.value as typeof p.findingSeverity,
                        }))
                      }
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
                    placeholder="Descrição técnica e impacto..."
                    value={d().findingDescription}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("scope-governance", (p) => ({
                        ...p,
                        findingDescription: e.currentTarget.value,
                      }))
                    }
                  />
                  <button type="button" class={BTN_PRIMARY} onClick={() => void wb.createManualFinding()}>
                    Registrar Finding
                  </button>

                  <div class="max-h-40 overflow-y-auto flex flex-col gap-1.5" data-scrollable>
                    <For each={wb.backend.findings}>
                      {(f) => (
                        <div class="flex flex-wrap items-center justify-between gap-2 rounded border border-v2-border-border-base p-2 text-[12px]">
                          <div>
                            <span class="font-mono uppercase text-[11px]">[{f.severity}]</span>{" "}
                            <strong class="text-v2-text-text-strong">{f.title}</strong>{" "}
                            <span class="text-v2-text-text-muted">({f.status})</span>
                          </div>
                          <div class="flex items-center gap-1">
                            <button
                              type="button"
                              class={CHIP_CLS}
                              onClick={() => void wb.reviewFindingDecision(f.findingId, "confirmed")}
                            >
                              Confirmar
                            </button>
                            <button
                              type="button"
                              class={CHIP_CLS}
                              onClick={() => void wb.reviewFindingDecision(f.findingId, "rejected")}
                            >
                              Rejeitar
                            </button>
                          </div>
                        </div>
                      )}
                    </For>
                  </div>
                </div>
              </Show>

              <Show when={d().subTab === "report"}>
                <div class="flex flex-col gap-2">
                  <div class="flex flex-wrap items-center gap-2">
                    <button type="button" class={BTN_PRIMARY} onClick={() => void wb.generateReportMarkdown()}>
                      Gerar Relatório Markdown (.md)
                    </button>
                    <Show when={wb.backend.reportMarkdown}>
                      <button
                        type="button"
                        class={BTN_SECONDARY}
                        onClick={() => {
                          const blob = new Blob([wb.backend.reportMarkdown], { type: "text/markdown;charset=utf-8" })
                          const a = document.createElement("a")
                          a.href = URL.createObjectURL(blob)
                          a.download = "relatorio-cyberlab-os.md"
                          a.click()
                        }}
                      >
                        Baixar .md
                      </button>
                      <button
                        type="button"
                        class={BTN_SECONDARY}
                        onClick={() =>
                          wb.attachToComposer(
                            "Relatório CyberLab OS",
                            wb.backend.reportMarkdown,
                            "relatorio-cyberlab.md",
                          )
                        }
                      >
                        Anexar na Caixa de Diálogo
                      </button>
                    </Show>
                  </div>
                  <Show when={wb.backend.reportMarkdown}>
                    <pre
                      class="max-h-56 overflow-auto rounded border border-v2-border-border-base bg-v2-background-bg-deep p-2.5 font-mono text-[11px] select-text"
                      data-scrollable
                    >
                      {wb.backend.reportMarkdown}
                    </pre>
                  </Show>
                </div>
              </Show>
            </div>
          )
        })()}
      </Match>
    </Switch>
  )
}
