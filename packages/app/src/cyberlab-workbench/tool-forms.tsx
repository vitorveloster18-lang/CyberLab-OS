import { For, Match, Show, Switch } from "solid-js"
import { Icon } from "@opencode/ui/icon"
import type { CyberLabWorkbenchService } from "./state"
import type {
  DecoderTransformStep,
  EntropyRecipeOp,
  EntropyRecipeStepRow,
  KeyValueHeaderRow,
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

const ENTROPY_RECIPE_OPS: Array<{ id: EntropyRecipeOp; label: string }> = [
  { id: "from_base64", label: "From Base64" },
  { id: "to_base64", label: "To Base64" },
  { id: "from_hex", label: "From Hex" },
  { id: "to_hex", label: "To Hex" },
  { id: "url_decode", label: "URL Decode" },
  { id: "url_encode", label: "URL Encode" },
  { id: "gunzip", label: "Gunzip (.gz)" },
  { id: "gzip", label: "Gzip Compress" },
  { id: "zlib_inflate", label: "Zlib Inflate" },
  { id: "raw_inflate", label: "Raw Deflate Inflate" },
  { id: "xor_key", label: "XOR com Chave" },
  { id: "xor_single_byte_bruteforce", label: "XOR Brute-Force (1 Byte)" },
  { id: "aes_cbc_decrypt", label: "AES-CBC Decrypt" },
  { id: "aes_gcm_decrypt", label: "AES-GCM Decrypt" },
  { id: "protobuf_raw_decode", label: "Protobuf Raw Wire Decode" },
  { id: "extract_strings", label: "Extract Printable Strings" },
  { id: "sha256", label: "SHA-256 Digest" },
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
                  <div class="flex flex-wrap items-center justify-between gap-1.5">
                    <label class={LABEL_CLS}>URL Alvo (dentro do escopo)</label>
                    <div class="flex flex-wrap items-center gap-1">
                      <button
                        type="button"
                        class={CHIP_CLS}
                        onClick={() => wb.sendUrlAcrossWebSuite(d().url, "headers")}
                      >
                        → Auditar Headers
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
                        → Auditar Parâmetros
                      </button>
                      <button
                        type="button"
                        class={CHIP_CLS}
                        onClick={() => wb.sendUrlAcrossWebSuite(d().url, "scanner")}
                      >
                        → Enviar p/ Scanner
                      </button>
                      <Show when={d().body}>
                        <button
                          type="button"
                          class={CHIP_CLS}
                          onClick={() => wb.sendTextToDecoder(d().body)}
                        >
                          → Corpo p/ Decoder
                        </button>
                      </Show>
                    </div>
                  </div>
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

              <div class="grid grid-cols-1 md:grid-cols-[1fr_auto_auto] items-center gap-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 px-3 py-2">
                <div class="flex flex-col gap-0.5 min-w-0">
                  <span class="text-[11px] font-semibold text-v2-text-text-strong">
                    Inspeção HTTPS (CONNECT) & WebSocket (ws/wss) — Root CA Local ECDSA P-256
                  </span>
                  <span class="font-mono text-[10px] text-v2-text-text-muted truncate">
                    SHA-256: {proxy()?.status.caFingerprintSha256 || "Inicie o Proxy para inicializar .cyberlab/ca/cyberlab-root-ca.pem"}
                  </span>
                </div>
                <select
                  value={proxy()?.status.httpsMode ?? d().httpsMode}
                  class={INPUT_CLS}
                  onChange={(e) => {
                    const mode = e.currentTarget.value as "tls_intercept" | "tunnel_passthrough"
                    wb.updateDraft("http-proxy", (p) => ({ ...p, httpsMode: mode }))
                    if (proxy()?.status.running) void wb.controlProxy("set_https_mode", mode)
                  }}
                >
                  <option value="tls_intercept">HTTPS MITM (Descriptografar c/ Root CA)</option>
                  <option value="tunnel_passthrough">Túnel CONNECT Passthrough (Sem MITM)</option>
                </select>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.downloadProxyRootCaCert()}>
                  Baixar Root CA (.crt)
                </button>
              </div>

              <label class="flex items-center gap-2 text-[11px] text-v2-text-text-muted cursor-pointer">
                <input
                  type="checkbox"
                  checked={d().allowSelfSignedUpstream}
                  onChange={(e) =>
                    wb.updateDraft("http-proxy", (p) => ({ ...p, allowSelfSignedUpstream: e.currentTarget.checked }))
                  }
                />
                <span>Aceitar certificados autoassinados do servidor alvo em laboratório (reinicie o Proxy ao alterar)</span>
              </label>

              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 px-3 py-2 text-[11px] text-v2-text-text-muted flex flex-col gap-1">
                <span>Configure seu navegador/cliente HTTP(S) para usar o proxy local ou teste com a Root CA:</span>
                <code class="font-mono text-v2-text-text-strong select-text">
                  curl --cacert .cyberlab/ca/cyberlab-root-ca.pem -x http://127.0.0.1:{proxy()?.status.listenPort ?? d().port} https://alvo-autorizado/
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
                            <td class="px-2.5 py-1.5 font-mono font-medium">
                              <span class="mr-1 rounded bg-v2-background-bg-base px-1 py-0.5 text-[10px] uppercase text-emerald-500">
                                {item.protocol || "http"}
                              </span>
                              {item.method}
                            </td>
                            <td class="px-2.5 py-1.5 font-mono truncate max-w-[220px]">{item.url}</td>
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
                          onClick={() => wb.sendTextToDecoder(sel().responseBody || sel().requestBody || sel().url)}
                        >
                          → Decoder / JWT
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
              <div class="flex flex-wrap items-center gap-4 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 text-[12px]">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={Boolean(d().deepCipherAudit)}
                    onChange={(e) =>
                      wb.updateDraft("tls-inspector", (p) => ({ ...p, deepCipherAudit: e.currentTarget.checked }))
                    }
                  />
                  <span class="text-v2-text-text-strong">
                    Auditoria Profunda (Matriz TLS 1.0–1.3, Cifras Fracas/CBC, Forward Secrecy ECDHE, RSA & Nota A+..F)
                  </span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={Boolean(d().checkHsts)}
                    onChange={(e) =>
                      wb.updateDraft("tls-inspector", (p) => ({ ...p, checkHsts: e.currentTarget.checked }))
                    }
                  />
                  <span class="text-v2-text-text-strong">Verificar HSTS & Preload HTTPS</span>
                </label>
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

      {/* 16. PARCEIROS COGNITIVOS CDI (KAIRÓS, NAIA, SALEM & NOVA) */}
      <Match when={toolId() === "cdi-hub"}>
        {(() => {
          const d = () => wb.drafts["cdi-hub"]
          const partners = () => wb.backend.partners?.partners ?? []
          const inboundActivity = () => wb.backend.partners?.inboundActivity ?? []
          const gatewayActions = [
            { id: "project.state", desc: "Estado ativo do projeto & pares" },
            { id: "evidence.list", desc: "Listar evidências SHA-256" },
            { id: "evidence.read", desc: "Ler evidência redigida" },
            { id: "workspace.list_files", desc: "Navegar ficheiros no escopo" },
            { id: "workspace.read_file", desc: "Ler ficheiro no escopo" },
            { id: "artifact.create", desc: "Criar relatórios, notas & análises" },
            { id: "finding.propose", desc: "Propor findings de segurança" },
            { id: "action.initiate", desc: "Iniciar execuções autonomamente" },
            { id: "action.status", desc: "Acompanhar estado de execuções" },
          ] as const

          const autonomyLabel = (mode: string) => {
            switch (mode) {
              case "autonomous_in_scope":
                return "Autónomo no Escopo Curado (Par Horizontal)"
              case "allow_readonly_and_low_propose_others":
                return "Autónomo em Read-Only + Low; Curadoria em Moderate"
              case "allow_readonly_propose_others":
                return "Autónomo em Read-Only; Curadoria nas Demais"
              case "propose_only":
                return "Curadoria Conjunta Prévia (Propose Only)"
              case "disabled":
                return "Consulta, Artefactos & Findings (Sem Iniciar Ações)"
              default:
                return mode
            }
          }

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
              <div class="rounded-md border border-emerald-500/30 bg-emerald-500/5 px-3 py-2 text-[12px] text-v2-text-text-base flex flex-wrap items-center justify-between gap-2">
                <div>
                  <strong class="text-emerald-400">Relação Horizontal · Sem Hierarquia:</strong>{" "}
                  <span>
                    Kairós, Naia, Salem e Nova operam como entidades cognitivas autónomas com identidade, memória e decisão própria; o humano atua como{" "}
                    <strong class="text-v2-text-text-strong">curador</strong> do escopo e da investigação partilhada.
                  </span>
                </div>
              </div>

              <Show when={d().cdiSubTab === "setup"}>
                <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-3 flex flex-col gap-3">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <span class={LABEL_CLS}>
                      Parceiros Cognitivos CDI ({partners().length}) — Segredo HMAC:{" "}
                      {wb.backend.partners?.secretConfigured
                        ? wb.backend.partners.secretPreview
                        : "NÃO CONFIGURADO"}
                    </span>
                    <div class="flex flex-wrap items-center gap-1.5">
                      <button type="button" class={CHIP_CLS} onClick={() => void wb.loadFourCdiPreset()}>
                        Restaurar Perfis dos 4 Pares CDI (8788–8791)
                      </button>
                      <button type="button" class={CHIP_CLS} onClick={() => void wb.manageCdiSecret("generate")}>
                        Gerar Secret 256-bit
                      </button>
                      <button type="button" class={CHIP_CLS} onClick={() => void wb.manageCdiSecret("reveal")}>
                        Revelar Variáveis & Comandos
                      </button>
                    </div>
                  </div>

                  <Show when={wb.backend.revealedSecret}>
                    <div class="rounded bg-v2-background-bg-base p-2.5 font-mono text-[11px] text-emerald-500 select-text break-all whitespace-pre-wrap">
                      {`$env:CYBERLAB_PARTNER_SECRET="${wb.backend.revealedSecret}"
$env:CYBERLAB_CALLBACK_URL="${wb.backend.partners?.cyberlabCallbackUrl || "http://127.0.0.1:4096/api/cyberlab/partner-gateway"}"
python integrations/partners/chat_py_bridge.py --port 8788 --partner-id kairos --chat-py "../kairos/chat.py"
python integrations/partners/chat_py_bridge.py --port 8789 --partner-id naia   --chat-py "../naia/chat.py"
python integrations/partners/chat_py_bridge.py --port 8790 --partner-id salem  --chat-py "../salem/chat.py"
python integrations/partners/chat_py_bridge.py --port 8791 --partner-id nova   --chat-py "../nova/chat.py"`}
                    </div>
                  </Show>

                  <div class="flex items-center gap-1.5">
                    <input
                      type="text"
                      value={d().customSecretInput}
                      placeholder="Ou defina um CYBERLAB_PARTNER_SECRET partilhado (mín. 16 caracteres)..."
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("cdi-hub", (p) => ({ ...p, customSecretInput: e.currentTarget.value }))
                      }
                    />
                    <button type="button" class={BTN_SECONDARY} onClick={() => void wb.manageCdiSecret("set")}>
                      Salvar Secret
                    </button>
                  </div>

                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                    <For each={partners()}>
                      {(partner) => (
                        <div class="rounded border border-v2-border-border-base bg-v2-background-bg-base p-2.5 text-[12px] flex flex-col gap-1.5">
                          <div class="flex items-start justify-between gap-2">
                            <div>
                              <div class="font-semibold text-v2-text-text-strong flex items-center gap-1.5 flex-wrap">
                                <span>{partner.displayName}</span>
                                <span class="font-mono text-[11px] text-v2-text-text-muted">({partner.partnerId})</span>
                                <span class="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-400">
                                  Par Autónomo · Sem Hierarquia
                                </span>
                              </div>
                              <div class="text-[11px] text-v2-text-text-base">{partner.specialty}</div>
                            </div>
                            <button
                              type="button"
                              class={CHIP_CLS}
                              onClick={() => wb.openPartnerProfileEditor(partner)}
                            >
                              {d().editingPartnerId === partner.partnerId ? "Fechar" : "Perfil Individual"}
                            </button>
                          </div>

                          <Show when={partner.profile?.identityNotes}>
                            <div class="text-[11px] text-v2-text-text-muted leading-snug">
                              {partner.profile?.identityNotes}
                            </div>
                          </Show>

                          <Show when={(partner.profile?.interests ?? []).length > 0}>
                            <div class="flex flex-wrap gap-1">
                              <For each={partner.profile?.interests ?? []}>
                                {(tag) => (
                                  <span class="rounded bg-v2-background-bg-deep px-1.5 py-0.5 font-mono text-[10px] text-v2-text-text-muted">
                                    #{tag}
                                  </span>
                                )}
                              </For>
                            </div>
                          </Show>

                          <div class="flex flex-wrap items-center justify-between gap-1 pt-0.5 border-t border-v2-border-border-base/60 text-[11px]">
                            <span class="font-mono text-v2-text-text-muted truncate">{partner.endpointUrl}</span>
                            <span class="text-emerald-400 font-medium">
                              {autonomyLabel(partner.permissions.initiateActions)}
                            </span>
                          </div>
                        </div>
                      )}
                    </For>
                  </div>

                  <Show when={Boolean(d().editingPartnerId)}>
                    <div class="rounded-md border border-emerald-500/40 bg-v2-background-bg-base p-3 flex flex-col gap-2.5">
                      <div class="flex items-center justify-between">
                        <span class="text-[12px] font-semibold text-v2-text-text-strong">
                          Editar Perfil Individual do Parceiro CDI ({d().editingPartnerId}) — Sem Hierarquia
                        </span>
                        <button
                          type="button"
                          class={CHIP_CLS}
                          onClick={() => wb.updateDraft("cdi-hub", (p) => ({ ...p, editingPartnerId: "" }))}
                        >
                          Cancelar
                        </button>
                      </div>

                      <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <div>
                          <label class={LABEL_CLS}>Nome / Identidade</label>
                          <input
                            type="text"
                            value={d().editDisplayName ?? ""}
                            class={INPUT_CLS}
                            onInput={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({ ...p, editDisplayName: e.currentTarget.value }))
                            }
                          />
                        </div>
                        <div>
                          <label class={LABEL_CLS}>Domínio / Perspetiva Própria</label>
                          <input
                            type="text"
                            value={d().editSpecialty ?? ""}
                            class={INPUT_CLS}
                            onInput={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({ ...p, editSpecialty: e.currentTarget.value }))
                            }
                          />
                        </div>
                        <div>
                          <label class={LABEL_CLS}>Endpoint do CDI</label>
                          <input
                            type="text"
                            value={d().editEndpointUrl ?? ""}
                            class={MONO_INPUT_CLS}
                            onInput={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({ ...p, editEndpointUrl: e.currentTarget.value }))
                            }
                          />
                        </div>
                      </div>

                      <div>
                        <label class={LABEL_CLS}>Notas de Identidade Cognitiva & Autonomia</label>
                        <textarea
                          rows={2}
                          value={d().editIdentityNotes ?? ""}
                          class={INPUT_CLS}
                          onInput={(e) =>
                            wb.updateDraft("cdi-hub", (p) => ({ ...p, editIdentityNotes: e.currentTarget.value }))
                          }
                        />
                      </div>

                      <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        <div>
                          <label class={LABEL_CLS}>Interesses Investigativos (separados por vírgula)</label>
                          <input
                            type="text"
                            value={d().editInterestsText ?? ""}
                            class={INPUT_CLS}
                            onInput={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({ ...p, editInterestsText: e.currentTarget.value }))
                            }
                          />
                        </div>
                        <div>
                          <label class={LABEL_CLS}>Autonomia para Iniciar Execuções (action.initiate)</label>
                          <select
                            value={d().editInitiateActions ?? "autonomous_in_scope"}
                            class={INPUT_CLS}
                            onChange={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({
                                ...p,
                                editInitiateActions: e.currentTarget.value as typeof p.editInitiateActions,
                              }))
                            }
                          >
                            <option value="autonomous_in_scope">
                              Autónomo no Escopo Curado (read_only, low e moderate diretos; high sob curadoria)
                            </option>
                            <option value="allow_readonly_and_low_propose_others">
                              Autónomo em read_only + low; curadoria em moderate/high
                            </option>
                            <option value="allow_readonly_propose_others">
                              Autónomo em read_only; curadoria nas demais
                            </option>
                            <option value="propose_only">Curadoria Conjunta Prévia (propose_only)</option>
                            <option value="disabled">Apenas Consulta, Artefactos & Findings</option>
                          </select>
                        </div>
                      </div>

                      <div class="flex flex-wrap items-center gap-4 text-[12px]">
                        <label class="flex items-center gap-1.5 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={d().editEnabled !== false}
                            onChange={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({ ...p, editEnabled: e.currentTarget.checked }))
                            }
                          />
                          <span>Parceiro Ativo no Gateway</span>
                        </label>
                        <label class="flex items-center gap-1.5 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={d().editReadProjectState !== false}
                            onChange={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({
                                ...p,
                                editReadProjectState: e.currentTarget.checked,
                              }))
                            }
                          />
                          <span>project.state</span>
                        </label>
                        <label class="flex items-center gap-1.5 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={d().editReadEvidenceAndFiles !== false}
                            onChange={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({
                                ...p,
                                editReadEvidenceAndFiles: e.currentTarget.checked,
                              }))
                            }
                          />
                          <span>evidence.* & workspace.*</span>
                        </label>
                        <label class="flex items-center gap-1.5 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={d().editCreateArtifactsAndFindings !== false}
                            onChange={(e) =>
                              wb.updateDraft("cdi-hub", (p) => ({
                                ...p,
                                editCreateArtifactsAndFindings: e.currentTarget.checked,
                              }))
                            }
                          />
                          <span>artifact.create & finding.propose</span>
                        </label>
                      </div>

                      <div class="flex flex-wrap items-center justify-between gap-2">
                        <input
                          type="text"
                          value={d().editSecretOverride ?? ""}
                          placeholder="Segredo HMAC individual opcional para este CDI (deixe vazio para usar o partilhado)..."
                          class={`${MONO_INPUT_CLS} flex-1`}
                          onInput={(e) =>
                            wb.updateDraft("cdi-hub", (p) => ({ ...p, editSecretOverride: e.currentTarget.value }))
                          }
                        />
                        <button type="button" class={BTN_PRIMARY} onClick={() => void wb.savePartnerProfile()}>
                          Guardar Perfil Individual
                        </button>
                      </div>
                    </div>
                  </Show>

                  <div class="rounded border border-v2-border-border-base bg-v2-background-bg-base p-2.5 flex flex-col gap-1.5">
                    <div class="flex flex-wrap items-center justify-between gap-2">
                      <span class={LABEL_CLS}>
                        9 Ações Canónicas do Gateway Bidirecional (CDI → CyberLab OS)
                      </span>
                      <span class="font-mono text-[11px] text-emerald-400">
                        {wb.backend.partners?.cyberlabCallbackUrl || "http://127.0.0.1:4096/api/cyberlab/partner-gateway"}
                      </span>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-1.5">
                      <For each={gatewayActions}>
                        {(act) => (
                          <div class="rounded bg-v2-background-bg-deep/60 px-2 py-1 text-[11px] flex items-center justify-between gap-1.5">
                            <span class="font-mono text-v2-text-text-strong">{act.id}</span>
                            <span class="text-v2-text-text-muted truncate">{act.desc}</span>
                          </div>
                        )}
                      </For>
                    </div>
                  </div>
                </div>
              </Show>

              <Show when={d().cdiSubTab !== "setup"}>
                <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2.5 flex flex-col gap-2">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <span class={LABEL_CLS}>
                      Parceiros CDI para Investigação Partilhada (Individual ou Entre Pares, Sem Hierarquia)
                    </span>
                    <Show when={partners().length === 0}>
                      <button type="button" class={CHIP_CLS} onClick={() => void wb.loadFourCdiPreset()}>
                        + Ativar Perfis dos 4 Pares CDI (8788–8791)
                      </button>
                    </Show>
                  </div>
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    <For each={partners()}>
                      {(partner) => (
                        <label class="flex items-start gap-2 rounded border border-v2-border-border-base bg-v2-background-bg-base p-2 text-[12px] cursor-pointer">
                          <input
                            type="checkbox"
                            checked={d().selectedPartnerIds.includes(partner.partnerId)}
                            onChange={() => togglePartner(partner.partnerId)}
                          />
                          <div class="flex flex-col min-w-0 flex-1">
                            <div class="flex items-center justify-between gap-1.5">
                              <span class="font-medium text-v2-text-text-strong">
                                {partner.displayName} ({partner.partnerId})
                              </span>
                              <span class="font-mono text-[10px] text-emerald-400">
                                {partner.permissions.initiateActions === "autonomous_in_scope" ? "autónomo" : partner.permissions.initiateActions}
                              </span>
                            </div>
                            <span class="text-[11px] text-v2-text-text-muted truncate">{partner.specialty}</span>
                            <span class="font-mono text-[10px] text-v2-text-text-muted truncate">
                              {partner.endpointUrl}
                            </span>
                          </div>
                        </label>
                      )}
                    </For>
                  </div>
                </div>
              </Show>

              <Show when={d().cdiSubTab !== "setup"}>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Tema, Hipótese ou Questão de Investigação Partilhada</label>
                  <input
                    type="text"
                    value={d().objective}
                    class={INPUT_CLS}
                    onInput={(e) => wb.updateDraft("cdi-hub", (p) => ({ ...p, objective: e.currentTarget.value }))}
                  />
                </div>

                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Notas do Curador / Contexto Partilhado (redigido automaticamente antes da partilha)</label>
                  <textarea
                    rows={3}
                    value={d().contextText}
                    placeholder="Partilhe observações, hipóteses ou contexto que possam interessar aos parceiros CDI..."
                    class={INPUT_CLS}
                    onInput={(e) => wb.updateDraft("cdi-hub", (p) => ({ ...p, contextText: e.currentTarget.value }))}
                  />
                </div>
              </Show>

              <Show when={d().cdiSubTab !== "setup" && wb.backend.evidence.length > 0}>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Partilhar Evidências SHA-256 do Projeto ({d().selectedEvidenceIds.length})</label>
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

              <Show when={d().cdiSubTab !== "setup"}>
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
                        ? "Em diálogo com parceiros CDI..."
                        : d().selectedPartnerIds.length > 1
                          ? `Convidar ${d().selectedPartnerIds.length} Parceiros CDI em Conjunto`
                          : "Convidar Parceiro CDI para Investigação"}
                    </button>
                  </div>
                </div>
              </Show>

              <Show when={inboundActivity().length > 0}>
                <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-col gap-1.5">
                  <span class={LABEL_CLS}>
                    Iniciativas Autónomas Recentes dos Parceiros CDI via Gateway ({inboundActivity().length})
                  </span>
                  <div class="max-h-36 overflow-y-auto flex flex-col gap-1" data-scrollable>
                    <For each={inboundActivity().slice(0, 12)}>
                      {(act) => (
                        <div class="rounded bg-v2-background-bg-base px-2 py-1 text-[11px] flex items-center justify-between gap-2">
                          <div class="flex items-center gap-1.5 min-w-0">
                            <span class="font-semibold text-emerald-400">{act.partnerId}</span>
                            <span class="font-mono text-v2-text-text-strong">{act.action}</span>
                            <span class="text-v2-text-text-muted truncate">{act.summary}</span>
                          </div>
                          <span class="font-mono text-[10px] text-v2-text-text-muted shrink-0">{act.outcome}</span>
                        </div>
                      )}
                    </For>
                  </div>
                </div>
              </Show>
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

      {/* 19. HTTP INTRUDER / PAYLOAD MATRIX */}
      <Match when={toolId() === "http-intruder"}>
        {(() => {
          const d = () => wb.drafts["http-intruder"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-[110px_minmax(0,1fr)] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Método</label>
                  <select
                    value={d().method}
                    class={MONO_INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({
                        ...p,
                        method: e.currentTarget.value as typeof p.method,
                      }))
                    }
                  >
                    <For each={["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]}>
                      {(m) => <option value={m}>{m}</option>}
                    </For>
                  </select>
                </div>
                <div class="flex flex-col gap-1">
                  <div class="flex flex-wrap items-center justify-between gap-1">
                    <label class={LABEL_CLS}>URL Alvo c/ Marcadores §slot§</label>
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() =>
                        wb.updateDraft("http-intruder", (p) => ({
                          ...p,
                          url: p.url.includes("§") ? p.url : `${p.url.replace(/\/$/, "")}/§slot§`,
                        }))
                      }
                    >
                      + Inserir §slot§ na URL
                    </button>
                  </div>
                  <input
                    type="text"
                    value={d().url}
                    placeholder="http://127.0.0.1:4096/api/§endpoint§"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("http-intruder", (p) => ({ ...p, url: e.currentTarget.value }))}
                  />
                </div>
              </div>

              <div class="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Modo de Ataque Paramétrico</label>
                  <select
                    value={d().attackMode}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({
                        ...p,
                        attackMode: e.currentTarget.value as typeof p.attackMode,
                      }))
                    }
                  >
                    <option value="sniper">Sniper (1 slot por vez, baseline nos demais)</option>
                    <option value="battering_ram">Battering Ram (mesmo payload em todos os §slots§)</option>
                    <option value="pitchfork">Pitchfork (pareia Lista 1 no 1º slot e Lista 2 no 2º)</option>
                  </select>
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Regex / Grep na Resposta (opcional)</label>
                  <input
                    type="text"
                    value={d().grepMatch}
                    placeholder="ex.: admin|token|exception|root"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({ ...p, grepMatch: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Governança</label>
                  <select
                    value={d().executionMode}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({
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

              <HeaderEditorTable
                title="Headers da Requisição (suporta §slot§ em valores)"
                rows={d().headers}
                onChange={(rows) => wb.updateDraft("http-intruder", (p) => ({ ...p, headers: rows }))}
              />

              <Show when={d().method !== "GET" && d().method !== "HEAD"}>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Template de Corpo (use §slot§ onde os payloads devem entrar)</label>
                  <textarea
                    rows={3}
                    value={d().bodyTemplate}
                    placeholder='{"id":"§id§","role":"user"}'
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({ ...p, bodyTemplate: e.currentTarget.value }))
                    }
                  />
                </div>
              </Show>

              <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <div class="flex flex-wrap items-center justify-between gap-1">
                    <label class={LABEL_CLS}>Payload Set 1 (1 por linha)</label>
                    <div class="flex items-center gap-1">
                      <button
                        type="button"
                        class={CHIP_CLS}
                        onClick={() =>
                          wb.updateDraft("http-intruder", (p) => ({
                            ...p,
                            payloadSet1Text: "info\nhealth\nmetrics\nopenapi.json\nconfig\nadmin",
                          }))
                        }
                      >
                        Preset Rotas API
                      </button>
                      <button
                        type="button"
                        class={CHIP_CLS}
                        onClick={() =>
                          wb.updateDraft("http-intruder", (p) => ({
                            ...p,
                            payloadSet1Text: "0\n1\n-1\n999999\ntrue\nnull\n[]\n{}",
                          }))
                        }
                      >
                        Preset Limites QA
                      </button>
                    </div>
                  </div>
                  <textarea
                    rows={4}
                    value={d().payloadSet1Text}
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({ ...p, payloadSet1Text: e.currentTarget.value }))
                    }
                  />
                </div>
                <Show when={d().attackMode === "pitchfork"}>
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Payload Set 2 — Pitchfork (1 por linha)</label>
                    <textarea
                      rows={4}
                      value={d().payloadSet2Text}
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("http-intruder", (p) => ({ ...p, payloadSet2Text: e.currentTarget.value }))
                      }
                    />
                  </div>
                </Show>
              </div>

              <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Requisições (1–200)</label>
                  <input
                    type="number"
                    min={1}
                    max={200}
                    value={d().maxRequests}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({ ...p, maxRequests: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Concorrência (1–5)</label>
                  <input
                    type="number"
                    min={1}
                    max={5}
                    value={d().concurrency}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({ ...p, concurrency: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Delay entre Req (ms)</label>
                  <input
                    type="number"
                    min={0}
                    max={5000}
                    value={d().delayMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({ ...p, delayMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Timeout (ms)</label>
                  <input
                    type="number"
                    min={500}
                    max={20000}
                    value={d().timeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("http-intruder", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>

              <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                <input
                  type="checkbox"
                  checked={d().urlEncodePayloads}
                  onChange={(e) =>
                    wb.updateDraft("http-intruder", (p) => ({ ...p, urlEncodePayloads: e.currentTarget.checked }))
                  }
                />
                <span>Codificar payloads inseridos na URL (encodeURIComponent)</span>
              </label>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("http-intruder", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("http-intruder", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("http-intruder")}
                >
                  {isRunning() ? "Executando Matriz..." : "Iniciar HTTP Intruder"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("http-intruder")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 20. AUDITOR DIFERENCIAL DE PARÂMETROS */}
      <Match when={toolId() === "param-audit"}>
        {(() => {
          const d = () => wb.drafts["param-audit"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-[100px_minmax(0,1fr)] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Método</label>
                  <select
                    value={d().method}
                    class={MONO_INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("param-audit", (p) => ({
                        ...p,
                        method: e.currentTarget.value as "GET" | "POST",
                      }))
                    }
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                  </select>
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>URL Alvo (parâmetros da query são detectados automaticamente)</label>
                  <input
                    type="text"
                    value={d().url}
                    placeholder="http://127.0.0.1:4096/?q=test&redirect=/home"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("param-audit", (p) => ({ ...p, url: e.currentTarget.value }))}
                  />
                </div>
              </div>

              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Parâmetros Adicionais p/ Auditar (opcional, separados por vírgula)</label>
                <input
                  type="text"
                  value={d().parameterNamesText}
                  placeholder="ex.: id, q, search, next, callback"
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("param-audit", (p) => ({ ...p, parameterNamesText: e.currentTarget.value }))
                  }
                />
              </div>

              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-col gap-2">
                <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().checkReflectionContext}
                    onChange={(e) =>
                      wb.updateDraft("param-audit", (p) => ({ ...p, checkReflectionContext: e.currentTarget.checked }))
                    }
                  />
                  <span>Auditar Reflexão Contextual Não-Destrutiva (HTML text, atributo ou &lt;script&gt; c/ canário alfanumérico)</span>
                </label>
                <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().checkErrorLeakage}
                    onChange={(e) =>
                      wb.updateDraft("param-audit", (p) => ({ ...p, checkErrorLeakage: e.currentTarget.checked }))
                    }
                  />
                  <span>Detectar Vazamento de Erros / Stack Traces (SQL, ORM, Template Engine, HTTP 5xx diferencial)</span>
                </label>
                <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().checkRedirectHygiene}
                    onChange={(e) =>
                      wb.updateDraft("param-audit", (p) => ({ ...p, checkRedirectHygiene: e.currentTarget.checked }))
                    }
                  />
                  <span>Verificar Higiene contra Open-Redirect em parâmetros de URL/retorno</span>
                </label>
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("param-audit", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("param-audit", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("param-audit")}
                >
                  {isRunning() ? "Auditando Parâmetros..." : "Executar Auditoria Diferencial"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("param-audit")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 21. DALFOX EXTERNAL SCANNER */}
      <Match when={toolId() === "dalfox"}>
        {(() => {
          const d = () => wb.drafts.dalfox
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>URL Alvo c/ Query String (Dalfox MIT)</label>
                <input
                  type="text"
                  value={d().url}
                  placeholder="http://127.0.0.1:8080/search?q=test"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("dalfox", (p) => ({ ...p, url: e.currentTarget.value }))}
                />
              </div>
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Focar em Parâmetro Específico (-p, opcional)</label>
                <input
                  type="text"
                  value={d().paramName}
                  placeholder="q"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("dalfox", (p) => ({ ...p, paramName: e.currentTarget.value }))}
                />
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("dalfox", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("dalfox", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("dalfox")}
                >
                  {isRunning() ? "Executando Dalfox..." : "Executar Dalfox Parameter Scan"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("dalfox")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 22. DNS, SUBDOMÍNIOS & EMAIL RECON */}
      <Match when={toolId() === "dns-recon"}>
        {(() => {
          const d = () => wb.drafts["dns-recon"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-1 md:grid-cols-[1fr_200px] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Domínio ou IP Alvo</label>
                  <input
                    type="text"
                    value={d().host}
                    placeholder="exemplo.com.br ou 127.0.0.1"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("dns-recon", (p) => ({ ...p, host: e.currentTarget.value }))}
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Resolver DNS Customizado (opcional)</label>
                  <input
                    type="text"
                    value={d().nameserver}
                    placeholder="ex.: 1.1.1.1 ou 8.8.8.8"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("dns-recon", (p) => ({ ...p, nameserver: e.currentTarget.value }))}
                  />
                </div>
              </div>

              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex flex-col gap-2">
                <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().checkEmailPosture}
                    onChange={(e) =>
                      wb.updateDraft("dns-recon", (p) => ({ ...p, checkEmailPosture: e.currentTarget.checked }))
                    }
                  />
                  <span>Auditar Postura de Email & Anti-Spoofing (SPF, _dmarc, políticas p=none/+all e CAA)</span>
                </label>
                <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().enumerateSubdomains}
                    onChange={(e) =>
                      wb.updateDraft("dns-recon", (p) => ({ ...p, enumerateSubdomains: e.currentTarget.checked }))
                    }
                  />
                  <span>Enumerar Subdomínios Comuns & Auditar CNAMEs Órfãos (Subdomain Takeover Hygiene)</span>
                </label>
                <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().includeCrtSh}
                    onChange={(e) =>
                      wb.updateDraft("dns-recon", (p) => ({ ...p, includeCrtSh: e.currentTarget.checked }))
                    }
                  />
                  <span>Consultar Certificate Transparency Passivo (crt.sh JSON)</span>
                </label>
              </div>

              <Show when={d().enumerateSubdomains}>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Prefixos de Subdomínio (separados por vírgula, máx 40)</label>
                  <input
                    type="text"
                    value={d().subdomainPrefixesText}
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("dns-recon", (p) => ({ ...p, subdomainPrefixesText: e.currentTarget.value }))
                    }
                  />
                </div>
              </Show>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("dns-recon", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("dns-recon", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("dns-recon")}
                >
                  {isRunning() ? "Consultando DNS..." : "Executar Reconhecimento DNS & Email"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("dns-recon")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 23. DISASSEMBLER NATIVO (x86_64 / ARM64) */}
      <Match when={toolId() === "binary-disasm"}>
        {(() => {
          const d = () => wb.drafts["binary-disasm"]
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Caminho do Binário no Projeto (ELF64 / PE / Mach-O / Raw)</label>
                <input
                  type="text"
                  value={d().binaryPath}
                  placeholder="amostra.elf"
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("binary-disasm", (p) => ({ ...p, binaryPath: e.currentTarget.value }))
                  }
                />
              </div>
              <div class="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Arquitetura</label>
                  <select
                    value={d().architecture}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("binary-disasm", (p) => ({
                        ...p,
                        architecture: e.currentTarget.value as "auto" | "x86_64" | "arm64",
                      }))
                    }
                  >
                    <option value="auto">Auto-detectar pelos Headers</option>
                    <option value="x86_64">x86_64 / AMD64</option>
                    <option value="arm64">ARM64 / AArch64</option>
                  </select>
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Offset Inicial no Arquivo (vazio = Entrypoint)</label>
                  <input
                    type="text"
                    value={d().startOffsetHex}
                    placeholder="ex.: 0x1000 ou 4096"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("binary-disasm", (p) => ({ ...p, startOffsetHex: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Instruções (5–400)</label>
                  <input
                    type="number"
                    min={5}
                    max={400}
                    value={d().maxInstructions}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("binary-disasm", (p) => ({
                        ...p,
                        maxInstructions: Number(e.currentTarget.value),
                      }))
                    }
                  />
                </div>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("binary-disasm", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("binary-disasm", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("binary-disasm")}
                >
                  {isRunning() ? "Desmontando Instruções..." : "Desmontar Instruções (ASM)"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("binary-disasm")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 24. GHIDRA HEADLESS */}
      <Match when={toolId() === "ghidra"}>
        {(() => {
          const d = () => wb.drafts.ghidra
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Binário no Projeto p/ Análise Ghidra Headless (Apache-2.0)</label>
                <input
                  type="text"
                  value={d().binaryPath}
                  placeholder="amostra.elf"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("ghidra", (p) => ({ ...p, binaryPath: e.currentTarget.value }))}
                />
              </div>
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Processor ID Ghidra (-processor, opcional — vazio = auto)</label>
                <input
                  type="text"
                  value={d().processor}
                  placeholder="ex.: x86:LE:64:default ou AARCH64:LE:64:v8A"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("ghidra", (p) => ({ ...p, processor: e.currentTarget.value }))}
                />
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("ghidra", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("ghidra", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("ghidra")}
                >
                  {isRunning() ? "Executando Ghidra Headless..." : "Executar Ghidra Headless"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("ghidra")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 25. JADX ANDROID DECOMPILER */}
      <Match when={toolId() === "jadx"}>
        {(() => {
          const d = () => wb.drafts.jadx
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Pacote Android (.apk / .dex / .aar) no Projeto</label>
                <input
                  type="text"
                  value={d().artifactPath}
                  placeholder="aplicativo.apk"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("jadx", (p) => ({ ...p, artifactPath: e.currentTarget.value }))}
                />
              </div>
              <label class="flex items-center gap-2 text-[12px] text-v2-text-text-strong cursor-pointer">
                <input
                  type="checkbox"
                  checked={d().deobfuscate}
                  onChange={(e) => wb.updateDraft("jadx", (p) => ({ ...p, deobfuscate: e.currentTarget.checked }))}
                />
                <span>Ativar Deobfuscação de Identificadores (--deobf) e salvar .java em .cyberlab/artifacts/jadx/</span>
              </label>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("jadx", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("jadx", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("jadx")}
                >
                  {isRunning() ? "Descompilando APK/DEX..." : "Descompilar p/ Java c/ JADX"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("jadx")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 26. MOTOR YARA NATIVO */}
      <Match when={toolId() === "yara-scan"}>
        {(() => {
          const d = () => wb.drafts["yara-scan"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-1 md:grid-cols-[1fr_160px] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Arquivo ou Pasta Alvo no Projeto</label>
                  <input
                    type="text"
                    value={d().targetPath}
                    placeholder="cyberlab ou amostra.elf"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("yara-scan", (p) => ({ ...p, targetPath: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Arquivos (1–500)</label>
                  <input
                    type="number"
                    min={1}
                    max={500}
                    value={d().maxFiles}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("yara-scan", (p) => ({ ...p, maxFiles: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>

              <div class="flex flex-col gap-1">
                <div class="flex flex-wrap items-center justify-between gap-1">
                  <label class={LABEL_CLS}>Regras YARA (suporta ascii, wide, nocase, hex {`{ 7F 45 ?? 46 }`} e condições)</label>
                  <div class="flex items-center gap-1">
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() =>
                        wb.updateDraft("yara-scan", (p) => ({
                          ...p,
                          rulesText: `rule Executable_Magic_Headers {\n  meta:\n    description = "Detecta binários ELF, PE/MZ ou Dalvik DEX"\n    severity = "info"\n  strings:\n    $elf = { 7F 45 4C 46 }\n    $mz  = { 4D 5A 90 00 }\n    $dex = { 64 65 78 0A 30 ?? 35 00 }\n  condition:\n    any of them\n}`,
                        }))
                      }
                    >
                      Template ELF/PE/DEX
                    </button>
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() =>
                        wb.updateDraft("yara-scan", (p) => ({
                          ...p,
                          rulesText: `rule Suspicious_Execution_Indicators {\n  meta:\n    description = "Comandos de reverse shell ou execução codificada"\n    severity = "high"\n  strings:\n    $s1 = "/bin/sh -i" ascii\n    $s2 = "FromBase64String" ascii wide nocase\n    $s3 = "Invoke-Expression" ascii wide nocase\n  condition:\n    any of ($s*)\n}`,
                        }))
                      }
                    >
                      Template Indicadores Suspeitos
                    </button>
                  </div>
                </div>
                <textarea
                  rows={8}
                  value={d().rulesText}
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("yara-scan", (p) => ({ ...p, rulesText: e.currentTarget.value }))}
                />
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("yara-scan", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("yara-scan", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("yara-scan")}
                >
                  {isRunning() ? "Varrendo com YARA..." : "Executar Regras YARA"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("yara-scan")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 27. YARA-X OFICIAL (YR) */}
      <Match when={toolId() === "yarax"}>
        {(() => {
          const d = () => wb.drafts.yarax
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Arquivo de Regras (.yar / .yara) no Projeto</label>
                <input
                  type="text"
                  value={d().rulesPath}
                  placeholder="regras.yar"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("yarax", (p) => ({ ...p, rulesPath: e.currentTarget.value }))}
                />
              </div>
              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Arquivo ou Pasta Alvo no Projeto</label>
                <input
                  type="text"
                  value={d().targetPath}
                  placeholder="amostra.elf"
                  class={MONO_INPUT_CLS}
                  onInput={(e) => wb.updateDraft("yarax", (p) => ({ ...p, targetPath: e.currentTarget.value }))}
                />
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("yarax", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("yarax", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("yarax")}
                >
                  {isRunning() ? "Executando YARA-X..." : "Executar YARA-X (yr scan)"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("yarax")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 28. API, GRAPHQL & OAUTH2 SECURITY LAB */}
      <Match when={toolId() === "api-security-lab"}>
        {(() => {
          const d = () => wb.drafts["api-security-lab"]
          return (
            <div class="flex flex-col gap-3">
              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/30 p-2.5 flex flex-col gap-2">
                <div class="text-[11px] font-medium uppercase tracking-wide text-emerald-500">
                  1. OpenAPI / Swagger / Postman Collection + Matriz Diferencial BOLA / IDOR
                </div>
                <div class="grid grid-cols-1 md:grid-cols-[1fr_1fr_120px] gap-2">
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Base URL da API REST</label>
                    <input
                      type="text"
                      value={d().baseUrl}
                      placeholder="http://127.0.0.1:4096"
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("api-security-lab", (p) => ({ ...p, baseUrl: e.currentTarget.value }))
                      }
                    />
                  </div>
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Caminho da Spec no Projeto (opcional)</label>
                    <input
                      type="text"
                      value={d().specPath}
                      placeholder="openapi.json ou collection.postman.json"
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("api-security-lab", (p) => ({ ...p, specPath: e.currentTarget.value }))
                      }
                    />
                  </div>
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Máx Rotas (1–40)</label>
                    <input
                      type="number"
                      min={1}
                      max={40}
                      value={d().maxEndpoints}
                      class={INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("api-security-lab", (p) => ({
                          ...p,
                          maxEndpoints: Number(e.currentTarget.value),
                        }))
                      }
                    />
                  </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Header Authorization — User A (Dono do Recurso)</label>
                    <input
                      type="text"
                      value={d().userAAuthHeader}
                      placeholder="Bearer eyJhbGci..."
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("api-security-lab", (p) => ({ ...p, userAAuthHeader: e.currentTarget.value }))
                      }
                    />
                  </div>
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Header Authorization — User B (Cross-Tenant / BOLA)</label>
                    <input
                      type="text"
                      value={d().userBAuthHeader}
                      placeholder="Bearer eyJhbGci..."
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("api-security-lab", (p) => ({ ...p, userBAuthHeader: e.currentTarget.value }))
                      }
                    />
                  </div>
                </div>

                <div class="flex flex-wrap items-center justify-between gap-2">
                  <label class="flex items-center gap-2 text-[12px] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={d().testUnauthenticated}
                      onChange={(e) =>
                        wb.updateDraft("api-security-lab", (p) => ({
                          ...p,
                          testUnauthenticated: e.currentTarget.checked,
                        }))
                      }
                    />
                    <span class="text-v2-text-text-strong">Testar também acesso Sem Autenticação (Broken Auth)</span>
                  </label>
                  <label class="text-[11px] text-v2-text-text-muted flex items-center gap-1.5">
                    <span>Importar JSON/YAML local:</span>
                    <input
                      type="file"
                      accept=".json,.yaml,.yml"
                      class="text-[11px]"
                      onChange={(e) => {
                        const file = e.currentTarget.files?.[0]
                        if (!file) return
                        void file.text().then((txt) => {
                          wb.updateDraft("api-security-lab", (p) => ({ ...p, inlineSpecJson: txt }))
                        })
                      }}
                    />
                  </label>
                </div>

                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Spec OpenAPI 3 / Swagger 2 / Postman Collection v2.1 Inline</label>
                  <textarea
                    rows={4}
                    value={d().inlineSpecJson}
                    placeholder='{"openapi":"3.0.3","paths":{"/api/users/{id}":{"get":{}}}}'
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("api-security-lab", (p) => ({ ...p, inlineSpecJson: e.currentTarget.value }))
                    }
                  />
                </div>
              </div>

              <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/30 p-2.5 flex flex-col gap-2">
                  <div class="text-[11px] font-medium uppercase tracking-wide text-sky-400">
                    2. GraphQL Posture Inspector (opcional)
                  </div>
                  <input
                    type="text"
                    value={d().graphqlUrl}
                    placeholder="http://127.0.0.1:8080/graphql"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("api-security-lab", (p) => ({ ...p, graphqlUrl: e.currentTarget.value }))
                    }
                  />
                  <div class="flex items-center justify-between gap-2 text-[12px]">
                    <label class="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={d().graphqlTestBatching}
                        onChange={(e) =>
                          wb.updateDraft("api-security-lab", (p) => ({
                            ...p,
                            graphqlTestBatching: e.currentTarget.checked,
                          }))
                        }
                      />
                      <span class="text-v2-text-text-strong">Testar Array Query Batching</span>
                    </label>
                    <div class="flex items-center gap-1">
                      <span class="text-[11px] text-v2-text-text-muted">Profundidade:</span>
                      <input
                        type="number"
                        min={2}
                        max={12}
                        value={d().graphqlMaxDepthProbe}
                        class="w-16 rounded border border-v2-border-border-base bg-v2-background-bg-deep px-1.5 py-0.5 text-[12px]"
                        onInput={(e) =>
                          wb.updateDraft("api-security-lab", (p) => ({
                            ...p,
                            graphqlMaxDepthProbe: Number(e.currentTarget.value),
                          }))
                        }
                      />
                    </div>
                  </div>
                </div>

                <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/30 p-2.5 flex flex-col gap-2">
                  <div class="text-[11px] font-medium uppercase tracking-wide text-amber-400">
                    3. OAuth2 / OIDC Hygiene Auditor (opcional)
                  </div>
                  <input
                    type="text"
                    value={d().issuerUrl}
                    placeholder="Issuer URL (ex.: http://127.0.0.1:8080/realms/lab)"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("api-security-lab", (p) => ({ ...p, issuerUrl: e.currentTarget.value }))
                    }
                  />
                  <input
                    type="text"
                    value={d().authorizeUrl}
                    placeholder="URL /authorize?client_id=...&redirect_uri=... (audita state/PKCE)"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("api-security-lab", (p) => ({ ...p, authorizeUrl: e.currentTarget.value }))
                    }
                  />
                </div>
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("api-security-lab", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("api-security-lab", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("api-security-lab")}
                >
                  {isRunning() ? "Auditando API / GraphQL / OAuth2..." : "Executar Auditoria API, BOLA, GraphQL & OAuth2"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("api-security-lab")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 29. SCA, SBOM CYCLONEDX & IAC AUDITOR */}
      <Match when={toolId() === "sca-sbom-iac"}>
        {(() => {
          const d = () => wb.drafts["sca-sbom-iac"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-1 md:grid-cols-[1fr_140px_140px] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Pasta ou Manifest Alvo no Projeto</label>
                  <input
                    type="text"
                    value={d().targetPath}
                    placeholder=". ou packages/app"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("sca-sbom-iac", (p) => ({ ...p, targetPath: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Arquivos (5–500)</label>
                  <input
                    type="number"
                    min={5}
                    max={500}
                    value={d().maxFiles}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("sca-sbom-iac", (p) => ({ ...p, maxFiles: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Timeout OSV (ms)</label>
                  <input
                    type="number"
                    min={1000}
                    max={20000}
                    value={d().timeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("sca-sbom-iac", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>

              <div class="flex flex-wrap items-center gap-4 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 text-[12px]">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().generateCycloneDx}
                    onChange={(e) =>
                      wb.updateDraft("sca-sbom-iac", (p) => ({ ...p, generateCycloneDx: e.currentTarget.checked }))
                    }
                  />
                  <span class="text-v2-text-text-strong">Gerar SBOM CycloneDX 1.5 JSON (evidência dedicada)</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().auditIac}
                    onChange={(e) =>
                      wb.updateDraft("sca-sbom-iac", (p) => ({ ...p, auditIac: e.currentTarget.checked }))
                    }
                  />
                  <span class="text-v2-text-text-strong">Auditar Dockerfile, Compose, Kubernetes & Terraform (.tf)</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().queryOsv}
                    onChange={(e) =>
                      wb.updateDraft("sca-sbom-iac", (p) => ({ ...p, queryOsv: e.currentTarget.checked }))
                    }
                  />
                  <span class="text-v2-text-text-strong">Consultar OSV.dev Online (CVEs em Tempo Real)</span>
                </label>
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("sca-sbom-iac", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("sca-sbom-iac", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("sca-sbom-iac")}
                >
                  {isRunning() ? "Auditando Dependências & IaC..." : "Executar SCA + SBOM CycloneDX + Auditor IaC"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("sca-sbom-iac")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 30. AQUA TRIVY EXTERNAL BRIDGE */}
      <Match when={toolId() === "trivy"}>
        {(() => {
          const d = () => wb.drafts.trivy
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Pasta ou Arquivo Alvo no Projeto</label>
                  <input
                    type="text"
                    value={d().targetPath}
                    placeholder="."
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("trivy", (p) => ({ ...p, targetPath: e.currentTarget.value }))}
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Scanners Trivy (--scanners)</label>
                  <input
                    type="text"
                    value={d().scanners}
                    placeholder="vuln,misconfig,secret"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("trivy", (p) => ({ ...p, scanners: e.currentTarget.value }))}
                  />
                </div>
              </div>
              <div class="flex flex-wrap gap-1">
                <For each={["vuln,misconfig", "vuln,misconfig,secret", "vuln", "misconfig", "secret"]}>
                  {(preset) => (
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() => wb.updateDraft("trivy", (p) => ({ ...p, scanners: preset }))}
                    >
                      {preset}
                    </button>
                  )}
                </For>
              </div>
              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("trivy", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("trivy", (p) => ({ ...p, rawJson: v }))}
              />
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("trivy")}
                >
                  {isRunning() ? "Executando Aqua Trivy..." : "Executar Aqua Trivy (trivy fs)"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("trivy")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 31. DFIR LOG ANALYZER & SIGMA RULES */}
      <Match when={toolId() === "dfir-sigma"}>
        {(() => {
          const d = () => wb.drafts["dfir-sigma"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-1 md:grid-cols-[1fr_180px_140px] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Arquivo ou Pasta de Logs no Projeto</label>
                  <input
                    type="text"
                    value={d().logPath}
                    placeholder="logs/auth.log, access.log ou events.jsonl"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("dfir-sigma", (p) => ({ ...p, logPath: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Formato do Log</label>
                  <select
                    value={d().logFormat}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("dfir-sigma", (p) => ({
                        ...p,
                        logFormat: e.currentTarget.value as "auto" | "syslog" | "nginx" | "json",
                      }))
                    }
                  >
                    <option value="auto">Auto-detectar</option>
                    <option value="syslog">Linux syslog / auth.log</option>
                    <option value="nginx">Nginx / Apache Combined</option>
                    <option value="json">JSON / NDJSON / Windows Event</option>
                  </select>
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx Eventos</label>
                  <input
                    type="number"
                    min={10}
                    max={50000}
                    value={d().maxEvents}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("dfir-sigma", (p) => ({ ...p, maxEvents: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>

              <div class="grid grid-cols-1 md:grid-cols-[auto_1fr] items-center gap-3 rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5">
                <label class="flex items-center gap-2 text-[12px] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().useBuiltinSigma}
                    onChange={(e) =>
                      wb.updateDraft("dfir-sigma", (p) => ({ ...p, useBuiltinSigma: e.currentTarget.checked }))
                    }
                  />
                  <span class="text-v2-text-text-strong">
                    Usar pacote Sigma integrado (SSH Brute-Force, Sudo Escalation, Webshells, PowerShell Encoded, Pass-the-Hash)
                  </span>
                </label>
                <input
                  type="text"
                  value={d().sigmaRulesPath}
                  placeholder="Pasta/arquivo .yml Sigma extra no projeto (opcional)"
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("dfir-sigma", (p) => ({ ...p, sigmaRulesPath: e.currentTarget.value }))
                  }
                />
              </div>

              <div class="flex flex-col gap-1">
                <div class="flex flex-wrap items-center justify-between gap-1">
                  <label class={LABEL_CLS}>Regra Sigma YAML Customizada Inline (opcional — suporta |contains, |startswith, |re, |all)</label>
                  <div class="flex items-center gap-1">
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() =>
                        wb.updateDraft("dfir-sigma", (p) => ({
                          ...p,
                          inlineSigmaYaml: `title: Custom Suspicious Admin Login\nid: sigma-custom-admin-01\nlevel: high\ndescription: Detecta falhas ou logins administrativos suspeitos\ndetection:\n  selection:\n    message|contains:\n      - 'Accepted publickey for root'\n      - 'Failed password for admin'\n  condition: selection`,
                        }))
                      }
                    >
                      Template Sigma SSH
                    </button>
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() =>
                        wb.updateDraft("dfir-sigma", (p) => ({
                          ...p,
                          inlineSigmaYaml: `title: Custom Web Exploit Probe\nid: sigma-custom-web-02\nlevel: critical\ndescription: Detecta SQLi ou RCE na URL HTTP\ndetection:\n  selection:\n    url|contains:\n      - 'UNION SELECT'\n      - '/etc/passwd'\n      - 'cmd.exe'\n  condition: selection`,
                        }))
                      }
                    >
                      Template Sigma Web
                    </button>
                  </div>
                </div>
                <textarea
                  rows={5}
                  value={d().inlineSigmaYaml}
                  placeholder="Cole aqui uma ou mais regras Sigma YAML separadas por ---"
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("dfir-sigma", (p) => ({ ...p, inlineSigmaYaml: e.currentTarget.value }))
                  }
                />
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("dfir-sigma", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("dfir-sigma", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("dfir-sigma")}
                >
                  {isRunning() ? "Correlacionando Eventos Sigma..." : "Executar Triagem DFIR & Gerar Timeline SHA-256"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("dfir-sigma")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 32. ACTIVE DIRECTORY, SMB, LDAP & NTLM LAB INSPECTOR */}
      <Match when={toolId() === "ad-smb-ldap"}>
        {(() => {
          const d = () => wb.drafts["ad-smb-ldap"]
          return (
            <div class="flex flex-col gap-3">
              <div class="grid grid-cols-1 md:grid-cols-[1fr_140px] gap-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Host / Controlador de Domínio de Laboratório</label>
                  <input
                    type="text"
                    value={d().host}
                    placeholder="127.0.0.1 ou dc01.lab.interno"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, host: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Timeout (ms)</label>
                  <input
                    type="number"
                    min={500}
                    max={10000}
                    value={d().timeoutMs}
                    class={INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, timeoutMs: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>

              <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex items-center justify-between gap-2">
                  <label class="flex items-center gap-2 text-[12px] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={d().checkSmbSigning}
                      onChange={(e) =>
                        wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, checkSmbSigning: e.currentTarget.checked }))
                      }
                    />
                    <span class="text-v2-text-text-strong">Checar SMB2/3 Signing (Exposição NTLM Relay)</span>
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={d().smbPort}
                    class="w-20 rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1 font-mono text-[12px]"
                    onInput={(e) =>
                      wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, smbPort: Number(e.currentTarget.value) }))
                    }
                  />
                </div>

                <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/40 p-2.5 flex items-center justify-between gap-2">
                  <label class="flex items-center gap-2 text-[12px] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={d().checkLdapRootDse}
                      onChange={(e) =>
                        wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, checkLdapRootDse: e.currentTarget.checked }))
                      }
                    />
                    <span class="text-v2-text-text-strong">Checar LDAPv3 RootDSE Anônimo</span>
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={d().ldapPort}
                    class="w-20 rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1 font-mono text-[12px]"
                    onInput={(e) =>
                      wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, ldapPort: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
              </div>

              <div class="flex flex-col gap-1">
                <label class={LABEL_CLS}>Endpoint HTTP NTLM Challenge Type-2 (opcional — extrai Domínio/FQDN/OS Build)</label>
                <input
                  type="text"
                  value={d().ntlmHttpUrl}
                  placeholder="http://127.0.0.1:8080/ews ou /autodiscover"
                  class={MONO_INPUT_CLS}
                  onInput={(e) =>
                    wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, ntlmHttpUrl: e.currentTarget.value }))
                  }
                />
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("ad-smb-ldap", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("ad-smb-ldap")}
                >
                  {isRunning() ? "Inspecionando SMB / LDAP / NTLM..." : "Executar Inspeção Passiva AD / SMB / LDAP"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("ad-smb-ldap")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* 33. BINARY ENTROPY VISUALIZER & CYBERCHEF RECIPE STUDIO */}
      <Match when={toolId() === "entropy-recipe"}>
        {(() => {
          const d = () => wb.drafts["entropy-recipe"]

          const addRecipeStep = (op: EntropyRecipeOp = "from_base64") => {
            const nextStep: EntropyRecipeStepRow = {
              id: `step-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              op,
              key: "",
              keyEncoding: "utf8",
              ivHex: "",
              authTagHex: "",
              minLength: 4,
            }
            wb.updateDraft("entropy-recipe", (p) => ({ ...p, recipeSteps: [...p.recipeSteps, nextStep] }))
          }

          const updateStep = (id: string, patch: Partial<EntropyRecipeStepRow>) => {
            wb.updateDraft("entropy-recipe", (p) => ({
              ...p,
              recipeSteps: p.recipeSteps.map((s) => (s.id === id ? { ...s, ...patch } : s)),
            }))
          }

          const removeStep = (id: string) => {
            wb.updateDraft("entropy-recipe", (p) => ({
              ...p,
              recipeSteps: p.recipeSteps.filter((s) => s.id !== id),
            }))
          }

          const saveCurrentRecipe = () => {
            const name = d().newRecipeName.trim()
            if (!name || d().recipeSteps.length === 0) return
            const entry = {
              id: `rec-${Date.now()}`,
              name,
              steps: d().recipeSteps.map((s) => ({ ...s })),
            }
            wb.updateDraft("entropy-recipe", (p) => ({
              ...p,
              newRecipeName: "",
              savedRecipes: [...p.savedRecipes, entry],
            }))
          }

          return (
            <div class="flex flex-col gap-3">
              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/30 p-2.5 flex flex-col gap-2">
                <div class="text-[11px] font-medium uppercase tracking-wide text-emerald-500">
                  1. Espectro Visual de Entropia (Byte 0 → EOF) & Assinaturas Embutidas
                </div>
                <div class="grid grid-cols-1 md:grid-cols-[1fr_180px] gap-2">
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Arquivo no Projeto (Binário, Firmware, Imagem, Pacote — opcional)</label>
                    <input
                      type="text"
                      value={d().targetPath}
                      placeholder="firmware.bin, amostra.elf ou package.json"
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("entropy-recipe", (p) => ({ ...p, targetPath: e.currentTarget.value }))
                      }
                    />
                  </div>
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Resolução do Gráfico (Buckets 8–256)</label>
                    <select
                      value={String(d().windowSize)}
                      class={INPUT_CLS}
                      onChange={(e) =>
                        wb.updateDraft("entropy-recipe", (p) => ({
                          ...p,
                          windowSize: Number(e.currentTarget.value),
                        }))
                      }
                    >
                      <option value="32">32 faixas (Compacto)</option>
                      <option value="64">64 faixas (Padrão)</option>
                      <option value="128">128 faixas (Detalhado)</option>
                      <option value="256">256 faixas (Máxima Resolução)</option>
                    </select>
                  </div>
                </div>
              </div>

              <div class="rounded-md border border-v2-border-border-base bg-v2-background-bg-deep/30 p-2.5 flex flex-col gap-2.5">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <div class="text-[11px] font-medium uppercase tracking-wide text-sky-400">
                    2. CyberChef Recipe Studio (XOR, AES-CBC/GCM, Zlib/Gzip, Protobuf)
                  </div>
                  <div class="flex flex-wrap items-center gap-1">
                    <For each={d().savedRecipes}>
                      {(rec) => (
                        <button
                          type="button"
                          class={CHIP_CLS}
                          onClick={() =>
                            wb.updateDraft("entropy-recipe", (p) => ({
                              ...p,
                              recipeSteps: rec.steps.map((s, idx) => ({ ...s, id: `loaded-${idx}-${Date.now()}` })),
                            }))
                          }
                        >
                          Receita: {rec.name}
                        </button>
                      )}
                    </For>
                  </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-[1fr_160px] gap-2">
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Entrada da Receita (deixe vazio para usar os bytes do arquivo acima)</label>
                    <textarea
                      rows={2}
                      value={d().rawInput}
                      placeholder="Texto, Base64 ou Hex para decodificar..."
                      class={MONO_INPUT_CLS}
                      onInput={(e) =>
                        wb.updateDraft("entropy-recipe", (p) => ({ ...p, rawInput: e.currentTarget.value }))
                      }
                    />
                  </div>
                  <div class="flex flex-col gap-1">
                    <label class={LABEL_CLS}>Codificação de Entrada</label>
                    <select
                      value={d().inputEncoding}
                      class={INPUT_CLS}
                      onChange={(e) =>
                        wb.updateDraft("entropy-recipe", (p) => ({
                          ...p,
                          inputEncoding: e.currentTarget.value as "utf8" | "hex" | "base64",
                        }))
                      }
                    >
                      <option value="utf8">UTF-8 / Texto</option>
                      <option value="hex">Hexadecimal Bruto</option>
                      <option value="base64">Base64 Bruto</option>
                    </select>
                  </div>
                </div>

                <div class="flex flex-col gap-1.5">
                  <For each={d().recipeSteps}>
                    {(step, idx) => (
                      <div class="rounded border border-v2-border-border-base bg-v2-background-bg-base p-2 flex flex-col gap-1.5">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                          <div class="flex items-center gap-2">
                            <span class="rounded bg-v2-background-bg-deep px-1.5 py-0.5 font-mono text-[10px] text-v2-text-text-muted">
                              #{idx() + 1}
                            </span>
                            <select
                              value={step.op}
                              class="rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1 text-[12px] text-v2-text-text-strong"
                              onChange={(e) =>
                                updateStep(step.id, { op: e.currentTarget.value as EntropyRecipeOp })
                              }
                            >
                              <For each={ENTROPY_RECIPE_OPS}>
                                {(opt) => <option value={opt.id}>{opt.label}</option>}
                              </For>
                            </select>
                          </div>
                          <button
                            type="button"
                            class="text-[11px] text-v2-text-text-muted hover:text-red-500 cursor-pointer"
                            onClick={() => removeStep(step.id)}
                          >
                            Remover
                          </button>
                        </div>

                        <Show
                          when={
                            step.op === "xor_key" ||
                            step.op === "aes_cbc_decrypt" ||
                            step.op === "aes_gcm_decrypt"
                          }
                        >
                          <div class="grid grid-cols-1 md:grid-cols-[1fr_110px_1fr_1fr] gap-1.5">
                            <input
                              type="text"
                              value={step.key}
                              placeholder="Chave (UTF-8 ou Hex)"
                              class={MONO_INPUT_CLS}
                              onInput={(e) => updateStep(step.id, { key: e.currentTarget.value })}
                            />
                            <select
                              value={step.keyEncoding}
                              class={INPUT_CLS}
                              onChange={(e) =>
                                updateStep(step.id, { keyEncoding: e.currentTarget.value as "utf8" | "hex" })
                              }
                            >
                              <option value="utf8">Key UTF-8</option>
                              <option value="hex">Key Hex</option>
                            </select>
                            <Show when={step.op === "aes_cbc_decrypt" || step.op === "aes_gcm_decrypt"}>
                              <input
                                type="text"
                                value={step.ivHex}
                                placeholder={step.op === "aes_cbc_decrypt" ? "IV Hex (32 chars)" : "Nonce/IV Hex (24 chars)"}
                                class={MONO_INPUT_CLS}
                                onInput={(e) => updateStep(step.id, { ivHex: e.currentTarget.value })}
                              />
                            </Show>
                            <Show when={step.op === "aes_gcm_decrypt"}>
                              <input
                                type="text"
                                value={step.authTagHex}
                                placeholder="AuthTag Hex (32 chars)"
                                class={MONO_INPUT_CLS}
                                onInput={(e) => updateStep(step.id, { authTagHex: e.currentTarget.value })}
                              />
                            </Show>
                          </div>
                        </Show>
                      </div>
                    )}
                  </For>
                </div>

                <div class="flex flex-wrap items-center justify-between gap-2">
                  <div class="flex flex-wrap items-center gap-1.5">
                    <button type="button" class={BTN_SECONDARY} onClick={() => addRecipeStep("from_base64")}>
                      + Adicionar Operação
                    </button>
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() => wb.updateDraft("entropy-recipe", (p) => ({ ...p, recipeSteps: [] }))}
                    >
                      Limpar Receita
                    </button>
                  </div>
                  <div class="flex items-center gap-1.5">
                    <input
                      type="text"
                      value={d().newRecipeName}
                      placeholder="Nome para salvar receita..."
                      class="w-44 rounded border border-v2-border-border-base bg-v2-background-bg-deep px-2 py-1 text-[12px]"
                      onInput={(e) =>
                        wb.updateDraft("entropy-recipe", (p) => ({ ...p, newRecipeName: e.currentTarget.value }))
                      }
                    />
                    <button type="button" class={BTN_SECONDARY} onClick={saveCurrentRecipe}>
                      Salvar Receita
                    </button>
                  </div>
                </div>
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("entropy-recipe", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("entropy-recipe", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("entropy-recipe")}
                >
                  {isRunning() ? "Processando Entropia & Receita..." : "Executar Espectro de Entropia & Receita CyberChef"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("entropy-recipe")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* ==================================================================
          KEY HUNTER — NATIVE MULTI-SURFACE STUDIO (MIT)
         ================================================================== */}
      <Match when={toolId() === "key-hunter"}>
        {(() => {
          const d = () => wb.drafts["key-hunter"]
          const providerPresets = [
            { label: "Todos (43+ Padrões)", value: "all" },
            { label: "IA / LLMs (OpenAI/Anthropic/Gemini/Grok/Groq/HF)", value: "ai_llm" },
            { label: "Cloud & Infra (AWS/GCP/Azure/Supabase/Vault/CF)", value: "cloud_infra" },
            { label: "Pagamentos (Stripe Live/Shopify/Square)", value: "payment_commerce" },
            { label: "Dev & VCS (GitHub/GitLab/npm/PyPI)", value: "developer_vcs" },
            { label: "Comunicação (Slack/Discord/Telegram/SendGrid)", value: "communication_saas" },
            { label: "Bancos & Crypto (Postgres/Mongo/Redis/PEM/JWK/JWT)", value: "database_observability,crypto_material" },
          ]
          return (
            <div class="flex flex-col gap-3">
              <div class="flex flex-wrap items-center justify-between gap-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-base/70 px-3 py-2 text-[12px]">
                <div class="flex flex-col">
                  <strong class="text-v2-text-text-strong">
                    CyberLab Key Hunter Studio (MIT Nativo — Código, Binários, Web/JS Bundles, Buffer & GitHub)
                  </strong>
                  <span class="text-[11px] text-v2-text-text-muted">
                    Inclui filtro inteligente anti-placeholder (estilo fadidevv/keyhunter), carving de chaves PEM/JWK/alta entropia, mascaramento automático SHA-256 e catálogo KeyHacks.
                  </span>
                </div>
                <select
                  value={d().executionMode}
                  class={`${INPUT_CLS} !w-auto`}
                  onChange={(e) =>
                    wb.updateDraft("key-hunter", (p) => ({
                      ...p,
                      executionMode: e.currentTarget.value as "manual" | "proposed",
                    }))
                  }
                >
                  <option value="manual">Manual Direto</option>
                  <option value="proposed">Propor p/ Aprovação</option>
                </select>
              </div>

              <div class="grid grid-cols-1 gap-2.5 md:grid-cols-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>1. Caminho no Workspace / Binário / .apk / .env (Opcional)</label>
                  <input
                    type="text"
                    value={d().subpath}
                    placeholder="Ex: . , src/ , .env , app-release.apk (vazio para ignorar disco)"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("key-hunter", (p) => ({ ...p, subpath: e.currentTarget.value }))}
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>2. URL Alvo Web & JS Bundles no Escopo (Opcional)</label>
                  <input
                    type="text"
                    value={d().targetUrl}
                    placeholder="Ex: http://127.0.0.1:4096 (extrai HTML + <script src='...'>)"
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("key-hunter", (p) => ({ ...p, targetUrl: e.currentTarget.value }))}
                  />
                </div>
              </div>

              <div class="grid grid-cols-1 gap-2.5 md:grid-cols-2">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>3. GitHub Autorizado — Org ou Owner/Repo (Opcional)</label>
                  <input
                    type="text"
                    value={d().githubRepoOrOrg}
                    placeholder="Ex: minha-org ou usuario/meu-repo (usa GITHUB_TOKEN)"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("key-hunter", (p) => ({ ...p, githubRepoOrOrg: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Query GitHub Code Search (Quando Repo/Org definido)</label>
                  <input
                    type="text"
                    value={d().githubQuery}
                    placeholder="(T3BlbkFJ OR sk-ant-api03 OR sk_live_ OR AKIA)"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("key-hunter", (p) => ({ ...p, githubQuery: e.currentTarget.value }))
                    }
                  />
                </div>
              </div>

              <div class="flex flex-col gap-1">
                <div class="flex flex-wrap items-center justify-between gap-1">
                  <label class={LABEL_CLS}>4. Buffer / Resposta HTTP / Dump de Strings Colado (Opcional)</label>
                  <button
                    type="button"
                    class={CHIP_CLS}
                    onClick={() =>
                      wb.updateDraft("key-hunter", (p) => ({
                        ...p,
                        subpath: "",
                        rawText: [
                          "# Exemplo de buffer misto (1 placeholder filtrado + chaves de teste sintéticas):",
                          "OPENAI_EXAMPLE=sk-proj-YOUR_API_KEY_HERE_XXXXXXXXXXXX",
                          "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REAL987",
                          "GITHUB_TOKEN=ghp_9Km2Pq8Vx4Lz7Bn3Rt6Yw1Jc5Hd8Gf0Sa2Ue",
                        ].join("\n"),
                      }))
                    }
                  >
                    Carregar Exemplo Anti-Placeholder
                  </button>
                </div>
                <textarea
                  rows={3}
                  value={d().rawText}
                  placeholder="Cole aqui arquivos .env, bundles JavaScript minificados, logs HTTP, JSON ou dumps de memória..."
                  class={`${MONO_INPUT_CLS} resize-y`}
                  onInput={(e) => wb.updateDraft("key-hunter", (p) => ({ ...p, rawText: e.currentTarget.value }))}
                />
              </div>

              <div class="grid grid-cols-1 gap-2.5 md:grid-cols-3">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Filtro de Provedores / Categorias</label>
                  <input
                    type="text"
                    value={d().providerFilter}
                    placeholder="all, openai, anthropic, aws, stripe..."
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("key-hunter", (p) => ({ ...p, providerFilter: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx. Ficheiros no Workspace (1–1000)</label>
                  <input
                    type="number"
                    min={1}
                    max={1000}
                    value={d().maxFiles}
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("key-hunter", (p) => ({ ...p, maxFiles: Number(e.currentTarget.value) }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Máx. JS Bundles Remotos (0–30)</label>
                  <input
                    type="number"
                    min={0}
                    max={30}
                    value={d().maxRemoteScripts}
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("key-hunter", (p) => ({
                        ...p,
                        maxRemoteScripts: Number(e.currentTarget.value),
                      }))
                    }
                  />
                </div>
              </div>

              <div class="flex flex-wrap items-center gap-1.5">
                <span class="text-[11px] text-v2-text-text-muted">Presets de Categoria:</span>
                <For each={providerPresets}>
                  {(preset) => (
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() => wb.updateDraft("key-hunter", (p) => ({ ...p, providerFilter: preset.value }))}
                    >
                      {preset.label}
                    </button>
                  )}
                </For>
              </div>

              <div class="grid grid-cols-1 gap-2 sm:grid-cols-3 rounded-md border border-v2-border-border-base bg-v2-background-bg-base/60 p-2.5 text-[12px]">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().skipPlaceholders}
                    onChange={(e) =>
                      wb.updateDraft("key-hunter", (p) => ({ ...p, skipPlaceholders: e.currentTarget.checked }))
                    }
                  />
                  <span>Filtrar Placeholders / Exemplos (Anti-FP)</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().carveCryptoMaterial}
                    onChange={(e) =>
                      wb.updateDraft("key-hunter", (p) => ({ ...p, carveCryptoMaterial: e.currentTarget.checked }))
                    }
                  />
                  <span>Carving PEM / JWK / JWT / Alta Entropia</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().verifyActive}
                    onChange={(e) =>
                      wb.updateDraft("key-hunter", (p) => ({ ...p, verifyActive: e.currentTarget.checked }))
                    }
                  />
                  <span class="text-amber-300">Verificar Chaves Ativas (Read-Only Opt-In)</span>
                </label>
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("key-hunter", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("key-hunter", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("key-hunter")}
                >
                  {isRunning() ? "Caçando Chaves & Segredos..." : "Executar Key Hunter"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("key-hunter")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>

      {/* ==================================================================
          EXTERNAL KEYHUNTER RUST CLI BRIDGE (fadidevv/keyhunter — MIT)
         ================================================================== */}
      <Match when={toolId() === "keyhunter-cli"}>
        {(() => {
          const d = () => wb.drafts["keyhunter-cli"]
          const providerChips = [
            "openai",
            "anthropic",
            "google_ai",
            "grok",
            "deepseek",
            "groq",
            "huggingface",
            "aws",
            "stripe_live",
            "github",
            "slack",
          ]
          return (
            <div class="flex flex-col gap-3">
              <ExternalBinaryBadge wb={wb} toolId="keyhunter" />
              <div class="flex flex-wrap items-center justify-between gap-2 rounded-md border border-v2-border-border-base bg-v2-background-bg-base/70 px-3 py-2 text-[12px]">
                <div class="flex flex-col">
                  <strong class="text-v2-text-text-strong">
                    KeyHunter Rust CLI Bridge (fadidevv/keyhunter — MIT)
                  </strong>
                  <span class="text-[11px] text-v2-text-text-muted">
                    Invoca o binário externo <code>keyhunter</code> (<code>cargo install github-keyhunter</code>) via <code>shell=false</code> com redação automática e custódia SHA-256.
                  </span>
                </div>
                <select
                  value={d().executionMode}
                  class={`${INPUT_CLS} !w-auto`}
                  onChange={(e) =>
                    wb.updateDraft("keyhunter-cli", (p) => ({
                      ...p,
                      executionMode: e.currentTarget.value as "manual" | "proposed",
                    }))
                  }
                >
                  <option value="manual">Manual Direto</option>
                  <option value="proposed">Propor p/ Aprovação</option>
                </select>
              </div>

              <div class="grid grid-cols-1 gap-2.5 md:grid-cols-3">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Subcomando KeyHunter</label>
                  <select
                    value={d().subcommand}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("keyhunter-cli", (p) => ({
                        ...p,
                        subcommand: e.currentTarget.value as "scan" | "verify" | "patterns",
                      }))
                    }
                  >
                    <option value="scan">scan (Buscar chaves no GitHub)</option>
                    <option value="verify">verify (Verificar arquivo JSON salvo)</option>
                    <option value="patterns">patterns (Listar provedores & regexes)</option>
                  </select>
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Provedor (-p)</label>
                  <input
                    type="text"
                    value={d().provider}
                    placeholder="openai, anthropic, aws, stripe_live (vazio = todos)"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("keyhunter-cli", (p) => ({ ...p, provider: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Formato de Saída (-o)</label>
                  <select
                    value={d().outputFormat}
                    class={INPUT_CLS}
                    onChange={(e) =>
                      wb.updateDraft("keyhunter-cli", (p) => ({
                        ...p,
                        outputFormat: e.currentTarget.value as "json" | "table" | "csv",
                      }))
                    }
                  >
                    <option value="json">json (Recomendado)</option>
                    <option value="table">table</option>
                    <option value="csv">csv</option>
                  </select>
                </div>
              </div>

              <div class="flex flex-wrap items-center gap-1.5">
                <span class="text-[11px] text-v2-text-text-muted">Provedores rápidos (-p):</span>
                <For each={providerChips}>
                  {(prov) => (
                    <button
                      type="button"
                      class={CHIP_CLS}
                      onClick={() => wb.updateDraft("keyhunter-cli", (p) => ({ ...p, provider: prov }))}
                    >
                      {prov}
                    </button>
                  )}
                </For>
              </div>

              <div class="grid grid-cols-1 gap-2.5 md:grid-cols-3">
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Query Customizada (-q, Opcional)</label>
                  <input
                    type="text"
                    value={d().query}
                    placeholder='Ex: OPENAI_API_KEY filename:.env'
                    class={MONO_INPUT_CLS}
                    onInput={(e) => wb.updateDraft("keyhunter-cli", (p) => ({ ...p, query: e.currentTarget.value }))}
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>Arquivo Config (-c, Opcional)</label>
                  <input
                    type="text"
                    value={d().configPath}
                    placeholder="config.toml"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("keyhunter-cli", (p) => ({ ...p, configPath: e.currentTarget.value }))
                    }
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <label class={LABEL_CLS}>JSON p/ Verify (-i, Modo verify)</label>
                  <input
                    type="text"
                    value={d().inputFindingsPath}
                    placeholder="results/findings.json"
                    class={MONO_INPUT_CLS}
                    onInput={(e) =>
                      wb.updateDraft("keyhunter-cli", (p) => ({ ...p, inputFindingsPath: e.currentTarget.value }))
                    }
                  />
                </div>
              </div>

              <div class="flex flex-wrap items-center gap-4 rounded-md border border-v2-border-border-base bg-v2-background-bg-base/60 p-2.5 text-[12px]">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().verifiedOnly}
                    onChange={(e) =>
                      wb.updateDraft("keyhunter-cli", (p) => ({ ...p, verifiedOnly: e.currentTarget.checked }))
                    }
                  />
                  <span>Modo Verified-Only (-V: somente chaves ativas)</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={d().verbose}
                    onChange={(e) =>
                      wb.updateDraft("keyhunter-cli", (p) => ({ ...p, verbose: e.currentTarget.checked }))
                    }
                  />
                  <span>Logs Detalhados (--verbose / -v)</span>
                </label>
              </div>

              <RawJsonOverrideSection
                enabled={d().useRawJson}
                rawJson={d().rawJson}
                onToggle={(v) => wb.updateDraft("keyhunter-cli", (p) => ({ ...p, useRawJson: v }))}
                onChange={(v) => wb.updateDraft("keyhunter-cli", (p) => ({ ...p, rawJson: v }))}
              />

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isRunning()}
                  class={BTN_PRIMARY}
                  onClick={() => void wb.runCapabilityTool("keyhunter-cli")}
                >
                  {isRunning() ? "Executando keyhunter CLI..." : "Executar KeyHunter Rust CLI"}
                </button>
                <button type="button" class={BTN_SECONDARY} onClick={() => wb.resetToolDraft("keyhunter-cli")}>
                  Restaurar Padrão
                </button>
              </div>
            </div>
          )
        })()}
      </Match>
    </Switch>
  )
}
