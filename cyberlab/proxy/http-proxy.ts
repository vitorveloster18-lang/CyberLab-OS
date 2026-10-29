import crypto from "node:crypto"
import http from "node:http"
import https from "node:https"
import net from "node:net"
import path from "node:path"
import tls from "node:tls"
import zlib from "node:zlib"
import type { Duplex } from "node:stream"
import type { EvidenceStore } from "../evidence/store.js"
import { redactSensitiveContent } from "../evidence/provenance.js"
import { capOutputBytes } from "../execution/cancellation.js"
import { normalizeRawOutputDraft } from "../execution/result-normalizer.js"
import { EngagementRuntime } from "../http/engagement-runtime.js"
import { extractTargetsFromInput, type ScopeController } from "../policy/scope.js"
import {
  detectInstalledProxyBrowsers,
  launchPreconfiguredProxyBrowser,
  type DetectedProxyBrowser,
  type LaunchProxyBrowserResult,
} from "./browser-launcher.js"
import { CyberLabLocalCa } from "./local-ca.js"

const SENSITIVE_PROXY_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "sec-websocket-protocol",
])

const STATIC_ASSET_EXT_RE = /\.(?:woff2?|ttf|otf|eot|png|jpe?g|gif|webp|avif|ico|svg|mp4|webm|mp3|wav|css)(?:\?|$)/i

function redactHeaderMap(raw: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue
    const joined = Array.isArray(v) ? v.join("; ") : v
    out[k] = SENSITIVE_PROXY_HEADERS.has(k.toLowerCase()) ? "[REDACTED:SENSITIVE_HEADER]" : joined
  }
  return out
}

function flattenHeaderMap(raw: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue
    out[k] = Array.isArray(v) ? v.join("; ") : v
  }
  return out
}

function decompressHttpBody(rawBuf: Buffer, contentEncodingHeader?: string | string[]): Buffer {
  const enc = (Array.isArray(contentEncodingHeader) ? contentEncodingHeader[0] : contentEncodingHeader ?? "")
    .trim()
    .toLowerCase()
  if (!enc || rawBuf.byteLength === 0) return rawBuf
  try {
    if (enc.includes("br")) {
      return zlib.brotliDecompressSync(rawBuf)
    }
    if (enc.includes("gzip") || enc.includes("x-gzip")) {
      return zlib.gunzipSync(rawBuf)
    }
    if (enc.includes("deflate")) {
      return zlib.inflateSync(rawBuf)
    }
  } catch {
    return rawBuf
  }
  return rawBuf
}

function decodeWsPreviewFrames(chunk: Buffer): { frames: number; textSample: string } {
  let offset = 0
  let frames = 0
  const snippets: string[] = []
  while (offset + 2 <= chunk.length && frames < 12) {
    const b0 = chunk[offset]!
    const b1 = chunk[offset + 1]!
    const opcode = b0 & 0x0f
    const masked = (b1 & 0x80) !== 0
    let payloadLen = b1 & 0x7f
    let headerLen = 2
    if (payloadLen === 126) {
      if (offset + 4 > chunk.length) break
      payloadLen = chunk.readUInt16BE(offset + 2)
      headerLen = 4
    } else if (payloadLen === 127) {
      break
    }
    const maskKeyOffset = headerLen
    if (masked) headerLen += 4
    if (offset + headerLen + payloadLen > chunk.length || payloadLen > 8192) break

    const rawPayload = Buffer.from(chunk.subarray(offset + headerLen, offset + headerLen + payloadLen))
    if (masked) {
      const mask = chunk.subarray(offset + maskKeyOffset, offset + maskKeyOffset + 4)
      for (let i = 0; i < rawPayload.length; i++) {
        rawPayload[i] = rawPayload[i]! ^ mask[i % 4]!
      }
    }
    frames++
    if (opcode === 0x01 && rawPayload.length > 0) {
      snippets.push(rawPayload.toString("utf8").slice(0, 320))
    }
    offset += headerLen + payloadLen
  }
  return { frames, textSample: snippets.join(" | ") }
}

function escapeShellSingleQuote(val: string): string {
  return `'${val.replace(/'/g, `'\\''`)}'`
}

function buildCurlCommand(method: string, url: string, headers: Record<string, string>, body: string): string {
  const parts: string[] = [`curl -i -s -k -X ${method}`]
  for (const [k, v] of Object.entries(headers)) {
    const lower = k.toLowerCase()
    if (lower === "content-length" || lower === "host" || lower === "connection") continue
    parts.push(`-H ${escapeShellSingleQuote(`${k}: ${v}`)}`)
  }
  if (body && method !== "GET" && method !== "HEAD") {
    parts.push(`--data-raw ${escapeShellSingleQuote(body)}`)
  }
  parts.push(escapeShellSingleQuote(url))
  return parts.join(" \\\n  ")
}

function buildRawHttpRequest(method: string, targetUrl: URL, headers: Record<string, string>, body: string): string {
  const lines: string[] = [`${method} ${targetUrl.pathname}${targetUrl.search} HTTP/1.1`]
  const hasHost = Object.keys(headers).some((k) => k.toLowerCase() === "host")
  if (!hasHost) {
    lines.push(`Host: ${targetUrl.host}`)
  }
  for (const [k, v] of Object.entries(headers)) {
    lines.push(`${k}: ${v}`)
  }
  lines.push("", body)
  return lines.join("\r\n")
}

export type ProxyHttpsMode = "tls_intercept" | "tunnel_passthrough"

export type MatchReplaceLocation =
  | "url"
  | "request_header"
  | "request_body"
  | "response_header"
  | "response_body"

export interface ProxyMatchReplaceRule {
  ruleId: string
  enabled: boolean
  location: MatchReplaceLocation
  headerName?: string
  matchPattern: string
  replaceWith: string
  isRegex: boolean
  comment?: string
}

export interface ProxyInterceptItem {
  interceptId: string
  phase: "request" | "response"
  createdAt: string
  protocol: "http" | "https"
  method: string
  url: string
  host: string
  path: string
  headers: Record<string, string>
  body: string
  statusCode?: number
}

export interface ProxyInterceptResolution {
  interceptId: string
  decision: "forward" | "drop"
  method?: string
  url?: string
  headers?: Record<string, string>
  body?: string
  statusCode?: number
}

export interface SiteMapEndpointNode {
  path: string
  methods: string[]
  statusCodes: number[]
  mimeTypes: string[]
  paramNames: string[]
  hitCount: number
  lastSeenAt: string
  sampleEntryId: string
}

export interface SiteMapHostNode {
  host: string
  scheme: "http" | "https" | "ws" | "wss"
  inScope: boolean
  requestCount: number
  passiveAlertCount: number
  endpoints: SiteMapEndpointNode[]
}

export interface PassiveProxyAlert {
  alertId: string
  timestamp: string
  severity: "info" | "low" | "medium" | "high"
  category: string
  title: string
  host: string
  url: string
  evidenceSnippet: string
  entryId: string
}

export interface OastCallbackHit {
  hitId: string
  timestamp: string
  method: string
  path: string
  query: string
  remoteAddress: string
  headers: Record<string, string>
  bodyPreview: string
}

export interface ProxyReplayBundle {
  entryId: string
  method: string
  url: string
  headers: Record<string, string>
  body: string
  responseStatusCode: number
  responseHeaders: Record<string, string>
  responseBody: string
  rawHttpRequest: string
  curlCommand: string
}

export interface ProxyHistoryEntry {
  entryId: string
  timestamp: string
  protocol?: "http" | "https" | "ws" | "wss" | "connect_tunnel"
  method: string
  url: string
  host: string
  path: string
  statusCode: number
  mimeType?: string
  elapsedMs: number
  requestHeaders: Record<string, string>
  requestBody: string
  responseHeaders: Record<string, string>
  responseBody: string
  responseBytes: number
  blockedByScope: boolean
  blockReason?: string
  modifiedByRuleOrIntercept?: boolean
  passiveAlertCount?: number
  persistedEvidenceId?: string
}

export interface ProxyStatus {
  running: boolean
  listenHost: string
  listenPort: number | null
  scopeOnly: boolean
  httpsMode: ProxyHttpsMode
  allowSelfSignedUpstream: boolean
  interceptEnabled: boolean
  interceptResponses: boolean
  interceptInScopeOnly: boolean
  skipStaticAssets: boolean
  pendingInterceptCount: number
  matchReplaceRuleCount: number
  siteMapHostCount: number
  passiveAlertCount: number
  oastRunning: boolean
  oastListenPort: number | null
  oastCallbackBaseUrl: string | null
  externalOastDomain: string | null
  oastHitCount: number
  caFingerprintSha256: string
  caSpkiSha256Base64: string
  caCertPath: string | null
  caCertPem: string
  availableBrowsers: DetectedProxyBrowser[]
  capturedCount: number
}

interface PendingInterceptRecord {
  item: ProxyInterceptItem
  timer: ReturnType<typeof setTimeout>
  resolve: (resolution: ProxyInterceptResolution) => void
}

interface StoredRawReplay {
  method: string
  url: string
  requestHeaders: Record<string, string>
  requestBody: string
  responseStatusCode: number
  responseHeaders: Record<string, string>
  responseBody: string
}

export class CyberLabHttpProxy {
  private server: http.Server | null = null
  private listenPort: number | null = null
  private scopeOnly = true
  private httpsMode: ProxyHttpsMode = "tls_intercept"
  private allowSelfSignedUpstream = true
  private interceptEnabled = false
  private interceptResponses = false
  private interceptInScopeOnly = true
  private skipStaticAssets = true
  private readonly pendingIntercepts = new Map<string, PendingInterceptRecord>()
  private readonly matchReplaceRules: ProxyMatchReplaceRule[] = []
  private readonly localCa: CyberLabLocalCa
  private readonly history: ProxyHistoryEntry[] = []
  private readonly rawReplayVault = new Map<string, StoredRawReplay>()
  private readonly passiveAlerts: PassiveProxyAlert[] = []
  private readonly seenPassiveAlertKeys = new Set<string>()
  private readonly siteMapHosts = new Map<
    string,
    {
      host: string
      scheme: "http" | "https" | "ws" | "wss"
      requestCount: number
      endpoints: Map<
        string,
        {
          path: string
          methods: Set<string>
          statusCodes: Set<number>
          mimeTypes: Set<string>
          paramNames: Set<string>
          hitCount: number
          lastSeenAt: string
          sampleEntryId: string
        }
      >
    }
  >()
  private oastServer: http.Server | null = null
  private oastPort: number | null = null
  private externalOastDomain: string | null = null
  private readonly oastHits: OastCallbackHit[] = []
  private readonly maxEntries: number
  private mitmHttpsServer: https.Server | null = null
  private mitmHttpsPort: number | null = null
  private readonly mitmTunnelOrigins = new Map<number, { hostOnly: string; mitmOrigin: string }>()
  private cachedBrowsers: DetectedProxyBrowser[] | null = null

  constructor(
    private readonly deps: {
      projectId: string
      scopes: ScopeController
      evidenceStore: EvidenceStore
      workspaceRoot?: string
      maxEntries?: number
    },
  ) {
    this.maxEntries = deps.maxEntries ?? 1000
    const caDirectory = deps.workspaceRoot ? path.join(deps.workspaceRoot, ".cyberlab", "ca") : undefined
    this.localCa = new CyberLabLocalCa({ caDirectory })
  }

  getCaBundle(): { certPem: string; fingerprintSha256: string; spkiSha256Base64: string; certPath: string | null } {
    return this.localCa.getBundleInfo()
  }

  private getBrowsersCached(): DetectedProxyBrowser[] {
    if (!this.cachedBrowsers) {
      this.cachedBrowsers = detectInstalledProxyBrowsers()
    }
    return this.cachedBrowsers
  }

  getStatus(): ProxyStatus {
    const ca = this.localCa.getBundleInfo()
    return {
      running: this.server !== null,
      listenHost: "127.0.0.1",
      listenPort: this.listenPort,
      scopeOnly: this.scopeOnly,
      httpsMode: this.httpsMode,
      allowSelfSignedUpstream: this.allowSelfSignedUpstream,
      interceptEnabled: this.interceptEnabled,
      interceptResponses: this.interceptResponses,
      interceptInScopeOnly: this.interceptInScopeOnly,
      skipStaticAssets: this.skipStaticAssets,
      pendingInterceptCount: this.pendingIntercepts.size,
      matchReplaceRuleCount: this.matchReplaceRules.filter((r) => r.enabled).length,
      siteMapHostCount: this.siteMapHosts.size,
      passiveAlertCount: this.passiveAlerts.length,
      oastRunning: this.oastServer !== null,
      oastListenPort: this.oastPort,
      oastCallbackBaseUrl: this.oastPort ? `http://127.0.0.1:${this.oastPort}` : null,
      externalOastDomain: this.externalOastDomain,
      oastHitCount: this.oastHits.length,
      caFingerprintSha256: ca.fingerprintSha256,
      caSpkiSha256Base64: ca.spkiSha256Base64,
      caCertPath: ca.certPath,
      caCertPem: ca.certPem,
      availableBrowsers: this.getBrowsersCached(),
      capturedCount: this.history.length,
    }
  }

  listHistory(): ProxyHistoryEntry[] {
    return [...this.history].reverse()
  }

  clearHistory(): void {
    this.history.length = 0
    this.rawReplayVault.clear()
    this.siteMapHosts.clear()
    this.passiveAlerts.length = 0
    this.seenPassiveAlertKeys.clear()
  }

  exportEntryForReplay(entryId: string): ProxyReplayBundle {
    const raw = this.rawReplayVault.get(entryId)
    const entry = this.history.find((h) => h.entryId === entryId)
    if (!entry && !raw) {
      throw new Error(`Proxy history entry "${entryId}" not found`)
    }
    const method = raw?.method ?? entry!.method
    const url = raw?.url ?? entry!.url
    const headers = raw ? { ...raw.requestHeaders } : { ...entry!.requestHeaders }
    const body = raw?.requestBody ?? entry!.requestBody
    const responseStatusCode = raw?.responseStatusCode ?? entry!.statusCode
    const responseHeaders = raw ? { ...raw.responseHeaders } : { ...entry!.responseHeaders }
    const responseBody = raw?.responseBody ?? entry!.responseBody
    const parsedUrl = new URL(url)

    return {
      entryId,
      method,
      url,
      headers,
      body,
      responseStatusCode,
      responseHeaders,
      responseBody,
      rawHttpRequest: buildRawHttpRequest(method, parsedUrl, headers, body),
      curlCommand: buildCurlCommand(method, url, headers, body),
    }
  }

  setScopeOnly(scopeOnly: boolean): ProxyStatus {
    this.scopeOnly = scopeOnly
    return this.getStatus()
  }

  setHttpsMode(mode: ProxyHttpsMode, allowSelfSignedUpstream?: boolean): ProxyStatus {
    this.httpsMode = mode
    if (allowSelfSignedUpstream !== undefined) {
      this.allowSelfSignedUpstream = allowSelfSignedUpstream
    }
    return this.getStatus()
  }

  configureIntercept(options: {
    enabled?: boolean
    interceptResponses?: boolean
    inScopeOnly?: boolean
    skipStaticAssets?: boolean
  }): ProxyStatus {
    if (options.interceptResponses !== undefined) {
      this.interceptResponses = options.interceptResponses
    }
    if (options.inScopeOnly !== undefined) {
      this.interceptInScopeOnly = options.inScopeOnly
    }
    if (options.skipStaticAssets !== undefined) {
      this.skipStaticAssets = options.skipStaticAssets
    }
    if (options.enabled !== undefined) {
      this.interceptEnabled = options.enabled
      if (!options.enabled) {
        this.forwardAllIntercepts()
      }
    }
    return this.getStatus()
  }

  listInterceptQueue(): ProxyInterceptItem[] {
    return Array.from(this.pendingIntercepts.values()).map((r) => ({
      ...r.item,
      headers: { ...r.item.headers },
    }))
  }

  resolveIntercept(resolution: ProxyInterceptResolution): boolean {
    const rec = this.pendingIntercepts.get(resolution.interceptId)
    if (!rec) return false
    clearTimeout(rec.timer)
    this.pendingIntercepts.delete(resolution.interceptId)
    rec.resolve(resolution)
    return true
  }

  forwardAllIntercepts(): number {
    let count = 0
    for (const [id, rec] of this.pendingIntercepts.entries()) {
      clearTimeout(rec.timer)
      this.pendingIntercepts.delete(id)
      rec.resolve({ interceptId: id, decision: "forward" })
      count++
    }
    return count
  }

  dropAllIntercepts(): number {
    let count = 0
    for (const [id, rec] of this.pendingIntercepts.entries()) {
      clearTimeout(rec.timer)
      this.pendingIntercepts.delete(id)
      rec.resolve({ interceptId: id, decision: "drop" })
      count++
    }
    return count
  }

  listMatchReplaceRules(): ProxyMatchReplaceRule[] {
    return this.matchReplaceRules.map((r) => ({ ...r }))
  }

  upsertMatchReplaceRule(rule: Omit<ProxyMatchReplaceRule, "ruleId"> & { ruleId?: string }): ProxyMatchReplaceRule {
    const ruleId = rule.ruleId?.trim() || `mr-${crypto.randomUUID().slice(0, 8)}`
    const clean: ProxyMatchReplaceRule = {
      ruleId,
      enabled: rule.enabled,
      location: rule.location,
      ...(rule.headerName?.trim() ? { headerName: rule.headerName.trim() } : {}),
      matchPattern: rule.matchPattern,
      replaceWith: rule.replaceWith,
      isRegex: rule.isRegex,
      ...(rule.comment?.trim() ? { comment: rule.comment.trim() } : {}),
    }
    const idx = this.matchReplaceRules.findIndex((r) => r.ruleId === ruleId)
    if (idx !== -1) {
      this.matchReplaceRules[idx] = clean
    } else {
      this.matchReplaceRules.push(clean)
    }
    return { ...clean }
  }

  removeMatchReplaceRule(ruleId: string): boolean {
    const idx = this.matchReplaceRules.findIndex((r) => r.ruleId === ruleId)
    if (idx === -1) return false
    this.matchReplaceRules.splice(idx, 1)
    return true
  }

  getSiteMap(): { hosts: SiteMapHostNode[]; passiveAlerts: PassiveProxyAlert[] } {
    const hosts: SiteMapHostNode[] = []
    for (const h of this.siteMapHosts.values()) {
      const check = this.deps.scopes.verifyTargets(
        this.deps.projectId,
        extractTargetsFromInput({ url: `${h.scheme === "https" || h.scheme === "wss" ? "https" : "http"}://${h.host}/` }),
        ["url_origin"],
      )
      const hostAlerts = this.passiveAlerts.filter((a) => a.host === h.host).length
      const endpoints: SiteMapEndpointNode[] = Array.from(h.endpoints.values())
        .map((ep) => ({
          path: ep.path,
          methods: Array.from(ep.methods),
          statusCodes: Array.from(ep.statusCodes),
          mimeTypes: Array.from(ep.mimeTypes),
          paramNames: Array.from(ep.paramNames),
          hitCount: ep.hitCount,
          lastSeenAt: ep.lastSeenAt,
          sampleEntryId: ep.sampleEntryId,
        }))
        .sort((a, b) => a.path.localeCompare(b.path))

      hosts.push({
        host: h.host,
        scheme: h.scheme,
        inScope: check.allowed,
        requestCount: h.requestCount,
        passiveAlertCount: hostAlerts,
        endpoints,
      })
    }
    hosts.sort((a, b) => Number(b.inScope) - Number(a.inScope) || b.requestCount - a.requestCount)
    return {
      hosts,
      passiveAlerts: [...this.passiveAlerts].reverse(),
    }
  }

  async startOastListener(port = 0, externalDomain?: string): Promise<ProxyStatus> {
    if (externalDomain !== undefined) {
      this.externalOastDomain = externalDomain.trim() || null
    }
    if (this.oastServer) {
      return this.getStatus()
    }
    const srv = http.createServer(async (req, res) => {
      const chunks: Buffer[] = []
      let total = 0
      for await (const c of req) {
        const b = Buffer.isBuffer(c) ? c : Buffer.from(c as Uint8Array)
        total += b.byteLength
        if (total <= 16_384) chunks.push(b)
      }
      const parsed = new URL(req.url ?? "/", "http://127.0.0.1")
      const hit: OastCallbackHit = {
        hitId: `oast-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        method: (req.method ?? "GET").toUpperCase(),
        path: parsed.pathname,
        query: parsed.search,
        remoteAddress: req.socket.remoteAddress ?? "unknown",
        headers: redactHeaderMap(req.headers),
        bodyPreview: redactSensitiveContent(Buffer.concat(chunks).toString("utf8").slice(0, 2048)).text,
      }
      this.oastHits.push(hit)
      if (this.oastHits.length > 300) this.oastHits.shift()
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      })
      res.end(JSON.stringify({ ok: true, callbackId: hit.hitId }))
    })

    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject)
      srv.listen(port, "0.0.0.0", () => {
        srv.removeListener("error", reject)
        resolve()
      })
    })
    const addr = srv.address()
    this.oastPort = typeof addr === "object" && addr ? addr.port : port
    this.oastServer = srv
    return this.getStatus()
  }

  async stopOastListener(): Promise<ProxyStatus> {
    if (!this.oastServer) return this.getStatus()
    const srv = this.oastServer
    this.oastServer = null
    this.oastPort = null
    await new Promise<void>((resolve) => srv.close(() => resolve()))
    return this.getStatus()
  }

  listOastHits(): OastCallbackHit[] {
    return [...this.oastHits].reverse()
  }

  clearOastHits(): void {
    this.oastHits.length = 0
  }

  async launchBrowser(options?: {
    startUrl?: string
    preferredBrowserId?: string
    defaultPort?: number
  }): Promise<LaunchProxyBrowserResult> {
    if (!this.server) {
      await this.start({ port: options?.defaultPort ?? 8899 })
    }
    const ca = this.localCa.getBundleInfo()
    return launchPreconfiguredProxyBrowser({
      proxyPort: this.listenPort ?? 8899,
      spkiSha256Base64: ca.spkiSha256Base64,
      workspaceRoot: this.deps.workspaceRoot ?? process.cwd(),
      ...(options?.startUrl ? { startUrl: options.startUrl } : {}),
      ...(options?.preferredBrowserId ? { preferredBrowserId: options.preferredBrowserId } : {}),
    })
  }

  async start(options?: {
    port?: number
    scopeOnly?: boolean
    httpsMode?: ProxyHttpsMode
    allowSelfSignedUpstream?: boolean
  }): Promise<ProxyStatus> {
    if (options?.scopeOnly !== undefined) {
      this.scopeOnly = options.scopeOnly
    }
    if (options?.httpsMode !== undefined) {
      this.httpsMode = options.httpsMode
    }
    if (options?.allowSelfSignedUpstream !== undefined) {
      this.allowSelfSignedUpstream = options.allowSelfSignedUpstream
    }
    if (this.server) {
      return this.getStatus()
    }

    const requestedPort = options?.port ?? 8899
    const defaultLeaf = this.localCa.issueHostCertificate("localhost")
    const mitmSrv = https.createServer(
      {
        key: defaultLeaf.keyPem,
        cert: defaultLeaf.certPem,
        SNICallback: (servername, cb) => {
          const targetHost = (servername || "").trim() || "localhost"
          const leaf = this.localCa.issueHostCertificate(targetHost)
          cb(null, tls.createSecureContext({ key: leaf.keyPem, cert: leaf.certPem }))
        },
      },
      (innerReq, innerRes) => {
        const remotePort = innerReq.socket.remotePort ?? 0
        const mapped = this.mitmTunnelOrigins.get(remotePort)
        const hostHdr = innerReq.headers.host ? String(innerReq.headers.host) : ""
        const fallbackOrigin = hostHdr ? `https://${hostHdr}` : null
        void this.handleProxyRequest(innerReq, innerRes, {
          tlsTerminatedOrigin: mapped?.mitmOrigin ?? fallbackOrigin,
        })
      },
    )

    mitmSrv.on("upgrade", (innerReq, innerSocket, innerHead) => {
      const remotePort = innerReq.socket.remotePort ?? 0
      const mapped = this.mitmTunnelOrigins.get(remotePort)
      const hostHdr = innerReq.headers.host ? String(innerReq.headers.host) : ""
      const fallbackOrigin = hostHdr ? `https://${hostHdr}` : null
      this.handleWebSocketUpgrade(innerReq, innerSocket, innerHead, {
        tlsTerminatedOrigin: mapped?.mitmOrigin ?? fallbackOrigin,
      })
    })
    mitmSrv.on("clientError", (_err, sock) => {
      sock.destroy()
    })

    await new Promise<void>((resolve, reject) => {
      mitmSrv.once("error", reject)
      mitmSrv.listen(0, "127.0.0.1", () => {
        mitmSrv.removeListener("error", reject)
        resolve()
      })
    })
    const mitmAddr = mitmSrv.address()
    this.mitmHttpsServer = mitmSrv
    this.mitmHttpsPort = typeof mitmAddr === "object" && mitmAddr ? mitmAddr.port : null

    const srv = http.createServer((req, res) => {
      void this.handleProxyRequest(req, res, { tlsTerminatedOrigin: null })
    })

    srv.on("connect", (req, clientSocket, head) => {
      this.handleConnectTunnel(req, clientSocket, head)
    })

    srv.on("upgrade", (req, clientSocket, head) => {
      this.handleWebSocketUpgrade(req, clientSocket, head, { tlsTerminatedOrigin: null })
    })

    try {
      await new Promise<void>((resolve, reject) => {
        srv.once("error", reject)
        srv.listen(requestedPort, "127.0.0.1", () => {
          srv.removeListener("error", reject)
          resolve()
        })
      })
    } catch (err) {
      mitmSrv.close()
      this.mitmHttpsServer = null
      this.mitmHttpsPort = null
      throw err
    }

    const addr = srv.address()
    this.listenPort = typeof addr === "object" && addr ? addr.port : requestedPort
    this.server = srv
    return this.getStatus()
  }

  async stop(): Promise<ProxyStatus> {
    this.dropAllIntercepts()
    if (this.oastServer) {
      await this.stopOastListener()
    }
    if (!this.server) {
      return this.getStatus()
    }
    const srv = this.server
    const mitmSrv = this.mitmHttpsServer
    this.server = null
    this.listenPort = null
    this.mitmHttpsServer = null
    this.mitmHttpsPort = null
    this.mitmTunnelOrigins.clear()
    await new Promise<void>((resolve) => srv.close(() => resolve()))
    if (mitmSrv) {
      await new Promise<void>((resolve) => mitmSrv.close(() => resolve()))
    }
    return this.getStatus()
  }

  persistEntryToEvidence(entryId: string, actor = "operator:proxy"): { evidenceId: string; sha256: string } {
    const entry = this.history.find((h) => h.entryId === entryId)
    if (!entry) {
      throw new Error(`Proxy history entry "${entryId}" not found`)
    }
    const transcript = [
      `=== PROXY CAPTURE (${entry.timestamp}) [${entry.protocol ?? "http"}] ===`,
      `${entry.method} ${entry.url}`,
      ...Object.entries(entry.requestHeaders).map(([k, v]) => `${k}: ${v}`),
      "",
      entry.requestBody,
      "",
      `=== RESPONSE: HTTP ${entry.statusCode} (${entry.elapsedMs}ms, ${entry.responseBytes} bytes) ===`,
      ...Object.entries(entry.responseHeaders).map(([k, v]) => `${k}: ${v}`),
      "",
      entry.responseBody,
    ].join("\n")

    const redacted = redactSensitiveContent(transcript)
    const draft = {
      ...normalizeRawOutputDraft({
        kind: "http_exchange",
        title: `Proxy Capture ${entry.method} ${entry.host}${entry.path} -> ${entry.statusCode}`,
        rawText: redacted.text,
        mediaType: "text/plain; charset=utf-8",
        toolId: "cyberlab-http-proxy",
        toolVersion: "4.0.0",
        executorId: "cyberlab-http-proxy",
        executionId: `proxy-${entry.entryId}`,
        maxOutputBytes: 512 * 1024,
        labels: [
          "proxy-history",
          `protocol:${entry.protocol ?? "http"}`,
          ...(entry.blockedByScope ? ["blocked-by-scope"] : ["in-scope"]),
        ],
      }),
      redactionApplied: redacted.redacted || true,
    }

    const stored = this.deps.evidenceStore.storeEvidence(this.deps.projectId, draft, { actor })
    entry.persistedEvidenceId = stored.evidenceId
    return {
      evidenceId: stored.evidenceId,
      sha256: stored.integrity.sha256,
    }
  }

  private pushEntry(entry: ProxyHistoryEntry, rawReplay?: StoredRawReplay): void {
    this.history.push(entry)
    if (rawReplay) {
      this.rawReplayVault.set(entry.entryId, rawReplay)
    }
    if (this.history.length > this.maxEntries) {
      const evicted = this.history.shift()
      if (evicted) {
        this.rawReplayVault.delete(evicted.entryId)
      }
    }
  }

  private recordInSiteMapAndPassiveScan(params: {
    entryId: string
    scheme: "http" | "https" | "ws" | "wss"
    targetUrl: URL
    method: string
    statusCode: number
    requestBody: string
    responseHeaders: Record<string, string>
    responseBodyText: string
  }): number {
    const hostKey = params.targetUrl.host.toLowerCase()
    let hostNode = this.siteMapHosts.get(hostKey)
    if (!hostNode) {
      hostNode = {
        host: hostKey,
        scheme: params.scheme,
        requestCount: 0,
        endpoints: new Map(),
      }
      this.siteMapHosts.set(hostKey, hostNode)
    }
    hostNode.requestCount++

    const epPath = params.targetUrl.pathname || "/"
    let ep = hostNode.endpoints.get(epPath)
    if (!ep) {
      ep = {
        path: epPath,
        methods: new Set(),
        statusCodes: new Set(),
        mimeTypes: new Set(),
        paramNames: new Set(),
        hitCount: 0,
        lastSeenAt: new Date().toISOString(),
        sampleEntryId: params.entryId,
      }
      hostNode.endpoints.set(epPath, ep)
    }
    ep.hitCount++
    ep.lastSeenAt = new Date().toISOString()
    ep.sampleEntryId = params.entryId
    ep.methods.add(params.method)
    ep.statusCodes.add(params.statusCode)

    const ctHeader =
      Object.entries(params.responseHeaders).find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? ""
    const mimeOnly = ctHeader.split(";")[0]?.trim().toLowerCase()
    if (mimeOnly) ep.mimeTypes.add(mimeOnly)

    for (const qKey of params.targetUrl.searchParams.keys()) {
      if (qKey) ep.paramNames.add(qKey)
    }
    if (params.requestBody.trim().startsWith("{")) {
      try {
        const parsedBody = JSON.parse(params.requestBody) as Record<string, unknown>
        if (parsedBody && typeof parsedBody === "object" && !Array.isArray(parsedBody)) {
          for (const k of Object.keys(parsedBody).slice(0, 25)) ep.paramNames.add(k)
        }
      } catch {
        // Ignore non-JSON
      }
    }

    // Passive security checks
    let newAlertsForEntry = 0
    const addAlert = (
      dedupKey: string,
      severity: PassiveProxyAlert["severity"],
      category: string,
      title: string,
      evidenceSnippet: string,
    ) => {
      const fullKey = `${hostKey}:${epPath}:${dedupKey}`
      if (this.seenPassiveAlertKeys.has(fullKey)) return
      this.seenPassiveAlertKeys.add(fullKey)
      newAlertsForEntry++
      this.passiveAlerts.push({
        alertId: `pal-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        severity,
        category,
        title,
        host: hostKey,
        url: params.targetUrl.toString(),
        evidenceSnippet: redactSensitiveContent(evidenceSnippet).text.slice(0, 260),
        entryId: params.entryId,
      })
      if (this.passiveAlerts.length > 500) {
        this.passiveAlerts.shift()
      }
    }

    const lowerHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(params.responseHeaders)) {
      lowerHeaders[k.toLowerCase()] = v
    }

    if (params.scheme === "https" && params.statusCode >= 200 && params.statusCode < 400) {
      if (!lowerHeaders["strict-transport-security"]) {
        addAlert(
          "missing-hsts",
          "low",
          "TLS / Headers",
          "Ausência de Strict-Transport-Security (HSTS) em resposta HTTPS",
          `HTTP ${params.statusCode} sem cabeçalho Strict-Transport-Security`,
        )
      }
    }

    const setCookieVal = lowerHeaders["set-cookie"]
    if (setCookieVal) {
      if (!/httponly/i.test(setCookieVal)) {
        addAlert(
          "cookie-no-httponly",
          "medium",
          "Session Hygiene",
          "Cookie definido sem flag HttpOnly",
          setCookieVal.slice(0, 140),
        )
      }
      if (params.scheme === "https" && !/;\s*secure/i.test(setCookieVal)) {
        addAlert(
          "cookie-no-secure",
          "medium",
          "Session Hygiene",
          "Cookie em HTTPS definido sem flag Secure",
          setCookieVal.slice(0, 140),
        )
      }
    }

    const acao = lowerHeaders["access-control-allow-origin"]
    const acac = lowerHeaders["access-control-allow-credentials"]
    if (acao && acac?.toLowerCase() === "true") {
      addAlert(
        `cors-creds-${acao}`,
        acao === "*" ? "high" : "medium",
        "CORS Policy",
        "CORS com Access-Control-Allow-Credentials: true detectado",
        `Access-Control-Allow-Origin: ${acao} | Allow-Credentials: true`,
      )
    }

    const bodySample = params.responseBodyText.slice(0, 65_536)
    if (bodySample) {
      const secretHit =
        /\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-proj-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|AIzaSy[A-Za-z0-9_-]{33})\b/.exec(
          bodySample,
        )
      if (secretHit?.[1]) {
        const masked = `${secretHit[1].slice(0, 6)}...${secretHit[1].slice(-4)}`
        addAlert(
          `secret-${secretHit[1].slice(0, 8)}`,
          "high",
          "Exposed Secret",
          "Possível chave de API / token exposto em resposta HTTP/JS",
          `Padrão detectado no corpo da resposta: ${masked}`,
        )
      }
      if (/\/\/[#@]\s*sourceMappingURL=([^\s]+)/.test(bodySample)) {
        const sm = /\/\/[#@]\s*sourceMappingURL=([^\s]+)/.exec(bodySample)?.[1] ?? ""
        addAlert(
          "sourcemap-exposed",
          "info",
          "Information Disclosure",
          "Referência SourceMap (.js.map) exposta em bundle JavaScript",
          `sourceMappingURL=${sm}`,
        )
      }
      if (
        /(?:SQL syntax.*MySQL|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBCDriver|Traceback \(most recent call last\)|UnhandledPromiseRejection)/i.test(
          bodySample,
        )
      ) {
        addAlert(
          "stack-or-sql-error",
          "medium",
          "Error Leakage",
          "Vazamento de erro interno de banco de dados / stack trace",
          bodySample.slice(0, 200),
        )
      }
    }

    return newAlertsForEntry
  }

  private applyMatchReplaceToString(
    input: string,
    location: MatchReplaceLocation,
  ): { value: string; changed: boolean } {
    let current = input
    let changed = false
    for (const rule of this.matchReplaceRules) {
      if (!rule.enabled || rule.location !== location || !rule.matchPattern) continue
      const before = current
      if (rule.isRegex) {
        try {
          const rx = new RegExp(rule.matchPattern, "g")
          current = current.replace(rx, rule.replaceWith)
        } catch {
          continue
        }
      } else {
        current = current.split(rule.matchPattern).join(rule.replaceWith)
      }
      if (current !== before) changed = true
    }
    return { value: current, changed }
  }

  private applyMatchReplaceToHeaders(
    headers: Record<string, string>,
    location: "request_header" | "response_header",
  ): { headers: Record<string, string>; changed: boolean } {
    const out: Record<string, string> = { ...headers }
    let changed = false
    for (const rule of this.matchReplaceRules) {
      if (!rule.enabled || rule.location !== location) continue
      if (rule.headerName && !rule.matchPattern) {
        // Set / add header directly when matchPattern is empty
        out[rule.headerName] = rule.replaceWith
        changed = true
        continue
      }
      for (const [k, v] of Object.entries(out)) {
        if (rule.headerName && k.toLowerCase() !== rule.headerName.toLowerCase()) continue
        const before = v
        let next = v
        if (rule.isRegex) {
          try {
            next = v.replace(new RegExp(rule.matchPattern, "g"), rule.replaceWith)
          } catch {
            continue
          }
        } else {
          next = v.split(rule.matchPattern).join(rule.replaceWith)
        }
        if (next !== before) {
          out[k] = next
          changed = true
        }
      }
    }
    return { headers: out, changed }
  }

  private shouldInterceptExchange(targetUrl: URL, inScope: boolean): boolean {
    if (!this.interceptEnabled) return false
    if (this.interceptInScopeOnly && !inScope) return false
    if (this.skipStaticAssets && STATIC_ASSET_EXT_RE.test(targetUrl.pathname)) return false
    return true
  }

  private waitForOperatorIntercept(item: Omit<ProxyInterceptItem, "interceptId" | "createdAt">): Promise<ProxyInterceptResolution> {
    const interceptId = `int-${crypto.randomUUID().slice(0, 8)}`
    const fullItem: ProxyInterceptItem = {
      ...item,
      interceptId,
      createdAt: new Date().toISOString(),
      headers: { ...item.headers },
    }
    return new Promise<ProxyInterceptResolution>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingIntercepts.delete(interceptId)
        resolve({ interceptId, decision: "forward" })
      }, 120_000)
      this.pendingIntercepts.set(interceptId, {
        item: fullItem,
        timer,
        resolve,
      })
    })
  }

  private checkTargetAllowed(targetUrl: URL): { allowed: boolean; inScope: boolean; reason?: string } {
    if (targetUrl.hostname === "169.254.169.254" || targetUrl.hostname === "metadata.google.internal") {
      return { allowed: false, inScope: false, reason: "Blocked cloud metadata SSRF endpoint" }
    }
    const scopeCheck = this.deps.scopes.verifyTargets(
      this.deps.projectId,
      extractTargetsFromInput({ url: targetUrl.toString() }),
      ["url_origin"],
    )
    if (this.scopeOnly && !scopeCheck.allowed) {
      return { allowed: false, inScope: false, reason: scopeCheck.reason || "Blocked out-of-scope target" }
    }
    return { allowed: true, inScope: scopeCheck.allowed }
  }

  private handleConnectTunnel(req: http.IncomingMessage, clientSocket: Duplex, head: Buffer): void {
    const startedAt = Date.now()
    const rawAuthority = (req.url ?? "").trim()
    const match = /^(\[[^\]]+\]|[^:]+):(\d{1,5})$/.exec(rawAuthority)
    if (!match) {
      clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n")
      return
    }
    const hostOnly = match[1]!.replace(/^\[|\]$/g, "")
    const port = Number(match[2])
    const syntheticHttpsUrl = new URL(`https://${rawAuthority}/`)
    const scopeVerdict = this.checkTargetAllowed(syntheticHttpsUrl)

    if (!scopeVerdict.allowed) {
      const reason = scopeVerdict.reason ?? "Blocked by ScopeController"
      this.pushEntry({
        entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        protocol: "https",
        method: "CONNECT",
        url: syntheticHttpsUrl.origin,
        host: rawAuthority,
        path: "/",
        statusCode: 403,
        elapsedMs: Date.now() - startedAt,
        requestHeaders: redactHeaderMap(req.headers),
        requestBody: "",
        responseHeaders: {},
        responseBody: JSON.stringify({ blockedByCyberLabScope: true, reason }),
        responseBytes: reason.length,
        blockedByScope: true,
        blockReason: reason,
      })
      clientSocket.end(
        `HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n${JSON.stringify({
          blockedByCyberLabScope: true,
          reason,
        })}`,
      )
      return
    }

    if (this.httpsMode === "tunnel_passthrough") {
      const upstream = net.connect(port, hostOnly, () => {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: CyberLab-OS\r\n\r\n")
        if (head.byteLength > 0) upstream.write(head)
        upstream.pipe(clientSocket)
        clientSocket.pipe(upstream)
        this.pushEntry({
          entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
          timestamp: new Date().toISOString(),
          protocol: "connect_tunnel",
          method: "CONNECT",
          url: syntheticHttpsUrl.origin,
          host: rawAuthority,
          path: "(TLS Passthrough Tunnel)",
          statusCode: 200,
          elapsedMs: Date.now() - startedAt,
          requestHeaders: redactHeaderMap(req.headers),
          requestBody: "",
          responseHeaders: {},
          responseBody: "[Encrypted TLS passthrough tunnel — switch Proxy to tls_intercept mode to inspect HTTPS/WSS]",
          responseBytes: 0,
          blockedByScope: false,
        })
      })
      upstream.on("error", () => clientSocket.destroy())
      clientSocket.on("error", () => upstream.destroy())
      return
    }

    if (!this.mitmHttpsPort) {
      clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n")
      return
    }
    this.localCa.issueHostCertificate(hostOnly)
    const mitmOrigin = `https://${rawAuthority}`

    const mitmBridge = net.connect(this.mitmHttpsPort, "127.0.0.1", () => {
      const localBridgePort = mitmBridge.localPort
      if (localBridgePort) {
        this.mitmTunnelOrigins.set(localBridgePort, { hostOnly, mitmOrigin })
        mitmBridge.once("close", () => {
          this.mitmTunnelOrigins.delete(localBridgePort)
        })
      }
      clientSocket.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: CyberLab-OS-MITM\r\n\r\n")
      if (head.byteLength > 0) {
        mitmBridge.write(head)
      }
      mitmBridge.pipe(clientSocket)
      clientSocket.pipe(mitmBridge)
    })

    mitmBridge.on("error", () => clientSocket.destroy())
    clientSocket.on("error", () => mitmBridge.destroy())
  }

  private handleWebSocketUpgrade(
    req: http.IncomingMessage,
    clientSocket: Duplex,
    head: Buffer,
    ctx: { tlsTerminatedOrigin: string | null },
  ): void {
    const startedAt = Date.now()
    const rawUrl = req.url ?? "/"
    let targetHttpUrl: URL
    try {
      if (/^wss?:\/\//i.test(rawUrl)) {
        const normalized = rawUrl.replace(/^ws:/i, "http:").replace(/^wss:/i, "https:")
        targetHttpUrl = new URL(normalized)
      } else if (/^https?:\/\//i.test(rawUrl)) {
        targetHttpUrl = new URL(rawUrl)
      } else if (ctx.tlsTerminatedOrigin) {
        targetHttpUrl = new URL(rawUrl, ctx.tlsTerminatedOrigin)
      } else if (req.headers.host) {
        targetHttpUrl = new URL(rawUrl, `http://${req.headers.host}`)
      } else {
        clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n")
        return
      }
    } catch {
      clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n")
      return
    }

    const isSecure = targetHttpUrl.protocol === "https:"
    const wsScheme: "ws" | "wss" = isSecure ? "wss" : "ws"
    const wsDisplayUrl = `${wsScheme}://${targetHttpUrl.host}${targetHttpUrl.pathname}${targetHttpUrl.search}`

    const scopeVerdict = this.checkTargetAllowed(targetHttpUrl)
    if (!scopeVerdict.allowed) {
      const reason = scopeVerdict.reason ?? "Blocked WebSocket target"
      this.pushEntry({
        entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        protocol: wsScheme,
        method: "WS_UPGRADE",
        url: wsDisplayUrl,
        host: targetHttpUrl.host,
        path: targetHttpUrl.pathname + targetHttpUrl.search,
        statusCode: 403,
        elapsedMs: Date.now() - startedAt,
        requestHeaders: redactHeaderMap(req.headers),
        requestBody: "",
        responseHeaders: {},
        responseBody: JSON.stringify({ blockedByCyberLabScope: true, reason }),
        responseBytes: 0,
        blockedByScope: true,
        blockReason: reason,
      })
      clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n")
      return
    }

    const forwardHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined || k.toLowerCase() === "proxy-connection") continue
      forwardHeaders[k] = Array.isArray(v) ? v.join(", ") : v
    }
    forwardHeaders.host = targetHttpUrl.host
    const withEngagement = scopeVerdict.inScope
      ? EngagementRuntime.applyHeaders(this.deps.projectId, forwardHeaders)
      : forwardHeaders

    const reqFn = isSecure ? https.request : http.request
    const upstreamReq = reqFn({
      hostname: targetHttpUrl.hostname,
      port: targetHttpUrl.port || (isSecure ? 443 : 80),
      path: targetHttpUrl.pathname + targetHttpUrl.search,
      method: "GET",
      headers: withEngagement,
      ...(isSecure ? { rejectUnauthorized: !this.allowSelfSignedUpstream } : {}),
    })

    upstreamReq.on("upgrade", (upstreamRes, upstreamSocket, upstreamHead) => {
      const statusLine = `HTTP/1.1 ${upstreamRes.statusCode ?? 101} ${upstreamRes.statusMessage ?? "Switching Protocols"}\r\n`
      const hdrLines: string[] = []
      for (const [hk, hv] of Object.entries(upstreamRes.headers)) {
        if (hv === undefined) continue
        if (Array.isArray(hv)) {
          for (const item of hv) hdrLines.push(`${hk}: ${item}\r\n`)
        } else {
          hdrLines.push(`${hk}: ${hv}\r\n`)
        }
      }
      clientSocket.write(`${statusLine}${hdrLines.join("")}\r\n`)
      if (upstreamHead.byteLength > 0) clientSocket.write(upstreamHead)
      if (head.byteLength > 0) upstreamSocket.write(head)

      const entryId = `px-${crypto.randomUUID().slice(0, 8)}`
      const entry: ProxyHistoryEntry = {
        entryId,
        timestamp: new Date().toISOString(),
        protocol: wsScheme,
        method: "WS_UPGRADE",
        url: wsDisplayUrl,
        host: targetHttpUrl.host,
        path: targetHttpUrl.pathname + targetHttpUrl.search,
        statusCode: upstreamRes.statusCode ?? 101,
        elapsedMs: Date.now() - startedAt,
        requestHeaders: redactHeaderMap(req.headers),
        requestBody: "",
        responseHeaders: redactHeaderMap(upstreamRes.headers),
        responseBody: "[WebSocket 101 Switching Protocols established]",
        responseBytes: 0,
        blockedByScope: false,
      }
      this.pushEntry(entry)
      this.recordInSiteMapAndPassiveScan({
        entryId,
        scheme: wsScheme,
        targetUrl: targetHttpUrl,
        method: "WS_UPGRADE",
        statusCode: upstreamRes.statusCode ?? 101,
        requestBody: "",
        responseHeaders: flattenHeaderMap(upstreamRes.headers),
        responseBodyText: "",
      })

      const transcriptLog: string[] = ["[WebSocket 101 Switching Protocols]"]
      let totalBytes = 0

      clientSocket.on("data", (chunk: Buffer) => {
        totalBytes += chunk.byteLength
        if (transcriptLog.length < 40) {
          const decoded = decodeWsPreviewFrames(chunk)
          if (decoded.textSample) {
            transcriptLog.push(`CLIENT -> SERVER: ${redactSensitiveContent(decoded.textSample).text}`)
            entry.responseBody = transcriptLog.join("\n")
          }
        }
        entry.responseBytes = totalBytes
      })

      upstreamSocket.on("data", (chunk: Buffer) => {
        totalBytes += chunk.byteLength
        if (transcriptLog.length < 40) {
          const decoded = decodeWsPreviewFrames(chunk)
          if (decoded.textSample) {
            transcriptLog.push(`SERVER -> CLIENT: ${redactSensitiveContent(decoded.textSample).text}`)
            entry.responseBody = transcriptLog.join("\n")
          }
        }
        entry.responseBytes = totalBytes
      })

      upstreamSocket.pipe(clientSocket)
      clientSocket.pipe(upstreamSocket)
      upstreamSocket.on("error", () => clientSocket.destroy())
      clientSocket.on("error", () => upstreamSocket.destroy())
    })

    upstreamReq.on("response", (resp) => {
      clientSocket.end(`HTTP/1.1 ${resp.statusCode ?? 502} Bad Gateway\r\n\r\n`)
    })

    upstreamReq.on("error", () => {
      clientSocket.destroy()
    })

    upstreamReq.end()
  }

  private async handleProxyRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    ctx: { tlsTerminatedOrigin: string | null },
  ): Promise<void> {
    const startedAt = Date.now()
    let method = (req.method ?? "GET").toUpperCase()
    const hostHeader = typeof req.headers.host === "string" ? req.headers.host.trim() : ""
    const isSelfProxyPortalHost =
      hostHeader.toLowerCase() === "cyberlab.proxy" ||
      (this.listenPort !== null &&
        (hostHeader === `127.0.0.1:${this.listenPort}` || hostHeader.toLowerCase() === `localhost:${this.listenPort}`))

    let rawUrl = req.headers["x-cyberlab-target-url"]
      ? String(req.headers["x-cyberlab-target-url"])
      : ctx.tlsTerminatedOrigin && (req.url ?? "").startsWith("/")
        ? `${ctx.tlsTerminatedOrigin}${req.url}`
        : (req.url ?? "").startsWith("/") && isSelfProxyPortalHost
          ? `http://cyberlab.proxy${req.url}`
          : (req.url ?? "").startsWith("/") && hostHeader
            ? `http://${hostHeader}${req.url}`
            : (req.url ?? "")

    if (!/^https?:\/\//i.test(rawUrl)) {
      res.writeHead(400, { "Content-Type": "application/json" })
      res.end(
        JSON.stringify({
          error:
            "CyberLab HTTP/HTTPS Proxy expects full http(s):// target URL, CONNECT tunnel, or X-CyberLab-Target-Url header.",
        }),
      )
      return
    }

    let modified = false
    const urlRuleRes = this.applyMatchReplaceToString(rawUrl, "url")
    if (urlRuleRes.changed) {
      rawUrl = urlRuleRes.value
      modified = true
    }

    let parsedTarget: URL
    try {
      parsedTarget = new URL(rawUrl)
    } catch {
      res.writeHead(400, { "Content-Type": "text/plain" })
      res.end("Malformed target URL")
      return
    }

    // Built-in http://cyberlab.proxy & http://cyberlab.proxy/cert portal (Firefox / Mobile CA download)
    if (parsedTarget.hostname.toLowerCase() === "cyberlab.proxy") {
      const ca = this.localCa.getBundleInfo()
      if (parsedTarget.pathname === "/cert" || parsedTarget.pathname === "/ca.crt" || parsedTarget.pathname === "/ca.pem") {
        res.writeHead(200, {
          "Content-Type": "application/x-x509-ca-cert",
          "Content-Disposition": 'attachment; filename="cyberlab-root-ca.pem"',
        })
        res.end(ca.certPem)
        return
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
      res.end(
        `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"/><title>CyberLab OS Proxy</title>` +
          `<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:32px;max-width:680px;margin:auto}` +
          `a.btn{display:inline-block;margin-top:14px;padding:10px 18px;background:#238636;color:#fff;text-decoration:none;border-radius:8px;font-weight:600}` +
          `code{background:#161b22;padding:2px 6px;border-radius:4px}</style></head><body>` +
          `<h2>CyberLab OS — Proxy HTTP/HTTPS/WSS Ativo</h2>` +
          `<p>Seu navegador está conectado com sucesso ao Proxy do CyberLab OS em <code>127.0.0.1:${this.listenPort ?? 8899}</code>.</p>` +
          `<p>Fingerprint SHA-256 da Root CA: <code>${ca.fingerprintSha256}</code></p>` +
          `<a class="btn" href="http://cyberlab.proxy/cert">Baixar Certificado Root CA (Firefox / Mobile)</a>` +
          `</body></html>`,
      )
      return
    }

    const reqChunks: Buffer[] = []
    let totalReqBytes = 0
    for await (const chunk of req) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array)
      totalReqBytes += buf.byteLength
      if (totalReqBytes <= 512 * 1024) {
        reqChunks.push(buf)
      }
    }
    let reqBodyBuf = Buffer.concat(reqChunks)
    let reqBodyRawStr = reqBodyBuf.toString("utf8")

    const initialHeadersFlat: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers)) {
      const lower = k.toLowerCase()
      if (
        lower === "proxy-connection" ||
        lower === "connection" ||
        lower === "transfer-encoding" ||
        lower === "content-length" ||
        lower === "x-cyberlab-target-url" ||
        v === undefined
      ) {
        continue
      }
      initialHeadersFlat[k] = Array.isArray(v) ? v.join(", ") : v
    }

    const scopeVerdict = this.checkTargetAllowed(parsedTarget)
    const isHttpsInitial = parsedTarget.protocol === "https:"
    const protoLabelInitial: "http" | "https" = isHttpsInitial ? "https" : "http"

    if (!scopeVerdict.allowed) {
      const reason = scopeVerdict.reason ?? "Blocked target"
      this.pushEntry({
        entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        protocol: protoLabelInitial,
        method,
        url: parsedTarget.toString(),
        host: parsedTarget.host,
        path: parsedTarget.pathname + parsedTarget.search,
        statusCode: 403,
        elapsedMs: Date.now() - startedAt,
        requestHeaders: redactHeaderMap(req.headers),
        requestBody: redactSensitiveContent(reqBodyRawStr).text,
        responseHeaders: { "content-type": "application/json" },
        responseBody: JSON.stringify({ blockedByCyberLabScope: true, reason }),
        responseBytes: reason.length,
        blockedByScope: true,
        blockReason: reason,
      })
      res.writeHead(403, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ blockedByCyberLabScope: true, reason }))
      return
    }

    // Apply Engagement Headers (e.g. X-Bug-Bounty, custom User-Agent) + Match & Replace Rules
    let forwardHeaders = scopeVerdict.inScope
      ? EngagementRuntime.applyHeaders(this.deps.projectId, initialHeadersFlat)
      : { ...initialHeadersFlat }

    const reqHdrMr = this.applyMatchReplaceToHeaders(forwardHeaders, "request_header")
    if (reqHdrMr.changed) {
      forwardHeaders = reqHdrMr.headers
      modified = true
    }

    const reqBodyMr = this.applyMatchReplaceToString(reqBodyRawStr, "request_body")
    if (reqBodyMr.changed) {
      reqBodyRawStr = reqBodyMr.value
      reqBodyBuf = Buffer.from(reqBodyRawStr, "utf8")
      modified = true
    }

    // Live Request Intercept Queue (Hold / Edit / Forward / Drop)
    if (this.shouldInterceptExchange(parsedTarget, scopeVerdict.inScope)) {
      const decision = await this.waitForOperatorIntercept({
        phase: "request",
        protocol: protoLabelInitial,
        method,
        url: parsedTarget.toString(),
        host: parsedTarget.host,
        path: parsedTarget.pathname + parsedTarget.search,
        headers: forwardHeaders,
        body: reqBodyRawStr,
      })
      if (decision.decision === "drop") {
        this.pushEntry({
          entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
          timestamp: new Date().toISOString(),
          protocol: protoLabelInitial,
          method,
          url: parsedTarget.toString(),
          host: parsedTarget.host,
          path: parsedTarget.pathname + parsedTarget.search,
          statusCode: 499,
          elapsedMs: Date.now() - startedAt,
          requestHeaders: redactHeaderMap(forwardHeaders),
          requestBody: redactSensitiveContent(reqBodyRawStr).text,
          responseHeaders: {},
          responseBody: "[Dropped manually by operator in Proxy Intercept]",
          responseBytes: 0,
          blockedByScope: false,
          modifiedByRuleOrIntercept: true,
        })
        res.writeHead(499, { "Content-Type": "text/plain; charset=utf-8" })
        res.end("Request dropped in CyberLab Proxy Intercept")
        return
      }
      if (decision.method && decision.method.trim().toUpperCase() !== method) {
        method = decision.method.trim().toUpperCase()
        modified = true
      }
      if (decision.url && decision.url.trim() !== parsedTarget.toString()) {
        try {
          const editedTarget = new URL(decision.url.trim())
          const recheck = this.checkTargetAllowed(editedTarget)
          if (!recheck.allowed) {
            res.writeHead(403, { "Content-Type": "application/json" })
            res.end(JSON.stringify({ blockedByCyberLabScope: true, reason: recheck.reason }))
            return
          }
          parsedTarget = editedTarget
          modified = true
        } catch {
          // Keep original parsedTarget if invalid
        }
      }
      if (decision.headers) {
        forwardHeaders = { ...decision.headers }
        modified = true
      }
      if (decision.body !== undefined && decision.body !== reqBodyRawStr) {
        reqBodyRawStr = decision.body
        reqBodyBuf = Buffer.from(reqBodyRawStr, "utf8")
        modified = true
      }
    }

    const isHttps = parsedTarget.protocol === "https:"
    const protoLabel: "http" | "https" = isHttps ? "https" : "http"

    try {
      if (scopeVerdict.inScope) {
        await EngagementRuntime.acquireRateSlot(this.deps.projectId)
      }

      const wireHeaders: Record<string, string> = {}
      for (const [k, v] of Object.entries(forwardHeaders)) {
        const lower = k.toLowerCase()
        if (lower === "host" || lower === "content-length" || lower === "transfer-encoding") continue
        wireHeaders[k] = v
      }
      wireHeaders.host = parsedTarget.host
      if (!Object.keys(wireHeaders).some((k) => k.toLowerCase() === "accept-encoding")) {
        wireHeaders["accept-encoding"] = "gzip, deflate, br"
      }
      if (reqBodyBuf.byteLength > 0 && method !== "GET" && method !== "HEAD") {
        wireHeaders["content-length"] = String(reqBodyBuf.byteLength)
      }

      const upstreamResult = await new Promise<{
        statusCode: number
        headers: http.IncomingHttpHeaders
        body: Buffer
      }>((resolve, reject) => {
        const reqFn = isHttps ? https.request : http.request
        const upReq = reqFn(
          {
            hostname: parsedTarget.hostname,
            port: parsedTarget.port || (isHttps ? 443 : 80),
            path: parsedTarget.pathname + parsedTarget.search,
            method,
            headers: wireHeaders,
            timeout: 25_000,
            ...(isHttps ? { rejectUnauthorized: !this.allowSelfSignedUpstream } : {}),
          },
          (upRes) => {
            const chunks: Buffer[] = []
            upRes.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)))
            upRes.on("end", () => {
              resolve({
                statusCode: upRes.statusCode ?? 502,
                headers: upRes.headers,
                body: Buffer.concat(chunks),
              })
            })
            upRes.on("error", reject)
          },
        )
        upReq.on("timeout", () => {
          upReq.destroy(new Error("Upstream proxy timeout"))
        })
        upReq.on("error", reject)
        if (reqBodyBuf.byteLength > 0 && method !== "GET" && method !== "HEAD") {
          upReq.write(reqBodyBuf)
        }
        upReq.end()
      })

      let statusCode = upstreamResult.statusCode
      let decodedRespBuf = decompressHttpBody(upstreamResult.body, upstreamResult.headers["content-encoding"])
      let decodedRespText = decodedRespBuf.toString("utf8")
      let flatRespHeaders = flattenHeaderMap(upstreamResult.headers)

      // Apply Response Match & Replace Rules
      let responseModified = false
      const respHdrMr = this.applyMatchReplaceToHeaders(flatRespHeaders, "response_header")
      if (respHdrMr.changed) {
        flatRespHeaders = respHdrMr.headers
        responseModified = true
      }
      const respBodyMr = this.applyMatchReplaceToString(decodedRespText, "response_body")
      if (respBodyMr.changed) {
        decodedRespText = respBodyMr.value
        decodedRespBuf = Buffer.from(decodedRespText, "utf8")
        responseModified = true
      }

      // Live Response Intercept Queue (optional)
      if (this.interceptResponses && this.shouldInterceptExchange(parsedTarget, scopeVerdict.inScope)) {
        const respDecision = await this.waitForOperatorIntercept({
          phase: "response",
          protocol: protoLabel,
          method,
          url: parsedTarget.toString(),
          host: parsedTarget.host,
          path: parsedTarget.pathname + parsedTarget.search,
          headers: flatRespHeaders,
          body: decodedRespText,
          statusCode,
        })
        if (respDecision.decision === "drop") {
          res.writeHead(499, { "Content-Type": "text/plain; charset=utf-8" })
          res.end("Response dropped in CyberLab Proxy Intercept")
          return
        }
        if (respDecision.statusCode !== undefined && respDecision.statusCode !== statusCode) {
          statusCode = respDecision.statusCode
          responseModified = true
        }
        if (respDecision.headers) {
          flatRespHeaders = { ...respDecision.headers }
          responseModified = true
        }
        if (respDecision.body !== undefined && respDecision.body !== decodedRespText) {
          decodedRespText = respDecision.body
          decodedRespBuf = Buffer.from(decodedRespText, "utf8")
          responseModified = true
        }
      }

      const elapsedMs = Date.now() - startedAt
      const wireOutBody = responseModified ? decodedRespBuf : upstreamResult.body
      const clientRespHeaders: Record<string, string | string[]> = {}
      if (responseModified) {
        for (const [k, v] of Object.entries(flatRespHeaders)) {
          const lower = k.toLowerCase()
          if (lower === "transfer-encoding" || lower === "content-encoding" || lower === "content-length") {
            continue
          }
          clientRespHeaders[k] = v
        }
        clientRespHeaders["content-length"] = String(wireOutBody.byteLength)
      } else {
        for (const [key, val] of Object.entries(upstreamResult.headers)) {
          if (val === undefined) continue
          if (key.toLowerCase() !== "transfer-encoding") {
            clientRespHeaders[key] = val
          }
        }
      }

      const entryId = `px-${crypto.randomUUID().slice(0, 8)}`
      const mimeType =
        (flatRespHeaders["content-type"] ?? flatRespHeaders["Content-Type"] ?? "").split(";")[0]?.trim() || undefined

      const passiveAlertCount = this.recordInSiteMapAndPassiveScan({
        entryId,
        scheme: protoLabel,
        targetUrl: parsedTarget,
        method,
        statusCode,
        requestBody: reqBodyRawStr,
        responseHeaders: flatRespHeaders,
        responseBodyText: decodedRespText,
      })

      const cappedRedactedRespText = redactSensitiveContent(capOutputBytes(decodedRespText, 128 * 1024).text).text
      const cappedRawReplayResp = capOutputBytes(decodedRespText, 256 * 1024).text

      this.pushEntry(
        {
          entryId,
          timestamp: new Date().toISOString(),
          protocol: protoLabel,
          method,
          url: parsedTarget.toString(),
          host: parsedTarget.host,
          path: parsedTarget.pathname + parsedTarget.search,
          statusCode,
          ...(mimeType ? { mimeType } : {}),
          elapsedMs,
          requestHeaders: redactHeaderMap(forwardHeaders),
          requestBody: redactSensitiveContent(reqBodyRawStr).text,
          responseHeaders: redactHeaderMap(flatRespHeaders),
          responseBody: cappedRedactedRespText,
          responseBytes: decodedRespBuf.byteLength,
          blockedByScope: false,
          ...(modified || responseModified ? { modifiedByRuleOrIntercept: true } : {}),
          ...(passiveAlertCount > 0 ? { passiveAlertCount } : {}),
        },
        {
          method,
          url: parsedTarget.toString(),
          requestHeaders: { ...forwardHeaders },
          requestBody: reqBodyRawStr,
          responseStatusCode: statusCode,
          responseHeaders: { ...flatRespHeaders },
          responseBody: cappedRawReplayResp,
        },
      )

      EngagementRuntime.recordTraffic({
        projectId: this.deps.projectId,
        sourceTool: "http-proxy",
        method,
        url: parsedTarget.toString(),
        host: parsedTarget.host,
        statusCode,
        elapsedMs,
        responseBytes: decodedRespBuf.byteLength,
      })

      res.writeHead(statusCode, clientRespHeaders)
      res.end(wireOutBody)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      res.writeHead(502, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ error: `Proxy upstream error: ${msg}` }))
    }
  }
}
