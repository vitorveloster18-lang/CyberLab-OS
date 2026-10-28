import crypto from "node:crypto"
import http from "node:http"
import https from "node:https"
import net from "node:net"
import path from "node:path"
import tls from "node:tls"
import type { Duplex } from "node:stream"
import type { EvidenceStore } from "../evidence/store.js"
import { redactSensitiveContent } from "../evidence/provenance.js"
import { capOutputBytes } from "../execution/cancellation.js"
import { normalizeRawOutputDraft } from "../execution/result-normalizer.js"
import { extractTargetsFromInput, type ScopeController } from "../policy/scope.js"
import { CyberLabLocalCa } from "./local-ca.js"

const SENSITIVE_PROXY_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "sec-websocket-protocol",
])

function redactHeaderMap(raw: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue
    const joined = Array.isArray(v) ? v.join("; ") : v
    out[k] = SENSITIVE_PROXY_HEADERS.has(k.toLowerCase()) ? "[REDACTED:SENSITIVE_HEADER]" : joined
  }
  return out
}

function decodeWsPreviewFrames(chunk: Buffer): { frames: number; textSample: string } {
  // Best-effort RFC 6455 frame header inspection (unmasked server frames & masked client frames)
  let offset = 0
  let frames = 0
  const snippets: string[] = []
  while (offset + 2 <= chunk.length && frames < 8) {
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
    if (offset + headerLen + payloadLen > chunk.length || payloadLen > 4096) break

    const rawPayload = Buffer.from(chunk.subarray(offset + headerLen, offset + headerLen + payloadLen))
    if (masked) {
      const mask = chunk.subarray(offset + maskKeyOffset, offset + maskKeyOffset + 4)
      for (let i = 0; i < rawPayload.length; i++) {
        rawPayload[i] = rawPayload[i]! ^ mask[i % 4]!
      }
    }
    frames++
    if (opcode === 0x01 && rawPayload.length > 0) {
      snippets.push(rawPayload.toString("utf8").slice(0, 240))
    }
    offset += headerLen + payloadLen
  }
  return { frames, textSample: snippets.join(" | ") }
}

export type ProxyHttpsMode = "tls_intercept" | "tunnel_passthrough"

export interface ProxyHistoryEntry {
  entryId: string
  timestamp: string
  protocol?: "http" | "https" | "ws" | "wss" | "connect_tunnel"
  method: string
  url: string
  host: string
  path: string
  statusCode: number
  elapsedMs: number
  requestHeaders: Record<string, string>
  requestBody: string
  responseHeaders: Record<string, string>
  responseBody: string
  responseBytes: number
  blockedByScope: boolean
  blockReason?: string
  persistedEvidenceId?: string
}

export interface ProxyStatus {
  running: boolean
  listenHost: string
  listenPort: number | null
  scopeOnly: boolean
  httpsMode: ProxyHttpsMode
  allowSelfSignedUpstream: boolean
  caFingerprintSha256: string
  caCertPath: string | null
  caCertPem: string
  capturedCount: number
}

export class CyberLabHttpProxy {
  private server: http.Server | null = null
  private listenPort: number | null = null
  private scopeOnly = true
  private httpsMode: ProxyHttpsMode = "tls_intercept"
  private allowSelfSignedUpstream = true
  private readonly localCa: CyberLabLocalCa
  private readonly history: ProxyHistoryEntry[] = []
  private readonly maxEntries: number
  private mitmHttpsServer: https.Server | null = null
  private mitmHttpsPort: number | null = null
  private readonly mitmTunnelOrigins = new Map<number, { hostOnly: string; mitmOrigin: string }>()

  constructor(
    private readonly deps: {
      projectId: string
      scopes: ScopeController
      evidenceStore: EvidenceStore
      workspaceRoot?: string
      maxEntries?: number
    },
  ) {
    this.maxEntries = deps.maxEntries ?? 250
    const caDirectory = deps.workspaceRoot ? path.join(deps.workspaceRoot, ".cyberlab", "ca") : undefined
    this.localCa = new CyberLabLocalCa({ caDirectory })
  }

  getCaBundle(): { certPem: string; fingerprintSha256: string; certPath: string | null } {
    return this.localCa.getBundleInfo()
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
      caFingerprintSha256: ca.fingerprintSha256,
      caCertPath: ca.certPath,
      caCertPem: ca.certPem,
      capturedCount: this.history.length,
    }
  }

  listHistory(): ProxyHistoryEntry[] {
    return [...this.history].reverse()
  }

  clearHistory(): void {
    this.history.length = 0
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
        toolVersion: "2.0.0",
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

  private pushEntry(entry: ProxyHistoryEntry): void {
    this.history.push(entry)
    if (this.history.length > this.maxEntries) {
      this.history.shift()
    }
  }

  private checkTargetAllowed(targetUrl: URL): { allowed: boolean; reason?: string } {
    if (targetUrl.hostname === "169.254.169.254" || targetUrl.hostname === "metadata.google.internal") {
      return { allowed: false, reason: "Blocked cloud metadata SSRF endpoint" }
    }
    const scopeCheck = this.deps.scopes.verifyTargets(
      this.deps.projectId,
      extractTargetsFromInput({ url: targetUrl.toString() }),
      ["url_origin"],
    )
    if (this.scopeOnly && !scopeCheck.allowed) {
      return { allowed: false, reason: scopeCheck.reason || "Blocked out-of-scope target" }
    }
    return { allowed: true }
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

    // HTTPS MITM Mode: bridge clientSocket into our persistent loopback mitmHttpsServer
    if (!this.mitmHttpsPort) {
      clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n")
      return
    }
    // Pre-warm leaf cert in cache for hostOnly
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

    const forwardHeaders: Record<string, string | string[]> = {}
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined || k.toLowerCase() === "proxy-connection") continue
      forwardHeaders[k] = v
    }
    forwardHeaders.host = targetHttpUrl.host

    const reqFn = isSecure ? https.request : http.request
    const upstreamReq = reqFn({
      hostname: targetHttpUrl.hostname,
      port: targetHttpUrl.port || (isSecure ? 443 : 80),
      path: targetHttpUrl.pathname + targetHttpUrl.search,
      method: "GET",
      headers: forwardHeaders,
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

      const entry: ProxyHistoryEntry = {
        entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
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

      const transcriptLog: string[] = ["[WebSocket 101 Switching Protocols]"]
      let totalBytes = 0

      clientSocket.on("data", (chunk: Buffer) => {
        totalBytes += chunk.byteLength
        if (transcriptLog.length < 24) {
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
        if (transcriptLog.length < 24) {
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
    const method = (req.method ?? "GET").toUpperCase()
    const rawUrl = req.headers["x-cyberlab-target-url"]
      ? String(req.headers["x-cyberlab-target-url"])
      : ctx.tlsTerminatedOrigin && (req.url ?? "").startsWith("/")
        ? `${ctx.tlsTerminatedOrigin}${req.url}`
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

    let parsedTarget: URL
    try {
      parsedTarget = new URL(rawUrl)
    } catch {
      res.writeHead(400, { "Content-Type": "text/plain" })
      res.end("Malformed target URL")
      return
    }

    const isHttps = parsedTarget.protocol === "https:"
    const protoLabel: "http" | "https" = isHttps ? "https" : "http"

    const reqChunks: Buffer[] = []
    let totalReqBytes = 0
    for await (const chunk of req) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array)
      totalReqBytes += buf.byteLength
      if (totalReqBytes <= 65_536) {
        reqChunks.push(buf)
      }
    }
    const reqBodyBuf = Buffer.concat(reqChunks)
    const reqBodyText = redactSensitiveContent(reqBodyBuf.toString("utf8")).text
    const redactedReqHeaders = redactHeaderMap(req.headers)

    const scopeVerdict = this.checkTargetAllowed(parsedTarget)
    if (!scopeVerdict.allowed) {
      const reason = scopeVerdict.reason ?? "Blocked target"
      this.pushEntry({
        entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        protocol: protoLabel,
        method,
        url: parsedTarget.toString(),
        host: parsedTarget.host,
        path: parsedTarget.pathname + parsedTarget.search,
        statusCode: 403,
        elapsedMs: Date.now() - startedAt,
        requestHeaders: redactedReqHeaders,
        requestBody: reqBodyText,
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

    try {
      const forwardHeaders: Record<string, string> = {}
      for (const [k, v] of Object.entries(req.headers)) {
        const lower = k.toLowerCase()
        if (
          lower === "host" ||
          lower === "proxy-connection" ||
          lower === "connection" ||
          lower === "content-length" ||
          lower === "accept-encoding" ||
          lower === "x-cyberlab-target-url" ||
          v === undefined
        ) {
          continue
        }
        forwardHeaders[k] = Array.isArray(v) ? v.join(", ") : v
      }
      forwardHeaders.host = parsedTarget.host
      if (reqBodyBuf.byteLength > 0 && method !== "GET" && method !== "HEAD") {
        forwardHeaders["content-length"] = String(reqBodyBuf.byteLength)
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
            headers: forwardHeaders,
            timeout: 10_000,
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

      const respBuf = upstreamResult.body
      const elapsedMs = Date.now() - startedAt
      const respHeadersRaw: Record<string, string> = redactHeaderMap(upstreamResult.headers)
      const clientRespHeaders: Record<string, string | string[]> = {}
      for (const [key, val] of Object.entries(upstreamResult.headers)) {
        if (val === undefined) continue
        if (key.toLowerCase() !== "transfer-encoding") {
          clientRespHeaders[key] = val
        }
      }

      const cappedRespText = redactSensitiveContent(capOutputBytes(respBuf.toString("utf8"), 16_384).text).text

      this.pushEntry({
        entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        protocol: protoLabel,
        method,
        url: parsedTarget.toString(),
        host: parsedTarget.host,
        path: parsedTarget.pathname + parsedTarget.search,
        statusCode: upstreamResult.statusCode,
        elapsedMs,
        requestHeaders: redactedReqHeaders,
        requestBody: reqBodyText,
        responseHeaders: respHeadersRaw,
        responseBody: cappedRespText,
        responseBytes: respBuf.byteLength,
        blockedByScope: false,
      })

      res.writeHead(upstreamResult.statusCode, clientRespHeaders)
      res.end(respBuf)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      res.writeHead(502, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ error: `Proxy upstream error: ${msg}` }))
    }
  }
}
