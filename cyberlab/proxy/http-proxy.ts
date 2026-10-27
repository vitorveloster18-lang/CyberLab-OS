import http from "node:http"
import type { EvidenceStore } from "../evidence/store.js"
import { redactSensitiveContent } from "../evidence/provenance.js"
import { capOutputBytes } from "../execution/cancellation.js"
import { normalizeRawOutputDraft } from "../execution/result-normalizer.js"
import { extractTargetsFromInput, type ScopeController } from "../policy/scope.js"

const SENSITIVE_PROXY_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
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

export interface ProxyHistoryEntry {
  entryId: string
  timestamp: string
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
  capturedCount: number
}

export class CyberLabHttpProxy {
  private server: http.Server | null = null
  private listenPort: number | null = null
  private scopeOnly = true
  private readonly history: ProxyHistoryEntry[] = []
  private readonly maxEntries: number

  constructor(
    private readonly deps: {
      projectId: string
      scopes: ScopeController
      evidenceStore: EvidenceStore
      maxEntries?: number
    },
  ) {
    this.maxEntries = deps.maxEntries ?? 200
  }

  getStatus(): ProxyStatus {
    return {
      running: this.server !== null,
      listenHost: "127.0.0.1",
      listenPort: this.listenPort,
      scopeOnly: this.scopeOnly,
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

  async start(options?: { port?: number; scopeOnly?: boolean }): Promise<ProxyStatus> {
    if (options?.scopeOnly !== undefined) {
      this.scopeOnly = options.scopeOnly
    }
    if (this.server) {
      return this.getStatus()
    }

    const requestedPort = options?.port ?? 8899
    const srv = http.createServer((req, res) => {
      void this.handleProxyRequest(req, res)
    })

    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject)
      srv.listen(requestedPort, "127.0.0.1", () => {
        srv.removeListener("error", reject)
        resolve()
      })
    })

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
    this.server = null
    this.listenPort = null
    await new Promise<void>((resolve) => srv.close(() => resolve()))
    return this.getStatus()
  }

  persistEntryToEvidence(entryId: string, actor = "operator:proxy"): { evidenceId: string; sha256: string } {
    const entry = this.history.find((h) => h.entryId === entryId)
    if (!entry) {
      throw new Error(`Proxy history entry "${entryId}" not found`)
    }
    const transcript = [
      `=== PROXY CAPTURE (${entry.timestamp}) ===`,
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
        toolVersion: "1.0.0",
        executorId: "cyberlab-http-proxy",
        executionId: `proxy-${entry.entryId}`,
        maxOutputBytes: 512 * 1024,
        labels: ["proxy-history", ...(entry.blockedByScope ? ["blocked-by-scope"] : ["in-scope"])],
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

  private async handleProxyRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const startedAt = Date.now()
    const method = (req.method ?? "GET").toUpperCase()
    const rawUrl = req.headers["x-cyberlab-target-url"]
      ? String(req.headers["x-cyberlab-target-url"])
      : (req.url ?? "")

    if (!/^https?:\/\//i.test(rawUrl)) {
      res.writeHead(400, { "Content-Type": "application/json" })
      res.end(
        JSON.stringify({
          error:
            "CyberLab HTTP Proxy expects full http:// target URL (e.g. curl -x http://127.0.0.1:8899 http://127.0.0.1:8080/ or X-CyberLab-Target-Url header).",
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

    // Always block cloud metadata SSRF, and check ScopeController when scopeOnly is enabled (or always for 169.254.169.254)
    const scopeCheck = this.deps.scopes.verifyTargets(
      this.deps.projectId,
      extractTargetsFromInput({ url: parsedTarget.toString() }),
      ["url_origin"],
    )

    if ((this.scopeOnly && !scopeCheck.allowed) || parsedTarget.hostname === "169.254.169.254") {
      const reason = scopeCheck.reason || "Blocked target"
      this.pushEntry({
        entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
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
      const forwardHeaders = new Headers()
      for (const [k, v] of Object.entries(req.headers)) {
        const lower = k.toLowerCase()
        if (
          lower === "host" ||
          lower === "proxy-connection" ||
          lower === "connection" ||
          lower === "content-length" ||
          lower === "x-cyberlab-target-url" ||
          v === undefined
        ) {
          continue
        }
        forwardHeaders.set(k, Array.isArray(v) ? v.join(", ") : v)
      }

      const abortCtrl = new AbortController()
      const timer = setTimeout(() => abortCtrl.abort("Upstream proxy timeout"), 10_000)
      try {
        const upstream = await fetch(parsedTarget.toString(), {
          method,
          headers: forwardHeaders,
          ...(method !== "GET" && method !== "HEAD" && reqBodyBuf.byteLength > 0 ? { body: reqBodyBuf } : {}),
          redirect: "manual",
          signal: abortCtrl.signal,
        })

        const respBuf = Buffer.from(await upstream.arrayBuffer())
        const elapsedMs = Date.now() - startedAt
        const respHeadersRaw: Record<string, string> = {}
        const clientRespHeaders: Record<string, string> = {}
        upstream.headers.forEach((val, key) => {
          respHeadersRaw[key] = SENSITIVE_PROXY_HEADERS.has(key.toLowerCase()) ? "[REDACTED:SENSITIVE_HEADER]" : val
          if (key.toLowerCase() !== "transfer-encoding" && key.toLowerCase() !== "content-encoding") {
            clientRespHeaders[key] = val
          }
        })

        const cappedRespText = redactSensitiveContent(capOutputBytes(respBuf.toString("utf8"), 16_384).text).text

        this.pushEntry({
          entryId: `px-${crypto.randomUUID().slice(0, 8)}`,
          timestamp: new Date().toISOString(),
          method,
          url: parsedTarget.toString(),
          host: parsedTarget.host,
          path: parsedTarget.pathname + parsedTarget.search,
          statusCode: upstream.status,
          elapsedMs,
          requestHeaders: redactedReqHeaders,
          requestBody: reqBodyText,
          responseHeaders: respHeadersRaw,
          responseBody: cappedRespText,
          responseBytes: respBuf.byteLength,
          blockedByScope: false,
        })

        res.writeHead(upstream.status, clientRespHeaders)
        res.end(respBuf)
      } finally {
        clearTimeout(timer)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      res.writeHead(502, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ error: `Proxy upstream error: ${msg}` }))
    }
  }
}
