#!/usr/bin/env bun
/**
 * CyberLab OS — Scope-Guarded Arsenal MCP Stdio Bridge (JSON-RPC 2.0)
 *
 * Exposes an installed external Arsenal tool slot to the OpenCode V2 AI Agent
 * over standard Model Context Protocol (stdio) while enforcing:
 * - Zero shell interpolation (spawn with argv array)
 * - Scope validation against .cyberlab/scope.json for external targets
 * - Automatic secret/credential redaction on stdout/stderr
 * - Native resilient SSE bridge for Burp Suite's official MCP Server extension (:9876,
 *   both host loopback and inside WSL2 Kali Linux) so `cyberlab-burp-suite` stays online
 *   in OpenCode even before Burp Suite or its MCP extension is opened!
 */

import { spawnSync } from "node:child_process"
import { existsSync, readFileSync } from "node:fs"
import http from "node:http"
import path from "node:path"
import { OFFICIAL_ARSENAL_SLOTS } from "../arsenal/catalog.js"
import { redactSensitiveContent } from "../evidence/provenance.js"

const argv = process.argv.slice(2)
function readArg(flag: string, fallback = ""): string {
  const idx = argv.indexOf(flag)
  return idx !== -1 && argv[idx + 1] ? argv[idx + 1]! : fallback
}

const slotId = readArg("--slot", "nuclei")
const workspaceRoot = path.resolve(readArg("--workspace", process.cwd()))
const preferredWslDistro = readArg("--wsl-distro", "kali-linux")
const burpMcpPort = Number.parseInt(
  readArg("--burp-port", process.env.CYBERLAB_BURP_MCP_PORT || "9876"),
  10,
) || 9876

const slotDef = OFFICIAL_ARSENAL_SLOTS.find((s) => s.slotId === slotId)
const safeToolPrefix = slotId.replace(/[^a-zA-Z0-9_]/g, "_")
const displayName = slotDef?.shortLabel ?? slotId

function checkTargetAllowedInWorkspaceScope(target: string): { allowed: boolean; reason?: string } {
  const trimmed = target.trim()
  if (!trimmed) return { allowed: true }
  // Local workspace files are always allowed if inside workspaceRoot
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) && !trimmed.includes("/")) {
    const candidate = path.resolve(workspaceRoot, trimmed)
    if (candidate.startsWith(workspaceRoot) && existsSync(candidate)) {
      return { allowed: true }
    }
  }
  const localLoopback = /^(https?:\/\/)?(127\.0\.0\.1|localhost)(:\d+)?(\/|$)/i
  if (localLoopback.test(trimmed)) return { allowed: true }

  const scopeRulesPath = path.join(workspaceRoot, ".cyberlab", "scope.json")
  if (!existsSync(scopeRulesPath)) {
    return {
      allowed: false,
      reason: `Alvo externo "${trimmed}" bloqueado: cadastre primeiro o escopo autorizado na aba 'Escopo Bug Bounty' do CyberLab OS.`,
    }
  }
  try {
    const raw = JSON.parse(readFileSync(scopeRulesPath, "utf8")) as {
      allowExternalTargets?: boolean
      allowedHosts?: string[]
      allowedDomains?: string[]
    }
    if (!raw.allowExternalTargets) {
      return {
        allowed: false,
        reason: `Alvos externos estão desativados no escopo atual (.cyberlab/scope.json).`,
      }
    }
    let host = trimmed
    try {
      host = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`).hostname.toLowerCase()
    } catch {
      host = trimmed.split("/")[0]!.split(":")[0]!.toLowerCase()
    }
    const hosts = [...(raw.allowedHosts ?? []), ...(raw.allowedDomains ?? [])].map((h) => h.toLowerCase())
    const matched = hosts.some((rule) => {
      if (rule.startsWith("*.")) {
        const suffix = rule.slice(1)
        return host.endsWith(suffix) || host === rule.slice(2)
      }
      return host === rule
    })
    if (!matched) {
      return {
        allowed: false,
        reason: `Host "${host}" fora da lista de domínios autorizados no escopo ativo.`,
      }
    }
    return { allowed: true }
  } catch {
    return { allowed: false, reason: "Não foi possível validar .cyberlab/scope.json." }
  }
}

function runToolArgs(args: string[]): { exitCode: number; output: string } {
  const bins = process.platform === "win32"
    ? [...(slotDef?.windowsBinaries ?? []), ...(slotDef?.posixBinaries ?? [])]
    : [...(slotDef?.posixBinaries ?? [slotId])]

  if (process.platform === "win32") {
    for (const winBin of slotDef?.windowsBinaries ?? []) {
      const res = spawnSync(winBin, args, {
        cwd: workspaceRoot,
        encoding: "utf8",
        timeout: 45_000,
        windowsHide: true,
      })
      if (!res.error) {
        const combined = `${res.stdout ?? ""}\n${res.stderr ?? ""}`.trim()
        return { exitCode: res.status ?? 0, output: redactSensitiveContent(combined).text }
      }
    }
    const posixBin = slotDef?.posixBinaries[0] ?? slotId
    const wslRes = spawnSync(
      "wsl.exe",
      ["-d", preferredWslDistro, "--", posixBin, ...args],
      {
        cwd: workspaceRoot,
        encoding: "utf8",
        timeout: 60_000,
        windowsHide: true,
      },
    )
    const combined = `${wslRes.stdout ?? ""}\n${wslRes.stderr ?? ""}`.trim()
    return { exitCode: wslRes.status ?? 1, output: redactSensitiveContent(combined).text }
  }

  const bin = bins[0] ?? slotId
  const res = spawnSync(bin, args, {
    cwd: workspaceRoot,
    encoding: "utf8",
    timeout: 60_000,
  })
  const combined = `${res.stdout ?? ""}\n${res.stderr ?? ""}`.trim()
  return { exitCode: res.status ?? 1, output: redactSensitiveContent(combined).text }
}

// =========================================================================
// BURP SUITE MCP (:9876 SSE) NATIVE BRIDGE (HOST LOOPBACK + WSL2 FALLBACK)
// =========================================================================

function postJsonHttp(targetUrl: URL, payload: unknown): Promise<{ status: number; text: string }> {
  const body = JSON.stringify(payload)
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: targetUrl.hostname,
        port: targetUrl.port || 80,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        method: "POST",
        headers: {
          Host: `${targetUrl.hostname}:${targetUrl.port || 80}`,
          "User-Agent": "CyberLab-MCP-Bridge/1.0",
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body, "utf8"),
        },
        timeout: 15_000,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on("data", (c: Buffer) => chunks.push(c))
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }),
        )
      },
    )
    req.on("error", reject)
    req.on("timeout", () => {
      req.destroy(new Error("HTTP POST timeout"))
    })
    req.write(body)
    req.end()
  })
}

function callBurpSseOverHostPath(
  ssePath: string,
  rpcMethod: string,
  rpcParams: Record<string, unknown>,
  timeoutMs = 15_000,
): Promise<unknown> {
  const baseUrl = `http://127.0.0.1:${burpMcpPort}`
  return new Promise((resolve, reject) => {
    let settled = false
    let postEndpoint: URL | null = null
    let initSent = false
    let callSent = false
    let sseBuf = ""

    const finish = (err: Error | null, val?: unknown) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        sseReq.destroy()
      } catch {
        // Ignore
      }
      if (err) reject(err)
      else resolve(val)
    }

    const timer = setTimeout(() => {
      finish(new Error(`Timeout aguardando resposta SSE do Burp MCP em ${baseUrl}${ssePath}`))
    }, timeoutMs)

    const sseReq = http.request(
      {
        hostname: "127.0.0.1",
        port: burpMcpPort,
        path: ssePath,
        method: "GET",
        headers: {
          Host: `127.0.0.1:${burpMcpPort}`,
          Accept: "text/event-stream",
          "Cache-Control": "no-cache",
          "User-Agent": "CyberLab-MCP-Bridge/1.0",
        },
      },
      (res) => {
        if ((res.statusCode ?? 0) !== 200) {
          finish(new Error(`HTTP ${res.statusCode} em ${baseUrl}${ssePath}`))
          return
        }

        res.on("data", (chunk: Buffer) => {
          sseBuf += chunk.toString("utf8").replace(/\r\n/g, "\n")
          let boundaryIdx: number
          while ((boundaryIdx = sseBuf.indexOf("\n\n")) !== -1) {
            const rawBlock = sseBuf.slice(0, boundaryIdx)
            sseBuf = sseBuf.slice(boundaryIdx + 2)
            let eventName = "message"
            const dataLines: string[] = []
            for (const line of rawBlock.split("\n")) {
              if (line.startsWith("event:")) {
                eventName = line.slice(6).trim()
              } else if (line.startsWith("data:")) {
                dataLines.push(line.slice(5).trimStart())
              }
            }
            const dataStr = dataLines.join("\n").trim()
            if (!dataStr) continue

            if (eventName === "endpoint" && !initSent) {
              initSent = true
              try {
                postEndpoint = new URL(dataStr, `${baseUrl}/`)
              } catch (e) {
                finish(e instanceof Error ? e : new Error(String(e)))
                return
              }
              void postJsonHttp(postEndpoint, {
                jsonrpc: "2.0",
                id: 1,
                method: "initialize",
                params: {
                  protocolVersion: "2024-11-05",
                  capabilities: {},
                  clientInfo: { name: "cyberlab-burp-bridge", version: "6.0.2" },
                },
              }).catch((err) => finish(err instanceof Error ? err : new Error(String(err))))
              continue
            }

            if (eventName === "message") {
              let parsed: { id?: number; result?: unknown; error?: { message?: string } }
              try {
                parsed = JSON.parse(dataStr)
              } catch {
                continue
              }
              if (parsed.id === 1 && postEndpoint && !callSent) {
                callSent = true
                void (async () => {
                  try {
                    await postJsonHttp(postEndpoint!, {
                      jsonrpc: "2.0",
                      method: "notifications/initialized",
                    })
                    await postJsonHttp(postEndpoint!, {
                      jsonrpc: "2.0",
                      id: 2,
                      method: rpcMethod,
                      params: rpcParams,
                    })
                  } catch (err) {
                    finish(err instanceof Error ? err : new Error(String(err)))
                  }
                })()
                continue
              }
              if (parsed.id === 2) {
                if (parsed.error) {
                  finish(new Error(parsed.error.message ?? JSON.stringify(parsed.error)))
                } else {
                  finish(null, parsed.result)
                }
                return
              }
            }
          }
        })

        res.on("error", (err) => finish(err))
        res.on("end", () => {
          if (!settled) finish(new Error("Stream SSE encerrado antes da resposta JSON-RPC"))
        })
      },
    )

    sseReq.on("error", (err) => finish(err))
    sseReq.end()
  })
}

function callBurpSseInsideWsl(
  rpcMethod: string,
  rpcParams: Record<string, unknown>,
): { ok: boolean; result?: unknown; error?: string } {
  const pyScript = `
import http.client, json, sys, urllib.parse

port = int(sys.argv[1])
method = sys.argv[2]
params = json.loads(sys.argv[3])

def post_msg(path_and_query, payload):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=12)
    body = json.dumps(payload).encode("utf-8")
    c.request("POST", path_and_query, body=body, headers={
        "Host": f"127.0.0.1:{port}",
        "User-Agent": "CyberLab-MCP-Bridge/1.0",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    c.getresponse().read()
    c.close()

last_err = "no response"
for sse_path in ("/", "/sse"):
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request("GET", sse_path, headers={
            "Host": f"127.0.0.1:{port}",
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "User-Agent": "CyberLab-MCP-Bridge/1.0",
        })
        resp = conn.getresponse()
        if resp.status != 200:
            last_err = f"HTTP {resp.status} on {sse_path}"
            conn.close()
            continue
        ev_name = "message"
        data_lines = []
        post_target = None
        while True:
            raw_line = resp.fp.readline()
            if not raw_line:
                break
            line = raw_line.decode("utf-8", "replace").rstrip("\\r\\n")
            if line == "":
                data_str = "\\n".join(data_lines).strip()
                data_lines = []
                cur_ev = ev_name
                ev_name = "message"
                if not data_str:
                    continue
                if cur_ev == "endpoint" and post_target is None:
                    parsed_u = urllib.parse.urljoin(f"http://127.0.0.1:{port}/", data_str)
                    u = urllib.parse.urlsplit(parsed_u)
                    post_target = u.path + (("?" + u.query) if u.query else "")
                    post_msg(post_target, {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "cyberlab-burp-wsl-bridge", "version": "6.0.2"},
                        },
                    })
                elif cur_ev == "message":
                    msg = json.loads(data_str)
                    if msg.get("id") == 1 and post_target:
                        post_msg(post_target, {"jsonrpc": "2.0", "method": "notifications/initialized"})
                        post_msg(post_target, {"jsonrpc": "2.0", "id": 2, "method": method, "params": params})
                    elif msg.get("id") == 2:
                        conn.close()
                        if "error" in msg:
                            print(json.dumps({"ok": False, "error": msg["error"]}))
                        else:
                            print(json.dumps({"ok": True, "result": msg.get("result")}))
                        sys.exit(0)
            elif line.startswith("event:"):
                ev_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
    except Exception as exc:
        last_err = str(exc)

print(json.dumps({"ok": False, "error": last_err}))
`
  const wslRes = spawnSync(
    "wsl.exe",
    [
      "-d",
      preferredWslDistro,
      "--",
      "python3",
      "-c",
      pyScript,
      String(burpMcpPort),
      rpcMethod,
      JSON.stringify(rpcParams),
    ],
    {
      encoding: "utf8",
      timeout: 22_000,
      windowsHide: true,
    },
  )
  const out = (wslRes.stdout ?? "").trim().split(/\r?\n/).pop() ?? ""
  try {
    const parsed = JSON.parse(out) as { ok: boolean; result?: unknown; error?: unknown }
    if (parsed.ok) return { ok: true, result: parsed.result }
    return {
      ok: false,
      error: typeof parsed.error === "string" ? parsed.error : JSON.stringify(parsed.error),
    }
  } catch {
    return { ok: false, error: (wslRes.stderr || out || "Falha ao conectar via WSL2").trim() }
  }
}

async function callBurpMcpRpc(
  rpcMethod: string,
  rpcParams: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  let hostErr = ""
  for (const ssePath of ["/", "/sse"]) {
    try {
      const result = await callBurpSseOverHostPath(ssePath, rpcMethod, rpcParams, 8_000)
      return { ok: true, result }
    } catch (err) {
      hostErr = err instanceof Error ? err.message : String(err)
    }
  }

  if (process.platform === "win32") {
    const wslAttempt = callBurpSseInsideWsl(rpcMethod, rpcParams)
    if (wslAttempt.ok) return wslAttempt
    return {
      ok: false,
      error: `${hostErr} | WSL2: ${wslAttempt.error ?? "indisponível"}`,
    }
  }

  return { ok: false, error: hostErr }
}

function ensureBurpExtensionJarDownloadedInWsl(): string {
  const script = [
    "mkdir -p /opt/cyberlab-burp",
    "if [ ! -s /opt/cyberlab-burp/burp-mcp-all.jar ]; then curl -fsSL --max-time 25 https://github.com/PortSwigger/mcp-server/releases/latest/download/burp-mcp-all.jar -o /opt/cyberlab-burp/burp-mcp-all.jar && chmod 644 /opt/cyberlab-burp/burp-mcp-all.jar; fi",
    "if [ -s /opt/cyberlab-burp/burp-mcp-all.jar ]; then echo READY:/opt/cyberlab-burp/burp-mcp-all.jar; else echo MISSING; fi",
  ].join(" && ")

  if (process.platform === "win32") {
    const res = spawnSync("wsl.exe", ["-d", preferredWslDistro, "--", "bash", "-c", script], {
      encoding: "utf8",
      timeout: 30_000,
      windowsHide: true,
    })
    return `${res.stdout ?? ""}\n${res.stderr ?? ""}`.trim()
  }
  if (existsSync("/opt/cyberlab-burp/burp-mcp-all.jar")) {
    return "READY:/opt/cyberlab-burp/burp-mcp-all.jar"
  }
  return "MISSING"
}

function extractBurpResultText(rawResult: unknown): string {
  if (!rawResult || typeof rawResult !== "object") {
    return redactSensitiveContent(String(rawResult ?? "")).text
  }
  const obj = rawResult as { content?: Array<{ type?: string; text?: string }> }
  if (Array.isArray(obj.content)) {
    const joined = obj.content
      .map((item) => (typeof item?.text === "string" ? item.text : JSON.stringify(item)))
      .join("\n")
    return redactSensitiveContent(joined).text
  }
  return redactSensitiveContent(JSON.stringify(rawResult, null, 2)).text
}

function offlineBurpGuideMessage(detail?: string): string {
  return [
    `⚠️ O Burp Suite ainda não está respondendo na porta MCP :${burpMcpPort} (${detail ?? "conexão recusada"}).`,
    "",
    "Como ativar em 30 segundos dentro do CyberLab OS (sem precisar reiniciar o OpenCode):",
    "1. Na barra esquerda ('Slots'), clique em 'Burp Suite' e depois em '🖥 Abrir Aqui Dentro do CyberLab' (o CyberLab já baixa automaticamente a extensão oficial '/opt/cyberlab-burp/burp-mcp-all.jar' da PortSwigger!).",
    "2. Dentro da janela do Burp Suite, abra a aba 'Extensions' -> 'Installed' -> clique em 'Add':",
    "   - Extension type: Java",
    "   - Extension file (.jar): /opt/cyberlab-burp/burp-mcp-all.jar  (ou instale 'MCP Server' pela aba BApp Store)",
    "   - Clique em 'Next' (a nova aba 'MCP' aparecerá no topo do Burp já com 'Enabled' marcado na porta 9876!).",
    "3. Pronto! Basta pedir novamente aqui no chat que a conexão será feita ao vivo.",
  ].join("\n")
}

const BURP_MCP_TOOLS = [
  {
    name: "burp_suite_status",
    description:
      "Verifica se o servidor MCP oficial do Burp Suite (:9876) está online (no host ou dentro do Kali WSL2), garante o download automático de '/opt/cyberlab-burp/burp-mcp-all.jar' e lista todas as ferramentas ativas do Burp.",
    inputSchema: {
      type: "object",
      properties: {
        ensureExtensionDownloaded: {
          type: "boolean",
          description: "Se true (padrão), baixa automaticamente burp-mcp-all.jar em /opt/cyberlab-burp/ caso ainda não exista.",
        },
      },
    },
  },
  {
    name: "burp_suite_get_proxy_history",
    description:
      "Lê o histórico HTTP capturado pelo Proxy do Burp Suite (com suporte opcional a filtro Regex e redação automática de segredos).",
    inputSchema: {
      type: "object",
      properties: {
        count: { type: "number", description: "Quantidade de itens para retornar (padrão: 20)" },
        offset: { type: "number", description: "Índice inicial para paginação (padrão: 0)" },
        regex: { type: "string", description: "Expressão regular opcional para filtrar URLs/requests/responses" },
      },
    },
  },
  {
    name: "burp_suite_send_http1_request",
    description:
      "Envia uma requisição HTTP/1.1 bruta diretamente pelo motor do Burp Suite (validada pela Trava de Escopo Bug Bounty do CyberLab OS) e retorna a resposta completa.",
    inputSchema: {
      type: "object",
      required: ["targetHostname", "targetPort", "usesHttps", "content"],
      properties: {
        targetHostname: { type: "string", description: "Hostname do alvo autorizado no escopo" },
        targetPort: { type: "number", description: "Porta TCP de destino (ex.: 443 ou 80)" },
        usesHttps: { type: "boolean", description: "true para HTTPS/TLS, false para HTTP" },
        content: { type: "string", description: "Requisição HTTP/1.1 completa (headers + linha em branco + body opcional)" },
      },
    },
  },
  {
    name: "burp_suite_create_repeater_tab",
    description:
      "Cria uma nova aba no Repeater dentro da janela aberta do Burp Suite com a requisição HTTP especificada.",
    inputSchema: {
      type: "object",
      required: ["targetHostname", "targetPort", "usesHttps", "content"],
      properties: {
        tabName: { type: "string", description: "Título opcional da aba no Repeater" },
        targetHostname: { type: "string", description: "Hostname do alvo autorizado" },
        targetPort: { type: "number", description: "Porta TCP (ex.: 443 ou 80)" },
        usesHttps: { type: "boolean", description: "true para HTTPS, false para HTTP" },
        content: { type: "string", description: "Requisição HTTP/1.1 bruta" },
      },
    },
  },
  {
    name: "burp_suite_send_to_intruder",
    description:
      "Envia uma requisição HTTP para uma nova aba do Intruder dentro do Burp Suite.",
    inputSchema: {
      type: "object",
      required: ["targetHostname", "targetPort", "usesHttps", "content"],
      properties: {
        tabName: { type: "string", description: "Título opcional da aba no Intruder" },
        targetHostname: { type: "string", description: "Hostname do alvo autorizado" },
        targetPort: { type: "number", description: "Porta TCP" },
        usesHttps: { type: "boolean", description: "true para HTTPS, false para HTTP" },
        content: { type: "string", description: "Requisição HTTP/1.1 bruta" },
      },
    },
  },
  {
    name: "burp_suite_set_intercept",
    description: "Liga ou desliga o botão 'Intercept is on/off' do Proxy do Burp Suite.",
    inputSchema: {
      type: "object",
      required: ["intercepting"],
      properties: {
        intercepting: { type: "boolean", description: "true para ligar Intercept, false para desligar" },
      },
    },
  },
  {
    name: "burp_suite_call_tool",
    description:
      "Executa qualquer ferramenta adicional exposta pela extensão oficial Burp MCP Server (:9876), como send_http2_request, create_repeater_tab_http2, get_proxy_websocket_history, get_organizer_items, get_active_editor_contents, output_project_options, url_encode ou base64_encode.",
    inputSchema: {
      type: "object",
      required: ["toolName"],
      properties: {
        toolName: { type: "string", description: "Nome exato da tool na extensão Burp MCP Server" },
        toolArgs: { type: "object", description: "Objeto JSON de argumentos para a tool" },
      },
    },
  },
]

interface JsonRpcRequest {
  jsonrpc: "2.0"
  id?: string | number | null
  method: string
  params?: Record<string, unknown>
}

let useContentLengthFraming = false

function sendResponse(payload: Record<string, unknown>) {
  const json = JSON.stringify(payload)
  if (useContentLengthFraming) {
    const byteLen = Buffer.byteLength(json, "utf8")
    process.stdout.write(`Content-Length: ${byteLen}\r\n\r\n${json}`)
  } else {
    process.stdout.write(`${json}\n`)
  }
}

async function handleBurpToolCall(
  id: string | number | null,
  toolName: string,
  callArgs: Record<string, unknown>,
): Promise<void> {
  if (toolName === "burp_suite_status") {
    const shouldEnsure = callArgs.ensureExtensionDownloaded !== false
    const extState = shouldEnsure ? ensureBurpExtensionJarDownloadedInWsl() : "SKIPPED"
    const listRes = await callBurpMcpRpc("tools/list", {})
    if (!listRes.ok) {
      sendResponse({
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: `${offlineBurpGuideMessage(listRes.error)}\n\nExtensão em disco (/opt/cyberlab-burp/burp-mcp-all.jar): ${extState}`,
            },
          ],
        },
      })
      return
    }
    const toolsArr =
      ((listRes.result as { tools?: Array<{ name?: string; description?: string }> })?.tools ?? [])
        .map((t) => `- ${t.name}: ${t.description ?? ""}`)
        .join("\n")
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        content: [
          {
            type: "text",
            text: `✅ Burp Suite MCP Server CONECTADO na porta :${burpMcpPort}!\nFerramentas ativas expostas pelo Burp:\n${toolsArr}`,
          },
        ],
      },
    })
    return
  }

  // Scope guard check whenever targetHostname is present
  const targetHost =
    typeof callArgs.targetHostname === "string"
      ? callArgs.targetHostname.trim()
      : typeof (callArgs.toolArgs as Record<string, unknown> | undefined)?.targetHostname === "string"
        ? String((callArgs.toolArgs as Record<string, unknown>).targetHostname).trim()
        : ""
  if (targetHost) {
    const scopeCheck = checkTargetAllowedInWorkspaceScope(targetHost)
    if (!scopeCheck.allowed) {
      sendResponse({
        jsonrpc: "2.0",
        id,
        result: {
          isError: true,
          content: [{ type: "text", text: scopeCheck.reason ?? "Alvo fora de escopo." }],
        },
      })
      return
    }
  }

  let upstreamName = ""
  let upstreamArgs: Record<string, unknown> = {}

  if (toolName === "burp_suite_get_proxy_history") {
    const count = typeof callArgs.count === "number" ? callArgs.count : 20
    const offset = typeof callArgs.offset === "number" ? callArgs.offset : 0
    const regex = typeof callArgs.regex === "string" ? callArgs.regex.trim() : ""
    if (regex) {
      upstreamName = "get_proxy_http_history_regex"
      upstreamArgs = { regex, count, offset }
    } else {
      upstreamName = "get_proxy_http_history"
      upstreamArgs = { count, offset }
    }
  } else if (toolName === "burp_suite_send_http1_request") {
    upstreamName = "send_http1_request"
    upstreamArgs = {
      targetHostname: String(callArgs.targetHostname ?? ""),
      targetPort: Number(callArgs.targetPort ?? 443),
      usesHttps: Boolean(callArgs.usesHttps ?? true),
      content: String(callArgs.content ?? ""),
    }
  } else if (toolName === "burp_suite_create_repeater_tab") {
    upstreamName = "create_repeater_tab"
    upstreamArgs = {
      tabName: typeof callArgs.tabName === "string" ? callArgs.tabName : null,
      targetHostname: String(callArgs.targetHostname ?? ""),
      targetPort: Number(callArgs.targetPort ?? 443),
      usesHttps: Boolean(callArgs.usesHttps ?? true),
      content: String(callArgs.content ?? ""),
    }
  } else if (toolName === "burp_suite_send_to_intruder") {
    upstreamName = "send_to_intruder"
    upstreamArgs = {
      tabName: typeof callArgs.tabName === "string" ? callArgs.tabName : null,
      targetHostname: String(callArgs.targetHostname ?? ""),
      targetPort: Number(callArgs.targetPort ?? 443),
      usesHttps: Boolean(callArgs.usesHttps ?? true),
      content: String(callArgs.content ?? ""),
    }
  } else if (toolName === "burp_suite_set_intercept") {
    upstreamName = "set_proxy_intercept_state"
    upstreamArgs = {
      intercepting: Boolean(callArgs.intercepting),
    }
  } else if (toolName === "burp_suite_call_tool") {
    upstreamName = String(callArgs.toolName ?? "")
    upstreamArgs =
      callArgs.toolArgs && typeof callArgs.toolArgs === "object"
        ? (callArgs.toolArgs as Record<string, unknown>)
        : {}
  } else {
    sendResponse({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Tool Burp desconhecida: ${toolName}` },
    })
    return
  }

  const rpcRes = await callBurpMcpRpc("tools/call", {
    name: upstreamName,
    arguments: upstreamArgs,
  })

  if (!rpcRes.ok) {
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        isError: true,
        content: [{ type: "text", text: offlineBurpGuideMessage(rpcRes.error) }],
      },
    })
    return
  }

  sendResponse({
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: extractBurpResultText(rpcRes.result) }],
    },
  })
}

async function handleRpc(msg: JsonRpcRequest): Promise<void> {
  if (msg.method === "notifications/initialized" || msg.id === undefined) {
    return
  }

  if (msg.method === "initialize") {
    sendResponse({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: `cyberlab-mcp-${slotId}`,
          version: "6.0.2",
        },
      },
    })
    return
  }

  if (msg.method === "ping") {
    sendResponse({ jsonrpc: "2.0", id: msg.id, result: {} })
    return
  }

  if (msg.method === "tools/list") {
    if (slotId === "burp-suite") {
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: { tools: BURP_MCP_TOOLS },
      })
      return
    }

    sendResponse({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        tools: [
          {
            name: `${safeToolPrefix}_help`,
            description: `Consulta a versão, flags e capacidades da ferramenta externa ${displayName} instalada no ambiente.`,
            inputSchema: {
              type: "object",
              properties: {},
            },
          },
          {
            name: `${safeToolPrefix}_audit`,
            description: `Executa auditoria/inspeção supervisionada com ${displayName} respeitando estritamente a Trava de Escopo do CyberLab OS e redação SHA-256.`,
            inputSchema: {
              type: "object",
              properties: {
                target: {
                  type: "string",
                  description: "Arquivo local do workspace ou alvo autorizado no escopo Bug Bounty",
                },
                args: {
                  type: "array",
                  items: { type: "string" },
                  description: "Lista de argumentos seguros (sem shell) para inspeção/auditoria",
                },
              },
            },
          },
        ],
      },
    })
    return
  }

  if (msg.method === "tools/call") {
    const params = (msg.params ?? {}) as { name?: string; arguments?: Record<string, unknown> }
    const toolName = params.name ?? ""
    const callArgs = params.arguments ?? {}

    if (slotId === "burp-suite") {
      await handleBurpToolCall(msg.id ?? null, toolName, callArgs)
      return
    }

    if (toolName === `${safeToolPrefix}_help`) {
      const res = runToolArgs(["--help"])
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          content: [
            {
              type: "text",
              text: res.output || `${displayName} respondeu com código ${res.exitCode}.`,
            },
          ],
        },
      })
      return
    }

    if (toolName === `${safeToolPrefix}_audit`) {
      const target = typeof callArgs.target === "string" ? callArgs.target.trim() : ""
      if (target) {
        const scopeCheck = checkTargetAllowedInWorkspaceScope(target)
        if (!scopeCheck.allowed) {
          sendResponse({
            jsonrpc: "2.0",
            id: msg.id,
            result: {
              isError: true,
              content: [{ type: "text", text: scopeCheck.reason ?? "Alvo fora de escopo." }],
            },
          })
          return
        }
      }
      const rawList = Array.isArray(callArgs.args)
        ? callArgs.args.filter((x): x is string => typeof x === "string")
        : ["--version"]
      const finalArgs = target ? [...rawList, target] : rawList
      const res = runToolArgs(finalArgs)
      sendResponse({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          isError: res.exitCode !== 0 && !res.output,
          content: [
            {
              type: "text",
              text: res.output || `Concluído (exitCode=${res.exitCode}).`,
            },
          ],
        },
      })
      return
    }

    sendResponse({
      jsonrpc: "2.0",
      id: msg.id,
      error: { code: -32601, message: `Tool desconhecida: ${toolName}` },
    })
    return
  }

  sendResponse({
    jsonrpc: "2.0",
    id: msg.id,
    error: { code: -32601, message: `Método MCP não suportado: ${msg.method}` },
  })
}

let rpcQueue: Promise<void> = Promise.resolve()
function enqueueRpc(req: JsonRpcRequest) {
  rpcQueue = rpcQueue.then(() => handleRpc(req)).catch(() => undefined)
}

let buffer = Buffer.alloc(0)
process.stdin.on("data", (chunk: Buffer) => {
  buffer = Buffer.concat([buffer, chunk])
  while (buffer.length > 0) {
    const preview = buffer.toString("utf8", 0, Math.min(buffer.length, 64))
    if (preview.startsWith("Content-Length:")) {
      useContentLengthFraming = true
      const headerEnd = buffer.indexOf("\r\n\r\n")
      if (headerEnd === -1) return
      const headerStr = buffer.toString("utf8", 0, headerEnd)
      const match = headerStr.match(/Content-Length:\s*(\d+)/i)
      const len = match ? Number.parseInt(match[1]!, 10) : 0
      const totalNeeded = headerEnd + 4 + len
      if (buffer.length < totalNeeded) return
      const bodyStr = buffer.toString("utf8", headerEnd + 4, totalNeeded)
      buffer = buffer.subarray(totalNeeded)
      try {
        enqueueRpc(JSON.parse(bodyStr) as JsonRpcRequest)
      } catch {
        // Ignore malformed frame
      }
    } else {
      const nlIdx = buffer.indexOf("\n")
      if (nlIdx === -1) return
      const line = buffer.toString("utf8", 0, nlIdx).trim()
      buffer = buffer.subarray(nlIdx + 1)
      if (!line) continue
      try {
        enqueueRpc(JSON.parse(line) as JsonRpcRequest)
      } catch {
        // Ignore malformed line
      }
    }
  }
})
