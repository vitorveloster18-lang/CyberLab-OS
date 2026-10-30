#!/usr/bin/env bun
/**
 * CyberLab OS — Scope-Guarded Arsenal MCP Stdio Bridge (JSON-RPC 2.0)
 *
 * Exposes an installed external Arsenal tool slot to the OpenCode V2 AI Agent
 * over standard Model Context Protocol (stdio) while enforcing:
 * - Zero shell interpolation (spawn with argv array)
 * - Scope validation against .cyberlab/scope-rules.json for external targets
 * - Automatic secret/credential redaction on stdout/stderr
 */

import { spawnSync } from "node:child_process"
import { existsSync, readFileSync } from "node:fs"
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

function handleRpc(msg: JsonRpcRequest) {
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
          version: "5.8.0",
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
        handleRpc(JSON.parse(bodyStr) as JsonRpcRequest)
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
        handleRpc(JSON.parse(line) as JsonRpcRequest)
      } catch {
        // Ignore malformed line
      }
    }
  }
})
