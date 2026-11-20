import { spawn } from "node:child_process"
import { mkdirSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { afterEach, describe, expect, test } from "bun:test"

const SCRIPT = path.resolve(import.meta.dir, "../../../cyberlab/mcp/knowledge-mcp-stdio.ts")

const EXPECTED_TOOLS = [
  "search_knowledge",
  "read_document",
  "get_related_documents",
  "get_document_metadata",
  "create_draft_note",
  "propose_document_update",
  "investigation_memory_read",
  "investigation_memory_update",
]

interface Rpc {
  jsonrpc: string
  id?: number
  method?: string
  params?: Record<string, unknown>
}

/** Sobe o servidor, envia as requisições e devolve as respostas coletadas. */
function runServer(workspace: string, requests: Rpc[], timeoutMs = 20000): Promise<
  Array<Record<string, unknown>>
> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, ["run", SCRIPT, "--workspace", workspace], {
      stdio: ["pipe", "pipe", "pipe"],
    })

    const responses: Array<Record<string, unknown>> = []
    let stdoutBuf = ""

    const timer = setTimeout(() => {
      proc.kill()
      reject(new Error(`Timeout. Respostas coletadas: ${responses.length}`))
    }, timeoutMs)

    proc.stdout.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf8")
      let nl: number
      while ((nl = stdoutBuf.indexOf("\n")) !== -1) {
        const line = stdoutBuf.slice(0, nl).trim()
        stdoutBuf = stdoutBuf.slice(nl + 1)
        if (!line) continue
        try {
          const parsed = JSON.parse(line) as Record<string, unknown>
          responses.push(parsed)
          if (responses.length === requests.filter((r) => r.id !== undefined).length) {
            clearTimeout(timer)
            proc.kill()
            resolve(responses)
          }
        } catch {
          // Ignora linha nao-JSON
        }
      }
    })

    proc.on("error", (err) => {
      clearTimeout(timer)
      reject(err)
    })

    const send = () => {
      for (const req of requests) proc.stdin.write(`${JSON.stringify(req)}\n`)
    }
    setTimeout(send, 400)
  })
}

let tmpWorkspace = ""

function makeWorkspace(): string {
  tmpWorkspace = mkdtempSync(path.join(tmpdir(), "cyberlab-knowledge-mcp-"))
  mkdirSync(path.join(tmpWorkspace, ".cyberlab"), { recursive: true })
  return tmpWorkspace
}

afterEach(() => {
  if (tmpWorkspace) {
    try {
      rmSync(tmpWorkspace, { recursive: true, force: true })
    } catch {
      // ignore
    }
    tmpWorkspace = ""
  }
})

describe("Servidor MCP da Biblioteca de Conhecimento", () => {
  test("responde initialize e lista as 8 ferramentas", async () => {
    const ws = makeWorkspace()
    const res = await runServer(ws, [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    ])

    const init = res.find((r) => r.id === 1) as { result: { serverInfo: { name: string } } }
    expect(init.result.serverInfo.name).toBe("cyberlab-knowledge")

    const list = res.find((r) => r.id === 2) as {
      result: { tools: Array<{ name: string }> }
    }
    const names = list.result.tools.map((t) => t.name)
    for (const tool of EXPECTED_TOOLS) expect(names).toContain(tool)
    // Nenhuma ferramenta do arsenal sobreviveu.
    expect(names.some((n) => n.startsWith("arsenal_"))).toBe(false)
  })

  test("search_knowledge semeia a biblioteca e devolve resultados", async () => {
    const ws = makeWorkspace()
    const res = await runServer(ws, [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "search_knowledge", arguments: { query: "hypothesis" } },
      },
    ])

    const call = res.find((r) => r.id === 2) as {
      result: { content: Array<{ text: string }> }
    }
    const text = call.result.content[0]?.text ?? ""
    expect(text.length).toBeGreaterThan(0)
    expect(text).toContain("methodologies/hypothesis-driven-testing")
  })

  test("ferramenta desconhecida devolve isError em vez de estourar", async () => {
    const ws = makeWorkspace()
    const res = await runServer(ws, [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "nao_existe", arguments: {} },
      },
    ])

    const call = res.find((r) => r.id === 2) as {
      result: { isError?: boolean; content: Array<{ text: string }> }
    }
    expect(call.result.isError).toBe(true)
  })
})
