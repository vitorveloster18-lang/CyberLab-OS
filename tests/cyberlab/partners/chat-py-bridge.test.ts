import { describe, expect, test } from "bun:test"
import { spawn } from "node:child_process"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url))
const bridgeScriptPath = path.join(repoRoot, "integrations", "partners", "chat_py_bridge.py")

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address()
      const port = typeof addr === "object" && addr ? addr.port : 0
      srv.close((err) => (err ? reject(err) : resolve(port)))
    })
  })
}

async function waitForHealth(port: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`)
      if (res.ok) return
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 80))
  }
  throw new Error(`chat_py_bridge.py did not become ready on port ${port}`)
}

describe("Python chat_py_bridge.py <-> CyberLab OS HMAC-SHA256 Interoperability", () => {
  test("bridges external chat.py script over signed HTTP envelope, redacts secrets, and records unreviewed findings", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-chatpy-"))
    const port = await getFreePort()
    const secret = "chat-py-bridge-shared-secret-key-2026"

    // Sample external chat.py runtime echoing whether any secret leaked and returning structured JSON
    const sampleChatPy = path.join(tmpDir, "chat.py")
    writeFileSync(
      sampleChatPy,
      [
        "import json, sys",
        "prompt = sys.argv[1] if len(sys.argv) > 1 else ''",
        "leaked = 'top_secret_bearer_999' in prompt",
        "print(json.dumps({",
        "  'status': 'completed',",
        "  'summary': f'Analisado pelo chat.py (secret_leaked={leaked})',",
        "  'findings': [{",
        "    'title': 'Cabeçalho Server exposto identificado pelo chat.py',",
        "    'description': 'O endpoint retornou versão explícita no cabeçalho HTTP.',",
        "    'evidenceRefs': [],",
        "    'confidence': 0.75",
        "  }],",
        "  'limitations': ['Análise externa via chat.py']",
        "}))",
      ].join("\n"),
      "utf8",
    )

    const proc = spawn(
      "python3",
      [
        bridgeScriptPath,
        "--partner-id",
        "chat-py-agent",
        "--host",
        "127.0.0.1",
        "--port",
        String(port),
        "--mode",
        "arg",
        "--script",
        sampleChatPy,
      ],
      {
        env: { ...process.env, CYBERLAB_PARTNER_SECRET: secret },
        stdio: ["ignore", "pipe", "pipe"],
      },
    )

    try {
      await waitForHealth(port)

      const ws = new CyberLabWorkspace({
        projectId: "proj-chatpy",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      })
      await ws.ensureInitialized()

      const rawEv = ws.evidenceStore.storeEvidence("proj-chatpy", {
        kind: "http_exchange",
        title: "API response with Bearer token",
        source: {
          toolId: "manual",
          executorId: "manual",
          executionId: "exec-1",
        },
        content: {
          mediaType: "text/plain",
          inlineText: "HTTP/1.1 200 OK\nAuthorization: Bearer top_secret_bearer_999\nServer: nginx/1.18.0",
        },
        observedAt: new Date().toISOString(),
      })

      const outcome = await ws.delegateToPartner({
        partnerId: "chat-py-agent",
        endpointUrl: `http://127.0.0.1:${port}/cyberlab/partner`,
        sharedSecret: secret,
        objective: "Revisar cabeçalhos HTTP capturados",
        evidenceIds: [rawEv.evidenceId],
      })

      expect(outcome.result?.status).toBe("completed")
      expect(outcome.result?.summary).toContain("secret_leaked=False")
      expect(outcome.createdFindings).toHaveLength(1)
      expect(outcome.createdFindings[0]?.status).toBe("unreviewed")

      ws.close()
    } finally {
      proc.kill("SIGTERM")
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
