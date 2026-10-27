import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"

describe("CyberLab Local HTTP Capture Proxy & Evidence Content Inspector", () => {
  test("captures live in-scope HTTP exchanges, redacts Authorization/Cookie headers, and persists SHA-256 custody records", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-proxy-"))
    const upstream = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const u = new URL(req.url)
        return new Response(JSON.stringify({ path: u.pathname, ok: true }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": "sid=super_secret_session_cookie_999; HttpOnly",
          },
        })
      },
    })
    const ws = new CyberLabWorkspace({ projectId: "proj-proxy-test", workspaceRoot: tmpDir, inMemoryDb: true })

    try {
      const started = await ws.controlProxy({ action: "start", port: 0, scopeOnly: true })
      expect(started.status.running).toBe(true)
      const proxyPort = started.status.listenPort!
      expect(proxyPort).toBeGreaterThan(0)

      // Send live traffic through local proxy via X-CyberLab-Target-Url
      const res = await fetch(`http://127.0.0.1:${proxyPort}/`, {
        method: "POST",
        headers: {
          "X-CyberLab-Target-Url": `http://127.0.0.1:${upstream.port}/api/login`,
          Authorization: "Bearer super_secret_bearer_token_abc",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ user: "analyst" }),
      })
      expect(res.status).toBe(200)
      const json = (await res.json()) as { path: string; ok: boolean }
      expect(json.path).toBe("/api/login")

      const overview = await ws.getProxyOverview()
      expect(overview.history.length).toBe(1)
      const captured = overview.history[0]!
      expect(captured.method).toBe("POST")
      expect(captured.statusCode).toBe(200)
      expect(captured.blockedByScope).toBe(false)
      // Sensitive headers must be redacted in proxy history!
      expect(captured.requestHeaders.authorization).toContain("[REDACTED")
      expect(captured.responseHeaders["set-cookie"]).toContain("[REDACTED")

      // Persist captured exchange to SQLite SHA-256 EvidenceStore & read via Studio inspector
      const saved = await ws.persistProxyEntry(captured.entryId, "operator-test")
      expect(saved.sha256).toMatch(/^[a-f0-9]{64}$/)

      const verify = await ws.verifyEvidence(saved.evidenceId, "operator-test")
      expect(verify.valid).toBe(true)

      const content = await ws.readEvidenceContent(saved.evidenceId, "operator-test")
      expect(content.sha256).toBe(saved.sha256)
      expect(content.text).toContain("/api/login")
      expect(content.text).not.toContain("super_secret_bearer_token_abc")
      expect(content.text).not.toContain("super_secret_session_cookie_999")
    } finally {
      await ws.close()
      upstream.stop(true)
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("blocks out-of-scope public targets when scopeOnly=true and unconditionally blocks cloud metadata SSRF (169.254.169.254)", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-proxy-scope-"))
    const ws = new CyberLabWorkspace({ projectId: "proj-proxy-scope", workspaceRoot: tmpDir, inMemoryDb: true })

    try {
      const started = await ws.controlProxy({ action: "start", port: 0, scopeOnly: true })
      const proxyPort = started.status.listenPort!

      // 1. Out-of-scope public target blocked with 403
      const blockedPublic = await fetch(`http://127.0.0.1:${proxyPort}/`, {
        headers: { "X-CyberLab-Target-Url": "http://93.184.216.34/secret" },
      })
      expect(blockedPublic.status).toBe(403)

      // 2. Even if operator disables scopeOnly, cloud metadata SSRF 169.254.169.254 remains unconditionally blocked
      await ws.controlProxy({ action: "set_scope_only", scopeOnly: false })
      const blockedMetadata = await fetch(`http://127.0.0.1:${proxyPort}/`, {
        headers: { "X-CyberLab-Target-Url": "http://169.254.169.254/latest/meta-data/" },
      })
      expect(blockedMetadata.status).toBe(403)
      const body = (await blockedMetadata.json()) as { reason: string }
      expect(body.reason).toContain("metadata")

      const overview = await ws.getProxyOverview()
      expect(overview.history.length).toBe(2)
      expect(overview.history.every((e) => e.blockedByScope)).toBe(true)
    } finally {
      await ws.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("enforces cross-project isolation in readEvidenceContent", async () => {
    const tmpA = mkdtempSync(path.join(os.tmpdir(), "cyberlab-iso-a-"))
    const tmpB = mkdtempSync(path.join(os.tmpdir(), "cyberlab-iso-b-"))
    const wsA = new CyberLabWorkspace({ projectId: "proj-a", workspaceRoot: tmpA, inMemoryDb: false })
    const wsB = new CyberLabWorkspace({ projectId: "proj-b", workspaceRoot: tmpB, inMemoryDb: false })

    try {
      const rec = await wsA.submitExecution({
        capabilityId: "web-assessment.decoder-sequencer",
        input: { value: "SGVsbG8gQ3liZXJMYWI=", transforms: ["base64_decode"] },
        mode: "manual",
      })
      expect(rec.status).toBe("succeeded")
      const evId = rec.resultEvidenceIds[0]!
      const docA = await wsA.readEvidenceContent(evId, "operator-a")
      expect(docA.text).toContain("Hello CyberLab")

      await expect(wsB.readEvidenceContent(evId, "operator-b")).rejects.toThrow()
    } finally {
      await wsA.close()
      await wsB.close()
      rmSync(tmpA, { recursive: true, force: true })
      rmSync(tmpB, { recursive: true, force: true })
    }
  })
})
