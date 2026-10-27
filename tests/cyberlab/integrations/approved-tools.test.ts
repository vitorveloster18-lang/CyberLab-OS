import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"
import { HttpSecurityInspectorCapability } from "../../../integrations/web-security/http-security-inspector.js"
import { TcpSurfaceProbeCapability } from "../../../integrations/network-observation/tcp-banner-inspector.js"
import { verifyRepositoryLicenseCompliance } from "../../../script/check-cyberlab-licenses.js"

describe("Approved Tool Integrations & License Compliance Gate", () => {
  test("passes repository license compliance gate and rejects copyleft/unnoticed embedded manifests", () => {
    const repoSummary = verifyRepositoryLicenseCompliance()
    expect(repoSummary.violations).toEqual([])
    expect(repoSummary.checkedCount).toBeGreaterThanOrEqual(5)
    expect(repoSummary.embeddedCount).toBeGreaterThanOrEqual(4)

    // Simulate a rogue AGPL embedded manifest in a temp folder
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-lic-"))
    try {
      const manifestsDir = path.join(tmpDir, "manifests")
      const noticesPath = path.join(tmpDir, "THIRD_PARTY_NOTICES.md")
      writeFileSync(noticesPath, "# Notices\n")
      const rogueManifest = {
        id: "rogue-agpl-agent",
        version: "0.1.0",
        source: "https://example.org/rogue",
        commit: "deadbeef",
        license: {
          spdx: "AGPL-3.0-only",
          reviewStatus: "approved_embed",
          reviewNotes: [],
        },
        integration: {
          mode: "embedded",
        },
        dependenciesReviewed: true,
        noticesRecorded: true,
        lastReviewedAt: "2026-10-26T00:00:00.000Z",
      }
      const { mkdirSync } = require("node:fs") as typeof import("node:fs")
      mkdirSync(manifestsDir, { recursive: true })
      writeFileSync(path.join(manifestsDir, "rogue.json"), JSON.stringify(rogueManifest, null, 2))

      const badSummary = verifyRepositoryLicenseCompliance(manifestsDir, noticesPath)
      expect(badSummary.violations.length).toBeGreaterThanOrEqual(2)
      expect(badSummary.violations.some((v) => v.includes("AGPL-3.0-only"))).toBe(true)
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("executes passive HTTP security inspector against local 127.0.0.1 lab server, redacts cookies, and blocks out-of-scope URLs", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-http-tool-"))
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        return new Response("<html><body>Lab Portal</body></html>", {
          status: 200,
          headers: {
            "Content-Type": "text/html",
            Server: "LabPortal/2.4.9",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": "sid=super_secret_session_cookie_999; Path=/",
          },
        })
      },
    })

    try {
      const ws = new CyberLabWorkspace({
        projectId: "proj-http-lab",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      })

      // Out-of-scope public domain and cloud metadata SSRF MUST be blocked before fetch!
      const blockedPublic = await ws.submitExecution({
        capabilityId: HttpSecurityInspectorCapability.id,
        input: { url: "https://example.com/login" },
        mode: "manual",
      })
      expect(blockedPublic.status).toBe("blocked")

      const blockedMetadata = await ws.submitExecution({
        capabilityId: HttpSecurityInspectorCapability.id,
        input: { url: "http://169.254.169.254/latest/meta-data/" },
        mode: "manual",
      })
      expect(blockedMetadata.status).toBe("blocked")

      // Authorized 127.0.0.1 lab endpoint succeeds and produces SHA-256 evidence
      const targetUrl = `http://127.0.0.1:${server.port}/`
      const okExec = await ws.submitExecution({
        capabilityId: HttpSecurityInspectorCapability.id,
        input: { url: targetUrl, method: "GET" },
        mode: "manual",
      })
      expect(okExec.status).toBe("succeeded")
      expect(okExec.resultEvidenceIds).toHaveLength(2)

      const evidence = await ws.listEvidence(okExec.executionId)
      const rawExchange = evidence.find((e) => e.kind === "http_exchange")
      const jsonReport = evidence.find((e) => e.kind === "json")

      expect(rawExchange).toBeDefined()
      expect(rawExchange?.content.inlineText).toContain("[REDACTED:COOKIE_VALUE]")
      expect(rawExchange?.content.inlineText).not.toContain("super_secret_session_cookie_999")

      const parsedReport = JSON.parse(jsonReport?.content.inlineText ?? "{}") as {
        issueCount: number
        observations: Array<{ code: string; status: string }>
      }
      expect(parsedReport.issueCount).toBeGreaterThanOrEqual(4)
      expect(parsedReport.observations.some((o) => o.code === "HDR-CORS-WILDCARD-CREDS")).toBe(true)
      expect(parsedReport.observations.some((o) => o.code === "COOKIE-FLAGS")).toBe(true)

      ws.close()
    } finally {
      server.stop(true)
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("executes controlled TCP surface & banner probe against local 127.0.0.1 lab listener", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-tcp-tool-"))
    const tcpServer = net.createServer((socket) => {
      socket.write("220 cyberlab-lab-service.local ESMTP Ready\r\n")
      socket.end()
    })

    await new Promise<void>((resolve) => tcpServer.listen(0, "127.0.0.1", resolve))
    const address = tcpServer.address()
    const port = typeof address === "object" && address ? address.port : 0

    try {
      const ws = new CyberLabWorkspace({
        projectId: "proj-tcp-lab",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      })

      const probeExec = await ws.submitExecution({
        capabilityId: TcpSurfaceProbeCapability.id,
        input: { host: "127.0.0.1", port, bannerWaitMs: 150 },
        mode: "manual",
      })
      expect(probeExec.status).toBe("succeeded")

      const evidence = await ws.listEvidence(probeExec.executionId)
      const netObs = evidence.find((e) => e.kind === "network_observation")
      expect(netObs).toBeDefined()
      expect(netObs?.content.inlineText).toContain("220 cyberlab-lab-service.local ESMTP Ready")

      ws.close()
    } finally {
      await new Promise<void>((resolve) => tcpServer.close(() => resolve()))
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
