import { afterEach, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import http from "node:http"
import os from "node:os"
import path from "node:path"
import zlib from "node:zlib"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"

const tempDirs: string[] = []
const workspaces: CyberLabWorkspace[] = []
const servers: http.Server[] = []

afterEach(async () => {
  for (const ws of workspaces.splice(0)) {
    ws.close()
  }
  for (const srv of servers.splice(0)) {
    await new Promise<void>((resolve) => srv.close(() => resolve()))
  }
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true })
  }
})

describe("CyberLab OS v4.0 — Bug Bounty / Production Readiness & Burp Suite / OpenTRAP Parity", () => {
  test("1. HackerOne structured_scopes importer, url_prefix/wildcard exclusions, and .cyberlab/scope.json disk persistence", async () => {
    const wsDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v4-scope-"))
    tempDirs.push(wsDir)

    const ws1 = new CyberLabWorkspace({
      projectId: "bounty-proj-1",
      workspaceRoot: wsDir,
      inMemoryDb: false,
    })
    workspaces.push(ws1)

    const hackerOneExport = JSON.stringify({
      attributes: {
        handle: "acme-corp",
        relationships: {
          structured_scopes: {
            data: [
              {
                attributes: {
                  asset_type: "WILDCARD",
                  asset_identifier: "*.acme-target.example",
                  eligible_for_submission: true,
                },
              },
              {
                attributes: {
                  asset_type: "URL",
                  asset_identifier: "https://api.acme-target.example/v2/",
                  eligible_for_submission: true,
                },
              },
              {
                attributes: {
                  asset_type: "DOMAIN",
                  asset_identifier: "billing.acme-target.example",
                  eligible_for_submission: false,
                },
              },
            ],
          },
        },
      },
    })

    const imported = await ws1.importBugBountyScope({
      rawInput: hackerOneExport,
      platformHint: "hackerone",
      researcherHandle: "vitorsec",
      maxRequestsPerSecond: 15,
    })

    expect(imported.detectedFormat).toBe("hackerone_json")
    expect(imported.importedAllowedCount).toBe(4) // 2 HackerOne assets + 127.0.0.1 + localhost
    expect(imported.importedBlockedCount).toBe(2) // 1 out-of-scope domain + .git
    expect(imported.scope.allowExternalTargets).toBe(true)
    expect(imported.scope.engagement?.mode).toBe("bug_bounty")
    expect(imported.scope.engagement?.customHeaders[0]).toEqual({
      name: "X-Bug-Bounty",
      value: "HackerOne-vitorsec",
      enabled: true,
    })

    // Wildcard allowed, url_prefix allowed, explicit out-of-scope subdomain blocked
    expect(
      ws1.scopes.verifyTargets("bounty-proj-1", {
        networkTargets: ["https://portal.acme-target.example/login"],
        workspacePaths: [],
      }).allowed,
    ).toBe(true)
    expect(
      ws1.scopes.verifyTargets("bounty-proj-1", {
        networkTargets: ["https://billing.acme-target.example/checkout"],
        workspacePaths: [],
      }).allowed,
    ).toBe(false)

    ws1.close()
    workspaces.pop()

    // Reload a fresh CyberLabWorkspace on the same directory -> must restore .cyberlab/scope.json!
    const ws2 = new CyberLabWorkspace({
      projectId: "bounty-proj-1",
      workspaceRoot: wsDir,
      inMemoryDb: false,
    })
    workspaces.push(ws2)

    const reloadedScope = await ws2.getScope()
    expect(reloadedScope?.allowExternalTargets).toBe(true)
    expect(reloadedScope?.engagement?.researcherHandle).toBe("vitorsec")
    expect(
      ws2.scopes.verifyTargets("bounty-proj-1", {
        networkTargets: ["https://app.acme-target.example/dashboard"],
        workspacePaths: [],
      }).allowed,
    ).toBe(true)
  })

  test("2. Pre-configured Browser SPKI pin, http://cyberlab.proxy/cert, Live Intercept Queue, Match & Replace, Gzip decompression, Replay Vault, Site Map, Passive Scanner & OAST", async () => {
    const wsDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v4-proxy-"))
    tempDirs.push(wsDir)

    const observedUpstreamHeaders: Array<Record<string, string | string[] | undefined>> = []
    const observedUpstreamBodies: string[] = []

    const upstream = http.createServer(async (req, res) => {
      observedUpstreamHeaders.push(req.headers)
      const chunks: Buffer[] = []
      for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c as Uint8Array))
      observedUpstreamBodies.push(Buffer.concat(chunks).toString("utf8"))

      const payload = JSON.stringify({
        ok: true,
        path: req.url,
        leakedDemoKey: "sk_live_ABCDEF1234567890ABCDEF1234",
      })
      const gz = zlib.gzipSync(Buffer.from(payload, "utf8"))
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "Set-Cookie": "sid=supersecretcookie123; Path=/",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
      })
      res.end(gz)
    })
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", () => resolve()))
    servers.push(upstream)
    const upPort = (upstream.address() as { port: number }).port

    const ws = new CyberLabWorkspace({
      projectId: "proxy-v4-proj",
      workspaceRoot: wsDir,
      inMemoryDb: true,
    })
    workspaces.push(ws)

    await ws.updateScope({
      allowExternalTargets: false,
      allowedTargets: [{ kind: "ip", value: "127.0.0.1" }],
      engagement: {
        mode: "bug_bounty",
        platform: "hackerone",
        researcherHandle: "tester",
        maxRequestsPerSecond: 50,
        customHeaders: [{ name: "X-Bug-Bounty", value: "HackerOne-tester", enabled: true }],
      },
    })

    const started = await ws.controlProxy({ action: "start", port: 0 })
    const proxyPort = started.status.listenPort!
    expect(started.status.caSpkiSha256Base64.length).toBeGreaterThan(20)

    // 2a. Built-in http://cyberlab.proxy/cert portal returns PEM Root CA
    const certPemResp = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = http.request(
        {
          hostname: "127.0.0.1",
          port: proxyPort,
          method: "GET",
          path: "http://cyberlab.proxy/cert",
          headers: { Host: "cyberlab.proxy" },
        },
        (res) => {
          const bufs: Buffer[] = []
          res.on("data", (c: Buffer) => bufs.push(c))
          res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(bufs).toString("utf8") }))
        },
      )
      r.on("error", reject)
      r.end()
    })
    expect(certPemResp.status).toBe(200)
    expect(certPemResp.text).toContain("BEGIN CERTIFICATE")

    // 2b. Match & Replace Rule + Gzip auto-decompression + Replay Vault + Passive Alerts + Site Map
    await ws.controlProxy({
      action: "upsert_match_replace",
      matchReplaceRule: {
        enabled: true,
        location: "request_header",
        headerName: "X-Injected-Rule",
        matchPattern: "",
        replaceWith: "active",
        isRegex: false,
      },
    })

    const proxyExchange = await new Promise<{ status: number; body: Buffer }>((resolve, reject) => {
      const r = http.request(
        {
          hostname: "127.0.0.1",
          port: proxyPort,
          method: "POST",
          path: `http://127.0.0.1:${upPort}/api/account?tab=security`,
          headers: {
            Host: `127.0.0.1:${upPort}`,
            Cookie: "session=live-operator-cookie-xyz",
            "Content-Type": "application/json",
          },
        },
        (res) => {
          const bufs: Buffer[] = []
          res.on("data", (c: Buffer) => bufs.push(c))
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(bufs) }))
        },
      )
      r.on("error", reject)
      r.write(JSON.stringify({ role: "member" }))
      r.end()
    })
    expect(proxyExchange.status).toBe(200)
    expect(observedUpstreamHeaders[0]?.["x-bug-bounty"]).toBe("HackerOne-tester")
    expect(observedUpstreamHeaders[0]?.["x-injected-rule"]).toBe("active")

    const overview = await ws.getProxyOverview()
    expect(overview.history.length).toBe(1)
    const entry = overview.history[0]!
    // Redacted in ProxyHistoryEntry for safe display/EvidenceStore:
    expect(entry.requestHeaders.cookie).toBe("[REDACTED:SENSITIVE_HEADER]")
    // Decompressed response text captured for inspection:
    expect(entry.responseBody).toContain('"ok":true')

    // Live Replay Vault preserves real session Cookie + generates cURL & Raw HTTP for Repeater!
    const replay = await ws.exportProxyEntryForReplay(entry.entryId)
    expect(replay.headers.cookie).toBe("session=live-operator-cookie-xyz")
    expect(replay.curlCommand).toContain("session=live-operator-cookie-xyz")
    expect(replay.rawHttpRequest).toContain("POST /api/account?tab=security HTTP/1.1")

    // Site Map + Passive Alerts populated automatically:
    expect(overview.siteMap.hosts.length).toBe(1)
    expect(overview.siteMap.hosts[0]?.endpoints[0]?.paramNames).toContain("tab")
    expect(overview.siteMap.hosts[0]?.endpoints[0]?.paramNames).toContain("role")
    expect(overview.siteMap.passiveAlerts.length).toBeGreaterThanOrEqual(2)

    // 2c. Live Intercept Queue (Hold -> Edit body -> Forward)
    await ws.controlProxy({
      action: "configure_intercept",
      interceptEnabled: true,
      interceptInScopeOnly: true,
    })

    const heldRequestPromise = new Promise<{ status: number }>((resolve, reject) => {
      const r = http.request(
        {
          hostname: "127.0.0.1",
          port: proxyPort,
          method: "POST",
          path: `http://127.0.0.1:${upPort}/api/transfer`,
          headers: { Host: `127.0.0.1:${upPort}`, "Content-Type": "application/json" },
        },
        (res) => {
          res.resume()
          res.on("end", () => resolve({ status: res.statusCode ?? 0 }))
        },
      )
      r.on("error", reject)
      r.write('{"amount":10}')
      r.end()
    })

    // Wait briefly for proxy to hold request in Intercept Queue
    let queue = (await ws.getProxyOverview()).interceptQueue
    for (let i = 0; i < 20 && queue.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25))
      queue = (await ws.getProxyOverview()).interceptQueue
    }
    expect(queue.length).toBe(1)
    expect(queue[0]?.body).toBe('{"amount":10}')

    await ws.controlProxy({
      action: "resolve_intercept",
      interceptId: queue[0]!.interceptId,
      decision: "forward",
      body: '{"amount":999}',
    })

    const forwardedRes = await heldRequestPromise
    expect(forwardedRes.status).toBe(200)
    expect(observedUpstreamBodies[1]).toBe('{"amount":999}')

    // 2d. Built-in OAST Callback Listener
    const withOast = await ws.controlProxy({ action: "start_oast", oastPort: 0 })
    expect(withOast.status.oastRunning).toBe(true)
    const cbRes = await fetch(`${withOast.status.oastCallbackBaseUrl}/ssrf-probe?token=canary1`)
    expect(cbRes.status).toBe(200)
    const afterHit = await ws.getProxyOverview()
    expect(afterHit.oastHits.length).toBe(1)
    expect(afterHit.oastHits[0]?.path).toBe("/ssrf-probe")
  })

  test("3. Raw HTTP Repeater + Redirect Following + Local Artifact Upload & Authorized External Folder Audit", async () => {
    const wsDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v4-tools-"))
    const externalDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-v4-external-bounty-"))
    tempDirs.push(wsDir, externalDir)

    writeFileSync(
      path.join(externalDir, "leaked.env"),
      "OPENAI_API_KEY=sk-proj-RealProductionKeyTest1234567890abcd\n",
      "utf8",
    )

    const targetSrv = http.createServer((req, res) => {
      if (req.url === "/old-endpoint") {
        res.writeHead(302, { Location: "/new-endpoint" })
        res.end()
        return
      }
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(
        JSON.stringify({
          landedAt: req.url,
          customHdr: req.headers["x-raw-repeater"],
          bountyHdr: req.headers["x-bug-bounty"],
        }),
      )
    })
    await new Promise<void>((resolve) => targetSrv.listen(0, "127.0.0.1", () => resolve()))
    servers.push(targetSrv)
    const port = (targetSrv.address() as { port: number }).port

    const ws = new CyberLabWorkspace({
      projectId: "tools-v4-proj",
      workspaceRoot: wsDir,
      inMemoryDb: true,
    })
    workspaces.push(ws)

    await ws.updateScope({
      allowedTargets: [
        { kind: "ip", value: "127.0.0.1" },
        { kind: "workspace_path", value: externalDir, notes: "External Bounty Folder" },
      ],
      engagement: {
        mode: "bug_bounty",
        platform: "bugcrowd",
        maxRequestsPerSecond: 40,
        customHeaders: [{ name: "X-Bug-Bounty", value: "Bugcrowd-vitor", enabled: true }],
      },
    })

    // 3a. Raw HTTP/1.1 Repeater + followRedirects=true
    const repExec = await ws.submitExecution({
      capabilityId: "web-assessment.http-repeater",
      mode: "manual",
      input: {
        url: `http://127.0.0.1:${port}/old-endpoint`,
        followRedirects: true,
        rawRequest: `GET /old-endpoint HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nX-Raw-Repeater: yes\r\n\r\n`,
      },
    })
    expect(repExec.status).toBe("succeeded")
    const repJson = await ws.readEvidenceContent(repExec.resultEvidenceIds[1]!)
    const parsedRep = JSON.parse(repJson.text) as { primary: { finalUrl: string; bodyText: string } }
    expect(parsedRep.primary.finalUrl).toContain("/new-endpoint")
    expect(parsedRep.primary.bodyText).toContain('"Bugcrowd-vitor"')
    expect(parsedRep.primary.bodyText).toContain('"yes"')

    // 3b. 1-Click Local Artifact Upload (.cyberlab/imports/)
    const uploaded = await ws.importArtifactToWorkspace({
      fileName: "openapi-prod.json",
      contentBase64: Buffer.from(
        JSON.stringify({ openapi: "3.0.0", paths: { "/new-endpoint": { get: {} } } }),
      ).toString("base64"),
    })
    expect(uploaded.relativePath).toBe(".cyberlab/imports/openapi-prod.json")
    const listed = await ws.listImportedArtifacts()
    expect(listed.length).toBe(1)

    // 3c. Native Key Hunter scanning an EXTERNAL folder outside workspaceRoot authorized via workspace_path
    const khExec = await ws.submitExecution({
      capabilityId: "code-analysis.key-hunter",
      mode: "manual",
      input: {
        subpath: externalDir,
      },
    })
    expect(khExec.status).toBe("succeeded")
    const khEv = await ws.readEvidenceContent(khExec.resultEvidenceIds[0]!)
    expect(khEv.text).toContain("openai")

    // Global HTTP Logger captured traffic across tools
    const proxyOverview = await ws.getProxyOverview()
    expect(proxyOverview.httpLogger.some((l) => l.sourceTool === "http-repeater")).toBe(true)
  })
})
