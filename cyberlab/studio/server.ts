#!/usr/bin/env bun

import { execFileSync } from "node:child_process"
import { mkdirSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import tls from "node:tls"
import { fileURLToPath } from "node:url"
import { CyberLabWorkspaceManager } from "../index.js"

const uiHtmlPath = fileURLToPath(new URL("./ui.html", import.meta.url))
const repoRoot = path.resolve(process.env.CYBERLAB_WORKSPACE_ROOT?.trim() || process.cwd())
const studioPort = Number(process.env.CYBERLAB_STUDIO_PORT || "4180")
const studioHost = process.env.CYBERLAB_STUDIO_HOST || "0.0.0.0"
const enableDemoLab = process.argv.includes("--demo-lab")

function createDemoPcap(): Uint8Array {
  const globalHdr = new Uint8Array(24)
  const gView = new DataView(globalHdr.buffer)
  gView.setUint32(0, 0xa1b2c3d4, true)
  gView.setUint16(4, 2, true)
  gView.setUint16(6, 4, true)
  gView.setUint32(16, 65535, true)
  gView.setUint32(20, 101, true)

  const dnsQuestion = Uint8Array.from([
    0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x63, 0x32, 0x03, 0x6c, 0x61, 0x62, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
    0x00, 0x01, 0x00, 0x01,
  ])
  const udpLen = 8 + dnsQuestion.byteLength
  const pkt1 = new Uint8Array(20 + udpLen)
  const p1v = new DataView(pkt1.buffer)
  pkt1[0] = 0x45
  p1v.setUint16(2, pkt1.byteLength, false)
  pkt1[8] = 64
  pkt1[9] = 17
  pkt1.set([10, 0, 0, 5], 12)
  pkt1.set([10, 0, 0, 53], 16)
  p1v.setUint16(20, 54001, false)
  p1v.setUint16(22, 53, false)
  p1v.setUint16(24, udpLen, false)
  pkt1.set(dnsQuestion, 28)

  const httpPayload = new TextEncoder().encode("GET /api/admin/config HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
  const pkt2 = new Uint8Array(40 + httpPayload.byteLength)
  const p2v = new DataView(pkt2.buffer)
  pkt2[0] = 0x45
  p2v.setUint16(2, pkt2.byteLength, false)
  pkt2[8] = 64
  pkt2[9] = 6
  pkt2.set([10, 0, 0, 5], 12)
  pkt2.set([10, 0, 0, 80], 16)
  p2v.setUint16(20, 49200, false)
  p2v.setUint16(22, 8080, false)
  pkt2[32] = 0x50
  pkt2.set(httpPayload, 40)

  const wrap = (pkt: Uint8Array) => {
    const rec = new Uint8Array(16 + pkt.byteLength)
    const rv = new DataView(rec.buffer)
    rv.setUint32(0, 1700000000, true)
    rv.setUint32(8, pkt.byteLength, true)
    rv.setUint32(12, pkt.byteLength, true)
    rec.set(pkt, 16)
    return rec
  }
  const r1 = wrap(pkt1)
  const r2 = wrap(pkt2)
  const full = new Uint8Array(24 + r1.byteLength + r2.byteLength)
  full.set(globalHdr, 0)
  full.set(r1, 24)
  full.set(r2, 24 + r1.byteLength)
  return full
}

function createDemoZip(files: Array<{ name: string; content: string }>): Uint8Array {
  const localParts: Uint8Array[] = []
  const centralParts: Uint8Array[] = []
  let offset = 0
  for (const f of files) {
    const nb = new TextEncoder().encode(f.name)
    const db = new TextEncoder().encode(f.content)
    const lfh = new Uint8Array(30 + nb.byteLength + db.byteLength)
    const lv = new DataView(lfh.buffer)
    lv.setUint32(0, 0x04034b50, true)
    lv.setUint16(4, 20, true)
    lv.setUint32(18, db.byteLength, true)
    lv.setUint32(22, db.byteLength, true)
    lv.setUint16(26, nb.byteLength, true)
    lfh.set(nb, 30)
    lfh.set(db, 30 + nb.byteLength)
    localParts.push(lfh)

    const cdh = new Uint8Array(46 + nb.byteLength)
    const cv = new DataView(cdh.buffer)
    cv.setUint32(0, 0x02014b50, true)
    cv.setUint16(4, 20, true)
    cv.setUint16(6, 20, true)
    cv.setUint32(20, db.byteLength, true)
    cv.setUint32(24, db.byteLength, true)
    cv.setUint16(28, nb.byteLength, true)
    cv.setUint32(42, offset, true)
    cdh.set(nb, 46)
    centralParts.push(cdh)
    offset += lfh.byteLength
  }
  const cdSize = centralParts.reduce((a, b) => a + b.byteLength, 0)
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054b50, true)
  ev.setUint16(8, files.length, true)
  ev.setUint16(10, files.length, true)
  ev.setUint32(12, cdSize, true)
  ev.setUint32(16, offset, true)

  const out = new Uint8Array(offset + cdSize + 22)
  let pos = 0
  for (const part of [...localParts, ...centralParts, eocd]) {
    out.set(part, pos)
    pos += part.byteLength
  }
  return out
}

interface DemoLabState {
  httpUrl: string
  tlsPort: number
}

async function setupDemoLab(workspaceRoot: string): Promise<DemoLabState> {
  const labDir = path.join(workspaceRoot, ".cyberlab", "demo-lab")
  mkdirSync(labDir, { recursive: true })

  // 1. Sample PCAP, ELF64, and Android APK for instant visual testing
  writeFileSync(path.join(labDir, "sample-traffic.pcap"), createDemoPcap())

  const elf = new Uint8Array(256)
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0)
  const ev = new DataView(elf.buffer)
  ev.setUint16(16, 3, true)
  ev.setUint16(18, 62, true)
  ev.setBigUint64(24, 0x401080n, true)
  elf.set(new TextEncoder().encode("http://10.88.77.66/stage2\0VirtualAlloc\0CreateRemoteThread\0/bin/sh\0"), 96)
  writeFileSync(path.join(labDir, "sample-agent.elf"), elf)

  const apk = createDemoZip([
    {
      name: "AndroidManifest.xml",
      content:
        "manifest android.permission.READ_SMS android.permission.RECORD_AUDIO android.permission.BIND_ACCESSIBILITY_SERVICE http://beacon.evil-mobile.test/collect",
    },
    { name: "classes.dex", content: "dex\n035\0https://api.legit.local/v1" },
    { name: "lib/arm64-v8a/libloader.so", content: "\x7fELF..." },
  ])
  writeFileSync(path.join(labDir, "sample-app.apk"), apk)

  // 2. Local 127.0.0.1 demo HTTP target app
  const demoHttp = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(req) {
      const p = new URL(req.url).pathname
      if (p === "/api/admin") {
        return new Response(JSON.stringify({ privileged: true, role: "admin", debugMode: true }, null, 2), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": "lab_sid=secret_cookie_12345; Path=/",
          },
        })
      }
      if (p === "/api/guest") {
        return new Response(JSON.stringify({ privileged: false, role: "guest" }, null, 2), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        })
      }
      if (p === "/.git/HEAD") {
        return new Response("ref: refs/heads/main\n", { status: 200 })
      }
      if (p === "/openapi.json") {
        return new Response(JSON.stringify({ openapi: "3.1.0", info: { title: "Demo Lab API", version: "1.0" } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      }
      return new Response("<html><body>Demo Lab Target</body></html>", {
        status: 200,
        headers: { "Content-Type": "text/html" },
      })
    },
  })

  // 3. Local 127.0.0.1 demo TLS server with ephemeral self-signed EC cert
  const keyFile = path.join(labDir, "demo-tls-key.pem")
  const certFile = path.join(labDir, "demo-tls-cert.pem")
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:prime256v1",
    "-keyout",
    keyFile,
    "-out",
    certFile,
    "-days",
    "5",
    "-nodes",
    "-subj",
    "/CN=localhost",
  ])
  const tlsSrv = tls.createServer(
    { key: readFileSync(keyFile), cert: readFileSync(certFile) },
    (sock) => sock.end("TLS Lab Ready\r\n"),
  )
  await new Promise<void>((resolve) => tlsSrv.listen(0, "127.0.0.1", resolve))
  const addr = tlsSrv.address()
  const tlsPort = typeof addr === "object" && addr ? addr.port : 8443

  return {
    httpUrl: `http://127.0.0.1:${demoHttp.port}`,
    tlsPort,
  }
}

export async function startCyberLabStudioServer() {
  const projectId = `proj-${path.basename(repoRoot).replace(/[^a-zA-Z0-9._-]/g, "-") || "workspace"}`
  const ws = await CyberLabWorkspaceManager.global.forProject(projectId, repoRoot)

  let demoLab: DemoLabState | null = null
  if (enableDemoLab) {
    demoLab = await setupDemoLab(repoRoot)
    await ws.controlProxy({ action: "start", port: 0, scopeOnly: true })
  }

  const jsonResp = (data: unknown, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    })

  const server = Bun.serve({
    hostname: studioHost,
    port: studioPort,
    async fetch(req) {
      const url = new URL(req.url)
      try {
        if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/cyberlab")) {
          return new Response(readFileSync(uiHtmlPath, "utf8"), {
            headers: {
              "Content-Type": "text/html; charset=utf-8",
              "Cache-Control": "no-store",
            },
          })
        }

        if (req.method === "GET" && url.pathname === "/api/studio/state") {
          const [status, capabilities, approvals, executions, evidence, findings, tools, proxy] = await Promise.all([
            ws.getStatus(),
            ws.listCapabilities(),
            ws.listPendingApprovals(),
            ws.listExecutions(),
            ws.listEvidence(),
            ws.listFindings(),
            ws.listExternalTools(),
            ws.getProxyOverview(),
          ])
          return jsonResp({
            status,
            capabilities,
            approvals,
            executions,
            evidence: evidence.map((e) => ({
              evidenceId: e.evidenceId,
              kind: e.kind,
              title: e.title,
              sha256: e.integrity.sha256,
              redactionStatus: e.redactionStatus,
            })),
            findings,
            external: {
              pendingInboxCount: ws.externalControl.countPendingInboxFiles(),
              tools,
            },
            proxy,
            demoLab,
          })
        }

        if (req.method === "POST" && url.pathname === "/api/studio/execute") {
          const body = (await req.json()) as { capabilityId: string; input: unknown }
          const record = await ws.submitExecution({
            capabilityId: body.capabilityId,
            input: body.input,
            mode: "manual",
          })
          const evidenceDocs = await Promise.all(
            record.resultEvidenceIds.map((id) => ws.readEvidenceContent(id, "studio-ui")),
          )
          return jsonResp({ record, evidenceDocs })
        }

        if (req.method === "POST" && url.pathname === "/api/studio/proxy") {
          const body = (await req.json()) as {
            action: "start" | "stop" | "clear" | "set_scope_only"
            port?: number
            scopeOnly?: boolean
          }
          return jsonResp(await ws.controlProxy(body))
        }

        if (req.method === "POST" && url.pathname === "/api/studio/proxy/persist") {
          const body = (await req.json()) as { entryId: string }
          return jsonResp(await ws.persistProxyEntry(body.entryId, "studio-ui"))
        }

        if (req.method === "POST" && url.pathname === "/api/studio/demo-traffic" && demoLab) {
          let proxyOverview = await ws.getProxyOverview()
          if (!proxyOverview.status.running) {
            proxyOverview = await ws.controlProxy({ action: "start", port: 0, scopeOnly: true })
          }
          const pxPort = proxyOverview.status.listenPort
          if (pxPort) {
            await fetch(`http://127.0.0.1:${pxPort}/`, {
              headers: {
                "X-CyberLab-Target-Url": `${demoLab.httpUrl}/api/admin`,
                Authorization: "Bearer super_secret_cookie_or_jwt",
              },
            })
            await fetch(`http://127.0.0.1:${pxPort}/`, {
              headers: {
                "X-CyberLab-Target-Url": `${demoLab.httpUrl}/api/guest`,
              },
            })
          }
          return jsonResp({
            message: "Captured 2 live HTTP exchanges through CyberLab Proxy -> click '→ Repeater' or '→ Baseline'!",
          })
        }

        if (req.method === "PUT" && url.pathname === "/api/studio/scope") {
          const body = (await req.json()) as Parameters<typeof ws.updateScope>[0]
          return jsonResp(await ws.updateScope(body))
        }

        if (req.method === "POST" && url.pathname === "/api/studio/inbox-sync") {
          return jsonResp(await ws.syncExternalInbox("studio-ui"))
        }

        if (req.method === "POST" && url.pathname === "/api/studio/ingest") {
          const body = (await req.json()) as { toolId: string; target?: string; rawOutput: string }
          return jsonResp(await ws.ingestExternalAction({ ...body, origin: "manual_external", actor: "studio-ui" }))
        }

        if (req.method === "POST" && url.pathname === "/api/studio/evidence/read") {
          const body = (await req.json()) as { evidenceId: string }
          return jsonResp(await ws.readEvidenceContent(body.evidenceId, "studio-ui"))
        }

        if (req.method === "POST" && url.pathname === "/api/studio/evidence/verify") {
          const body = (await req.json()) as { evidenceId: string }
          return jsonResp(await ws.verifyEvidence(body.evidenceId, "studio-ui"))
        }

        if (req.method === "POST" && url.pathname === "/api/studio/approve") {
          const body = (await req.json()) as { approvalId: string }
          return jsonResp(await ws.approveExecution({ approvalId: body.approvalId, decidedBy: "studio-ui" }))
        }

        if (req.method === "GET" && url.pathname === "/api/studio/report") {
          return jsonResp({ markdown: await ws.generateMarkdownReport() })
        }

        return jsonResp({ error: "Not found" }, 404)
      } catch (err) {
        return jsonResp({ error: err instanceof Error ? err.message : String(err) }, 400)
      }
    },
  })

  console.log(
    `[CyberLab Security Studio] Listening on http://${server.hostname}:${server.port} (project=${projectId}, demoLab=${Boolean(demoLab)})`,
  )
  return server
}

if (import.meta.main) {
  await startCyberLabStudioServer()
}
