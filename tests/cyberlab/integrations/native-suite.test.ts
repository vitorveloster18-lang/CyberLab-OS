import { describe, expect, test } from "bun:test"
import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import tls from "node:tls"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"
import { HttpRepeaterCapability } from "../../../integrations/web-security/http-repeater-comparer.js"
import { DecoderSequencerCapability } from "../../../integrations/web-security/decoder-sequencer.js"
import { WebSurfaceDiscoveryCapability } from "../../../integrations/web-security/surface-discovery.js"
import { TlsInspectorCapability } from "../../../integrations/network-observation/tls-certificate-inspector.js"
import { PcapAnalyzerCapability } from "../../../integrations/network-observation/pcap-packet-analyzer.js"
import { BinaryStaticTriageCapability } from "../../../integrations/reverse-forensics/binary-static-triage.js"
import { MobileArtifactTriageCapability } from "../../../integrations/reverse-forensics/mobile-artifact-triage.js"

function buildSyntheticPcapBuffer(): Uint8Array {
  // Global header (24 bytes, little-endian magic 0xd4c3b2a1, linkType 101 = Raw IP)
  const globalHdr = new Uint8Array(24)
  const gView = new DataView(globalHdr.buffer)
  gView.setUint32(0, 0xa1b2c3d4, true)
  gView.setUint16(4, 2, true)
  gView.setUint16(6, 4, true)
  gView.setUint32(16, 65535, true)
  gView.setUint32(20, 101, true) // LINKTYPE_RAW (Raw IPv4)

  // Packet 1: Raw IPv4 (20B) + UDP (8B) + DNS Query for "c2.lab.local"
  const dnsQuestion = Uint8Array.from([
    0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DNS header (QDCOUNT=1)
    0x02, 0x63, 0x32, // "c2"
    0x03, 0x6c, 0x61, 0x62, // "lab"
    0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, // "local"
    0x00, // root
    0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
  ])
  const udpLen = 8 + dnsQuestion.byteLength
  const ip1Len = 20 + udpLen
  const pkt1 = new Uint8Array(ip1Len)
  const p1v = new DataView(pkt1.buffer)
  pkt1[0] = 0x45
  p1v.setUint16(2, ip1Len, false)
  pkt1[8] = 64
  pkt1[9] = 17 // UDP
  pkt1.set([10, 0, 0, 5], 12)
  pkt1.set([10, 0, 0, 53], 16)
  p1v.setUint16(20, 51234, false)
  p1v.setUint16(22, 53, false)
  p1v.setUint16(24, udpLen, false)
  pkt1.set(dnsQuestion, 28)

  // Packet 2: Raw IPv4 (20B) + TCP (20B) + HTTP GET
  const httpPayload = new TextEncoder().encode("GET /internal/admin HTTP/1.1\r\nHost: lab.local\r\n\r\n")
  const ip2Len = 20 + 20 + httpPayload.byteLength
  const pkt2 = new Uint8Array(ip2Len)
  const p2v = new DataView(pkt2.buffer)
  pkt2[0] = 0x45
  p2v.setUint16(2, ip2Len, false)
  pkt2[8] = 64
  pkt2[9] = 6 // TCP
  pkt2.set([10, 0, 0, 5], 12)
  pkt2.set([10, 0, 0, 80], 16)
  p2v.setUint16(20, 49100, false)
  p2v.setUint16(22, 8080, false)
  pkt2[32] = 0x50 // data offset = 5 * 4 = 20 bytes
  pkt2.set(httpPayload, 40)

  const wrapRecord = (pkt: Uint8Array) => {
    const rec = new Uint8Array(16 + pkt.byteLength)
    const rv = new DataView(rec.buffer)
    rv.setUint32(0, 1700000000, true)
    rv.setUint32(8, pkt.byteLength, true)
    rv.setUint32(12, pkt.byteLength, true)
    rec.set(pkt, 16)
    return rec
  }

  const r1 = wrapRecord(pkt1)
  const r2 = wrapRecord(pkt2)
  const out = new Uint8Array(globalHdr.byteLength + r1.byteLength + r2.byteLength)
  out.set(globalHdr, 0)
  out.set(r1, globalHdr.byteLength)
  out.set(r2, globalHdr.byteLength + r1.byteLength)
  return out
}

function buildMinimalZipArchive(files: Array<{ name: string; content: string }>): Uint8Array {
  const localParts: Uint8Array[] = []
  const centralParts: Uint8Array[] = []
  let localOffset = 0

  for (const f of files) {
    const nameBytes = new TextEncoder().encode(f.name)
    const dataBytes = new TextEncoder().encode(f.content)

    const lfh = new Uint8Array(30 + nameBytes.byteLength + dataBytes.byteLength)
    const lv = new DataView(lfh.buffer)
    lv.setUint32(0, 0x04034b50, true)
    lv.setUint16(4, 20, true)
    lv.setUint32(18, dataBytes.byteLength, true)
    lv.setUint32(22, dataBytes.byteLength, true)
    lv.setUint16(26, nameBytes.byteLength, true)
    lfh.set(nameBytes, 30)
    lfh.set(dataBytes, 30 + nameBytes.byteLength)
    localParts.push(lfh)

    const cdh = new Uint8Array(46 + nameBytes.byteLength)
    const cv = new DataView(cdh.buffer)
    cv.setUint32(0, 0x02014b50, true)
    cv.setUint16(4, 20, true)
    cv.setUint16(6, 20, true)
    cv.setUint32(20, dataBytes.byteLength, true)
    cv.setUint32(24, dataBytes.byteLength, true)
    cv.setUint16(28, nameBytes.byteLength, true)
    cv.setUint32(42, localOffset, true)
    cdh.set(nameBytes, 46)
    centralParts.push(cdh)

    localOffset += lfh.byteLength
  }

  const cdSize = centralParts.reduce((acc, b) => acc + b.byteLength, 0)
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054b50, true)
  ev.setUint16(8, files.length, true)
  ev.setUint16(10, files.length, true)
  ev.setUint32(12, cdSize, true)
  ev.setUint32(16, localOffset, true)

  const total = localOffset + cdSize + eocd.byteLength
  const full = new Uint8Array(total)
  let pos = 0
  for (const p of [...localParts, ...centralParts, eocd]) {
    full.set(p, pos)
    pos += p.byteLength
  }
  return full
}

describe("Embedded Native Security Suite (All-In-One MIT Capabilities)", () => {
  test("registers all 20 built-in native capabilities plus 9 governed external plugin bridges out-of-the-box", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-suite-caps-"))
    try {
      const ws = new CyberLabWorkspace({ projectId: "proj-caps", workspaceRoot: tmpDir, inMemoryDb: true })
      const caps = await ws.listCapabilities()
      expect(caps.length).toBe(29)
      const ids = caps.map((c) => c.id)
      expect(ids).toContain(HttpRepeaterCapability.id)
      expect(ids).toContain(DecoderSequencerCapability.id)
      expect(ids).toContain(WebSurfaceDiscoveryCapability.id)
      expect(ids).toContain(TlsInspectorCapability.id)
      expect(ids).toContain(PcapAnalyzerCapability.id)
      expect(ids).toContain(BinaryStaticTriageCapability.id)
      expect(ids).toContain(MobileArtifactTriageCapability.id)
      expect(ids).toContain("external.nmap-service-probe")
      expect(ids).toContain("external.nuclei-template-scan")
      expect(ids).toContain("external.ffuf-endpoint-probe")
      expect(ids).toContain("external.tshark-pcap-summary")
      ws.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("executes HTTP Repeater & Comparer, redacts auth headers, and enforces scope on baselineUrl", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-repeater-"))
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const u = new URL(req.url)
        if (u.pathname === "/v1/admin") {
          return new Response("admin_flag=enabled\nrole=superuser\n", {
            status: 200,
            headers: { "Set-Cookie": "admin_token=secret123" },
          })
        }
        return new Response("role=guest\n", { status: 403 })
      },
    })

    try {
      const ws = new CyberLabWorkspace({ projectId: "proj-repeater", workspaceRoot: tmpDir, inMemoryDb: true })

      // Must block SSRF smuggled via baselineUrl!
      const smuggled = await ws.submitExecution({
        capabilityId: HttpRepeaterCapability.id,
        input: {
          url: `http://127.0.0.1:${server.port}/v1/admin`,
          baselineUrl: "http://169.254.169.254/latest/meta-data/",
        },
        mode: "manual",
      })
      expect(smuggled.status).toBe("blocked")

      const ok = await ws.submitExecution({
        capabilityId: HttpRepeaterCapability.id,
        input: {
          url: `http://127.0.0.1:${server.port}/v1/admin`,
          headers: { Authorization: "Bearer super_sensitive_jwt" },
          baselineUrl: `http://127.0.0.1:${server.port}/v1/guest`,
        },
        mode: "manual",
      })
      expect(ok.status).toBe("succeeded")

      const ev = await ws.listEvidence(ok.executionId)
      const raw = ev.find((e) => e.kind === "http_exchange")
      expect(raw?.content.inlineText).toContain("[REDACTED:SENSITIVE_HEADER]")
      expect(raw?.content.inlineText).not.toContain("super_sensitive_jwt")
      expect(raw?.content.inlineText).not.toContain("secret123")

      const jsonEv = ev.find((e) => e.kind === "json")
      const parsed = JSON.parse(jsonEv?.content.inlineText ?? "{}")
      expect(parsed.comparison.statusChanged).toBe(true)
      expect(parsed.comparison.primaryStatus).toBe(200)
      expect(parsed.comparison.baselineStatus).toBe(403)
      ws.close()
    } finally {
      server.stop(true)
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("executes Decoder, JWT Inspector (alg:none detection), and Token Entropy Sequencer", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-decoder-"))
    try {
      const ws = new CyberLabWorkspace({ projectId: "proj-decoder", workspaceRoot: tmpDir, inMemoryDb: true })

      const headerB64 = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")
      const payloadB64 = Buffer.from(JSON.stringify({ sub: "admin", role: "root" })).toString("base64url")
      const forgedJwt = `${headerB64}.${payloadB64}.`
      const outerEncoded = encodeURIComponent(Buffer.from(forgedJwt, "utf8").toString("base64"))

      const execRes = await ws.submitExecution({
        capabilityId: DecoderSequencerCapability.id,
        input: {
          value: outerEncoded,
          transforms: ["url_decode", "base64_decode"],
          tokenSamples: ["100001", "100002", "100003", "100004"],
        },
        mode: "manual",
      })
      expect(execRes.status).toBe("succeeded")

      const ev = await ws.listEvidence(execRes.executionId)
      const parsed = JSON.parse(ev[0]?.content.inlineText ?? "{}")
      expect(parsed.jwtInspection.warnings.some((w: string) => w.includes("alg='none'"))).toBe(true)
      expect(parsed.sequencerReport.sequentialNumericDetected).toBe(true)
      expect(parsed.sequencerReport.entropyRating).toBe("weak_predictable")
      ws.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("executes Web Surface Discovery and filters out HTML soft-404 false positives", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-surface-"))
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const p = new URL(req.url).pathname
        if (p === "/.git/HEAD") return new Response("ref: refs/heads/main\n", { status: 200 })
        if (p === "/.env") {
          // Soft-404 SPA fallback returning HTML 200 OK — must NOT be flagged as .env secret exposure!
          return new Response("<html><body>SPA Not Found</body></html>", {
            status: 200,
            headers: { "content-type": "text/html" },
          })
        }
        return new Response("Not Found", { status: 404 })
      },
    })

    try {
      const ws = new CyberLabWorkspace({ projectId: "proj-surface", workspaceRoot: tmpDir, inMemoryDb: true })
      const res = await ws.submitExecution({
        capabilityId: WebSurfaceDiscoveryCapability.id,
        input: { baseUrl: `http://127.0.0.1:${server.port}` },
        mode: "manual",
      })
      expect(res.status).toBe("succeeded")

      const ev = await ws.listEvidence(res.executionId)
      const parsed = JSON.parse(ev[0]?.content.inlineText ?? "{}")
      expect(parsed.confirmedExposureCount).toBe(1)
      expect(parsed.hits[0].templateId).toBe("TPL-GIT-HEAD")
      ws.close()
    } finally {
      server.stop(true)
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("executes TLS Handshake & X.509 Inspector against ephemeral local TLS server", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-tls-"))
    const keyPath = path.join(tmpDir, "key.pem")
    const certPath = path.join(tmpDir, "cert.pem")
    execFileSync("openssl", [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "2",
      "-nodes",
      "-subj",
      "/CN=localhost",
    ])

    const tlsServer = tls.createServer(
      { key: readFileSync(keyPath), cert: readFileSync(certPath) },
      (socket) => socket.end("hello tls"),
    )
    await new Promise<void>((resolve) => tlsServer.listen(0, "127.0.0.1", resolve))
    const addr = tlsServer.address()
    const port = typeof addr === "object" && addr ? addr.port : 0

    try {
      const ws = new CyberLabWorkspace({ projectId: "proj-tls", workspaceRoot: tmpDir, inMemoryDb: true })
      const res = await ws.submitExecution({
        capabilityId: TlsInspectorCapability.id,
        input: { host: "127.0.0.1", port, servername: "localhost" },
        mode: "manual",
      })
      expect(res.status).toBe("succeeded")

      const ev = await ws.listEvidence(res.executionId)
      const parsed = JSON.parse(ev[0]?.content.inlineText ?? "{}")
      expect(parsed.protocol).toMatch(/^TLSv1\.[23]$/)
      expect(parsed.subject.CN).toBe("localhost")
      expect(parsed.fingerprint256).toBeTruthy()
      // Self-signed + expiring in 2 days triggers explicit warnings
      expect(parsed.warnings.length).toBeGreaterThanOrEqual(2)
      ws.close()
    } finally {
      await new Promise<void>((resolve) => tlsServer.close(() => resolve()))
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("parses .pcap packet captures, ELF64 binaries, and Android .apk archives offline", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-forensics-"))
    try {
      // 1. Write synthetic .pcap
      writeFileSync(path.join(tmpDir, "capture.pcap"), buildSyntheticPcapBuffer())

      // 2. Write synthetic ELF64 binary with embedded C2 string & VirtualAlloc indicator
      const elfBuf = new Uint8Array(256)
      elfBuf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0) // ELF64, little-endian
      const elfView = new DataView(elfBuf.buffer)
      elfView.setUint16(16, 3, true) // ET_DYN (PIE)
      elfView.setUint16(18, 62, true) // x86_64
      elfView.setBigUint64(24, 0x401000n, true)
      const indicatorBytes = new TextEncoder().encode("http://10.99.88.77/beacon\0VirtualAlloc\0/bin/sh\0")
      elfBuf.set(indicatorBytes, 96)
      writeFileSync(path.join(tmpDir, "sample.elf"), elfBuf)

      // 3. Write synthetic Android APK archive
      const apkBytes = buildMinimalZipArchive([
        {
          name: "AndroidManifest.xml",
          content:
            "manifest android.permission.READ_SMS android.permission.BIND_ACCESSIBILITY_SERVICE http://c2.evil-mobile.test/collect",
        },
        { name: "classes.dex", content: "dex\n035\0https://api.legit.example/v1" },
        { name: "lib/arm64-v8a/libhook.so", content: "\x7fELF..." },
      ])
      writeFileSync(path.join(tmpDir, "suspect.apk"), apkBytes)

      const ws = new CyberLabWorkspace({ projectId: "proj-forensics", workspaceRoot: tmpDir, inMemoryDb: true })

      // Execute PCAP analyzer
      const pcapExec = await ws.submitExecution({
        capabilityId: PcapAnalyzerCapability.id,
        input: { pcapPath: "capture.pcap" },
        mode: "manual",
      })
      expect(pcapExec.status).toBe("succeeded")
      const pcapJson = JSON.parse((await ws.listEvidence(pcapExec.executionId))[0]?.content.inlineText ?? "{}")
      expect(pcapJson.packetCount).toBe(2)
      expect(pcapJson.dnsQueries).toContain("c2.lab.local")
      expect(pcapJson.cleartextHttpRequests[0]).toContain("GET /internal/admin")

      // Execute Binary Static Triage
      const binExec = await ws.submitExecution({
        capabilityId: BinaryStaticTriageCapability.id,
        input: { binaryPath: "sample.elf" },
        mode: "manual",
      })
      expect(binExec.status).toBe("succeeded")
      const binJson = JSON.parse((await ws.listEvidence(binExec.executionId))[0]?.content.inlineText ?? "{}")
      expect(binJson.binaryInfo.format).toBe("ELF64")
      expect(binJson.binaryInfo.architecture).toContain("x86_64")
      expect(binJson.indicators.urls[0]).toContain("http://10.99.88.77/beacon")
      expect(binJson.indicators.suspiciousApis).toContain("VirtualAlloc")

      // Execute Mobile APK Forensics Triage
      const apkExec = await ws.submitExecution({
        capabilityId: MobileArtifactTriageCapability.id,
        input: { artifactPath: "suspect.apk", iocDomains: ["evil-mobile.test"] },
        mode: "manual",
      })
      expect(apkExec.status).toBe("succeeded")
      const apkJson = JSON.parse((await ws.listEvidence(apkExec.executionId))[0]?.content.inlineText ?? "{}")
      expect(apkJson.platformKind).toBe("android_apk")
      expect(apkJson.dexFiles).toEqual(["classes.dex"])
      expect(apkJson.nativeLibraries).toEqual(["lib/arm64-v8a/libhook.so"])
      expect(apkJson.detectedHighRiskPermissions).toContain("android.permission.READ_SMS")
      expect(apkJson.cleartextHttpUrls).toContain("http://c2.evil-mobile.test/collect")
      expect(apkJson.iocHits).toEqual(["evil-mobile.test"])

      ws.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
