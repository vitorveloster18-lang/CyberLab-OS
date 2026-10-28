import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import https from "node:https"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import tls from "node:tls"
import { CyberLabLocalCa, CyberLabWorkspace } from "../../../cyberlab/index.js"

/**
 * Builds a minimal valid 64-bit ELF binary containing executable code at offset 0x100.
 */
function buildMinimalElf64(eMachine: 62 | 183, codeBytes: Uint8Array): Buffer {
  const buf = Buffer.alloc(0x100 + codeBytes.byteLength, 0)
  buf[0] = 0x7f
  buf[1] = 0x45
  buf[2] = 0x4c
  buf[3] = 0x46
  buf[4] = 2 // 64-bit
  buf[5] = 1 // little-endian
  buf[6] = 1
  buf.writeUInt16LE(2, 16) // ET_EXEC
  buf.writeUInt16LE(eMachine, 18) // 62 = x86_64, 183 = ARM64
  buf.writeUInt32LE(1, 20)
  buf.writeBigUInt64LE(0x401000n, 24) // e_entry
  buf.writeBigUInt64LE(64n, 32) // e_phoff
  buf.writeUInt16LE(64, 52) // e_ehsize
  buf.writeUInt16LE(56, 54) // e_phentsize
  buf.writeUInt16LE(1, 56) // e_phnum

  // Single PT_LOAD program header @ 64 mapping file offset 0x100 -> vaddr 0x401000
  buf.writeUInt32LE(1, 64) // PT_LOAD
  buf.writeUInt32LE(5, 68) // PF_R | PF_X
  buf.writeBigUInt64LE(0x100n, 72) // p_offset
  buf.writeBigUInt64LE(0x401000n, 80) // p_vaddr
  buf.writeBigUInt64LE(0x401000n, 88) // p_paddr
  buf.writeBigUInt64LE(BigInt(codeBytes.byteLength), 96) // p_filesz
  buf.writeBigUInt64LE(BigInt(codeBytes.byteLength), 104) // p_memsz
  buf.writeBigUInt64LE(0x1000n, 112) // p_align

  Buffer.from(codeBytes).copy(buf, 0x100)
  return buf
}

/**
 * Builds a minimal valid Dalvik `dex\n035\0` file with 2 strings, 1 type, 1 method, and 1 class_def.
 */
function buildMinimalDalvikDex(): Buffer {
  const s0 = Buffer.from([0x04, ...Buffer.from("main", "utf8"), 0x00]) // uleb128 len=4 + "main\0"
  const s1 = Buffer.from([0x16, ...Buffer.from("Lcom/cyberlab/AppMain;", "utf8"), 0x00]) // len=22
  const headerSize = 0x70
  const stringIdsOff = 0x70 // 2 * 4 = 8 bytes -> 0x78
  const typeIdsOff = 0x78 // 1 * 4 = 4 bytes -> 0x7c
  const methodIdsOff = 0x7c // 1 * 8 = 8 bytes -> 0x84
  const classDefsOff = 0x84 // 1 * 32 = 32 bytes -> 0xa4
  const dataOff = 0xa4
  const s0Off = dataOff
  const s1Off = s0Off + s0.length
  const totalSize = s1Off + s1.length

  const dex = Buffer.alloc(totalSize, 0)
  Buffer.from("dex\n035\0", "ascii").copy(dex, 0)
  dex.writeUInt32LE(totalSize, 32)
  dex.writeUInt32LE(headerSize, 36)
  dex.writeUInt32LE(0x12345678, 40)
  dex.writeUInt32LE(2, 56) // string_ids_size
  dex.writeUInt32LE(stringIdsOff, 60)
  dex.writeUInt32LE(1, 64) // type_ids_size
  dex.writeUInt32LE(typeIdsOff, 68)
  dex.writeUInt32LE(1, 88) // method_ids_size
  dex.writeUInt32LE(methodIdsOff, 92)
  dex.writeUInt32LE(1, 96) // class_defs_size
  dex.writeUInt32LE(classDefsOff, 100)

  dex.writeUInt32LE(s0Off, stringIdsOff)
  dex.writeUInt32LE(s1Off, stringIdsOff + 4)
  dex.writeUInt32LE(1, typeIdsOff)
  dex.writeUInt16LE(0, methodIdsOff)
  dex.writeUInt16LE(0, methodIdsOff + 2)
  dex.writeUInt32LE(0, methodIdsOff + 4)
  dex.writeUInt32LE(0, classDefsOff)

  s0.copy(dex, s0Off)
  s1.copy(dex, s1Off)
  return dex
}

describe("CyberLab OS — 7 New Native Security Engines & Permissive Bridges", () => {
  test("1. Local Root CA + HTTPS CONNECT MITM Proxy decrypts in-scope HTTPS traffic & exposes CA fingerprint", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-https-proxy-"))
    const ws = new CyberLabWorkspace({
      projectId: "proj-https-proxy",
      workspaceRoot: tmpDir,
      inMemoryDb: true,
    })
    await ws.ensureInitialized()

    const upstreamCa = new CyberLabLocalCa({ caDirectory: path.join(tmpDir, "upstream-ca") })
    const upstreamLeaf = upstreamCa.issueHostCertificate("127.0.0.1")
    const httpsTarget = https.createServer(
      { key: upstreamLeaf.keyPem, cert: upstreamLeaf.certPem },
      (req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" })
        res.end(JSON.stringify({ ok: true, tlsPath: req.url, secretEcho: "clean" }))
      },
    )
    await new Promise<void>((resolve) => httpsTarget.listen(0, "127.0.0.1", () => resolve()))
    const targetPort = (httpsTarget.address() as net.AddressInfo).port

    try {
      await ws.updateScope({
        allowExternalTargets: false,
        allowedTargets: [{ kind: "ip", value: "127.0.0.1" }],
      })

      const started = await ws.controlProxy({
        action: "start",
        port: 0,
        scopeOnly: true,
        httpsMode: "tls_intercept",
        allowSelfSignedUpstream: true,
      })
      expect(started.status.running).toBe(true)
      expect(started.status.httpsMode).toBe("tls_intercept")
      expect(started.status.caFingerprintSha256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/)
      expect(started.status.caCertPem).toContain("BEGIN CERTIFICATE")

      const proxyPort = started.status.listenPort!

      const bodyText = await new Promise<string>((resolve, reject) => {
        const rawSock = net.connect(proxyPort, "127.0.0.1", () => {
          rawSock.write(
            `CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`,
          )
        })
        let headerBuf = ""
        const onData = (chunk: Buffer) => {
          headerBuf += chunk.toString("latin1")
          if (headerBuf.includes("\r\n\r\n")) {
            rawSock.off("data", onData)
            expect(headerBuf).toContain("200 Connection Established")
            const tlsSock = tls.connect(
              {
                socket: rawSock,
                ca: started.status.caCertPem,
                servername: "localhost",
              },
              () => {
                tlsSock.write(
                  `GET /https-secret-check HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nAuthorization: Bearer super_secret_https_tok\r\nConnection: close\r\n\r\n`,
                )
              },
            )
            const chunks: Buffer[] = []
            tlsSock.on("data", (c: Buffer | string) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)))
            tlsSock.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")))
            tlsSock.on("error", reject)
          }
        }
        rawSock.on("data", onData)
        rawSock.on("error", reject)
      })

      expect(bodyText).toContain('"tlsPath":"/https-secret-check"')

      await new Promise((r) => setTimeout(r, 60))
      const snap = await ws.getProxyOverview()
      const httpsEntry = snap.history.find((h) => h.protocol === "https" && h.path === "/https-secret-check")
      expect(httpsEntry).toBeDefined()
      expect(httpsEntry?.statusCode).toBe(200)
      expect(JSON.stringify(httpsEntry?.requestHeaders)).not.toContain("super_secret_https_tok")
    } finally {
      await ws.controlProxy({ action: "stop" })
      httpsTarget.close()
      ws.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("2 & 6. HTTP Intruder (§slot§ Sniper/Pitchfork) and Non-Destructive Differential Parameter Auditor", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-web-new-"))
    const ws = new CyberLabWorkspace({
      projectId: "proj-web-new",
      workspaceRoot: tmpDir,
      inMemoryDb: true,
    })
    await ws.ensureInitialized()

    const demoApp = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const u = new URL(req.url)
        if (u.pathname === "/api/admin") {
          return new Response(JSON.stringify({ role: "admin", flag: "FOUND_ADMIN_PANEL" }), { status: 200 })
        }
        if (u.pathname === "/search") {
          const q = u.searchParams.get("q") || ""
          const redirect = u.searchParams.get("redirect") || ""
          if (redirect.startsWith("//") || redirect.startsWith("https://")) {
            return new Response("", { status: 302, headers: { Location: redirect } })
          }
          return new Response(`<html><body>Busca por: "${q}"</body></html>`, {
            status: 200,
            headers: { "Content-Type": "text/html" },
          })
        }
        return new Response("Not Found", { status: 404 })
      },
    })

    try {
      await ws.updateScope({
        allowExternalTargets: false,
        allowedTargets: [{ kind: "url_origin", value: `http://127.0.0.1:${demoApp.port}` }],
      })

      // A) HTTP Intruder Sniper
      const intruderExec = await ws.submitExecution({
        capabilityId: "web-assessment.http-intruder",
        mode: "manual",
        input: {
          url: `http://127.0.0.1:${demoApp.port}/api/§route§`,
          method: "GET",
          attackMode: "sniper",
          payloadSet1: ["guest", "admin", "health"],
          grepMatch: "FOUND_ADMIN_PANEL",
        },
      })
      expect(intruderExec.status).toBe("succeeded")
      const intruderEvs = await ws.listEvidence(intruderExec.executionId)
      const intruderJsonEv = intruderEvs.find((e) => e.kind === "json") ?? intruderEvs[0]!
      const intruderJson = JSON.parse((await ws.readEvidenceContent(intruderJsonEv.evidenceId)).text)
      expect(intruderJson.anomaliesCount).toBe(1)
      const adminRow = intruderJson.rows.find((r: { payloads: string[] }) => r.payloads[0] === "admin")
      expect(adminRow.statusCode).toBe(200)
      expect(adminRow.grepMatched).toBe(true)

      // B) Differential Parameter Auditor
      const paramExec = await ws.submitExecution({
        capabilityId: "web-assessment.param-audit",
        mode: "manual",
        input: {
          url: `http://127.0.0.1:${demoApp.port}/search?q=hello&redirect=/dashboard`,
          method: "GET",
          checkReflectionContext: true,
          checkErrorLeakage: true,
          checkRedirectHygiene: true,
        },
      })
      expect(paramExec.status).toBe("succeeded")
      const paramEvs = await ws.listEvidence(paramExec.executionId)
      const paramEv = await ws.readEvidenceContent(paramEvs[0]!.evidenceId)
      const paramJson = JSON.parse(paramEv.text)
      expect(paramJson.auditedParameters).toHaveLength(2)
      expect(paramJson.observationsCount).toBeGreaterThanOrEqual(2)
    } finally {
      demoApp.stop(true)
      ws.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("3, 4, 5 & 7. Native x86_64/ARM64 Disassembler, Dalvik .dex Inspector, YARA Rule Engine & DNS Recon", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-rev-yara-dns-"))
    // x86_64 ELF: push rbp (55); mov rbp, rsp (48 89 e5); xor eax, eax (31 c0); pop rbp (5d); ret (c3)
    const x64Elf = buildMinimalElf64(62, Uint8Array.from([0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]))
    writeFileSync(path.join(tmpDir, "sample_x64.elf"), x64Elf)

    // ARM64 ELF: mov x0, #0 (0x00, 0x00, 0x80, 0xd2); ret (0xc0, 0x03, 0x5f, 0xd6)
    const arm64Elf = buildMinimalElf64(183, Uint8Array.from([0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6]))
    writeFileSync(path.join(tmpDir, "sample_arm64.elf"), arm64Elf)

    // Dalvik classes.dex
    const dexBytes = buildMinimalDalvikDex()
    writeFileSync(path.join(tmpDir, "classes.dex"), dexBytes)

    const ws = new CyberLabWorkspace({
      projectId: "proj-rev-yara-dns",
      workspaceRoot: tmpDir,
      inMemoryDb: true,
    })
    await ws.ensureInitialized()

    try {
      await ws.updateScope({
        allowExternalTargets: false,
        allowedTargets: [{ kind: "ip", value: "127.0.0.1" }],
      })

      // 3A) x86_64 Disassembly
      const disX64 = await ws.submitExecution({
        capabilityId: "reverse-engineering.binary-disasm",
        mode: "manual",
        input: { binaryPath: "sample_x64.elf", maxInstructions: 10 },
      })
      expect(disX64.status).toBe("succeeded")
      const x64Evs = await ws.listEvidence(disX64.executionId)
      const x64AllText = (await Promise.all(x64Evs.map((e) => ws.readEvidenceContent(e.evidenceId)))).map((r) => r.text).join("\n")
      expect(x64AllText).toContain("push     rbp")
      expect(x64AllText).toContain("mov      rbp, rsp")
      expect(x64AllText).toContain("ret")

      // 3B) ARM64 Disassembly
      const disArm = await ws.submitExecution({
        capabilityId: "reverse-engineering.binary-disasm",
        mode: "manual",
        input: { binaryPath: "sample_arm64.elf", maxInstructions: 8 },
      })
      expect(disArm.status).toBe("succeeded")
      const armEvs = await ws.listEvidence(disArm.executionId)
      const armAllText = (await Promise.all(armEvs.map((e) => ws.readEvidenceContent(e.evidenceId)))).map((r) => r.text).join("\n")
      expect(armAllText).toContain("ret")

      // 4) Dalvik .dex Class & Method Inspection
      const dexExec = await ws.submitExecution({
        capabilityId: "mobile-forensics.artifact-triage",
        mode: "manual",
        input: { artifactPath: "classes.dex" },
      })
      expect(dexExec.status).toBe("succeeded")
      const dexEvs = await ws.listEvidence(dexExec.executionId)
      const dexJsonEv = dexEvs.find((e) => e.kind === "json") ?? dexEvs[0]!
      const dexJson = JSON.parse((await ws.readEvidenceContent(dexJsonEv.evidenceId)).text)
      expect(dexJson.platformKind).toBe("android_dex")
      expect(dexJson.dalvikDexAnalysis.dexVersion).toBe("035")
      expect(dexJson.dalvikDexAnalysis.discoveredClasses).toContain("com.cyberlab.AppMain")
      expect(dexJson.dalvikDexAnalysis.discoveredMethods).toContain("com.cyberlab.AppMain#main()")

      // 5) Native YARA Rule Engine (hex wildcards + ASCII strings)
      const yaraExec = await ws.submitExecution({
        capabilityId: "forensics.yara-scan",
        mode: "manual",
        input: {
          targetPath: ".",
          rulesText: `
            rule Detect_ELF_And_Dex {
              meta:
                severity = "high"
              strings:
                $elf_x64_prologue = { 7F 45 4C 46 02 01 }
                $dalvik_class = "Lcom/cyberlab/AppMain;" ascii
              condition:
                $elf_x64_prologue or $dalvik_class
            }
          `,
        },
      })
      expect(yaraExec.status).toBe("succeeded")
      const yaraEvs = await ws.listEvidence(yaraExec.executionId)
      const yaraJsonEv = yaraEvs.find((e) => e.kind === "json") ?? yaraEvs[0]!
      const yaraJson = JSON.parse((await ws.readEvidenceContent(yaraJsonEv.evidenceId)).text)
      expect(yaraJson.matchesCount).toBe(3)

      // 7) Native DNS Recon on 127.0.0.1
      const dnsExec = await ws.submitExecution({
        capabilityId: "network-assessment.dns-recon",
        mode: "manual",
        input: {
          host: "127.0.0.1",
          checkEmailPosture: false,
          enumerateSubdomains: false,
          includeCrtSh: false,
        },
      })
      expect(dnsExec.status).toBe("succeeded")

      // External tool catalog includes all 8 governed bridges
      const extCatalog = await ws.listExternalTools()
      const extIds = extCatalog.map((t) => t.toolId)
      expect(extIds).toContain("dalfox")
      expect(extIds).toContain("ghidra-headless")
      expect(extIds).toContain("jadx")
      expect(extIds).toContain("yarax")
    } finally {
      ws.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
