import { describe, expect, test } from "bun:test"
import crypto from "node:crypto"
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import http from "node:http"
import https from "node:https"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { gzipSync } from "node:zlib"
import { CyberLabLocalCa, CyberLabWorkspace } from "../../../cyberlab/index.js"

function buildMockSmb2NegotiateResponse(securityMode: number, dialect = 0x0311): Buffer {
  const smbHeader = Buffer.alloc(64, 0)
  smbHeader[0] = 0xfe
  smbHeader[1] = 0x53
  smbHeader[2] = 0x4d
  smbHeader[3] = 0x42
  smbHeader.writeUInt16LE(64, 4)
  smbHeader.writeUInt16LE(0x0001, 16) // Flags = ServerToRedir

  const negRespBody = Buffer.alloc(66, 0)
  negRespBody.writeUInt16LE(65, 0) // StructureSize = 65
  negRespBody.writeUInt16LE(securityMode, 2) // 0x01 = SigningEnabled (NOT required!)
  negRespBody.writeUInt16LE(dialect, 4) // 0x0311 = SMB 3.1.1

  const payload = Buffer.concat([smbHeader, negRespBody])
  const netbios = Buffer.alloc(4, 0)
  netbios.writeUInt32BE(payload.length & 0x00ffffff, 0)
  return Buffer.concat([netbios, payload])
}

function buildMockLdapSearchEntryResponse(): Buffer {
  const oct = (s: string) => {
    const b = Buffer.from(s, "utf8")
    return Buffer.concat([Buffer.from([0x04, b.length]), b])
  }
  // Minimal BER sequence containing OCTET STRING attributes returned in RootDSE SearchResultEntry (0x64)
  const content = Buffer.concat([
    oct("defaultNamingContext"),
    oct("DC=cyberlab,DC=local"),
    oct("dnsHostName"),
    oct("dc01.cyberlab.local"),
  ])
  const entry = Buffer.concat([Buffer.from([0x64, content.length]), content])
  return Buffer.concat([Buffer.from([0x30, entry.length]), entry])
}

function buildMockNtlmType2Base64(): string {
  const targetName = Buffer.from("CYBERLAB", "utf16le")
  const avPairs: Buffer[] = []
  const pushAv = (id: number, str?: string) => {
    const val = str ? Buffer.from(str, "utf16le") : Buffer.alloc(0)
    const hdr = Buffer.alloc(4)
    hdr.writeUInt16LE(id, 0)
    hdr.writeUInt16LE(val.length, 2)
    avPairs.push(hdr, val)
  }
  pushAv(2, "CYBERLAB") // MsvAvNbDomainName
  pushAv(1, "DC01") // MsvAvNbComputerName
  pushAv(4, "cyberlab.local") // MsvAvDnsDomainName
  pushAv(3, "dc01.cyberlab.local") // MsvAvDnsComputerName
  pushAv(0) // MsvAvEOL

  const targetInfo = Buffer.concat(avPairs)
  const headerLen = 56
  const tNameOff = headerLen
  const tiOff = tNameOff + targetName.length
  const msg = Buffer.alloc(tiOff + targetInfo.length, 0)

  Buffer.from("NTLMSSP\0", "ascii").copy(msg, 0)
  msg.writeUInt32LE(2, 8) // Type 2 Challenge
  msg.writeUInt16LE(targetName.length, 12)
  msg.writeUInt16LE(targetName.length, 14)
  msg.writeUInt32LE(tNameOff, 16)
  msg.writeUInt32LE(0x00000001 | 0x00800000 | 0x02000000, 20) // Unicode | TargetInfo | Version
  crypto.randomBytes(8).copy(msg, 24) // ServerChallenge
  msg.writeUInt16LE(targetInfo.length, 40)
  msg.writeUInt16LE(targetInfo.length, 42)
  msg.writeUInt32LE(tiOff, 44)
  // OS Version: 10.0 Build 20348 (Windows Server 2022)
  msg[48] = 10
  msg[49] = 0
  msg.writeUInt16LE(20348, 50)
  msg[55] = 15

  targetName.copy(msg, tNameOff)
  targetInfo.copy(msg, tiOff)
  return msg.toString("base64")
}

describe("CyberLab OS v3.0 — Final 6 Security Engineering & Blue/Red Lab Suites", () => {
  test("1. API, GraphQL & OAuth2 Security Lab detects OpenAPI BOLA/IDOR, GraphQL introspection/batching, and OIDC/PKCE flaws", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-api-lab-"))
    let server: http.Server | undefined
    try {
      server = http.createServer(async (req, res) => {
        const u = new URL(req.url ?? "/", "http://127.0.0.1")
        if (u.pathname === "/api/accounts/1") {
          const auth = req.headers.authorization ?? ""
          if (!auth) {
            res.writeHead(401, { "content-type": "application/json" })
            res.end(JSON.stringify({ error: "unauthorized" }))
            return
          }
          // Vulnerable BOLA: User B gets User A's private record with HTTP 200!
          res.writeHead(200, { "content-type": "application/json" })
          res.end(JSON.stringify({ accountId: 1, owner: "alice", balance: 94500, ssnLast4: "9921" }))
          return
        }
        if (u.pathname === "/graphql" && req.method === "POST") {
          const chunks: Buffer[] = []
          for await (const c of req) chunks.push(Buffer.from(c))
          const bodyText = Buffer.concat(chunks).toString("utf8")
          const parsed = JSON.parse(bodyText) as unknown
          if (Array.isArray(parsed)) {
            res.writeHead(200, { "content-type": "application/json" })
            res.end(JSON.stringify(parsed.map(() => ({ data: { __typename: "Query" } }))))
            return
          }
          if (bodyText.includes("__schema")) {
            res.writeHead(200, { "content-type": "application/json" })
            res.end(
              JSON.stringify({
                data: {
                  __schema: {
                    queryType: { name: "Query" },
                    mutationType: { name: "Mutation" },
                    types: [{ name: "Query" }, { name: "UserSecret" }, { name: "Mutation" }],
                  },
                },
              }),
            )
            return
          }
          res.writeHead(400, { "content-type": "application/json" })
          res.end(JSON.stringify({ errors: [{ message: 'Cannot query field. Did you mean "userSecret"?' }] }))
          return
        }
        if (u.pathname === "/.well-known/openid-configuration") {
          res.writeHead(200, { "content-type": "application/json" })
          res.end(
            JSON.stringify({
              issuer: `http://127.0.0.1:${(server!.address() as net.AddressInfo).port}`,
              authorization_endpoint: `http://127.0.0.1:${(server!.address() as net.AddressInfo).port}/oauth/authorize`,
              token_endpoint: `http://127.0.0.1:${(server!.address() as net.AddressInfo).port}/oauth/token`,
              response_types_supported: ["code", "token", "id_token token"],
              grant_types_supported: ["authorization_code", "implicit", "password"],
              code_challenge_methods_supported: ["plain"],
            }),
          )
          return
        }
        res.writeHead(404).end()
      })

      await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", () => resolve()))
      const port = (server.address() as net.AddressInfo).port
      const baseUrl = `http://127.0.0.1:${port}`

      const openApiSpec = {
        openapi: "3.0.3",
        info: { title: "Banking Lab API", version: "1.0.0" },
        paths: {
          "/api/accounts/{id}": {
            get: { summary: "Get private account details" },
          },
        },
      }

      const ws = await new CyberLabWorkspace({
        projectId: "proj-api-lab",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      }).ensureInitialized()

      const exec = await ws.submitExecution({
        capabilityId: "web-assessment.api-graphql-oauth-lab",
        mode: "manual",
        input: {
          baseUrl,
          specJsonText: JSON.stringify(openApiSpec),
          authHeaderA: "Bearer user-a-owner-token",
          authHeaderB: "Bearer user-b-attacker-token",
          testUnauthenticated: true,
          graphqlUrl: `${baseUrl}/graphql`,
          checkGraphqlIntrospection: true,
          checkGraphqlBatchingAndDepth: true,
          issuerUrl: baseUrl,
          authorizeUrl: `${baseUrl}/oauth/authorize?response_type=token&client_id=web&redirect_uri=http://evil.lab/cb`,
        },
      })

      expect(exec.status).toBe("succeeded")
      const evList = await ws.listEvidence(exec.executionId)
      expect(evList.length).toBe(1)
      const content = await ws.readEvidenceContent(evList[0]!.evidenceId)
      const report = JSON.parse(content.text) as {
        bolaEndpointsTested: number
        bolaMatrix: Array<{ bolaSuspected: boolean }>
        graphqlAudit: { introspectionEnabled: boolean; batchingAccepted: boolean }
        findingsCount: number
      }

      expect(report.bolaEndpointsTested).toBe(1)
      expect(report.bolaMatrix[0]?.bolaSuspected).toBe(true)
      expect(report.graphqlAudit.introspectionEnabled).toBe(true)
      expect(report.graphqlAudit.batchingAccepted).toBe(true)
      expect(report.findingsCount).toBeGreaterThanOrEqual(4)

      ws.close()
    } finally {
      server?.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("2. SCA, CycloneDX 1.5 SBOM, Container/IaC Auditor & Aqua Trivy Bridge detect lockfile/manifest deps and IaC misconfigs", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-sca-iac-"))
    try {
      writeFileSync(
        path.join(tmpDir, "package.json"),
        JSON.stringify(
          {
            name: "demo-service",
            dependencies: { lodash: "4.17.15", express: "^4.18.2", jsonwebtoken: "8.5.1" },
          },
          null,
          2,
        ),
      )
      writeFileSync(path.join(tmpDir, "requirements.txt"), "flask==2.0.1\npyyaml==5.3.1\nrequests>=2.31.0\n")
      writeFileSync(
        path.join(tmpDir, "Dockerfile"),
        "FROM ubuntu:latest\nUSER root\nENV AWS_SECRET_KEY=supersecret\nRUN curl -fsSL https://get.example.sh | bash\n",
      )
      writeFileSync(
        path.join(tmpDir, "deployment.yaml"),
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - name: app\n          image: nginx:latest\n          securityContext:\n            privileged: true\n",
      )
      writeFileSync(
        path.join(tmpDir, "main.tf"),
        'resource "aws_security_group" "ssh" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\nresource "aws_db_instance" "db" {\n  storage_encrypted = false\n}\n',
      )

      // Also create a mock Trivy binary in .cyberlab/bin/trivy to test external.trivy-scan bridge
      const binDir = path.join(tmpDir, ".cyberlab", "bin")
      mkdirSync(binDir, { recursive: true })
      const fakeTrivy = path.join(binDir, "trivy")
      writeFileSync(
        fakeTrivy,
        '#!/usr/bin/env bash\necho \'{"SchemaVersion":2,"Results":[{"Target":"Dockerfile","MisconfSummary":{"Successes":0,"Failures":3}}]}\'\n',
      )
      chmodSync(fakeTrivy, 0o755)

      const ws = await new CyberLabWorkspace({
        projectId: "proj-sca-iac",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      }).ensureInitialized()

      const scaExec = await ws.submitExecution({
        capabilityId: "code-analysis.sca-sbom-iac-audit",
        mode: "manual",
        input: {
          subpath: ".",
          generateCycloneDxSbom: true,
          queryOsvDev: false,
          auditContainersAndIac: true,
        },
      })
      expect(scaExec.status).toBe("succeeded")
      const scaEvs = await ws.listEvidence(scaExec.executionId)
      expect(scaEvs.length).toBeGreaterThanOrEqual(1)
      const mainEv = scaEvs.find((e) => e.title.startsWith("SCA, SBOM & IaC Audit")) ?? scaEvs[0]!
      const mainJson = JSON.parse((await ws.readEvidenceContent(mainEv.evidenceId)).text) as {
        dependencyCount: number
        iacMisconfigurationsCount: number
        cycloneDxSbom: { bomFormat: string; specVersion: string; components: unknown[] }
      }
      expect(mainJson.dependencyCount).toBeGreaterThanOrEqual(5)
      expect(mainJson.iacMisconfigurationsCount).toBeGreaterThanOrEqual(5)
      expect(mainJson.cycloneDxSbom.bomFormat).toBe("CycloneDX")
      expect(mainJson.cycloneDxSbom.specVersion).toBe("1.5")
      expect(mainJson.cycloneDxSbom.components.length).toBeGreaterThanOrEqual(5)

      // Verify governed Aqua Trivy external bridge
      const trivyExec = await ws.submitExecution({
        capabilityId: "external.trivy-scan",
        mode: "manual",
        input: { targetPath: ".", scanners: "vuln,misconfig" },
      })
      expect(trivyExec.status).toBe("succeeded")
      const trivyEvs = await ws.listEvidence(trivyExec.executionId)
      const trivyOut = (await ws.readEvidenceContent(trivyEvs[0]!.evidenceId)).text
      expect(trivyOut).toContain("SchemaVersion")

      ws.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("3 & 5. TLS Deep Cipher/HSTS Auditor (v1.1.0) & Enterprise Lab AD/SMB/LDAP/NTLM Inspector", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-tls-ad-"))
    let httpsSrv: https.Server | undefined
    let smbSrv: net.Server | undefined
    let ldapSrv: net.Server | undefined
    let ntlmHttpSrv: http.Server | undefined

    try {
      const ca = new CyberLabLocalCa({ caDirectory: path.join(tmpDir, ".cyberlab", "ca") })
      const leaf = ca.issueHostCertificate("127.0.0.1")

      httpsSrv = https.createServer({ key: leaf.keyPem, cert: leaf.certPem }, (_req, res) => {
        res.writeHead(200, {
          "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
          "content-type": "text/plain",
        })
        res.end("ok")
      })
      await new Promise<void>((r) => httpsSrv!.listen(0, "127.0.0.1", () => r()))
      const tlsPort = (httpsSrv.address() as net.AddressInfo).port

      smbSrv = net.createServer((sock) => {
        sock.once("data", () => {
          sock.write(buildMockSmb2NegotiateResponse(0x01, 0x0311))
          sock.end()
        })
      })
      await new Promise<void>((r) => smbSrv!.listen(0, "127.0.0.1", () => r()))
      const smbPort = (smbSrv.address() as net.AddressInfo).port

      ldapSrv = net.createServer((sock) => {
        sock.once("data", () => {
          sock.write(buildMockLdapSearchEntryResponse())
          sock.end()
        })
      })
      await new Promise<void>((r) => ldapSrv!.listen(0, "127.0.0.1", () => r()))
      const ldapPort = (ldapSrv.address() as net.AddressInfo).port

      const ntlmB64 = buildMockNtlmType2Base64()
      ntlmHttpSrv = http.createServer((req, res) => {
        if ((req.headers.authorization ?? "").startsWith("NTLM ")) {
          res.writeHead(401, { "WWW-Authenticate": `NTLM ${ntlmB64}` })
          res.end()
          return
        }
        res.writeHead(401, { "WWW-Authenticate": "NTLM" })
        res.end()
      })
      await new Promise<void>((r) => ntlmHttpSrv!.listen(0, "127.0.0.1", () => r()))
      const ntlmPort = (ntlmHttpSrv.address() as net.AddressInfo).port

      const ws = await new CyberLabWorkspace({
        projectId: "proj-tls-ad",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      }).ensureInitialized()

      // Test TLS v1.1.0 Deep Cipher Audit + HSTS
      const tlsExec = await ws.submitExecution({
        capabilityId: "network-assessment.tls-inspector",
        mode: "manual",
        input: {
          host: "127.0.0.1",
          port: tlsPort,
          deepCipherAudit: true,
          checkHsts: true,
          timeoutMs: 4000,
        },
      })
      if (tlsExec.status !== "succeeded") {
        throw new Error(`tlsExec failed: ${JSON.stringify(tlsExec.error)}`)
      }
      expect(tlsExec.status).toBe("succeeded")
      const tlsEv = await ws.listEvidence(tlsExec.executionId)
      const tlsJson = JSON.parse((await ws.readEvidenceContent(tlsEv[0]!.evidenceId)).text) as {
        deepAudit: {
          securityGrade: string
          forwardSecrecy: boolean
          protocolSupportMatrix: Array<{ version: string; supported: boolean }>
          hsts: { present: boolean; preload: boolean }
        }
      }
      expect(tlsJson.deepAudit).toBeDefined()
      expect(tlsJson.deepAudit.forwardSecrecy).toBe(true)
      expect(tlsJson.deepAudit.protocolSupportMatrix.length).toBe(4)
      expect(tlsJson.deepAudit.hsts.present).toBe(true)
      expect(tlsJson.deepAudit.hsts.preload).toBe(true)

      // Test Passive AD / SMB / LDAP / NTLM Lab Inspector
      const adExec = await ws.submitExecution({
        capabilityId: "network-assessment.ad-smb-ldap-inspector",
        mode: "manual",
        input: {
          host: "127.0.0.1",
          checkSmbSigning: true,
          smbPort,
          checkLdapRootDse: true,
          ldapPort,
          ntlmHttpUrl: `http://127.0.0.1:${ntlmPort}/ews`,
          timeoutMs: 4000,
        },
      })
      expect(adExec.status).toBe("succeeded")
      const adEv = await ws.listEvidence(adExec.executionId)
      const adJson = JSON.parse((await ws.readEvidenceContent(adEv[0]!.evidenceId)).text) as {
        smbSigningAudit: { validSmb2: boolean; signingEnabled: boolean; signingRequired: boolean }
        ldapRootDseAudit: { anonymousRootDseExposed: boolean; namingContexts: string[] }
        ntlmMetadataAudit: { validNtlmChallenge: boolean; dnsDomainName: string; osVersion: string }
        findingsCount: number
      }
      expect(adJson.smbSigningAudit.validSmb2).toBe(true)
      expect(adJson.smbSigningAudit.signingEnabled).toBe(true)
      expect(adJson.smbSigningAudit.signingRequired).toBe(false)
      expect(adJson.ldapRootDseAudit.anonymousRootDseExposed).toBe(true)
      expect(adJson.ntlmMetadataAudit.validNtlmChallenge).toBe(true)
      expect(adJson.ntlmMetadataAudit.dnsDomainName).toBe("cyberlab.local")
      expect(adJson.ntlmMetadataAudit.osVersion).toContain("20348")
      expect(adJson.findingsCount).toBeGreaterThanOrEqual(2)

      ws.close()
    } finally {
      httpsSrv?.close()
      smbSrv?.close()
      ldapSrv?.close()
      ntlmHttpSrv?.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("4 & 6. DFIR Log Analyzer with Sigma YAML Rules + Binary Entropy Visualizer & CyberChef Recipe Studio", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-dfir-entropy-"))
    try {
      mkdirSync(path.join(tmpDir, "logs"), { recursive: true })
      writeFileSync(
        path.join(tmpDir, "logs", "incident.log"),
        [
          "Oct 28 14:01:02 srv01 sshd[2110]: Failed password for invalid user admin from 10.10.10.55 port 51234 ssh2",
          "Oct 28 14:02:10 srv01 sudo: www-data : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash -c chmod +s /bin/bash",
          '10.10.10.55 - - [28/Oct/2026:14:03:00 +0000] "GET /uploads/cmd.php?cmd=whoami HTTP/1.1" 200 512 "-" "curl/8.0"',
          JSON.stringify({
            timestamp: "2026-10-28T14:04:00Z",
            EventID: 4688,
            CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
          }),
        ].join("\n"),
      )

      // Build a composite firmware image: low-entropy ASCII header + PNG magic + high-entropy encrypted payload
      const header = Buffer.from("CYBERLAB-FIRMWARE-V1\n".repeat(40), "ascii")
      const pngMagic = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
      const encryptedBlob = crypto.randomBytes(8192)
      writeFileSync(path.join(tmpDir, "firmware.bin"), Buffer.concat([header, pngMagic, encryptedBlob]))

      // Prepare an AES-128-GCM + Gzipped secret message to decode via CyberChef recipe!
      const key = Buffer.from("00112233445566778899aabbccddeeff", "hex")
      const iv = Buffer.from("aabbccddeeff001122334455", "hex")
      const compressedPlain = gzipSync(Buffer.from("FLAG{CYBERLAB_RECIPE_STUDIO_DECODED_OK}", "utf8"))
      const cipher = crypto.createCipheriv("aes-128-gcm", key, iv)
      const enc = Buffer.concat([cipher.update(compressedPlain), cipher.final()])
      const tag = cipher.getAuthTag()
      const b64Payload = enc.toString("base64")

      const ws = await new CyberLabWorkspace({
        projectId: "proj-dfir-entropy",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      }).ensureInitialized()

      // 4. DFIR Sigma Triage
      const dfirExec = await ws.submitExecution({
        capabilityId: "forensics.dfir-sigma-triage",
        mode: "manual",
        input: {
          logPath: "logs/incident.log",
          includeBuiltinRules: true,
          sigmaRulesYaml: [
            "title: Custom SUID Bash Escalation",
            "id: sigma-custom-suid-01",
            "level: critical",
            "detection:",
            "  selection:",
            "    message|contains: 'chmod +s /bin/bash'",
            "  condition: selection",
          ].join("\n"),
        },
      })
      expect(dfirExec.status).toBe("succeeded")
      const dfirEv = await ws.listEvidence(dfirExec.executionId)
      const dfirReport = JSON.parse((await ws.readEvidenceContent(dfirEv[0]!.evidenceId)).text) as {
        totalEventsParsed: number
        alertsCount: number
        incidentTimeline: Array<{ ruleTitle: string }>
      }
      expect(dfirReport.totalEventsParsed).toBe(4)
      expect(dfirReport.alertsCount).toBeGreaterThanOrEqual(4)
      expect(dfirReport.incidentTimeline.some((a) => a.ruleTitle.includes("Custom SUID Bash"))).toBe(true)

      // 6. Entropy Visualizer + CyberChef Recipe Studio (Base64 -> AES-GCM -> Gunzip)
      const entropyExec = await ws.submitExecution({
        capabilityId: "reverse-engineering.entropy-recipe-studio",
        mode: "manual",
        input: {
          filePath: "firmware.bin",
          bucketCount: 16,
          inputText: b64Payload,
          recipeSteps: [
            { op: "from_base64" },
            {
              op: "aes_gcm_decrypt",
              keyHexOrUtf8: key.toString("hex"),
              ivHex: `${iv.toString("hex")}:${tag.toString("hex")}`,
            },
            { op: "gunzip" },
          ],
        },
      })
      expect(entropyExec.status).toBe("succeeded")
      const entEv = await ws.listEvidence(entropyExec.executionId)
      const entReport = JSON.parse((await ws.readEvidenceContent(entEv[0]!.evidenceId)).text) as {
        entropyProfile: {
          buckets: Array<{ entropy: number; classification: string }>
          embeddedSignatures: Array<{ signature: string }>
        }
        recipeResult: { finalText: string }
      }
      expect(entReport.entropyProfile.buckets.length).toBe(16)
      expect(entReport.entropyProfile.embeddedSignatures.some((s) => s.signature.includes("PNG"))).toBe(true)
      expect(entReport.entropyProfile.buckets.some((b) => b.entropy > 7.0)).toBe(true)
      expect(entReport.recipeResult.finalText).toContain("FLAG{CYBERLAB_RECIPE_STUDIO_DECODED_OK}")

      ws.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
