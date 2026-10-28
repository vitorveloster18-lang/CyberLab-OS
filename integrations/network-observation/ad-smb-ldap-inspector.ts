import net from "node:net"
import { Schema } from "effect"
import {
  normalizeRawOutputDraft,
  redactSensitiveContent,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const AD_SMB_LDAP_INPUT_SCHEMA_ID = "cyberlab.ad-smb-ldap.input.v1"
export const AD_SMB_LDAP_OUTPUT_SCHEMA_ID = "cyberlab.ad-smb-ldap.output.v1"

export const AdSmbLdapInputSchema = Schema.Struct({
  host: Schema.String.check(
    Schema.isMinLength(1),
    Schema.isMaxLength(253),
    Schema.isPattern(/^[a-zA-Z0-9._:-]+$/),
  ),
  checkSmbSigning: Schema.optionalKey(Schema.Boolean),
  smbPort: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(65_535))),
  checkLdapRootDse: Schema.optionalKey(Schema.Boolean),
  ldapPort: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(65_535))),
  ntlmHttpUrl: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2048))),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(300), Schema.isLessThanOrEqualTo(10_000)),
  ),
})

export type AdSmbLdapInput = typeof AdSmbLdapInputSchema.Type

export const AdSmbLdapCapability: CapabilityDefinition = {
  id: "network-assessment.ad-smb-ldap-inspector",
  version: "1.0.0",
  title: "Enterprise Lab Protocol Inspector (SMB2/3 Signing, LDAP RootDSE & NTLM Metadata)",
  description:
    "Performs passive, credential-free protocol posture checks against authorized lab infrastructure: SMB2/3 Negotiate Signing enforcement, LDAPv3 anonymous RootDSE disclosure, and HTTP NTLM Type-2 Challenge target metadata decoding.",
  inputSchemaId: AD_SMB_LDAP_INPUT_SCHEMA_ID,
  outputSchemaId: AD_SMB_LDAP_OUTPUT_SCHEMA_ID,
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-active"],
  requiredScope: ["ip"],
  executorId: "ad-smb-ldap-inspector-executor",
  skillIds: ["network-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

/**
 * Builds a minimal RFC-compliant NetBIOS Session + SMB2 NEGOTIATE packet (MS-SMB2 2.2.3)
 * proposing dialects 0x0202 (2.0.2), 0x0210 (2.1), 0x0300 (3.0), 0x0302 (3.0.2).
 */
export function buildSmb2NegotiatePacket(): Buffer {
  const smbHeader = Buffer.alloc(64, 0)
  // ProtocolId: 0xFE 'S' 'M' 'B'
  smbHeader[0] = 0xfe
  smbHeader[1] = 0x53
  smbHeader[2] = 0x4d
  smbHeader[3] = 0x42
  smbHeader.writeUInt16LE(64, 4) // StructureSize = 64
  smbHeader.writeUInt16LE(0x0000, 12) // Command = SMB2 NEGOTIATE (0x0000)
  smbHeader.writeUInt16LE(1, 14) // CreditRequest = 1

  // SMB2 NEGOTIATE Request body (36 bytes fixed + 4 * 2 dialect bytes = 44 bytes)
  const negBody = Buffer.alloc(44, 0)
  negBody.writeUInt16LE(36, 0) // StructureSize = 36
  negBody.writeUInt16LE(4, 2) // DialectCount = 4
  negBody.writeUInt16LE(1, 4) // SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED (0x01)
  // Dialects at offset 36
  negBody.writeUInt16LE(0x0202, 36)
  negBody.writeUInt16LE(0x0210, 38)
  negBody.writeUInt16LE(0x0300, 40)
  negBody.writeUInt16LE(0x0302, 42)

  const payload = Buffer.concat([smbHeader, negBody])
  const netbios = Buffer.alloc(4)
  netbios.writeUInt32BE(payload.length & 0x00ffffff, 0)
  return Buffer.concat([netbios, payload])
}

export function parseSmb2NegotiateResponse(raw: Buffer): {
  validSmb2: boolean
  dialectHex: string | null
  dialectLabel: string | null
  signingEnabled: boolean
  signingRequired: boolean
} {
  const idx = raw.indexOf(Buffer.from([0xfe, 0x53, 0x4d, 0x42]))
  if (idx === -1 || idx + 72 > raw.length) {
    return { validSmb2: false, dialectHex: null, dialectLabel: null, signingEnabled: false, signingRequired: false }
  }
  const bodyOff = idx + 64
  const structSize = raw.readUInt16LE(bodyOff)
  if (structSize !== 65 || bodyOff + 6 > raw.length) {
    return { validSmb2: false, dialectHex: null, dialectLabel: null, signingEnabled: false, signingRequired: false }
  }
  const secMode = raw.readUInt16LE(bodyOff + 2)
  const dialect = raw.readUInt16LE(bodyOff + 4)
  const dialectMap: Record<number, string> = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x02ff: "SMB 2.x Wildcard",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
  }
  return {
    validSmb2: true,
    dialectHex: `0x${dialect.toString(16).padStart(4, "0")}`,
    dialectLabel: dialectMap[dialect] ?? `Unknown (0x${dialect.toString(16)})`,
    signingEnabled: (secMode & 0x01) !== 0,
    signingRequired: (secMode & 0x02) !== 0,
  }
}

/**
 * Builds a minimal RFC 4511 LDAPv3 unauthenticated RootDSE SearchRequest
 * (baseObject="", scope=baseObject(0), deref=0, filter=(objectClass=*)).
 */
export function buildLdapRootDseSearchPacket(): Buffer {
  const encodeBer = (tag: number, content: Buffer): Buffer => {
    if (content.length < 0x80) {
      return Buffer.concat([Buffer.from([tag, content.length]), content])
    }
    const lenHex = content.length.toString(16)
    const lenBytes = Buffer.from(lenHex.length % 2 ? `0${lenHex}` : lenHex, "hex")
    return Buffer.concat([Buffer.from([tag, 0x80 | lenBytes.length]), lenBytes, content])
  }
  const octStr = (s: string) => encodeBer(0x04, Buffer.from(s, "utf8"))
  const enumVal = (n: number) => encodeBer(0x0a, Buffer.from([n]))
  const intVal = (n: number) => encodeBer(0x02, Buffer.from([n]))
  const boolVal = (b: boolean) => encodeBer(0x01, Buffer.from([b ? 0xff : 0x00]))

  const attrs = encodeBer(
    0x30,
    Buffer.concat([
      octStr("defaultNamingContext"),
      octStr("namingContexts"),
      octStr("dnsHostName"),
      octStr("supportedLDAPVersion"),
      octStr("supportedSASLMechanisms"),
    ]),
  )
  // Present filter [7] IMPLICIT AttributeDescription "objectClass"
  const presentFilter = encodeBer(0x87, Buffer.from("objectClass", "utf8"))
  const searchReq = encodeBer(
    0x63, // SearchRequest [APPLICATION 3]
    Buffer.concat([
      octStr(""), // baseObject = "" (RootDSE)
      enumVal(0), // scope = baseObject
      enumVal(0), // derefAliases = neverDerefAliases
      intVal(5), // sizeLimit = 5
      intVal(5), // timeLimit = 5
      boolVal(false), // typesOnly = false
      presentFilter,
      attrs,
    ]),
  )
  return encodeBer(0x30, Buffer.concat([intVal(1), searchReq]))
}

export function extractPrintableLdapStrings(raw: Buffer): string[] {
  const out: string[] = []
  let i = 0
  while (i + 2 <= raw.length) {
    if (raw[i] === 0x04) {
      const len = raw[i + 1]!
      if (len > 0 && len < 0x80 && i + 2 + len <= raw.length) {
        const str = raw.subarray(i + 2, i + 2 + len).toString("utf8")
        if (/^[\x20-\x7e]+$/.test(str)) {
          out.push(str)
        }
        i += 2 + len
        continue
      }
    }
    i++
  }
  return [...new Set(out)]
}

/**
 * Decodes an NTLMSSP Type-2 Challenge message (MS-NLMP 2.2.1.2) from Base64,
 * extracting NetBIOS/DNS domain & computer names and Windows OS build version.
 */
export function decodeNtlmType2Challenge(b64: string): {
  validNtlmChallenge: boolean
  targetName: string | null
  osVersion: string | null
  nbDomainName: string | null
  nbComputerName: string | null
  dnsDomainName: string | null
  dnsComputerName: string | null
  dnsTreeName: string | null
} {
  const empty = {
    validNtlmChallenge: false,
    targetName: null,
    osVersion: null,
    nbDomainName: null,
    nbComputerName: null,
    dnsDomainName: null,
    dnsComputerName: null,
    dnsTreeName: null,
  }
  let buf: Buffer
  try {
    buf = Buffer.from(b64.trim(), "base64")
  } catch {
    return empty
  }
  if (buf.length < 32 || buf.subarray(0, 8).toString("ascii") !== "NTLMSSP\0") {
    return empty
  }
  const msgType = buf.readUInt32LE(8)
  if (msgType !== 2) return empty

  const tNameLen = buf.readUInt16LE(12)
  const tNameOff = buf.readUInt32LE(16)
  const flags = buf.readUInt32LE(20)
  const unicode = (flags & 0x00000001) !== 0
  const targetName =
    tNameLen > 0 && tNameOff + tNameLen <= buf.length
      ? buf.subarray(tNameOff, tNameOff + tNameLen).toString(unicode ? "utf16le" : "ascii")
      : null

  let osVersion: string | null = null
  if (buf.length >= 56 && (flags & 0x02000000) !== 0) {
    const major = buf[48]!
    const minor = buf[49]!
    const build = buf.readUInt16LE(50)
    osVersion = `${major}.${minor} (Build ${build})`
  }

  let nbDomainName: string | null = null
  let nbComputerName: string | null = null
  let dnsDomainName: string | null = null
  let dnsComputerName: string | null = null
  let dnsTreeName: string | null = null

  if (buf.length >= 48) {
    const tiLen = buf.readUInt16LE(40)
    const tiOff = buf.readUInt32LE(44)
    if (tiLen > 0 && tiOff + tiLen <= buf.length) {
      let pos = tiOff
      const end = tiOff + tiLen
      while (pos + 4 <= end) {
        const avId = buf.readUInt16LE(pos)
        const avLen = buf.readUInt16LE(pos + 2)
        pos += 4
        if (avId === 0 || pos + avLen > end) break
        const val = buf.subarray(pos, pos + avLen).toString("utf16le")
        if (avId === 1) nbComputerName = val
        else if (avId === 2) nbDomainName = val
        else if (avId === 3) dnsComputerName = val
        else if (avId === 4) dnsDomainName = val
        else if (avId === 5) dnsTreeName = val
        pos += avLen
      }
    }
  }

  return {
    validNtlmChallenge: true,
    targetName,
    osVersion,
    nbDomainName,
    nbComputerName,
    dnsDomainName,
    dnsComputerName,
    dnsTreeName,
  }
}

async function sendSingleTcpExchange(
  host: string,
  port: number,
  requestBytes: Buffer,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<{ reachable: boolean; response: Buffer; error?: string }> {
  return new Promise((resolve) => {
    let settled = false
    const chunks: Buffer[] = []
    const sock = net.connect({ host, port })
    const finish = (reachable: boolean, error?: string) => {
      if (settled) return
      settled = true
      signal.removeEventListener("abort", onAbort)
      sock.destroy()
      resolve({ reachable, response: Buffer.concat(chunks), ...(error ? { error } : {}) })
    }
    const onAbort = () => finish(false, "aborted")
    signal.addEventListener("abort", onAbort, { once: true })
    sock.setTimeout(timeoutMs)

    sock.once("connect", () => {
      sock.write(requestBytes)
    })
    sock.on("data", (c: Buffer | string) => {
      chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c))
      if (Buffer.concat(chunks).length >= 64) {
        setTimeout(() => finish(true), 40)
      }
    })
    sock.once("end", () => finish(chunks.length > 0))
    sock.once("timeout", () => finish(chunks.length > 0, chunks.length === 0 ? "timeout" : undefined))
    sock.once("error", (err) => finish(false, err.message))
  })
}

export class AdSmbLdapInspectorExecutor implements CyberLabExecutor {
  readonly id = "ad-smb-ldap-inspector-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      Schema.decodeUnknownSync(AdSmbLdapInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(AdSmbLdapInputSchema)(req.input)
    const timeoutMs = parsed.timeoutMs ?? 3_500
    const postureFindings: Array<{ protocol: string; severityHint: string; summary: string }> = []

    // 1. SMB2/3 Signing Check
    let smbResult: Record<string, unknown> | null = null
    if (parsed.checkSmbSigning ?? true) {
      const smbPort = parsed.smbPort ?? 445
      const ex = await sendSingleTcpExchange(parsed.host, smbPort, buildSmb2NegotiatePacket(), timeoutMs, ctx.signal)
      if (ex.reachable && ex.response.length > 0) {
        const neg = parseSmb2NegotiateResponse(ex.response)
        smbResult = { port: smbPort, reachable: true, ...neg }
        if (neg.validSmb2 && !neg.signingRequired) {
          postureFindings.push({
            protocol: "SMB2/3",
            severityHint: "high",
            summary: `SMB Signing NÃO é obrigatório em ${parsed.host}:${smbPort} (${neg.dialectLabel}) — risco de ataques de NTLM Relay em rede interna.`,
          })
        }
      } else {
        smbResult = { port: smbPort, reachable: false, error: ex.error ?? "no_response" }
      }
    }

    // 2. LDAPv3 Anonymous RootDSE Check
    let ldapResult: Record<string, unknown> | null = null
    if (parsed.checkLdapRootDse ?? true) {
      const ldapPort = parsed.ldapPort ?? 389
      const ex = await sendSingleTcpExchange(parsed.host, ldapPort, buildLdapRootDseSearchPacket(), timeoutMs, ctx.signal)
      if (ex.reachable && ex.response.length > 0) {
        const strings = extractPrintableLdapStrings(ex.response)
        const namingContexts = strings.filter((s) => /^DC=/i.test(s))
        const anonymousExposed = namingContexts.length > 0 || strings.some((s) => /GSSAPI|NTLM|PLAIN/i.test(s))
        ldapResult = {
          port: ldapPort,
          reachable: true,
          anonymousRootDseExposed: anonymousExposed,
          namingContexts,
          extractedAttributes: strings.slice(0, 30),
        }
        if (anonymousExposed) {
          postureFindings.push({
            protocol: "LDAP",
            severityHint: "low",
            summary: `RootDSE LDAP acessível sem autenticação em ${parsed.host}:${ldapPort} (namingContexts: ${namingContexts.join(", ") || "exposto"}).`,
          })
        }
      } else {
        ldapResult = { port: ldapPort, reachable: false, error: ex.error ?? "no_response" }
      }
    }

    // 3. Optional HTTP NTLM Type-2 Metadata Inspection
    let ntlmResult: Record<string, unknown> | null = null
    if (parsed.ntlmHttpUrl) {
      try {
        const ctrl = new AbortController()
        const timer = setTimeout(() => ctrl.abort(), timeoutMs)
        // Standard minimal inert NTLMSSP Type-1 Negotiate header (no credentials)
        const type1Header = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
        const res = await fetch(parsed.ntlmHttpUrl, {
          method: "GET",
          headers: { Authorization: type1Header },
          redirect: "manual",
          signal: ctrl.signal,
        })
        clearTimeout(timer)
        const wwwAuth = res.headers.get("www-authenticate") ?? ""
        const m = /NTLM\s+([A-Za-z0-9+/=]{24,})/i.exec(wwwAuth)
        if (m) {
          const decoded = decodeNtlmType2Challenge(m[1]!)
          ntlmResult = { url: parsed.ntlmHttpUrl, statusCode: res.status, ...decoded }
          if (decoded.validNtlmChallenge) {
            postureFindings.push({
              protocol: "HTTP-NTLM",
              severityHint: "info",
              summary: `Challenge NTLM expõe metadados internos: Domínio DNS=${decoded.dnsDomainName ?? decoded.nbDomainName ?? "n/a"}, Host=${decoded.dnsComputerName ?? decoded.nbComputerName ?? "n/a"}, OS=${decoded.osVersion ?? "n/a"}.`,
            })
          }
        } else {
          ntlmResult = { url: parsed.ntlmHttpUrl, statusCode: res.status, validNtlmChallenge: false }
        }
      } catch (err) {
        ntlmResult = { url: parsed.ntlmHttpUrl, error: err instanceof Error ? err.message : String(err) }
      }
    }

    const report = {
      host: parsed.host,
      smbSigningAudit: smbResult,
      ldapRootDseAudit: ldapResult,
      ntlmMetadataAudit: ntlmResult,
      findingsCount: postureFindings.length,
      postureFindings,
    }

    const redacted = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await ctx.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "network_observation",
        title: `AD / SMB / LDAP / NTLM Lab Inspection: ${parsed.host} (${postureFindings.length} observação(ões))`,
        rawText: redacted.text,
        mediaType: "application/json",
        toolId: "cyberlab-ad-smb-ldap",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 256 * 1024,
        labels: ["ad-lab", "smb-signing", "ldap", "ntlm"],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `Inspeção de infraestrutura em ${parsed.host} concluída: ${postureFindings.length} observação(ões) em SMB/LDAP/NTLM.`,
      exitCode: 0,
    }
  }
}
