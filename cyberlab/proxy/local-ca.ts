import crypto from "node:crypto"
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import net from "node:net"
import path from "node:path"

/**
 * Pure TypeScript / node:crypto X.509v3 Local Lab Certificate Authority (MIT)
 *
 * Generates a project-scoped Root CA (.cyberlab/ca/cyberlab-root-ca.pem) and signs
 * ephemeral in-memory leaf certificates per target SNI / IP so CyberLabHttpProxy can
 * inspect local/in-scope HTTPS (CONNECT) and WSS traffic without requiring external OpenSSL binaries.
 */

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len])
  const bytes: number[] = []
  let n = len
  while (n > 0) {
    bytes.unshift(n & 0xff)
    n >>= 8
  }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

function derWrap(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content])
}

function derSeq(...items: Buffer[]): Buffer {
  return derWrap(0x30, Buffer.concat(items))
}

function derSet(...items: Buffer[]): Buffer {
  return derWrap(0x31, Buffer.concat(items))
}

function derOid(oid: string): Buffer {
  const parts = oid.split(".").map((x) => Number(x))
  const first = parts[0]! * 40 + parts[1]!
  const out: number[] = [first]
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i]!
    if (val === 0) {
      out.push(0)
      continue
    }
    const stack: number[] = []
    while (val > 0) {
      stack.unshift(val & 0x7f)
      val = Math.floor(val / 128)
    }
    for (let j = 0; j < stack.length - 1; j++) {
      stack[j] = stack[j]! | 0x80
    }
    out.push(...stack)
  }
  return derWrap(0x06, Buffer.from(out))
}

function derIntegerFromBytes(raw: Buffer): Buffer {
  let b = raw
  while (b.length > 1 && b[0] === 0x00 && (b[1]! & 0x80) === 0) {
    b = b.subarray(1)
  }
  if ((b[0]! & 0x80) !== 0) {
    b = Buffer.concat([Buffer.from([0x00]), b])
  }
  return derWrap(0x02, b)
}

function derSmallInt(n: number): Buffer {
  return derWrap(0x02, Buffer.from([n & 0xff]))
}

function derBoolean(val: boolean): Buffer {
  return derWrap(0x01, Buffer.from([val ? 0xff : 0x00]))
}

function derOctetString(buf: Buffer): Buffer {
  return derWrap(0x04, buf)
}

function derBitString(payload: Buffer, unusedBits = 0): Buffer {
  return derWrap(0x03, Buffer.concat([Buffer.from([unusedBits & 0xff]), payload]))
}

function derUtf8String(text: string): Buffer {
  return derWrap(0x0c, Buffer.from(text, "utf8"))
}

function derUtcTime(date: Date): Buffer {
  const yy = String(date.getUTCFullYear() % 100).padStart(2, "0")
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0")
  const dd = String(date.getUTCDate()).padStart(2, "0")
  const hh = String(date.getUTCHours()).padStart(2, "0")
  const mi = String(date.getUTCMinutes()).padStart(2, "0")
  const ss = String(date.getUTCSeconds()).padStart(2, "0")
  return derWrap(0x17, Buffer.from(`${yy}${mm}${dd}${hh}${mi}${ss}Z`, "ascii"))
}

function derExplicit(contextTag: number, inner: Buffer): Buffer {
  return derWrap(0xa0 | contextTag, inner)
}

function derName(cn: string, org: string): Buffer {
  const rdnOrg = derSet(derSeq(derOid("2.5.4.10"), derUtf8String(org)))
  const rdnCn = derSet(derSeq(derOid("2.5.4.3"), derUtf8String(cn)))
  return derSeq(rdnOrg, rdnCn)
}

function derExtension(oid: string, critical: boolean, extnValueDer: Buffer): Buffer {
  if (critical) {
    return derSeq(derOid(oid), derBoolean(true), derOctetString(extnValueDer))
  }
  return derSeq(derOid(oid), derOctetString(extnValueDer))
}

function derToPem(label: string, der: Buffer): string {
  const b64 = der.toString("base64")
  const lines: string[] = []
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64))
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`
}

function buildSanExtensionValue(host: string): Buffer {
  const cleanHost = host.replace(/^\[|\]$/g, "").trim()
  const ipKind = net.isIP(cleanHost)
  if (ipKind === 4) {
    const octets = Buffer.from(cleanHost.split(".").map((p) => Number(p)))
    // GeneralName iPAddress [7] IMPLICIT OCTET STRING
    return derSeq(derWrap(0x87, octets))
  }
  if (ipKind === 6) {
    // Expand IPv6 into 16 bytes via URL/Buffer helper
    const groups = expandIpv6(cleanHost)
    return derSeq(derWrap(0x87, groups))
  }
  // GeneralName dNSName [2] IMPLICIT IA5String
  return derSeq(derWrap(0x82, Buffer.from(cleanHost, "ascii")))
}

function expandIpv6(addr: string): Buffer {
  const halves = addr.split("::")
  const left = halves[0] ? halves[0].split(":").filter(Boolean) : []
  const right = halves.length > 1 && halves[1] ? halves[1].split(":").filter(Boolean) : []
  const missing = Math.max(0, 8 - (left.length + right.length))
  const full = [...left, ...Array.from({ length: missing }, () => "0"), ...right]
  const buf = Buffer.alloc(16)
  for (let i = 0; i < 8; i++) {
    buf.writeUInt16BE(parseInt(full[i] || "0", 16), i * 2)
  }
  return buf
}

// OID ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
const ALG_ECDSA_SHA256 = derSeq(derOid("1.2.840.10045.4.3.2"))

export interface LocalCaBundle {
  certPem: string
  keyPem: string
  fingerprintSha256: string
  certPath: string | null
}

export class CyberLabLocalCa {
  private rootCertPem: string
  private rootKeyPem: string
  private rootPrivateKey: crypto.KeyObject
  private fingerprintSha256: string
  private readonly certPath: string | null
  private readonly leafCache = new Map<string, { certPem: string; keyPem: string }>()

  private static readonly ROOT_CN = "CyberLab OS Local Lab Root CA"
  private static readonly ROOT_ORG = "CyberLab OS Security Workbench"

  constructor(options?: { caDirectory?: string }) {
    const caDir = options?.caDirectory
    const certFile = caDir ? path.join(caDir, "cyberlab-root-ca.pem") : null
    const keyFile = caDir ? path.join(caDir, "cyberlab-root-ca-key.pem") : null
    this.certPath = certFile

    if (certFile && keyFile && existsSync(certFile) && existsSync(keyFile)) {
      this.rootCertPem = readFileSync(certFile, "utf8")
      this.rootKeyPem = readFileSync(keyFile, "utf8")
      this.rootPrivateKey = crypto.createPrivateKey(this.rootKeyPem)
      const x509 = new crypto.X509Certificate(this.rootCertPem)
      this.fingerprintSha256 = x509.fingerprint256
      return
    }

    const generated = CyberLabLocalCa.generateRootCa()
    this.rootCertPem = generated.certPem
    this.rootKeyPem = generated.keyPem
    this.rootPrivateKey = generated.privateKey
    this.fingerprintSha256 = generated.fingerprintSha256

    if (caDir && certFile && keyFile) {
      try {
        mkdirSync(caDir, { recursive: true })
        writeFileSync(certFile, this.rootCertPem, { encoding: "utf8", mode: 0o644 })
        writeFileSync(keyFile, this.rootKeyPem, { encoding: "utf8", mode: 0o600 })
      } catch {
        // Fallback to in-memory if filesystem is read-only
      }
    }
  }

  private static generateRootCa(): {
    certPem: string
    keyPem: string
    privateKey: crypto.KeyObject
    fingerprintSha256: string
  } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    })
    const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer
    const serial = crypto.randomBytes(16)
    serial[0] = serial[0]! & 0x7f
    if (serial[0] === 0) serial[0] = 0x01

    const now = new Date(Date.now() - 60_000)
    const notAfter = new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000) // 10 years
    const dn = derName(CyberLabLocalCa.ROOT_CN, CyberLabLocalCa.ROOT_ORG)

    const basicConstraints = derExtension("2.5.29.19", true, derSeq(derBoolean(true)))
    // keyCertSign (bit 5) | cRLSign (bit 6) => 0b00000110 = 0x06, unused bits = 1
    const keyUsage = derExtension("2.5.29.15", true, derBitString(Buffer.from([0x06]), 1))
    const skiHash = crypto.createHash("sha1").update(spkiDer).digest()
    const skiExt = derExtension("2.5.29.14", false, derOctetString(skiHash))

    const tbs = derSeq(
      derExplicit(0, derSmallInt(2)),
      derIntegerFromBytes(serial),
      ALG_ECDSA_SHA256,
      dn,
      derSeq(derUtcTime(now), derUtcTime(notAfter)),
      dn,
      spkiDer,
      derExplicit(3, derSeq(basicConstraints, keyUsage, skiExt)),
    )

    const sig = crypto.sign("sha256", tbs, privateKey)
    const certDer = derSeq(tbs, ALG_ECDSA_SHA256, derBitString(sig, 0))
    const certPem = derToPem("CERTIFICATE", certDer)
    const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string
    const x509 = new crypto.X509Certificate(certPem)

    return {
      certPem,
      keyPem,
      privateKey,
      fingerprintSha256: x509.fingerprint256,
    }
  }

  getBundleInfo(): Omit<LocalCaBundle, "keyPem"> {
    return {
      certPem: this.rootCertPem,
      fingerprintSha256: this.fingerprintSha256,
      certPath: this.certPath,
    }
  }

  issueHostCertificate(rawHost: string): { certPem: string; keyPem: string } {
    const cleanHost = rawHost.replace(/:\d+$/, "").replace(/^\[|\]$/g, "").trim().toLowerCase() || "localhost"
    const cached = this.leafCache.get(cleanHost)
    if (cached) return cached

    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    })
    const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer
    const serial = crypto.randomBytes(16)
    serial[0] = serial[0]! & 0x7f
    if (serial[0] === 0) serial[0] = 0x01

    const now = new Date(Date.now() - 60_000)
    const notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
    const issuerDn = derName(CyberLabLocalCa.ROOT_CN, CyberLabLocalCa.ROOT_ORG)
    const subjectDn = derName(cleanHost.slice(0, 64), "CyberLab OS Dynamic TLS Proxy")

    const basicConstraints = derExtension("2.5.29.19", true, derSeq())
    // digitalSignature (bit 0) => 0b10000000 = 0x80, unused bits = 7
    const keyUsage = derExtension("2.5.29.15", true, derBitString(Buffer.from([0x80]), 7))
    // serverAuth (1.3.6.1.5.5.7.3.1)
    const extKeyUsage = derExtension("2.5.29.37", false, derSeq(derOid("1.3.6.1.5.5.7.3.1")))
    const sanExt = derExtension("2.5.29.17", false, buildSanExtensionValue(cleanHost))

    const tbs = derSeq(
      derExplicit(0, derSmallInt(2)),
      derIntegerFromBytes(serial),
      ALG_ECDSA_SHA256,
      issuerDn,
      derSeq(derUtcTime(now), derUtcTime(notAfter)),
      subjectDn,
      spkiDer,
      derExplicit(3, derSeq(basicConstraints, keyUsage, extKeyUsage, sanExt)),
    )

    const sig = crypto.sign("sha256", tbs, this.rootPrivateKey)
    const certDer = derSeq(tbs, ALG_ECDSA_SHA256, derBitString(sig, 0))
    const leaf = {
      certPem: derToPem("CERTIFICATE", certDer),
      keyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    }

    if (this.leafCache.size >= 256) {
      const oldest = this.leafCache.keys().next().value
      if (oldest) this.leafCache.delete(oldest)
    }
    this.leafCache.set(cleanHost, leaf)
    return leaf
  }
}
