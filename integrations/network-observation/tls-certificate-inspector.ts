import https from "node:https"
import net from "node:net"
import tls from "node:tls"
import { Schema } from "effect"
import {
  normalizeRawOutputDraft,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const TLS_INSPECTOR_INPUT_SCHEMA_ID = "cyberlab.tls-inspector.input.v1"
export const TLS_INSPECTOR_OUTPUT_SCHEMA_ID = "cyberlab.tls-inspector.output.v1"

export const TlsInspectorInputSchema = Schema.Struct({
  host: Schema.String.check(
    Schema.isMinLength(1),
    Schema.isMaxLength(253),
    Schema.isPattern(/^[a-zA-Z0-9._:-]+$/),
  ),
  port: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(65_535))),
  servername: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(253))),
  deepCipherAudit: Schema.optionalKey(Schema.Boolean),
  checkHsts: Schema.optionalKey(Schema.Boolean),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(200), Schema.isLessThanOrEqualTo(10_000)),
  ),
})

export type TlsInspectorInput = typeof TlsInspectorInputSchema.Type

export const TlsInspectorCapability: CapabilityDefinition = {
  id: "network-assessment.tls-inspector",
  version: "1.1.0",
  title: "Native TLS/SSL Handshake, Deep Cipher/Downgrade Audit & X.509 Inspector",
  description:
    "Performs passive TLS handshake and optional testssl-style deep cryptographic posture audit (TLS 1.0/1.1 downgrade support, RC4/3DES/CBC weak cipher suites, ECDHE Forward Secrecy, X.509 key strength, SANs, and HSTS preload).",
  inputSchemaId: TLS_INSPECTOR_INPUT_SCHEMA_ID,
  outputSchemaId: TLS_INSPECTOR_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-passive"],
  requiredScope: ["ip"],
  executorId: "tls-certificate-inspector-executor",
  skillIds: ["network-assessment", "web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

function classifyCipherStrength(cipherName: string | null, protocol: string | null): {
  forwardSecrecy: boolean
  aeadAuthenticated: boolean
  weakOrLegacy: boolean
  notes: string[]
} {
  const upper = (cipherName ?? "").toUpperCase()
  const notes: string[] = []
  const isTls13 = protocol === "TLSv1.3"
  const forwardSecrecy = isTls13 || upper.includes("ECDHE") || upper.includes("DHE")
  const aeadAuthenticated = upper.includes("GCM") || upper.includes("CHACHA20") || upper.includes("CCM")
  let weakOrLegacy = false

  if (/RC4|DES|3DES|NULL|EXPORT|MD5|ANON/i.test(upper)) {
    weakOrLegacy = true
    notes.push(`Cifra criptograficamente obsoleta/insegura detectada: ${cipherName}`)
  }
  if (!aeadAuthenticated && upper.includes("CBC")) {
    notes.push(`Modo de bloco CBC negociado (${cipherName}) — prefira cifras AEAD (AES-GCM ou ChaCha20-Poly1305)`)
  }
  if (!forwardSecrecy) {
    weakOrLegacy = true
    notes.push(`Ausência de Perfect Forward Secrecy (ECDHE/DHE) na cifra ${cipherName}`)
  }
  return { forwardSecrecy, aeadAuthenticated, weakOrLegacy, notes }
}

async function probeSpecificTlsVersion(
  host: string,
  port: number,
  servername: string | undefined,
  version: tls.SecureVersion,
  timeoutMs: number,
): Promise<{ version: string; supported: boolean; negotiatedCipher: string | null }> {
  return new Promise((resolve) => {
    let settled = false
    let sock: tls.TLSSocket
    try {
      sock = tls.connect({
        host,
        port,
        ...(servername ? { servername } : {}),
        minVersion: version,
        maxVersion: version,
        rejectUnauthorized: false,
      })
    } catch {
      resolve({ version, supported: false, negotiatedCipher: null })
      return
    }
    const done = (supported: boolean, cipher: string | null) => {
      if (settled) return
      settled = true
      sock.destroy()
      resolve({ version, supported, negotiatedCipher: cipher })
    }
    sock.setTimeout(Math.min(timeoutMs, 2_500))
    sock.once("secureConnect", () => done(true, sock.getCipher()?.name ?? null))
    sock.once("timeout", () => done(false, null))
    sock.once("error", () => done(false, null))
  })
}

async function probeHstsHeader(
  host: string,
  port: number,
  servername: string | undefined,
  timeoutMs: number,
): Promise<{
  present: boolean
  rawHeader: string | null
  maxAgeSeconds: number | null
  includeSubDomains: boolean
  preload: boolean
}> {
  return new Promise((resolve) => {
    const sniName = servername || (net.isIP(host) === 0 ? host : undefined)
    let req: ReturnType<typeof https.request>
    try {
      req = https.request(
        {
          host,
          port,
          path: "/",
          method: "HEAD",
          ...(sniName ? { servername: sniName } : {}),
          rejectUnauthorized: false,
          timeout: Math.min(timeoutMs, 3_000),
        },
        (res) => {
          const raw = res.headers["strict-transport-security"]
          const headerStr = Array.isArray(raw) ? raw.join("; ") : (raw ?? null)
          res.resume()
          if (!headerStr) {
            resolve({ present: false, rawHeader: null, maxAgeSeconds: null, includeSubDomains: false, preload: false })
            return
          }
          const m = /max-age\s*=\s*(\d+)/i.exec(headerStr)
          resolve({
            present: true,
            rawHeader: headerStr,
            maxAgeSeconds: m ? Number(m[1]) : null,
            includeSubDomains: /\bincludeSubDomains\b/i.test(headerStr),
            preload: /\bpreload\b/i.test(headerStr),
          })
        },
      )
    } catch {
      resolve({ present: false, rawHeader: null, maxAgeSeconds: null, includeSubDomains: false, preload: false })
      return
    }
    req.on("timeout", () => {
      req.destroy()
      resolve({ present: false, rawHeader: null, maxAgeSeconds: null, includeSubDomains: false, preload: false })
    })
    req.on("error", () => {
      resolve({ present: false, rawHeader: null, maxAgeSeconds: null, includeSubDomains: false, preload: false })
    })
    req.end()
  })
}

export class TlsCertificateInspectorExecutor implements CyberLabExecutor {
  readonly id = "tls-certificate-inspector-executor"
  readonly version = "1.1.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string }> {
    return { available: true, version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      Schema.decodeUnknownSync(TlsInspectorInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(TlsInspectorInputSchema)(execInput.input)
    const port = params.port ?? 443
    const timeoutMs = params.timeoutMs ?? 4_000

    const result = await new Promise<{
      protocol: string | null
      cipherName: string | null
      cipherStandardName: string | null
      keyBits: number | null
      authorized: boolean
      authorizationError: string | null
      subject: Record<string, unknown>
      issuer: Record<string, unknown>
      subjectAltName: string | null
      validFrom: string | null
      validTo: string | null
      daysRemaining: number | null
      fingerprint256: string | null
      warnings: string[]
    }>((resolve, reject) => {
      if (ctx.signal.aborted) {
        reject(new Error("Execution aborted prior to TLS handshake"))
        return
      }

      let settled = false
      const socket = tls.connect({
        host: params.host,
        port,
        ...(params.servername ? { servername: params.servername } : {}),
        rejectUnauthorized: false,
      })

      const cleanup = () => {
        ctx.signal.removeEventListener("abort", onAbort)
        socket.destroy()
      }

      const onAbort = () => {
        if (settled) return
        settled = true
        cleanup()
        reject(new Error("TLS inspection cancelled via AbortSignal"))
      }

      ctx.signal.addEventListener("abort", onAbort, { once: true })
      socket.setTimeout(timeoutMs)

      socket.once("secureConnect", () => {
        if (settled) return
        settled = true
        const protocol = socket.getProtocol()
        const cipher = socket.getCipher()
        const cert = socket.getPeerCertificate(false)
        const authErr = socket.authorizationError ? String(socket.authorizationError) : null
        const warnings: string[] = []

        if (protocol === "TLSv1" || protocol === "TLSv1.1" || protocol === "SSLv3") {
          warnings.push(`Deprecated TLS/SSL protocol version negotiated: ${protocol}`)
        }
        if (!socket.authorized) {
          warnings.push(`Certificate chain not trusted by system CA store: ${authErr ?? "untrusted"}`)
        }

        const keyBits = typeof cert?.bits === "number" ? cert.bits : null
        if (keyBits !== null && keyBits > 0 && keyBits < 256 && keyBits < 2048) {
          // ECDSA P-256 is 256 bits; RSA < 2048 is e.g. 1024 bits
        } else if (keyBits !== null && keyBits >= 512 && keyBits < 2048) {
          warnings.push(`Weak RSA public key length detected (${keyBits} bits < 2048 bits)`)
        }

        const cipherEval = classifyCipherStrength(cipher?.name ?? null, protocol)
        warnings.push(...cipherEval.notes)

        let daysRemaining: number | null = null
        if (cert?.valid_to) {
          const expMs = Date.parse(cert.valid_to)
          if (!Number.isNaN(expMs)) {
            daysRemaining = Math.floor((expMs - Date.now()) / 86_400_000)
            if (daysRemaining < 0) warnings.push(`Certificate EXPIRED ${Math.abs(daysRemaining)} day(s) ago`)
            else if (daysRemaining < 14) warnings.push(`Certificate expires soon (${daysRemaining} day(s) left)`)
          }
        }

        cleanup()
        resolve({
          protocol,
          cipherName: cipher?.name ?? null,
          cipherStandardName: (cipher as { standardName?: string } | undefined)?.standardName ?? null,
          keyBits,
          authorized: socket.authorized,
          authorizationError: authErr,
          subject: (cert?.subject as unknown as Record<string, unknown>) ?? {},
          issuer: (cert?.issuer as unknown as Record<string, unknown>) ?? {},
          subjectAltName: cert?.subjectaltname ?? null,
          validFrom: cert?.valid_from ?? null,
          validTo: cert?.valid_to ?? null,
          daysRemaining,
          fingerprint256: cert?.fingerprint256 ?? null,
          warnings,
        })
      })

      socket.once("timeout", () => {
        if (settled) return
        settled = true
        cleanup()
        reject(new Error(`TLS handshake timed out on ${params.host}:${port}`))
      })

      socket.once("error", (err: Error) => {
        if (settled) return
        settled = true
        cleanup()
        reject(err)
      })
    })

    let deepAudit: Record<string, unknown> | undefined
    if (params.deepCipherAudit || params.checkHsts) {
      const protocolMatrix = params.deepCipherAudit
        ? await Promise.all(
            (["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"] as tls.SecureVersion[]).map((ver) =>
              probeSpecificTlsVersion(params.host, port, params.servername, ver, timeoutMs),
            ),
          )
        : []

      const legacyAccepted = protocolMatrix.filter((p) => (p.version === "TLSv1" || p.version === "TLSv1.1") && p.supported)
      for (const leg of legacyAccepted) {
        result.warnings.push(`Servidor aceita downgrade para protocolo obsoleto ${leg.version} (${leg.negotiatedCipher})`)
      }

      const cipherPosture = classifyCipherStrength(result.cipherName, result.protocol)
      const hsts = params.checkHsts ? await probeHstsHeader(params.host, port, params.servername, timeoutMs) : null
      if (params.checkHsts && hsts && !hsts.present) {
        result.warnings.push("Cabeçalho HTTPS Strict-Transport-Security (HSTS) ausente")
      }

      const supportsTls13 = protocolMatrix.some((p) => p.version === "TLSv1.3" && p.supported) || result.protocol === "TLSv1.3"
      const grade =
        legacyAccepted.length > 0 || cipherPosture.weakOrLegacy || (result.daysRemaining !== null && result.daysRemaining < 0)
          ? "F"
          : !result.authorized
            ? "C"
            : supportsTls13 && cipherPosture.forwardSecrecy && hsts?.present && (hsts.maxAgeSeconds ?? 0) >= 31_536_000
              ? "A+"
              : supportsTls13 && cipherPosture.forwardSecrecy
                ? "A"
                : "B"

      deepAudit = {
        securityGrade: grade,
        forwardSecrecy: cipherPosture.forwardSecrecy,
        aeadAuthenticated: cipherPosture.aeadAuthenticated,
        protocolSupportMatrix: protocolMatrix,
        hsts,
      }
    }

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "network_observation",
        title: `TLS Certificate & Cipher Inspection ${params.host}:${port} (${result.protocol ?? "unknown"})`,
        rawText: JSON.stringify({ host: params.host, port, ...result, ...(deepAudit ? { deepAudit } : {}) }, null, 2),
        mediaType: "application/json",
        toolId: "cyberlab-tls-inspector",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 128 * 1024,
        labels: ["tls", "x509", ...(deepAudit ? ["cipher-audit"] : [])],
      }),
    )

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `TLS ${params.host}:${port} negotiated ${result.protocol} (${result.cipherName}); warnings=${result.warnings.length}${deepAudit ? `, grade=${String(deepAudit.securityGrade)}` : ""}.`,
      exitCode: 0,
    }
  }
}
