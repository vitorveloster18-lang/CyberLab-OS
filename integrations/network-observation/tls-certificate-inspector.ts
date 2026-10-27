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
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(200), Schema.isLessThanOrEqualTo(10_000)),
  ),
})

export type TlsInspectorInput = typeof TlsInspectorInputSchema.Type

export const TlsInspectorCapability: CapabilityDefinition = {
  id: "network-assessment.tls-inspector",
  version: "1.0.0",
  title: "Native TLS/SSL Handshake & X.509 Certificate Inspector",
  description:
    "Performs a passive TLS handshake against an authorized host:port, inspecting negotiated TLS protocol version, cipher suite, X.509 subject/issuer, Subject Alternative Names (SANs), SHA-256 certificate fingerprint, trust chain status, and expiration window.",
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

export class TlsCertificateInspectorExecutor implements CyberLabExecutor {
  readonly id = "tls-certificate-inspector-executor"
  readonly version = "1.0.0"

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
      // Passive TLS inspection connects with rejectUnauthorized: false so self-signed/expired lab certs can be inspected and flagged explicitly.
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

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "network_observation",
        title: `TLS Certificate Inspection ${params.host}:${port} (${result.protocol ?? "unknown"})`,
        rawText: JSON.stringify({ host: params.host, port, ...result }, null, 2),
        mediaType: "application/json",
        toolId: "cyberlab-tls-inspector",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 128 * 1024,
        labels: ["tls", "x509"],
      }),
    )

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `TLS ${params.host}:${port} negotiated ${result.protocol} (${result.cipherName}); warnings=${result.warnings.length}.`,
      exitCode: 0,
    }
  }
}
