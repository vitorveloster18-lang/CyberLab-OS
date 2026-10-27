import net from "node:net"
import { Schema } from "effect"
import {
  normalizeRawOutputDraft,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const TCP_SURFACE_PROBE_INPUT_SCHEMA_ID = "cyberlab.tcp-surface-probe.input.v1"
export const TCP_SURFACE_PROBE_OUTPUT_SCHEMA_ID = "cyberlab.tcp-surface-probe.output.v1"

export const TcpSurfaceProbeInputSchema = Schema.Struct({
  host: Schema.String.check(
    Schema.isMinLength(1),
    Schema.isMaxLength(253),
    Schema.isPattern(/^[a-zA-Z0-9._:-]+$/),
  ),
  port: Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(65_535)),
  connectTimeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(100), Schema.isLessThanOrEqualTo(5_000)),
  ),
  bannerWaitMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(20), Schema.isLessThanOrEqualTo(1_000)),
  ),
})

export type TcpSurfaceProbeInput = typeof TcpSurfaceProbeInputSchema.Type

export const TcpSurfaceProbeCapability: CapabilityDefinition = {
  id: "network-assessment.tcp-surface-probe",
  version: "1.0.0",
  title: "Controlled TCP Reachability & Passive Banner Probe",
  description:
    "Establishes a single non-intrusive TCP connection to an explicitly authorized in-scope host:port, passively reads any unsolicited greeting banner (<= 1024 bytes) without transmitting fuzzing payloads, and records reproducible SHA-256 network observation evidence.",
  inputSchemaId: TCP_SURFACE_PROBE_INPUT_SCHEMA_ID,
  outputSchemaId: TCP_SURFACE_PROBE_OUTPUT_SCHEMA_ID,
  risk: "low",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["ip"],
  executorId: "tcp-surface-probe-executor",
  skillIds: ["network-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export class TcpSurfaceInspectorExecutor implements CyberLabExecutor {
  readonly id = "tcp-surface-probe-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string; reason?: string }> {
    return { available: true, version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      Schema.decodeUnknownSync(TcpSurfaceProbeInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(TcpSurfaceProbeInputSchema)(execInput.input)
    const connectTimeoutMs = params.connectTimeoutMs ?? 2_000
    const bannerWaitMs = params.bannerWaitMs ?? 150

    const startedAt = Date.now()
    const probeResult = await new Promise<{
      reachable: boolean
      banner: string
      elapsedMs: number
      errorCode?: string
    }>((resolve, reject) => {
      if (ctx.signal.aborted) {
        reject(new Error("Execution aborted before TCP connect"))
        return
      }

      const socket = new net.Socket()
      let settled = false
      const chunks: Buffer[] = []
      let totalBytes = 0

      const finish = (outcome: { reachable: boolean; banner: string; elapsedMs: number; errorCode?: string }) => {
        if (settled) return
        settled = true
        ctx.signal.removeEventListener("abort", onAbort)
        socket.destroy()
        resolve(outcome)
      }

      const onAbort = () => {
        if (settled) return
        settled = true
        socket.destroy()
        reject(new Error("TCP surface probe cancelled via AbortSignal"))
      }

      ctx.signal.addEventListener("abort", onAbort, { once: true })
      socket.setTimeout(connectTimeoutMs)

      socket.once("connect", () => {
        const bannerTimer = setTimeout(() => {
          finish({
            reachable: true,
            banner: Buffer.concat(chunks).toString("utf8").trim(),
            elapsedMs: Date.now() - startedAt,
          })
        }, bannerWaitMs)

        socket.on("data", (chunk: Buffer) => {
          const remaining = 1024 - totalBytes
          if (remaining > 0) {
            const slice = chunk.subarray(0, remaining)
            chunks.push(slice)
            totalBytes += slice.byteLength
          }
          if (totalBytes >= 1024) {
            clearTimeout(bannerTimer)
            finish({
              reachable: true,
              banner: Buffer.concat(chunks).toString("utf8").trim(),
              elapsedMs: Date.now() - startedAt,
            })
          }
        })

        socket.once("end", () => {
          clearTimeout(bannerTimer)
          finish({
            reachable: true,
            banner: Buffer.concat(chunks).toString("utf8").trim(),
            elapsedMs: Date.now() - startedAt,
          })
        })
      })

      socket.once("timeout", () => {
        finish({
          reachable: false,
          banner: "",
          elapsedMs: Date.now() - startedAt,
          errorCode: "ETIMEDOUT",
        })
      })

      socket.once("error", (err: NodeJS.ErrnoException) => {
        finish({
          reachable: false,
          banner: "",
          elapsedMs: Date.now() - startedAt,
          errorCode: err.code ?? err.message,
        })
      })

      socket.connect(params.port, params.host)
    })

    const observationPayload = {
      host: params.host,
      port: params.port,
      state: probeResult.reachable ? "open" : "closed_or_filtered",
      banner: probeResult.banner || null,
      elapsedMs: probeResult.elapsedMs,
      ...(probeResult.errorCode !== undefined ? { errorCode: probeResult.errorCode } : {}),
    }

    const obsEvidenceId = await ctx.emitEvidence({
      kind: "network_observation",
      title: `TCP Surface Probe ${params.host}:${params.port} (${observationPayload.state})`,
      source: {
        toolId: "cyberlab-tcp-surface-probe",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
      },
      content: {
        mediaType: "application/json",
        inlineText: JSON.stringify(observationPayload, null, 2),
      },
      observedAt: new Date().toISOString(),
      labels: ["tcp-probe", observationPayload.state],
    })

    const summaryEvidenceId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "stdout",
        title: `TCP Banner Transcript ${params.host}:${params.port}`,
        rawText: probeResult.reachable
          ? `TCP ${params.host}:${params.port} OPEN (${probeResult.elapsedMs}ms)\nBanner: ${probeResult.banner || "(none)"}`
          : `TCP ${params.host}:${params.port} UNREACHABLE (${probeResult.errorCode ?? "closed"})`,
        mediaType: "text/plain; charset=utf-8",
        toolId: "cyberlab-tcp-surface-probe",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 64 * 1024,
      }),
    )

    return {
      status: "succeeded",
      evidenceIds: [obsEvidenceId, summaryEvidenceId],
      summary: `TCP ${params.host}:${params.port} -> ${observationPayload.state}${probeResult.banner ? ` [banner: ${probeResult.banner.slice(0, 60)}]` : ""}`,
      exitCode: 0,
    }
  }
}
