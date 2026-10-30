import {
  validatePartnerResult,
  type PartnerEnvelope,
  type PartnerTask,
  type SignedPartnerEnvelope,
} from "../contracts/partner-protocol.js"
import { computeEnvelopeHmac } from "./authentication.js"

export interface PartnerSendOptions {
  signal: AbortSignal
  timeoutMs: number
}

export interface PartnerTransport {
  send(envelope: SignedPartnerEnvelope, options: PartnerSendOptions): Promise<SignedPartnerEnvelope[]>
}

export class HttpPartnerTransport implements PartnerTransport {
  constructor(
    private readonly endpointUrl: string,
    private readonly maxRetries: number = 1,
  ) {}

  async send(envelope: SignedPartnerEnvelope, options: PartnerSendOptions): Promise<SignedPartnerEnvelope[]> {
    let lastError: unknown
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const timeoutCtrl = new AbortController()
      const timer = setTimeout(() => timeoutCtrl.abort(new Error(`Partner HTTP timeout after ${options.timeoutMs}ms`)), options.timeoutMs)
      const onParentAbort = () => timeoutCtrl.abort(options.signal.reason ?? new Error("Aborted"))
      options.signal.addEventListener("abort", onParentAbort, { once: true })

      try {
        const res = await fetch(this.endpointUrl, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-cyberlab-protocol": "cyberlab-partner/1.0",
          },
          body: JSON.stringify(envelope),
          signal: timeoutCtrl.signal,
        })
        if (!res.ok) {
          throw new Error(`Partner HTTP ${res.status}`)
        }
        const json = (await res.json()) as SignedPartnerEnvelope | SignedPartnerEnvelope[]
        return Array.isArray(json) ? json : [json]
      } catch (err) {
        lastError = err
        if (options.signal.aborted || attempt === this.maxRetries) {
          throw err
        }
      } finally {
        clearTimeout(timer)
        options.signal.removeEventListener("abort", onParentAbort)
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError))
  }
}

/**
 * Adapter for partner runtimes that only expose an unstructured chat/prompt script.
 * Explicitly marks bridged results with structural reliability limitations per Section 8.3.
 */
export class PromptChatPartnerTransport implements PartnerTransport {
  constructor(
    private readonly partnerId: string,
    private readonly partnerSecret: string,
    private readonly chatFn: (prompt: string, signal: AbortSignal) => Promise<string>,
  ) {}

  async send(envelope: SignedPartnerEnvelope, options: PartnerSendOptions): Promise<SignedPartnerEnvelope[]> {
    if (envelope.type === "task.cancel") {
      return []
    }
    const task = envelope.payload as PartnerTask
    const prompt = [
      "You are an external partner security analysis runtime bridged into CyberLab OS.",
      `Task ID: ${task.taskId}`,
      `Objective: ${task.objective}`,
      `Context Evidence IDs: ${task.contextBundle.evidenceIds.join(", ") || "none"}`,
      task.contextBundle.text ? `Redacted Context:\n${task.contextBundle.text}` : "",
      "Return ONLY valid JSON matching PartnerResult: { taskId, status, summary, findings, limitations, artifactRefs }.",
    ]
      .filter(Boolean)
      .join("\n\n")

    const rawReply = await this.chatFn(prompt, options.signal)
    let parsedJson: Record<string, unknown>
    const extraLimitations: string[] = []
    try {
      const candidate = JSON.parse(rawReply) as unknown
      if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
        parsedJson = candidate as Record<string, unknown>
      } else {
        throw new Error("Non-object JSON reply")
      }
    } catch {
      parsedJson = {
        status: "completed",
        summary: String(rawReply).slice(0, 4_000) || "Empty partner reply",
        findings: [],
        limitations: [],
        artifactRefs: [],
      }
      extraLimitations.push("Partner returned non-JSON unstructured text; coerced safely without execution.")
    }

    const validated = validatePartnerResult({
      ...parsedJson,
      taskId: task.taskId,
      limitations: [
        ...(Array.isArray(parsedJson["limitations"]) ? (parsedJson["limitations"] as string[]) : []),
        ...extraLimitations,
        "Bridged via unstructured prompt-chat adapter; verify against raw EvidenceStore artifacts.",
      ],
    })

    const responseEnvelope: PartnerEnvelope = {
      protocol: "cyberlab-partner",
      protocolVersion: "1.0",
      messageId: `pmsg-${crypto.randomUUID()}`,
      correlationId: envelope.correlationId,
      sentAt: new Date().toISOString(),
      sender: { id: this.partnerId, type: "partner" },
      recipient: { id: envelope.sender.id },
      type: "task.result",
      payload: validated,
    }
    const signature = computeEnvelopeHmac(responseEnvelope, this.partnerSecret)
    return [{ ...responseEnvelope, signature }]
  }
}

export class InMemoryPartnerTransport implements PartnerTransport {
  constructor(
    private readonly handler: (
      envelope: SignedPartnerEnvelope,
      signal: AbortSignal,
    ) => Promise<SignedPartnerEnvelope[]>,
  ) {}

  async send(envelope: SignedPartnerEnvelope, options: PartnerSendOptions): Promise<SignedPartnerEnvelope[]> {
    return this.handler(envelope, options.signal)
  }
}
