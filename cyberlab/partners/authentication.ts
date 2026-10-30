import { createHmac, timingSafeEqual } from "node:crypto"
import {
  validatePartnerEnvelope,
  type PartnerEnvelope,
  type SignedPartnerEnvelope,
} from "../contracts/partner-protocol.js"
import { canonicalJson } from "../evidence/hashing.js"

export interface PartnerProfile {
  partnerId: string
  displayName: string
  /** Shared HMAC secret kept strictly in local memory/credential store, never serialized into logs or envelopes. */
  sharedSecret: string
  allowedActions: string[]
  prohibitedActions: string[]
  enabled: boolean
}

export class PartnerAuthError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = "PartnerAuthError"
    this.code = code
  }
}

export function computeEnvelopeHmac(envelope: PartnerEnvelope, secret: string): string {
  const canonical = canonicalJson(envelope)
  return createHmac("sha256", secret).update(canonical, "utf8").digest("hex")
}

export class PartnerAuthenticator {
  private readonly profiles = new Map<string, PartnerProfile>()
  private readonly seenMessages = new Map<string, number>()

  constructor(private readonly maxClockSkewMs: number = 5 * 60 * 1000) {}

  registerPartner(profile: PartnerProfile): void {
    if (!profile.partnerId.trim()) {
      throw new Error("partnerId cannot be empty")
    }
    if (profile.sharedSecret.length < 16) {
      throw new Error(`Shared secret for partner "${profile.partnerId}" must be at least 16 characters`)
    }
    this.profiles.set(profile.partnerId, {
      ...profile,
      allowedActions: [...profile.allowedActions],
      prohibitedActions: [...profile.prohibitedActions],
    })
  }

  getPublicProfile(partnerId: string): Omit<PartnerProfile, "sharedSecret"> | undefined {
    const p = this.profiles.get(partnerId)
    if (!p) return undefined
    return {
      partnerId: p.partnerId,
      displayName: p.displayName,
      allowedActions: [...p.allowedActions],
      prohibitedActions: [...p.prohibitedActions],
      enabled: p.enabled,
    }
  }

  listPublicProfiles(): Array<Omit<PartnerProfile, "sharedSecret">> {
    return Array.from(this.profiles.keys()).map((id) => this.getPublicProfile(id)!)
  }

  signOutbound<TPayload>(partnerId: string, envelope: PartnerEnvelope<TPayload>): SignedPartnerEnvelope<TPayload> {
    const profile = this.profiles.get(partnerId)
    if (!profile || !profile.enabled) {
      throw new PartnerAuthError("PARTNER_NOT_ENABLED", `Partner "${partnerId}" is not registered or is disabled`)
    }
    const signature = computeEnvelopeHmac(envelope, profile.sharedSecret)
    return {
      ...envelope,
      signature,
    }
  }

  verifyInbound(
    rawSigned: unknown,
    options?: { maxEnvelopeBytes?: number; now?: Date },
  ): PartnerEnvelope {
    const nowMs = (options?.now ?? new Date()).getTime()
    this.pruneExpiredMessages(nowMs)

    if (!rawSigned || typeof rawSigned !== "object") {
      throw new PartnerAuthError("MALFORMED_ENVELOPE", "Signed partner message must be a JSON object")
    }

    const { signature, ...rest } = rawSigned as Record<string, unknown>
    if (typeof signature !== "string" || !/^[a-f0-9]{64}$/.test(signature)) {
      throw new PartnerAuthError("MISSING_OR_INVALID_SIGNATURE", "Partner message is missing a valid 64-char hex HMAC signature")
    }

    const envelope = validatePartnerEnvelope(rest, options?.maxEnvelopeBytes)

    if (envelope.sender.type !== "partner") {
      throw new PartnerAuthError("INVALID_SENDER_TYPE", "Inbound partner message must have sender.type === 'partner'")
    }

    const profile = this.profiles.get(envelope.sender.id)
    if (!profile || !profile.enabled) {
      throw new PartnerAuthError("UNKNOWN_OR_DISABLED_PARTNER", `Partner "${envelope.sender.id}" is unknown or disabled`)
    }

    const expectedHex = computeEnvelopeHmac(envelope, profile.sharedSecret)
    const sigBuf = Buffer.from(signature, "hex")
    const expBuf = Buffer.from(expectedHex, "hex")
    if (sigBuf.byteLength !== expBuf.byteLength || !timingSafeEqual(sigBuf, expBuf)) {
      throw new PartnerAuthError("SIGNATURE_MISMATCH", `HMAC verification failed for partner "${envelope.sender.id}"`)
    }

    const sentAtMs = Date.parse(envelope.sentAt)
    if (Number.isNaN(sentAtMs) || Math.abs(nowMs - sentAtMs) > this.maxClockSkewMs) {
      throw new PartnerAuthError(
        "TIMESTAMP_OUT_OF_WINDOW",
        `Message sentAt "${envelope.sentAt}" is outside allowed clock skew (${this.maxClockSkewMs}ms)`,
      )
    }

    const replayKey = `${envelope.sender.id}:${envelope.messageId}`
    if (this.seenMessages.has(replayKey)) {
      throw new PartnerAuthError("REPLAY_DETECTED", `Duplicate messageId "${envelope.messageId}" from "${envelope.sender.id}" rejected`)
    }
    this.seenMessages.set(replayKey, nowMs + this.maxClockSkewMs * 2)

    return envelope
  }

  private pruneExpiredMessages(nowMs: number): void {
    for (const [key, expiresAt] of this.seenMessages.entries()) {
      if (nowMs > expiresAt) {
        this.seenMessages.delete(key)
      }
    }
  }
}
