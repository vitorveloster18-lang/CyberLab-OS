import crypto from "node:crypto"
import { createDefaultEngagementProfile, type EngagementProfile } from "../contracts/policy.js"

export interface GlobalHttpLogEntry {
  logId: string
  timestamp: string
  projectId: string
  sourceTool: string
  method: string
  url: string
  host: string
  statusCode: number
  elapsedMs: number
  responseBytes: number
  notes?: string
}

export type GlobalHttpTrafficEntry = GlobalHttpLogEntry

interface RateBucket {
  nextAllowedAtMs: number
}

const MAX_GLOBAL_HTTP_LOGS = 600

class EngagementRuntimeRegistry {
  private readonly profiles = new Map<string, EngagementProfile>()
  private readonly buckets = new Map<string, RateBucket>()
  private readonly logsByProject = new Map<string, GlobalHttpLogEntry[]>()

  setProfile(projectId: string, profile?: EngagementProfile): void {
    if (!profile) {
      this.profiles.set(projectId, createDefaultEngagementProfile())
      return
    }
    this.profiles.set(projectId, {
      ...profile,
      maxRequestsPerSecond: Math.max(1, Math.min(200, Math.round(profile.maxRequestsPerSecond || 20))),
      customHeaders: profile.customHeaders.map((h) => ({ ...h })),
    })
  }

  getProfile(projectId: string): EngagementProfile {
    const existing = this.profiles.get(projectId)
    if (!existing) return createDefaultEngagementProfile()
    return {
      ...existing,
      customHeaders: existing.customHeaders.map((h) => ({ ...h })),
    }
  }

  /**
   * Enforces program `maxRequestsPerSecond` when engagement mode is `bug_bounty` or `authorized_pentest`
   * (or whenever custom RPS <= 50 is explicitly configured).
   */
  async acquireRateSlot(projectId: string, signal?: AbortSignal): Promise<void> {
    const profile = this.profiles.get(projectId)
    if (!profile) return
    if (profile.mode === "lab_isolated" && profile.maxRequestsPerSecond >= 20) return

    const rps = Math.max(1, Math.min(200, profile.maxRequestsPerSecond || 10))
    const intervalMs = Math.ceil(1000 / rps)
    const now = Date.now()
    const bucket = this.buckets.get(projectId) ?? { nextAllowedAtMs: now }
    const waitMs = Math.max(0, bucket.nextAllowedAtMs - now)
    bucket.nextAllowedAtMs = Math.max(now, bucket.nextAllowedAtMs) + intervalMs
    this.buckets.set(projectId, bucket)

    if (waitMs > 0) {
      await new Promise<void>((resolve, reject) => {
        if (signal?.aborted) {
          reject(new Error("Aborted while waiting for engagement rate-limit slot"))
          return
        }
        const timer = setTimeout(() => {
          signal?.removeEventListener("abort", onAbort)
          resolve()
        }, waitMs)
        const onAbort = () => {
          clearTimeout(timer)
          reject(new Error("Aborted while waiting for engagement rate-limit slot"))
        }
        signal?.addEventListener("abort", onAbort, { once: true })
      })
    }
  }

  /**
   * Applies engagement headers (`X-Bug-Bounty`, custom `User-Agent`, session headers)
   * without overwriting headers explicitly set on the individual request.
   */
  applyHeaders(projectId: string, existingHeaders: Record<string, string>): Record<string, string> {
    const out: Record<string, string> = { ...existingHeaders }
    const lowerMap = new Set(Object.keys(out).map((k) => k.toLowerCase()))
    const profile = this.profiles.get(projectId)
    if (!profile) return out

    if (profile.customUserAgent?.trim() && !lowerMap.has("user-agent")) {
      out["User-Agent"] = profile.customUserAgent.trim()
      lowerMap.add("user-agent")
    }

    for (const hdr of profile.customHeaders) {
      if (!hdr.enabled) continue
      const key = hdr.name.trim()
      if (!key) continue
      if (!lowerMap.has(key.toLowerCase())) {
        out[key] = hdr.value
        lowerMap.add(key.toLowerCase())
      }
    }

    return out
  }

  recordTraffic(entry: Omit<GlobalHttpLogEntry, "logId" | "timestamp">): GlobalHttpLogEntry {
    const full: GlobalHttpLogEntry = {
      logId: `hlog-${crypto.randomUUID().slice(0, 8)}`,
      timestamp: new Date().toISOString(),
      ...entry,
    }
    const arr = this.logsByProject.get(entry.projectId) ?? []
    arr.push(full)
    if (arr.length > MAX_GLOBAL_HTTP_LOGS) {
      arr.shift()
    }
    this.logsByProject.set(entry.projectId, arr)
    return full
  }

  listTraffic(projectId: string, limit = 250): GlobalHttpLogEntry[] {
    const arr = this.logsByProject.get(projectId) ?? []
    return [...arr].reverse().slice(0, limit)
  }

  clearTraffic(projectId: string): void {
    this.logsByProject.set(projectId, [])
  }
}

export const EngagementRuntime = new EngagementRuntimeRegistry()
