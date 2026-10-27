import net from "node:net"
import path from "node:path"
import { validateProjectScope, type ProjectScope, type ScopeTargetRule } from "../contracts/policy.js"

export interface ExtractedTargets {
  networkTargets: string[]
  workspacePaths: string[]
}

export interface ScopeCheckResult {
  allowed: boolean
  reason: string
  matchedRule?: ScopeTargetRule
  violatedTarget?: string
}

function ipv4ToUint32(ip: string): number | undefined {
  const parts = ip.trim().split(".")
  if (parts.length !== 4) return undefined
  let acc = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined
    const octet = Number(part)
    if (octet < 0 || octet > 255) return undefined
    acc = ((acc << 8) | octet) >>> 0
  }
  return acc >>> 0
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const [networkStr, prefixStr] = cidr.trim().split("/")
  if (!networkStr || prefixStr === undefined) return false
  const ipNum = ipv4ToUint32(ip)
  const netNum = ipv4ToUint32(networkStr)
  const prefix = Number(prefixStr)
  if (ipNum === undefined || netNum === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false
  }
  if (prefix === 0) return true
  const mask = (0xffffffff << (32 - prefix)) >>> 0
  return (ipNum & mask) === (netNum & mask)
}

export function isPrivateOrLoopbackIp(ip: string): boolean {
  const trimmed = ip.trim().toLowerCase()
  if (trimmed === "::1" || trimmed === "0:0:0:0:0:0:0:1") return true
  if (trimmed.startsWith("fc") || trimmed.startsWith("fd") || trimmed.startsWith("fe80:")) return true
  if (net.isIP(trimmed) !== 4) return false
  return (
    isIpInCidr(trimmed, "127.0.0.0/8") ||
    isIpInCidr(trimmed, "10.0.0.0/8") ||
    isIpInCidr(trimmed, "172.16.0.0/12") ||
    isIpInCidr(trimmed, "192.168.0.0/16") ||
    isIpInCidr(trimmed, "100.64.0.0/10")
  )
}

export function isCloudMetadataIp(ip: string): boolean {
  return net.isIP(ip) === 4 && isIpInCidr(ip, "169.254.169.254/32")
}

function normalizeHostFromTarget(raw: string): { host: string; origin?: string } {
  const trimmed = raw.trim()
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    const parsed = new URL(trimmed)
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase()
    return { host: hostname, origin: parsed.origin.toLowerCase() }
  }
  // Handle host:port for non-IPv6
  if (!trimmed.startsWith("[") && trimmed.split(":").length === 2) {
    const [hostPart] = trimmed.split(":")
    return { host: (hostPart ?? trimmed).toLowerCase() }
  }
  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]")
    if (end > 1) return { host: trimmed.slice(1, end).toLowerCase() }
  }
  return { host: trimmed.toLowerCase() }
}

function matchesDomainRule(host: string, pattern: string): boolean {
  const normHost = host.toLowerCase().replace(/\.$/, "")
  const normPat = pattern.trim().toLowerCase().replace(/\.$/, "")
  if (normPat.startsWith("*.")) {
    const base = normPat.slice(2)
    return normHost === base || normHost.endsWith(`.${base}`)
  }
  return normHost === normPat
}

function matchesNetworkRule(rawTarget: string, rule: ScopeTargetRule): boolean {
  const { host, origin } = normalizeHostFromTarget(rawTarget)
  switch (rule.kind) {
    case "ip":
      return host === rule.value.trim().toLowerCase()
    case "cidr":
      return net.isIP(host) === 4 && isIpInCidr(host, rule.value)
    case "domain":
      return matchesDomainRule(host, rule.value)
    case "url_origin":
      return origin !== undefined && origin === rule.value.trim().toLowerCase().replace(/\/$/, "")
    case "workspace_path":
      return false
  }
}

export function isPathInsideRoot(candidatePath: string, workspaceRoot: string): boolean {
  if (candidatePath.includes("\0")) return false
  const resolvedRoot = path.resolve(workspaceRoot)
  const resolvedCandidate = path.resolve(resolvedRoot, candidatePath)
  const relative = path.relative(resolvedRoot, resolvedCandidate)
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

export function extractTargetsFromInput(input: unknown): ExtractedTargets {
  const networkTargets: string[] = []
  const workspacePaths: string[] = []

  if (!input || typeof input !== "object") {
    return { networkTargets, workspacePaths }
  }

  const record = input as Record<string, unknown>
  const networkKeys = ["target", "url", "host", "ip", "endpoint", "origin"]
  const networkArrayKeys = ["targets", "urls", "hosts"]
  const pathKeys = ["path", "subpath", "file", "directory", "targetPath"]
  const pathArrayKeys = ["paths", "files"]

  for (const key of networkKeys) {
    const val = record[key]
    if (typeof val === "string" && val.trim().length > 0) {
      networkTargets.push(val.trim())
    }
  }
  for (const key of networkArrayKeys) {
    const val = record[key]
    if (Array.isArray(val)) {
      for (const item of val) {
        if (typeof item === "string" && item.trim().length > 0) networkTargets.push(item.trim())
      }
    }
  }
  for (const key of pathKeys) {
    const val = record[key]
    if (typeof val === "string" && val.trim().length > 0) {
      workspacePaths.push(val.trim())
    }
  }
  for (const key of pathArrayKeys) {
    const val = record[key]
    if (Array.isArray(val)) {
      for (const item of val) {
        if (typeof item === "string" && item.trim().length > 0) workspacePaths.push(item.trim())
      }
    }
  }

  return { networkTargets, workspacePaths }
}

export class ScopeController {
  private readonly scopesByProject = new Map<string, ProjectScope>()

  setProjectScope(scope: ProjectScope): ProjectScope {
    const validated = validateProjectScope(scope)
    this.scopesByProject.set(validated.projectId, validated)
    return validated
  }

  getProjectScope(projectId: string): ProjectScope | undefined {
    const scope = this.scopesByProject.get(projectId)
    if (!scope) return undefined
    return {
      ...scope,
      allowedTargets: scope.allowedTargets.map((r) => ({ ...r })),
      blockedTargets: scope.blockedTargets.map((r) => ({ ...r })),
    }
  }

  verifyTargets(
    projectId: string,
    targets: ExtractedTargets,
    requiredScopeKinds?: string[],
  ): ScopeCheckResult {
    const scope = this.scopesByProject.get(projectId)
    if (!scope || !scope.active) {
      return {
        allowed: false,
        reason: `No active ProjectScope configured for project "${projectId}"`,
      }
    }

    const needsNetwork =
      targets.networkTargets.length > 0 ||
      (requiredScopeKinds?.some((k) => k === "network" || k === "cidr" || k === "ip" || k === "domain" || k === "url_origin") ??
        false)

    if (needsNetwork && targets.networkTargets.length === 0) {
      return {
        allowed: false,
        reason: "Capability requires an explicit network target within scope, but none was provided",
      }
    }

    // 1. Validate workspace paths against workspaceRoot and optional workspace_path rules
    for (const candidatePath of targets.workspacePaths) {
      if (!isPathInsideRoot(candidatePath, scope.workspaceRoot)) {
        return {
          allowed: false,
          reason: `Path "${candidatePath}" escapes project workspaceRoot "${scope.workspaceRoot}"`,
          violatedTarget: candidatePath,
        }
      }

      const resolvedCandidate = path.resolve(scope.workspaceRoot, candidatePath)
      const blockedPathRule = scope.blockedTargets.find(
        (rule) =>
          rule.kind === "workspace_path" &&
          isPathInsideRoot(resolvedCandidate, path.resolve(scope.workspaceRoot, rule.value)),
      )
      if (blockedPathRule) {
        return {
          allowed: false,
          reason: `Path "${candidatePath}" is inside blocked workspace path "${blockedPathRule.value}"`,
          matchedRule: blockedPathRule,
          violatedTarget: candidatePath,
        }
      }
    }

    // 2. Validate network targets
    for (const rawTarget of targets.networkTargets) {
      const { host } = normalizeHostFromTarget(rawTarget)

      // Block cloud metadata SSRF vector unconditionally unless explicitly listed as exact IP in allowedTargets AND allowExternalTargets
      if (isCloudMetadataIp(host)) {
        return {
          allowed: false,
          reason: `Target "${rawTarget}" resolves to cloud metadata IP 169.254.169.254 and is blocked`,
          violatedTarget: rawTarget,
        }
      }

      // Explicit blocklist always wins
      const blockedRule = scope.blockedTargets.find((rule) => matchesNetworkRule(rawTarget, rule))
      if (blockedRule) {
        return {
          allowed: false,
          reason: `Target "${rawTarget}" matches blocked scope rule (${blockedRule.kind}: ${blockedRule.value})`,
          matchedRule: blockedRule,
          violatedTarget: rawTarget,
        }
      }

      // Prevent accidental external network expansion when allowExternalTargets === false
      if (!scope.allowExternalTargets) {
        const ipVersion = net.isIP(host)
        if (ipVersion !== 0 && !isPrivateOrLoopbackIp(host)) {
          return {
            allowed: false,
            reason: `External/public IP target "${rawTarget}" is prohibited because scope.allowExternalTargets is false`,
            violatedTarget: rawTarget,
          }
        }
        if (ipVersion === 0 && host !== "localhost" && !host.endsWith(".local") && !host.endsWith(".internal") && !host.endsWith(".lab")) {
          return {
            allowed: false,
            reason: `External hostname "${rawTarget}" is prohibited because scope.allowExternalTargets is false`,
            violatedTarget: rawTarget,
          }
        }
      }

      // Must match at least one allowed rule
      const allowedRule = scope.allowedTargets.find((rule) => matchesNetworkRule(rawTarget, rule))
      if (!allowedRule) {
        return {
          allowed: false,
          reason: `Target "${rawTarget}" is outside the authorized ProjectScope allowlist`,
          violatedTarget: rawTarget,
        }
      }
    }

    return {
      allowed: true,
      reason: "All targets verified within active ProjectScope",
    }
  }
}
