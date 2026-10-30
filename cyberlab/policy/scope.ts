import net from "node:net"
import path from "node:path"
import {
  validateProjectScope,
  type BugBountyPlatform,
  type EngagementHeaderRule,
  type EngagementProfile,
  type ProjectScope,
  type ScopeTargetRule,
} from "../contracts/policy.js"

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

export interface ImportedScopeBundle {
  detectedFormat: "hackerone_json" | "bugcrowd_json" | "plaintext_rules"
  programName?: string
  allowedTargets: ScopeTargetRule[]
  blockedTargets: ScopeTargetRule[]
  allowExternalTargets: boolean
  engagement: EngagementProfile
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

function normalizeHostFromTarget(raw: string): { host: string; origin?: string; normalizedUrl?: string } {
  const trimmed = raw.trim()
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    const safeUrlStr = trimmed.replace(/§[^§]*§/g, "marker")
    const parsed = new URL(safeUrlStr)
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase()
    return {
      host: hostname,
      origin: parsed.origin.toLowerCase(),
      normalizedUrl: `${parsed.origin.toLowerCase()}${parsed.pathname}${parsed.search}`,
    }
  }
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

function sanitizeDomainPattern(pattern: string): string {
  let clean = pattern.trim().toLowerCase()
  clean = clean.replace(/^https?:\/\//, "")
  const slashIdx = clean.indexOf("/")
  if (slashIdx !== -1) clean = clean.slice(0, slashIdx)
  const colonIdx = clean.indexOf(":")
  if (colonIdx !== -1 && !clean.startsWith("[")) clean = clean.slice(0, colonIdx)
  return clean.replace(/\.$/, "")
}

function matchesDomainRule(host: string, pattern: string): boolean {
  const normHost = host.toLowerCase().replace(/\.$/, "")
  const normPat = sanitizeDomainPattern(pattern)
  if (normPat.startsWith("*.")) {
    const base = normPat.slice(2)
    return normHost === base || normHost.endsWith(`.${base}`)
  }
  return normHost === normPat
}

function matchesUrlPrefixRule(normalizedUrl: string | undefined, host: string, rawPrefix: string): boolean {
  const cleanRule = rawPrefix.trim().replace(/\*+$/, "")
  if (!cleanRule) return false
  if (normalizedUrl) {
    const lowerUrl = normalizedUrl.toLowerCase()
    const lowerRule = cleanRule.toLowerCase()
    if (/^https?:\/\//.test(lowerRule)) {
      return lowerUrl.startsWith(lowerRule)
    }
    if (lowerRule.startsWith("/")) {
      try {
        const parsed = new URL(normalizedUrl)
        return parsed.pathname.toLowerCase().startsWith(lowerRule)
      } catch {
        return false
      }
    }
  }
  return matchesDomainRule(host, cleanRule)
}

function matchesUrlRegexRule(normalizedUrl: string | undefined, host: string, rawRegex: string): boolean {
  const pattern = rawRegex.trim()
  if (!pattern || pattern.length > 256) return false
  try {
    const rx = new RegExp(pattern, "i")
    return rx.test(normalizedUrl ?? host)
  } catch {
    return false
  }
}

function matchesNetworkRule(rawTarget: string, rule: ScopeTargetRule): boolean {
  const { host, origin, normalizedUrl } = normalizeHostFromTarget(rawTarget)
  switch (rule.kind) {
    case "ip":
      return host === rule.value.trim().toLowerCase()
    case "cidr":
      return net.isIP(host) === 4 && isIpInCidr(host, rule.value)
    case "domain":
      return matchesDomainRule(host, rule.value)
    case "url_origin":
      return origin !== undefined && origin === rule.value.trim().toLowerCase().replace(/\/$/, "")
    case "url_prefix":
      return matchesUrlPrefixRule(normalizedUrl, host, rule.value)
    case "url_regex":
      return matchesUrlRegexRule(normalizedUrl, host, rule.value)
    case "workspace_path":
      return false
  }
}

const externalAuthorizedRootsByWorkspace = new Map<
  string,
  { allowedRoots: string[]; blockedRoots: string[] }
>()

function isDirectPathInsideRoot(candidatePath: string, rootDir: string): boolean {
  if (candidatePath.includes("\0")) return false
  const resolvedRoot = path.resolve(rootDir)
  const resolvedCandidate = path.resolve(resolvedRoot, candidatePath)
  const relative = path.relative(resolvedRoot, resolvedCandidate)
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

export function isPathInsideRoot(candidatePath: string, workspaceRoot: string): boolean {
  if (candidatePath.includes("\0")) return false
  const resolvedWorkspace = path.resolve(workspaceRoot)
  const resolvedCandidate = path.resolve(resolvedWorkspace, candidatePath)

  const extra = externalAuthorizedRootsByWorkspace.get(resolvedWorkspace)
  if (extra && extra.blockedRoots.some((b) => isDirectPathInsideRoot(resolvedCandidate, b))) {
    return false
  }
  if (isDirectPathInsideRoot(candidatePath, resolvedWorkspace)) {
    return true
  }
  if (extra && extra.allowedRoots.some((a) => isDirectPathInsideRoot(resolvedCandidate, a))) {
    return true
  }
  return false
}

export function extractTargetsFromInput(input: unknown): ExtractedTargets {
  const networkTargets: string[] = []
  const workspacePaths: string[] = []

  if (!input || typeof input !== "object") {
    return { networkTargets, workspacePaths }
  }

  const record = input as Record<string, unknown>
  const networkKeys = [
    "target",
    "url",
    "targetUrl",
    "baseUrl",
    "baselineUrl",
    "host",
    "ip",
    "endpoint",
    "origin",
    "graphqlUrl",
    "issuerUrl",
    "authorizeUrl",
    "ntlmHttpUrl",
    "specUrl",
  ]
  const networkArrayKeys = ["targets", "urls", "hosts"]
  const pathKeys = [
    "path",
    "subpath",
    "file",
    "filePath",
    "directory",
    "targetPath",
    "pcapPath",
    "binaryPath",
    "artifactPath",
    "wordlistPath",
    "rulesPath",
    "outputSubdir",
    "specPath",
    "logPath",
    "sigmaRulesPath",
    "iacPath",
    "lockfilePath",
  ]
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

function classifyAssetIdentifierToRule(rawIdentifier: string, notes?: string): ScopeTargetRule | null {
  const clean = rawIdentifier.trim()
  if (!clean) return null

  // CIDR check
  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(clean)) {
    return { kind: "cidr", value: clean, ...(notes ? { notes } : {}) }
  }
  // Exact IPv4 / IPv6
  if (net.isIP(clean) !== 0) {
    return { kind: "ip", value: clean, ...(notes ? { notes } : {}) }
  }
  // Wildcard URL like https://*.example.com or http://*.example.com/*
  const wildcardUrlMatch = /^https?:\/\/(\*\.[a-z0-9.-]+)(?:\/.*)?$/i.exec(clean)
  if (wildcardUrlMatch?.[1]) {
    return { kind: "domain", value: wildcardUrlMatch[1].toLowerCase(), ...(notes ? { notes } : {}) }
  }
  // Full URL
  if (/^https?:\/\//i.test(clean)) {
    try {
      const parsed = new URL(clean.replace(/\*+$/, ""))
      const hasSubPath = (parsed.pathname && parsed.pathname !== "/") || Boolean(parsed.search)
      if (hasSubPath || clean.endsWith("*")) {
        return {
          kind: "url_prefix",
          value: clean.replace(/\*+$/, ""),
          ...(notes ? { notes } : {}),
        }
      }
      return {
        kind: "domain",
        value: parsed.hostname.toLowerCase(),
        ...(notes ? { notes } : {}),
      }
    } catch {
      return null
    }
  }
  // Regex indicator
  if (clean.startsWith("^") || clean.endsWith("$")) {
    return { kind: "url_regex", value: clean, ...(notes ? { notes } : {}) }
  }
  // Domain or *.wildcard.domain (strip trailing /* if present)
  const dom = clean.replace(/\/\*.*$/, "").toLowerCase()
  if (/^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(dom) || dom === "localhost") {
    return { kind: "domain", value: dom, ...(notes ? { notes } : {}) }
  }
  return null
}

function dedupeRules(rules: ScopeTargetRule[]): ScopeTargetRule[] {
  const seen = new Set<string>()
  const out: ScopeTargetRule[] = []
  for (const r of rules) {
    const key = `${r.kind}:${r.value.toLowerCase()}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(r)
  }
  return out
}

function buildPlatformHeaders(platform: BugBountyPlatform, handle?: string): EngagementHeaderRule[] {
  const cleanHandle = (handle ?? "").trim()
  if (!cleanHandle) return []
  switch (platform) {
    case "hackerone":
      return [{ name: "X-Bug-Bounty", value: `HackerOne-${cleanHandle}`, enabled: true }]
    case "bugcrowd":
      return [{ name: "X-Bug-Bounty", value: `Bugcrowd-${cleanHandle}`, enabled: true }]
    case "intigriti":
      return [{ name: "X-Bug-Bounty", value: `Intigriti-${cleanHandle}`, enabled: true }]
    case "yeswehack":
      return [{ name: "X-Bug-Bounty", value: `YesWeHack-${cleanHandle}`, enabled: true }]
    case "custom":
      return [{ name: "X-Researcher", value: cleanHandle, enabled: true }]
  }
}

/**
 * Imports authorized target scope from:
 * 1) HackerOne program JSON (`relationships.structured_scopes.data` or `structured_scopes`)
 * 2) Bugcrowd / Intigriti target JSON (`targets.in_scope` / `targets.out_of_scope` / `inScope` / `outOfScope`)
 * 3) Plaintext / Wildcard / Markdown lines (`*.example.com`, `!admin.example.com`, `-https://example.com/logout`)
 */
export function parseBugBountyScopeImport(
  rawInput: string,
  options?: {
    platform?: BugBountyPlatform
    programName?: string
    researcherHandle?: string
    maxRequestsPerSecond?: number
  },
): ImportedScopeBundle {
  const trimmed = rawInput.trim()
  if (!trimmed) {
    throw new Error("Empty scope import payload")
  }

  const allowed: ScopeTargetRule[] = []
  const blocked: ScopeTargetRule[] = [
    { kind: "workspace_path", value: ".git", notes: "Protect repository VCS metadata" },
  ]
  let detectedFormat: ImportedScopeBundle["detectedFormat"] = "plaintext_rules"
  let inferredPlatform: BugBountyPlatform = options?.platform ?? "custom"
  let inferredProgramName = options?.programName?.trim()

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    let parsedJson: unknown
    try {
      parsedJson = JSON.parse(trimmed)
    } catch (err) {
      throw new Error(`Invalid JSON in scope import: ${err instanceof Error ? err.message : String(err)}`)
    }

    const rootObj =
      parsedJson && typeof parsedJson === "object" && !Array.isArray(parsedJson)
        ? (parsedJson as Record<string, unknown>)
        : undefined
    const attrs =
      rootObj?.attributes && typeof rootObj.attributes === "object"
        ? (rootObj.attributes as Record<string, unknown>)
        : rootObj

    if (!inferredProgramName && attrs) {
      const candidateName = attrs.name ?? attrs.handle ?? rootObj?.name ?? rootObj?.handle
      if (typeof candidateName === "string" && candidateName.trim()) {
        inferredProgramName = candidateName.trim()
      }
    }

    // Check HackerOne structured_scopes format
    const attrObj = rootObj?.attributes as Record<string, unknown> | undefined
    const dataObj = rootObj?.data as Record<string, unknown> | undefined
    const relScopes = (
      (rootObj?.relationships as Record<string, unknown> | undefined)?.structured_scopes ??
      (attrObj?.relationships as Record<string, unknown> | undefined)?.structured_scopes ??
      (dataObj?.relationships as Record<string, unknown> | undefined)?.structured_scopes
    ) as Record<string, unknown> | undefined
    const h1Array = Array.isArray(parsedJson)
      ? parsedJson
      : Array.isArray(relScopes?.data)
        ? (relScopes.data as unknown[])
        : Array.isArray(rootObj?.structured_scopes)
          ? (rootObj.structured_scopes as unknown[])
          : Array.isArray(attrObj?.structured_scopes)
            ? (attrObj.structured_scopes as unknown[])
            : Array.isArray(dataObj?.structured_scopes)
              ? (dataObj.structured_scopes as unknown[])
              : undefined

    if (
      h1Array &&
      h1Array.some((item) => {
        if (!item || typeof item !== "object") return false
        const o = item as Record<string, unknown>
        const a = (o.attributes && typeof o.attributes === "object" ? o.attributes : o) as Record<string, unknown>
        return typeof a.asset_identifier === "string"
      })
    ) {
      detectedFormat = "hackerone_json"
      if (inferredPlatform === "custom") inferredPlatform = "hackerone"

      for (const entry of h1Array) {
        if (!entry || typeof entry !== "object") continue
        const obj = entry as Record<string, unknown>
        const a = (obj.attributes && typeof obj.attributes === "object" ? obj.attributes : obj) as Record<
          string,
          unknown
        >
        const identifier = typeof a.asset_identifier === "string" ? a.asset_identifier : ""
        const assetType = typeof a.asset_type === "string" ? a.asset_type.toUpperCase() : "URL"
        if (
          assetType &&
          !["URL", "WILDCARD", "DOMAIN", "CIDR", "IP_ADDRESS", "API", "OTHER"].includes(assetType)
        ) {
          continue
        }
        const eligible = a.eligible_for_submission !== false && a.in_scope !== false
        const noteText =
          typeof a.instruction === "string" && a.instruction.trim()
            ? a.instruction.trim().slice(0, 120)
            : `HackerOne ${assetType}`
        const rule = classifyAssetIdentifierToRule(identifier, noteText)
        if (!rule) continue
        if (eligible) {
          allowed.push(rule)
        } else {
          blocked.push({ ...rule, notes: `Out-of-Scope (${noteText})` })
        }
      }
    } else if (rootObj) {
      // Check Bugcrowd / Intigriti / generic { targets: { in_scope: [...], out_of_scope: [...] } }
      detectedFormat = "bugcrowd_json"
      if (inferredPlatform === "custom") inferredPlatform = "bugcrowd"
      const targetsContainer =
        rootObj.targets && typeof rootObj.targets === "object"
          ? (rootObj.targets as Record<string, unknown>)
          : rootObj

      const inList = (
        Array.isArray(targetsContainer.in_scope)
          ? targetsContainer.in_scope
          : Array.isArray(targetsContainer.inScope)
            ? targetsContainer.inScope
            : []
      ) as unknown[]
      const outList = (
        Array.isArray(targetsContainer.out_of_scope)
          ? targetsContainer.out_of_scope
          : Array.isArray(targetsContainer.outOfScope)
            ? targetsContainer.outOfScope
            : []
      ) as unknown[]

      const extractTargetStrings = (arr: unknown[], label: string, dest: ScopeTargetRule[]) => {
        for (const item of arr) {
          if (typeof item === "string") {
            const r = classifyAssetIdentifierToRule(item, label)
            if (r) dest.push(r)
            continue
          }
          if (!item || typeof item !== "object") continue
          const o = item as Record<string, unknown>
          const nestedTargets = Array.isArray(o.targets) ? (o.targets as unknown[]) : [o]
          for (const sub of nestedTargets) {
            if (!sub || typeof sub !== "object") continue
            const s = sub as Record<string, unknown>
            const uri =
              (typeof s.uri === "string" && s.uri) ||
              (typeof s.endpoint === "string" && s.endpoint) ||
              (typeof s.name === "string" && s.name) ||
              (typeof s.target === "string" && s.target) ||
              ""
            const r = classifyAssetIdentifierToRule(uri, label)
            if (r) dest.push(r)
          }
        }
      }

      extractTargetStrings(inList, "In-Scope Target", allowed)
      extractTargetStrings(outList, "Out-of-Scope Exclusion", blocked)
    }
  } else {
    // Plaintext / Markdown lines
    const lines = trimmed.split(/\r?\n/)
    for (const rawLine of lines) {
      let line = rawLine.trim()
      if (!line || line.startsWith("#") || line.startsWith("//")) continue
      line = line.replace(/^[-*]\s+\[[xX ]\]\s*/, "").replace(/^\*\s+/, "")
      let isExcluded = false
      if (line.startsWith("!") || line.startsWith("-") || /^out[-_ ]?of[-_ ]?scope\s*:/i.test(line)) {
        isExcluded = true
        line = line.replace(/^[!-]\s*/, "").replace(/^out[-_ ]?of[-_ ]?scope\s*:\s*/i, "").trim()
      } else if (/^in[-_ ]?scope\s*:/i.test(line)) {
        line = line.replace(/^in[-_ ]?scope\s*:\s*/i, "").trim()
      }
      const token = line.split(/\s+/)[0] ?? ""
      const rule = classifyAssetIdentifierToRule(
        token,
        isExcluded ? "Out-of-Scope Exclusion" : "Authorized Scope Target",
      )
      if (!rule) continue
      if (isExcluded) {
        blocked.push(rule)
      } else {
        allowed.push(rule)
      }
    }
  }

  // Always keep localhost available for local testing alongside production scope
  allowed.push(
    { kind: "ip", value: "127.0.0.1", notes: "Localhost IPv4 loopback" },
    { kind: "domain", value: "localhost", notes: "Localhost loopback hostname" },
  )

  const rps = Math.max(1, Math.min(100, Math.round(options?.maxRequestsPerSecond ?? 5)))
  const researcherHandle = options?.researcherHandle?.trim()

  return {
    detectedFormat,
    ...(inferredProgramName ? { programName: inferredProgramName } : {}),
    allowedTargets: dedupeRules(allowed),
    blockedTargets: dedupeRules(blocked),
    allowExternalTargets: true,
    engagement: {
      mode: inferredPlatform === "custom" ? "authorized_pentest" : "bug_bounty",
      platform: inferredPlatform,
      ...(inferredProgramName ? { programName: inferredProgramName } : {}),
      ...(researcherHandle ? { researcherHandle } : {}),
      ...(researcherHandle
        ? {
            customUserAgent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberLabOS/4.0 (${inferredPlatform}:${researcherHandle})`,
          }
        : {}),
      customHeaders: buildPlatformHeaders(inferredPlatform, researcherHandle),
      maxRequestsPerSecond: rps,
    },
  }
}

export class ScopeController {
  private readonly scopesByProject = new Map<string, ProjectScope>()

  setProjectScope(scope: ProjectScope): ProjectScope {
    const validated = validateProjectScope(scope)
    this.scopesByProject.set(validated.projectId, validated)
    const wsKey = path.resolve(validated.workspaceRoot)
    const allowedRoots = validated.allowedTargets
      .filter((r) => r.kind === "workspace_path")
      .map((r) => path.resolve(wsKey, r.value))
    const blockedRoots = validated.blockedTargets
      .filter((r) => r.kind === "workspace_path")
      .map((r) => path.resolve(wsKey, r.value))
    externalAuthorizedRootsByWorkspace.set(wsKey, { allowedRoots, blockedRoots })
    return validated
  }

  getProjectScope(projectId: string): ProjectScope | undefined {
    const scope = this.scopesByProject.get(projectId)
    if (!scope) return undefined
    return {
      ...scope,
      allowedTargets: scope.allowedTargets.map((r) => ({ ...r })),
      blockedTargets: scope.blockedTargets.map((r) => ({ ...r })),
      ...(scope.engagement
        ? {
            engagement: {
              ...scope.engagement,
              customHeaders: scope.engagement.customHeaders.map((h) => ({ ...h })),
            },
          }
        : {}),
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
      (requiredScopeKinds?.some(
        (k) =>
          k === "network" ||
          k === "cidr" ||
          k === "ip" ||
          k === "domain" ||
          k === "url_origin" ||
          k === "url_prefix" ||
          k === "url_regex",
      ) ??
        false)

    if (needsNetwork && targets.networkTargets.length === 0) {
      return {
        allowed: false,
        reason: "Capability requires an explicit network target within scope, but none was provided",
      }
    }

    // 1. Validate workspace paths against workspaceRoot OR explicitly authorized external workspace_path rules
    const allowedExternalRoots = scope.allowedTargets
      .filter((r) => r.kind === "workspace_path")
      .map((r) => path.resolve(scope.workspaceRoot, r.value))

    for (const candidatePath of targets.workspacePaths) {
      const inMainWorkspace = isDirectPathInsideRoot(candidatePath, scope.workspaceRoot)
      const resolvedCandidate = path.resolve(scope.workspaceRoot, candidatePath)
      const inAuthorizedExternalDir = allowedExternalRoots.some((extRoot) =>
        isDirectPathInsideRoot(resolvedCandidate, extRoot),
      )

      if (!inMainWorkspace && !inAuthorizedExternalDir) {
        return {
          allowed: false,
          reason: `Path "${candidatePath}" escapes project workspaceRoot "${scope.workspaceRoot}" (import the file into Workspace or add an authorized workspace_path rule in Scope)`,
          violatedTarget: candidatePath,
        }
      }

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

      // Block cloud metadata SSRF vector unconditionally
      if (isCloudMetadataIp(host) || host === "metadata.google.internal") {
        return {
          allowed: false,
          reason: `Target "${rawTarget}" resolves to cloud metadata IP 169.254.169.254 and is blocked`,
          violatedTarget: rawTarget,
        }
      }

      // Explicit Out-of-Scope blocklist ALWAYS wins (e.g., billing.example.com or /logout)
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
            reason: `External/public IP target "${rawTarget}" is prohibited because scope.allowExternalTargets is false (enable External / Bug Bounty mode in Scope)`,
            violatedTarget: rawTarget,
          }
        }
        if (
          ipVersion === 0 &&
          host !== "localhost" &&
          !host.endsWith(".local") &&
          !host.endsWith(".internal") &&
          !host.endsWith(".lab")
        ) {
          return {
            allowed: false,
            reason: `External hostname "${rawTarget}" is prohibited because scope.allowExternalTargets is false (enable External / Bug Bounty mode in Scope)`,
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
