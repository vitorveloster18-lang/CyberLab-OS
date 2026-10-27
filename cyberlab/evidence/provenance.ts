import type { FindingStatus, SecurityFinding } from "../contracts/evidence.js"

export type CustodyAction =
  | "collected"
  | "accessed"
  | "integrity_verified"
  | "integrity_failed"
  | "redacted_share"
  | "exported"

export interface CustodyEvent {
  eventId: string
  evidenceId: string
  projectId: string
  action: CustodyAction
  actor: string
  details?: string
  timestamp: string
}

export interface FindingRevision {
  revisionId: string
  findingId: string
  projectId: string
  previousStatus?: FindingStatus
  newStatus: FindingStatus
  changedBy: string
  notes?: string
  snapshot: SecurityFinding
  timestamp: string
}

export interface RedactionResult {
  text: string
  redacted: boolean
  matchedCategories: string[]
}

const REDACTION_PATTERNS: ReadonlyArray<{ category: string; regex: RegExp; replacement: string }> = [
  {
    category: "pem_private_key",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replacement: "[REDACTED:PRIVATE_KEY]",
  },
  {
    category: "authorization_header",
    regex: /((?:Authorization|Proxy-Authorization)\s*:\s*(?:Bearer|Basic|Token)\s+)[^\r\n"'\s]+/gi,
    replacement: "$1[REDACTED:AUTH_TOKEN]",
  },
  {
    category: "cookie_header",
    regex: /((?:Set-Cookie|Cookie)\s*:\s*)[^\r\n]+/gi,
    replacement: "$1[REDACTED:COOKIE]",
  },
  {
    category: "api_key_header",
    regex: /((?:X-Api-Key|X-Auth-Token|Api-Key)\s*:\s*)[^\r\n"'\s]+/gi,
    replacement: "$1[REDACTED:API_KEY]",
  },
  {
    category: "aws_access_key",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replacement: "[REDACTED:AWS_ACCESS_KEY]",
  },
  {
    category: "github_token",
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    replacement: "[REDACTED:GITHUB_TOKEN]",
  },
  {
    category: "jwt",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replacement: "[REDACTED:JWT]",
  },
  {
    category: "url_credentials",
    regex: /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\s/@]+:)([^@\s/]+)(@)/g,
    replacement: "$1[REDACTED:URL_SECRET]$3",
  },
  {
    category: "secret_assignment",
    regex: /((?:password|passwd|secret|client_secret|access_token|refresh_token)\s*[=:]\s*["']?)([^"'\s&;,\r\n]{4,})(["']?)/gi,
    replacement: "$1[REDACTED:SECRET]$3",
  },
]

export function redactSensitiveContent(input: string): RedactionResult {
  let current = input
  const matched = new Set<string>()

  for (const rule of REDACTION_PATTERNS) {
    const updated = current.replace(rule.regex, (...args) => {
      matched.add(rule.category)
      // Reconstruct simple group replacements
      if (rule.replacement === "[REDACTED:PRIVATE_KEY]" || rule.replacement.startsWith("[REDACTED:")) {
        return rule.replacement
      }
      if (rule.replacement === "$1[REDACTED:URL_SECRET]$3") {
        return `${args[1]}[REDACTED:URL_SECRET]${args[3]}`
      }
      if (rule.replacement === "$1[REDACTED:SECRET]$3") {
        return `${args[1]}[REDACTED:SECRET]${args[3]}`
      }
      return `${args[1]}${rule.replacement.slice(2)}`
    })
    current = updated
  }

  return {
    text: current,
    redacted: matched.size > 0,
    matchedCategories: Array.from(matched).sort(),
  }
}
