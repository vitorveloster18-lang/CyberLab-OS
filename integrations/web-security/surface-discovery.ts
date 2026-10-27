import { Schema } from "effect"
import {
  normalizeRawOutputDraft,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const WEB_SURFACE_DISCOVERY_INPUT_SCHEMA_ID = "cyberlab.web-surface-discovery.input.v1"
export const WEB_SURFACE_DISCOVERY_OUTPUT_SCHEMA_ID = "cyberlab.web-surface-discovery.output.v1"

export const WebSurfaceDiscoveryInputSchema = Schema.Struct({
  baseUrl: Schema.String.check(
    Schema.isMinLength(8),
    Schema.isMaxLength(2048),
    Schema.isPattern(/^https?:\/\/[^\s/$.?#].[^\s]*$/i),
  ),
  customPaths: Schema.optionalKey(
    Schema.Array(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256))).check(
      Schema.isMaxLength(25),
    ),
  ),
  concurrency: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(4))),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(200), Schema.isLessThanOrEqualTo(15_000)),
  ),
})

export type WebSurfaceDiscoveryInput = typeof WebSurfaceDiscoveryInputSchema.Type

export const WebSurfaceDiscoveryCapability: CapabilityDefinition = {
  id: "web-assessment.surface-discovery",
  version: "1.0.0",
  title: "Native Web Surface & Exposure Template Scanner (Nuclei/ffuf Style)",
  description:
    "Checks an authorized in-scope HTTP/HTTPS origin against curated, false-positive-verified exposure templates (/.git/HEAD, /.env, /openapi.json, /robots.txt, /.well-known/security.txt, /actuator/health, and bounded custom paths) with strict concurrency caps.",
  inputSchemaId: WEB_SURFACE_DISCOVERY_INPUT_SCHEMA_ID,
  outputSchemaId: WEB_SURFACE_DISCOVERY_OUTPUT_SCHEMA_ID,
  risk: "low",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["url_origin"],
  executorId: "web-surface-discovery-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

interface BuiltinExposureTemplate {
  templateId: string
  path: string
  category: "vcs_exposure" | "secret_exposure" | "api_schema" | "diagnostics" | "policy_discovery"
  severityHint: "info" | "low" | "medium" | "high"
  matcher: (status: number, contentType: string, body: string) => boolean
}

const BUILTIN_TEMPLATES: readonly BuiltinExposureTemplate[] = [
  {
    templateId: "TPL-GIT-HEAD",
    path: "/.git/HEAD",
    category: "vcs_exposure",
    severityHint: "high",
    matcher: (status, _ct, body) => status === 200 && /^ref:\s+refs\/heads\//m.test(body),
  },
  {
    templateId: "TPL-DOTENV",
    path: "/.env",
    category: "secret_exposure",
    severityHint: "high",
    matcher: (status, ct, body) =>
      status === 200 &&
      !ct.includes("text/html") &&
      /^[A-Z0-9_]{3,}=[^\r\n]+$/m.test(body),
  },
  {
    templateId: "TPL-OPENAPI-JSON",
    path: "/openapi.json",
    category: "api_schema",
    severityHint: "info",
    matcher: (status, _ct, body) => status === 200 && /"(openapi|swagger)"\s*:/.test(body),
  },
  {
    templateId: "TPL-ACTUATOR-HEALTH",
    path: "/actuator/health",
    category: "diagnostics",
    severityHint: "low",
    matcher: (status, _ct, body) => status === 200 && /"status"\s*:\s*"(UP|DOWN)"/.test(body),
  },
  {
    templateId: "TPL-SECURITY-TXT",
    path: "/.well-known/security.txt",
    category: "policy_discovery",
    severityHint: "info",
    matcher: (status, _ct, body) => status === 200 && /^Contact:/im.test(body),
  },
  {
    templateId: "TPL-ROBOTS-TXT",
    path: "/robots.txt",
    category: "policy_discovery",
    severityHint: "info",
    matcher: (status, _ct, body) => status === 200 && /^(User-agent|Disallow|Allow):/im.test(body),
  },
]

export class WebSurfaceDiscoveryExecutor implements CyberLabExecutor {
  readonly id = "web-surface-discovery-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string }> {
    return { available: typeof fetch === "function", version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(WebSurfaceDiscoveryInputSchema)(input)
      const u = new URL(decoded.baseUrl)
      if (u.protocol !== "http:" && u.protocol !== "https:") {
        return { valid: false, errors: ["baseUrl must use http: or https:"] }
      }
      if (u.username || u.password) {
        return { valid: false, errors: ["Embedded credentials in baseUrl are prohibited"] }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(WebSurfaceDiscoveryInputSchema)(execInput.input)
    const originUrl = new URL(params.baseUrl)
    const concurrency = params.concurrency ?? 3
    const timeoutMs = params.timeoutMs ?? 8_000

    const abortCtrl = new AbortController()
    const timer = setTimeout(() => abortCtrl.abort("Surface discovery timeout"), timeoutMs)
    const onParentAbort = () => abortCtrl.abort("Parent execution aborted")
    ctx.signal.addEventListener("abort", onParentAbort, { once: true })

    try {
      const checks: Array<{
        templateId: string
        path: string
        severityHint: string
        matcher: (status: number, ct: string, body: string) => boolean
      }> = BUILTIN_TEMPLATES.map((t) => ({
        templateId: t.templateId,
        path: t.path,
        severityHint: t.severityHint,
        matcher: t.matcher,
      }))

      for (const rawCustom of params.customPaths ?? []) {
        const normalizedPath = rawCustom.startsWith("/") ? rawCustom : `/${rawCustom}`
        checks.push({
          templateId: `CUSTOM:${normalizedPath}`,
          path: normalizedPath,
          severityHint: "info",
          matcher: (status, ct) => status >= 200 && status < 300 && !ct.includes("text/html"),
        })
      }

      const hits: Array<{
        templateId: string
        url: string
        statusCode: number
        contentType: string
        severityHint: string
        matchedSignature: boolean
        bodyPreview: string
      }> = []

      let cursor = 0
      const workers = Array.from({ length: Math.min(concurrency, checks.length) }, async () => {
        while (cursor < checks.length && !abortCtrl.signal.aborted) {
          const item = checks[cursor++]!
          const target = new URL(item.path, originUrl.origin)
          const res = await fetch(target.toString(), {
            method: "GET",
            redirect: "manual",
            headers: { "User-Agent": "CyberLab-OS-Surface-Scanner/1.0" },
            signal: abortCtrl.signal,
          })
          const contentType = res.headers.get("content-type")?.toLowerCase() ?? ""
          const rawText = (await res.text()).slice(0, 2048)
          const matchedSignature = item.matcher(res.status, contentType, rawText)
          if (matchedSignature || (item.templateId.startsWith("CUSTOM:") && res.status !== 404)) {
            hits.push({
              templateId: item.templateId,
              url: target.toString(),
              statusCode: res.status,
              contentType,
              severityHint: item.severityHint,
              matchedSignature,
              bodyPreview: rawText.slice(0, 240),
            })
          }
        }
      })

      await Promise.all(workers)

      const report = {
        origin: originUrl.origin,
        checkedCount: checks.length,
        confirmedExposureCount: hits.filter((h) => h.matchedSignature).length,
        hits,
      }

      const evId = await ctx.emitEvidence(
        normalizeRawOutputDraft({
          kind: "json",
          title: `Web Surface Discovery (${originUrl.host}: ${report.confirmedExposureCount} verified match(es))`,
          rawText: JSON.stringify(report, null, 2),
          mediaType: "application/json",
          toolId: "cyberlab-web-surface-discovery",
          toolVersion: this.version,
          executorId: this.id,
          executionId: ctx.executionId,
          maxOutputBytes: 256 * 1024,
          labels: ["surface-discovery", "templates"],
        }),
      )

      return {
        status: "succeeded",
        evidenceIds: [evId],
        summary: `Evaluated ${checks.length} template/surface path(s) on ${originUrl.origin}; ${report.confirmedExposureCount} verified signature match(es).`,
        exitCode: 0,
      }
    } finally {
      clearTimeout(timer)
      ctx.signal.removeEventListener("abort", onParentAbort)
    }
  }
}
