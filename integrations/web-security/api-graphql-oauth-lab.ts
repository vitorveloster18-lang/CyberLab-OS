import { existsSync, lstatSync, readFileSync } from "node:fs"
import path from "node:path"
import { Schema } from "effect"
import {
  EngagementRuntime,
  isPathInsideRoot,
  normalizeRawOutputDraft,
  redactSensitiveContent,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const API_SECURITY_LAB_INPUT_SCHEMA_ID = "cyberlab.api-graphql-oauth.input.v1"
export const API_SECURITY_LAB_OUTPUT_SCHEMA_ID = "cyberlab.api-graphql-oauth.output.v1"

export const ApiGraphqlOauthInputSchema = Schema.Struct({
  baseUrl: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2048))),
  specPath: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512))),
  specJsonText: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(262_144))),
  customEndpoints: Schema.optionalKey(
    Schema.Array(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512))).check(Schema.isMaxLength(40)),
  ),
  authHeaderA: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(4096))),
  authHeaderB: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(4096))),
  testUnauthenticated: Schema.optionalKey(Schema.Boolean),
  graphqlUrl: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2048))),
  checkGraphqlIntrospection: Schema.optionalKey(Schema.Boolean),
  checkGraphqlBatchingAndDepth: Schema.optionalKey(Schema.Boolean),
  issuerUrl: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2048))),
  authorizeUrl: Schema.optionalKey(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2048))),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(500), Schema.isLessThanOrEqualTo(15_000)),
  ),
})

export type ApiGraphqlOauthInput = typeof ApiGraphqlOauthInputSchema.Type

export const ApiGraphqlOauthCapability: CapabilityDefinition = {
  id: "web-assessment.api-graphql-oauth-lab",
  version: "1.0.0",
  title: "API (OpenAPI/Postman BOLA Matrix), GraphQL & OAuth2/OIDC Security Lab",
  description:
    "Imports OpenAPI/Swagger or Postman Collection specs to evaluate BOLA/IDOR differential access control across User A vs User B / unauthenticated profiles, audits GraphQL introspection/batching/field-suggestions, and inspects OAuth2/OIDC PKCE, state, and redirect_uri posture.",
  inputSchemaId: API_SECURITY_LAB_INPUT_SCHEMA_ID,
  outputSchemaId: API_SECURITY_LAB_OUTPUT_SCHEMA_ID,
  risk: "moderate",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-active"],
  requiredScope: [],
  executorId: "api-graphql-oauth-lab-executor",
  skillIds: ["web-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

interface DiscoveredApiEndpoint {
  method: string
  pathTemplate: string
  concretePath: string
  source: "openapi" | "postman" | "manual"
}

function materializePathTemplate(rawPath: string): string {
  // Replace OpenAPI {id} or Postman :id placeholders with safe probe identifier "1"
  return rawPath
    .replace(/\{[^}/]+\}/g, "1")
    .replace(/\/:([a-zA-Z0-9_]+)(?=\/|$)/g, "/1")
}

export function extractEndpointsFromSpecObject(spec: unknown): DiscoveredApiEndpoint[] {
  const endpoints: DiscoveredApiEndpoint[] = []
  if (!spec || typeof spec !== "object") return endpoints
  const obj = spec as Record<string, unknown>

  // 1. OpenAPI 3.x / Swagger 2.0 `paths`
  if (obj.paths && typeof obj.paths === "object") {
    for (const [routePath, methodsObj] of Object.entries(obj.paths as Record<string, unknown>)) {
      if (!methodsObj || typeof methodsObj !== "object") continue
      for (const methodKey of Object.keys(methodsObj as Record<string, unknown>)) {
        const upper = methodKey.toUpperCase()
        if (["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(upper)) {
          endpoints.push({
            method: upper,
            pathTemplate: routePath,
            concretePath: materializePathTemplate(routePath),
            source: "openapi",
          })
        }
      }
    }
  }

  // 2. Postman Collection v2.1 `item` tree
  const walkPostmanItems = (items: unknown[]) => {
    for (const entry of items) {
      if (!entry || typeof entry !== "object") continue
      const item = entry as Record<string, unknown>
      if (Array.isArray(item.item)) {
        walkPostmanItems(item.item)
      }
      if (item.request && typeof item.request === "object") {
        const req = item.request as Record<string, unknown>
        const method = typeof req.method === "string" ? req.method.toUpperCase() : "GET"
        let rawPath = "/"
        if (typeof req.url === "string") {
          try {
            const u = new URL(req.url.replace(/\{\{[^}]+\}\}/g, "http://placeholder.local"))
            rawPath = u.pathname + u.search
          } catch {
            rawPath = req.url.startsWith("/") ? req.url : `/${req.url}`
          }
        } else if (req.url && typeof req.url === "object") {
          const uObj = req.url as Record<string, unknown>
          if (Array.isArray(uObj.path)) {
            rawPath = "/" + uObj.path.map((p) => String(p)).join("/")
          } else if (typeof uObj.raw === "string") {
            const stripped = uObj.raw.replace(/^\{\{[^}]+\}\}/, "")
            rawPath = stripped.startsWith("/") ? stripped : `/${stripped}`
          }
        }
        endpoints.push({
          method,
          pathTemplate: rawPath,
          concretePath: materializePathTemplate(rawPath),
          source: "postman",
        })
      }
    }
  }
  if (Array.isArray(obj.item)) {
    walkPostmanItems(obj.item)
  }

  return endpoints.slice(0, 40)
}

function parseAuthHeaderPair(rawHeader?: string): Record<string, string> {
  if (!rawHeader || !rawHeader.trim()) return {}
  const trimmed = rawHeader.trim()
  const colonIdx = trimmed.indexOf(":")
  if (colonIdx > 0) {
    return {
      [trimmed.slice(0, colonIdx).trim()]: trimmed.slice(colonIdx + 1).trim(),
    }
  }
  return { Authorization: trimmed.startsWith("Bearer ") ? trimmed : `Bearer ${trimmed}` }
}

async function safeFetchProbe(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  parentSignal: AbortSignal,
  projectId?: string,
): Promise<{ status: number; bodyText: string; contentType: string }> {
  const ctrl = new AbortController()
  const onAbort = () => ctrl.abort()
  parentSignal.addEventListener("abort", onAbort, { once: true })
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    if (projectId) {
      await EngagementRuntime.acquireRateSlot(projectId)
    }
    const baseHeaders: Record<string, string> = {}
    if (init.headers && typeof init.headers === "object" && !Array.isArray(init.headers)) {
      for (const [k, v] of Object.entries(init.headers as Record<string, string>)) {
        if (v !== undefined) baseHeaders[k] = v
      }
    }
    const finalHeaders = projectId ? EngagementRuntime.applyHeaders(projectId, baseHeaders) : baseHeaders
    const t0 = Date.now()
    const res = await fetch(url, { ...init, headers: finalHeaders, redirect: "manual", signal: ctrl.signal })
    const buf = Buffer.from(await res.arrayBuffer())
    if (projectId) {
      const parsed = new URL(url)
      EngagementRuntime.recordTraffic({
        projectId,
        sourceTool: "api-graphql-oauth",
        method: (init.method ?? "GET").toUpperCase(),
        url,
        host: parsed.host,
        statusCode: res.status,
        elapsedMs: Date.now() - t0,
        responseBytes: buf.byteLength,
      })
    }
    return {
      status: res.status,
      bodyText: buf.subarray(0, 32_768).toString("utf8"),
      contentType: res.headers.get("content-type") ?? "",
    }
  } finally {
    clearTimeout(timer)
    parentSignal.removeEventListener("abort", onAbort)
  }
}

export class ApiGraphqlOauthLabExecutor implements CyberLabExecutor {
  readonly id = "api-graphql-oauth-lab-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      const parsed = Schema.decodeUnknownSync(ApiGraphqlOauthInputSchema)(input)
      if (!parsed.baseUrl && !parsed.graphqlUrl && !parsed.issuerUrl && !parsed.authorizeUrl) {
        return {
          valid: false,
          errors: ["Informe ao menos baseUrl (API BOLA), graphqlUrl (GraphQL) ou issuerUrl/authorizeUrl (OAuth2/OIDC)."],
        }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(ApiGraphqlOauthInputSchema)(req.input)
    const timeoutMs = parsed.timeoutMs ?? 6_000
    const findings: Array<{ category: string; severityHint: "high" | "medium" | "low" | "info"; detail: string }> = []

    // 1. OpenAPI / Postman BOLA & Differential Access Control Matrix
    const bolaRows: Array<{
      method: string
      endpoint: string
      userAStatus: number
      userABytes: number
      userBStatus: number | null
      userBBytes: number | null
      unauthStatus: number | null
      bolaSuspected: boolean
      note: string
    }> = []

    if (parsed.baseUrl) {
      const baseOrigin = new URL(parsed.baseUrl)
      const discovered: DiscoveredApiEndpoint[] = []

      if (parsed.specPath) {
        const resolved = path.resolve(ctx.workspaceRoot, parsed.specPath)
        if (!isPathInsideRoot(resolved, ctx.workspaceRoot) || !existsSync(resolved) || lstatSync(resolved).isSymbolicLink()) {
          return {
            status: "failed",
            evidenceIds: [],
            summary: `Arquivo de especificação inválido ou fora do workspace: ${parsed.specPath}`,
            exitCode: 2,
          }
        }
        const rawSpec = readFileSync(resolved, "utf8")
        discovered.push(...extractEndpointsFromSpecObject(JSON.parse(rawSpec)))
      } else if (parsed.specJsonText && parsed.specJsonText.trim()) {
        discovered.push(...extractEndpointsFromSpecObject(JSON.parse(parsed.specJsonText)))
      }

      for (const ep of parsed.customEndpoints ?? []) {
        const clean = ep.trim()
        if (!clean) continue
        const parts = clean.split(/\s+/)
        const hasVerb = parts.length >= 2 && /^[A-Z]+$/.test(parts[0]!)
        const method = hasVerb ? parts[0]! : "GET"
        const route = hasVerb ? parts.slice(1).join(" ") : clean
        discovered.push({
          method,
          pathTemplate: route,
          concretePath: materializePathTemplate(route),
          source: "manual",
        })
      }

      if (discovered.length === 0) {
        discovered.push({
          method: "GET",
          pathTemplate: baseOrigin.pathname || "/",
          concretePath: baseOrigin.pathname + baseOrigin.search,
          source: "manual",
        })
      }

      // Only execute non-destructive read probes automatically (GET/HEAD/OPTIONS) to protect target state
      const safeEndpoints = discovered.filter((d) => ["GET", "HEAD", "OPTIONS"].includes(d.method)).slice(0, 25)
      const headersA = parseAuthHeaderPair(parsed.authHeaderA)
      const headersB = parseAuthHeaderPair(parsed.authHeaderB)
      const hasUserB = Object.keys(headersB).length > 0
      const checkUnauth = parsed.testUnauthenticated ?? true

      for (const ep of safeEndpoints) {
        if (ctx.signal.aborted) break
        const targetUrl = new URL(ep.concretePath, baseOrigin.origin)
        if (targetUrl.origin !== baseOrigin.origin) continue

        const resA = await safeFetchProbe(targetUrl.toString(), { method: ep.method, headers: headersA }, timeoutMs, ctx.signal, ctx.projectId)
        const resB = hasUserB
          ? await safeFetchProbe(targetUrl.toString(), { method: ep.method, headers: headersB }, timeoutMs, ctx.signal, ctx.projectId)
          : null
        const resUnauth = checkUnauth
          ? await safeFetchProbe(targetUrl.toString(), { method: ep.method }, timeoutMs, ctx.signal, ctx.projectId)
          : null

        let bolaSuspected = false
        const notes: string[] = []

        if (resA.status >= 200 && resA.status < 300 && resA.bodyText.length > 2) {
          if (resB && resB.status === resA.status && Math.abs(resB.bodyText.length - resA.bodyText.length) <= Math.max(16, resA.bodyText.length * 0.1)) {
            bolaSuspected = true
            notes.push("Perfil B recebeu HTTP 2xx equivalente ao Perfil A (revisar isolamento BOLA/IDOR por objeto)")
          }
          if (
            resUnauth &&
            Object.keys(headersA).length > 0 &&
            resUnauth.status === resA.status &&
            Math.abs(resUnauth.bodyText.length - resA.bodyText.length) <= Math.max(16, resA.bodyText.length * 0.1)
          ) {
            bolaSuspected = true
            notes.push("Requisição sem credenciais retornou payload equivalente ao autenticado")
          }
        }

        if (bolaSuspected) {
          findings.push({
            category: "BOLA_OR_MISSING_AUTH_CANDIDATE",
            severityHint: "high",
            detail: `${ep.method} ${ep.concretePath}: ${notes.join("; ")}`,
          })
        }

        bolaRows.push({
          method: ep.method,
          endpoint: ep.concretePath,
          userAStatus: resA.status,
          userABytes: resA.bodyText.length,
          userBStatus: resB ? resB.status : null,
          userBBytes: resB ? resB.bodyText.length : null,
          unauthStatus: resUnauth ? resUnauth.status : null,
          bolaSuspected,
          note: notes.join("; ") || "Controle de acesso consistente ou endpoint público esperado",
        })
      }
    }

    // 2. GraphQL Security Posture Audit
    let graphqlReport: Record<string, unknown> | null = null
    if (parsed.graphqlUrl) {
      const gqlTarget = new URL(parsed.graphqlUrl).toString()
      const gqlHeaders = {
        "Content-Type": "application/json",
        ...parseAuthHeaderPair(parsed.authHeaderA),
      }
      let introspectionEnabled = false
      let discoveredTypesCount = 0
      let batchingAccepted = false
      let fieldSuggestionsExposed = false

      if (parsed.checkGraphqlIntrospection ?? true) {
        const introRes = await safeFetchProbe(
          gqlTarget,
          {
            method: "POST",
            headers: gqlHeaders,
            body: JSON.stringify({ query: "query CyberLabIntrospection { __schema { queryType { name } types { name kind } } }" }),
          },
          timeoutMs,
          ctx.signal,
          ctx.projectId,
        )
        if (introRes.status === 200 && introRes.bodyText.includes('"__schema"')) {
          introspectionEnabled = true
          try {
            const j = JSON.parse(introRes.bodyText) as { data?: { __schema?: { types?: unknown[] } } }
            discoveredTypesCount = j.data?.__schema?.types?.length ?? 0
          } catch {
            // ignore JSON parse errors
          }
          findings.push({
            category: "GRAPHQL_INTROSPECTION_ENABLED",
            severityHint: "medium",
            detail: `Introspecção GraphQL (__schema) habilitada em ${gqlTarget} (${discoveredTypesCount} tipos expostos).`,
          })
        }
      }

      if (parsed.checkGraphqlBatchingAndDepth ?? true) {
        // Bounded 2-query array batching check (strictly non-destructive)
        const batchRes = await safeFetchProbe(
          gqlTarget,
          {
            method: "POST",
            headers: gqlHeaders,
            body: JSON.stringify([{ query: "{ __typename }" }, { query: "{ __typename }" }]),
          },
          timeoutMs,
          ctx.signal,
          ctx.projectId,
        )
        if (batchRes.status === 200 && batchRes.bodyText.trim().startsWith("[")) {
          batchingAccepted = true
          findings.push({
            category: "GRAPHQL_ARRAY_BATCHING_ALLOWED",
            severityHint: "low",
            detail: `Endpoint GraphQL aceita batching de arrays JSON ([{query},{query}]) — validar rate-limit por operação para evitar bypass de brute-force.`,
          })
        }

        // Field suggestion leakage check
        const typoRes = await safeFetchProbe(
          gqlTarget,
          {
            method: "POST",
            headers: gqlHeaders,
            body: JSON.stringify({ query: "{ __typenam }" }),
          },
          timeoutMs,
          ctx.signal,
          ctx.projectId,
        )
        if (/did you mean/i.test(typoRes.bodyText)) {
          fieldSuggestionsExposed = true
          findings.push({
            category: "GRAPHQL_FIELD_SUGGESTIONS",
            severityHint: "info",
            detail: "Servidor GraphQL retorna dicas 'Did you mean...?' em campos inválidos, permitindo enumeração de schema mesmo sem introspecção.",
          })
        }
      }

      graphqlReport = {
        graphqlUrl: gqlTarget,
        introspectionEnabled,
        discoveredTypesCount,
        batchingAccepted,
        fieldSuggestionsExposed,
      }
    }

    // 3. OAuth2 / OIDC Configuration & Authorization URL Hygiene
    let oauthReport: Record<string, unknown> | null = null
    if (parsed.issuerUrl || parsed.authorizeUrl) {
      const oauthIssues: string[] = []
      let oidcMetadata: Record<string, unknown> | null = null

      if (parsed.issuerUrl) {
        const baseIssuer = parsed.issuerUrl.replace(/\/+$/, "")
        const wellKnownUrl = baseIssuer.endsWith("openid-configuration")
          ? baseIssuer
          : `${baseIssuer}/.well-known/openid-configuration`
        const wkRes = await safeFetchProbe(wellKnownUrl, { method: "GET" }, timeoutMs, ctx.signal, ctx.projectId)
        if (wkRes.status === 200) {
          try {
            const meta = JSON.parse(wkRes.bodyText) as Record<string, unknown>
            oidcMetadata = {
              issuer: meta.issuer,
              authorization_endpoint: meta.authorization_endpoint,
              token_endpoint: meta.token_endpoint,
              response_types_supported: meta.response_types_supported,
              code_challenge_methods_supported: meta.code_challenge_methods_supported,
              token_endpoint_auth_methods_supported: meta.token_endpoint_auth_methods_supported,
            }
            const respTypes = Array.isArray(meta.response_types_supported) ? meta.response_types_supported.map(String) : []
            if (respTypes.some((r) => r.includes("token") && !r.includes("code"))) {
              oauthIssues.push("Implicit Flow legado ('token') anunciado em response_types_supported")
            }
            const pkceMethods = Array.isArray(meta.code_challenge_methods_supported)
              ? meta.code_challenge_methods_supported.map(String)
              : []
            if (!pkceMethods.includes("S256")) {
              oauthIssues.push("PKCE S256 ausente em code_challenge_methods_supported")
            }
            if (pkceMethods.includes("plain")) {
              oauthIssues.push("Método PKCE 'plain' habilitado — recomenda-se restringir apenas a 'S256'")
            }
          } catch {
            oauthIssues.push("Resposta /.well-known/openid-configuration não é JSON válido")
          }
        }
      }

      if (parsed.authorizeUrl) {
        const authU = new URL(parsed.authorizeUrl)
        if (authU.protocol === "http:" && authU.hostname !== "127.0.0.1" && authU.hostname !== "localhost") {
          oauthIssues.push("URL de autorização utiliza HTTP sem TLS fora de loopback")
        }
        if (!authU.searchParams.get("state")) {
          oauthIssues.push("Parâmetro anti-CSRF 'state' ausente na URL de autorização OAuth2")
        }
        const ccm = authU.searchParams.get("code_challenge_method")
        if (!authU.searchParams.get("code_challenge")) {
          oauthIssues.push("PKCE 'code_challenge' ausente no fluxo de autorização")
        } else if (ccm && ccm.toLowerCase() === "plain") {
          oauthIssues.push("PKCE configurado como 'plain' em vez de 'S256'")
        }
        const redir = authU.searchParams.get("redirect_uri")
        if (redir && (redir.includes("*") || redir.startsWith("http://") && !redir.includes("127.0.0.1") && !redir.includes("localhost"))) {
          oauthIssues.push(`redirect_uri potencialmente inseguro detectado: ${redir}`)
        }
      }

      for (const issue of oauthIssues) {
        findings.push({
          category: "OAUTH2_OIDC_POSTURE",
          severityHint: issue.includes("state") || issue.includes("Implicit") ? "medium" : "low",
          detail: issue,
        })
      }

      oauthReport = {
        oidcMetadata,
        authorizeUrlChecked: parsed.authorizeUrl ?? null,
        issues: oauthIssues,
      }
    }

    const report = {
      evaluatedAt: new Date().toISOString(),
      bolaEndpointsTested: bolaRows.length,
      bolaMatrix: bolaRows,
      graphqlAudit: graphqlReport,
      oauthAudit: oauthReport,
      findingsCount: findings.length,
      findings,
    }

    const redacted = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await ctx.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "json",
        title: `API / GraphQL / OAuth2 Security Lab (${findings.length} achado(s))`,
        rawText: redacted.text,
        mediaType: "application/json",
        toolId: "cyberlab-api-security-lab",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["api-security", "bola", "graphql", "oauth2"],
      }),
      redactionApplied: true,
    })

    return {
      status: ctx.signal.aborted ? "cancelled" : "succeeded",
      evidenceIds: [evId],
      summary: `API/GraphQL/OAuth2 Lab concluído: ${bolaRows.length} endpoint(s) BOLA testados, ${findings.length} observação(ões) de postura registrada(s).`,
      exitCode: 0,
    }
  }
}
