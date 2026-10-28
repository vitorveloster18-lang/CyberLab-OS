import { Resolver } from "node:dns/promises"
import net from "node:net"
import { Schema } from "effect"
import {
  normalizeRawOutputDraft,
  redactSensitiveContent,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const DNS_RECON_INPUT_SCHEMA_ID = "cyberlab.dns-recon.input.v1"
export const DNS_RECON_OUTPUT_SCHEMA_ID = "cyberlab.dns-recon.output.v1"

export const DnsReconInputSchema = Schema.Struct({
  host: Schema.String.check(
    Schema.isMinLength(1),
    Schema.isMaxLength(253),
    Schema.isPattern(/^[a-zA-Z0-9._-]+$/),
  ),
  nameserver: Schema.optionalKey(
    Schema.String.check(Schema.isMaxLength(64), Schema.isPattern(/^[a-zA-Z0-9.:_-]*$/)),
  ),
  checkEmailPosture: Schema.optionalKey(Schema.Boolean),
  enumerateSubdomains: Schema.optionalKey(Schema.Boolean),
  subdomainPrefixes: Schema.optionalKey(
    Schema.Array(
      Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(32), Schema.isPattern(/^[a-zA-Z0-9-]+$/)),
    ).check(Schema.isMaxLength(25)),
  ),
  includeCrtSh: Schema.optionalKey(Schema.Boolean),
  timeoutMs: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(500), Schema.isLessThanOrEqualTo(15_000)),
  ),
})

export type DnsReconInput = typeof DnsReconInputSchema.Type

export const DnsReconCapability: CapabilityDefinition = {
  id: "network-assessment.dns-recon",
  version: "1.0.0",
  title: "Native DNS, Subdomain Hygiene, SPF/DMARC & Certificate Transparency Auditor",
  description:
    "Queries DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA), audits SPF/DMARC email spoofing protections, checks dangling CNAME subdomain takeover indicators, and optionally queries passive Certificate Transparency logs.",
  inputSchemaId: DNS_RECON_INPUT_SCHEMA_ID,
  outputSchemaId: DNS_RECON_OUTPUT_SCHEMA_ID,
  risk: "low",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
  requiredScope: ["ip", "cidr", "domain"],
  executorId: "dns-surface-recon-executor",
  skillIds: ["network-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

const DEFAULT_SUBDOMAIN_PREFIXES = [
  "www",
  "api",
  "dev",
  "staging",
  "auth",
  "mail",
  "cdn",
  "portal",
  "admin",
  "docs",
]

const CLOUD_ALIAS_SUFFIXES = [
  ".github.io",
  ".herokuapp.com",
  ".azurewebsites.net",
  ".cloudapp.net",
  ".s3.amazonaws.com",
  ".cloudfront.net",
  ".vercel.app",
  ".netlify.app",
  ".pages.dev",
]

export class DnsSurfaceReconExecutor implements CyberLabExecutor {
  readonly id = "dns-surface-recon-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      Schema.decodeUnknownSync(DnsReconInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, context: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(DnsReconInputSchema)(req.input)
    const domain = parsed.host.trim().toLowerCase().replace(/\.$/, "")
    const timeoutMs = parsed.timeoutMs ?? 5_000
    const resolver = new Resolver({ timeout: Math.min(timeoutMs, 4_000), tries: 1 })
    if (parsed.nameserver && parsed.nameserver.trim()) {
      resolver.setServers([parsed.nameserver.trim()])
    }

    const safeResolve = async <T>(fn: () => Promise<T>, fallback: T): Promise<T> => {
      try {
        return await fn()
      } catch {
        return fallback
      }
    }

    const isIp = net.isIP(domain) !== 0
    const reversePtr = isIp ? await safeResolve(() => resolver.reverse(domain), [] as string[]) : []

    const [aRecords, aaaaRecords, cnameRecords, mxRecords, nsRecords, txtChunks, soaRecord, caaRecords] = isIp
      ? [[domain], [], [], [], [], [], null, []]
      : await Promise.all([
          safeResolve(() => resolver.resolve4(domain), [] as string[]),
          safeResolve(() => resolver.resolve6(domain), [] as string[]),
          safeResolve(() => resolver.resolveCname(domain), [] as string[]),
          safeResolve(() => resolver.resolveMx(domain), [] as Array<{ exchange: string; priority: number }>),
          safeResolve(() => resolver.resolveNs(domain), [] as string[]),
          safeResolve(() => resolver.resolveTxt(domain), [] as string[][]),
          safeResolve(() => resolver.resolveSoa(domain), null),
          safeResolve(() => resolver.resolveCaa(domain), [] as unknown[]),
        ])

    const txtRecords = txtChunks.map((parts) => parts.join(""))
    const postureFindings: Array<{ severity: "info" | "low" | "medium" | "high"; check: string; detail: string }> = []

    let dmarcRecords: string[] = []
    if (!isIp && (parsed.checkEmailPosture ?? true) && domain !== "localhost") {
      const dmarcRaw = await safeResolve(() => resolver.resolveTxt(`_dmarc.${domain}`), [] as string[][])
      dmarcRecords = dmarcRaw.map((p) => p.join(""))

      const spf = txtRecords.find((t) => /^v=spf1\b/i.test(t))
      if (!spf) {
        postureFindings.push({
          severity: mxRecords.length > 0 ? "medium" : "low",
          check: "missing_spf",
          detail: `Nenhum registro TXT SPF (v=spf1) encontrado para ${domain}.`,
        })
      } else if (/\+all\b/i.test(spf)) {
        postureFindings.push({
          severity: "high",
          check: "permissive_spf_plus_all",
          detail: `Política SPF crítica com '+all' permite envio autorizado de qualquer IP (${spf}).`,
        })
      } else if (/~all\b/i.test(spf)) {
        postureFindings.push({
          severity: "info",
          check: "spf_softfail",
          detail: `Política SPF configurada com '~all' (SoftFail): ${spf}.`,
        })
      }

      const dmarc = dmarcRecords.find((t) => /^v=DMARC1\b/i.test(t))
      if (!dmarc) {
        postureFindings.push({
          severity: mxRecords.length > 0 ? "medium" : "low",
          check: "missing_dmarc",
          detail: `Nenhum registro TXT em _dmarc.${domain} encontrado.`,
        })
      } else if (/\bp=none\b/i.test(dmarc)) {
        postureFindings.push({
          severity: "low",
          check: "dmarc_policy_none",
          detail: `DMARC em modo somente monitoramento (p=none): ${dmarc}.`,
        })
      }

      if (caaRecords.length === 0) {
        postureFindings.push({
          severity: "info",
          check: "no_caa_records",
          detail: `Sem registros DNS CAA restringindo quais Autoridades Certificadoras podem emitir certificados para ${domain}.`,
        })
      }
    }

    const discoveredSubdomains: Array<{
      fqdn: string
      ipv4: string[]
      cname: string[]
      danglingCnameSuspect: boolean
    }> = []

    if (!isIp && (parsed.enumerateSubdomains ?? false) && domain !== "localhost") {
      const prefixes = (parsed.subdomainPrefixes && parsed.subdomainPrefixes.length > 0
        ? parsed.subdomainPrefixes
        : DEFAULT_SUBDOMAIN_PREFIXES
      ).slice(0, 25)

      for (const sub of prefixes) {
        if (context.signal.aborted) break
        const fqdn = `${sub}.${domain}`
        const [subA, subCname] = await Promise.all([
          safeResolve(() => resolver.resolve4(fqdn), [] as string[]),
          safeResolve(() => resolver.resolveCname(fqdn), [] as string[]),
        ])
        if (subA.length > 0 || subCname.length > 0) {
          const pointsToCloud = subCname.some((c) =>
            CLOUD_ALIAS_SUFFIXES.some((suf) => c.toLowerCase().endsWith(suf)),
          )
          const dangling = subCname.length > 0 && subA.length === 0
          if (dangling) {
            postureFindings.push({
              severity: pointsToCloud ? "high" : "medium",
              check: "dangling_cname_hygiene",
              detail: `Subdomínio ${fqdn} possui CNAME (${subCname.join(", ")}) sem resolução A ativa — revisar risco de Subdomain Takeover.`,
            })
          }
          discoveredSubdomains.push({
            fqdn,
            ipv4: subA,
            cname: subCname,
            danglingCnameSuspect: dangling,
          })
        }
      }
    }

    let crtShNames: string[] = []
    let crtShNote: string | undefined
    if (!isIp && parsed.includeCrtSh && domain !== "localhost") {
      try {
        const ctrl = new AbortController()
        const t = setTimeout(() => ctrl.abort(), Math.min(timeoutMs, 6_000))
        try {
          const resp = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, {
            headers: { Accept: "application/json", "User-Agent": "CyberLab-OS-DNS-Auditor/1.0" },
            signal: ctrl.signal,
          })
          if (resp.ok) {
            const items = (await resp.json()) as Array<{ name_value?: string }>
            const set = new Set<string>()
            for (const row of items.slice(0, 300)) {
              for (const line of String(row.name_value ?? "").split("\n")) {
                const clean = line.trim().toLowerCase()
                if (clean && !clean.startsWith("*")) set.add(clean)
              }
            }
            crtShNames = [...set].slice(0, 60)
          } else {
            crtShNote = `crt.sh retornou HTTP ${resp.status}`
          }
        } finally {
          clearTimeout(t)
        }
      } catch (err) {
        crtShNote = `Consulta passiva crt.sh indisponível neste ambiente (${err instanceof Error ? err.message : String(err)})`
      }
    }

    const report = {
      target: domain,
      isIpAddress: isIp,
      reversePtr,
      records: {
        A: aRecords,
        AAAA: aaaaRecords,
        CNAME: cnameRecords,
        MX: mxRecords,
        NS: nsRecords,
        TXT: txtRecords,
        DMARC: dmarcRecords,
        SOA: soaRecord,
        CAA: caaRecords,
      },
      discoveredSubdomains,
      certificateTransparencyHosts: crtShNames,
      ...(crtShNote ? { crtShNote } : {}),
      postureFindings,
    }

    const redacted = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await context.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "network_observation",
        title: `DNS & Domain Surface Recon: ${domain}`,
        rawText: redacted.text,
        mediaType: "application/json",
        toolId: "cyberlab-dns-recon",
        toolVersion: this.version,
        executorId: this.id,
        executionId: context.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["dns-recon", "spf-dmarc"],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: context.signal.aborted ? "cancelled" : "succeeded",
      evidenceIds: [evId],
      summary: `DNS Recon em ${domain}: ${aRecords.length} A, ${mxRecords.length} MX, ${txtRecords.length} TXT, ${discoveredSubdomains.length} subdomínio(s), ${postureFindings.length} observação(ões) de postura.`,
      exitCode: 0,
    }
  }
}
