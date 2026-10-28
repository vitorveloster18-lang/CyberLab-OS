import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { Schema } from "effect"
import {
  isPathInsideRoot,
  normalizeRawOutputDraft,
  redactSensitiveContent,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const SCA_SBOM_IAC_INPUT_SCHEMA_ID = "cyberlab.sca-sbom-iac.input.v1"
export const SCA_SBOM_IAC_OUTPUT_SCHEMA_ID = "cyberlab.sca-sbom-iac.output.v1"

export const ScaSbomIacInputSchema = Schema.Struct({
  subpath: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  generateCycloneDxSbom: Schema.optionalKey(Schema.Boolean),
  queryOsvDev: Schema.optionalKey(Schema.Boolean),
  auditContainersAndIac: Schema.optionalKey(Schema.Boolean),
  maxFiles: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(5), Schema.isLessThanOrEqualTo(500)),
  ),
})

export type ScaSbomIacInput = typeof ScaSbomIacInputSchema.Type

export const ScaSbomIacCapability: CapabilityDefinition = {
  id: "code-analysis.sca-sbom-iac-audit",
  version: "1.0.0",
  title: "SCA Dependency Vulnerability Scanner (OSV.dev), CycloneDX SBOM & Container/IaC Auditor",
  description:
    "Parses project manifests & lockfiles (npm/bun/PyPI/Go/Cargo/Maven) to generate a CycloneDX 1.5 SBOM, queries OSV.dev for real CVEs, and statically audits Dockerfiles, docker-compose, Kubernetes manifests, and Terraform (.tf) configurations.",
  inputSchemaId: SCA_SBOM_IAC_INPUT_SCHEMA_ID,
  outputSchemaId: SCA_SBOM_IAC_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "sca-sbom-iac-auditor-executor",
  skillIds: ["code-review", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export interface DiscoveredDependency {
  ecosystem: "npm" | "PyPI" | "Go" | "crates.io" | "Maven"
  name: string
  version: string
  purl: string
  sourceFile: string
}

export interface IacMisconfiguration {
  file: string
  line: number
  kind: "dockerfile" | "docker-compose" | "kubernetes" | "terraform"
  ruleId: string
  severity: "high" | "medium" | "low"
  message: string
}

const SKIP_DIRS = new Set([".git", "node_modules", ".cyberlab", "dist", "build", ".venv", "target"])

function cleanSemver(raw: string): string {
  return raw.trim().replace(/^[~^>=<v\s]+/, "").split(/\s+/)[0] ?? ""
}

function buildPurl(eco: DiscoveredDependency["ecosystem"], name: string, version: string): string {
  const map: Record<DiscoveredDependency["ecosystem"], string> = {
    npm: "npm",
    PyPI: "pypi",
    Go: "golang",
    "crates.io": "cargo",
    Maven: "maven",
  }
  return `pkg:${map[eco]}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`
}

export function parseDependenciesFromFile(relPath: string, content: string): DiscoveredDependency[] {
  const base = path.basename(relPath)
  const deps: DiscoveredDependency[] = []
  const pushDep = (ecosystem: DiscoveredDependency["ecosystem"], name: string, rawVer: string) => {
    const version = cleanSemver(rawVer)
    if (!name || !version || version === "*" || version.startsWith("workspace:") || version.startsWith("file:")) return
    deps.push({
      ecosystem,
      name,
      version,
      purl: buildPurl(ecosystem, name, version),
      sourceFile: relPath,
    })
  }

  try {
    if (base === "package.json") {
      const pkg = JSON.parse(content) as Record<string, unknown>
      for (const sec of ["dependencies", "devDependencies"]) {
        const map = pkg[sec]
        if (map && typeof map === "object") {
          for (const [k, v] of Object.entries(map as Record<string, unknown>)) {
            if (typeof v === "string") pushDep("npm", k, v)
          }
        }
      }
    } else if (base === "package-lock.json") {
      const lock = JSON.parse(content) as Record<string, unknown>
      if (lock.packages && typeof lock.packages === "object") {
        for (const [pkgPath, meta] of Object.entries(lock.packages as Record<string, unknown>)) {
          if (!pkgPath || !meta || typeof meta !== "object") continue
          const m = meta as Record<string, unknown>
          const idx = pkgPath.lastIndexOf("node_modules/")
          const pkgName = idx !== -1 ? pkgPath.slice(idx + "node_modules/".length) : pkgPath
          if (pkgName && typeof m.version === "string") pushDep("npm", pkgName, m.version)
        }
      }
    } else if (base === "requirements.txt") {
      for (const line of content.split(/\r?\n/)) {
        const clean = line.split("#")[0]!.trim()
        const m = /^([a-zA-Z0-9._-]+)\s*==\s*([a-zA-Z0-9._+-]+)/.exec(clean)
        if (m) pushDep("PyPI", m[1]!, m[2]!)
      }
    } else if (base === "poetry.lock" || base === "Cargo.lock") {
      const eco: DiscoveredDependency["ecosystem"] = base === "poetry.lock" ? "PyPI" : "crates.io"
      const blocks = content.split(/\[\[package\]\]/g).slice(1)
      for (const blk of blocks) {
        const n = /^\s*name\s*=\s*"([^"]+)"/m.exec(blk)
        const v = /^\s*version\s*=\s*"([^"]+)"/m.exec(blk)
        if (n && v) pushDep(eco, n[1]!, v[1]!)
      }
    } else if (base === "go.mod") {
      for (const line of content.split(/\r?\n/)) {
        const trimmed = line.trim()
        const m = /^([a-zA-Z0-9._/-]+\.[a-zA-Z0-9._/-]+)\s+v([0-9][^\s/]*)/.exec(trimmed)
        if (m) pushDep("Go", m[1]!, m[2]!)
      }
    } else if (base === "pom.xml") {
      const depBlocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []
      for (const blk of depBlocks) {
        const g = /<groupId>([^<]+)<\/groupId>/.exec(blk)?.[1]?.trim()
        const a = /<artifactId>([^<]+)<\/artifactId>/.exec(blk)?.[1]?.trim()
        const v = /<version>([^<$]+)<\/version>/.exec(blk)?.[1]?.trim()
        if (g && a && v) pushDep("Maven", `${g}:${a}`, v)
      }
    }
  } catch {
    // Ignore malformed manifest files
  }

  return deps
}

export function auditIacFileContent(relPath: string, content: string): IacMisconfiguration[] {
  const issues: IacMisconfiguration[] = []
  const base = path.basename(relPath).toLowerCase()
  const lines = content.split(/\r?\n/)

  if (base === "dockerfile" || base.startsWith("dockerfile.") || base === "containerfile") {
    let hasUserDirective = false
    let lastUserIsRoot = false
    lines.forEach((line, idx) => {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#")) return
      if (/^FROM\s+\S+:latest\b/i.test(trimmed) || (/^FROM\s+[^\s:@]+(\s+AS\s+\S+)?$/i.test(trimmed) && !trimmed.toLowerCase().includes("scratch"))) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "dockerfile",
          ruleId: "CL-DOCKER-001",
          severity: "low",
          message: "Imagem base sem tag imutável/digest fixado (:latest ou sem tag explícita).",
        })
      }
      if (/^USER\s+/i.test(trimmed)) {
        hasUserDirective = true
        const u = trimmed.replace(/^USER\s+/i, "").trim().toLowerCase()
        lastUserIsRoot = u === "root" || u === "0" || u.startsWith("0:")
      }
      if (/^(ENV|ARG)\s+.*(PASSWORD|SECRET|API_KEY|PRIVATE_KEY|TOKEN)\s*=\s*["']?[^\s"']{4,}/i.test(trimmed)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "dockerfile",
          ruleId: "CL-DOCKER-002",
          severity: "high",
          message: "Credencial/segredo potencialmente embutido em camada ENV/ARG do Dockerfile.",
        })
      }
      if (/\b(curl|wget)\b.*\|\s*(sh|bash)\b/i.test(trimmed)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "dockerfile",
          ruleId: "CL-DOCKER-003",
          severity: "medium",
          message: "Execução remota via pipe para shell (curl/wget | sh) sem verificação de checksum SHA-256.",
        })
      }
    })
    if (!hasUserDirective || lastUserIsRoot) {
      issues.push({
        file: relPath,
        line: 1,
        kind: "dockerfile",
        ruleId: "CL-DOCKER-004",
        severity: "medium",
        message: "Container executa como root por padrão (adicione diretiva USER não-root).",
      })
    }
  } else if (base.includes("docker-compose") && (base.endsWith(".yml") || base.endsWith(".yaml"))) {
    lines.forEach((line, idx) => {
      if (/privileged\s*:\s*true/i.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "docker-compose",
          ruleId: "CL-COMPOSE-001",
          severity: "high",
          message: "Container com 'privileged: true' possui acesso quase total ao kernel do host.",
        })
      }
      if (/\/var\/run\/docker\.sock/.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "docker-compose",
          ruleId: "CL-COMPOSE-002",
          severity: "high",
          message: "Montagem do socket /var/run/docker.sock expõe controle equivalente a root sobre o daemon Docker.",
        })
      }
      if (/network_mode\s*:\s*["']?host["']?/i.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "docker-compose",
          ruleId: "CL-COMPOSE-003",
          severity: "medium",
          message: "network_mode: host desativa o isolamento de namespace de rede do container.",
        })
      }
    })
  } else if ((base.endsWith(".yml") || base.endsWith(".yaml")) && /apiVersion\s*:/m.test(content) && /kind\s*:/m.test(content)) {
    lines.forEach((line, idx) => {
      if (/privileged\s*:\s*true/i.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "kubernetes",
          ruleId: "CL-K8S-001",
          severity: "high",
          message: "Pod/Container Kubernetes configurado com securityContext.privileged: true.",
        })
      }
      if (/hostNetwork\s*:\s*true|hostPID\s*:\s*true/i.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "kubernetes",
          ruleId: "CL-K8S-002",
          severity: "high",
          message: "Manifesto Kubernetes compartilha namespace crítico do nó (hostNetwork/hostPID: true).",
        })
      }
      if (/allowPrivilegeEscalation\s*:\s*true/i.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "kubernetes",
          ruleId: "CL-K8S-003",
          severity: "medium",
          message: "allowPrivilegeEscalation: true habilitado no container.",
        })
      }
    })
  } else if (base.endsWith(".tf")) {
    lines.forEach((line, idx) => {
      if (/0\.0\.0\.0\/0/.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "terraform",
          ruleId: "CL-TF-001",
          severity: "medium",
          message: "Regra CIDR aberta para toda a internet (0.0.0.0/0) — revisar portas expostas (SSH/RDP/DB).",
        })
      }
      if (/acl\s*=\s*"public-read(-write)?"/i.test(line) || /publicly_accessible\s*=\s*true/i.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "terraform",
          ruleId: "CL-TF-002",
          severity: "high",
          message: "Recurso de armazenamento/banco configurado como publicamente acessível (public-read / publicly_accessible).",
        })
      }
      if (/(storage_encrypted|encrypted)\s*=\s*false/i.test(line)) {
        issues.push({
          file: relPath,
          line: idx + 1,
          kind: "terraform",
          ruleId: "CL-TF-003",
          severity: "medium",
          message: "Criptografia em repouso explicitamente desabilitada (encrypted = false).",
        })
      }
    })
  }

  return issues
}

// Offline known-vulnerable educational/high-profile signatures so offline labs still surface actionable detections
const OFFLINE_KNOWN_ADVISORIES: Array<{
  ecosystem: DiscoveredDependency["ecosystem"]
  name: string
  maxVulnPrefix: RegExp
  cve: string
  severity: "critical" | "high" | "medium"
  fixedIn: string
  summary: string
}> = [
  {
    ecosystem: "npm",
    name: "lodash",
    maxVulnPrefix: /^4\.(0|1[0-6]|17\.([0-9]|1[0-9]|20))$/,
    cve: "CVE-2021-23337",
    severity: "high",
    fixedIn: "4.17.21",
    summary: "Command Injection via template function in lodash < 4.17.21",
  },
  {
    ecosystem: "npm",
    name: "jsonwebtoken",
    maxVulnPrefix: /^[0-8]\./,
    cve: "CVE-2022-23529",
    severity: "high",
    fixedIn: "9.0.0",
    summary: "Insecure key retrieval / arbitrary code execution risk in jsonwebtoken < 9.0.0",
  },
  {
    ecosystem: "PyPI",
    name: "pyyaml",
    maxVulnPrefix: /^[0-4]\.|^5\.[0-3](\.|$)/,
    cve: "CVE-2020-14343",
    severity: "critical",
    fixedIn: "5.4",
    summary: "Arbitrary code execution in PyYAML < 5.4 full_load",
  },
  {
    ecosystem: "Maven",
    name: "org.apache.logging.log4j:log4j-core",
    maxVulnPrefix: /^2\.([0-9]|1[0-6])(\.|$)/,
    cve: "CVE-2021-44228",
    severity: "critical",
    fixedIn: "2.17.1",
    summary: "Log4Shell JNDI Remote Code Execution in log4j-core < 2.17.1",
  },
]

export class ScaSbomIacAuditorExecutor implements CyberLabExecutor {
  readonly id = "sca-sbom-iac-auditor-executor"
  readonly version = "1.0.0"

  async checkAvailability() {
    return { available: true, version: this.version }
  }

  async validate(input: unknown) {
    try {
      Schema.decodeUnknownSync(ScaSbomIacInputSchema)(input)
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(req: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const parsed = Schema.decodeUnknownSync(ScaSbomIacInputSchema)(req.input)
    const subpath = parsed.subpath?.trim() || "."
    const maxFiles = parsed.maxFiles ?? 200
    const targetDir = path.resolve(ctx.workspaceRoot, subpath)

    if (!isPathInsideRoot(targetDir, ctx.workspaceRoot) || !existsSync(targetDir)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Caminho fora do escopo ou inexistente: ${subpath}`,
        exitCode: 2,
      }
    }

    const candidateFiles: string[] = []
    const walk = (p: string) => {
      if (candidateFiles.length >= maxFiles || ctx.signal.aborted) return
      if (!isPathInsideRoot(p, ctx.workspaceRoot) || !existsSync(p)) return
      const st = lstatSync(p)
      if (st.isSymbolicLink()) return
      if (st.isFile()) {
        if (st.size <= 2 * 1024 * 1024) candidateFiles.push(p)
        return
      }
      if (st.isDirectory()) {
        for (const name of readdirSync(p)) {
          if (SKIP_DIRS.has(name)) continue
          walk(path.join(p, name))
          if (candidateFiles.length >= maxFiles) break
        }
      }
    }
    walk(targetDir)

    const depMap = new Map<string, DiscoveredDependency>()
    const iacFindings: IacMisconfiguration[] = []
    const doIac = parsed.auditContainersAndIac ?? true

    for (const absFile of candidateFiles) {
      const rel = path.relative(ctx.workspaceRoot, absFile).replace(/\\/g, "/")
      const base = path.basename(absFile)
      const isManifest = [
        "package.json",
        "package-lock.json",
        "requirements.txt",
        "poetry.lock",
        "go.mod",
        "Cargo.lock",
        "pom.xml",
      ].includes(base)
      const isIac =
        doIac &&
        (/^dockerfile/i.test(base) ||
          base.toLowerCase() === "containerfile" ||
          base.endsWith(".tf") ||
          base.endsWith(".yml") ||
          base.endsWith(".yaml"))

      if (!isManifest && !isIac) continue
      const text = readFileSync(absFile, "utf8")
      if (isManifest) {
        for (const d of parseDependenciesFromFile(rel, text)) {
          depMap.set(d.purl, d)
        }
      }
      if (isIac) {
        iacFindings.push(...auditIacFileContent(rel, text))
      }
    }

    const dependencies = [...depMap.values()].slice(0, 300)
    const vulnerabilities: Array<{
      package: string
      version: string
      ecosystem: string
      advisoryId: string
      severity: string
      fixedVersion?: string
      summary: string
      source: "offline-rules" | "osv.dev"
    }> = []

    // 1. Offline deterministic advisory check
    for (const dep of dependencies) {
      for (const rule of OFFLINE_KNOWN_ADVISORIES) {
        if (dep.ecosystem === rule.ecosystem && dep.name.toLowerCase() === rule.name.toLowerCase() && rule.maxVulnPrefix.test(dep.version)) {
          vulnerabilities.push({
            package: dep.name,
            version: dep.version,
            ecosystem: dep.ecosystem,
            advisoryId: rule.cve,
            severity: rule.severity,
            fixedVersion: rule.fixedIn,
            summary: rule.summary,
            source: "offline-rules",
          })
        }
      }
    }

    // 2. Optional live OSV.dev batch lookup (graceful fallback when offline/sandboxed)
    let osvQueryStatus = "skipped"
    if (parsed.queryOsvDev && dependencies.length > 0) {
      try {
        const batchSlice = dependencies.slice(0, 80)
        const ctrl = new AbortController()
        const timer = setTimeout(() => ctrl.abort(), 5_000)
        const res = await fetch("https://api.osv.dev/v1/querybatch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            queries: batchSlice.map((d) => ({
              package: { name: d.name, ecosystem: d.ecosystem },
              version: d.version,
            })),
          }),
          signal: ctrl.signal,
        })
        clearTimeout(timer)
        if (res.ok) {
          osvQueryStatus = "ok"
          const data = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string; summary?: string }> }> }
          ;(data.results ?? []).forEach((entry, idx) => {
            const dep = batchSlice[idx]
            if (!dep || !entry.vulns) return
            for (const v of entry.vulns.slice(0, 5)) {
              if (!vulnerabilities.some((existing) => existing.advisoryId === v.id && existing.package === dep.name)) {
                vulnerabilities.push({
                  package: dep.name,
                  version: dep.version,
                  ecosystem: dep.ecosystem,
                  advisoryId: v.id,
                  severity: "medium",
                  summary: v.summary ?? `Advisory reported by OSV.dev (${v.id})`,
                  source: "osv.dev",
                })
              }
            }
          })
        } else {
          osvQueryStatus = `http_${res.status}`
        }
      } catch {
        osvQueryStatus = "offline_fallback"
      }
    }

    const cycloneDxSbom =
      parsed.generateCycloneDxSbom !== false
        ? {
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            version: 1,
            metadata: {
              timestamp: new Date().toISOString(),
              tools: [{ vendor: "CyberLab OS", name: "sca-sbom-iac-auditor", version: this.version }],
            },
            components: dependencies.map((d) => ({
              type: "library",
              name: d.name,
              version: d.version,
              purl: d.purl,
            })),
          }
        : null

    const report = {
      subpath,
      scannedFilesCount: candidateFiles.length,
      dependencyCount: dependencies.length,
      osvQueryStatus,
      vulnerabilitiesCount: vulnerabilities.length,
      vulnerabilities,
      iacMisconfigurationsCount: iacFindings.length,
      iacMisconfigurations: iacFindings,
      cycloneDxSbom,
    }

    const redacted = redactSensitiveContent(JSON.stringify(report, null, 2))
    const evId = await ctx.emitEvidence({
      ...normalizeRawOutputDraft({
        kind: "json",
        title: `SCA, SBOM & IaC Audit: ${subpath} (${vulnerabilities.length} CVE(s), ${iacFindings.length} IaC alert(s))`,
        rawText: redacted.text,
        mediaType: "application/json",
        toolId: "cyberlab-sca-sbom-iac",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 768 * 1024,
        labels: ["sca", "sbom", "cyclonedx", "iac"],
      }),
      redactionApplied: redacted.redacted,
    })

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `SCA/SBOM/IaC analisou ${dependencies.length} dependência(s) (${vulnerabilities.length} CVE/advisory) e encontrou ${iacFindings.length} alerta(s) em Containers/K8s/Terraform.`,
      exitCode: 0,
    }
  }
}
