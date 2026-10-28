import type {
  KeyValueHeaderRow,
  ManualToolCategoryId,
  ManualToolDraftMap,
  ManualToolId,
  ManualToolMeta,
} from "./types"

export const MANUAL_TOOL_CATEGORIES: Array<{
  id: ManualToolCategoryId
  label: string
  description: string
}> = [
  {
    id: "web",
    label: "Web, Proxy & API",
    description: "Repeater/Comparer, Proxy HTTP Local, Headers, Scanners Web, Nuclei, ffuf e Decoder/JWT",
  },
  {
    id: "network",
    label: "Rede, TLS & Pacotes",
    description: "Certificados TLS/X.509, Sondas TCP & Banners, Nmap, Analisador .pcap e Wireshark tshark",
  },
  {
    id: "forensics",
    label: "Código, Binários & Mobile",
    description: "Auditoria Estática de Segredos, Engenharia Reversa ELF/PE/Mach-O e Forense Mobile .apk/.ipa",
  },
  {
    id: "cdi_external",
    label: "Agentes CDI & Externos",
    description: "Hub Multi-CDI (Salem, Kairós, Naia, CDI-04) e Ingestão Manual / Inbox Externa",
  },
  {
    id: "governance",
    label: "Escopo, Evidências & Relatório",
    description: "Regras de Escopo, Aprovações Humanas, Custódia SHA-256, Findings e Relatório Markdown",
  },
]

export const MANUAL_TOOLS: ManualToolMeta[] = [
  {
    id: "http-repeater",
    category: "web",
    title: "HTTP Repeater & Comparer",
    shortTitle: "Repeater",
    subtitle: "Envia requisições HTTP customizadas com headers/body completos e compara diff contra baseline",
    icon: "globe",
    badge: "MIT Nativo",
    capabilityId: "web-assessment.http-repeater",
    riskLabel: "Risco Baixo",
  },
  {
    id: "http-proxy",
    category: "web",
    title: "Proxy HTTP de Captura Local",
    shortTitle: "Proxy HTTP",
    subtitle: "Listener local 127.0.0.1:8899 com filtro de escopo, histórico ao vivo e envio em 1 clique ao Repeater",
    icon: "sliders",
    badge: "MIT Nativo",
    riskLabel: "Interceptação Local",
  },
  {
    id: "http-headers",
    category: "web",
    title: "Inspetor HTTP Headers, Cookies & CORS",
    shortTitle: "HTTP Headers",
    subtitle: "Auditoria passiva de HSTS, CSP, X-Frame-Options, CORS, Server e flags HttpOnly/Secure/SameSite",
    icon: "outline-cookie",
    badge: "MIT Nativo",
    capabilityId: "web-assessment.http-security-headers",
    riskLabel: "Somente Leitura",
  },
  {
    id: "web-surface",
    category: "web",
    title: "Scanner Nativo de Superfície Web",
    shortTitle: "Web Scanner",
    subtitle: "Descoberta controlada de endpoints, arquivos sensíveis e APIs com detecção automática de Soft-404",
    icon: "magnifying-glass",
    badge: "MIT Nativo",
    capabilityId: "web-assessment.surface-discovery",
    riskLabel: "Risco Baixo",
  },
  {
    id: "nuclei",
    category: "web",
    title: "Nuclei Template Scanner",
    shortTitle: "Nuclei",
    subtitle: "Executa templates do Nuclei com tags customizadas, rate-limit estrito e captura SHA-256",
    icon: "flask",
    badge: "Plugin Externo",
    capabilityId: "external.nuclei-template-scan",
    riskLabel: "Risco Moderado (Aprovação)",
  },
  {
    id: "ffuf",
    category: "web",
    title: "ffuf Endpoint & Directory Fuzzer",
    shortTitle: "ffuf",
    subtitle: "Fuzzing controlado de diretórios/rotas com wordlist do projeto e limite de requisições/s",
    icon: "terminal",
    badge: "Plugin Externo",
    capabilityId: "external.ffuf-endpoint-probe",
    riskLabel: "Risco Moderado (Aprovação)",
  },
  {
    id: "decoder-jwt",
    category: "web",
    title: "Decoder, JWT Inspector & Sequencer",
    shortTitle: "Decoder / JWT",
    subtitle: "Pipeline encadeável Base64/URL/Hex/HTML/SHA-256, auditoria JWT (alg:none/exp) e entropia de tokens",
    icon: "code",
    badge: "MIT Nativo",
    capabilityId: "web-assessment.decoder-sequencer",
    riskLabel: "Somente Leitura",
  },
  {
    id: "tls-inspector",
    category: "network",
    title: "Inspetor TLS & Certificado X.509",
    shortTitle: "TLS / X.509",
    subtitle: "Handshake TLS passivo com protocolo, cifra, cadeia X.509, SANs, validade e fingerprint SHA-256",
    icon: "lock",
    badge: "MIT Nativo",
    capabilityId: "network-assessment.tls-inspector",
    riskLabel: "Somente Leitura",
  },
  {
    id: "tcp-probe",
    category: "network",
    title: "Sonda TCP de Portas & Banners",
    shortTitle: "Sonda TCP",
    subtitle: "Testa conectividade TCP individual ou multi-portas sequencial com coleta passiva de banner",
    icon: "server",
    badge: "MIT Nativo",
    capabilityId: "network-assessment.tcp-surface-probe",
    riskLabel: "Risco Baixo",
  },
  {
    id: "nmap",
    category: "network",
    title: "Nmap Port & Service Scanner",
    shortTitle: "Nmap",
    subtitle: "Varredura controlada de portas e versões de serviço (-sV) via binário Nmap governado",
    icon: "window-analytics",
    badge: "Plugin Externo",
    capabilityId: "external.nmap-service-probe",
    riskLabel: "Risco Moderado (Aprovação)",
  },
  {
    id: "pcap-analyzer",
    category: "network",
    title: "Analisador Nativo de Capturas .pcap",
    shortTitle: "PCAP Nativo",
    subtitle: "Disseca arquivos .pcap offline extraindo fluxos IP, conversas TCP/UDP, DNS, HTTP e TLS SNI",
    icon: "file-document",
    badge: "MIT Nativo",
    capabilityId: "network-assessment.pcap-analyzer",
    riskLabel: "Somente Leitura",
  },
  {
    id: "tshark",
    category: "network",
    title: "Wireshark tshark Deep Dissector",
    shortTitle: "tshark",
    subtitle: "Inspeção profunda de capturas .pcap usando o motor externo tshark em modo somente leitura (-r)",
    icon: "console",
    badge: "Plugin Externo",
    capabilityId: "external.tshark-pcap-summary",
    riskLabel: "Somente Leitura",
  },
  {
    id: "workspace-audit",
    category: "forensics",
    title: "Auditoria Estática de Código & Segredos",
    shortTitle: "Code Audit",
    subtitle: "Varre pastas do projeto em busca de chaves expostas, TLS desativado e padrões inseguros de execução",
    icon: "code-lines",
    badge: "MIT Nativo",
    capabilityId: "code-analysis.workspace-audit",
    riskLabel: "Somente Leitura",
  },
  {
    id: "binary-triage",
    category: "forensics",
    title: "Triagem Reversa de Binários (ELF/PE/Mach-O)",
    shortTitle: "Binários ELF/PE",
    subtitle: "Analisa headers, arquitetura, entropia por seção (packing), NX/PIE/ASLR e strings suspeitas offline",
    icon: "cube",
    badge: "MIT Nativo",
    capabilityId: "reverse-engineering.binary-triage",
    riskLabel: "Somente Leitura",
  },
  {
    id: "mobile-triage",
    category: "forensics",
    title: "Forense Mobile (.apk / .ipa / Backups)",
    shortTitle: "Mobile APK/IPA",
    subtitle: "Inspeciona pacotes mobile em memória sem extração em disco: permissões perigosas, DEX, JNI e IoCs",
    icon: "shield",
    badge: "MIT Nativo",
    capabilityId: "mobile-forensics.artifact-triage",
    riskLabel: "Somente Leitura",
  },
  {
    id: "cdi-hub",
    category: "cdi_external",
    title: "Hub Multi-CDI (Salem, Kairós, Naia, CDI-04)",
    shortTitle: "Agentes CDI",
    subtitle: "Despacho manual individual ou paralelo para os 4 CDIs (8788–8791), Secret HMAC e log bidirecional",
    icon: "brain",
    badge: "Agentes CDI",
    riskLabel: "HMAC-SHA256 Bidirecional",
  },
  {
    id: "external-ingest",
    category: "cdi_external",
    title: "Ingestão Externa & .cyberlab/inbox",
    shortTitle: "Ingestão Externa",
    subtitle: "Importa saídas manuais do OpenTRAP, Burp, Wireshark, Ghidra ou MVT com redação e hash SHA-256",
    icon: "download",
    badge: "Plugin Externo",
    riskLabel: "Custódia Forense",
  },
  {
    id: "scope-governance",
    category: "governance",
    title: "Escopo, Aprovações, Evidências & Relatório",
    shortTitle: "Escopo & Evidências",
    subtitle: "Gerencia IPs/domínios autorizados, aprova tickets, verifica SHA-256, cria Findings e exporta .md",
    icon: "checklist",
    badge: "Governança",
    riskLabel: "Controle Total",
  },
]

export const DEFAULT_QUICK_TOOLS: ManualToolId[] = [
  "http-repeater",
  "http-proxy",
  "decoder-jwt",
  "web-surface",
  "tls-inspector",
  "tcp-probe",
  "workspace-audit",
  "cdi-hub",
  "scope-governance",
]

export function getToolMeta(toolId: ManualToolId): ManualToolMeta {
  return MANUAL_TOOLS.find((t) => t.id === toolId) ?? MANUAL_TOOLS[0]!
}

export function createDefaultToolDrafts(): ManualToolDraftMap {
  return {
    "http-repeater": {
      method: "GET",
      url: "http://127.0.0.1:4096/api/info",
      headers: [
        { id: "h-1", enabled: true, name: "Accept", value: "application/json" },
        { id: "h-2", enabled: false, name: "Authorization", value: "Bearer token-exemplo" },
      ],
      body: "",
      enableBaseline: false,
      baselineUrl: "http://127.0.0.1:4096/api/health",
      baselineHeaders: [{ id: "bh-1", enabled: true, name: "Accept", value: "application/json" }],
      timeoutMs: 6000,
      maxBodyBytes: 32768,
      executionMode: "manual",
      useRawJson: false,
      rawJson: "{\n  \"url\": \"http://127.0.0.1:4096/api/info\",\n  \"method\": \"GET\"\n}",
    },
    "http-proxy": {
      port: 8899,
      scopeOnly: true,
      filterText: "",
      selectedEntryId: "",
    },
    "http-headers": {
      url: "http://127.0.0.1:4096",
      method: "GET",
      timeoutMs: 6000,
      maxBodyBytes: 16384,
      executionMode: "manual",
      useRawJson: false,
      rawJson: "{\n  \"url\": \"http://127.0.0.1:4096\",\n  \"method\": \"GET\"\n}",
    },
    "web-surface": {
      baseUrl: "http://127.0.0.1:4096",
      customPathsText: "/robots.txt\n/.well-known/security.txt\n/api/info\n/api/health\n/openapi.json",
      concurrency: 2,
      timeoutMs: 5000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: "{\n  \"baseUrl\": \"http://127.0.0.1:4096\",\n  \"concurrency\": 2\n}",
    },
    nuclei: {
      url: "http://127.0.0.1:8080",
      tags: "misconfig,exposure,tech",
      rateLimit: 10,
      executionMode: "manual",
      useRawJson: false,
      rawJson: "{\n  \"url\": \"http://127.0.0.1:8080\",\n  \"tags\": \"misconfig,exposure\",\n  \"rateLimit\": 10\n}",
    },
    ffuf: {
      baseUrl: "http://127.0.0.1:8080",
      wordlistPath: "wordlist.txt",
      rateLimit: 10,
      executionMode: "manual",
      useRawJson: false,
      rawJson: "{\n  \"baseUrl\": \"http://127.0.0.1:8080\",\n  \"wordlistPath\": \"wordlist.txt\",\n  \"rateLimit\": 10\n}",
    },
    "decoder-jwt": {
      value: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0.",
      transforms: ["base64url_decode"],
      inspectJwt: true,
      tokenSamplesText: "",
      useRawJson: false,
      rawJson: "{\n  \"value\": \"SGVsbG8gQ3liZXJMYWI=\",\n  \"transforms\": [\"base64_decode\"],\n  \"inspectJwt\": true\n}",
    },
    "tls-inspector": {
      host: "127.0.0.1",
      port: 443,
      servername: "",
      timeoutMs: 5000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: "{\n  \"host\": \"127.0.0.1\",\n  \"port\": 443\n}",
    },
    "tcp-probe": {
      host: "127.0.0.1",
      port: 4096,
      multiPortList: "22,80,443,4096,8080,8788",
      useMultiPort: false,
      connectTimeoutMs: 1500,
      bannerWaitMs: 250,
      executionMode: "manual",
      useRawJson: false,
      rawJson: "{\n  \"host\": \"127.0.0.1\",\n  \"port\": 4096,\n  \"connectTimeoutMs\": 1500\n}",
    },
    nmap: {
      host: "127.0.0.1",
      ports: "22,80,443,4096,8080",
      serviceVersion: true,
      executionMode: "manual",
      useRawJson: false,
      rawJson: "{\n  \"host\": \"127.0.0.1\",\n  \"ports\": \"80,443,8080\",\n  \"serviceVersion\": true\n}",
    },
    "pcap-analyzer": {
      pcapPath: "captura.pcap",
      maxPackets: 5000,
      useRawJson: false,
      rawJson: "{\n  \"pcapPath\": \"captura.pcap\",\n  \"maxPackets\": 5000\n}",
    },
    tshark: {
      pcapPath: "captura.pcap",
      maxPackets: 1000,
      useRawJson: false,
      rawJson: "{\n  \"pcapPath\": \"captura.pcap\",\n  \"maxPackets\": 1000\n}",
    },
    "workspace-audit": {
      subpath: "cyberlab",
      maxFiles: 120,
      maxFileBytes: 262144,
      useRawJson: false,
      rawJson: "{\n  \"subpath\": \"cyberlab\",\n  \"maxFiles\": 120\n}",
    },
    "binary-triage": {
      binaryPath: "amostra.elf",
      minStringLength: 6,
      maxStrings: 120,
      useRawJson: false,
      rawJson: "{\n  \"binaryPath\": \"amostra.elf\",\n  \"minStringLength\": 6,\n  \"maxStrings\": 120\n}",
    },
    "mobile-triage": {
      artifactPath: "aplicativo.apk",
      iocDomainsText: "",
      useRawJson: false,
      rawJson: "{\n  \"artifactPath\": \"aplicativo.apk\"\n}",
    },
    "cdi-hub": {
      selectedPartnerIds: ["salem"],
      objective: "Revisar evidências e sugerir próximas verificações de segurança dentro do escopo",
      contextText: "",
      selectedEvidenceIds: [],
      timeoutMs: 30000,
      customSecretInput: "",
    },
    "external-ingest": {
      toolId: "opentrap",
      title: "Sessão HTTP exportada manualmente",
      origin: "manual_gui_export",
      target: "http://127.0.0.1:8080",
      commandSummary: "Exportação manual da ferramenta externa",
      mediaType: "text/plain",
      rawOutput: "",
    },
    "scope-governance": {
      subTab: "scope",
      newRuleKind: "url_origin",
      newRuleValue: "",
      newRuleNotes: "",
      newRuleBlocked: false,
      findingTitle: "",
      findingDescription: "",
      findingSeverity: "medium",
      findingConfidence: 0.85,
      findingAssetsText: "http://127.0.0.1:4096",
      findingEvidenceIds: [],
      findingRemediation: "",
    },
  }
}

function rowsToRecord(rows: KeyValueHeaderRow[]): Record<string, string> | undefined {
  const out: Record<string, string> = {}
  let count = 0
  for (const row of rows) {
    if (!row.enabled) continue
    const k = row.name.trim()
    if (!k) continue
    out[k] = row.value
    count += 1
  }
  return count > 0 ? out : undefined
}

export function buildCapabilityInput<K extends ManualToolId>(
  toolId: K,
  drafts: ManualToolDraftMap,
): { capabilityId: string; mode: "manual" | "proposed"; targetSummary: string; input: Record<string, unknown> } {
  switch (toolId) {
    case "http-repeater": {
      const d = drafts["http-repeater"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "web-assessment.http-repeater",
          mode: d.executionMode,
          targetSummary: `${String(parsed.method ?? d.method)} ${String(parsed.url ?? d.url)}`,
          input: parsed,
        }
      }
      const headers = rowsToRecord(d.headers)
      const baselineHeaders = rowsToRecord(d.baselineHeaders)
      const input: Record<string, unknown> = {
        url: d.url.trim(),
        method: d.method,
        timeoutMs: Math.min(15000, Math.max(100, Math.trunc(Number(d.timeoutMs) || 6000))),
        maxBodyBytes: Math.min(65536, Math.max(256, Math.trunc(Number(d.maxBodyBytes) || 32768))),
      }
      if (headers) input.headers = headers
      if (d.body && d.method !== "GET" && d.method !== "HEAD") input.body = d.body
      if (d.enableBaseline && d.baselineUrl.trim()) {
        input.baselineUrl = d.baselineUrl.trim()
        if (baselineHeaders) input.baselineHeaders = baselineHeaders
      }
      return {
        capabilityId: "web-assessment.http-repeater",
        mode: d.executionMode,
        targetSummary: `${d.method} ${d.url.trim()}${d.enableBaseline ? ` vs ${d.baselineUrl.trim()}` : ""}`,
        input,
      }
    }
    case "http-headers": {
      const d = drafts["http-headers"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "web-assessment.http-security-headers",
          mode: d.executionMode,
          targetSummary: `${String(parsed.method ?? d.method)} ${String(parsed.url ?? d.url)}`,
          input: parsed,
        }
      }
      return {
        capabilityId: "web-assessment.http-security-headers",
        mode: d.executionMode,
        targetSummary: `${d.method} ${d.url.trim()}`,
        input: {
          url: d.url.trim(),
          method: d.method,
          timeoutMs: Math.min(15000, Math.max(100, Math.trunc(Number(d.timeoutMs) || 6000))),
          maxBodyBytes: Math.min(65536, Math.max(256, Math.trunc(Number(d.maxBodyBytes) || 16384))),
        },
      }
    }
    case "web-surface": {
      const d = drafts["web-surface"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "web-assessment.surface-discovery",
          mode: d.executionMode,
          targetSummary: String(parsed.baseUrl ?? d.baseUrl),
          input: parsed,
        }
      }
      const customPaths = d.customPathsText
        .split(/[\r\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 25)
      const input: Record<string, unknown> = {
        baseUrl: d.baseUrl.trim(),
        concurrency: Math.min(4, Math.max(1, Math.trunc(Number(d.concurrency) || 2))),
        timeoutMs: Math.min(15000, Math.max(200, Math.trunc(Number(d.timeoutMs) || 5000))),
      }
      if (customPaths.length > 0) input.customPaths = customPaths
      return {
        capabilityId: "web-assessment.surface-discovery",
        mode: d.executionMode,
        targetSummary: `${d.baseUrl.trim()} (${customPaths.length || "padrão"} rotas)`,
        input,
      }
    }
    case "nuclei": {
      const d = drafts.nuclei
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.nuclei-template-scan",
          mode: d.executionMode,
          targetSummary: String(parsed.url ?? d.url),
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        url: d.url.trim(),
        rateLimit: Math.min(50, Math.max(1, Math.trunc(Number(d.rateLimit) || 10))),
      }
      if (d.tags.trim()) input.tags = d.tags.trim()
      return {
        capabilityId: "external.nuclei-template-scan",
        mode: d.executionMode,
        targetSummary: `${d.url.trim()} [${d.tags.trim() || "default"}]`,
        input,
      }
    }
    case "ffuf": {
      const d = drafts.ffuf
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.ffuf-endpoint-probe",
          mode: d.executionMode,
          targetSummary: String(parsed.baseUrl ?? d.baseUrl),
          input: parsed,
        }
      }
      return {
        capabilityId: "external.ffuf-endpoint-probe",
        mode: d.executionMode,
        targetSummary: `${d.baseUrl.trim()} (wordlist: ${d.wordlistPath.trim()})`,
        input: {
          baseUrl: d.baseUrl.trim(),
          wordlistPath: d.wordlistPath.trim(),
          rateLimit: Math.min(25, Math.max(1, Math.trunc(Number(d.rateLimit) || 10))),
        },
      }
    }
    case "decoder-jwt": {
      const d = drafts["decoder-jwt"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "web-assessment.decoder-sequencer",
          mode: "manual",
          targetSummary: "Pipeline Decoder / JWT",
          input: parsed,
        }
      }
      const tokenSamples = d.tokenSamplesText
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 500)
      const input: Record<string, unknown> = {
        inspectJwt: d.inspectJwt,
      }
      if (d.value) input.value = d.value
      if (d.transforms.length > 0) input.transforms = [...d.transforms]
      if (tokenSamples.length > 0) input.tokenSamples = tokenSamples
      return {
        capabilityId: "web-assessment.decoder-sequencer",
        mode: "manual",
        targetSummary: `${d.transforms.join(" → ") || "Inspeção"}${d.inspectJwt ? " + JWT" : ""}${tokenSamples.length ? ` + ${tokenSamples.length} tokens` : ""}`,
        input,
      }
    }
    case "tls-inspector": {
      const d = drafts["tls-inspector"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "network-assessment.tls-inspector",
          mode: d.executionMode,
          targetSummary: `${String(parsed.host ?? d.host)}:${String(parsed.port ?? d.port)}`,
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        host: d.host.trim(),
        port: Math.min(65535, Math.max(1, Math.trunc(Number(d.port) || 443))),
        timeoutMs: Math.min(10000, Math.max(200, Math.trunc(Number(d.timeoutMs) || 5000))),
      }
      if (d.servername.trim()) input.servername = d.servername.trim()
      return {
        capabilityId: "network-assessment.tls-inspector",
        mode: d.executionMode,
        targetSummary: `TLS ${d.host.trim()}:${input.port}${d.servername.trim() ? ` (SNI: ${d.servername.trim()})` : ""}`,
        input,
      }
    }
    case "tcp-probe": {
      const d = drafts["tcp-probe"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "network-assessment.tcp-surface-probe",
          mode: d.executionMode,
          targetSummary: `${String(parsed.host ?? d.host)}:${String(parsed.port ?? d.port)}`,
          input: parsed,
        }
      }
      const portNum = Math.min(65535, Math.max(1, Math.trunc(Number(d.port) || 80)))
      return {
        capabilityId: "network-assessment.tcp-surface-probe",
        mode: d.executionMode,
        targetSummary: `TCP ${d.host.trim()}:${portNum}`,
        input: {
          host: d.host.trim(),
          port: portNum,
          connectTimeoutMs: Math.min(5000, Math.max(100, Math.trunc(Number(d.connectTimeoutMs) || 1500))),
          bannerWaitMs: Math.min(1000, Math.max(20, Math.trunc(Number(d.bannerWaitMs) || 250))),
        },
      }
    }
    case "nmap": {
      const d = drafts.nmap
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.nmap-service-probe",
          mode: d.executionMode,
          targetSummary: `${String(parsed.host ?? d.host)} (${String(parsed.ports ?? d.ports)})`,
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        host: d.host.trim(),
        serviceVersion: d.serviceVersion,
      }
      if (d.ports.trim()) input.ports = d.ports.trim()
      return {
        capabilityId: "external.nmap-service-probe",
        mode: d.executionMode,
        targetSummary: `Nmap ${d.host.trim()} [${d.ports.trim() || "top-ports"}]`,
        input,
      }
    }
    case "pcap-analyzer": {
      const d = drafts["pcap-analyzer"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "network-assessment.pcap-analyzer",
          mode: "manual",
          targetSummary: String(parsed.pcapPath ?? d.pcapPath),
          input: parsed,
        }
      }
      return {
        capabilityId: "network-assessment.pcap-analyzer",
        mode: "manual",
        targetSummary: `PCAP ${d.pcapPath.trim()} (máx ${d.maxPackets} pkts)`,
        input: {
          pcapPath: d.pcapPath.trim(),
          maxPackets: Math.min(50000, Math.max(1, Math.trunc(Number(d.maxPackets) || 5000))),
        },
      }
    }
    case "tshark": {
      const d = drafts.tshark
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.tshark-pcap-summary",
          mode: "manual",
          targetSummary: String(parsed.pcapPath ?? d.pcapPath),
          input: parsed,
        }
      }
      return {
        capabilityId: "external.tshark-pcap-summary",
        mode: "manual",
        targetSummary: `tshark ${d.pcapPath.trim()} (máx ${d.maxPackets} pkts)`,
        input: {
          pcapPath: d.pcapPath.trim(),
          maxPackets: Math.min(5000, Math.max(1, Math.trunc(Number(d.maxPackets) || 1000))),
        },
      }
    }
    case "workspace-audit": {
      const d = drafts["workspace-audit"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "code-analysis.workspace-audit",
          mode: "manual",
          targetSummary: String(parsed.subpath ?? d.subpath),
          input: parsed,
        }
      }
      return {
        capabilityId: "code-analysis.workspace-audit",
        mode: "manual",
        targetSummary: `Audit ${d.subpath.trim()} (até ${d.maxFiles} arqs)`,
        input: {
          subpath: d.subpath.trim(),
          maxFiles: Math.min(500, Math.max(1, Math.trunc(Number(d.maxFiles) || 120))),
          maxFileBytes: Math.min(1048576, Math.max(1024, Math.trunc(Number(d.maxFileBytes) || 262144))),
        },
      }
    }
    case "binary-triage": {
      const d = drafts["binary-triage"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "reverse-engineering.binary-triage",
          mode: "manual",
          targetSummary: String(parsed.binaryPath ?? d.binaryPath),
          input: parsed,
        }
      }
      return {
        capabilityId: "reverse-engineering.binary-triage",
        mode: "manual",
        targetSummary: `Binário ${d.binaryPath.trim()}`,
        input: {
          binaryPath: d.binaryPath.trim(),
          minStringLength: Math.min(64, Math.max(4, Math.trunc(Number(d.minStringLength) || 6))),
          maxStrings: Math.min(500, Math.max(10, Math.trunc(Number(d.maxStrings) || 120))),
        },
      }
    }
    case "mobile-triage": {
      const d = drafts["mobile-triage"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "mobile-forensics.artifact-triage",
          mode: "manual",
          targetSummary: String(parsed.artifactPath ?? d.artifactPath),
          input: parsed,
        }
      }
      const iocDomains = d.iocDomainsText
        .split(/[\r\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 200)
      const input: Record<string, unknown> = {
        artifactPath: d.artifactPath.trim(),
      }
      if (iocDomains.length > 0) input.iocDomains = iocDomains
      return {
        capabilityId: "mobile-forensics.artifact-triage",
        mode: "manual",
        targetSummary: `Mobile ${d.artifactPath.trim()}${iocDomains.length ? ` (${iocDomains.length} IoCs)` : ""}`,
        input,
      }
    }
    default:
      throw new Error(`A ferramenta "${toolId}" utiliza controlador especializado direto.`)
  }
}
