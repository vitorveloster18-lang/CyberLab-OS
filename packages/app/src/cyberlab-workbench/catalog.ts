import type {
  KeyValueHeaderRow,
  ManualToolCategoryId,
  ManualToolDraftMap,
  ManualToolId,
  ManualToolMeta,
  ToolSuiteId,
  ToolSuiteMeta,
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
    title: "Inspetor TLS, Cifras, PFS, HSTS & Certificado X.509",
    shortTitle: "TLS / X.509",
    subtitle: "Handshake TLS passivo + matriz TLS 1.0–1.3, cifras fracas/CBC, Forward Secrecy, HSTS Preload e nota A+..F",
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
    id: "http-intruder",
    category: "web",
    title: "HTTP Intruder & Matriz de Payloads (§slot§)",
    shortTitle: "HTTP Intruder",
    subtitle: "Testes paramétricos controlados Sniper / Battering Ram / Pitchfork com rate-limit e filtro regex",
    icon: "globe",
    badge: "MIT Nativo",
    capabilityId: "web-assessment.http-intruder",
    riskLabel: "Moderado (Escopo)",
  },
  {
    id: "param-audit",
    category: "web",
    title: "Auditor Diferencial de Parâmetros",
    shortTitle: "Param Auditor",
    subtitle: "Auditoria não-destrutiva de reflexão contextual, vazamento de stack traces e open-redirect",
    icon: "globe",
    badge: "MIT Nativo",
    capabilityId: "web-assessment.param-audit",
    riskLabel: "Baixo (Não-Destrutivo)",
  },
  {
    id: "dalfox",
    category: "web",
    title: "Dalfox Parameter & XSS Scanner",
    shortTitle: "Dalfox",
    subtitle: "Auditoria focada de parâmetros via binário externo dalfox (MIT) supervisionado pelo escopo",
    icon: "globe",
    badge: "Plugin Externo",
    capabilityId: "external.dalfox-param-scan",
    riskLabel: "Moderado (Escopo)",
  },
  {
    id: "dns-recon",
    category: "network",
    title: "Reconhecimento DNS, Subdomínios & Email (SPF/DMARC)",
    shortTitle: "DNS & Email",
    subtitle: "Registros DNS, postura SPF/DMARC/CAA, higiene contra Subdomain Takeover e crt.sh passivo",
    icon: "server",
    badge: "MIT Nativo",
    capabilityId: "network-assessment.dns-recon",
    riskLabel: "Baixo (Escopo)",
  },
  {
    id: "binary-disasm",
    category: "forensics",
    title: "Disassembler Nativo (x86_64 / ARM64)",
    shortTitle: "Disassembler",
    subtitle: "Desmontagem estática offline de instruções x86_64 e ARM64 para ELF64, PE/COFF e Mach-O",
    icon: "cube",
    badge: "MIT Nativo",
    capabilityId: "reverse-engineering.binary-disasm",
    riskLabel: "Somente Leitura",
  },
  {
    id: "ghidra",
    category: "forensics",
    title: "Ghidra Headless Decompiler",
    shortTitle: "Ghidra Headless",
    subtitle: "Análise estática profunda via analyzeHeadless (Apache-2.0) com custódia SHA-256",
    icon: "cube",
    badge: "Plugin Externo",
    capabilityId: "external.ghidra-decompile",
    riskLabel: "Somente Leitura",
  },
  {
    id: "mobile-triage",
    category: "forensics",
    title: "Forense Mobile (.apk / .dex / .ipa / Backups)",
    shortTitle: "Mobile APK/DEX",
    subtitle: "Inspeciona pacotes mobile e decodifica tabelas Dalvik classes.dex (classes/métodos), permissões e IoCs",
    icon: "shield",
    badge: "MIT Nativo",
    capabilityId: "mobile-forensics.artifact-triage",
    riskLabel: "Somente Leitura",
  },
  {
    id: "jadx",
    category: "forensics",
    title: "JADX Android Decompiler (.apk/.dex → .java)",
    shortTitle: "JADX Java",
    subtitle: "Descompila pacotes Android para código Java navegável em .cyberlab/artifacts/jadx/ (Apache-2.0)",
    icon: "shield",
    badge: "Plugin Externo",
    capabilityId: "external.jadx-decompile",
    riskLabel: "Somente Leitura",
  },
  {
    id: "yara-scan",
    category: "forensics",
    title: "Caça de Indicadores YARA Nativo",
    shortTitle: "YARA Nativo",
    subtitle: "Motor integrado de regras YARA (strings ASCII/wide, hex curinga ?? e condições booleanas)",
    icon: "code-lines",
    badge: "MIT Nativo",
    capabilityId: "forensics.yara-scan",
    riskLabel: "Somente Leitura",
  },
  {
    id: "yarax",
    category: "forensics",
    title: "YARA-X Oficial (VirusTotal yr)",
    shortTitle: "YARA-X (yr)",
    subtitle: "Execução governada de arquivos .yar/.yara via motor YARA-X em Rust (BSD-3-Clause)",
    icon: "code-lines",
    badge: "Plugin Externo",
    capabilityId: "external.yarax-scan",
    riskLabel: "Somente Leitura",
  },
  {
    id: "api-security-lab",
    category: "web",
    title: "API, GraphQL & OAuth2/OIDC Security Lab",
    shortTitle: "API / GraphQL / OAuth",
    subtitle: "Importador OpenAPI/Postman com matriz diferencial BOLA/IDOR (User A vs User B), GraphQL e OAuth2/PKCE",
    icon: "globe",
    badge: "MIT Nativo",
    capabilityId: "web-assessment.api-graphql-oauth-lab",
    riskLabel: "Risco Baixo (Escopo)",
  },
  {
    id: "ad-smb-ldap",
    category: "network",
    title: "Inspetor Active Directory, SMB, LDAP & NTLM (Lab)",
    shortTitle: "AD / SMB / LDAP",
    subtitle: "Enumeração passiva sem credenciais: SMB2/3 Signing, LDAPv3 RootDSE anônimo e metadados NTLM Type-2",
    icon: "server",
    badge: "MIT Nativo",
    capabilityId: "network-assessment.ad-smb-ldap-inspector",
    riskLabel: "Somente Leitura (Lab)",
  },
  {
    id: "key-hunter",
    category: "forensics",
    title: "Key Hunter — Caçador Multi-Superfície de API Keys, Tokens & Chaves Criptográficas",
    shortTitle: "Key Hunter",
    subtitle: "43+ assinaturas (OpenAI/Anthropic/AWS/Stripe/GitHub/Slack/DB/PEM/JWT) em Workspace, Binários, Web/JS Bundles, Buffer e GitHub com filtro anti-placeholder e KeyHacks",
    icon: "lock",
    badge: "MIT Nativo",
    capabilityId: "code-analysis.key-hunter",
    riskLabel: "Risco Baixo (Redação SHA-256)",
  },
  {
    id: "keyhunter-cli",
    category: "forensics",
    title: "KeyHunter Rust CLI Bridge (fadidevv/keyhunter)",
    shortTitle: "KeyHunter CLI",
    subtitle: "Execução governada do scanner oficial em Rust (cargo install github-keyhunter — scan/verify/patterns) com redação automática e custódia SHA-256",
    icon: "terminal",
    badge: "Plugin Externo",
    capabilityId: "external.keyhunter-cli",
    riskLabel: "Risco Baixo",
  },
  {
    id: "sca-sbom-iac",
    category: "forensics",
    title: "SCA (Vulnerabilidades), SBOM CycloneDX & Auditor IaC",
    shortTitle: "SCA / SBOM / IaC",
    subtitle: "Lockfiles (npm/bun/PyPI/Go/Cargo/Maven) + OSV.dev CVEs + SBOM CycloneDX 1.5 + Dockerfile/K8s/Terraform",
    icon: "code-lines",
    badge: "MIT Nativo",
    capabilityId: "code-analysis.sca-sbom-iac-audit",
    riskLabel: "Somente Leitura",
  },
  {
    id: "trivy",
    category: "forensics",
    title: "Aqua Trivy SCA, Container & IaC Scanner",
    shortTitle: "Trivy (Apache-2.0)",
    subtitle: "Varredura externa governada via binário trivy fs (vuln, misconfig, secret) com custódia SHA-256",
    icon: "code-lines",
    badge: "Plugin Externo",
    capabilityId: "external.trivy-scan",
    riskLabel: "Somente Leitura",
  },
  {
    id: "entropy-recipe",
    category: "forensics",
    title: "Visualizador de Entropia Binária & CyberChef Studio",
    shortTitle: "Entropia & CyberChef",
    subtitle: "Gráfico de entropia byte 0 → EOF, carving de assinaturas e receitas salváveis (XOR, AES, Zlib, Protobuf)",
    icon: "cube",
    badge: "MIT Nativo",
    capabilityId: "reverse-engineering.entropy-recipe-studio",
    riskLabel: "Somente Leitura",
  },
  {
    id: "dfir-sigma",
    category: "forensics",
    title: "DFIR Log Analyzer & Motor de Regras Sigma (YAML)",
    shortTitle: "DFIR & Sigma",
    subtitle: "Triagem Blue Team/SOC de logs Linux, Nginx/Apache e JSON/Windows Events com Sigma YAML e Timeline SHA-256",
    icon: "file-document",
    badge: "MIT Nativo",
    capabilityId: "forensics.dfir-sigma-triage",
    riskLabel: "Somente Leitura",
  },
  {
    id: "cdi-hub",
    category: "cdi_external",
    title: "Parceiros Cognitivos CDI (Kairós, Naia, Salem & Nova)",
    shortTitle: "Parceiros CDI",
    subtitle: "Entidades cognitivas autónomas em relação horizontal com o curador — Kairós (8788), Naia (8789), Salem (8790) e Nova (8791)",
    icon: "brain",
    badge: "Agentes CDI",
    riskLabel: "Parceria Horizontal HMAC-SHA256",
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

/**
 * 7 Ferramentas / Suítes Distintas (estilo Burp Suite / Wireshark / Nmap).
 * Cada suíte aparece como 1 único item limpo na caixa vertical, e suas funcionalidades
 * correlatas são alternadas por abas/motores internos lá dentro.
 */
export const TOOL_SUITES: ToolSuiteMeta[] = [
  {
    id: "web-suite",
    title: "Web & API Security Suite",
    shortTitle: "Web & API Suite",
    subtitle: "Proxy HTTPS CA & WS · Repeater · Intruder (§slot§) · API/GraphQL/OAuth2 BOLA · Parâmetros & Dalfox · JWT",
    icon: "globe",
    keywords: [
      "burp",
      "opentrap",
      "proxy",
      "https",
      "ca",
      "websocket",
      "repeater",
      "intruder",
      "sniper",
      "api",
      "openapi",
      "swagger",
      "postman",
      "bola",
      "idor",
      "graphql",
      "oauth",
      "oidc",
      "pkce",
      "dalfox",
      "xss",
      "sqli",
      "parametros",
      "nuclei",
      "ffuf",
      "jwt",
      "decoder",
      "headers",
      "web",
    ],
    functions: [
      {
        id: "repeater",
        label: "Repeater & Comparer",
        description: "Manipule requisições HTTP manualmente e compare diferenças lado a lado contra uma URL baseline",
        engines: [
          {
            toolId: "http-repeater",
            label: "HTTP Repeater & Diff",
            badge: "MIT Nativo",
            description: "Requisição estruturada + comparação de resposta",
          },
        ],
      },
      {
        id: "proxy",
        label: "Proxy Intercept (HTTPS / WS)",
        description: "Capture HTTP, HTTPS (MITM com Root CA local .crt ou túnel CONNECT) e WebSockets (ws/wss) em 127.0.0.1:8899",
        engines: [
          {
            toolId: "http-proxy",
            label: "Proxy Local HTTP / HTTPS CA / WS",
            badge: "MIT Nativo",
            description: "Root CA ECDSA P-256 local + inspeção TLS & WebSocket",
          },
        ],
      },
      {
        id: "intruder",
        label: "Intruder / Payload Lab",
        description: "Marque slots §payload§ na URL, cabeçalhos ou corpo e execute matrizes Sniper, Battering Ram ou Pitchfork",
        engines: [
          {
            toolId: "http-intruder",
            label: "HTTP Intruder (§slot§ Matrix)",
            badge: "MIT Nativo",
            description: "Sniper / Battering Ram / Pitchfork com rate-limit e grep",
          },
        ],
      },
      {
        id: "params",
        label: "Auditor de Parâmetros",
        description: "Audite reflexão contextual não-destrutiva, vazamento de erros de banco/framework, open-redirect ou Dalfox",
        engines: [
          {
            toolId: "param-audit",
            label: "Auditor Diferencial (Não-Destrutivo)",
            badge: "MIT Nativo",
            description: "Baseline vs canário seguro sem payloads destrutivos",
          },
          {
            toolId: "dalfox",
            label: "Dalfox Parameter Scanner",
            badge: "MIT Externo",
            description: "Scanner especializado de parâmetros e reflexão XSS",
          },
        ],
      },
      {
        id: "scanner",
        label: "Scanner & Fuzzer",
        description: "Descubra rotas sensíveis, rode templates de vulnerabilidade ou faça fuzzing controlado com wordlist",
        engines: [
          {
            toolId: "web-surface",
            label: "Surface Scanner (Anti-Soft-404)",
            badge: "MIT Nativo",
            description: "Rápido, zero binários externos, filtra falsos 200 OK",
          },
          {
            toolId: "nuclei",
            label: "Nuclei Templates",
            badge: "Motor Externo",
            description: "Varredura por tags (misconfig, exposure, cve, tech)",
          },
          {
            toolId: "ffuf",
            label: "ffuf Directory Fuzzer",
            badge: "Motor Externo",
            description: "Fuzzing de endpoints usando wordlist do projeto",
          },
        ],
      },
      {
        id: "headers",
        label: "Headers & Cookies",
        description: "Auditoria passiva imediata de HSTS, CSP, X-Frame-Options, CORS e flags de sessão (HttpOnly/Secure/SameSite)",
        engines: [
          {
            toolId: "http-headers",
            label: "Inspetor de Segurança HTTP",
            badge: "Nativo",
            description: "Análise passiva de cabeçalhos e cookies",
          },
        ],
      },
      {
        id: "api-lab",
        label: "API, GraphQL & OAuth2 Lab",
        description: "Importe OpenAPI/Postman com matriz diferencial BOLA/IDOR (User A vs User B), audite GraphQL e fluxos OAuth2/PKCE",
        engines: [
          {
            toolId: "api-security-lab",
            label: "OpenAPI BOLA + GraphQL + OAuth2/OIDC",
            badge: "MIT Nativo",
            description: "BOLA diferencial, introspecção/batching GraphQL e higiene OIDC/PKCE",
          },
        ],
      },
      {
        id: "decoder",
        label: "Decoder, JWT & Sequencer",
        description: "Encadeie decodificações (Base64, URL, Hex, HTML, SHA-256), audite tokens JWT e meça entropia de sessões",
        engines: [
          {
            toolId: "decoder-jwt",
            label: "Decoder + JWT + Sequencer",
            badge: "Nativo",
            description: "Transformações em cadeia e análise criptográfica de tokens",
          },
        ],
      },
    ],
  },
  {
    id: "network-suite",
    title: "Network, TLS Deep Audit & AD Lab",
    shortTitle: "Rede, TLS & AD",
    subtitle: "Port Scanner TCP & Nmap (-sV) · TLS 1.0–1.3, Cifras, PFS, HSTS & Nota A+..F · DNS/SPF/DMARC · AD/SMB/LDAP/NTLM",
    icon: "server",
    keywords: [
      "nmap",
      "tcp",
      "portas",
      "banner",
      "tls",
      "ssl",
      "x509",
      "certificado",
      "hsts",
      "cifras",
      "pfs",
      "sni",
      "rede",
      "dns",
      "subdominio",
      "spf",
      "dmarc",
      "takeover",
      "crt",
      "ad",
      "active directory",
      "smb",
      "signing",
      "ldap",
      "rootdse",
      "ntlm",
    ],
    functions: [
      {
        id: "ports",
        label: "Port & Service Scanner",
        description: "Verifique portas abertas, banners de serviço e versões ativas no host alvo",
        engines: [
          {
            toolId: "tcp-probe",
            label: "Sonda TCP & Banners (Porta Única ou Lista)",
            badge: "MIT Nativo",
            description: "Execução imediata sem depender do Nmap instalado",
          },
          {
            toolId: "nmap",
            label: "Nmap Service Scanner (-sV)",
            badge: "Motor Externo",
            description: "Detecção profunda de serviços/versões via binário Nmap",
          },
        ],
      },
      {
        id: "tls",
        label: "TLS Profundo, Cifras & HSTS",
        description: "Inspecione cadeia X.509, matriz TLS 1.0–1.3, cifras fracas/CBC, Forward Secrecy (ECDHE), RSA, HSTS Preload e nota A+..F",
        engines: [
          {
            toolId: "tls-inspector",
            label: "Inspetor TLS Profundo & Nota de Segurança",
            badge: "MIT Nativo",
            description: "Handshake + matriz de downgrade TLS + HSTS Preload",
          },
        ],
      },
      {
        id: "dns",
        label: "DNS, Subdomínios & Email",
        description: "Consulte registros A/AAAA/CNAME/MX/NS/TXT/CAA, audite SPF/DMARC, detecte CNAMEs órfãos e busque crt.sh",
        engines: [
          {
            toolId: "dns-recon",
            label: "DNS Surface, SPF/DMARC & Takeover Hygiene",
            badge: "MIT Nativo",
            description: "Reconhecimento DNS completo + transparência de certificados",
          },
        ],
      },
      {
        id: "ad-lab",
        label: "AD, SMB, LDAP & NTLM Lab",
        description: "Enumeração passiva autorizada sem credenciais: SMB2/3 Signing obrigatório, LDAPv3 RootDSE anônimo e challenge HTTP NTLM",
        engines: [
          {
            toolId: "ad-smb-ldap",
            label: "Inspetor Passivo SMB / LDAP / NTLM",
            badge: "MIT Nativo",
            description: "Verifica exposição a NTLM Relay e políticas RootDSE sem brute-force",
          },
        ],
      },
    ],
  },
  {
    id: "packet-suite",
    title: "Packet Capture Analyzer",
    shortTitle: "Analisador PCAP",
    subtitle: "Dissecação de arquivos .pcap (estilo Wireshark): fluxos IP, conversas TCP/UDP, DNS, HTTP e TLS SNI",
    icon: "window-analytics",
    keywords: ["wireshark", "tshark", "pcap", "pacotes", "dns", "sni", "trafego"],
    functions: [
      {
        id: "pcap",
        label: "Inspeção de Captura .pcap",
        description: "Analise capturas de rede salvas no projeto usando o dissecador nativo ou o Wireshark tshark",
        engines: [
          {
            toolId: "pcap-analyzer",
            label: "Dissecador Nativo (.pcap)",
            badge: "MIT Nativo",
            description: "Extrai fluxos IPv4/IPv6, portas, DNS, HTTP e TLS SNI offline",
          },
          {
            toolId: "tshark",
            label: "Wireshark tshark (-r)",
            badge: "Motor Externo",
            description: "Resumo profundo via motor oficial tshark somente-leitura",
          },
        ],
      },
    ],
  },
  {
    id: "reversing-suite",
    title: "Reverse Engineering, Entropy & Mobile Lab",
    shortTitle: "Reversa, Entropia & Mobile",
    subtitle: "ELF/PE/Mach-O · Disasm x86_64/ARM64 & Ghidra · Entropia Visual & CyberChef · Android DEX & JADX · YARA",
    icon: "cube",
    keywords: [
      "ghidra",
      "disassembler",
      "x86_64",
      "arm64",
      "asm",
      "elf",
      "pe",
      "exe",
      "dll",
      "mach-o",
      "entropia",
      "cyberchef",
      "firmware",
      "xor",
      "aes",
      "zlib",
      "protobuf",
      "apk",
      "dex",
      "jadx",
      "ipa",
      "android",
      "ios",
      "yara",
      "yarax",
      "malware",
      "binario",
    ],
    functions: [
      {
        id: "binary",
        label: "Binários ELF / PE / Mach-O",
        description: "Arquitetura, seções compactadas (alta entropia), flags NX/PIE/ASLR e strings suspeitas sem executar a amostra",
        engines: [
          {
            toolId: "binary-triage",
            label: "Triagem Estática de Binários",
            badge: "MIT Nativo",
            description: "Parser seguro offline ELF / PE / Mach-O",
          },
        ],
      },
      {
        id: "disasm",
        label: "Disassembly & Decompilação",
        description: "Desmonte instruções nativas x86_64 / ARM64 do entrypoint ou invoque o Ghidra Headless (Apache-2.0)",
        engines: [
          {
            toolId: "binary-disasm",
            label: "Disassembler x86_64 / ARM64",
            badge: "MIT Nativo",
            description: "Desmontagem imediata com resolução de símbolos",
          },
          {
            toolId: "ghidra",
            label: "Ghidra Headless (analyzeHeadless)",
            badge: "Apache-2.0 Externo",
            description: "Análise profunda via suíte oficial Ghidra",
          },
        ],
      },
      {
        id: "mobile",
        label: "Forense Mobile & JADX",
        description: "Inspecione classes/métodos Dalvik (.dex), manifestos e IoCs em memória ou descompile para .java com JADX",
        engines: [
          {
            toolId: "mobile-triage",
            label: "Inspetor .apk / .dex / .ipa (Dalvik)",
            badge: "MIT Nativo",
            description: "Tabelas classes.dex + permissões + IoCs sem extrair ZIP",
          },
          {
            toolId: "jadx",
            label: "JADX Decompiler (.apk → .java)",
            badge: "Apache-2.0 Externo",
            description: "Gera código Java navegável em .cyberlab/artifacts/jadx/",
          },
        ],
      },
      {
        id: "entropy",
        label: "Entropia & CyberChef Studio",
        description: "Visualize o gráfico de entropia byte 0 → EOF (regiões cifradas/comprimidas) e monte receitas XOR/AES/Zlib/Protobuf",
        engines: [
          {
            toolId: "entropy-recipe",
            label: "Visualizador de Entropia + CyberChef Studio",
            badge: "MIT Nativo",
            description: "Espectro de Shannon, carving de assinaturas e receitas salváveis",
          },
        ],
      },
      {
        id: "yara",
        label: "Caça com YARA / YARA-X",
        description: "Execute regras YARA customizadas (strings ASCII/wide, hex curinga ?? e condições) em binários ou pastas",
        engines: [
          {
            toolId: "yara-scan",
            label: "Motor YARA Integrado",
            badge: "MIT Nativo",
            description: "Editor de regras YARA ao vivo, zero dependências externas",
          },
          {
            toolId: "yarax",
            label: "YARA-X Oficial (yr)",
            badge: "BSD-3-Clause Externo",
            description: "Scanner oficial VirusTotal YARA-X sobre arquivo .yar",
          },
        ],
      },
    ],
  },
  {
    id: "dfir-suite",
    title: "DFIR & Incident Response Lab (Sigma)",
    shortTitle: "DFIR & Sigma (SOC)",
    subtitle: "Análise forense Blue Team de logs Linux (auth.log/syslog), Web (Nginx/Apache) e JSON/Windows Events com regras Sigma YAML",
    icon: "file-document",
    keywords: ["dfir", "soc", "blue team", "sigma", "logs", "auth.log", "syslog", "nginx", "apache", "evtx", "windows", "timeline", "incidente"],
    functions: [
      {
        id: "sigma-triage",
        label: "Triagem de Logs & Regras Sigma",
        description: "Aplique regras Sigma YAML integradas ou customizadas sobre logs e gere Timeline de Incidente com custódia SHA-256",
        engines: [
          {
            toolId: "dfir-sigma",
            label: "Motor DFIR Multi-Formato + Sigma YAML",
            badge: "MIT Nativo",
            description: "Detecta brute-force, webshells, escalonamento e movimento lateral",
          },
        ],
      },
    ],
  },
  {
    id: "code-suite",
    title: "Key Hunter, SAST, SCA, SBOM CycloneDX & IaC",
    shortTitle: "Key Hunter, Código & SCA",
    subtitle: "Key Hunter (API Keys, JS Bundles, GitHub & PEM) · SAST · SCA (OSV.dev) · SBOM CycloneDX 1.5 · IaC & Trivy",
    icon: "code-lines",
    keywords: [
      "keyhunter",
      "key hunter",
      "key",
      "keyhacks",
      "openai",
      "anthropic",
      "aws",
      "stripe",
      "github",
      "pem",
      "sast",
      "sca",
      "sbom",
      "cyclonedx",
      "osv",
      "cve",
      "dependencias",
      "npm",
      "lockfile",
      "dockerfile",
      "kubernetes",
      "k8s",
      "terraform",
      "iac",
      "trivy",
      "codigo",
      "segredos",
      "api key",
      "token",
      "audit",
    ],
    functions: [
      {
        id: "key-hunter-tab",
        label: "Key Hunter (API Keys & Crypto)",
        description: "Cace API keys (OpenAI, Anthropic, AWS, GCP, Stripe, GitHub, Slack, DBs) e chaves PEM/JWK/JWT no workspace, binários, URLs/JS bundles, textos colados ou GitHub autorizado",
        engines: [
          {
            toolId: "key-hunter",
            label: "CyberLab Key Hunter Studio (43+ Assinaturas + KeyHacks)",
            badge: "MIT Nativo",
            description: "Workspace, Binários, Web/JS Bundles, Buffer & GitHub + filtro anti-placeholder e verificação segura opt-in",
          },
          {
            toolId: "keyhunter-cli",
            label: "KeyHunter Rust CLI (fadidevv/keyhunter)",
            badge: "Plugin Externo",
            description: "Bridge governado para o binário oficial 'keyhunter' (cargo install github-keyhunter)",
          },
        ],
      },
      {
        id: "audit",
        label: "SAST & Segredos",
        description: "Inspecione pastas ou arquivos do workspace em busca de segredos hardcoded, chaves privadas e código inseguro",
        engines: [
          {
            toolId: "workspace-audit",
            label: "Workspace Code & Secret Audit",
            badge: "MIT Nativo",
            description: "Regras estáticas para segredos, TLS e execução insegura",
          },
        ],
      },
      {
        id: "sca-iac",
        label: "SCA, SBOM CycloneDX & IaC",
        description: "Audite dependências (package-lock, requirements, go.mod, Cargo, pom.xml), gere SBOM CycloneDX e valide Dockerfile/K8s/Terraform",
        engines: [
          {
            toolId: "sca-sbom-iac",
            label: "SCA + OSV.dev + SBOM CycloneDX + IaC",
            badge: "MIT Nativo",
            description: "Zero binários externos, gera CycloneDX 1.5 e audita Containers/IaC",
          },
          {
            toolId: "trivy",
            label: "Aqua Trivy Scanner (trivy fs)",
            badge: "Apache-2.0 Externo",
            description: "Scanner externo oficial Aqua Trivy para CVEs, IaC e segredos",
          },
        ],
      },
    ],
  },
  {
    id: "cdi-suite",
    title: "Parceiros Cognitivos CDI (Kairós, Naia, Salem & Nova)",
    shortTitle: "Parceiros CDI",
    subtitle: "Entidades cognitivas autónomas sem hierarquia em relação horizontal com o curador — Kairós (8788), Naia (8789), Salem (8790) e Nova (8791)",
    icon: "brain",
    keywords: ["cdi", "kairos", "naia", "salem", "nova", "chat.py", "parceiro", "autonomo", "curador", "hmac", "gateway"],
    functions: [
      {
        id: "dispatch",
        label: "Colaboração & Diálogo entre Pares",
        description: "Convide 1 ou mais parceiros CDI horizontalmente para investigar um tema ou hipótese partilhada com evidências SHA-256",
        cdiSubTab: "dispatch",
        engines: [
          {
            toolId: "cdi-hub",
            label: "Investigação Partilhada entre Pares",
            badge: "Sem Hierarquia",
            description: "Diálogo horizontal Curador <-> Parceiros CDI",
          },
        ],
      },
      {
        id: "setup",
        label: "Perfis Individuais, Autonomia Plena & Gateway",
        description: "Configure os perfis individuais de Kairós, Naia, Salem e Nova, autonomia plena (projetos, laboratórios, escrita de código e runtime) e as 25 ações do gateway",
        cdiSubTab: "setup",
        engines: [
          {
            toolId: "cdi-hub",
            label: "Perfis Autónomos & Gateway :4096",
            badge: "25 Ações Gateway",
            description: "Autonomia plena sem engessamento + projetos, labs, código e runtime",
          },
        ],
      },
    ],
  },
  {
    id: "governance-suite",
    title: "Escopo, Laboratórios, Cofre SHA-256 & Relatório",
    shortTitle: "Escopo, Labs & Evidências",
    subtitle: "Laboratórios de Treinamento interativos, criação de projetos, controle de alvos permitidos, aprovações, evidências SHA-256, Findings e Relatório .md",
    icon: "shield",
    keywords: ["escopo", "laboratorio", "treino", "training", "lab", "projeto", "alvo", "aprovacao", "evidencia", "sha256", "finding", "relatorio", "markdown", "inbox", "importar"],
    functions: [
      {
        id: "labs",
        label: "Laboratórios & Projetos",
        description: "Inicie, reinicie ou encerre os 5 Laboratórios de Treinamento locais (Web/API BOLA, GraphQL/OAuth, Key Hunter, DFIR/SOC e Reversing ELF64) e crie/alterne projetos",
        governanceSubTab: "labs",
        engines: [{ toolId: "scope-governance", label: "Laboratórios de Treinamento & Projetos", badge: "5 Labs Locais", description: "Servidores locais + escopo automático" }],
      },
      {
        id: "scope",
        label: "Escopo de Alvos",
        description: "Libere alvos externos e cadastre IPs, CIDRs, domínios e URLs autorizados para os testes",
        governanceSubTab: "scope",
        engines: [{ toolId: "scope-governance", label: "Regras de Escopo", badge: "PolicyEngine", description: "Confinamento anti-TOCTOU" }],
      },
      {
        id: "approvals",
        label: "Aprovações",
        description: "Aprove ou cancele execuções moderadas/externas pendentes em 1 clique",
        governanceSubTab: "approvals",
        engines: [{ toolId: "scope-governance", label: "Fila de Tickets", badge: "Uso Único", description: "Autorização humana" }],
      },
      {
        id: "evidence",
        label: "Cofre SHA-256",
        description: "Leia o conteúdo redigido das evidências coletadas e revalide o hash criptográfico SHA-256",
        governanceSubTab: "evidence",
        engines: [{ toolId: "scope-governance", label: "EvidenceStore", badge: "SQLite WAL", description: "Cadeia de custódia" }],
      },
      {
        id: "import",
        label: "Importar Externo / Inbox",
        description: "Sincronize a pasta .cyberlab/inbox ou cole/importe saídas manuais de ferramentas externas (Burp, OpenTRAP, Ghidra)",
        engines: [{ toolId: "external-ingest", label: "Ingestão Externa Governada", badge: "Inbox", description: "Redação + SHA-256 automático" }],
      },
      {
        id: "findings",
        label: "Findings",
        description: "Registre vulnerabilidades vinculadas às evidências e confirme/rejeite revisões analíticas",
        governanceSubTab: "findings",
        engines: [{ toolId: "scope-governance", label: "Gestão de Findings", badge: "Analítico", description: "Severidade independente de confiança" }],
      },
      {
        id: "report",
        label: "Relatório (.md)",
        description: "Gere, baixe ou anexe na caixa de diálogo o relatório técnico reproduzível em Markdown",
        governanceSubTab: "report",
        engines: [{ toolId: "scope-governance", label: "Gerador de Relatório", badge: "Markdown", description: "Referências SHA-256 verificáveis" }],
      },
    ],
  },
]

export function getSuiteMeta(suiteId: ToolSuiteId): ToolSuiteMeta {
  return TOOL_SUITES.find((s) => s.id === suiteId) ?? TOOL_SUITES[0]!
}

export function getSuiteAllToolIds(suiteId: ToolSuiteId): ManualToolId[] {
  const suite = getSuiteMeta(suiteId)
  const set = new Set<ManualToolId>()
  for (const fn of suite.functions) {
    for (const eng of fn.engines) {
      set.add(eng.toolId)
    }
  }
  return [...set]
}

export function findSuiteAndFunctionForTool(toolId: ManualToolId): { suiteId: ToolSuiteId; functionId: string } {
  for (const suite of TOOL_SUITES) {
    for (const fn of suite.functions) {
      if (fn.engines.some((e) => e.toolId === toolId)) {
        return { suiteId: suite.id, functionId: fn.id }
      }
    }
  }
  return { suiteId: "web-suite", functionId: "repeater" }
}

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
      httpsMode: "tls_intercept",
      allowSelfSignedUpstream: false,
      filterText: "",
      selectedEntryId: "",
    },
    "http-intruder": {
      method: "GET",
      url: "http://127.0.0.1:4096/api/§endpoint§",
      headers: [{ id: "ih-1", enabled: true, name: "Accept", value: "application/json" }],
      bodyTemplate: "",
      attackMode: "sniper",
      payloadSet1Text: "info\nhealth\nstatus\nversion",
      payloadSet2Text: "1\n2\n3\n4",
      maxRequests: 50,
      concurrency: 2,
      delayMs: 25,
      timeoutMs: 5000,
      grepMatch: "",
      urlEncodePayloads: true,
      executionMode: "manual",
      useRawJson: false,
      rawJson:
        '{\n  "url": "http://127.0.0.1:4096/api/§endpoint§",\n  "attackMode": "sniper",\n  "payloadSet1": ["info", "health"]\n}',
    },
    "param-audit": {
      url: "http://127.0.0.1:4096/?q=test&redirect=/home",
      method: "GET",
      parameterNamesText: "",
      checkReflectionContext: true,
      checkErrorLeakage: true,
      checkRedirectHygiene: true,
      timeoutMs: 5000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "url": "http://127.0.0.1:4096/?q=test"\n}',
    },
    dalfox: {
      url: "http://127.0.0.1:8080/search?q=test",
      paramName: "q",
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "url": "http://127.0.0.1:8080/search?q=test",\n  "paramName": "q"\n}',
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
      deepCipherAudit: true,
      checkHsts: true,
      timeoutMs: 5000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "host": "127.0.0.1",\n  "port": 443,\n  "deepCipherAudit": true,\n  "checkHsts": true\n}',
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
    "dns-recon": {
      host: "localhost",
      nameserver: "",
      checkEmailPosture: true,
      enumerateSubdomains: true,
      subdomainPrefixesText: "www,api,dev,staging,mail,admin,auth,cdn",
      includeCrtSh: false,
      timeoutMs: 4000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "host": "localhost",\n  "checkEmailPosture": true\n}',
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
    "binary-disasm": {
      binaryPath: "amostra.elf",
      architecture: "auto",
      startOffsetHex: "",
      maxInstructions: 80,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "binaryPath": "amostra.elf",\n  "maxInstructions": 80\n}',
    },
    ghidra: {
      binaryPath: "amostra.elf",
      processor: "",
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "binaryPath": "amostra.elf"\n}',
    },
    "mobile-triage": {
      artifactPath: "aplicativo.apk",
      iocDomainsText: "",
      useRawJson: false,
      rawJson: "{\n  \"artifactPath\": \"aplicativo.apk\"\n}",
    },
    jadx: {
      artifactPath: "aplicativo.apk",
      deobfuscate: true,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "artifactPath": "aplicativo.apk",\n  "deobfuscate": true\n}',
    },
    "yara-scan": {
      targetPath: "cyberlab",
      rulesText: `rule Suspicious_Hardcoded_Token {\n  meta:\n    description = "Detecta cabeçalhos de chave privada ou tokens sensíveis"\n    severity = "medium"\n  strings:\n    $pem = "BEGIN PRIVATE KEY" ascii nocase\n    $jwt = "eyJhbGciOi" ascii\n    $elf = { 7F 45 4C 46 }\n  condition:\n    $pem or $jwt or $elf\n}`,
      maxFiles: 120,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "targetPath": "cyberlab",\n  "rulesText": "rule Demo { strings: $a = \\"CyberLab\\" condition: $a }"\n}',
    },
    yarax: {
      rulesPath: "regras.yar",
      targetPath: "amostra.elf",
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "rulesPath": "regras.yar",\n  "targetPath": "amostra.elf"\n}',
    },
    "api-security-lab": {
      baseUrl: "http://127.0.0.1:4096",
      specPath: "",
      inlineSpecJson: JSON.stringify(
        {
          openapi: "3.0.3",
          info: { title: "CyberLab Demo API", version: "1.0.0" },
          paths: {
            "/api/info": { get: { summary: "System Info" } },
            "/api/cyberlab/status": { get: { summary: "Workspace Status" } },
          },
        },
        null,
        2,
      ),
      userAAuthHeader: "Bearer token-user-a-example",
      userBAuthHeader: "Bearer token-user-b-example",
      testUnauthenticated: true,
      maxEndpoints: 12,
      graphqlUrl: "",
      graphqlTestBatching: true,
      graphqlMaxDepthProbe: 6,
      issuerUrl: "",
      authorizeUrl: "",
      timeoutMs: 6000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "baseUrl": "http://127.0.0.1:4096",\n  "testUnauthenticated": true\n}',
    },
    "key-hunter": {
      subpath: ".",
      targetUrl: "",
      rawText: "",
      githubRepoOrOrg: "",
      githubQuery: "(T3BlbkFJ OR sk-ant-api03 OR sk_live_ OR AKIA)",
      providerFilter: "all",
      skipPlaceholders: true,
      carveCryptoMaterial: true,
      verifyActive: false,
      maxFiles: 250,
      maxRemoteScripts: 10,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "subpath": ".",\n  "skipPlaceholders": true,\n  "carveCryptoMaterial": true,\n  "verifyActive": false\n}',
    },
    "keyhunter-cli": {
      subcommand: "scan",
      provider: "openai",
      query: "",
      configPath: "",
      inputFindingsPath: "",
      outputFormat: "json",
      verifiedOnly: false,
      verbose: false,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "subcommand": "scan",\n  "provider": "openai",\n  "outputFormat": "json"\n}',
    },
    "sca-sbom-iac": {
      targetPath: ".",
      queryOsv: false,
      generateCycloneDx: true,
      auditIac: true,
      maxFiles: 200,
      timeoutMs: 8000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "targetPath": ".",\n  "generateCycloneDx": true,\n  "auditIac": true\n}',
    },
    trivy: {
      targetPath: ".",
      scanners: "vuln,misconfig",
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "targetPath": ".",\n  "scanners": "vuln,misconfig"\n}',
    },
    "dfir-sigma": {
      logPath: "logs/auth.log",
      logFormat: "auto",
      useBuiltinSigma: true,
      sigmaRulesPath: "",
      inlineSigmaYaml: "",
      maxEvents: 5000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "logPath": "logs/auth.log",\n  "useBuiltinSigma": true\n}',
    },
    "ad-smb-ldap": {
      host: "127.0.0.1",
      checkSmbSigning: true,
      smbPort: 445,
      checkLdapRootDse: true,
      ldapPort: 389,
      ntlmHttpUrl: "",
      timeoutMs: 4000,
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "host": "127.0.0.1",\n  "checkSmbSigning": true,\n  "checkLdapRootDse": true\n}',
    },
    "entropy-recipe": {
      targetPath: "package.json",
      windowSize: 64,
      rawInput: "Q3liZXJMYWIgT1MgUmVjaXBlIFN0dWRpbw==",
      inputEncoding: "utf8",
      recipeSteps: [
        {
          id: "step-1",
          op: "from_base64",
          key: "",
          keyEncoding: "utf8",
          ivHex: "",
          authTagHex: "",
          minLength: 4,
        },
      ],
      newRecipeName: "",
      savedRecipes: [
        {
          id: "preset-b64-gunzip",
          name: "Base64 → Gunzip → Strings",
          steps: [
            { id: "s1", op: "from_base64", key: "", keyEncoding: "utf8", ivHex: "", authTagHex: "", minLength: 4 },
            { id: "s2", op: "gunzip", key: "", keyEncoding: "utf8", ivHex: "", authTagHex: "", minLength: 4 },
            { id: "s3", op: "extract_strings", key: "", keyEncoding: "utf8", ivHex: "", authTagHex: "", minLength: 4 },
          ],
        },
        {
          id: "preset-hex-xor1",
          name: "Hex → XOR Brute-Force 1-Byte",
          steps: [
            { id: "x1", op: "from_hex", key: "", keyEncoding: "utf8", ivHex: "", authTagHex: "", minLength: 4 },
            { id: "x2", op: "xor_single_byte_bruteforce", key: "", keyEncoding: "utf8", ivHex: "", authTagHex: "", minLength: 4 },
          ],
        },
      ],
      executionMode: "manual",
      useRawJson: false,
      rawJson: '{\n  "targetPath": "package.json",\n  "windowSize": 256\n}',
    },
    "cdi-hub": {
      cdiSubTab: "dispatch",
      selectedPartnerIds: ["kairos"],
      objective: "Explorar conjuntamente as evidências recolhidas e partilhar hipóteses independentes dentro do escopo curado",
      contextText: "",
      selectedEvidenceIds: [],
      timeoutMs: 30000,
      customSecretInput: "",
      editingPartnerId: "",
      editDisplayName: "",
      editSpecialty: "",
      editEndpointUrl: "",
      editIdentityNotes: "",
      editInterestsText: "",
      editInitiateActions: "autonomous_in_scope",
      editReadProjectState: true,
      editReadEvidenceAndFiles: true,
      editCreateArtifactsAndFindings: true,
      editEnabled: true,
      editSecretOverride: "",
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
        deepCipherAudit: Boolean(d.deepCipherAudit),
        checkHsts: Boolean(d.checkHsts),
        timeoutMs: Math.min(10000, Math.max(200, Math.trunc(Number(d.timeoutMs) || 5000))),
      }
      if (d.servername.trim()) input.servername = d.servername.trim()
      return {
        capabilityId: "network-assessment.tls-inspector",
        mode: d.executionMode,
        targetSummary: `TLS ${d.host.trim()}:${input.port}${d.deepCipherAudit ? " [Deep+Grade]" : ""}${d.servername.trim() ? ` (SNI: ${d.servername.trim()})` : ""}`,
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
    case "http-intruder": {
      const d = drafts["http-intruder"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "web-assessment.http-intruder",
          mode: d.executionMode,
          targetSummary: String(parsed.url ?? d.url),
          input: parsed,
        }
      }
      const payloadSet1 = d.payloadSet1Text
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
      const payloadSet2 = d.payloadSet2Text
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
      const headers = rowsToRecord(d.headers)
      const input: Record<string, unknown> = {
        url: d.url.trim(),
        method: d.method,
        attackMode: d.attackMode,
        payloadSet1,
        maxRequests: Math.min(200, Math.max(1, Math.trunc(Number(d.maxRequests) || 50))),
        concurrency: Math.min(5, Math.max(1, Math.trunc(Number(d.concurrency) || 2))),
        delayMs: Math.min(5000, Math.max(0, Math.trunc(Number(d.delayMs) || 0))),
        timeoutMs: Math.min(20000, Math.max(500, Math.trunc(Number(d.timeoutMs) || 5000))),
        urlEncodePayloads: d.urlEncodePayloads,
      }
      if (headers) input.headers = headers
      if (d.bodyTemplate.length > 0) input.bodyTemplate = d.bodyTemplate
      if (d.attackMode === "pitchfork" && payloadSet2.length > 0) input.payloadSet2 = payloadSet2
      if (d.grepMatch.trim()) input.grepMatch = d.grepMatch.trim()
      return {
        capabilityId: "web-assessment.http-intruder",
        mode: d.executionMode,
        targetSummary: `Intruder ${d.attackMode} ${d.method} ${d.url.trim()} (${payloadSet1.length} payloads)`,
        input,
      }
    }
    case "param-audit": {
      const d = drafts["param-audit"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "web-assessment.param-audit",
          mode: d.executionMode,
          targetSummary: String(parsed.url ?? d.url),
          input: parsed,
        }
      }
      const parameterNames = d.parameterNamesText
        .split(/[\r\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
      const input: Record<string, unknown> = {
        url: d.url.trim(),
        method: d.method,
        checkReflectionContext: d.checkReflectionContext,
        checkErrorLeakage: d.checkErrorLeakage,
        checkRedirectHygiene: d.checkRedirectHygiene,
        timeoutMs: Math.min(15000, Math.max(500, Math.trunc(Number(d.timeoutMs) || 5000))),
      }
      if (parameterNames.length > 0) input.parameterNames = parameterNames
      return {
        capabilityId: "web-assessment.param-audit",
        mode: d.executionMode,
        targetSummary: `Param Audit ${d.method} ${d.url.trim()}`,
        input,
      }
    }
    case "dalfox": {
      const d = drafts.dalfox
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.dalfox-param-scan",
          mode: d.executionMode,
          targetSummary: String(parsed.url ?? d.url),
          input: parsed,
        }
      }
      const input: Record<string, unknown> = { url: d.url.trim() }
      if (d.paramName.trim()) input.paramName = d.paramName.trim()
      return {
        capabilityId: "external.dalfox-param-scan",
        mode: d.executionMode,
        targetSummary: `Dalfox ${d.url.trim()}`,
        input,
      }
    }
    case "dns-recon": {
      const d = drafts["dns-recon"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "network-assessment.dns-recon",
          mode: d.executionMode,
          targetSummary: String(parsed.host ?? d.host),
          input: parsed,
        }
      }
      const subdomainPrefixes = d.subdomainPrefixesText
        .split(/[\r\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
      const input: Record<string, unknown> = {
        host: d.host.trim(),
        checkEmailPosture: d.checkEmailPosture,
        enumerateSubdomains: d.enumerateSubdomains,
        includeCrtSh: d.includeCrtSh,
        timeoutMs: Math.min(15000, Math.max(800, Math.trunc(Number(d.timeoutMs) || 4000))),
      }
      if (d.nameserver.trim()) input.nameserver = d.nameserver.trim()
      if (subdomainPrefixes.length > 0) input.subdomainPrefixes = subdomainPrefixes
      return {
        capabilityId: "network-assessment.dns-recon",
        mode: d.executionMode,
        targetSummary: `DNS Recon ${d.host.trim()}${d.includeCrtSh ? " + crt.sh" : ""}`,
        input,
      }
    }
    case "binary-disasm": {
      const d = drafts["binary-disasm"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "reverse-engineering.binary-disasm",
          mode: d.executionMode,
          targetSummary: String(parsed.binaryPath ?? d.binaryPath),
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        binaryPath: d.binaryPath.trim(),
        architecture: d.architecture,
        maxInstructions: Math.min(256, Math.max(8, Math.trunc(Number(d.maxInstructions) || 80))),
      }
      if (d.startOffsetHex.trim()) {
        input.startOffsetHex = d.startOffsetHex.trim()
      }
      return {
        capabilityId: "reverse-engineering.binary-disasm",
        mode: d.executionMode,
        targetSummary: `Disasm (${d.architecture}) ${d.binaryPath.trim()}`,
        input,
      }
    }
    case "ghidra": {
      const d = drafts.ghidra
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.ghidra-decompile",
          mode: d.executionMode,
          targetSummary: String(parsed.binaryPath ?? d.binaryPath),
          input: parsed,
        }
      }
      const input: Record<string, unknown> = { binaryPath: d.binaryPath.trim() }
      if (d.processor.trim()) input.processor = d.processor.trim()
      return {
        capabilityId: "external.ghidra-decompile",
        mode: d.executionMode,
        targetSummary: `Ghidra Headless ${d.binaryPath.trim()}`,
        input,
      }
    }
    case "jadx": {
      const d = drafts.jadx
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.jadx-decompile",
          mode: d.executionMode,
          targetSummary: String(parsed.artifactPath ?? d.artifactPath),
          input: parsed,
        }
      }
      return {
        capabilityId: "external.jadx-decompile",
        mode: d.executionMode,
        targetSummary: `JADX ${d.artifactPath.trim()}`,
        input: {
          artifactPath: d.artifactPath.trim(),
          deobfuscate: d.deobfuscate,
        },
      }
    }
    case "yara-scan": {
      const d = drafts["yara-scan"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "forensics.yara-scan",
          mode: d.executionMode,
          targetSummary: String(parsed.targetPath ?? d.targetPath),
          input: parsed,
        }
      }
      return {
        capabilityId: "forensics.yara-scan",
        mode: d.executionMode,
        targetSummary: `YARA Scan ${d.targetPath.trim()}`,
        input: {
          targetPath: d.targetPath.trim(),
          rulesText: d.rulesText,
          maxFiles: Math.min(500, Math.max(1, Math.trunc(Number(d.maxFiles) || 120))),
        },
      }
    }
    case "yarax": {
      const d = drafts.yarax
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.yarax-scan",
          mode: d.executionMode,
          targetSummary: String(parsed.targetPath ?? d.targetPath),
          input: parsed,
        }
      }
      return {
        capabilityId: "external.yarax-scan",
        mode: d.executionMode,
        targetSummary: `YARA-X ${d.rulesPath.trim()} → ${d.targetPath.trim()}`,
        input: {
          rulesPath: d.rulesPath.trim(),
          targetPath: d.targetPath.trim(),
        },
      }
    }
    case "api-security-lab": {
      const d = drafts["api-security-lab"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "web-assessment.api-graphql-oauth-lab",
          mode: d.executionMode,
          targetSummary: String(parsed.baseUrl ?? parsed.graphqlUrl ?? parsed.issuerUrl ?? "API Lab"),
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        testUnauthenticated: d.testUnauthenticated,
        checkGraphqlIntrospection: true,
        checkGraphqlBatchingAndDepth: d.graphqlTestBatching,
        timeoutMs: Math.min(15000, Math.max(500, Math.trunc(Number(d.timeoutMs) || 6000))),
      }
      if (d.baseUrl.trim()) input.baseUrl = d.baseUrl.trim()
      if (d.specPath.trim()) input.specPath = d.specPath.trim()
      if (d.inlineSpecJson.trim()) input.specJsonText = d.inlineSpecJson
      if (d.userAAuthHeader.trim()) input.authHeaderA = d.userAAuthHeader.trim()
      if (d.userBAuthHeader.trim()) input.authHeaderB = d.userBAuthHeader.trim()
      if (d.graphqlUrl.trim()) input.graphqlUrl = d.graphqlUrl.trim()
      if (d.issuerUrl.trim()) input.issuerUrl = d.issuerUrl.trim()
      if (d.authorizeUrl.trim()) input.authorizeUrl = d.authorizeUrl.trim()
      const parts = [d.baseUrl.trim(), d.graphqlUrl.trim(), d.issuerUrl.trim()].filter(Boolean)
      return {
        capabilityId: "web-assessment.api-graphql-oauth-lab",
        mode: d.executionMode,
        targetSummary: `API/GraphQL/OAuth (${parts[0] ?? "Inline Spec"})`,
        input,
      }
    }
    case "key-hunter": {
      const d = drafts["key-hunter"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "code-analysis.key-hunter",
          mode: d.executionMode,
          targetSummary: `Key Hunter → ${String(parsed.subpath ?? parsed.targetUrl ?? "Custom JSON")}`,
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        skipPlaceholders: d.skipPlaceholders,
        carveCryptoMaterial: d.carveCryptoMaterial,
        verifyActive: d.verifyActive,
        maxFiles: Math.min(1000, Math.max(1, Math.trunc(Number(d.maxFiles) || 250))),
        maxRemoteScripts: Math.min(30, Math.max(0, Math.trunc(Number(d.maxRemoteScripts) || 10))),
      }
      if (d.subpath.trim()) input.subpath = d.subpath.trim()
      if (d.targetUrl.trim()) input.targetUrl = d.targetUrl.trim()
      if (d.rawText.trim()) input.rawText = d.rawText
      if (d.githubRepoOrOrg.trim()) {
        input.githubRepoOrOrg = d.githubRepoOrOrg.trim()
        if (d.githubQuery.trim()) input.githubQuery = d.githubQuery.trim()
      }
      if (d.providerFilter.trim() && d.providerFilter.trim().toLowerCase() !== "all") {
        input.providerFilter = d.providerFilter.trim()
      }
      const targetsLabel = [
        d.subpath.trim() ? `path:${d.subpath.trim()}` : "",
        d.targetUrl.trim() ? `url:${d.targetUrl.trim()}` : "",
        d.rawText.trim() ? "buffer" : "",
        d.githubRepoOrOrg.trim() ? `gh:${d.githubRepoOrOrg.trim()}` : "",
      ]
        .filter(Boolean)
        .join(" + ")
      return {
        capabilityId: "code-analysis.key-hunter",
        mode: d.executionMode,
        targetSummary: `Key Hunter (${targetsLabel || "workspace"})${d.verifyActive ? " [Verify]" : ""}`,
        input,
      }
    }
    case "keyhunter-cli": {
      const d = drafts["keyhunter-cli"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.keyhunter-cli",
          mode: d.executionMode,
          targetSummary: `KeyHunter CLI (${String(parsed.subcommand ?? d.subcommand)})`,
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        subcommand: d.subcommand,
        outputFormat: d.outputFormat,
        verifiedOnly: d.verifiedOnly,
        verbose: d.verbose,
      }
      if (d.provider.trim()) input.provider = d.provider.trim()
      if (d.query.trim()) input.query = d.query.trim()
      if (d.configPath.trim()) input.configPath = d.configPath.trim()
      if (d.inputFindingsPath.trim()) input.inputFindingsPath = d.inputFindingsPath.trim()
      return {
        capabilityId: "external.keyhunter-cli",
        mode: d.executionMode,
        targetSummary: `keyhunter ${d.subcommand}${d.provider.trim() && d.subcommand === "scan" ? ` -p ${d.provider.trim()}` : ""}`,
        input,
      }
    }
    case "sca-sbom-iac": {
      const d = drafts["sca-sbom-iac"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "code-analysis.sca-sbom-iac-audit",
          mode: d.executionMode,
          targetSummary: `SCA/SBOM/IaC ${String(parsed.subpath ?? d.targetPath)}`,
          input: parsed,
        }
      }
      const subpath = d.targetPath.trim() || "."
      return {
        capabilityId: "code-analysis.sca-sbom-iac-audit",
        mode: d.executionMode,
        targetSummary: `SCA/SBOM/IaC ${subpath}${d.queryOsv ? " + OSV.dev" : ""}`,
        input: {
          subpath,
          queryOsvDev: d.queryOsv,
          generateCycloneDxSbom: d.generateCycloneDx,
          auditContainersAndIac: d.auditIac,
          maxFiles: Math.min(500, Math.max(5, Math.trunc(Number(d.maxFiles) || 200))),
        },
      }
    }
    case "trivy": {
      const d = drafts.trivy
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "external.trivy-scan",
          mode: d.executionMode,
          targetSummary: `Trivy ${String(parsed.targetPath ?? d.targetPath)}`,
          input: parsed,
        }
      }
      const targetPath = d.targetPath.trim() || "."
      const scanners = d.scanners.trim() || "vuln,misconfig"
      return {
        capabilityId: "external.trivy-scan",
        mode: d.executionMode,
        targetSummary: `Trivy (${scanners}) → ${targetPath}`,
        input: {
          targetPath,
          scanners,
        },
      }
    }
    case "dfir-sigma": {
      const d = drafts["dfir-sigma"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "forensics.dfir-sigma-triage",
          mode: d.executionMode,
          targetSummary: `DFIR Sigma ${String(parsed.logPath ?? d.logPath)}`,
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        includeBuiltinRules: d.useBuiltinSigma,
        maxEvents: Math.min(10000, Math.max(10, Math.trunc(Number(d.maxEvents) || 5000))),
      }
      if (d.logPath.trim()) input.logPath = d.logPath.trim()
      if (d.sigmaRulesPath.trim()) input.sigmaRulesPath = d.sigmaRulesPath.trim()
      if (d.inlineSigmaYaml.trim()) input.sigmaRulesYaml = d.inlineSigmaYaml
      return {
        capabilityId: "forensics.dfir-sigma-triage",
        mode: d.executionMode,
        targetSummary: `DFIR Sigma → ${d.logPath.trim() || "Inline"}`,
        input,
      }
    }
    case "ad-smb-ldap": {
      const d = drafts["ad-smb-ldap"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "network-assessment.ad-smb-ldap-inspector",
          mode: d.executionMode,
          targetSummary: `AD/SMB/LDAP ${String(parsed.host ?? d.host)}`,
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        host: d.host.trim(),
        checkSmbSigning: d.checkSmbSigning,
        smbPort: Math.min(65535, Math.max(1, Math.trunc(Number(d.smbPort) || 445))),
        checkLdapRootDse: d.checkLdapRootDse,
        ldapPort: Math.min(65535, Math.max(1, Math.trunc(Number(d.ldapPort) || 389))),
        timeoutMs: Math.min(10000, Math.max(300, Math.trunc(Number(d.timeoutMs) || 4000))),
      }
      if (d.ntlmHttpUrl.trim()) input.ntlmHttpUrl = d.ntlmHttpUrl.trim()
      return {
        capabilityId: "network-assessment.ad-smb-ldap-inspector",
        mode: d.executionMode,
        targetSummary: `AD/SMB/LDAP ${d.host.trim()}${d.ntlmHttpUrl.trim() ? " + NTLM" : ""}`,
        input,
      }
    }
    case "entropy-recipe": {
      const d = drafts["entropy-recipe"]
      if (d.useRawJson) {
        const parsed = JSON.parse(d.rawJson) as Record<string, unknown>
        return {
          capabilityId: "reverse-engineering.entropy-recipe-studio",
          mode: d.executionMode,
          targetSummary: `Entropia/CyberChef ${String(parsed.filePath ?? "Recipe")}`,
          input: parsed,
        }
      }
      const input: Record<string, unknown> = {
        bucketCount: Math.min(256, Math.max(8, Math.trunc(Number(d.windowSize) || 64))),
      }
      if (d.targetPath.trim()) input.filePath = d.targetPath.trim()
      if (d.rawInput.length > 0) input.inputText = d.rawInput
      if (d.recipeSteps.length > 0) {
        input.recipeSteps = d.recipeSteps.slice(0, 16).map((s) => {
          const step: Record<string, unknown> = { op: s.op }
          if (s.key) {
            step.keyHexOrUtf8 = s.key
          }
          if (s.ivHex.trim()) {
            const combinedIv =
              s.op === "aes_gcm_decrypt" && s.authTagHex.trim()
                ? `${s.ivHex.trim()}:${s.authTagHex.trim()}`
                : s.ivHex.trim()
            step.ivHex = combinedIv
          }
          return step
        })
      }
      return {
        capabilityId: "reverse-engineering.entropy-recipe-studio",
        mode: d.executionMode,
        targetSummary: `${d.targetPath.trim() ? `Entropia ${d.targetPath.trim()}` : "Buffer"}${d.recipeSteps.length ? ` + ${d.recipeSteps.length} etapas` : ""}`,
        input,
      }
    }
    default:
      throw new Error(`A ferramenta "${toolId}" utiliza controlador especializado direto.`)
  }
}
