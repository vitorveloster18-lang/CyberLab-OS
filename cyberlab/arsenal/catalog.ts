/**
 * CyberLab OS v5.0 — Official Real External Arsenal Catalog
 *
 * Zero crippled internal clones: every slot connects to the genuine upstream tool
 * installed outside the repository (Windows native, C:\CyberLab-Tools, PATH, or WSL2 Kali Linux),
 * plus unlimited user-defined Custom Slots.
 */

export type ArsenalCategory =
  | "web_proxy_suite"
  | "web_bounty_cli"
  | "recon_network_ad"
  | "reverse_mobile"
  | "secrets_sast_cloud"
  | "cyberchef_dfir_kali"
  | "custom"

export type ArsenalSlotKind = "web_embed" | "desktop_gui" | "cli_runner"

export type ArsenalRuntimePreference = "auto" | "windows" | "wsl" | "linux_mac"

export interface ArsenalPresetCommand {
  id: string
  label: string
  description: string
  argsTemplate: string
}

export interface ArsenalSlotDefinition {
  slotId: string
  name: string
  shortLabel: string
  category: ArsenalCategory
  kind: ArsenalSlotKind
  tagline: string
  description: string
  upstreamUrl: string
  licenseNote: string
  isCustom?: boolean
  /** Candidate binary names on Windows */
  windowsBinaries: string[]
  /** Well-known Windows installation paths (supports %LOCALAPPDATA%, %ProgramFiles%, %USERPROFILE%, {toolsRoot}) */
  windowsKnownPaths?: string[]
  /** Candidate binary names on Linux / WSL2 Kali / macOS */
  posixBinaries: string[]
  /** Well-known Linux / WSL2 paths (supports ~, {toolsRoot}) */
  posixKnownPaths?: string[]
  /** For web_embed slots: default URL or local static directory pattern */
  defaultEmbedUrl?: string
  /** Optional local HTML folder inside {toolsRoot} served automatically via loopback HTTP (e.g. CyberChef) */
  localStaticDirSubpath?: string
  /** Optional managed daemon launch args when starting a web_embed backend locally */
  managedDaemonArgs?: string[]
  managedDaemonPort?: number
  /** Proxy port if this tool exposes an intercepting proxy for the 1-Click Isolated Browser */
  companionProxyPort?: number
  /** Exact Windows PowerShell installation command */
  installPowerShell: string
  /** Exact WSL2 Kali Linux installation command */
  installKaliWsl: string
  /** Ready-to-use real-world command presets (editable freely by operator) */
  presets: ArsenalPresetCommand[]
}

export const ARSENAL_CATEGORY_LABELS: Record<ArsenalCategory, { title: string; subtitle: string }> = {
  web_proxy_suite: {
    title: "Proxies, Interceptação & Suites Web",
    subtitle: "Burp Suite, OpenTRAP, mitmweb, Caido e OWASP ZAP",
  },
  web_bounty_cli: {
    title: "Bug Bounty Web, Fuzzing & OAST",
    subtitle: "Nuclei, ffuf, Katana, httpx, Interactsh, Dalfox e sqlmap",
  },
  recon_network_ad: {
    title: "Recon, Rede, Pacotes & Active Directory",
    subtitle: "Subfinder, Nmap, Wireshark/tshark, Naabu/DNSx/TLSx, NetExec e BloodHound",
  },
  reverse_mobile: {
    title: "Engenharia Reversa, Malware & Mobile",
    subtitle: "Ghidra, JADX, Rizin/Cutter, Frida/Apktool e Mandiant Capa",
  },
  secrets_sast_cloud: {
    title: "Key Hunting, SAST, SCA & Cloud",
    subtitle: "KeyHunter Rust, Gitleaks, TruffleHog, Semgrep e Aqua Trivy",
  },
  cyberchef_dfir_kali: {
    title: "CyberChef Oficial, DFIR & Kali Desktop",
    subtitle: "GCHQ CyberChef 100% embutido, Hayabusa, YARA-X e Kali Win-KeX / noVNC",
  },
  custom: {
    title: "Meus Slots Personalizados",
    subtitle: "Ferramentas extras, scripts próprios e novas suítes adicionadas por você",
  },
}

export const OFFICIAL_ARSENAL_SLOTS: ArsenalSlotDefinition[] = [
  // =========================================================================
  // 1. PROXIES, INTERCEPTAÇÃO & SUITES WEB
  // =========================================================================
  {
    slotId: "burp-suite",
    name: "Burp Suite Community / Pro",
    shortLabel: "Burp Suite",
    category: "web_proxy_suite",
    kind: "desktop_gui",
    tagline: "Proxy interceptador e Repeater padrão da indústria + Navegador Isolado 1-Clique (:8080)",
    description:
      "Abre o seu Burp Suite Community/Pro instalado no Windows (ou Kali), conecta em 1 clique um navegador Chrome/Edge isolado direto na porta 8080 sem mexer nos certificados do Windows e sincroniza exports XML/logs com a IA e os 4 CDIs.",
    upstreamUrl: "https://portswigger.net/burp/communitydownload",
    licenseNote: "Proprietary Free / Pro (Externo)",
    windowsBinaries: ["BurpSuiteCommunity.exe", "BurpSuitePro.exe"],
    windowsKnownPaths: [
      "%LOCALAPPDATA%\\Programs\\BurpSuiteCommunity\\BurpSuiteCommunity.exe",
      "%LOCALAPPDATA%\\Programs\\BurpSuitePro\\BurpSuitePro.exe",
      "%ProgramFiles%\\BurpSuiteCommunity\\BurpSuiteCommunity.exe",
      "%ProgramFiles%\\BurpSuitePro\\BurpSuitePro.exe",
      "{toolsRoot}\\BurpSuite\\BurpSuiteCommunity.exe",
    ],
    posixBinaries: ["burpsuite"],
    posixKnownPaths: ["/usr/bin/burpsuite", "/opt/BurpSuiteCommunity/BurpSuiteCommunity"],
    companionProxyPort: 8080,
    installPowerShell: "winget install --id PortSwigger.BurpSuite.Community -e",
    installKaliWsl: "sudo apt update && sudo apt install -y burpsuite",
    presets: [],
  },
  {
    slotId: "opentrap",
    name: "OpenTRAP (ZAP Active Scanner + Intruder s/ Limite + Collaborator)",
    shortLabel: "OpenTRAP",
    category: "web_proxy_suite",
    kind: "desktop_gui",
    tagline: "Complemento perfeito ao Burp Community: Active Scanner real, Intruder rápido e Collaborator gratuito",
    description:
      "Roda o OpenTRAP oficial via WSL2 Kali Linux (janela nativa WSLg no Windows 11 ou dentro da aba via Kali Win-KeX/noVNC), entregando tudo que o Burp Community bloqueia: Active Scanner (OWASP ZAP), Intruder sem limite de velocidade, Collaborator (Interactsh) e projetos salvos.",
    upstreamUrl: "https://github.com/opentrap/opentrap",
    licenseNote: "AGPL-3.0 (Externo em WSL2 / Linux)",
    windowsBinaries: [],
    posixBinaries: ["opentrap", "OpenTRAP.AppImage", "opentrap-x86_64.appimage"],
    posixKnownPaths: [
      "/opt/opentrap/OpenTRAP.AppImage",
      "/opt/opentrap/opentrap-x86_64.appimage",
      "/usr/local/bin/opentrap",
      "~/CyberLab-Tools/opentrap/opentrap-x86_64.appimage",
      "~/.local/bin/opentrap",
    ],
    companionProxyPort: 8080,
    installPowerShell:
      'wsl -d kali-linux -u root -- bash -lc "mkdir -p /opt/opentrap && curl -fL https://github.com/opentrap/opentrap/releases/latest/download/opentrap-x86_64.appimage -o /opt/opentrap/OpenTRAP.AppImage && chmod +x /opt/opentrap/OpenTRAP.AppImage && ln -sf /opt/opentrap/OpenTRAP.AppImage /usr/local/bin/opentrap"',
    installKaliWsl:
      "sudo mkdir -p /opt/opentrap && sudo curl -fL https://github.com/opentrap/opentrap/releases/latest/download/opentrap-x86_64.appimage -o /opt/opentrap/OpenTRAP.AppImage && sudo chmod +x /opt/opentrap/OpenTRAP.AppImage && sudo ln -sf /opt/opentrap/OpenTRAP.AppImage /usr/local/bin/opentrap",
    presets: [
      {
        id: "opentrap-wslg",
        label: "Iniciar OpenTRAP (AppImage via WSLg)",
        description: "Executa o AppImage oficial com --appimage-extract-and-run (funciona mesmo sem FUSE no WSL2)",
        argsTemplate: "--appimage-extract-and-run",
      },
    ],
  },
  {
    slotId: "mitmweb",
    name: "mitmproxy (mitmweb Oficial Embutido na Aba)",
    shortLabel: "mitmweb",
    category: "web_proxy_suite",
    kind: "web_embed",
    tagline: "Interface Web oficial do mitmproxy aberta 100% dentro do centro do CyberLab OS",
    description:
      "Inicia o daemon oficial `mitmweb` (UI na porta 8081, Proxy HTTP/HTTPS/HTTP2/WS na porta 8082) e abre a interface original completa do mitmproxy direto no painel central, com replay, interceptação por expressão, scripts Python e export cURL.",
    upstreamUrl: "https://mitmproxy.org/",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["mitmweb.exe", "mitmweb"],
    windowsKnownPaths: [
      "%ProgramFiles%\\mitmproxy\\bin\\mitmweb.exe",
      "%LOCALAPPDATA%\\Programs\\Python\\Python312\\Scripts\\mitmweb.exe",
      "{toolsRoot}\\mitmproxy\\mitmweb.exe",
    ],
    posixBinaries: ["mitmweb"],
    defaultEmbedUrl: "http://127.0.0.1:8081",
    managedDaemonPort: 8081,
    managedDaemonArgs: [
      "--web-host",
      "127.0.0.1",
      "--web-port",
      "8081",
      "--listen-host",
      "127.0.0.1",
      "--listen-port",
      "8082",
      "--no-web-open-browser",
      "--set",
      "web_password=",
    ],
    companionProxyPort: 8082,
    installPowerShell: "winget install --id mitmproxy.mitmproxy -e",
    installKaliWsl: "sudo apt update && sudo apt install -y mitmproxy",
    presets: [],
  },
  {
    slotId: "caido",
    name: "Caido (Toolkit Web Security em Rust — UI Web Nativa)",
    shortLabel: "Caido",
    category: "web_proxy_suite",
    kind: "web_embed",
    tagline: "Alternativa ultrarrápida ao Burp que já roda nativamente em interface Web (:7000)",
    description:
      "Inicia o Caido CLI local na porta 7000 e incorpora sua interface completa direto no painel central do CyberLab OS (Intercept, HTTP History, Replay, Automate, Match & Replace e Workflows).",
    upstreamUrl: "https://caido.io/",
    licenseNote: "Proprietary Free / Pro (Externo)",
    windowsBinaries: ["caido-cli.exe", "Caido.exe", "caido.exe"],
    windowsKnownPaths: [
      "{toolsRoot}\\caido\\caido-cli.exe",
      "%LOCALAPPDATA%\\Programs\\caido\\Caido.exe",
      "%LOCALAPPDATA%\\Programs\\Caido\\Caido.exe",
      "%LOCALAPPDATA%\\caido\\Caido.exe",
      "%ProgramFiles%\\Caido\\Caido.exe",
    ],
    posixBinaries: ["caido-cli", "caido"],
    defaultEmbedUrl: "http://127.0.0.1:7000",
    managedDaemonPort: 7000,
    managedDaemonArgs: ["--listen", "127.0.0.1:7000", "--no-open"],
    companionProxyPort: 7000,
    installPowerShell: "winget install --id Caido.Caido -e",
    installKaliWsl:
      "# Baixe o caido-cli Linux x86_64 em https://caido.io/download para ~/CyberLab-Tools/caido/caido-cli",
    presets: [],
  },
  {
    slotId: "owasp-zap",
    name: "OWASP ZAP (Active Scanner Completo + AJAX Spider + HUD)",
    shortLabel: "OWASP ZAP",
    category: "web_proxy_suite",
    kind: "desktop_gui",
    tagline: "Scanner ativo completo Apache-2.0 nativo p/ Windows e Kali + HUD direto no navegador",
    description:
      "Executa o OWASP ZAP completo (Desktop ou Daemon/Baseline Scan) com centenas de plugins reais de SQLi, XSS, SSRF, Path Traversal, XXE, AJAX Spider com navegador headless e ZAP HUD.",
    upstreamUrl: "https://www.zaproxy.org/",
    licenseNote: "Apache-2.0 (Externo)",
    windowsBinaries: ["zap.bat", "ZAP.exe"],
    windowsKnownPaths: [
      "%ProgramFiles%\\ZAP\\Zed Attack Proxy\\zap.bat",
      "%ProgramFiles%\\OWASP\\Zed Attack Proxy\\zap.bat",
      "{toolsRoot}\\ZAP\\zap.bat",
    ],
    posixBinaries: ["zaproxy", "zap.sh"],
    posixKnownPaths: ["/usr/share/zaproxy/zap.sh", "/usr/bin/zaproxy"],
    companionProxyPort: 8090,
    installPowerShell: "winget install --id ZAP.ZAP -e",
    installKaliWsl: "sudo apt update && sudo apt install -y zaproxy",
    presets: [
      {
        id: "zap-quick-scan",
        label: "ZAP Quick Scan CLI c/ Relatório HTML",
        description: "Executa crawl + auditoria rápida contra {target} salvando relatório em .cyberlab/outputs/",
        argsTemplate: "-cmd -quickurl {target} -quickout {outputs}/zap-report.html -port 8090",
      },
    ],
  },

  // =========================================================================
  // 2. BUG BOUNTY WEB, FUZZING, CRAWLING & OAST
  // =========================================================================
  {
    slotId: "nuclei",
    name: "ProjectDiscovery Nuclei (11.000+ Templates Oficiais)",
    shortLabel: "Nuclei",
    category: "web_bounty_cli",
    kind: "cli_runner",
    tagline: "Scanner oficial de CVEs, misconfigs, takeovers, OAST e exposições em Bug Bounty",
    description:
      "Executa o binário real do Nuclei com a base completa de templates da comunidade ProjectDiscovery, suporte a rate-limit, cabeçalhos X-Bug-Bounty e exportação JSONL direto para o CyberLab OS.",
    upstreamUrl: "https://github.com/projectdiscovery/nuclei",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["nuclei.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\nuclei.exe", "%USERPROFILE%\\go\\bin\\nuclei.exe"],
    posixBinaries: ["nuclei"],
    posixKnownPaths: ["~/go/bin/nuclei", "/usr/bin/nuclei", "~/.pdtm/go/bin/nuclei"],
    installPowerShell: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    installKaliWsl: "sudo apt update && sudo apt install -y nuclei && nuclei -update-templates",
    presets: [
      {
        id: "nuclei-bounty-safe",
        label: "Scan Bug Bounty (CVEs, Exposures & Misconfigs c/ Rate-Limit)",
        description: "Varre {target} respeitando rate-limit e header do programa",
        argsTemplate: "-u {target} -tags cve,exposure,misconfig,takeover -rl 25 {bounty_header_flag} -o {outputs}/nuclei-findings.txt",
      },
      {
        id: "nuclei-tech",
        label: "Fingerprinting de Tecnologias (WAF / Stack / Painéis)",
        description: "Detecta stack tecnológica sem payloads intrusivos",
        argsTemplate: "-u {target} -tags tech,panel -rl 30 {bounty_header_flag}",
      },
      {
        id: "nuclei-update",
        label: "Atualizar Base Oficial de Templates (-ut)",
        description: "Baixa os últimos templates publicados pela ProjectDiscovery",
        argsTemplate: "-update-templates",
      },
    ],
  },
  {
    slotId: "ffuf",
    name: "ffuf — Fuzz Faster U Fool",
    shortLabel: "ffuf",
    category: "web_bounty_cli",
    kind: "cli_runner",
    tagline: "Fuzzer Web em Go sem trava de velocidade (substitui o Intruder limitado do Burp Community!)",
    description:
      "Descoberta ultrarrápida de diretórios, APIs ocultas, parâmetros GET/POST, Virtual Hosts e fuzzing autenticado com auto-calibração (-ac) contra páginas Soft-404.",
    upstreamUrl: "https://github.com/ffuf/ffuf",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["ffuf.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\ffuf.exe", "%USERPROFILE%\\go\\bin\\ffuf.exe"],
    posixBinaries: ["ffuf"],
    posixKnownPaths: ["~/go/bin/ffuf", "/usr/bin/ffuf"],
    installPowerShell: "go install github.com/ffuf/ffuf/v2@latest",
    installKaliWsl: "sudo apt update && sudo apt install -y ffuf seclists",
    presets: [
      {
        id: "ffuf-dirs",
        label: "Descoberta de Rotas c/ Auto-Calibração (-ac)",
        description: "Fuzzing de endpoints filtrando falsos positivos automaticamente",
        argsTemplate: "-u {target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac -rate 40 {bounty_header_flag} -o {outputs}/ffuf.json -of json",
      },
      {
        id: "ffuf-vhost",
        label: "Descoberta de Virtual Hosts (Host Header Fuzzing)",
        description: "Encontra subdomínios internos respondendo no mesmo IP",
        argsTemplate: "-u {target} -H \"Host: FUZZ.alvo.com\" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac -rate 40",
      },
    ],
  },
  {
    slotId: "katana",
    name: "ProjectDiscovery Katana (JS & Headless Crawler)",
    shortLabel: "Katana",
    category: "web_bounty_cli",
    kind: "cli_runner",
    tagline: "Crawler moderno que extrai rotas ocultas em bundles JavaScript, SPAs React/Vue e formulários",
    description:
      "Mapeia toda a superfície de ataque de SPAs modernas parseando arquivos `.js` automaticamente (-jc) e opcionalmente controlando Chromium headless (-hl).",
    upstreamUrl: "https://github.com/projectdiscovery/katana",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["katana.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\katana.exe", "%USERPROFILE%\\go\\bin\\katana.exe"],
    posixBinaries: ["katana"],
    posixKnownPaths: ["~/go/bin/katana", "/usr/bin/katana", "~/.pdtm/go/bin/katana"],
    installPowerShell: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    installKaliWsl: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    presets: [
      {
        id: "katana-js",
        label: "Crawl Profundo + Parsing de JS Bundles (-jc -kf all)",
        description: "Extrai endpoints de API escondidos em código JavaScript",
        argsTemplate: "-u {target} -jc -kf all -d 3 -rl 25 {bounty_header_flag} -o {outputs}/katana-urls.txt",
      },
    ],
  },
  {
    slotId: "httpx",
    name: "ProjectDiscovery httpx",
    shortLabel: "httpx",
    category: "web_bounty_cli",
    kind: "cli_runner",
    tagline: "Probing HTTP em massa: status, título, servidor, CDN/WAF, hashes favicon e tech stack",
    description:
      "Valida listas inteiras de subdomínios do Subfinder identificando quais serviços Web estão vivos, códigos HTTP, títulos, redirecionamentos e tecnologias.",
    upstreamUrl: "https://github.com/projectdiscovery/httpx",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["httpx.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\httpx.exe", "%USERPROFILE%\\go\\bin\\httpx.exe"],
    posixBinaries: ["httpx-toolkit", "httpx"],
    posixKnownPaths: ["/usr/bin/httpx-toolkit", "~/go/bin/httpx", "~/.pdtm/go/bin/httpx"],
    installPowerShell: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    installKaliWsl: "sudo apt update && sudo apt install -y httpx-toolkit",
    presets: [
      {
        id: "httpx-single",
        label: "Probe Detalhado de Alvo Único (-sc -title -tech-detect)",
        description: "Inspeciona status, título, servidor e tecnologias do alvo",
        argsTemplate: "-u {target} -sc -title -tech-detect -server -follow-redirects",
      },
      {
        id: "httpx-list",
        label: "Validar Lista de Subdomínios do Subfinder",
        description: "Lê .cyberlab/outputs/subdomains.txt e salva hosts vivos",
        argsTemplate: "-l {outputs}/subdomains.txt -sc -title -tech-detect -rl 50 -o {outputs}/live-hosts.txt",
      },
    ],
  },
  {
    slotId: "interactsh",
    name: "Interactsh Client (Collaborator Real OAST DNS/HTTP/SMTP)",
    shortLabel: "Interactsh OAST",
    category: "web_bounty_cli",
    kind: "cli_runner",
    tagline: "Substituto gratuito e real do Burp Collaborator Pro para Blind SSRF, Blind XSS, XXE e RCE",
    description:
      "Gera um domínio OAST exclusivo (*.oast.pro / *.oast.fun) e monitora ao vivo interações DNS, HTTP, HTTPS e SMTP recebidas de servidores vulneráveis externos.",
    upstreamUrl: "https://github.com/projectdiscovery/interactsh",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["interactsh-client.exe"],
    windowsKnownPaths: [
      "{toolsRoot}\\bin\\interactsh-client.exe",
      "%USERPROFILE%\\go\\bin\\interactsh-client.exe",
    ],
    posixBinaries: ["interactsh-client"],
    posixKnownPaths: ["~/go/bin/interactsh-client", "/usr/bin/interactsh-client", "~/.pdtm/go/bin/interactsh-client"],
    installPowerShell:
      "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    installKaliWsl: "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    presets: [
      {
        id: "interactsh-listen",
        label: "Gerar Payload OAST Público & Escutar Callbacks ao Vivo",
        description: "Mantém sessão viva gravando interações DNS/HTTP em .cyberlab/outputs/oast.txt",
        argsTemplate: "-v -o {outputs}/oast-interactions.txt",
      },
    ],
  },
  {
    slotId: "dalfox",
    name: "Dalfox (XSS Scanner & Parameter Analyzer)",
    shortLabel: "Dalfox",
    category: "web_bounty_cli",
    kind: "cli_runner",
    tagline: "Motor especializado em análise contextual DOM/Reflected XSS, BAV e bypass de filtros",
    description:
      "Analisa reflexão de parâmetros, testa contextos HTML/JS/Atributos, suporta Blind XSS com Interactsh e integração direta com URLs coletadas pelo Katana.",
    upstreamUrl: "https://github.com/hahwul/dalfox",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["dalfox.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\dalfox.exe", "%USERPROFILE%\\go\\bin\\dalfox.exe"],
    posixBinaries: ["dalfox"],
    posixKnownPaths: ["~/go/bin/dalfox", "/usr/bin/dalfox"],
    installPowerShell: "go install github.com/hahwul/dalfox/v2@latest",
    installKaliWsl: "go install github.com/hahwul/dalfox/v2@latest",
    presets: [
      {
        id: "dalfox-url",
        label: "Auditar URL Parametrizada p/ XSS",
        description: "Executa Dalfox em modo URL respeitando cabeçalhos do escopo",
        argsTemplate: "url {target} --silence {bounty_header_flag} -o {outputs}/dalfox-xss.txt",
      },
    ],
  },
  {
    slotId: "sqlmap",
    name: "sqlmap (Detecção & Auditoria Completa de SQL Injection)",
    shortLabel: "sqlmap",
    category: "web_bounty_cli",
    kind: "cli_runner",
    tagline: "Motor definitivo para testes Boolean-blind, Time-based, Error-based e UNION SQLi",
    description:
      "Aceita URLs diretas ou requisições HTTP brutas salvas do Burp Suite / OpenTRAP (`-r request.txt`) para auditar injeções SQL em qualquer SGBD.",
    upstreamUrl: "https://sqlmap.org/",
    licenseNote: "GPL-2.0 (Externo)",
    windowsBinaries: ["sqlmap.exe", "sqlmap"],
    posixBinaries: ["sqlmap"],
    posixKnownPaths: ["/usr/bin/sqlmap"],
    installPowerShell: "pip install sqlmap",
    installKaliWsl: "sudo apt update && sudo apt install -y sqlmap",
    presets: [
      {
        id: "sqlmap-safe",
        label: "Teste Não-Destrutivo de Fingerprint (--batch --level=2 --risk=1)",
        description: "Verifica se parâmetros de {target} são injetáveis",
        argsTemplate: "-u \"{target}\" --batch --level=2 --risk=1 --random-agent",
      },
      {
        id: "sqlmap-burp-req",
        label: "Testar Request Exportada do Burp (-r .cyberlab/imports/request.txt)",
        description: "Analisa requisição autenticada salva pelo Burp Suite",
        argsTemplate: "-r {imports}/request.txt --batch --level=3 --risk=1",
      },
    ],
  },

  // =========================================================================
  // 3. RECON, REDE, PACOTES & ACTIVE DIRECTORY
  // =========================================================================
  {
    slotId: "subfinder",
    name: "ProjectDiscovery Subfinder",
    shortLabel: "Subfinder",
    category: "recon_network_ad",
    kind: "cli_runner",
    tagline: "Enumeração passiva ultrarrápida de subdomínios usando dezenas de fontes OSINT e CT Logs",
    description:
      "Primeiro passo de todo Bug Bounty: descobre subdomínios passivamente sem tocar no alvo e grava em `.cyberlab/outputs/subdomains.txt` pronto para o `httpx` e `nuclei`.",
    upstreamUrl: "https://github.com/projectdiscovery/subfinder",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["subfinder.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\subfinder.exe", "%USERPROFILE%\\go\\bin\\subfinder.exe"],
    posixBinaries: ["subfinder"],
    posixKnownPaths: ["~/go/bin/subfinder", "/usr/bin/subfinder", "~/.pdtm/go/bin/subfinder"],
    installPowerShell: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    installKaliWsl: "sudo apt update && sudo apt install -y subfinder",
    presets: [
      {
        id: "subfinder-domain",
        label: "Enumerar Todos os Subdomínios Passivos (-all)",
        description: "Salva resultado em .cyberlab/outputs/subdomains.txt",
        argsTemplate: "-d {target} -all -o {outputs}/subdomains.txt",
      },
    ],
  },
  {
    slotId: "nmap",
    name: "Nmap + NSE Vulnerability & Service Engine",
    shortLabel: "Nmap",
    category: "recon_network_ad",
    kind: "cli_runner",
    tagline: "O scanner oficial completo de portas, versões de serviços, OS e 600+ scripts NSE",
    description:
      "Executa o Nmap verdadeiro instalado no Windows ou no Kali WSL2 com suporte total a `-sV`, `-sC`, `--script vuln`, `ssl-enum-ciphers` e exportação XML/Nmap.",
    upstreamUrl: "https://nmap.org/",
    licenseNote: "NPSL (Externo)",
    windowsBinaries: ["nmap.exe"],
    windowsKnownPaths: [
      "%ProgramFiles(x86)%\\Nmap\\nmap.exe",
      "%ProgramFiles%\\Nmap\\nmap.exe",
      "{toolsRoot}\\Nmap\\nmap.exe",
    ],
    posixBinaries: ["nmap"],
    posixKnownPaths: ["/usr/bin/nmap"],
    installPowerShell: "winget install --id Insecure.Nmap -e",
    installKaliWsl: "sudo apt update && sudo apt install -y nmap",
    presets: [
      {
        id: "nmap-sv-sc",
        label: "Service Version + Default Scripts (-sV -sC)",
        description: "Identifica versões reais e roda scripts seguros padrão",
        argsTemplate: "-sV -sC -T4 -oN {outputs}/nmap-scan.txt {target}",
      },
      {
        id: "nmap-tls",
        label: "Auditoria Profunda de Cifras TLS (ssl-enum-ciphers)",
        description: "Enumera todos os protocolos TLS e cifras suportadas na porta 443",
        argsTemplate: "-p 443 --script ssl-enum-ciphers,ssl-cert {target}",
      },
      {
        id: "nmap-vuln",
        label: "NSE Vulnerability Scripts (--script vuln)",
        description: "Executa a categoria vuln oficial do Nmap contra o alvo autorizado",
        argsTemplate: "-sV --script vuln -oN {outputs}/nmap-vuln.txt {target}",
      },
    ],
  },
  {
    slotId: "naabu-dnsx-tlsx",
    name: "DNSx & TLSx (Resolução DNS em Massa, Takeover & Auditoria X.509)",
    shortLabel: "DNSx / TLSx",
    category: "recon_network_ad",
    kind: "cli_runner",
    tagline: "Resolução DNS A/AAAA/CNAME/MX/TXT/SPF/DMARC e extração SANs de certificados TLS reais",
    description:
      "Usa `dnsx` ou `tlsx` da ProjectDiscovery para auditar registros DNS, CNAMEs órfãos e certificados TLS em escala.",
    upstreamUrl: "https://github.com/projectdiscovery/dnsx",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["dnsx.exe", "tlsx.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\dnsx.exe", "%USERPROFILE%\\go\\bin\\dnsx.exe"],
    posixBinaries: ["dnsx", "tlsx"],
    posixKnownPaths: ["~/go/bin/dnsx", "/usr/bin/dnsx"],
    installPowerShell:
      "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest; go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    installKaliWsl: "sudo apt update && sudo apt install -y dnsx",
    presets: [
      {
        id: "dnsx-records",
        label: "Consultar Todos os Registros DNS (-a -aaaa -cname -mx -txt -ns)",
        description: "Resolve registros completos de subdomínios",
        argsTemplate: "-l {outputs}/subdomains.txt -a -aaaa -cname -mx -txt -resp -o {outputs}/dns-records.txt",
      },
    ],
  },
  {
    slotId: "wireshark",
    name: "Wireshark GUI & tshark Oficial",
    shortLabel: "Wireshark / tshark",
    category: "recon_network_ad",
    kind: "desktop_gui",
    tagline: "Captura ao vivo da placa de rede e dissecação real de 3.000+ protocolos",
    description:
      "Abre o Wireshark Desktop completo no seu Windows/Kali ou roda o `tshark` oficial no console central com filtros reais de display (`http.request`, `tls.handshake`, `dns`, Follow TCP Stream).",
    upstreamUrl: "https://www.wireshark.org/",
    licenseNote: "GPL-2.0 (Externo)",
    windowsBinaries: ["Wireshark.exe", "tshark.exe"],
    windowsKnownPaths: [
      "%ProgramFiles%\\Wireshark\\Wireshark.exe",
      "%ProgramFiles%\\Wireshark\\tshark.exe",
    ],
    posixBinaries: ["wireshark", "tshark"],
    posixKnownPaths: ["/usr/bin/wireshark", "/usr/bin/tshark"],
    installPowerShell: "winget install --id WiresharkFoundation.Wireshark -e",
    installKaliWsl: "sudo apt update && sudo apt install -y wireshark tshark",
    presets: [
      {
        id: "tshark-conversations",
        label: "tshark — Resumo de Conversas IP/TCP de um .pcap",
        description: "Analisa um arquivo .pcap usando o motor oficial do Wireshark",
        argsTemplate: "-r {imports}/capture.pcap -q -z conv,ip -z http,tree",
      },
    ],
  },
  {
    slotId: "netexec",
    name: "NetExec (nxc) & Impacket (Active Directory / SMB / LDAP / Kerberos)",
    shortLabel: "NetExec / AD",
    category: "recon_network_ad",
    kind: "cli_runner",
    tagline: "Sucessor oficial do CrackMapExec p/ pentest real de redes Windows/Active Directory",
    description:
      "Auditoria real de SMB Signing, sessões nulas, enumeração LDAP/AD, WinRM, MSSQL, RDP e Kerberoasting/ASREPRoast via Kali WSL2.",
    upstreamUrl: "https://github.com/Pennyw0rth/NetExec",
    licenseNote: "BSD-2-Clause (Externo)",
    windowsBinaries: ["nxc.exe", "netexec.exe"],
    posixBinaries: ["nxc", "netexec"],
    posixKnownPaths: ["/usr/bin/nxc", "/usr/bin/netexec", "~/.local/bin/nxc"],
    installPowerShell: "wsl -d kali-linux -- sudo apt update && wsl -d kali-linux -- sudo apt install -y netexec python3-impacket",
    installKaliWsl: "sudo apt update && sudo apt install -y netexec python3-impacket",
    presets: [
      {
        id: "nxc-smb-signing",
        label: "Auditar SMB Signing & Versão do Windows (Sem Credenciais)",
        description: "Identifica hosts sem SMB Signing obrigatório na rede autorizada",
        argsTemplate: "smb {target} --gen-relay-list {outputs}/smb-relay-targets.txt",
      },
      {
        id: "nxc-ldap",
        label: "Enumerar Info Base LDAP / Domain Controller",
        description: "Verifica exposição LDAP do controlador de domínio",
        argsTemplate: "ldap {target}",
      },
    ],
  },

  // =========================================================================
  // 4. ENGENHARIA REVERSA, MALWARE & MOBILE PENTEST
  // =========================================================================
  {
    slotId: "ghidra",
    name: "NSA Ghidra (GUI Completa + Decompilador C Headless)",
    shortLabel: "Ghidra",
    category: "reverse_mobile",
    kind: "desktop_gui",
    tagline: "Suite oficial da NSA de engenharia reversa e descompilação para C/C++ em qualquer arquitetura",
    description:
      "Abre a interface gráfica completa do Ghidra no Windows/Kali ou roda o `analyzeHeadless` para importar e analisar binários `.exe`, `.dll`, `.so`, ELF e firmwares.",
    upstreamUrl: "https://ghidra-sre.org/",
    licenseNote: "Apache-2.0 (Externo)",
    windowsBinaries: ["ghidraRun.bat", "analyzeHeadless.bat"],
    windowsKnownPaths: [
      "{toolsRoot}\\ghidra\\ghidraRun.bat",
      "C:\\ghidra\\ghidraRun.bat",
    ],
    posixBinaries: ["ghidra", "ghidraRun", "analyzeHeadless"],
    posixKnownPaths: ["/usr/bin/ghidra", "/opt/ghidra/ghidraRun"],
    installPowerShell: "winget install --id EclipseAdoptium.Temurin.21.JDK -e; winget install --id NSA.Ghidra -e",
    installKaliWsl: "sudo apt update && sudo apt install -y ghidra",
    presets: [],
  },
  {
    slotId: "jadx",
    name: "JADX & JADX-GUI (Descompilador Oficial Android APK / DEX -> Java)",
    shortLabel: "JADX Android",
    category: "reverse_mobile",
    kind: "desktop_gui",
    tagline: "Descompila qualquer APK inteiro em código Java legível direto para a árvore de arquivos do projeto!",
    description:
      "Abre o `jadx-gui` interativo ou descompila o `.apk` completo para `.cyberlab/outputs/apk-src/` — permitindo que você, o OpenCode e os 4 CDIs pesquisem chaves, endpoints ocultos e falhas no código Java real!",
    upstreamUrl: "https://github.com/skylot/jadx",
    licenseNote: "Apache-2.0 (Externo)",
    windowsBinaries: ["jadx-gui.bat", "jadx-gui.exe", "jadx.bat", "jadx.exe"],
    windowsKnownPaths: [
      "{toolsRoot}\\jadx\\bin\\jadx-gui.bat",
      "%LOCALAPPDATA%\\Microsoft\\WinGet\\Links\\jadx-gui.exe",
    ],
    posixBinaries: ["jadx-gui", "jadx"],
    posixKnownPaths: ["/usr/bin/jadx-gui", "/usr/bin/jadx"],
    installPowerShell: "winget install --id skylot.jadx -e",
    installKaliWsl: "sudo apt update && sudo apt install -y jadx",
    presets: [
      {
        id: "jadx-decompile-to-workspace",
        label: "Descompilar APK Inteiro p/ Árvore do Projeto (.cyberlab/outputs/apk-src)",
        description: "Extrai AndroidManifest.xml + todo código Java para análise com IA/CDIs",
        argsTemplate: "-d {outputs}/apk-src {imports}/app.apk",
      },
    ],
  },
  {
    slotId: "rizin-cutter",
    name: "Rizin & Cutter (Disassembly, CFG, Strings & Binários)",
    shortLabel: "Rizin / Cutter",
    category: "reverse_mobile",
    kind: "cli_runner",
    tagline: "Framework moderno open-source de engenharia reversa (fork limpo do radare2) + GUI Cutter",
    description:
      "Inspeciona proteções NX/PIE/Canary, seções, imports, strings, XREFs, ROP gadgets e disassembly rápido com `rz-bin` e `rizin`.",
    upstreamUrl: "https://rizin.re/",
    licenseNote: "LGPL-3.0 (Externo)",
    windowsBinaries: ["rz-bin.exe", "rizin.exe", "cutter.exe"],
    windowsKnownPaths: ["{toolsRoot}\\rizin\\bin\\rz-bin.exe", "{toolsRoot}\\cutter\\cutter.exe"],
    posixBinaries: ["rz-bin", "rizin", "cutter"],
    posixKnownPaths: ["/usr/bin/rz-bin", "/usr/bin/rizin"],
    installPowerShell: "winget install --id Rizin.Cutter -e",
    installKaliWsl: "sudo apt update && sudo apt install -y rizin rizin-cutter",
    presets: [
      {
        id: "rz-bin-info",
        label: "Triagem Completa de Binário (rz-bin -I -S -i -z)",
        description: "Arquitetura, proteções de compilação, seções, imports e strings",
        argsTemplate: "-I -S -i {imports}/sample.bin",
      },
    ],
  },
  {
    slotId: "frida-apktool",
    name: "Frida & Apktool (Instrumentação Mobile Dinâmica & SSL Unpinning)",
    shortLabel: "Frida / Apktool",
    category: "reverse_mobile",
    kind: "cli_runner",
    tagline: "Hooks em tempo de execução Android/iOS/Windows, bypass de SSL Pinning ( para usar c/ Burp!) e Apktool",
    description:
      "Essencial para Bug Bounty Mobile: conecta via ADB/Frida para desativar SSL Pinning em apps Android/iOS para que todo o tráfego HTTPS apareça no seu Burp Suite ou OpenTRAP!",
    upstreamUrl: "https://frida.re/",
    licenseNote: "wxWindows / Apache-2.0 (Externo)",
    windowsBinaries: ["frida.exe", "frida-ps.exe", "apktool.bat"],
    posixBinaries: ["frida", "frida-ps", "apktool"],
    installPowerShell: "pip install frida-tools objection",
    installKaliWsl: "sudo apt update && sudo apt install -y apktool adb && pip3 install --break-system-packages frida-tools objection",
    presets: [
      {
        id: "frida-ps-usb",
        label: "Listar Processos do Dispositivo/Emulador USB (frida-ps -Uai)",
        description: "Lista todos os apps instalados no Android/iOS conectado via USB/ADB",
        argsTemplate: "-Uai",
      },
    ],
  },
  {
    slotId: "capa",
    name: "Mandiant Capa (Capacidades Reais de Binários & MITRE ATT&CK)",
    shortLabel: "Mandiant Capa",
    category: "reverse_mobile",
    kind: "cli_runner",
    tagline: "Detecta exatamente o que um executável faz (C2, keylogger, anti-debug, persistência, criptografia)",
    description:
      "Motor oficial do FLARE/Mandiant que analisa PE, ELF e .NET mapeando comportamentos diretamente para técnicas MITRE ATT&CK e MBC.",
    upstreamUrl: "https://github.com/mandiant/capa",
    licenseNote: "Apache-2.0 (Externo)",
    windowsBinaries: ["capa.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\capa.exe"],
    posixBinaries: ["capa"],
    posixKnownPaths: ["~/CyberLab-Tools/bin/capa", "/usr/local/bin/capa"],
    installPowerShell:
      "# Baixe capa-windows.zip oficial em https://github.com/mandiant/capa/releases e extraia capa.exe em C:\\CyberLab-Tools\\bin\\",
    installKaliWsl:
      "# Baixe capa-linux oficial em https://github.com/mandiant/capa/releases para ~/CyberLab-Tools/bin/capa",
    presets: [
      {
        id: "capa-triage",
        label: "Mapear Capacidades & MITRE ATT&CK do Executável",
        description: "Analisa binário importado em .cyberlab/imports/",
        argsTemplate: "{imports}/sample.exe",
      },
    ],
  },

  // =========================================================================
  // 5. KEY HUNTING, SAST, SCA & CLOUD
  // =========================================================================
  {
    slotId: "keyhunter",
    name: "KeyHunter Rust Oficial (fadidevv/keyhunter)",
    shortLabel: "KeyHunter Rust",
    category: "secrets_sast_cloud",
    kind: "cli_runner",
    tagline: "Caçador oficial em Rust de chaves de IA (OpenAI/Anthropic/Gemini), AWS, Stripe e GitHub c/ validação",
    description:
      "Executa o binário Rust original `keyhunter` (`cargo install github-keyhunter`) com 45+ padrões de alta precisão, busca no GitHub e verificação ativa de chaves.",
    upstreamUrl: "https://github.com/fadidevv/keyhunter",
    licenseNote: "MIT (Externo)",
    windowsBinaries: ["keyhunter.exe"],
    windowsKnownPaths: ["%USERPROFILE%\\.cargo\\bin\\keyhunter.exe", "{toolsRoot}\\bin\\keyhunter.exe"],
    posixBinaries: ["keyhunter"],
    posixKnownPaths: ["~/.cargo/bin/keyhunter"],
    installPowerShell: "winget install --id Rustlang.Rustup -e; cargo install github-keyhunter",
    installKaliWsl: "sudo apt update && sudo apt install -y cargo pkg-config libssl-dev && cargo install github-keyhunter",
    presets: [
      {
        id: "kh-patterns",
        label: "Listar Todos os Provedores & Padrões Suportados",
        description: "Exibe os 45+ provedores de chaves suportados pelo KeyHunter",
        argsTemplate: "patterns",
      },
      {
        id: "kh-scan",
        label: "Scan de Chaves Vazadas (JSON Output)",
        description: "Executa busca com query configurada",
        argsTemplate: "scan -q \"{target}\" -o json",
      },
    ],
  },
  {
    slotId: "gitleaks-trufflehog",
    name: "Gitleaks & TruffleHog (Segredos em Histórico Git Completo & Buckets)",
    shortLabel: "Gitleaks / TruffleHog",
    category: "secrets_sast_cloud",
    kind: "cli_runner",
    tagline: "Vasculha todos os commits antigos apagados de repositórios Git, organizações e S3",
    description:
      "Encontra segredos que desenvolvedores tentaram apagar em commits antigos do Git (`git log -p` completo) e valida credenciais ativas.",
    upstreamUrl: "https://github.com/gitleaks/gitleaks",
    licenseNote: "MIT / AGPL-3.0 (Externo)",
    windowsBinaries: ["gitleaks.exe", "trufflehog.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\gitleaks.exe"],
    posixBinaries: ["gitleaks", "trufflehog"],
    posixKnownPaths: ["/usr/bin/gitleaks", "/usr/local/bin/trufflehog"],
    installPowerShell: "winget install --id Gitleaks.Gitleaks -e",
    installKaliWsl: "sudo apt update && sudo apt install -y gitleaks",
    presets: [
      {
        id: "gitleaks-git",
        label: "Auditar Histórico Git Inteiro do Workspace Atual",
        description: "Verifica todos os commits históricos e salva relatório JSON",
        argsTemplate: "detect --source {workspace} --report-format json --report-path {outputs}/gitleaks-report.json -v",
      },
    ],
  },
  {
    slotId: "semgrep",
    name: "Semgrep / Opengrep (SAST Real Multi-Linguagem por AST)",
    shortLabel: "Semgrep SAST",
    category: "secrets_sast_cloud",
    kind: "cli_runner",
    tagline: "Análise estática real de vulnerabilidades em código JS/TS, Python, Go, Java, PHP, C# e Rust",
    description:
      "Audita código-fonte (inclusive projetos abertos ou APKs descompilados pelo JADX!) com milhares de regras OWASP Top 10 baseadas em árvore sintática real.",
    upstreamUrl: "https://github.com/semgrep/semgrep",
    licenseNote: "LGPL-2.1 (Externo)",
    windowsBinaries: ["semgrep.exe", "opengrep.exe"],
    posixBinaries: ["semgrep", "opengrep"],
    installPowerShell: "pip install semgrep",
    installKaliWsl: "pip3 install --break-system-packages semgrep",
    presets: [
      {
        id: "semgrep-auto",
        label: "Auditoria OWASP Top 10 & Security Audit no Workspace",
        description: "Analisa o projeto atual e gera SARIF/JSON para revisão",
        argsTemplate: "scan --config p/security-audit --config p/owasp-top-ten {workspace} --json -o {outputs}/semgrep.json",
      },
    ],
  },
  {
    slotId: "trivy",
    name: "Aqua Trivy (CVEs Reais, SBOM CycloneDX, Containers, K8s & IaC)",
    shortLabel: "Aqua Trivy",
    category: "secrets_sast_cloud",
    kind: "cli_runner",
    tagline: "Scanner oficial de vulnerabilidades CVE, imagens Docker, Terraform, Kubernetes e geração SBOM",
    description:
      "Consulta o banco oficial atualizado de CVEs (NVD, GitHub Advisories, RedHat, Alpine, Debian) para dependências, containers e infraestrutura como código.",
    upstreamUrl: "https://github.com/aquasecurity/trivy",
    licenseNote: "Apache-2.0 (Externo)",
    windowsBinaries: ["trivy.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\trivy.exe"],
    posixBinaries: ["trivy"],
    posixKnownPaths: ["/usr/local/bin/trivy", "/usr/bin/trivy"],
    installPowerShell: "winget install --id AquaSecurity.Trivy -e",
    installKaliWsl: "sudo apt update && sudo apt install -y wget apt-transport-https gnupg && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null && echo \"deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main\" | sudo tee /etc/apt/sources.list.d/trivy.list && sudo apt update && sudo apt install -y trivy",
    presets: [
      {
        id: "trivy-fs",
        label: "Auditar CVEs, Segredos & Misconfigs IaC no Projeto",
        description: "Varre lockfiles, Dockerfiles, Terraform e Kubernetes",
        argsTemplate: "fs --scanners vuln,misconfig,secret {workspace} -o {outputs}/trivy-report.txt",
      },
      {
        id: "trivy-sbom",
        label: "Gerar SBOM Oficial CycloneDX (.json)",
        description: "Exporta inventário CycloneDX completo em .cyberlab/outputs/sbom.cdx.json",
        argsTemplate: "fs --format cyclonedx --output {outputs}/sbom.cdx.json {workspace}",
      },
    ],
  },

  // =========================================================================
  // 6. CYBERCHEF OFICIAL, FORENSE DFIR & KALI DESKTOP NA ABA
  // =========================================================================
  {
    slotId: "cyberchef",
    name: "GCHQ CyberChef Oficial (300+ Operações 100% Embutido)",
    shortLabel: "CyberChef Oficial",
    category: "cyberchef_dfir_kali",
    kind: "web_embed",
    tagline: "O verdadeiro CyberChef completo do GCHQ rodando offline dentro da aba central do CyberLab OS!",
    description:
      "Serve o GCHQ CyberChef oficial instalado em `C:\\CyberLab-Tools\\CyberChef` (ou instância local) direto no centro da tela: mais de 300 operações reais de criptografia, decodificação, compressão, Magic, Protobuf, JWT, regex e forense.",
    upstreamUrl: "https://github.com/gchq/CyberChef",
    licenseNote: "Apache-2.0 (Externo em C:\\CyberLab-Tools\\CyberChef)",
    windowsBinaries: [],
    posixBinaries: [],
    localStaticDirSubpath: "CyberChef",
    installPowerShell:
      NewCyberChefInstallPowerShell(),
    installKaliWsl:
      "mkdir -p ~/CyberLab-Tools/CyberChef && cd ~/CyberLab-Tools/CyberChef && curl -s https://api.github.com/repos/gchq/CyberChef/releases/latest | grep browser_download_url | cut -d '\"' -f 4 | head -n 1 | xargs wget -O cyberchef.zip && unzip -o cyberchef.zip",
    presets: [],
  },
  {
    slotId: "hayabusa-yarax",
    name: "Hayabusa (Windows .evtx Sigma) & VirusTotal YARA-X",
    shortLabel: "Hayabusa / YARA-X",
    category: "cyberchef_dfir_kali",
    kind: "cli_runner",
    tagline: "Forense ultrarrápida em Rust sobre logs reais do Windows (.evtx) com milhares de regras Sigma + YARA-X",
    description:
      "Analisa logs reais de eventos do Windows (`.evtx`) em segundos usando milhares de regras Sigma oficiais (`hayabusa`) ou caça malware com o motor oficial `yr` (VirusTotal YARA-X).",
    upstreamUrl: "https://github.com/Yamato-Security/hayabusa",
    licenseNote: "AGPL-3.0 / BSD-3 (Externo)",
    windowsBinaries: ["hayabusa.exe", "yr.exe", "yara64.exe", "yara.exe"],
    windowsKnownPaths: ["{toolsRoot}\\bin\\hayabusa.exe", "{toolsRoot}\\bin\\yr.exe"],
    posixBinaries: ["hayabusa", "yr", "yara"],
    posixKnownPaths: ["~/.cargo/bin/yr", "~/CyberLab-Tools/bin/hayabusa", "/usr/bin/yara"],
    installPowerShell: "winget install --id VirusTotal.YARA-X -e",
    installKaliWsl: "sudo apt update && sudo apt install -y yara && cargo install yara-x-cli",
    presets: [
      {
        id: "yarax-scan",
        label: "YARA-X — Escanear Pasta com Arquivo de Regras (.yar)",
        description: "Executa yr scan contra artefatos importados",
        argsTemplate: "scan {imports}/rules.yar {imports}",
      },
    ],
  },
  {
    slotId: "kali-desktop-stream",
    name: "Kali Linux Desktop na Aba (Win-KeX / noVNC)",
    shortLabel: "Kali Desktop (Web)",
    category: "cyberchef_dfir_kali",
    kind: "web_embed",
    tagline: "Exibe a área de trabalho gráfica completa do seu Kali WSL2 ao vivo dentro da aba central!",
    description:
      "Inicia e incorpora automaticamente um servidor X11/noVNC do Kali Linux no WSL2 dentro do painel central, permitindo operar OpenTRAP, Wireshark, Burp, Ghidra, BloodHound e todo o menu gráfico do Kali dentro do navegador, com o OpenCode e os 4 CDIs na barra lateral!",
    upstreamUrl: "https://www.kali.org/docs/wsl/win-kex/",
    licenseNote: "GPL / Kali Official (WSL2)",
    windowsBinaries: [],
    posixBinaries: ["Xtigervnc", "websockify", "kex", "vncserver"],
    defaultEmbedUrl: "http://127.0.0.1:6080/vnc.html?autoconnect=true&resize=remote",
    installPowerShell: "wsl --install -d kali-linux",
    installKaliWsl: "sudo apt update && sudo apt install -y kali-win-kex tigervnc-standalone-server openbox novnc websockify x11vnc",
    presets: [],
  },
]

function NewCyberChefInstallPowerShell(): string {
  return [
    `$dir = "C:\\CyberLab-Tools\\CyberChef"; New-Item -ItemType Directory -Force -Path $dir | Out-Null`,
    `$rel = Invoke-RestMethod "https://api.github.com/repos/gchq/CyberChef/releases/latest"`,
    `$url = $rel.assets[0].browser_download_url`,
    `Invoke-WebRequest -Uri $url -OutFile "$dir\\CyberChef.zip"`,
    `Expand-Archive -Path "$dir\\CyberChef.zip" -DestinationPath $dir -Force`,
  ].join("; ")
}
