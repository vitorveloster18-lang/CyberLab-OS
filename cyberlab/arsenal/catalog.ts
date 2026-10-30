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
  | "ai_offensive_agents"
  | "privacy_opsec_crypto"
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
    title: "Recon, Rede, Exploração & Active Directory",
    subtitle: "Subfinder, Nmap, Wireshark, Naabu/DNSx/TLSx, NetExec, BloodHound, Metasploit e Impacket/Hashcat",
  },
  reverse_mobile: {
    title: "Engenharia Reversa, REA, Malware & Mobile",
    subtitle: "REA (Reverse Engineer Anything), Ghidra, JADX, Rizin/Cutter, Frida/Apktool, Capa e MVT Forensics",
  },
  secrets_sast_cloud: {
    title: "Key Hunting, SAST, SCA & Cloud",
    subtitle: "KeyHunter Rust, Gitleaks, TruffleHog, Semgrep e Aqua Trivy",
  },
  ai_offensive_agents: {
    title: "Agentes Ofensivos de IA & MCPs Autônomos",
    subtitle: "Strix, Shannon, HexStrike AI (150+ tools MCP), PentAGI, PentestGPT e CAI",
  },
  privacy_opsec_crypto: {
    title: "OpSec, Privacidade, Criptografia & Hardening",
    subtitle: "Tor/Torsocks, OnionShare, VeraCrypt, Mullvad VPN, Signal e GrapheneOS ADB Auditor",
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
    name: "Burp Suite Community (Oficial)",
    shortLabel: "Burp Suite",
    category: "web_proxy_suite",
    kind: "desktop_gui",
    tagline: "Proxy interceptador e Repeater padrão da indústria + Navegador Isolado 1-Clique (:8080)",
    description:
      "Abre o seu Burp Suite Community gratuito (ou Pro, se tiver licença) dentro do palco central do CyberLab OS ou em janela nativa, conecta em 1 clique um navegador Chrome/Edge isolado direto na porta 8080 e sincroniza requests/logs com a IA e os 4 CDIs.",
    upstreamUrl: "https://portswigger.net/burp/communitydownload",
    licenseNote: "Free Community Edition (Externo)",
    windowsBinaries: ["BurpSuiteCommunity.exe", "burpsuite_community.jar"],
    windowsKnownPaths: [
      "%LOCALAPPDATA%\\BurpSuiteCommunity\\BurpSuiteCommunity.exe",
      "%LOCALAPPDATA%\\BurpSuiteCommunity\\burpsuite_community.jar",
      "%LOCALAPPDATA%\\Programs\\BurpSuiteCommunity\\BurpSuiteCommunity.exe",
      "%ProgramFiles%\\BurpSuiteCommunity\\BurpSuiteCommunity.exe",
      "%USERPROFILE%\\BurpSuiteCommunity\\BurpSuiteCommunity.exe",
      "{toolsRoot}\\BurpSuite\\burpsuite_community.jar",
      "{toolsRoot}\\BurpSuite\\BurpSuiteCommunity.exe",
    ],
    posixBinaries: ["burpsuite"],
    posixKnownPaths: [
      "/opt/cyberlab-burp/burpsuite.jar",
      "/usr/local/bin/burpsuite",
      "/usr/share/burpsuite/burpsuite.jar",
      "/usr/bin/burpsuite",
    ],
    companionProxyPort: 8080,
    installPowerShell: "winget install --id PortSwigger.BurpSuite.Community -e",
    installKaliWsl: [
      "sudo rm -rf /opt/cyberlab-burp /root/.BurpSuite /home/*/.BurpSuite",
      "sudo mkdir -p /opt/cyberlab-burp",
      "sudo apt-get update -qq",
      "sudo apt-get install -y -qq curl jq unzip tar file ca-certificates tigervnc-standalone-server openbox novnc websockify dbus-x11 x11-xserver-utils x11-utils fonts-dejavu-core libxtst6 libxi6 libxrender1 libxext6 libxfixes3 libxrandr2 libxcomposite1 libxdamage1 libxkbcommon0 libgbm1 libdrm2 libnss3 libnspr4 libfreetype6 fontconfig",
      "if [ ! -x /opt/cyberlab-jre21/bin/java ] && [ ! -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java ]; then JRE_URL=$(curl -fsSL https://api.github.com/repos/adoptium/temurin21-binaries/releases/latest | jq -r '.assets[] | select(.name | test(\"OpenJDK21U-jre_x64_linux_hotspot_.*\\\\.tar\\\\.gz$\")) | .browser_download_url' | head -n 1); mkdir -p /opt/cyberlab-jre21 && curl -fL \"$JRE_URL\" -o /tmp/jre21.tar.gz && tar -xzf /tmp/jre21.tar.gz -C /opt/cyberlab-jre21 --strip-components=1 && rm -f /tmp/jre21.tar.gz; fi",
      "BURP_VER=$(curl -fsSL 'https://portswigger.net/burp/releases/rss' 2>/dev/null | grep -o 'professional-community-[0-9-]\\+' | sed 's/professional-community-//;s/-/./g' | sort -V | tail -n 1); [ -z \"$BURP_VER\" ] && BURP_VER='2026.10.1'",
      "echo \"Baixando Burp Suite Community Edition v$BURP_VER oficial da PortSwigger CDN...\"",
      "(curl -fL \"https://portswigger-cdn.net/burp/releases/download?product=desktop&version=$BURP_VER&type=Jar\" -o /opt/cyberlab-burp/burpsuite.jar || curl -fL \"https://portswigger-cdn.net/burp/releases/download?product=desktop&version=2026.10.1&type=Jar\" -o /opt/cyberlab-burp/burpsuite.jar)",
      "unzip -tq /opt/cyberlab-burp/burpsuite.jar >/dev/null",
      "chmod 644 /opt/cyberlab-burp/burpsuite.jar",
      "printf '#!/bin/sh\\nJAVA_BIN=/opt/cyberlab-jre21/bin/java\\n[ ! -x \"$JAVA_BIN\" ] && JAVA_BIN=/usr/lib/jvm/java-21-openjdk-amd64/bin/java\\n[ ! -x \"$JAVA_BIN\" ] && JAVA_BIN=java\\nexec \"$JAVA_BIN\" --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/javax.crypto=ALL-UNNAMED --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.desktop/java.awt=ALL-UNNAMED --add-opens=java.desktop/java.awt.color=ALL-UNNAMED --add-opens=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED -jar /opt/cyberlab-burp/burpsuite.jar --suppress-jre-check --disable-check-for-updates-dialog --disable-auto-update --i-accept-the-license-agreement \"$@\"\\n' | sudo tee /usr/local/bin/burpsuite >/dev/null && sudo chmod +x /usr/local/bin/burpsuite",
    ].join(" && "),
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
    defaultEmbedUrl: "http://127.0.0.1:8081/?token=cyberlab",
    managedDaemonPort: 8081,
    managedDaemonArgs: [
      "--web-host",
      "0.0.0.0",
      "--web-port",
      "8081",
      "--listen-host",
      "0.0.0.0",
      "--listen-port",
      "8082",
      "--no-web-open-browser",
      "--set",
      "web_password=cyberlab",
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
    posixKnownPaths: [
      "/usr/local/bin/caido-cli",
      "/usr/local/bin/caido",
      "/usr/bin/caido",
      "~/CyberLab-Tools/caido/caido-cli",
    ],
    defaultEmbedUrl: "http://127.0.0.1:7000",
    managedDaemonPort: 7000,
    managedDaemonArgs: ["--listen", "0.0.0.0:7000", "--no-open", "--allow-guests"],
    companionProxyPort: 7000,
    installPowerShell:
      "winget install --id Caido.Caido -e --accept-source-agreements --accept-package-agreements",
    installKaliWsl:
      'sudo apt-get update -qq && sudo apt-get install -y -qq curl jq tar ca-certificates && URL=$(curl -fsSL https://api.caido.io/releases/latest | jq -r \'.links[] | select((.display | ascii_downcase | contains("linux")) and (.link | contains("x86_64"))) | .link\' | head -n 1); [ -z "$URL" ] && URL=$(curl -fsSL https://api.caido.io/releases/latest | jq -r \'.links[] | select(.display == "Linux") | .link\' | head -n 1); curl -fsSL "$URL" -o /tmp/caido.tar.gz && sudo tar -xzf /tmp/caido.tar.gz -C /usr/local/bin && sudo chmod +x /usr/local/bin/caido* && rm -f /tmp/caido.tar.gz',
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
    posixKnownPaths: ["/usr/local/bin/katana", "~/go/bin/katana", "/usr/bin/katana", "~/.pdtm/go/bin/katana"],
    installPowerShell: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    installKaliWsl:
      'sudo apt-get install -y -qq curl jq unzip && URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/katana/releases/latest | jq -r \'.assets[] | select(.name | test("linux_amd64\\\\.zip$")) | .browser_download_url\' | head -n 1) && curl -fsSL "$URL" -o /tmp/katana.zip && sudo unzip -o /tmp/katana.zip katana -d /usr/local/bin && sudo chmod +x /usr/local/bin/katana && rm -f /tmp/katana.zip',
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
    posixKnownPaths: [
      "/usr/local/bin/interactsh-client",
      "~/go/bin/interactsh-client",
      "/usr/bin/interactsh-client",
      "~/.pdtm/go/bin/interactsh-client",
    ],
    installPowerShell:
      "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    installKaliWsl:
      'sudo apt-get install -y -qq curl jq unzip && URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/interactsh/releases/latest | jq -r \'.assets[] | select(.name | test("interactsh-client_.*_linux_amd64\\\\.zip$")) | .browser_download_url\' | head -n 1) && curl -fsSL "$URL" -o /tmp/interactsh.zip && sudo unzip -o /tmp/interactsh.zip interactsh-client -d /usr/local/bin && sudo chmod +x /usr/local/bin/interactsh-client && rm -f /tmp/interactsh.zip',
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
    posixKnownPaths: ["/usr/local/bin/dalfox", "/usr/bin/dalfox", "~/go/bin/dalfox"],
    installPowerShell: "go install github.com/hahwul/dalfox/v2@latest",
    installKaliWsl:
      'sudo apt-get install -y -qq curl jq && URL=$(curl -fsSL https://api.github.com/repos/hahwul/dalfox/releases/latest | jq -r \'.assets[] | select(.name | test("linux-x86_64\\\\.deb$")) | .browser_download_url\' | head -n 1) && curl -fsSL "$URL" -o /tmp/dalfox.deb && sudo dpkg -i /tmp/dalfox.deb && rm -f /tmp/dalfox.deb',
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
    posixKnownPaths: ["/usr/local/bin/frida", "/usr/bin/apktool", "~/.local/bin/frida"],
    installPowerShell: "pip install frida-tools objection",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y apktool adb python3-pip && sudo python3 -m pip install --break-system-packages frida-tools",
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
    posixKnownPaths: ["/usr/local/bin/capa", "~/CyberLab-Tools/bin/capa"],
    installPowerShell:
      '$rel = Invoke-RestMethod "https://api.github.com/repos/mandiant/capa/releases/latest"; $u = ($rel.assets | Where-Object { $_.name -match "windows\\.zip$" })[0].browser_download_url; New-Item -ItemType Directory -Force -Path "C:\\CyberLab-Tools\\bin" | Out-Null; Invoke-WebRequest -Uri $u -OutFile "$env:TEMP\\capa.zip"; Expand-Archive -Path "$env:TEMP\\capa.zip" -DestinationPath "C:\\CyberLab-Tools\\bin" -Force',
    installKaliWsl:
      'sudo apt-get install -y -qq curl jq unzip && URL=$(curl -fsSL https://api.github.com/repos/mandiant/capa/releases/latest | jq -r \'.assets[] | select(.name | test("capa-v[0-9.]+-linux\\\\.zip$")) | .browser_download_url\' | head -n 1) && curl -fsSL "$URL" -o /tmp/capa.zip && sudo unzip -o /tmp/capa.zip capa -d /usr/local/bin && sudo chmod +x /usr/local/bin/capa && rm -f /tmp/capa.zip',
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
    posixKnownPaths: ["/usr/local/bin/keyhunter", "~/.cargo/bin/keyhunter"],
    installPowerShell: "winget install --id Rustlang.Rustup -e; cargo install github-keyhunter",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y cargo rustc pkg-config libssl-dev && sudo cargo install github-keyhunter --root /usr/local",
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
    posixKnownPaths: [
      "/usr/local/bin/semgrep",
      "/usr/local/bin/opengrep",
      "/usr/bin/semgrep",
      "~/.local/bin/semgrep",
    ],
    installPowerShell: "pip install semgrep",
    installKaliWsl:
      'sudo apt-get install -y -qq curl jq ca-certificates && URL=$(curl -fsSL https://api.github.com/repos/opengrep/opengrep/releases/latest | jq -r \'.assets[] | select(.name == "opengrep_manylinux_x86") | .browser_download_url\' | head -n 1) && sudo curl -fsSL "$URL" -o /usr/local/bin/opengrep && sudo chmod +x /usr/local/bin/opengrep && sudo ln -sf /usr/local/bin/opengrep /usr/local/bin/semgrep',
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
    posixKnownPaths: ["/usr/local/bin/yr", "/usr/bin/yara", "~/.cargo/bin/yr", "~/CyberLab-Tools/bin/hayabusa"],
    installPowerShell: "winget install --id VirusTotal.YARA-X -e",
    installKaliWsl:
      'sudo apt-get update && sudo apt-get install -y yara curl jq tar && URL=$(curl -fsSL https://api.github.com/repos/VirusTotal/yara-x/releases/latest | jq -r \'.assets[] | select(.name | test("x86_64-unknown-linux-gnu\\\\.tar\\\\.gz$")) | .browser_download_url\' | head -n 1) && curl -fsSL "$URL" -o /tmp/yarax.tar.gz && sudo tar -xzf /tmp/yarax.tar.gz -C /usr/local/bin && sudo chmod +x /usr/local/bin/yr && rm -f /tmp/yarax.tar.gz',
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
    posixBinaries: ["startxfce4"],
    posixKnownPaths: ["/usr/bin/startxfce4"],
    defaultEmbedUrl: "http://127.0.0.1:6080/cyberlab_canvas.html?mode=fit",
    installPowerShell: "wsl --install -d kali-linux",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y xfce4 xfce4-terminal thunar dbus-x11 kali-menu kali-themes x11-xserver-utils x11-utils xterm tigervnc-standalone-server openbox novnc websockify",
    presets: [],
  },

  // =========================================================================
  // EXPANSÃO v5.6 — REA + TODAS AS FERRAMENTAS REMANESCENTES DO INVENTÁRIO
  // =========================================================================
  {
    slotId: "rea",
    name: "REA — Reverse Engineer Anything (Ghidra / JADX / JS / MCP)",
    shortLabel: "REA (morluto/rea)",
    category: "reverse_mobile",
    kind: "cli_runner",
    tagline: "Motor oficial MIT de engenharia reversa assistida por IA (Binários, APKs, Electron/ASAR) com integração nativa ao MCP do OpenCode!",
    description:
      "Conecta binários ELF/PE/Mach-O (via Ghidra Headless no Kali WSL2), APKs (via JADX) e aplicações Electron/ASAR/JS direto ao CLI `rea` e ao servidor MCP nativo do OpenCode V2 (`rea setup --client opencode`), gerando grafos de módulos e evidências verificáveis.",
    upstreamUrl: "https://github.com/morluto/rea",
    licenseNote: "MIT Oficial (rea-agents via npm; usa Ghidra/JADX externos)",
    windowsBinaries: ["rea.cmd", "rea.exe", "rea"],
    windowsKnownPaths: [
      "%APPDATA%\\npm\\rea.cmd",
      "%USERPROFILE%\\AppData\\Roaming\\npm\\rea.cmd",
    ],
    posixBinaries: ["rea"],
    posixKnownPaths: ["/usr/local/bin/rea", "/usr/bin/rea", "~/.npm-global/bin/rea"],
    installPowerShell: "npm install --global rea-agents",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y nodejs npm procps jq && sudo npm install --global rea-agents",
    presets: [
      {
        id: "rea-doctor",
        label: "Diagnóstico REA + Motores (Ghidra / JADX / OpenCode)",
        description: "Verifica prontidão do REA, Ghidra, JADX e registro MCP",
        argsTemplate: "doctor --json",
      },
      {
        id: "rea-connect-opencode",
        label: "Conectar MCP do REA Direto ao Agente OpenCode",
        description: "Registra o servidor MCP oficial do REA na configuração do OpenCode",
        argsTemplate: "setup --client opencode --yes --json",
      },
      {
        id: "rea-analyze-target",
        label: "Analisar Binário / APK / Pasta ou .asar",
        description: "Executa engenharia reversa completa com geração de evidências JSON",
        argsTemplate: "analyze {target} --json",
      },
      {
        id: "rea-analyze-js-electron",
        label: "Reconstruir App Electron / ASAR / JavaScript",
        description: "Extrai grafo de módulos, fronteiras IPC Electron e evidências sem código-fonte",
        argsTemplate: "analyze-javascript-application {target} --json",
      },
    ],
  },
  {
    slotId: "mvt",
    name: "MVT — Mobile Verification Toolkit (Amnesty International)",
    shortLabel: "MVT Forensics",
    category: "reverse_mobile",
    kind: "cli_runner",
    tagline: "Forense mobile oficial de Android & iOS (detecção de spyware/Pegasus e IOCs da Amnesty Tech)",
    description:
      "Executa o Mobile Verification Toolkit (`mvt-android` e `mvt-ios`) no Kali WSL2 para auditar backups Android/iTunes, dumps ADB, SMS, bancos SQLite e pacotes instalados contra indicadores públicos de comprometimento (IOCs).",
    upstreamUrl: "https://github.com/mvt-project/mvt",
    licenseNote: "MVT License (Processo Externo Isolado em WSL2)",
    windowsBinaries: ["mvt-android.exe", "mvt-ios.exe"],
    posixBinaries: ["mvt-android", "mvt-ios"],
    posixKnownPaths: ["/usr/local/bin/mvt-android", "/opt/mvt/bin/mvt-android", "~/.local/bin/mvt-android"],
    installPowerShell:
      "'apt-get update && apt-get install -y python3-venv python3-pip libusb-1.0-0-dev adb sqlite3 && python3 -m venv /opt/mvt && /opt/mvt/bin/pip install -U pip mvt && ln -sf /opt/mvt/bin/mvt-android /usr/local/bin/mvt-android && ln -sf /opt/mvt/bin/mvt-ios /usr/local/bin/mvt-ios' | wsl -d kali-linux -u root -- bash -s",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y python3-venv python3-pip libusb-1.0-0-dev adb sqlite3 && sudo python3 -m venv /opt/mvt && sudo /opt/mvt/bin/pip install -U pip mvt && sudo ln -sf /opt/mvt/bin/mvt-android /usr/local/bin/mvt-android && sudo ln -sf /opt/mvt/bin/mvt-ios /usr/local/bin/mvt-ios",
    presets: [
      {
        id: "mvt-download-iocs",
        label: "Baixar IOCs Oficiais Atualizados (Amnesty Tech)",
        description: "Atualiza a base pública de indicadores de spyware do MVT",
        argsTemplate: "download-iocs",
      },
      {
        id: "mvt-check-backup",
        label: "Auditar Backup AndroidExtraído ({target})",
        description: "Verifica pasta de backup Android contra IOCs e grava resultados em exports",
        argsTemplate: "check-backup --output {exports}/mvt-report {target}",
      },
      {
        id: "mvt-check-adb",
        label: "Coletar & Auditar Dispositivo Android via ADB",
        description: "Inspeciona aparelho conectado via USB/ADB em busca de artefatos suspeitos",
        argsTemplate: "check-adb --output {exports}/mvt-adb",
      },
    ],
  },
  {
    slotId: "metasploit",
    name: "Metasploit Framework Oficial (msfconsole / msfvenom)",
    shortLabel: "Metasploit",
    category: "recon_network_ad",
    kind: "cli_runner",
    tagline: "Validação de exploração autorizada, módulos auxiliares de enumeração e geração de artefatos de laboratório",
    description:
      "Integra o Metasploit Framework oficial (`msfconsole`) instalado nativamente no Kali WSL2 ou Windows, permitindo pesquisar módulos CVE, rodar scanners auxiliares não-interativos (`-q -x`) dentro de alvos em escopo e registrar toda a saída com custódia SHA-256.",
    upstreamUrl: "https://github.com/rapid7/metasploit-framework",
    licenseNote: "BSD-3-Clause / Rapid7 (Processo Externo)",
    windowsBinaries: ["msfconsole.bat", "msfconsole.exe"],
    windowsKnownPaths: ["C:\\metasploit-framework\\bin\\msfconsole.bat"],
    posixBinaries: ["msfconsole", "msfvenom"],
    posixKnownPaths: ["/usr/bin/msfconsole", "/opt/metasploit-framework/bin/msfconsole"],
    installPowerShell:
      "'apt-get update && apt-get install -y metasploit-framework' | wsl -d kali-linux -u root -- bash -s",
    installKaliWsl: "sudo apt-get update && sudo apt-get install -y metasploit-framework",
    presets: [
      {
        id: "msf-search-cve",
        label: "Pesquisar Módulos / CVEs no Metasploit",
        description: "Busca módulos exploits e auxiliary correspondentes ao termo {target}",
        argsTemplate: '-q -x "search {target}; exit"',
      },
      {
        id: "msf-version-db",
        label: "Verificar Versão & Status do Banco Metasploit",
        description: "Confere versão de módulos carregados e conexão PostgreSQL",
        argsTemplate: '-q -x "version; db_status; exit"',
      },
    ],
  },
  {
    slotId: "impacket-hashcat",
    name: "Impacket Suite + Evil-WinRM + Hashcat / John",
    shortLabel: "Impacket / Hashcat",
    category: "recon_network_ad",
    kind: "cli_runner",
    tagline: "Kerberoasting, AS-REP Roasting, SMB/LDAP dumping e auditoria de força de hashes NTLMv2/JWT/Kerberos",
    description:
      "Reúne a suíte oficial Fortra Impacket (`impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-secretsdump`), `evil-winrm` e `hashcat`/`john` para operações completas de Active Directory e auditoria de senhas/JWTs.",
    upstreamUrl: "https://github.com/fortra/impacket",
    licenseNote: "Apache-2.0 / MIT (Externo em Kali WSL2 / Windows)",
    windowsBinaries: ["hashcat.exe", "GetUserSPNs.py"],
    posixBinaries: ["hashcat", "john", "impacket-GetUserSPNs", "evil-winrm"],
    posixKnownPaths: ["/usr/bin/hashcat", "/usr/bin/john", "/usr/bin/impacket-GetUserSPNs", "/usr/bin/evil-winrm"],
    installPowerShell: "winget install --id Hashcat.Hashcat -e",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y python3-impacket impacket-scripts evil-winrm hashcat john wordlists",
    presets: [
      {
        id: "hashcat-benchmark",
        label: "Hashcat — Dispositivos & Benchmark Rápido (NTLM / JWT)",
        description: "Lista GPUs/CPUs detectadas pelo Hashcat",
        argsTemplate: "-I",
      },
      {
        id: "hashcat-jwt",
        label: "Hashcat — Auditar Segredo JWT HS256 (-m 16500)",
        description: "Testa hash/token salvo em {target} contra rockyou.txt",
        argsTemplate: "-m 16500 -a 0 {target} /usr/share/wordlists/rockyou.txt",
      },
    ],
  },
  {
    slotId: "strix",
    name: "Strix — Autonomous AI Pentesting Agents (usestrix/strix)",
    shortLabel: "Strix AI",
    category: "ai_offensive_agents",
    kind: "cli_runner",
    tagline: "Agentes autônomos open-source (Apache-2.0) que testam apps dinamicamente, validam PoCs reais e propõem correções",
    description:
      "Executa o CLI oficial `strix` (`usestrix/strix`) para orquestrar agentes de pentest que analisam código e endpoints em escopo, validam vulnerabilidades com provas de conceito reais (zero falso-positivo) e salvam relatórios estruturados.",
    upstreamUrl: "https://github.com/usestrix/strix",
    licenseNote: "Apache-2.0 Oficial (Processo Externo)",
    windowsBinaries: ["strix.exe", "strix.cmd"],
    posixBinaries: ["strix"],
    posixKnownPaths: ["~/.local/bin/strix", "/usr/local/bin/strix", "/root/.local/bin/strix"],
    installPowerShell: "pip install -U strix-agent",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y curl pipx python3-venv && (curl -sSL https://strix.ai/install | bash || PIPX_BIN_DIR=/usr/local/bin sudo pipx install strix-agent)",
    presets: [
      {
        id: "strix-help",
        label: "Verificar Versão & Opções do Strix AI",
        description: "Exibe comandos e provedores LLM suportados pelo Strix",
        argsTemplate: "--help",
      },
      {
        id: "strix-scan-target",
        label: "Executar Avaliação Strix no Alvo / Repositório ({target})",
        description: "Inicia avaliação dinâmica com validação de PoC contra {target}",
        argsTemplate: "--target {target}",
      },
    ],
  },
  {
    slotId: "shannon",
    name: "Shannon — AI Pentester for Web Apps & APIs (KeygraphHQ)",
    shortLabel: "Shannon AI",
    category: "ai_offensive_agents",
    kind: "cli_runner",
    tagline: "Pentester autônomo Web/API ('No exploit, no report') rodando 100% desacoplado como ferramenta externa",
    description:
      "Como o Shannon possui licença AGPL-3.0, nenhum código dele entra no repositório MIT do CyberLab OS: este slot executa diretamente o pacote oficial `@keygraph/shannon` instalado externamente no seu sistema para auditar aplicações Web e APIs.",
    upstreamUrl: "https://github.com/KeygraphHQ/shannon",
    licenseNote: "AGPL-3.0 (100% Externo via CLI Oficial — zero código embutido)",
    windowsBinaries: ["shannon.cmd", "shannon"],
    windowsKnownPaths: ["%APPDATA%\\npm\\shannon.cmd"],
    posixBinaries: ["shannon"],
    posixKnownPaths: ["/usr/local/bin/shannon", "/usr/bin/shannon"],
    installPowerShell: "npm install --global @keygraph/shannon@latest",
    installKaliWsl: "sudo apt-get update && sudo apt-get install -y nodejs npm && sudo npm install --global @keygraph/shannon@latest",
    presets: [
      {
        id: "shannon-help",
        label: "Verificar CLI Oficial do Shannon",
        description: "Exibe opções de execução e configuração BYOK do Shannon",
        argsTemplate: "--help",
      },
    ],
  },
  {
    slotId: "hexstrike-ai",
    name: "HexStrike AI MCP — Ponte para 150+ Ferramentas Ofensivas",
    shortLabel: "HexStrike MCP",
    category: "ai_offensive_agents",
    kind: "cli_runner",
    tagline: "Servidor MCP e API local (MIT) em `/opt/hexstrike-ai` que conecta LLMs a mais de 150 ferramentas do Kali",
    description:
      "Instala e gerencia o servidor oficial `0x4m4/hexstrike-ai` em ambiente Python isolado (`/opt/hexstrike-ai`), permitindo iniciar a API REST (`:8888`) ou plugar `hexstrike_mcp.py` diretamente como servidor MCP de ferramentas Kali.",
    upstreamUrl: "https://github.com/0x4m4/hexstrike-ai",
    licenseNote: "MIT Oficial (Externo em /opt/hexstrike-ai)",
    windowsBinaries: [],
    posixBinaries: ["hexstrike-server"],
    posixKnownPaths: ["/usr/local/bin/hexstrike-server", "/opt/hexstrike-ai/hexstrike_server.py"],
    installPowerShell:
      "'apt-get update && apt-get install -y git python3-venv python3-pip && rm -rf /opt/hexstrike-ai && git clone --depth 1 https://github.com/0x4m4/hexstrike-ai.git /opt/hexstrike-ai && python3 -m venv /opt/hexstrike-ai/venv && /opt/hexstrike-ai/venv/bin/pip install -U pip -r /opt/hexstrike-ai/requirements.txt && ln -sf /opt/hexstrike-ai/hexstrike_server.py /usr/local/bin/hexstrike-server && chmod +x /opt/hexstrike-ai/hexstrike_server.py' | wsl -d kali-linux -u root -- bash -s",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y git python3-venv python3-pip && sudo rm -rf /opt/hexstrike-ai && sudo git clone --depth 1 https://github.com/0x4m4/hexstrike-ai.git /opt/hexstrike-ai && sudo python3 -m venv /opt/hexstrike-ai/venv && sudo /opt/hexstrike-ai/venv/bin/pip install -U pip -r /opt/hexstrike-ai/requirements.txt && printf '#!/bin/sh\\nexec /opt/hexstrike-ai/venv/bin/python /opt/hexstrike-ai/hexstrike_server.py \"$@\"\\n' | sudo tee /usr/local/bin/hexstrike-server >/dev/null && sudo chmod +x /usr/local/bin/hexstrike-server",
    presets: [
      {
        id: "hexstrike-help",
        label: "Verificar Servidor HexStrike AI (:8888)",
        description: "Testa inicialização e argumentos do HexStrike AI Server",
        argsTemplate: "--help",
      },
    ],
  },
  {
    slotId: "pentagi",
    name: "PentAGI — Sistema Multi-Agente Autônomo de Pentest (Web UI)",
    shortLabel: "PentAGI",
    category: "ai_offensive_agents",
    kind: "web_embed",
    tagline: "Plataforma multi-agente autônoma (MIT, vxcontrol/pentagi) com painel Web próprio incorporável no centro",
    description:
      "Permite clonar e subir o stack oficial `vxcontrol/pentagi` (Docker Compose em `:8443`) e incorporar a interface Web do PentAGI diretamente no palco central do CyberLab OS.",
    upstreamUrl: "https://github.com/vxcontrol/pentagi",
    licenseNote: "MIT Oficial (Stack Docker Externo)",
    windowsBinaries: ["docker.exe"],
    posixBinaries: ["pentagi", "docker"],
    posixKnownPaths: ["/opt/pentagi/docker-compose.yml", "/usr/bin/docker"],
    defaultEmbedUrl: "https://127.0.0.1:8443",
    installPowerShell: "git clone https://github.com/vxcontrol/pentagi.git C:\\CyberLab-Tools\\pentagi",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y git && sudo rm -rf /opt/pentagi && sudo git clone --depth 1 https://github.com/vxcontrol/pentagi.git /opt/pentagi",
    presets: [],
  },
  {
    slotId: "pentestgpt-cai",
    name: "PentestGPT & CAI (Cybersecurity AI Framework)",
    shortLabel: "PentestGPT / CAI",
    category: "ai_offensive_agents",
    kind: "cli_runner",
    tagline: "Pipelines multi-estágio para Pentest, Bug Bounty e CTF (`GreyDGL/PentestGPT` + `aliasrobotics/cai`)",
    description:
      "Executa o PentestGPT ou o framework CAI instalados em ambiente Python isolado (`/opt/cyberlab-ai-pentest`) no Kali WSL2 sem poluir pacotes do sistema.",
    upstreamUrl: "https://github.com/GreyDGL/PentestGPT",
    licenseNote: "MIT / Pesquisa Externa (WSL2 Python Venv)",
    windowsBinaries: ["pentestgpt.exe", "cai.exe"],
    posixBinaries: ["pentestgpt", "cai"],
    posixKnownPaths: ["/usr/local/bin/pentestgpt", "/usr/local/bin/cai", "/opt/cyberlab-ai-pentest/bin/cai"],
    installPowerShell:
      "'apt-get update && apt-get install -y python3-venv python3-pip git && python3 -m venv /opt/cyberlab-ai-pentest && /opt/cyberlab-ai-pentest/bin/pip install -U pip cai-framework && ln -sf /opt/cyberlab-ai-pentest/bin/cai /usr/local/bin/cai' | wsl -d kali-linux -u root -- bash -s",
    installKaliWsl:
      "sudo apt-get update && sudo apt-get install -y python3-venv python3-pip git && sudo python3 -m venv /opt/cyberlab-ai-pentest && sudo /opt/cyberlab-ai-pentest/bin/pip install -U pip cai-framework && sudo ln -sf /opt/cyberlab-ai-pentest/bin/cai /usr/local/bin/cai",
    presets: [
      {
        id: "cai-help",
        label: "Verificar Agentes CAI Disponíveis",
        description: "Lista opções e agentes ofensivos/defensivos do CAI",
        argsTemplate: "--help",
      },
    ],
  },
  {
    slotId: "tor-onionshare",
    name: "Tor + Torsocks + OnionShare (Transporte Anônimo & Entrega E2EE)",
    shortLabel: "Tor / OnionShare",
    category: "privacy_opsec_crypto",
    kind: "cli_runner",
    tagline: "Proxy anônimo SOCKS5 (`:9050`), roteamento `torsocks` e entrega efêmera de relatórios via OnionShare",
    description:
      "Integra os binários oficiais do Tor Project (`tor`, `torsocks`) e `onionshare-cli` para roteamento opcional de reconhecimento passivo ou compartilhamento anônimo criptografado de bundles de evidências.",
    upstreamUrl: "https://github.com/onionshare/onionshare",
    licenseNote: "BSD-3-Clause (Tor) / GPL-3.0 (OnionShare Externo)",
    windowsBinaries: ["tor.exe", "onionshare-cli.exe", "onionshare.exe"],
    windowsKnownPaths: [
      "%ProgramFiles%\\OnionShare\\onionshare-cli.exe",
      "%ProgramFiles%\\OnionShare\\onionshare.exe",
    ],
    posixBinaries: ["onionshare-cli", "torsocks", "tor"],
    posixKnownPaths: ["/usr/bin/onionshare-cli", "/usr/bin/torsocks", "/usr/sbin/tor", "/usr/bin/tor"],
    companionProxyPort: 9050,
    installPowerShell: "winget install --id OnionShare.OnionShare -e",
    installKaliWsl: "sudo apt-get update && sudo apt-get install -y tor torsocks onionshare",
    presets: [
      {
        id: "tor-version-check",
        label: "Verificar Versão & Ferramentas Tor / OnionShare",
        description: "Exibe ajuda e modos de compartilhamento seguro",
        argsTemplate: "--help",
      },
    ],
  },
  {
    slotId: "veracrypt",
    name: "VeraCrypt Oficial — Cofres Criptografados de Evidências",
    shortLabel: "VeraCrypt",
    category: "privacy_opsec_crypto",
    kind: "desktop_gui",
    tagline: "Volumes criptografados AES-256 / Serpent / Twofish para custódia física de achados críticos e chaves",
    description:
      "Abre a interface gráfica oficial do VeraCrypt (em janela nativa do Windows ou dentro do palco central X11/noVNC no Linux/WSL2) para montar e desmontar cofres criptografados onde você guarda dumps e escopos confidenciais.",
    upstreamUrl: "https://github.com/veracrypt/VeraCrypt",
    licenseNote: "Apache-2.0 / TrueCrypt 3.0 (Binário Oficial Externo)",
    windowsBinaries: ["VeraCrypt.exe"],
    windowsKnownPaths: [
      "%ProgramFiles%\\VeraCrypt\\VeraCrypt.exe",
      "C:\\Program Files\\VeraCrypt\\VeraCrypt.exe",
    ],
    posixBinaries: ["veracrypt"],
    posixKnownPaths: ["/usr/bin/veracrypt", "/usr/local/bin/veracrypt"],
    installPowerShell: "winget install --id IDRIX.VeraCrypt -e",
    installKaliWsl: "sudo apt-get update && sudo apt-get install -y veracrypt || sudo apt-get install -y cryptsetup",
    presets: [],
  },
  {
    slotId: "mullvad-opsec",
    name: "OpSec Check — Mullvad VPN, Signal & GrapheneOS ADB Hardening",
    shortLabel: "Mullvad / GrapheneOS",
    category: "privacy_opsec_crypto",
    kind: "cli_runner",
    tagline: "Verificação pré-voo de túnel Mullvad VPN, kill-switch e auditoria de hardening/boot Android & GrapheneOS via ADB",
    description:
      "Consolida os utilitários de OpSec e privacidade do inventário original: verifica o estado do túnel/kill-switch da Mullvad VPN (`mullvad status`), inspeciona propriedades de segurança SELinux/Verified Boot de aparelhos GrapheneOS/Android via `adb` e valida prontidão de canal seguro externo.",
    upstreamUrl: "https://github.com/mullvad/mullvadvpn-app",
    licenseNote: "GPL-3.0 / Apache-2.0 (Somente Consulta de Estado Local)",
    windowsBinaries: ["mullvad.exe", "adb.exe"],
    windowsKnownPaths: [
      "%ProgramFiles%\\Mullvad VPN\\resources\\mullvad.exe",
      "C:\\Program Files\\Mullvad VPN\\resources\\mullvad.exe",
      "%LOCALAPPDATA%\\Android\\Sdk\\platform-tools\\adb.exe",
    ],
    posixBinaries: ["mullvad", "adb"],
    posixKnownPaths: ["/usr/bin/mullvad", "/usr/bin/adb"],
    installPowerShell: "winget install --id MullvadVPN.MullvadVPN -e; winget install --id Google.PlatformTools -e",
    installKaliWsl: "sudo apt-get update && sudo apt-get install -y adb android-sdk-platform-tools-common curl",
    presets: [
      {
        id: "opsec-status",
        label: "Verificar Status de Túnel / Dispositivos Conectados",
        description: "Consulta status do cliente Mullvad ou lista dispositivos ADB",
        argsTemplate: "status",
      },
      {
        id: "grapheneos-hardening-audit",
        label: "Auditar Verified Boot, Patch Level & SELinux (GrapheneOS / Android ADB)",
        description: "Lê propriedades de segurança do dispositivo Android/GrapheneOS via adb shell",
        argsTemplate: "shell getprop ro.boot.verifiedbootstate",
      },
    ],
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
