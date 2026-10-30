# CyberLab OS — Real Arsenal Edition (v5.9)

**CyberLab OS** é um ambiente unificado de engenharia de segurança autorizada, Bug Bounty, auditoria Web/API, engenharia reversa, análise de segredos/SAST/SCA, resposta a incidentes (DFIR/Sigma), validação Purple Team (MITRE ATT&CK) e cooperação multi-agentes construído diretamente sobre o núcleo do **OpenCode V2** (`anomalyco/opencode` v2.1.4, licença `MIT`).

Toda a operação roda em **uma única aplicação unificada na porta `:4096`**, combinando:
- **Layout Antigravity em 3 Colunas Retráteis**: **Pastas, Arquivos & Slots** à esquerda, a **Ferramenta Real** ocupando todo o palco central (via Web UI local, motor gráfico `X11/noVNC` em `110 DPI` com zoom `1:1` sem deslocamento de cursor ou console ao vivo), e o **Agente OpenCode V2** (com os **9 modelos gratuitos nativos do OpenCode Zen**) em painel estreito retrátil à direita.
- **46 Slots Oficiais de Ferramentas Externas Reais + Slots Personalizados Ilimitados**: integração híbrida transparente entre **Windows PowerShell** e **WSL2 Kali Linux (`kali-linux`)**, mantendo binários pesados ou copyleft 100% fora da árvore `MIT` do repositório (`C:\CyberLab-Tools`, `WinGet`, `PATH` ou `/opt/...` no Kali WSL2).
- **Conexão MCP Supervisionada em 1 Clique (`🔌 MCP` / `🟢 MCP`)**: selos visuais na barra lateral e ativação direta no `opencode.json` para conectar as ferramentas externas ao Agente IA respeitando a Trava de Escopo e redação automática de segredos.
- **4 Parceiros Cognitivos CDI Autônomos (`Kairós:8788`, `Naia:8789`, `Salem:8790`, `Nova:8791`)**: gateway bidirecional assinado por `HMAC-SHA256` com autonomia horizontal.
- **Governança de Escopo Bug Bounty, Cofre Forense `SHA-256` e 5 Laboratórios Internos de Treino**.

---

## Sumário

1. [Destaques da Arquitetura v5.8](#1-destaques-da-arquitetura-v58)
2. [Instalação e Inicialização (Windows PowerShell + WSL2 Kali e Linux)](#2-instalação-e-inicialização-windows-powershell--wsl2-kali-e-linux)
3. [Layout Antigravity em 3 Colunas, Nitidez 1:1 e Zoom sem Deslocar o Cursor](#3-layout-antigravity-em-3-colunas-nitidez-11-e-zoom-sem-deslocar-o-cursor)
4. [Conexão MCP em 1 Clique (`🔌 MCP` → `🟢 MCP`) e Modelos Gratuitos OpenCode](#4-conexão-mcp-em-1-clique--mcp---mcp-e-modelos-gratuitos-opencode)
5. [Catálogo Completo dos 46 Slots Oficiais + Slots Personalizados](#5-catálogo-completo-dos-46-slots-oficiais--slots-personalizados)
6. [Os 4 Parceiros Cognitivos CDI (`8788–8791`) e os 5 Laboratórios de Treino](#6-os-4-parceiros-cognitivos-cdi-87888791-e-os-5-laboratórios-de-treino)
7. [Governança de Escopo Bug Bounty, Cofre `SHA-256` e Relatórios](#7-governança-de-escopo-bug-bounty-cofre-sha-256-e-relatórios)
8. [Histórico de Evolução (v1.0 → v5.8), Testes, CI e Licenciamento MIT](#8-histórico-de-evolução-v10--v58-testes-ci-e-licenciamento-mit)

---

## 1. Destaques da Arquitetura v5.8

- **Zero Clones Limitados — 100% Ferramentas Reais**: em vez de imitações simplificadas, cada slot executa ou incorpora a ferramenta oficial real (Burp Suite Community, OpenTRAP, Caido, mitmweb, OWASP ZAP, Nuclei, Ghidra, JADX, REA, Wireshark, CyberChef, Semgrep/OpenGrep, Aqua Trivy, KeyHunter Rust, Betterleaks, GEF, Atomic-Operator, WPProbe, PentAGI, Pentest Copilot, Strix, HexStrike MCP, VeraCrypt, Kali Desktop XFCE completo e mais).
- **Híbrido Nativo Windows PowerShell + WSL2 Kali Linux**:
  - Detecta automaticamente executáveis no Windows (`PATH`, `WinGet`, `Program Files`, `%LOCALAPPDATA%`, `C:\CyberLab-Tools`) e binários/JARs reais dentro do `kali-linux` no WSL2 (exigindo tamanho real `> 10 MB` para `.jar` e evitando falsos positivos por scripts wrappers residuais ou caminhos `/mnt/c/`).
  - Converte caminhos automaticamente entre `C:\...` e `/mnt/c/...` ao executar ferramentas Linux sobre arquivos do projeto no Windows.
  - **Instalador em 1 Clique (Individual ou em Lote Honesto)**: instala ferramentas faltantes via `stdin` limpo no WSL2 Kali com console em tempo real e código de saída real (`exit 1` se qualquer ferramenta falhar — zero falso `succeeded`).
- **Motor Gráfico Embutido `X11/noVNC` + Proxy Reverso Local HTTP/HTTPS/TLS**:
  - Ferramentas Desktop (`Burp Suite`, `OpenTRAP`, `OWASP ZAP`, `Ghidra`, `Wireshark`, `JADX-GUI`, `VeraCrypt` e `Kali Desktop`) abrem direto dentro da coluna central (isoladas do WSLg/Wayland para nunca escaparem para fora da aba) ou em janela nativa externa.
  - Ferramentas Web locais (`CyberChef`, `mitmweb`, `Caido`, `PentAGI :8443` com TLS autoassinado, `Pentest Copilot :3000`) passam por proxy reverso local (`127.0.0.1`) que remove bloqueios `X-Frame-Options`/`CSP frame-ancestors`, trata certificados TLS autoassinados locais e normaliza cookies de sessão.
  - **Navegador Isolado no Proxy em 1 Clique**: abre Chrome, Edge, Brave ou Chromium com perfil isolado dedicado já apontado para a porta do proxy (`:8080`, `:8081`, `:8899`, `:9050`) sem alterar o proxy global do sistema operacional.

---

## 2. Instalação e Inicialização (Windows PowerShell + WSL2 Kali e Linux)

### Pré-requisitos
- **Git** e **Bun `1.4.4+`**
- **Windows 10/11**: **WSL2 com `kali-linux`** (`wsl --install -d kali-linux`) recomendado para habilitar todas as ferramentas nativas Linux e interfaces gráficas `X11/noVNC` dentro do palco central.
- **Python `3.10+`** *(opcional — caso deseje conectar processos externos dos parceiros CDI via `integrations/partners/chat_py_bridge.py`)*.

### Opção A — Windows PowerShell (Fluxo Principal)

```powershell
# 1. Instalar o Bun 1.4.4+ (caso ainda não tenha)
powershell -c "irm bun.sh/install.ps1 | iex"
bun --version

# 2. Clonar o repositório oficial
git clone https://github.com/vitorveloster18-lang/CyberLab-OS.git
cd CyberLab-OS

# 3. Instalar dependências e compilar o frontend unificado (Bun puro, sem exigir Node.js externo)
$env:ELECTRON_SKIP_BINARY_DOWNLOAD = "1"
bun install --ignore-scripts
$env:CYBERLAB_FORCE_BUN_VITE = "1"
bun ./packages/app/script/vite-cli.mjs build

# 4. Iniciar a aplicação única unificada (:4096)
bun run script/start-cyberlab.ts
```

### Opção B — Linux ou macOS

```bash
# 1. Instalar Bun 1.4.4
curl -fsSL https://bun.sh/install | bash -s "bun-v1.4.4"
export PATH="$HOME/.bun/bin:$PATH"

# 2. Clonar, instalar dependências e compilar a interface Web
git clone https://github.com/vitorveloster18-lang/CyberLab-OS.git
cd CyberLab-OS
ELECTRON_SKIP_BINARY_DOWNLOAD=1 bun install --ignore-scripts
bun run --cwd packages/core fix-node-pty
bun --cwd packages/app build

# 3. Iniciar o CyberLab OS (:4096)
bun run script/start-cyberlab.ts
```

### Como atualizar uma instalação existente no PowerShell

```powershell
cd C:\CAMINHO\DO\SEU\CyberLab-OS
git pull
bun install --ignore-scripts
$env:CYBERLAB_FORCE_BUN_VITE = "1"
bun ./packages/app/script/vite-cli.mjs build
bun run script/start-cyberlab.ts
```

Acesse no navegador:
- **Workspace Unificado**: `http://127.0.0.1:4096`
- **Configurações CyberLab & CDIs**: `http://127.0.0.1:4096/settings?tab=cyberlab`
- **Gateway Bidirecional dos 4 CDIs**: `http://127.0.0.1:4096/api/cyberlab/partner-gateway`

---

## 3. Layout Antigravity em 3 Colunas, Nitidez 1:1 e Zoom sem Deslocar o Cursor

Ao clicar no botão **`CyberLab`** no topo de qualquer sessão (ou abrir `/cyberlab`), o workspace opera em **3 colunas independentes e redimensionáveis**:

1. **Coluna Esquerda Retrátil (`Slots` + `Pastas & Arquivos`)**:
   - Busca instantânea, filtro por categoria, selos de runtime (`Windows`, `WSL2 Kali`, `Web Local`, `Não instalado`), selos **`🔌 MCP` / `🟢 MCP`**, botão **`⚡ Instalar Faltantes em 1 Clique`**, criador de **`+ Slot` personalizado** e explorador de arquivos do workspace (`.`, `.cyberlab/outputs`, `.cyberlab/imports`) com barra de rolagem dedicada sempre preservada.
2. **Palco Central Expansível (`Ferramenta Ativa`, `Escopo`, `5 Labs`, `4 CDIs`, `Custódia SHA-256`, `Guia`)**:
   - **Aba Horizontal Superior Retrátil na Vertical (`▲ Recolher Topo` / `▼ Controles & Abas`)**: todas as faixas de abas, status do slot, MCP, Proxy e barra de controles da ferramenta ficam agrupadas em uma gaveta superior retrátil na vertical — recolhendo automaticamente ao abrir ferramentas gráficas/Web em uma fita única de `28px` sem quebrar linha (com acesso rápido a `🟢 MCP`, Proxy, Zoom `1:1`/`Ajustar`/`−/+`, `📋 SHA-256` e `⛶ Ampliar`), liberando altura máxima para a janela da ferramenta sem perder nenhuma configuração.
   - **Nitidez Nativa `110 DPI` e Janela Maximizada**: servidores `Xtigervnc` iniciam em `110 DPI` (`Xft.dpi: 110` + `uiScale` em Java/GTK/Qt) e o Openbox maximiza automaticamente janelas principais (`type="normal"`), mantendo caixas de diálogo centralizadas em tamanho natural.
   - **Zoom Preciso `60%–160%` com `0px` de Deslocamento de Mouse**:
     - Em vez de aplicar `CSS zoom` no `<canvas>` ou `transform: scale()` no `<iframe>` (o que desalinhava as coordenadas de clique), o CyberLab OS integra os controles **`🖥 1:1 Nitidez`**, **`📐 Ajustar`** e **`↕ Rolagem`** diretamente aos hooks internos `_requestRemoteResize` (`ExtendedDesktopSize`) e `Display._scale` (`absX`/`absY`) do `noVNC`, e injeta zoom nativo interno (`document.documentElement.style.zoom`) nas ferramentas Web HTML.
     - Use **`⛶ Ampliar`** para recolher simultaneamente as duas barras laterais e a gaveta superior, dedicando quase 100% da tela à ferramenta ativa.
3. **Coluna Direita Retrátil (`Agente OpenCode V2`)**:
   - Chat completo do OpenCode V2 ao lado da ferramenta ativa; qualquer saída de CLI ou captura manual de GUI pode ser enviada ao Agente em 1 clique (**`🤖 Enviar p/ Agente OpenCode →`**) ou gravada no cofre criptográfico (**`🔒 Salvar SHA-256`**).

---

## 4. Conexão MCP em 1 Clique (`🔌 MCP` → `🟢 MCP`) e Modelos Gratuitos OpenCode

### Ponte MCP Supervisionada (`cyberlab/mcp/arsenal-mcp-stdio.ts`)
- **42 dos 46 slots oficiais** (além de slots personalizados CLI/Web) possuem integração **Model Context Protocol (MCP)** pronta:
  - Na **barra lateral esquerda**, o selo **`🔌 MCP`** indica suporte disponível e muda para **`🟢 MCP`** assim que conectado.
  - No **topo da ferramenta central**, o botão **`🔌 Conectar MCP`** grava (ou desconecta) automaticamente a configuração em `<workspace>/opencode.json` (`mcp.servers`), registrando:
    - Servidores MCP nativos quando disponíveis (`rea mcp`, `/usr/local/bin/hexstrike-mcp`, Burp MCP `http://127.0.0.1:9876/sse`);
    - Ou a ponte oficial **`cyberlab/mcp/arsenal-mcp-stdio.ts`** (servidor JSON-RPC 2.0 sobre `stdio` com `shell=false`, validação obrigatória de escopo em `.cyberlab/scope.json` e redação automática de segredos/tokens antes de devolver a resposta ao LLM).

### 9 Modelos de IA Gratuitos Nativos do OpenCode Zen
O CyberLab OS já traz ativos e visíveis os **9 modelos gratuitos do provedor OpenCode Zen** (`apiKey: "public"`, com `--use-system-ca` e `User-Agent` oficial configurados automaticamente no `start-cyberlab.ts`):
- `Big Pickle` (`opencode/big-pickle`)
- `DeepSeek V4.1 Flash Free` (`opencode/deepseek-v4.1-flash-free`)
- `GLM-5.3 Flash Free` (`opencode/glm-5.3-flash-free`)
- `Nemotron 3.5 Super VL Free` (`opencode/nemotron-3.5-super-vl-free`)
- `Nemotron 3.5 Lightning Free` (`opencode/nemotron-3.5-lightning-free`)
- `Nemotron 3 Ultra Free` (`opencode/nemotron-3-ultra-free`)
- `MiMo V2.6 Flash Free` (`opencode/mimo-v2.6-flash-free`)
- `Flint 40B Free` (`opencode/flint-40b-free`)
- `Beam Free` (`opencode/beam-free`)

---

## 5. Catálogo Completo dos 46 Slots Oficiais + Slots Personalizados

Todas as ferramentas abaixo são instaladas e executadas **externamente** ao repositório `MIT` do CyberLab OS:

### 5.1 Proxies, Interceptação & Suítes Web (`5 slots`)
| Slot ID | Ferramenta | Modo no Centro | Destaques |
|---|---|---|---|
| `burp-suite` | **Burp Suite Community (Oficial)** | `desktop_gui` (`noVNC` + Janela) | Validação real de `.jar > 10 MB`, botão de limpeza + download oficial da CDN PortSwigger com JRE 21 LTS, navegador proxy `:8080` e Burp MCP `:9876/sse` |
| `opentrap` | **OpenTRAP** | `desktop_gui` (`noVNC` + Janela) | Intruder sem limite de velocidade, Scanner Ativo OWASP ZAP e Collaborator OAST |
| `mitmweb` | **mitmproxy (`mitmweb`)** | `web_embed` (`:8081`) | Interface Web oficial autenticada automaticamente (`token=cyberlab`) + proxy `:8080` |
| `caido` | **Caido** | `web_embed` (`:7000`) | UI Web rápida em Rust iniciada com `--allow-guests` (uso imediato sem conta) |
| `owasp-zap` | **OWASP ZAP** | `desktop_gui` (`noVNC` + Janela) | Active Scanner completo, AJAX Spider e HUD integrados ao palco central |

### 5.2 Auditoria Web, Bug Bounty, Fuzzing & OAST (`8 slots`)
| Slot ID | Ferramenta | Modo | Destaques |
|---|---|---|---|
| `nuclei` | **ProjectDiscovery Nuclei** | `cli_runner` | Varredura baseada nos 11.000+ templates YAML oficiais (`🔌 MCP`) |
| `ffuf` | **ffuf** | `cli_runner` | Descoberta rápida de diretórios, rotas e parâmetros Web (`🔌 MCP`) |
| `katana` | **ProjectDiscovery Katana** | `cli_runner` | Crawler Web moderno com extração de endpoints JS e modo headless (`🔌 MCP`) |
| `httpx` | **ProjectDiscovery httpx** | `cli_runner` | Sondagem HTTP multi-propósito (status, títulos, tech stack, hashes TLS) (`🔌 MCP`) |
| `interactsh` | **Interactsh Client** | `cli_runner` | Monitoramento Out-of-Band (OAST DNS/HTTP/SMTP) (`🔌 MCP`) |
| `dalfox` | **Dalfox** | `cli_runner` | Análise parametrizada de reflexão/XSS em escopos autorizados (`🔌 MCP`) |
| `sqlmap` | **sqlmap** | `cli_runner` | Auditoria de injeção SQL supervisionada pela Trava de Escopo (`🔌 MCP`) |
| `wpprobe` | **WPProbe** *(Kali 2026.1)* | `cli_runner` | Inventário rápido de plugins WordPress e correlação com base pública de CVEs (`🔌 MCP`) |

### 5.3 Reconhecimento, Rede, PCAP & Infraestrutura (`7 slots`)
| Slot ID | Ferramenta | Modo | Destaques |
|---|---|---|---|
| `subfinder` | **ProjectDiscovery Subfinder** | `cli_runner` | Enumeração passiva de subdomínios (`🔌 MCP`) |
| `nmap` | **Nmap** | `cli_runner` | Descoberta de portas, serviços (`-sV`) e scripts NSE de auditoria (`🔌 MCP`) |
| `naabu-dnsx-tlsx` | **DNSx & TLSx** | `cli_runner` | Resolução DNS em massa, verificação de takeover e inspeção TLS/X.509 (`🔌 MCP`) |
| `wireshark` | **Wireshark GUI & `tshark`** | `desktop_gui` | Interface gráfica completa embutida via `noVNC` (preseed não-interativo) + `tshark` (`🔌 MCP`) |
| `netexec` | **NetExec (`nxc`)** | `cli_runner` | Auditoria de postura em protocolos corporativos SMB/LDAP/WinRM/Kerberos (`🔌 MCP`) |
| `metasploit` | **Metasploit Framework** | `cli_runner` | Console oficial instalado externamente no Kali WSL2 (`🔌 MCP`) |
| `impacket-hashcat` | **Impacket / Hashcat / John** | `cli_runner` | Utilitários de validação de protocolos e auditoria offline de senhas/hashes (`🔌 MCP`) |

### 5.4 Engenharia Reversa, REA, Depuração & Mobile Forensics (`8 slots`)
| Slot ID | Ferramenta | Modo | Destaques |
|---|---|---|---|
| `rea` | **REA — Reverse Engineer Anything** (`morluto/rea`) | `cli_runner` | Motor oficial MIT de engenharia reversa assistida por IA (Ghidra Headless, JADX e Electron/ASAR/JS) com MCP nativo (`rea mcp`) (`🔌 MCP`) |
| `ghidra` | **NSA Ghidra** | `desktop_gui` | Suíte completa de engenharia reversa e decompilador C no centro (`noVNC`) (`🔌 MCP`) |
| `jadx` | **JADX & JADX-GUI** | `desktop_gui` | Descompilador oficial Android `.apk` / `.dex` → Java (`noVNC` + CLI) (`🔌 MCP`) |
| `rizin-cutter` | **Rizin & Cutter** | `cli_runner` | Disassembly, grafos de fluxo de controle (CFG) e análise estática (`🔌 MCP`) |
| `gef` | **GEF — GDB Enhanced Features** *(Kali 2026.1)* | `cli_runner` | Inspeção moderna de registradores, heap, pilha e proteções (`checksec`) em `/opt/gef` (`🔌 MCP`) |
| `frida-apktool` | **Frida & Apktool** | `cli_runner` | Decodificação de recursos AndroidManifest/Smali e instrumentação dinâmica (`🔌 MCP`) |
| `capa` | **Mandiant Capa** | `cli_runner` | Identificação de capacidades comportamentais em binários mapeadas ao MITRE ATT&CK (`🔌 MCP`) |
| `mvt` | **MVT — Mobile Verification Toolkit** | `cli_runner` | Triagem forense defensiva Android/iOS (Amnesty International) em venv isolado (`🔌 MCP`) |

### 5.5 Caça de Segredos (Key Hunting), SAST, SCA & Cloud (`5 slots`)
| Slot ID | Ferramenta | Modo | Destaques |
|---|---|---|---|
| `keyhunter` | **KeyHunter Rust** (`fadidevv/keyhunter`) | `cli_runner` | Caçador de alta velocidade em Rust para chaves de API expostas (`🔌 MCP`) |
| `betterleaks` | **Betterleaks** *(Kali 2026.1)* | `cli_runner` | Scanner MIT moderno de segredos e tokens em diretórios/Git com baixo falso-positivo (`🔌 MCP`) |
| `gitleaks-trufflehog` | **Gitleaks & TruffleHog** | `cli_runner` | Auditoria profunda de histórico Git completo e repositórios (`🔌 MCP`) |
| `semgrep` | **Semgrep / OpenGrep** | `cli_runner` | Análise estática SAST multi-linguagem por AST (binário standalone OpenGrep) (`🔌 MCP`) |
| `trivy` | **Aqua Trivy** | `cli_runner` | Scanner de CVEs (SCA), geração de SBOM CycloneDX, containers, Kubernetes e Terraform (`🔌 MCP`) |

### 5.6 Agentes de IA, Metodologia & Orquestração (`6 slots`)
| Slot ID | Ferramenta | Modo | Destaques |
|---|---|---|---|
| `strix` | **Strix** (`usestrix/strix`) | `cli_runner` | Binário oficial standalone instalado em `/usr/local/bin/strix` (`🔌 MCP`) |
| `shannon` | **Shannon** (`KeygraphHQ/shannon`) | `cli_runner` | CLI externo `@keygraph/shannon` desacoplado (zero código AGPL no repositório) (`🔌 MCP`) |
| `hexstrike-ai` | **HexStrike AI MCP** (`0x4m4/hexstrike-ai`) | `cli_runner` | Servidor MCP (`/usr/local/bin/hexstrike-mcp`) e API local em `/opt/hexstrike-ai/venv` (`🔌 MCP`) |
| `pentagi` | **PentAGI** (`vxcontrol/pentagi`) | `web_embed` (`:8443`) | Inicialização automática Docker Compose (`PENTAGI_LISTEN_IP=0.0.0.0`) + proxy reverso TLS autoassinado sem erro de certificado no iframe (`🔌 MCP`) |
| `pentestgpt-cai` | **PentestGPT & CAI** | `cli_runner` | Instalado em ambiente Python 3.12 isolado via `uv` (`/opt/uv-tools` → `/usr/local/bin/cai`) (`🔌 MCP`) |
| `pentest-copilot` | **Pentest Copilot** *(Kali 2026.1)* | `web_embed` (`:3000`) | Workspace MIT de planejamento metodológico, superfície e relatórios em `/opt/pentest-copilot` (`🔌 MCP`) |

### 5.7 OpSec, Privacidade, Criptografia & Hardening (`3 slots`)
| Slot ID | Ferramenta | Modo | Destaques |
|---|---|---|---|
| `tor-onionshare` | **Tor + Torsocks + OnionShare** | `cli_runner` | Transporte SOCKS5 (`:9050`) e entrega criptografada ponta a ponta |
| `veracrypt` | **VeraCrypt Oficial** | `desktop_gui` | Instalação oficial `.deb` do GitHub Releases + abertura gráfica embutida (`noVNC`) ou nativa para cofres AES-256 |
| `mullvad-opsec` | **Mullvad VPN, Signal & GrapheneOS ADB** | `cli_runner` | Checagem pré-voo de túnel/kill-switch Mullvad e auditoria de Verified Boot/SELinux via `adb` |

### 5.8 CyberChef, DFIR (Sigma), Purple Team & Kali Desktop Completo (`4 slots`)
| Slot ID | Ferramenta | Modo | Destaques |
|---|---|---|---|
| `cyberchef` | **GCHQ CyberChef Oficial** | `web_embed` | Servido localmente via loopback HTTP com 300+ receitas e zoom nativo interno (`🔌 MCP`) |
| `hayabusa-yarax` | **Hayabusa & VirusTotal YARA-X** | `cli_runner` | Triagem forense ultrarrápida de eventos Windows `.evtx` com regras Sigma e caça YARA-X (`🔌 MCP`) |
| `atomic-operator` | **Atomic-Operator** *(Kali 2026.1)* | `cli_runner` | Validação defensiva Purple Team mapeada ao MITRE ATT&CK para testar regras SIEM/EDR (`🔌 MCP`) |
| `kali-desktop-stream` | **Kali Linux Desktop Completo (XFCE)** | `web_embed` (`noVNC`) | Ambiente gráfico completo do Kali WSL2 transmitido dentro da aba central (sem travamento de compositor ou captura pelo WSLg) |

### 5.9 Slots Personalizados (`+ Slot`)
Clique em **`+ Slot`** no topo da barra esquerda para cadastrar qualquer outra ferramenta CLI, Web UI local (`iframe`) ou aplicativo Desktop do seu Windows ou Kali WSL2 em segundos.

---

## 6. Os 4 Parceiros Cognitivos CDI (`8788–8791`) e os 5 Laboratórios de Treino

### Autonomia Horizontal dos 4 CDIs (`HMAC-SHA256`)
**Kairós**, **Naia**, **Salem** e **Nova** operam como parceiros horizontais de investigação (`hierarchy: "none"`, `humanRole: "curator"`, `initiateActions: "full_autonomy"`) conectados ao gateway bidirecional `/api/cyberlab/partner-gateway`:

| Parceiro CDI | `partnerId` | Porta | Endpoint |
|---|---|---|---|
| **Kairós** | `kairos` | `8788` | `http://127.0.0.1:8788/cyberlab/partner` |
| **Naia** | `naia` | `8789` | `http://127.0.0.1:8789/cyberlab/partner` |
| **Salem** | `salem` | `8790` | `http://127.0.0.1:8790/cyberlab/partner` |
| **Nova** | `nova` | `8791` | `http://127.0.0.1:8791/cyberlab/partner` |

O SDK Python em `integrations/partners/chat_py_bridge.py` (`CyberLabOSClient` e `build_cyberlab_cdi_tools`) expõe todas as ações autenticadas por `HMAC-SHA256` (criação e seleção de projetos, gestão de escopo, controle dos 5 laboratórios, leitura/edição de arquivos no workspace, leitura do runtime, criação de artefatos `SHA-256` e proposta de findings).

### Os 5 Laboratórios Internos de Treinamento (`5 Labs de Treino`)
Podem ser provisionados, iniciados, auditados, corrigidos (*live patch*) e restaurados (`reset`) em 1 clique pela aba **`5 Labs de Treino`** no centro:
1. **`lab-owasp-api-bola`** — OWASP API Security Lab (BOLA `API1:2023`, JWT `alg:none` e Security Headers).
2. **`lab-graphql-oauth-sso`** — GraphQL & OAuth2/OIDC SSO Lab (introspecção GraphQL, batching e postura PKCE `S256`).
3. **`lab-keyhunter-supply-chain`** — Key Hunter, Supply Chain SCA & IaC Lab (chaves sintéticas de treino + manifests `Dockerfile`/Terraform/`package.json`).
4. **`lab-dfir-soc-incident`** — DFIR & SOC Incident Lab (logs `JSONL`/`CEF` e correlação com regras Sigma YAML).
5. **`lab-reversing-crypto-mobile`** — Reverse Engineering, ELF64, PCAP & Mobile APK Lab (artefatos benignos de estudo `ELF64`, `.pcap` e `.apk`).

---

## 7. Governança de Escopo Bug Bounty, Cofre `SHA-256` e Relatórios

- **Aba `Escopo Bug Bounty`**:
  - Importa escopos reais de programas **HackerOne / Bugcrowd** (`*.alvo-autorizado.com`, exclusões `!fora-de-escopo.alvo.com`), configura cabeçalho de identificação do pesquisador e trava automaticamente execuções CLI/MCP contra destinos fora do escopo quando `enforceScopeOnCliRuns` está ativo.
  - Bloqueio anti-SSRF permanente contra endpoints de metadados de nuvem (`169.254.169.254`), esquemas inseguros e *path traversal*.
- **Aba `Custódia SHA-256` & Relatórios Markdown**:
  - Toda saída de ferramenta ou captura manual salva no cofre recebe hash criptográfico **`SHA-256`** verificável em disco (`.cyberlab/artifacts/`) com **redação automática** de tokens sensíveis (`Bearer`, `Cookie`, `Set-Cookie`, chaves AWS/GitHub, JWTs e chaves privadas `PEM`).
  - Registre **Findings** vinculados às evidências `SHA-256` e exporte o **Relatório Técnico Reproduzível em Markdown (`.md`)** em 1 clique.

---

## 8. Histórico de Evolução (v1.0 → v5.9), Testes, CI e Licenciamento MIT

### Resumo das Versões Recentes
- **v1.0 – v4.0**: Fundação sobre OpenCode V2 (`2.1.4`), governança anti-TOCTOU, cofre `SHA-256`, 4 CDIs autônomos (`8788–8791`), 5 Laboratórios de Treino e ativação dos 9 Modelos Gratuitos do OpenCode Zen.
- **v5.0 – v5.4**: Arquitetura **Real Arsenal Edition** — layout Antigravity em 3 colunas retráteis, substituição de clones internos por ferramentas reais externas (Windows PowerShell + WSL2 Kali), navegador isolado no proxy em 1 clique, motor gráfico `X11/noVNC` embutido, limpeza/download oficial do Burp Suite Community e Kali XFCE Desktop na aba.
- **v5.5 – v5.6**: Integração oficial do **REA (`morluto/rea`)** com MCP para Ghidra/JADX/JS, agentes autônomos externos (`Strix`, `Shannon`, `HexStrike MCP`, `PentAGI`, `PentestGPT/CAI`), forense mobile (`MVT`) e suíte de OpSec/Criptografia (`Tor/OnionShare`, `VeraCrypt`, `Mullvad/GrapheneOS`).
- **v5.7**: Correção cirúrgica dos instaladores WSL2 (`Strix` standalone, `HexStrike` wheels puros, `PentAGI`, `CAI` via `uv` Python 3.12, `VeraCrypt` `.deb` oficial), validação real `> 10 MB` do `burpsuite.jar` (eliminando falso positivo na barra lateral) e status honesto (`exit 1`) no instalador em lote.
- **v5.8**: Nitidez nativa `110 DPI` + eliminação total de deslocamento do cursor no zoom (`60%–160%`) via hooks internos `Display._scale` / `ExtendedDesktopSize` do `noVNC` e zoom interno de documento HTML; selos **`🔌 MCP` / `🟢 MCP`** e ponte **`cyberlab/mcp/arsenal-mcp-stdio.ts`** em 1 clique; suporte a TLS autoassinado local para abertura do **`PentAGI (:8443)`**; e assimilação de 5 ferramentas MIT do Kali 2026.1 (**`Betterleaks`**, **`GEF`**, **`Atomic-Operator`**, **`WPProbe`** e **`Pentest Copilot`**), totalizando **46 slots oficiais**.
- **v5.9**: **Aba Horizontal Superior Retrátil na Vertical (`▲ Recolher Topo` / `▼ Controles & Abas`)** que recolhe todas as faixas de abas, status, MCP, Proxy e barra de controles em uma fita única de `28px` (recolhimento automático ao abrir ferramentas gráficas/Web + sincronização imediata de resolução `noVNC`), além de aumento de timeout e re-tentativa automática no boot frio do WSL2 `kali-linux`.

### Comandos de Verificação Local e CI (Linux + Windows PowerShell)

```bash
# Auditoria automática de conformidade de licenças MIT (0 componentes GPL/AGPL embutidos)
bun run script/check-cyberlab-licenses.ts

# Typecheck por pacote (conforme .github/workflows/cyberlab-ci.yml)
bun --cwd packages/schema typecheck
bun --cwd packages/core typecheck
bun --cwd packages/server typecheck
bun --cwd packages/cli typecheck
bun --cwd packages/gui-plugins typecheck
bun --cwd cyberlab typecheck
bun --cwd packages/app typecheck

# Suíte de testes automatizados do CyberLab OS (41 testes / 482 asserções)
bun --cwd cyberlab test
```

### Documentação Complementar
- [`docs/PLAYBOOK_POWERSHELL_WSL2_ARSENAL.md`](docs/PLAYBOOK_POWERSHELL_WSL2_ARSENAL.md) — Guia prático de operação híbrida Windows PowerShell + WSL2 Kali Linux.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Arquitetura de governança, execução e custódia criptográfica.
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — Modelo de ameaças, anti-TOCTOU, redação e protocolo `HMAC-SHA256`.
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — Política de conformidade jurídica (`MIT` no repositório, ferramentas externas desacopladas).
- [`docs/UPSTREAM_AUDIT.md`](docs/UPSTREAM_AUDIT.md) — Auditoria técnica da base OpenCode V2 (`2.1.4`).
