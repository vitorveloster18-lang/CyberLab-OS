# Playbook Oficial — CyberLab OS v5.0 ("Real Arsenal Edition")
## Windows PowerShell + WSL2 Kali Linux + Bancada 3 Colunas (Estilo Antigravity)

Este guia contém **todos os comandos prontos para copiar e colar** no seu **Windows PowerShell** e no **Kali Linux via WSL2**, mantendo **100% das ferramentas pesadas fora do repositório** (`C:\CyberLab-Tools` e `/opt`/`/usr/bin` do WSL2) para que o CyberLab OS continue rápido, leve, sem gambiarras e livre de conflitos de licença.

---

## 1. Como funciona o novo Layout de 3 Colunas (Estilo Antigravity)

Ao clicar em **"Arsenal Real (Modo Antigravity)"** ou **"Abrir 3 Colunas"** dentro do OpenCode (`http://127.0.0.1:4096`):

1. **Coluna Esquerda (Retrátil `«` / `»`) — Pastas, Outputs & Slots**:
   - Alterna entre **Arsenal (29 Slots Oficiais + Slots Custom)** e **Pastas & Outputs** (`.` raiz do projeto, `.cyberlab/outputs` com os logs em tempo real de cada ferramenta executada, e `.cyberlab/imports` com botão **+ Importar PC** para subir APKs, PCAPs, wordlists ou binários).
   - Quando não estiver usando, clique em `«` para recolher para uma barra estreita de `38px`.
2. **Coluna Central (Tela Cheia) — A Ferramenta Real Ocupa Tudo**:
   - **Web UIs Reais Embutidas (`<iframe>` 100% central)**: **CyberChef Oficial (GCHQ)** servido localmente, **mitmweb** (`:8081`), **Caido** (`:7000`), **OWASP ZAP Web**, **Kali Linux Desktop Stream (`Win-KeX` / `noVNC :6080`)**, ou qualquer Web UI adicionada via `+ Slot`.
   - **Console CLI Real em Tempo Real**: Executa binários instalados no **Windows Nativo** ou no **WSL2 Kali Linux** (com tradução automática de caminhos `C:\Users\...` → `/mnt/c/Users/...`!), presets de 1 clique, botão **🔒 Salvar SHA-256** e botão **🤖 Enviar p/ Agente OpenCode →**.
   - **Lançador Desktop / WSLg + Navegador Proxy Isolado de 1 Clique**: Abre **Burp Suite**, **OpenTRAP**, **Ghidra**, **Wireshark**, **JADX-GUI** ou **Rizin/Cutter** + abre uma janela isolada do **Chrome/Edge/Brave** já roteada para `127.0.0.1:8080` (`:8082`, `:7000`, `:8090`).
3. **Coluna Direita (Estreita & Retrátil `»` / `«`) — Agente OpenCode IA**:
   - Mantém sua sessão de chat do OpenCode V2 (com os 9 modelos gratuitos e integração com os 4 CDIs **Kairós**, **Naia**, **Salem** e **Nova**) sempre viva ao lado da ferramenta. Quando não precisar do agente, clique em **Recolher »** sem perder o histórico nem interromper respostas em andamento!

---

## 2. Passo 1 — Preparação Base no Windows PowerShell (Administrador)

Abra o **Windows PowerShell como Administrador** e cole:

```powershell
# 1. Criar a pasta dedicada para ferramentas externas (fora do repositório Git!)
New-Item -ItemType Directory -Force -Path "C:\CyberLab-Tools" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\CyberLab-Tools\bin" | Out-Null

# Adicionar C:\CyberLab-Tools\bin ao PATH do seu usuário no Windows
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*C:\CyberLab-Tools\bin*") {
  [Environment]::SetEnvironmentVariable("Path", "$currentPath;C:\CyberLab-Tools\bin", "User")
}

# 2. Instalar / ativar WSL2 com Kali Linux (suporte nativo WSLg para janelas gráficas Linux no Windows 11!)
wsl --install -d kali-linux
wsl --set-default-version 2
```

> **Nota**: Se for a primeira vez ativando o WSL2 no Windows, reinicie o computador quando solicitado, abra o app **Kali Linux** uma vez para criar seu usuário/senha Linux, e siga para os blocos abaixo.

---

## 3. Passo 2 — Instalar o Arsenal Nativo do Windows via PowerShell (`winget` + `CyberChef`)

No **Windows PowerShell** (pode ser janela normal), cole o bloco completo abaixo para instalar as melhores ferramentas nativas de Windows:

```powershell
# === SUÍTES DE PROXY WEB & INTERCEPTAÇÃO ===
winget install --id PortSwigger.BurpSuite.Community -e --accept-source-agreements --accept-package-agreements
winget install --id Caido.Caido -e --accept-source-agreements --accept-package-agreements
winget install --id ZAP.ZAP -e --accept-source-agreements --accept-package-agreements
winget install --id mitmproxy.mitmproxy -e --accept-source-agreements --accept-package-agreements

# === BUG BOUNTY & RECONHECIMENTO RÁPIDO (PROJECTDISCOVERY + FFUF) ===
winget install --id ProjectDiscovery.Nuclei -e --accept-source-agreements --accept-package-agreements
winget install --id ProjectDiscovery.Subfinder -e --accept-source-agreements --accept-package-agreements
winget install --id ProjectDiscovery.Httpx -e --accept-source-agreements --accept-package-agreements
winget install --id ProjectDiscovery.Katana -e --accept-source-agreements --accept-package-agreements
winget install --id ProjectDiscovery.Naabu -e --accept-source-agreements --accept-package-agreements
winget install --id ProjectDiscovery.Dnsx -e --accept-source-agreements --accept-package-agreements
winget install --id ProjectDiscovery.Tlsx -e --accept-source-agreements --accept-package-agreements
winget install --id ProjectDiscovery.Interactsh -e --accept-source-agreements --accept-package-agreements
winget install --id ffuf.ffuf -e --accept-source-agreements --accept-package-agreements

# === REDE, PACOTES & ENGENHARIA REVERSA ===
winget install --id Insecure.Nmap -e --accept-source-agreements --accept-package-agreements
winget install --id WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements
winget install --id Skylot.Jadx -e --accept-source-agreements --accept-package-agreements
winget install --id Rizin.Cutter -e --accept-source-agreements --accept-package-agreements
winget install --id EclipseAdoptium.Temurin.21.JDK -e --accept-source-agreements --accept-package-agreements

# === SEGREDOS, SAST, SUPPLY CHAIN & CLOUD ===
winget install --id Gitleaks.Gitleaks -e --accept-source-agreements --accept-package-agreements
winget install --id AquaSecurity.Trivy -e --accept-source-agreements --accept-package-agreements
winget install --id Rustlang.Rustup -e --accept-source-agreements --accept-package-agreements

# === CYBERCHEF OFICIAL (GCHQ) — EMBUTIDO EM TELA CHEIA NO CENTRO DO CYBERLAB OS ===
Invoke-WebRequest -Uri "https://github.com/gchq/CyberChef/releases/download/v10.19.4/CyberChef_v10.19.4.zip" -OutFile "$env:TEMP\CyberChef.zip"
Expand-Archive -Force "$env:TEMP\CyberChef.zip" "C:\CyberLab-Tools\CyberChef"

# === CAPA (Mandiant) + HAYABUSA (DFIR Windows Event Logs) ===
Invoke-WebRequest -Uri "https://github.com/mandiant/capa/releases/latest/download/capa-v8.0.1-windows.zip" -OutFile "$env:TEMP\capa.zip"
Expand-Archive -Force "$env:TEMP\capa.zip" "C:\CyberLab-Tools\bin"
```

Para instalar o **KeyHunter Rust CLI** (`fadidevv/keyhunter`) e o **Dalfox** (caso tenha Go/Rust no Windows):

```powershell
cargo install github-keyhunter
```

---

## 4. Passo 3 — Instalar o Arsenal Completo no WSL2 Kali Linux (incluindo OpenTRAP, NetExec, sqlmap, Ghidra e Win-KeX)

Do próprio **Windows PowerShell**, entre no Kali com `wsl -d kali-linux` e cole:

```bash
# 1. Atualizar repositórios Kali e instalar todo o arsenal profissional de uma só vez
sudo apt update && sudo apt install -y \
  kali-win-kex novnc websockify \
  mitmproxy zaproxy sqlmap \
  nmap wireshark tshark netexec \
  ghidra jadx rizin-cutter apktool python3-frida-tools \
  nuclei ffuf subfinder naabu dnsx interactsh-client \
  gitleaks trivy semgrep yara \
  golang-go cargo libfuse2 curl wget unzip jq

# 2. Instalar Dalfox (XSS), httpx, Katana, TruffleHog e KeyHunter Rust CLI
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
cargo install github-keyhunter

# Garantir ~/go/bin e ~/.cargo/bin no PATH do Kali
grep -q 'go/bin' ~/.bashrc || echo 'export PATH="$HOME/go/bin:$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/go/bin:$HOME/.cargo/bin:$PATH"

# 3. Instalar OpenTRAP (AppImage oficial Linux x86_64) em /opt/opentrap
sudo mkdir -p /opt/opentrap
LATEST_OPENTRAP_URL=$(curl -fsSL https://api.github.com/repos/opentrap/opentrap/releases/latest | jq -r '.assets[] | select(.name | endswith(".AppImage")) | .browser_download_url' | head -n 1)
if [ -n "$LATEST_OPENTRAP_URL" ]; then
  sudo curl -fL "$LATEST_OPENTRAP_URL" -o /opt/opentrap/OpenTRAP.AppImage
  sudo chmod +x /opt/opentrap/OpenTRAP.AppImage
  sudo ln -sf /opt/opentrap/OpenTRAP.AppImage /usr/local/bin/opentrap
  echo "OpenTRAP instalado com sucesso em /opt/opentrap/OpenTRAP.AppImage!"
fi
```

---

## 5. Burp Suite Community + OpenTRAP: Como eles se complementam na prática?

Em vez de escolher apenas um, o **CyberLab OS v5.0** traz slots dedicados para **ambos** porque eles cobrem exatamente os pontos fracos um do outro:

| Capacidade Operacional | **Burp Suite Community** (Slot Windows `:8080`) | **OpenTRAP** (Slot WSL2 Kali `:8080`/`:8082`) | Como usar juntos no CyberLab OS |
|---|---|---|---|
| **Proxy Manual, Repeater, Decoder, Comparer** | **Excelente (Referência de mercado)** — interface madura e ultra-estável no Windows | Muito bom (UI Java 17 FlatLaf inspirada no Burp) | Use o **Burp** como proxy primário de navegação manual na porta `:8080` |
| **Ecossistema de Extensões** | **BApp Store gigante** (*Autorize* para BOLA/IDOR, *Param Miner*, *Logger++*, *JWT Editor*) | Sem BApp Store da PortSwigger | Insubstituível no Burp para testes de autorização (IDOR/BOLA) |
| **Intruder (Fuzzing de Payloads)** | **Limitado artificialmente (throttled)** na versão Community gratuita | **Sem throttling artificial!** + Slot **ffuf** em Go ultra-rápido | Envie ataques de força bruta/fuzzing pesado para o **OpenTRAP** ou para o slot **ffuf** |
| **Scanner Ativo de Vulnerabilidades** | **Bloqueado** na versão Community (exclusivo do Burp Pro pago) | **Liberado gratuitamente!** Orquestra o motor **OWASP ZAP headless** por trás da interface | Use o **OpenTRAP** + o slot **Nuclei** para varredura ativa sem pagar licença Pro |
| **Collaborator / OAST (SSRF, Blind XSS, XXE)** | **Bloqueado** na versão Community (exclusivo do Burp Pro pago) | **Liberado gratuitamente!** Traz cliente **Interactsh** integrado nativamente | Use o Collaborator do **OpenTRAP** ou o slot **Interactsh OAST** |

### Fluxo Recomendado em 1 Clique:
1. Abra o **Burp Suite Community** pelo slot `burp-suite` (escutando em `127.0.0.1:8080`).
2. Clique em **🌐 Navegador Proxy (:8080)** no CyberLab OS — ele abre um Chrome/Edge com perfil limpo e isolado já apontando para o seu proxy.
3. Quando quiser **Scanner Ativo**, **Intruder sem limite** ou **Collaborator OAST**, abra o **OpenTRAP** pelo slot `opentrap` (em `127.0.0.1:8082` ou encadeado como *Upstream Proxy* do Burp!).
4. Qualquer request, alerta ou output relevante: clique em **🔒 Salvar SHA-256** para custódia criptográfica ou **🤖 Enviar p/ Agente OpenCode →** para análise imediata na barra direita!

---

## 6. Subindo o CyberLab OS no seu Windows PowerShell

```powershell
# Na pasta do repositório CyberLab-OS:
bun start
```

Depois acesse **`http://127.0.0.1:4096`**, clique em **"Arsenal Real (Modo Antigravity)"** e clique no ícone **`↻`** (Re-escanear PowerShell + WSL2 Kali) na barra esquerda para ver todos os seus slots ficarem verdes!
