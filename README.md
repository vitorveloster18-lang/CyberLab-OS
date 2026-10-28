# CyberLab OS

**CyberLab OS** é uma plataforma unificada de engenharia de segurança autorizada, testes Web/API, reconhecimento de rede/TLS/AD, engenharia reversa, análise forense Blue Team (DFIR/Sigma), auditoria de código/SCA/SBOM/IaC e orquestração multi-agentes construída diretamente sobre o núcleo do **OpenCode V2** (`anomalyco/opencode` v2.1.4, licença `MIT`).

Toda a operação — chat com IA, provedores/modelos, terminal, árvore de arquivos, ferramentas manuais de segurança (estilo **Burp Suite / Wireshark / CyberChef / Ghidra**), governança de escopo, cofre criptográfico `SHA-256` e ponte bidirecional para os 4 agentes **CDI (`Kairós`, `Naia`, `Salem`, `Nova`)** — roda integrada em **uma única aplicação (`:4096`)**, compatível com **Windows PowerShell**, **WSL2**, **Linux** e **macOS**.

---

## Sumário

1. [Destaques da Arquitetura](#1-destaques-da-arquitetura)
2. [Instalação e Atualização (Windows PowerShell, WSL2 e Linux)](#2-instalação-e-atualização-windows-powershell-wsl2-e-linux)
3. [Como Iniciar e Navegar na Aplicação Unificada (`:4096`)](#3-como-iniciar-e-navegar-na-aplicação-unificada-4096)
4. [Instruções de Uso das 8 Suítes Manuais (33 Modos / 29 Capacidades)](#4-instruções-de-uso-das-8-suítes-manuais-33-modos--29-capacidades)
5. [Configuração e Uso dos 4 Agentes Externos CDI (`8788–8791`)](#5-configuração-e-uso-dos-4-agentes-externos-cdi-87888791)
6. [Referência de Linha de Comando (`cyberlab` CLI)](#6-referência-de-linha-de-comando-cyberlab-cli)
7. [Instalação de Motores Externos Opcionais (`.cyberlab/bin`)](#7-instalação-de-motores-externos-opcionais-cyberlabbin)
8. [Catálogo Técnico Completo (29 Capacidades) e Licenciamento (`MIT`)](#8-catálogo-técnico-completo-29-capacidades-e-licenciamento-mit)

---

## 1. Destaques da Arquitetura

- **Aplicação Única Unificada sobre OpenCode V2 (`:4096`)**: preserva 100% dos recursos originais do OpenCode V2 (sessões de IA, agentes, modelos, provedores, MCP, plugins, terminal e editor) e acopla nativamente o **Workbench Manual do CyberLab OS** logo abaixo da caixa de diálogo.
- **Uso 100% Manual ou Assistido por IA**: todas as 8 suítes podem ser operadas manualmente com formulários visuais completos e override JSON bruto — **mesmo sem nenhuma chave de modelo de IA configurada** — e qualquer resultado pode ser anexado na caixa de diálogo em 1 clique quando você quiser pedir análise da IA ou dos CDIs.
- **Governança de Escopo em Duas Fases (`PolicyEngine` + `ScopeController`)**:
  - Por padrão (`allowExternalTargets: false`), apenas o diretório do projeto atual (protegendo `.git`) e `127.0.0.1` / `localhost` são aceitos.
  - Bloqueio incondicional anti-SSRF contra metadados de nuvem (`169.254.169.254`), `file://`/`gopher://` e path traversal.
  - Revalidação de escopo no instante exato da execução (**anti-TOCTOU**) e tickets humanos de **uso único** (`ApprovalTicket`) para ações propostas por IA/parceiros ou motores externos moderados.
- **Cofre Forense Criptográfico (`EvidenceStore` SQLite WAL + `SHA-256`)**:
  - Separa **Execução**, **Evidência Bruta** (`.cyberlab/artifacts/<sha256>`) e **Finding Analítico** (`severity` independente de `confidence`).
  - Redige automaticamente segredos sensíveis (`Authorization`, `Cookie`, `Set-Cookie`, JWTs, chaves AWS/GitHub e chaves privadas PEM) antes de persistir ou compartilhar com agentes externos.
- **Execução Segura (`shell=false`)**: nenhum executor concatena strings em `sh -c` ou `cmd.exe /c`; binários externos recebem arrays tipados validados por `Effect Schema` e obedecem ao botão **Kill / Cancel** em tempo real (`AbortSignal`).

---

## 2. Instalação e Atualização (Windows PowerShell, WSL2 e Linux)

### Pré-requisitos
- **Git** e **Bun `1.4.4+`**
- **Python `3.10+`** *(opcional — necessário apenas se você for conectar os agentes externos CDI via `chat_py_bridge.py`)*

### Opção A — Windows PowerShell (Nativo)

```powershell
# 1. Instalar o Bun no Windows (caso ainda não tenha)
powershell -c "irm bun.sh/install.ps1 | iex"
bun --version

# 2. Clonar o repositório
git clone -b arena/ce70b843-cyberlab-os https://github.com/vitorveloster18-lang/CyberLab-OS.git
# (Após o merge do PR #1 na main, basta: git clone https://github.com/vitorveloster18-lang/CyberLab-OS.git)
cd CyberLab-OS

# 3. Instalar dependências (pula binário pesado do Electron para uso Web/CLI)
$env:ELECTRON_SKIP_BINARY_DOWNLOAD="1"
bun install --ignore-scripts
bun run --cwd packages/core fix-node-pty

# 4. Validar licenças, tipagem e suíte de testes (54 testes)
bun run cyberlab:check-licenses
bun run cyberlab:typecheck
bun run cyberlab:test
```

### Opção B — Linux ou WSL2 (Ubuntu 22.04 / 24.04)

> **Dica WSL2**: clone dentro do filesystem Linux (`~/projetos/CyberLab-OS`), evitando `/mnt/c/...` para máxima velocidade de I/O e permissões `0600` no SQLite.

```bash
# 1. Instalar Bun 1.4.4
curl -fsSL https://bun.sh/install | bash -s "bun-v1.4.4"
export PATH="$HOME/.bun/bin:$PATH"

# 2. Clonar e instalar dependências
git clone -b arena/ce70b843-cyberlab-os https://github.com/vitorveloster18-lang/CyberLab-OS.git
cd CyberLab-OS
ELECTRON_SKIP_BINARY_DOWNLOAD=1 bun install --ignore-scripts
bun run --cwd packages/core fix-node-pty

# 3. Validar tudo localmente
bun run cyberlab:check-licenses
bun run cyberlab:typecheck
bun run cyberlab:test
```

### Como atualizar após novos commits (`git pull`)
O lançador `bun run start` verifica automaticamente o carimbo de versão da interface (`UI_BUILD_STAMP`) e reconstrói `packages/app/dist` sempre que houver atualização:

```powershell
git pull
bun run start
```
*(Se quiser forçar uma reconstrução limpa da interface web a qualquer momento, execute `bun run start --rebuild`).*

---

## 3. Como Iniciar e Navegar na Aplicação Unificada (`:4096`)

Execute na raiz do repositório:

```powershell
bun run start
```

Abra no navegador:
- **Aplicação Principal**: `http://127.0.0.1:4096` *(ou `http://localhost:4096`)*
- **Configurações CyberLab & CDIs**: `http://127.0.0.1:4096/settings?tab=cyberlab`

### Onde fica cada recurso na tela
1. **Caixa de Diálogo e Chat (OpenCode V2)**: converse normalmente com qualquer modelo configurado em `Settings → Providers / Models` (Anthropic, OpenAI, Google Gemini, OpenRouter, Ollama local, etc.).
2. **Botão Único `"Ferramentas"` (abaixo da caixa de diálogo)**:
   - Clique em **`Ferramentas`** para abrir/recolher a bancada manual ou trocar de suíte através de uma **caixa vertical limpa** com busca instantânea (sem barras horizontais poluídas).
   - Dentro de cada suíte, navegue pelas **abas internas de funções** (estilo Burp Suite) e alterne entre o **Motor Nativo (`MIT`)** e o **Motor Externo** correspondente quando houver mais de uma opção.
   - Use os botões de layout no topo da bancada para alternar entre **Dividido (Chat + Bancada lado a lado)** e **Tela Cheia**, ou oculte/exiba a coluna lateral de **Histórico Persistente** (`Desta função` vs `Toda a suíte` — salvo automaticamente no navegador).
   - Em qualquer execução concluída, clique em **`Anexar na Caixa de Diálogo`** para enviar a saída formatada + hash `SHA-256` direto ao prompt do chat.
3. **Configurações Gerais (`Settings → CyberLab OS`)**:
   - Libere ou restrinja alvos externos no **Escopo do Projeto**.
   - Configure o `CYBERLAB_PARTNER_SECRET` e os **4 CDIs (`8788–8791`)** em 1 clique.
   - Confira o radar de binários externos detectados em `.cyberlab/bin/` ou no `PATH`.

---

## 4. Instruções de Uso das 8 Suítes Manuais (33 Modos / 29 Capacidades)

> **Importante sobre Escopo de Alvos**: antes de apontar qualquer ferramenta de rede/web para um host fora de `127.0.0.1`/`localhost` (por exemplo `192.168.1.50` ou `lab.empresa.local`), abra **`Escopo, Cofre SHA-256 & Relatório → Escopo de Alvos`**, ative **"Permitir Alvos Externos Autorizados"** e cadastre a regra (`ip`, `cidr`, `domain` ou `url_origin`).

---

### Suíte 1 — `Web & API Security Suite`
Reúne 8 abas internas para inspeção e testes de aplicações Web, APIs REST, GraphQL e OAuth2:

1. **`Repeater & Comparer`** (`web-assessment.http-repeater`):
   - Escolha método (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`), URL, tabela de cabeçalhos editáveis e corpo da requisição.
   - Ative **"Comparar contra Baseline"** para enviar a mesma requisição a uma segunda URL/credencial e inspecionar o diff de status, tamanho e linhas alteradas.
2. **`Proxy Intercept (HTTPS / WS)`** (Listener local `127.0.0.1:8899`):
   - Escolha a porta (padrão `8899`), marque ` Interceptação HTTPS MITM (Root CA Local)` (ou `Túnel CONNECT Passthrough`) e clique em **`Iniciar Proxy Local`**.
   - Para inspecionar tráfego **HTTPS** descriptografado e frames **WebSocket (`ws://` / `wss://`)**, baixe o certificado raiz gerado automaticamente em `<projeto>/.cyberlab/ca/cyberlab-root-ca.crt` (ou pelo botão **`Baixar Root CA (.crt)`** na aba Proxy) e confie nele no navegador de testes ou via `curl --proxy http://127.0.0.1:8899 --cacert .cyberlab/ca/cyberlab-root-ca.crt https://alvo`.
   - Clique em **`Enviar ao Repeater`** em qualquer linha capturada para reenviar e editar a requisição.
3. **`Intruder / Payload Lab`** (`web-assessment.http-intruder`):
   - Envolva qualquer ponto da URL, header ou body com `§nome§` (ex.: `http://127.0.0.1:8080/api/users/§id§`).
   - Escolha o modo **`Sniper`**, **`Battering Ram`** ou **`Pitchfork`**, preencha a lista de payloads (1 por linha), configure concorrência/delay e `Grep Match` para destacar anomalias de tamanho ou status HTTP.
4. **`Auditor de Parâmetros`** (`web-assessment.param-audit` | `external.dalfox-param-scan`):
   - **Motor Nativo (Não-Destrutivo)**: injeta canários benignos nos parâmetros de query/body para detectar reflexão contextual sem sanitização, vazamento de stack traces/SQL errors e parâmetros de Open Redirect.
   - **Motor Dalfox (`MIT`)**: invoca o binário `dalfox` supervisionado pelo escopo.
5. **`Scanner & Fuzzer`** (`web-assessment.surface-discovery` | `external.nuclei-template-scan` | `external.ffuf-endpoint-probe`):
   - Descubra rotas sensíveis com calibração automática contra páginas **Soft-404**, rode templates do **Nuclei** por tags (`misconfig,exposure,cve`) ou faça fuzzing com **ffuf** usando wordlists do projeto.
6. **`Headers & Cookies`** (`web-assessment.http-security-headers`):
   - Audita passivamente `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `CORS` e flags `HttpOnly` / `Secure` / `SameSite` em cookies.
7. **`API, GraphQL & OAuth2 Lab`** (`web-assessment.api-graphql-oauth-lab`):
   - **OpenAPI / Swagger / Postman BOLA Matrix**: importe um arquivo `openapi.json` / `collection.postman.json` (ou cole o JSON inline), informe o `Authorization` do **User A** (dono do recurso) e do **User B** (outro usuário/tenant) e marque `Testar também acesso Sem Autenticação`. O motor testa cada rota parametrizada e aponta potenciais falhas **BOLA / IDOR / Broken Auth**.
   - **GraphQL Inspector**: informe a URL `/graphql` para verificar introspecção (`__schema`) aberta, aceitação de **Array Query Batching** (`[{query},{query}]`) e vazamento de sugestões de campos (`Did you mean...`).
   - **OAuth2 / OIDC Auditor**: informe o `Issuer URL` (inspeciona `/.well-known/openid-configuration`) e/ou uma `Authorize URL` para detectar fluxos legados (`implicit`/`password`), ausência de `PKCE S256`, falta de parâmetro anti-CSRF `state` e `redirect_uri` inseguro.
8. **`Decoder, JWT & Sequencer`** (`web-assessment.decoder-sequencer`):
   - Encadeie transformações (`Base64`, `Base64URL`, `URL`, `Hex`, `HTML`, `SHA-256`), inspecione cabeçalho/claims/expiração/`alg:none` de JWTs e meça a entropia de Shannon em amostras de tokens de sessão.

---

### Suíte 2 — `Network, TLS Deep Audit & AD Lab`
Quatro abas dedicadas a infraestrutura, criptografia de transporte, DNS e laboratórios corporativos Active Directory:

1. **`Port & Service Scanner`** (`network-assessment.tcp-surface-probe` | `external.nmap-service-probe`):
   - Teste portas únicas ou listas (`22,80,443,445,3389,8080`) com coleta passiva de banner TCP nativo ou varredura de versões `-sV` com **Nmap**.
2. **`TLS Profundo, Cifras & HSTS`** (`network-assessment.tls-inspector` v1.1.0):
   - Inspeciona cadeia X.509, SANs, validade e fingerprint `SHA-256`.
   - Com **`Auditoria Profunda`** e **`Verificar HSTS`** marcados, testa matriz de suporte a downgrade (`TLSv1.0`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`), cifras fracas/CBC vs AEAD, **Forward Secrecy (`ECDHE`)**, tamanho de chave RSA, cabeçalho `Strict-Transport-Security` (`preload`) e exibe o selo visual de **Nota de Segurança TLS (`A+` a `F`)**.
3. **`DNS, Subdomínios & Email`** (`network-assessment.dns-recon`):
   - Consulta registros `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT` e `CAA`, avalia políticas anti-spoofing **SPF** e **DMARC**, verifica CNAMEs órfãos (*Subdomain Takeover*) e consulta transparência de certificados (`crt.sh`) opcional.
4. **`AD, SMB, LDAP & NTLM Lab`** (`network-assessment.ad-smb-ldap-inspector`):
   - **100% passivo e sem brute-force / sem credenciais** (ideal para laboratórios internos autorizados):
     - **SMB2/3 Signing (`445`)**: envia apenas um pacote `SMB2 NEGOTIATE` padrão para verificar se `Signing Required` está desabilitado (condição clássica de exposição a **NTLM Relay**).
     - **LDAPv3 RootDSE Anônimo (`389`)**: verifica se o controlador de domínio expõe `defaultNamingContext`, `namingContexts` e `dnsHostName` sem autenticação.
     - **HTTP NTLM Challenge Type-2**: envia um header `NTLM Type-1` vazio a um endpoint HTTP/EWS/IIS informado para decodificar os pares `AV_PAIR` retornados pelo servidor (Domínio NetBIOS/DNS, FQDN da máquina e Build exata do Windows Server).

---

### Suíte 3 — `Packet Capture Analyzer`
- **`Inspeção de Captura .pcap`** (`network-assessment.pcap-analyzer` | `external.tshark-pcap-summary`):
  - Informe o caminho de um arquivo `.pcap` dentro do projeto para extrair offline conversas IPv4/IPv6, portas TCP/UDP, queries DNS, requisições HTTP em texto claro e nomes de host TLS SNI (ou use o motor **Wireshark `tshark -r`**).

---

### Suíte 4 — `Reverse Engineering, Entropy & Mobile Lab`
Cinco abas para análise estática segura de binários, firmwares, malware de estudo e aplicativos móveis (sem nunca executar a amostra):

1. **`Binários ELF / PE / Mach-O`** (`reverse-engineering.binary-triage`):
   - Identifica formato/arquitetura, seções empacotadas, proteções de compilação (`NX`, `PIE`, `ASLR`, `Canary`) e strings/importações suspeitas.
2. **`Disassembly & Decompilação`** (`reverse-engineering.binary-disasm` | `external.ghidra-decompile`):
   - Desmonta instruções nativas **`x86_64`** e **`ARM64`** direto do entrypoint (ou de um offset hexadecimal escolhido) ou aciona o **Ghidra Headless (`analyzeHeadless`)**.
3. **`Forense Mobile & JADX`** (`mobile-forensics.artifact-triage` | `external.jadx-decompile`):
   - Inspeciona arquivos `.apk`, `.dex` e `.ipa` em memória extraindo permissões perigosas, tabelas de classes/métodos **Dalvik (`classes.dex`)** e indicadores de rede/IoCs, ou descompila o APK para código `.java` com **JADX**.
4. **`Entropia & CyberChef Studio`** (`reverse-engineering.entropy-recipe-studio`):
   - **Visualizador de Entropia (Byte `0` → `EOF`)**: aponte qualquer binário, imagem ou firmware do projeto para renderizar o **Gráfico de Barras Colorido de Entropia de Shannon** (identificando instantaneamente padding/texto `<3.5`, código estruturado, dados binários e blobs cifrados/comprimidos `>=7.2`) + detecção de assinaturas mágicas embutidas (`PNG`, `ZIP/APK`, `GZIP`, `ZLIB`, `ELF`, `PE`, `SQLite`, `DEX`, `PEM`).
   - **CyberChef Recipe Studio**: encadeie até 16 operações (`From/To Base64`, `From/To Hex`, `URL Encode/Decode`, `Gunzip`, `Gzip`, `Zlib Inflate`, `Raw Deflate`, `XOR com Chave`, **`XOR Brute-Force 1-Byte`**, **`AES-CBC Decrypt`**, **`AES-GCM Decrypt`**, **`Protobuf Raw Wire Decode`**, `Extract Printable Strings`, `SHA-256`) e **salve suas receitas favoritas** para reutilizar em 1 clique.
5. **`Caça com YARA / YARA-X`** (`forensics.yara-scan` | `external.yarax-scan`):
   - Escreva e teste regras **YARA** ao vivo (suporta strings `ascii`, `wide` UTF-16LE, `nocase`, bytes hexadecimais com curinga `{ 7F 45 ?? 46 }` e condições booleanas) ou rode o motor oficial **VirusTotal YARA-X (`yr`)**.

---

### Suíte 5 — `DFIR & Incident Response Lab (Sigma)`
Dedicada a **Blue Team, SOC e Resposta a Incidentes**:

- **`Triagem de Logs & Regras Sigma`** (`forensics.dfir-sigma-triage`):
  - Aponte um arquivo ou pasta de logs no projeto: suporta automaticamente **Linux `syslog` / `auth.log`**, **Nginx / Apache Access Logs** e **JSON / NDJSON / Eventos do Windows exportados** (`EventID 4624`, `4625`, `4688`, etc.).
  - Utilize o pacote integrado de regras **Sigma** (força bruta SSH, escalonamento `sudo`, webshells/SQLi/traversal HTTP, PowerShell `-enc` oculto, indicadores de Pass-the-Hash/LogonType 9) e/ou escreva suas próprias regras **Sigma YAML** inline (`|contains`, `|startswith`, `|endswith`, `|all`, `|re`).
  - Gera automaticamente a **Timeline Cronológica Forense de Incidente** selada com hash `SHA-256`.

---

### Suíte 6 — `SAST, SCA, SBOM CycloneDX & Containers/IaC`
Segurança de aplicações, cadeia de suprimentos (Supply Chain) e infraestrutura como código:

1. **`SAST & Segredos`** (`code-analysis.workspace-audit`):
   - Varre arquivos-fonte em busca de chaves/credenciais hardcoded, validação TLS desabilitada e chamadas perigosas de execução.
2. **`SCA, SBOM CycloneDX & IaC`** (`code-analysis.sca-sbom-iac-audit` | `external.trivy-scan`):
   - **Motor Nativo (`MIT`)**:
     - Lê manifests e lockfiles (`package.json`, `package-lock.json`, `bun.lock`, `requirements.txt`, `poetry.lock`, `go.mod`, `Cargo.lock`, `pom.xml`).
     - Gera o inventário oficial **SBOM CycloneDX 1.5 (`JSON`)** como evidência verificável.
     - Consulta opcionalmente a API pública **`OSV.dev`** em lote para listar CVEs reais das versões instaladas.
     - Audita estaticamente **`Dockerfile`**, **`docker-compose.yml`**, manifestos **Kubernetes** (`privileged: true`, `hostNetwork`, `:latest`, falta de limites) e **Terraform (`.tf`)** (`0.0.0.0/0` em SSH/RDP, S3 público, storage sem criptografia).
   - **Motor Aqua Trivy (`Apache-2.0`)**: executa `trivy fs` (`vuln,misconfig,secret`) governado dentro do workspace.

---

### Suíte 7 — `Hub de Agentes Externos CDI`
- Despacho manual individual ou em paralelo (`Promise.all`) para os 4 especialistas externos (**`Kairós`**, **`Naia`**, **`Salem`**, **`Nova`**), anexando evidências `SHA-256` selecionadas e exibindo o feed em tempo real das ações iniciadas pelos CDIs. Veja a [Seção 5](#5-configuração-e-uso-dos-4-agentes-externos-cdi-87888791) para o passo a passo completo.

---

### Suíte 8 — `Escopo, Cofre SHA-256 & Relatório`
- **`Escopo de Alvos`**: libere/bloqueie alvos externos e gerencie regras `ip`, `cidr`, `domain`, `url_origin` e `workspace_path`.
- **`Aprovações`**: aprove ou rejeite tickets pendentes em 1 clique.
- **`Cofre SHA-256`**: inspecione o conteúdo de cada evidência e clique em **`Verificar SHA-256`** para revalidar criptograficamente o blob no disco.
- **`Importar Externo / Inbox`**: sincronize a pasta `.cyberlab/inbox/` ou cole exportações manuais do Burp Suite, OpenTRAP, Wireshark, Ghidra ou MVT.
- **`Findings` & `Relatório (.md)`**: cadastre vulnerabilidades vinculadas às evidências `SHA-256`, aprove/rejeite revisões analíticas e baixe ou anexe o **Relatório Técnico Reproduzível em Markdown**.

---

## 5. Configuração e Uso dos 4 Agentes Externos CDI (`8788–8791`)

O CyberLab OS vem pré-alinhado com os identificadores e portas dos seus 4 agentes CDI:

| Agente CDI | `partnerId` | Porta Local | Endpoint Esperado pelo CyberLab OS |
|---|---|---|---|
| **Kairós** | `kairos` | `8788` | `http://127.0.0.1:8788/cyberlab/partner` |
| **Naia** | `naia` | `8789` | `http://127.0.0.1:8789/cyberlab/partner` |
| **Salem** | `salem` | `8790` | `http://127.0.0.1:8790/cyberlab/partner` |
| **Nova** | `nova` | `8791` | `http://127.0.0.1:8791/cyberlab/partner` |

### Passo a passo no Windows PowerShell (ou Linux/WSL2)

1. **No CyberLab OS (`http://127.0.0.1:4096`)**:
   - Abra **`Ferramentas → Hub de Agentes Externos CDI → Conexão, Secret & PowerShell`** *(ou `Settings → CyberLab OS`)*.
   - Clique em **`Gerar Novo Secret (256-bit)`** (ou defina o seu próprio segredo) e clique em **`Preset 4 CDIs (8788–8791)`**.
   - Clique em **`Copiar Comandos PowerShell`** — ele já copia os comandos com o seu `CYBERLAB_PARTNER_SECRET` preenchido!

2. **Nos terminais dos seus CDIs**:

```powershell
# Defina o mesmo segredo compartilhado exibido na interface (ou gere via CLI: bun run cyberlab partner --generate-secret --preset-4)
$env:CYBERLAB_PARTNER_SECRET = "SEU_SEGREDO_COMPARTILHADO_AQUI"
$env:CYBERLAB_CALLBACK_URL   = "http://127.0.0.1:4096/api/cyberlab/partner-gateway"

# Suba cada ponte apontando para o chat.py de cada agente:
python integrations/partners/chat_py_bridge.py --port 8788 --partner-id kairos --chat-py "../kairos/chat.py"
python integrations/partners/chat_py_bridge.py --port 8789 --partner-id naia   --chat-py "../naia/chat.py"
python integrations/partners/chat_py_bridge.py --port 8790 --partner-id salem  --chat-py "../salem/chat.py"
python integrations/partners/chat_py_bridge.py --port 8791 --partner-id nova   --chat-py "../nova/chat.py"
```

3. **Comunicação Bidirecional dentro do Python (`CyberLabOSClient`)**:
   Dentro do `chat.py` de qualquer CDI, você pode importar `CyberLabOSClient` de `integrations/partners/chat_py_bridge.py` para consultar estado do projeto, ler evidências/arquivos em escopo, gravar artefatos `SHA-256`, propor findings e iniciar ferramentas governadas no CyberLab OS autonomamente.

---

## 6. Referência de Linha de Comando (`cyberlab` CLI)

Todas as capacidades também podem ser operadas diretamente pelo terminal (PowerShell ou Bash):

```bash
# Status geral do projeto, escopo ativo e contagem de capacidades (29 capacidades)
bun run cyberlab status
bun run cyberlab capabilities

# Exemplos das capacidades nativas (MIT):
bun run cyberlab run -c web-assessment.api-graphql-oauth-lab -i '{"baseUrl":"http://127.0.0.1:4096","testUnauthenticated":true}'
bun run cyberlab run -c code-analysis.sca-sbom-iac-audit -i '{"subpath":".","generateCycloneDxSbom":true,"auditContainersAndIac":true}'
bun run cyberlab run -c network-assessment.tls-inspector -i '{"host":"127.0.0.1","port":443,"deepCipherAudit":true,"checkHsts":true}'
bun run cyberlab run -c forensics.dfir-sigma-triage -i '{"logPath":"logs/auth.log","includeBuiltinRules":true}'
bun run cyberlab run -c network-assessment.ad-smb-ldap-inspector -i '{"host":"127.0.0.1","checkSmbSigning":true,"checkLdapRootDse":true}'
bun run cyberlab run -c reverse-engineering.entropy-recipe-studio -i '{"filePath":"package.json","bucketCount":32}'
bun run cyberlab run -c web-assessment.http-intruder -i '{"url":"http://127.0.0.1:4096/api/§ep§","attackMode":"sniper","payloadSet1":["info","health"]}'
bun run cyberlab run -c reverse-engineering.binary-disasm -i '{"binaryPath":"amostra.elf","maxInstructions":64}'
bun run cyberlab run -c forensics.yara-scan -i '{"targetPath":"cyberlab","rulesText":"rule Demo { strings: $a = \"CyberLab\" condition: $a }"}'

# Verificar custódia criptográfica SHA-256 e exportar relatório Markdown:
bun run cyberlab evidence
bun run cyberlab evidence --verify <EVIDENCE_ID>
bun run cyberlab findings
bun run cyberlab report > relatorio-cyberlab.md
```

---

## 7. Instalação de Motores Externos Opcionais (`.cyberlab/bin`)

O CyberLab OS já funciona imediatamente sem binários externos graças aos **20 motores nativos `MIT`**. Quando você quiser também habilitar os **9 motores externos governados** (`nmap`, `nuclei`, `ffuf`, `tshark`, `dalfox`, `ghidra-headless`, `jadx`, `yarax`, `trivy`), basta instalá-los no sistema ou colocá-los na pasta local `<projeto>/.cyberlab/bin/`:

```powershell
# Windows PowerShell — baixa automaticamente Nuclei + ffuf para .cyberlab/bin/:
powershell -ExecutionPolicy Bypass -File .\script\bootstrap-local-tools.ps1

# Ferramentas adicionais via winget no Windows (opcionais):
winget install Insecure.Nmap
winget install WiresharkFoundation.Wireshark
winget install AquaSecurity.Trivy
winget install Skylot.Jadx
```

```bash
# Linux / WSL2 — baixa automaticamente Nuclei + ffuf para .cyberlab/bin/ (adicione --with-agpl para OpenTRAP AppImage):
./script/bootstrap-local-tools.sh
```

---

## 8. Catálogo Técnico Completo (29 Capacidades) e Licenciamento (`MIT`)

Todos os **32 manifestos** em `vendor/manifests/` são auditados automaticamente em CI por `bun run cyberlab:check-licenses` (**0 componentes copyleft `GPL`/`AGPL` embutidos no código-fonte**):

### A. 20 Capacidades Nativas Embutidas (`100% MIT` — Zero Dependências Binárias Externas)

| # | `capabilityId` | Suíte | Função Principal |
|---|---|---|---|
| 1 | `web-assessment.http-repeater` | Web & API | HTTP Repeater estruturado + Comparer diferencial contra baseline |
| 2 | `web-assessment.http-intruder` | Web & API | Matriz de payloads `§slot§` (`Sniper`, `Battering Ram`, `Pitchfork`) com rate-limit |
| 3 | `web-assessment.param-audit` | Web & API | Auditoria diferencial não-destrutiva de reflexão, erros de banco e open-redirect |
| 4 | `web-assessment.api-graphql-oauth-lab` | Web & API | Importador OpenAPI/Postman com matriz BOLA/IDOR, GraphQL posture e OAuth2/PKCE |
| 5 | `web-assessment.surface-discovery` | Web & API | Descoberta de endpoints e APIs com filtro inteligente anti-Soft-404 |
| 6 | `web-assessment.http-security-headers` | Web & API | Auditoria passiva de HSTS, CSP, X-Frame-Options, CORS e cookies |
| 7 | `web-assessment.decoder-sequencer` | Web & API | Decoder encadeável, inspetor JWT (`alg:none`/`exp`) e entropia de tokens |
| 8 | `network-assessment.tcp-surface-probe` | Network & AD | Sonda TCP controlada de portas e coleta passiva de banners |
| 9 | `network-assessment.tls-inspector` | Network & AD | Cadeia X.509 + matriz TLS 1.0–1.3, cifras/PFS, RSA, HSTS Preload e nota `A+..F` |
| 10 | `network-assessment.dns-recon` | Network & AD | Registros DNS, postura SPF/DMARC/CAA, Subdomain Takeover e `crt.sh` |
| 11 | `network-assessment.ad-smb-ldap-inspector` | Network & AD | Checagem passiva de SMB2/3 Signing, LDAPv3 RootDSE anônimo e HTTP NTLM Type-2 |
| 12 | `network-assessment.pcap-analyzer` | Packet (`.pcap`) | Dissecador offline `.pcap` (fluxos IPv4/IPv6, TCP/UDP, DNS, HTTP e TLS SNI) |
| 13 | `reverse-engineering.binary-triage` | Reversing | Triagem estática `ELF` / `PE` / `Mach-O` (NX, PIE, ASLR, seções e strings) |
| 14 | `reverse-engineering.binary-disasm` | Reversing | Disassembler estático nativo para arquiteturas `x86_64` e `ARM64` |
| 15 | `reverse-engineering.entropy-recipe-studio` | Reversing | Gráfico visual de entropia (byte `0` → `EOF`), carving e CyberChef Studio (`XOR`/`AES`/`Zlib`/`Protobuf`) |
| 16 | `mobile-forensics.artifact-triage` | Reversing | Triagem `.apk` / `.dex` (tabelas Dalvik `classes.dex`) e `.ipa` com busca de IoCs |
| 17 | `forensics.yara-scan` | Reversing | Motor integrado de regras YARA (`ascii`, `wide`, `nocase`, hex `??` e condições) |
| 18 | `forensics.dfir-sigma-triage` | DFIR & Sigma | Parser multi-log (`syslog`/`auth.log`, Nginx/Apache, JSON/Windows) + regras Sigma YAML + Timeline |
| 19 | `code-analysis.workspace-audit` | Código & IaC | Auditoria estática SAST somente-leitura de segredos e padrões inseguros |
| 20 | `code-analysis.sca-sbom-iac-audit` | Código & IaC | Scanner SCA + OSV.dev CVEs + SBOM CycloneDX 1.5 + Dockerfile/Compose/K8s/Terraform |

*(Mais o **Proxy Local HTTP / HTTPS MITM com Root CA ECDSA P-256 + WebSocket** em `cyberlab/proxy/` e as **6 Skills metodológicas `SKILL.md`** em `skills/`).*

### B. 9 Pontes Governadas para Motores Externos (`plugin_only` — `shell=false` + `SHA-256`)

| # | `capabilityId` | Binário | Licença SPDX |
|---|---|---|---|
| 21 | `external.nuclei-template-scan` | `nuclei` | `MIT` |
| 22 | `external.ffuf-endpoint-probe` | `ffuf` | `MIT` |
| 23 | `external.dalfox-param-scan` | `dalfox` | `MIT` |
| 24 | `external.ghidra-decompile` | `analyzeHeadless` | `Apache-2.0` |
| 25 | `external.jadx-decompile` | `jadx` | `Apache-2.0` |
| 26 | `external.trivy-scan` | `trivy` | `Apache-2.0` |
| 27 | `external.yarax-scan` | `yr` / `yara` | `BSD-3-Clause` |
| 28 | `external.nmap-service-probe` | `nmap` | `NPSL-0.95` *(externo isolado)* |
| 29 | `external.tshark-pcap-summary` | `tshark` | `GPL-2.0-or-later` *(externo isolado)* |

---

## Documentação Complementar

- [`docs/UPSTREAM_AUDIT.md`](docs/UPSTREAM_AUDIT.md) — Auditoria do núcleo OpenCode V2 (`2.1.4`).
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Arquitetura de governança, execução e custódia de evidências.
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — Modelo de ameaças, anti-TOCTOU, redação e isolamento HMAC-SHA256.
- [`docs/TOOL_INVENTORY.md`](docs/TOOL_INVENTORY.md) — Inventário técnico e classificação das ferramentas avaliadas.
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — Política de conformidade jurídica (`approved_embed`, `plugin_only`, `blocked`).
- [`vendor/THIRD_PARTY_NOTICES.md`](vendor/THIRD_PARTY_NOTICES.md) — Avisos de terceiros e registro completo de manifestos SPDX.
