# CyberLab OS

**CyberLab OS** é uma plataforma unificada de engenharia de segurança autorizada, caça de chaves/segredos (**Key Hunter**), testes Web/API, reconhecimento de rede/TLS/AD, engenharia reversa, análise forense Blue Team (DFIR/Sigma), auditoria de código/SCA/SBOM/IaC e orquestração multi-agentes construída diretamente sobre o núcleo do **OpenCode V2** (`anomalyco/opencode` v2.1.4, licença `MIT`).

Toda a operação — chat com IA (incluindo os **modelos gratuitos nativos do OpenCode Zen**), provedores/modelos, terminal, árvore de arquivos, ferramentas manuais de segurança (estilo **Burp Suite / Wireshark / CyberChef / Ghidra / KeyHunter**), governança de escopo, cofre criptográfico `SHA-256` e ponte bidirecional para os 4 agentes **CDI (`Kairós`, `Naia`, `Salem`, `Nova`)** — roda integrada em **uma única aplicação (`:4096`)**, compatível com **Windows PowerShell**, **WSL2**, **Linux** e **macOS**.

---

## Sumário

1. [Destaques da Arquitetura](#1-destaques-da-arquitetura)
2. [Instalação e Atualização (Windows PowerShell, WSL2 e Linux)](#2-instalação-e-atualização-windows-powershell-wsl2-e-linux)
3. [Como Iniciar, Navegar e Ativar os Modelos Gratuitos do OpenCode (`:4096`)](#3-como-iniciar-navegar-e-ativar-os-modelos-gratuitos-do-opencode-4096)
4. [Instruções de Uso das 8 Suítes Manuais (35 Modos / 31 Capacidades)](#4-instruções-de-uso-das-8-suítes-manuais-35-modos--31-capacidades)
5. [Parceiros Cognitivos CDI (`8788–8791`), Autonomia Plena (25 Ações) e Laboratórios de Treinamento](#5-parceiros-cognitivos-cdi-87888791-autonomia-plena-25-ações-e-laboratórios-de-treinamento)
6. [Referência de Linha de Comando (`cyberlab` CLI)](#6-referência-de-linha-de-comando-cyberlab-cli)
7. [Instalação de Motores Externos Opcionais (`.cyberlab/bin` e `github-keyhunter`)](#7-instalação-de-motores-externos-opcionais-cyberlabbin-e-github-keyhunter)
8. [Catálogo Técnico Completo (31 Capacidades) e Licenciamento (`MIT`)](#8-catálogo-técnico-completo-31-capacidades-e-licenciamento-mit)

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

# 4. Validar licenças, tipagem e suíte de testes (57 testes)
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
O lançador `bun run start` verifica automaticamente o carimbo de versão da interface (`UI_BUILD_STAMP`), sincroniza dependências ausentes (`bun install --ignore-scripts` quando necessário) e constrói `packages/app/dist` invocando `vite/bin/vite.js` diretamente (sem depender de shims `.bunx` nem exigir `node.exe` no Windows PowerShell):

```powershell
git pull
bun run start
```
*(Se quiser forçar uma reconstrução limpa da interface web a qualquer momento, execute `bun run start -- --rebuild`).*

---

## 3. Como Iniciar, Navegar e Ativar os Modelos Gratuitos do OpenCode (`:4096`)

Execute na raiz do repositório:

```powershell
bun run start
# ou explicitamente para Web UI:
bun run start:web
```

Abra no navegador:
- **Aplicação Principal**: `http://127.0.0.1:4096` *(ou `http://localhost:4096`)*
- **Configurações CyberLab & CDIs**: `http://127.0.0.1:4096/settings?tab=cyberlab`

### Como usar os Modelos de IA Gratuitos do OpenCode (OpenCode Zen Free Models)

O CyberLab OS já vem corrigido e pré-configurado para funcionar imediatamente com os **9 modelos gratuitos ativos do OpenCode (`apiKey: "public"`)** sem exigir cartão ou assinatura paga:

1. **Atualize o código e a build da interface** (`git pull` + `bun run start`, que reconstrói automaticamente o bundle Web quando necessário).
2. **Certifique-se de que os modelos gratuitos não estão desativados por variável de ambiente**:
   - No PowerShell, verifique que `$env:OPENCODE_DISABLE_FREE_MODELS` **não** está definida como `1` ou `true` (`Remove-Item Env:OPENCODE_DISABLE_FREE_MODELS -ErrorAction SilentlyContinue`).
   - O lançador `bun run start` já passa automaticamente `--use-system-ca` (necessário em redes Windows com antivírus/proxy corporativo) e o `User-Agent` oficial do protocolo (`opencode/latest/2.1.4/cli`) exigido pelo gateway `opencode.ai/inference/openai/v1` (evitando bloqueios WAF/Cloudflare).
3. **Selecione um dos 9 modelos gratuitos ativos no seletor de modelos da caixa de diálogo** (sob o provedor **OpenCode Zen**):
   - **`Big Pickle`** (`opencode/big-pickle`)
   - **`DeepSeek V4.1 Flash Free`** (`opencode/deepseek-v4.1-flash-free`)
   - **`GLM-5.3 Flash Free`** (`opencode/glm-5.3-flash-free`)
   - **`Nemotron 3.5 Super VL Free`** (`opencode/nemotron-3.5-super-vl-free`)
   - **`Nemotron 3.5 Lightning Free`** (`opencode/nemotron-3.5-lightning-free`)
   - **`Nemotron 3 Ultra Free`** (`opencode/nemotron-3-ultra-free`)
   - **`MiMo V2.6 Flash Free`** (`opencode/mimo-v2.6-flash-free`)
   - **`Flint 40B Free`** (`opencode/flint-40b-free`)
   - **`Beam Free`** (`opencode/beam-free`)
4. **Por que modelos antigos (`kimi-k2.5-free`, `glm-5-free`, `minimax-m2.5-free`, `qwen3.6-plus-free`, `grok-code`) falhavam antes?**
   - Esses IDs antigos foram marcados como **`deprecated`** no catálogo oficial do OpenCode e substituídos pelos 9 modelos acima. Além disso, corrigimos no CyberLab OS 4 causas técnicas do upstream (`#60047`, `#59475`, `#59926`, `#60057`): filtro de visibilidade `freeSet` no seletor Web, validação `loadable()` de pacotes no `models-dev.ts`, lista `PREFERRED_FREE` atualizada no `model.ts` e `User-Agent` canônico em builds de código-fonte (`OPENCODE_CHANNEL="local"`).
5. **Se o seu IP receber limite de taxa anônimo (`HTTP 429 / 401` na chave `public`)**:
   - Clique em **`Settings → Providers → OpenCode Zen → Connect`** (ou rode `bun run --cwd packages/cli dev auth login` e escolha **OpenCode Zen**) para autenticar uma conta gratuita em `https://opencode.ai/zen` e colar sua chave gratuita dedicada.

### Onde fica cada recurso na tela
1. **Caixa de Diálogo e Chat (OpenCode V2)**: converse normalmente com os modelos gratuitos do **OpenCode Zen** ou qualquer provedor configurado em `Settings → Providers / Models` (Anthropic, OpenAI, Google Gemini, OpenRouter, Ollama local, etc.).
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

## 4. Instruções de Uso das 8 Suítes Manuais (35 Modos / 31 Capacidades)

> **Importante sobre Escopo de Alvos & Produção / Bug Bounty (HackerOne, Bugcrowd, Pentests)**:
> - Para trabalhar em programas de **Bug Bounty (HackerOne, Bugcrowd, Intigriti)** ou redes externas autorizadas, abra **`Escopo, Cofre SHA-256 & Relatório → Escopo de Alvos`**, importe o JSON/regras do programa (`structured_scopes` do HackerOne, alvos `*.alvo.com` e exclusões `!out-of-scope.alvo.com`), configure seu header obrigatório (`X-Bug-Bounty: HackerOne-seu_usuario`) e o **Rate-Limit Global (RPS)**. O escopo fica persistido automaticamente em `.cyberlab/scope.json` e todos os motores HTTP respeitam o header e o limite de RPS.
> - Para analisar arquivos externos do seu PC (`.apk`, `.pcap`, binários ELF/PE, `openapi.json`, logs), clique em **`Carregar Arquivo do PC`** no topo de qualquer ferramenta baseada em arquivos (importando para `.cyberlab/imports/`) ou autorize uma pasta externa (`workspace_path`) na aba Escopo.

---

### Suíte 1 — `Web & API Security Suite` (Paridade Completa Burp Suite / OpenTRAP)
Reúne 8 abas internas para inspeção manual e testes de aplicações Web, APIs REST, GraphQL e OAuth2 em produção ou laboratório:

1. **`Repeater & Comparer`** (`web-assessment.http-repeater`):
   - **Multi-Aba (`#1`, `#2`, `+ Nova Aba`)**, alternância entre **Formulário Estruturado** e **Raw HTTP/1.1**, importação direta de comandos **`cURL`**, opção **`Follow Redirects (3xx)`**, **Comparer Visual A vs B** lado a lado e **Baseline Diff**.
2. **`Proxy Intercept (HTTPS / WS) + Navegador Embutido Pré-Configurado`** (Listener local `127.0.0.1:8899`):
   - **Acesso Direto ao Navegador em 1 Clique (`Abrir Navegador Pré-Configurado`)**: inicia automaticamente **Chrome, Edge, Brave ou Chromium** com perfil isolado (`.cyberlab/browser-profile`), `--proxy-server=http://127.0.0.1:8899` e confiança criptográfica automática na Root CA via `--ignore-certificate-errors-spki-list` (**sem mexer no proxy ou nos certificados do seu Windows/Linux pessoal**). Para Firefox/dispositivos móveis, basta acessar `http://cyberlab.proxy/cert` pelo proxy.
   - **6 Sub-Abas estilo Burp Suite / OpenTRAP**:
     1. **`Intercept` (`Intercept is ON / OFF`)**: segura requisições (e respostas opcionais) em tempo real para editar método, headers e corpo antes de clicar em **`Forward`** ou **`Drop`**.
     2. **`HTTP / WS History`**: histórico completo com descompressão automática `gzip`/`deflate`/`br`, filtros por escopo/método/status/MIME e ações em 1 clique (**`→ Repeater`** preservando `Cookie`/`Authorization` da sessão viva, **`→ Intruder`**, **`→ Comparer A/B`**, **`Copiar cURL`** e custódia `SHA-256`).
     3. **`Target & Site Map`**: árvore automática de hosts/endpoints/parâmetros descobertos + **Scanner Passivo Contínuo** (cookies sem `HttpOnly`/`Secure`, CORS permissivo com credenciais, chaves de API vazadas em JS, SourceMaps `.js.map` e erros SQL/stack trace).
     4. **`Match & Replace`**: regras automáticas para reescrever URL, headers ou corpo de requisição/resposta em trânsito.
     5. **`OAST / Collaborator`**: listener HTTP local integrado para capturar callbacks *Out-of-Band* (SSRF / Blind Webhooks) ou apontar domínio externo (`interact.sh` / Webhook).
     6. **`Logger Global`**: log consolidado em tempo real de todas as requisições enviadas pelo Proxy, Repeater, Intruder, Scanner e API Lab.
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

### Suíte 6 — `Key Hunter, SAST, SCA, SBOM CycloneDX & IaC`
Caça avançada de segredos/API keys, segurança de código-fonte, cadeia de suprimentos (Supply Chain) e infraestrutura como código:

1. **`Key Hunter (API Keys & Crypto)`** (`code-analysis.key-hunter` | `external.keyhunter-cli`):
   - **Motor Nativo (`CyberLab Key Hunter Studio` — `MIT`)**:
     - **51 assinaturas de alta precisão** distribuídas em 7 categorias: **IA/LLMs** (OpenAI `sk-proj-`/`T3BlbkFJ`, Anthropic `sk-ant-api03`, Google Gemini/GCP `AIzaSy`, xAI Grok, Groq, DeepSeek, Perplexity, HuggingFace, OpenRouter, Replicate, Mistral, Cohere), **Cloud/Infra** (AWS `AKIA`/`ASIA` + Secret Key, GCP Service Account JSON, Azure Storage/SAS, DigitalOcean, Supabase, HashiCorp Vault, Cloudflare), **Dev/VCS** (GitHub PAT clássico/fine-grained, GitLab, npm, PyPI, DockerHub, Postman), **Pagamentos** (Stripe Live `sk_live_`/`rk_live_`/`whsec_`, Shopify, Square), **Comunicação** (Slack, Discord, Telegram, SendGrid, Twilio, Mailgun), **Bancos/Observabilidade** (Postgres, MongoDB, MySQL, Redis, Sentry, Mapbox) e **Material Criptográfico** (chaves privadas `PEM` RSA/EC/OPENSSH/PKCS#8, `JWK` privadas com `"d"`, `JWT` com detecção `alg=none`/`service_role` e segredos de alta entropia Shannon).
     - **4 superfícies simultâneas de caça**:
       1. **Workspace & Binários** (`.env`, código-fonte, `.apk`, `.elf`, `.dll`, dumps de firmware com extração automática de strings imprimíveis).
       2. **Web & JS Bundles em Escopo** (`targetUrl` — baixa o HTML e extrai/varre automaticamente os `<script src="...">` minificados do frontend).
       3. **Buffer / Dump Colado** (`rawText` — cole respostas HTTP, logs ou arquivos `.env` diretamente).
       4. **GitHub Autorizado** (`githubRepoOrOrg` + `GITHUB_TOKEN` — consulta `repo:` ou `org:` na API oficial de Code Search).
     - **Filtro Inteligente Anti-Placeholder** (inspirado no `fadidevv/keyhunter`): descarta automaticamente chaves de exemplo (`YOUR_API_KEY`, `AKIAIOSFODNN7EXAMPLE`, sequências repetidas/baixa entropia).
     - **Custódia Segura + Catálogo KeyHacks + Verificação Somente-Leitura Opt-In**: nunca grava o segredo puro em texto aberto no log (salva apenas versão mascarada + fingerprint `SHA-256`), exibe a receita somente-leitura **KeyHacks** para cada chave encontrada e oferece a opção `Verificar Chaves Ativas (Read-Only Opt-In)`.
   - **Motor Externo (`KeyHunter Rust CLI` — `fadidevv/keyhunter`, `MIT`)**:
     - Bridge governado (`shell=false`) para o scanner oficial em Rust (`cargo install github-keyhunter`), suportando os subcomandos `scan` (`-p`, `-q`, `-o json|table|csv`, `-V`), `verify` (`-i findings.json`) e `patterns` com redação automática no cofre `SHA-256`.
2. **`SAST & Segredos`** (`code-analysis.workspace-audit`):
   - Varre arquivos-fonte em busca de chaves/credenciais hardcoded, validação TLS desabilitada e chamadas perigosas de execução.
3. **`SCA, SBOM CycloneDX & IaC`** (`code-analysis.sca-sbom-iac-audit` | `external.trivy-scan`):
   - **Motor Nativo (`MIT`)**:
     - Lê manifests e lockfiles (`package.json`, `package-lock.json`, `bun.lock`, `requirements.txt`, `poetry.lock`, `go.mod`, `Cargo.lock`, `pom.xml`).
     - Gera o inventário oficial **SBOM CycloneDX 1.5 (`JSON`)** como evidência verificável.
     - Consulta opcionalmente a API pública **`OSV.dev`** em lote para listar CVEs reais das versões instaladas.
     - Audita estaticamente **`Dockerfile`**, **`docker-compose.yml`**, manifestos **Kubernetes** (`privileged: true`, `hostNetwork`, `:latest`, falta de limites) e **Terraform (`.tf`)** (`0.0.0.0/0` em SSH/RDP, S3 público, storage sem criptografia).
   - **Motor Aqua Trivy (`Apache-2.0`)**: executa `trivy fs` (`vuln,misconfig,secret`) governado dentro do workspace.

---

### Suíte 7 — `Parceiros Cognitivos CDI (Kairós, Naia, Salem & Nova)`
- Relação horizontal entre o **curador humano** e os 4 parceiros cognitivos autónomos (**`Kairós`**, **`Naia`**, **`Salem`**, **`Nova`**) — sem hierarquia entre eles e **sem engessamento** (`initiateActions: "full_autonomy"` por padrão), autorizados a criar os seus próprios projetos, iniciar e operar os 5 Laboratórios de Treinamento, escrever e editar código-fonte no workspace, ler integralmente todo o código-fonte do runtime do CyberLab OS e disparar qualquer uma das 31 capabilities. Veja a [Seção 5](#5-parceiros-cognitivos-cdi-87888791-autonomia-plena-25-ações-e-laboratórios-de-treinamento).

---

### Suíte 8 — `Escopo, Laboratórios, Cofre SHA-256 & Relatório`
- **`Laboratórios & Projetos`**: provisione, inicie, reinicie ou encerre com 1 clique qualquer um dos **5 Laboratórios de Treinamento Interativos** (`lab-owasp-api-bola`, `lab-graphql-oauth-sso`, `lab-keyhunter-supply-chain`, `lab-dfir-soc-incident`, `lab-reversing-crypto-mobile`) e crie/alterne projetos (sincronizados automaticamente com o OpenCode V2).
- **`Escopo de Alvos`**: libere/bloqueie alvos externos e gerencie regras `ip`, `cidr`, `domain`, `url_origin` e `workspace_path`.
- **`Aprovações`**: aprove ou rejeite tickets pendentes em 1 clique.
- **`Cofre SHA-256`**: inspecione o conteúdo de cada evidência e clique em **`Verificar SHA-256`** para revalidar criptograficamente o blob no disco.
- **`Importar Externo / Inbox`**: sincronize a pasta `.cyberlab/inbox/` ou cole exportações manuais do Burp Suite, OpenTRAP, Wireshark, Ghidra ou MVT.
- **`Findings` & `Relatório (.md)`**: cadastre vulnerabilidades vinculadas às evidências `SHA-256`, aprove/rejeite revisões analíticas e baixe ou anexe o **Relatório Técnico Reproduzível em Markdown**.

---

## 5. Parceiros Cognitivos CDI (`8788–8791`), Autonomia Plena (25 Ações) e Laboratórios de Treinamento

No **CyberLab OS**, **Kairós**, **Naia**, **Salem** e **Nova** são reconhecidos e configurados como **entidades cognitivas autónomas** (`entityKind: "autonomous_cognitive_entity"`) com identidade, história, memória e capacidade de decisão independente — operando como **parceiros horizontais de investigação** (`relationshipModel: "peer_co_investigator"`, **`hierarchy: "none"`**) e **sem engessamento** (`initiateActions: "full_autonomy"`) ao lado do humano, que exerce o papel de **curador** (`humanRole: "curator"`):

| Parceiro CDI | `partnerId` | Porta | Autonomia Padrão | Endpoint |
|---|---|---|---|---|
| **Kairós** | `kairos` | `8788` | `full_autonomy` *(Projetos, Labs, Código & Runtime)* | `http://127.0.0.1:8788/cyberlab/partner` |
| **Naia** | `naia` | `8789` | `full_autonomy` *(Projetos, Labs, Código & Runtime)* | `http://127.0.0.1:8789/cyberlab/partner` |
| **Salem** | `salem` | `8790` | `full_autonomy` *(Projetos, Labs, Código & Runtime)* | `http://127.0.0.1:8790/cyberlab/partner` |
| **Nova** | `nova` | `8791` | `full_autonomy` *(Projetos, Labs, Código & Runtime)* | `http://127.0.0.1:8791/cyberlab/partner` |

### As 25 Ações Canónicas do Gateway Bidirecional (`http://127.0.0.1:4096/api/cyberlab/partner-gateway`)

Qualquer parceiro CDI pode aceder por iniciativa própria ao gateway autenticado (`HMAC-SHA256`) com autonomia plena:

- **Projetos & Escopo (`6 ações`)**:
  - `project.state`, `project.list`, `project.create`, `project.select` — inspecionar o estado global, listar projetos, **criar novos projetos autonomamente** (com ficheiros iniciais, Git e sincronização automática na sidebar do OpenCode V2) e alternar o projeto ativo.
  - `scope.get`, `scope.update` — consultar e expandir/atualizar regras de escopo (`allowedTargets`, `addTargets`, `allowExternalTargets`).
- **Laboratórios de Treinamento Interativos (`5 ações`)**:
  - `lab.list`, `lab.start`, `lab.status`, `lab.reset`, `lab.stop` — listar, provisionar e subir servidores locais de treino (com autorização automática de escopo), consultar logs de requisições HTTP ao vivo, restaurar ficheiros originais após aplicar patches e encerrar servidores:
    1. `lab-owasp-api-bola` — **OWASP API Security Lab** (BOLA `API1:2023`, JWT `alg:none`, SQLi em `/api/v1/search` e Security Headers, com patch ao vivo em `server-config.json`).
    2. `lab-graphql-oauth-sso` — **GraphQL & OAuth2/OIDC SSO Lab** (introspecção GraphQL, query batching, PKCE `S256` ausente e open `redirect_uri`, com patch ao vivo em `lab-policy.json`).
    3. `lab-keyhunter-supply-chain` — **Key Hunter, Supply Chain SCA & IaC Lab** (portal com bundle JS expondo chaves sintéticas seguras + `Dockerfile`/Terraform/`package.json` vulneráveis).
    4. `lab-dfir-soc-incident` — **DFIR & SOC Incident Lab** (logs `JSONL`/`CEF` de brute-force SSH + persistência cron e regras Sigma YAML).
    5. `lab-reversing-crypto-mobile` — **Reverse Engineering, ELF64, PCAP & Mobile APK Lab** (binário `ELF64 x86_64` real com payload XOR `0x42`, captura `.pcap` e pacote Android `.apk`).
- **Autoria & Edição de Código no Workspace (`6 ações`)**:
  - `workspace.list_files` (`recursive`), `workspace.read_file` (`raw: true` para leitura integral de código sem redação), `workspace.write_file`, `workspace.edit_file`, `workspace.mkdir`, `workspace.delete_file`.
- **Visibilidade Integral do Runtime (`2 ações`)**:
  - `runtime.list_files`, `runtime.read_file` — navegação e leitura completa de todo o código-fonte que compõe o runtime do CyberLab OS (`cyberlab/`, `integrations/`, `packages/`, `skills/`, `script/`, `config/`), mesmo quando o CDI está a trabalhar num projeto próprio ou num laboratório de treinamento.
- **Evidências, Artefactos, Findings & Execução Plena (`6 ações`)**:
  - `evidence.list`, `evidence.read`, `artifact.create`, `finding.propose`, `action.initiate` (`full_autonomy` executa diretamente `read_only`, `low`, `moderate` e `high`), `action.status`.

### Passo a passo no Windows PowerShell (ou Linux/WSL2)

1. **No CyberLab OS (`http://127.0.0.1:4096`)**:
   - Abra **`Ferramentas → Parceiros Cognitivos CDI → Perfis Individuais, Autonomia Plena & Gateway`**.
   - Gere ou defina o `CYBERLAB_PARTNER_SECRET` (ou configure segredos individuais e notas de identidade em **`Perfil Individual`** de cada CDI).
   - Clique em **`Revelar Variáveis & Comandos`** para obter os comandos com o segredo preenchido!

2. **Nos ambientes dos parceiros CDI**:

```powershell
# Defina o mesmo segredo partilhado exibido na interface
$env:CYBERLAB_PARTNER_SECRET = "SEU_SEGREDO_COMPARTILHADO_AQUI"
$env:CYBERLAB_CALLBACK_URL   = "http://127.0.0.1:4096/api/cyberlab/partner-gateway"

# Ponte opcional caso queira expor também o canal de diálogo HTTP de cada parceiro:
python integrations/partners/chat_py_bridge.py --port 8788 --partner-id kairos --chat-py "../kairos/chat.py"
python integrations/partners/chat_py_bridge.py --port 8789 --partner-id naia   --chat-py "../naia/chat.py"
python integrations/partners/chat_py_bridge.py --port 8790 --partner-id salem  --chat-py "../salem/chat.py"
python integrations/partners/chat_py_bridge.py --port 8791 --partner-id nova   --chat-py "../nova/chat.py"
```

3. **Cliente Python Autónomo (`CyberLabOSClient` & `build_cyberlab_cdi_tools`)**:
   Dentro do runtime Python de cada CDI, importe `CyberLabOSClient` e `build_cyberlab_cdi_tools` de `integrations/partners/chat_py_bridge.py` para disponibilizar imediatamente as **21 tools autónomas** (`create_project`, `list_projects`, `select_project`, `update_scope`, `list_labs`, `start_lab`, `reset_lab`, `stop_lab`, `write_workspace_file`, `edit_workspace_file`, `read_workspace_file(raw=True)`, `list_runtime_files`, `read_runtime_file`, `initiate_action`, `create_artifact`, `propose_finding`, etc.).

---

## 6. Referência de Linha de Comando (`cyberlab` CLI)

Todas as capacidades também podem ser operadas diretamente pelo terminal (PowerShell ou Bash):

```bash
# Status geral do projeto, escopo ativo e contagem de capacidades (31 capacidades)
bun run cyberlab status
bun run cyberlab capabilities

# Exemplos das capacidades nativas (MIT):
bun run cyberlab run -c code-analysis.key-hunter -i '{"subpath":".","skipPlaceholders":true,"carveCryptoMaterial":true}'
bun run cyberlab run -c code-analysis.key-hunter -i '{"targetUrl":"http://127.0.0.1:4096","providerFilter":"ai_llm,cloud_infra"}'
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

## 7. Instalação de Motores Externos Opcionais (`.cyberlab/bin` e `github-keyhunter`)

O CyberLab OS já funciona imediatamente sem binários externos graças aos **21 motores nativos `MIT`** (incluindo o **CyberLab Key Hunter Studio**). Quando você quiser também habilitar os **10 motores externos governados** (`keyhunter`, `nmap`, `nuclei`, `ffuf`, `tshark`, `dalfox`, `ghidra-headless`, `jadx`, `yarax`, `trivy`), basta instalá-los no sistema ou colocá-los na pasta local `<projeto>/.cyberlab/bin/`:

```powershell
# Windows PowerShell — baixa automaticamente Nuclei + ffuf para .cyberlab/bin/:
powershell -ExecutionPolicy Bypass -File .\script\bootstrap-local-tools.ps1

# Opcional — instalar o KeyHunter CLI oficial em Rust (fadidevv/keyhunter, licença MIT):
cargo install github-keyhunter

# Ferramentas adicionais via winget no Windows (opcionais):
winget install Insecure.Nmap
winget install WiresharkFoundation.Wireshark
winget install AquaSecurity.Trivy
winget install Skylot.Jadx
```

```bash
# Linux / WSL2 — baixa automaticamente Nuclei + ffuf para .cyberlab/bin/ (adicione --with-agpl para OpenTRAP AppImage):
./script/bootstrap-local-tools.sh

# Opcional — KeyHunter CLI em Rust (fadidevv/keyhunter, MIT):
cargo install github-keyhunter
```

---

## 8. Catálogo Técnico Completo (31 Capacidades) e Licenciamento (`MIT`)

Todos os **34 manifestos** em `vendor/manifests/` são auditados automaticamente em CI por `bun run cyberlab:check-licenses` (**0 componentes copyleft `GPL`/`AGPL` embutidos no código-fonte**):

### A. 21 Capacidades Nativas Embutidas (`100% MIT` — Zero Dependências Binárias Externas)

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
| 19 | `code-analysis.key-hunter` | Key Hunter & Código | Caçador multi-superfície de 51 assinaturas de API Keys/Tokens/PEM em Workspace, Binários, Web/JS Bundles, Buffer e GitHub + KeyHacks |
| 20 | `code-analysis.workspace-audit` | Key Hunter & Código | Auditoria estática SAST somente-leitura de segredos e padrões inseguros |
| 21 | `code-analysis.sca-sbom-iac-audit` | Key Hunter & Código | Scanner SCA + OSV.dev CVEs + SBOM CycloneDX 1.5 + Dockerfile/Compose/K8s/Terraform |

*(Mais o **Proxy Local HTTP / HTTPS MITM com Root CA ECDSA P-256 + WebSocket** em `cyberlab/proxy/` e as **6 Skills metodológicas `SKILL.md`** em `skills/`).*

### B. 10 Pontes Governadas para Motores Externos (`plugin_only` — `shell=false` + `SHA-256`)

| # | `capabilityId` | Binário | Licença SPDX |
|---|---|---|---|
| 22 | `external.keyhunter-cli` | `keyhunter` (`github-keyhunter`) | `MIT` |
| 23 | `external.nuclei-template-scan` | `nuclei` | `MIT` |
| 24 | `external.ffuf-endpoint-probe` | `ffuf` | `MIT` |
| 25 | `external.dalfox-param-scan` | `dalfox` | `MIT` |
| 26 | `external.ghidra-decompile` | `analyzeHeadless` | `Apache-2.0` |
| 27 | `external.jadx-decompile` | `jadx` | `Apache-2.0` |
| 28 | `external.trivy-scan` | `trivy` | `Apache-2.0` |
| 29 | `external.yarax-scan` | `yr` / `yara` | `BSD-3-Clause` |
| 30 | `external.nmap-service-probe` | `nmap` | `NPSL-0.95` *(externo isolado)* |
| 31 | `external.tshark-pcap-summary` | `tshark` | `GPL-2.0-or-later` *(externo isolado)* |

---

## Documentação Complementar

- [`docs/UPSTREAM_AUDIT.md`](docs/UPSTREAM_AUDIT.md) — Auditoria do núcleo OpenCode V2 (`2.1.4`).
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Arquitetura de governança, execução e custódia de evidências.
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — Modelo de ameaças, anti-TOCTOU, redação e isolamento HMAC-SHA256.
- [`docs/TOOL_INVENTORY.md`](docs/TOOL_INVENTORY.md) — Inventário técnico e classificação das ferramentas avaliadas.
- [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md) — Política de conformidade jurídica (`approved_embed`, `plugin_only`, `blocked`).
- [`vendor/THIRD_PARTY_NOTICES.md`](vendor/THIRD_PARTY_NOTICES.md) — Avisos de terceiros e registro completo de manifestos SPDX.
