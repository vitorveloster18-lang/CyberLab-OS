# Third-Party Notices — CyberLab OS

Este arquivo registra os componentes de software incorporados ao repositório **CyberLab OS**, suas origens, commits fixados e licenças aplicáveis. Nenhum componente sob licenças copyleft restritivas (`GPL`, `AGPL`, `SSPL`), `NPSL` ou proprietárias é embutido neste produto.

---

## 1. `opencode-v2-core` — OpenCode V2 (`anomalyco/opencode`)

- **ID de Manifesto**: `opencode-v2-core`
- **Componente**: OpenCode V2 (pacotes de produto em `packages/`, scripts base em `script/`, patches de dependências em `patches/`)
- **Versão**: `2.1.4`
- **Origem**: `https://github.com/anomalyco/opencode`
- **Commit fixado**: `dae4077a96243257ea0a2086068504b791629f10`
- **Licença SPDX**: `MIT`

```text
MIT License

Copyright (c) 2025 Anomaly

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. Componentes Nativos Aprovados do CyberLab OS (`MIT`)

Os seguintes adaptadores e executores em `cyberlab/` e `integrations/` são implementações originais `MIT` do **CyberLab OS**, auditadas quanto a dependências transitivas e registradas em `vendor/manifests/`:

- **`cyberlab-workspace-audit`** (`integrations/code-analysis/workspace-audit-executor.ts`) — Auditoria somente leitura de configuração e segredos no workspace (`MIT`).
- **`cyberlab-http-security-inspector`** (`integrations/web-security/http-security-inspector.ts`) — Inspetor passivo de cabeçalhos HTTP de segurança, flags de cookies e CORS (`MIT`).
- **`cyberlab-http-repeater`** (`integrations/web-security/http-repeater-comparer.ts`) — Repeater HTTP nativo e Comparer diferencial de respostas com redação automática de segredos (`MIT`).
- **`cyberlab-decoder-sequencer`** (`integrations/web-security/decoder-sequencer.ts`) — Decoder encadeado de payloads, inspetor de segurança JWT e Sequencer de entropia de Shannon (`MIT`).
- **`cyberlab-web-surface-discovery`** (`integrations/web-security/surface-discovery.ts`) — Scanner nativo de superfície web e templates de exposição com controle de concorrência (`MIT`).
- **`cyberlab-tcp-surface-probe`** (`integrations/network-observation/tcp-banner-inspector.ts`) — Sonda controlada de conectividade TCP e observação passiva de banners em laboratório (`MIT`).
- **`cyberlab-tls-inspector`** (`integrations/network-observation/tls-certificate-inspector.ts`) — Inspetor nativo de handshake TLS/SSL, cifras e certificados X.509 (`MIT`).
- **`cyberlab-pcap-analyzer`** (`integrations/network-observation/pcap-packet-analyzer.ts`) — Analisador nativo TypeScript de capturas de pacotes `.pcap` sem dependências GPL (`MIT`).
- **`cyberlab-binary-triage`** (`integrations/reverse-forensics/binary-static-triage.ts`) — Triagem estática nativa de binários `ELF`, `PE/COFF` e `Mach-O`, flags NX/ASLR/PIE e entropia de packers (`MIT`).
- **`cyberlab-mobile-triage`** (`integrations/reverse-forensics/mobile-artifact-triage.ts`) — Forense nativa em memória de pacotes mobile `.apk`/`.ipa`/backups e detecção de permissões críticas e IoCs (`MIT`).
- **`cyberlab-external-control-plane`** (`cyberlab/external/control-plane.ts`) — Plano de controle unificado `MIT` para descoberta, supervisão (`shell=false` + kill-switch), ingestão de sessões manuais externas e sincronização `.cyberlab/inbox/` com custódia `SHA-256` (`MIT`).
- **`cyberlab-http-proxy`** (`cyberlab/proxy/http-proxy.ts`) — Proxy HTTP local `MIT` (`127.0.0.1`) de captura de tráfego com validação `ScopeController`, proteção SSRF, redação automática de cabeçalhos sensíveis e integração direta com Repeater/Comparer e custódia `SHA-256` (`MIT`).
- **`cyberlab-security-studio`** (`packages/gui-plugins/src/cyberlab/` e `cyberlab/studio/`) — Interface manual visual completa integrada ao OpenCode V2 e em janela cheia no navegador para todas as 7 disciplinas de segurança, sem dependência de UIs externas (`MIT`).
- **`cyberlab-cdi-hub`** (`cyberlab/partners/cdi-hub.ts` e `integrations/partners/chat_py_bridge.py`) — Hub Multi-CDI e Gateway Bidirecional `HMAC-SHA256` (`Kairós`, `Naia`, `Salem`, `Nova`) para colaboração individual ou em paralelo de múltiplos agentes CDI externos com acesso governado a estado, evidências, ficheiros, artifacts `SHA-256` e iniciação de capabilities (`MIT`).
- **`cyberlab-http-intruder`** (`integrations/web-security/http-intruder-matrix.ts`) — Executor paramétrico nativo `§slot§` (*Sniper*, *Battering Ram*, *Pitchfork*) com rate-limit, bloqueio de escape de origem e custódia `SHA-256` (`MIT`).
- **`cyberlab-param-auditor`** (`integrations/web-security/differential-param-auditor.ts`) — Auditor diferencial não-destrutivo de parâmetros, reflexão de canário alfanumérico, vazamento de stack traces e redirecionamentos (`MIT`).
- **`cyberlab-dns-recon`** (`integrations/network-observation/dns-surface-recon.ts`) — Reconhecimento DNS (`A/AAAA/CNAME/MX/NS/TXT/SOA/CAA`), postura `SPF`/`DMARC`, higiene contra *Subdomain Takeover* e transparência de certificados (`MIT`).
- **`cyberlab-binary-disassembler`** (`integrations/reverse-forensics/binary-disassembler.ts`) — Disassembler estático multi-arquitetura (`x86_64` e `ARM64`) e resolvedor de símbolos offline para `ELF64`, `PE/COFF` e `Mach-O` (`MIT`).
- **`cyberlab-yara-scanner`** (`integrations/reverse-forensics/yara-rule-scanner.ts`) — Motor nativo de regras YARA (padrões ASCII, UTF-16LE `wide`, `nocase`, hex curinga `??` e condições booleanas) para arquivos e pastas do projeto (`MIT`).
- **`cyberlab-api-security-lab`** (`integrations/web-security/api-graphql-oauth-lab.ts`) — Importador OpenAPI/Swagger e Postman Collection v2.1 com matriz diferencial BOLA/IDOR, inspetor de postura GraphQL e auditor OAuth2/OIDC (`MIT`).
- **`cyberlab-sca-sbom-iac`** (`integrations/code-analysis/sca-sbom-iac-auditor.ts`) — Scanner nativo SCA (`npm`/`bun`/`PyPI`/`Go`/`Cargo`/`Maven`) com geração de SBOM CycloneDX 1.5, integração OSV.dev e auditor estático de `Dockerfile`, `docker-compose`, Kubernetes e Terraform (`MIT`).
- **`cyberlab-dfir-sigma`** (`integrations/reverse-forensics/dfir-sigma-analyzer.ts`) — Analisador forense DFIR de logs (`syslog`/`auth.log`, Nginx/Apache, JSON/Windows Events), motor de regras Sigma YAML e gerador de Timeline de Incidente com custódia `SHA-256` (`MIT`).
- **`cyberlab-ad-smb-ldap`** (`integrations/network-observation/ad-smb-ldap-inspector.ts`) — Inspetor passivo de laboratório para assinatura SMB2/3 (`SMB Signing`), exposição anônima de `RootDSE` LDAPv3 e decodificação de metadados de challenge HTTP NTLM (`MIT`).
- **`cyberlab-entropy-recipe-studio`** (`integrations/reverse-forensics/entropy-recipe-studio.ts`) — Mapeador visual de entropia de Shannon por janelas, detector de assinaturas mágicas embutidas e estúdio de receitas estilo CyberChef (`XOR`, `AES`, `Gzip/Zlib`, `Protobuf raw`) (`MIT`).
- **`cyberlab-key-hunter`** (`integrations/code-analysis/key-hunter.ts`) — Motor nativo `MIT` **Key Hunter** de caça de API keys, tokens cloud/LLM/SaaS/pagamentos, URIs de banco de dados e chaves criptográficas (`PEM`/`JWK`/`JWT`/alta entropia) em ficheiros/binários do workspace, páginas web + JS bundles remotos em escopo, buffers colados e repositórios GitHub autorizados, com filtro inteligente anti-placeholders, redação automática de segredos e receitas KeyHacks (`MIT`).

 Conectores externos opcionais sob licenças permissivas registrados em `vendor/manifests/` (invocados via `shell=false` sem incorporação binária): `dalfox-external-connector` (`MIT`), `ghidra-headless-connector` (`Apache-2.0`), `jadx-external-connector` (`Apache-2.0`), `yarax-external-connector` (`BSD-3-Clause`), `trivy-external-connector` (`Apache-2.0`) e `keyhunter-external-connector` (`MIT`, `fadidevv/keyhunter`).

---

## 3. Principais Dependências Runtime Permissivas

- **Effect (`effect@4.0.1`)** — `MIT` (`https://github.com/Effect-TS/effect`)
- **SolidJS (`solid-js@1.9.15`)** — `MIT` (`https://github.com/solidjs/solid`)
- **Hono (`hono@4.10.7`)** — `MIT` (`https://github.com/honojs/hono`)
- **Drizzle ORM (`drizzle-orm@1.0.0-rc.5`)** — `Apache-2.0` (`https://github.com/drizzle-team/drizzle-orm`)
