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
- **`cyberlab-cdi-hub`** (`cyberlab/partners/cdi-hub.ts` e `integrations/partners/chat_py_bridge.py`) — Hub Multi-CDI e Gateway Bidirecional `HMAC-SHA256` para colaboração individual ou em paralelo de múltiplos agentes CDI externos com acesso governado a estado, evidências, ficheiros, artifacts `SHA-256` e iniciação de capabilities (`MIT`).

---

## 3. Principais Dependências Runtime Permissivas

- **Effect (`effect@4.0.1`)** — `MIT` (`https://github.com/Effect-TS/effect`)
- **SolidJS (`solid-js@1.9.15`)** — `MIT` (`https://github.com/solidjs/solid`)
- **Hono (`hono@4.10.7`)** — `MIT` (`https://github.com/honojs/hono`)
- **Drizzle ORM (`drizzle-orm@1.0.0-rc.5`)** — `Apache-2.0` (`https://github.com/drizzle-team/drizzle-orm`)
