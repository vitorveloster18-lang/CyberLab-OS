# Third-Party Notices — CyberLab OS v5.0 ("Real Arsenal Edition")

Este arquivo registra os componentes de software incorporados ao repositório **CyberLab OS**, suas origens, commits fixados e licenças aplicáveis. Nenhum componente sob licenças copyleft restritivas (`GPL`, `AGPL`, `SSPL`), `NPSL` ou proprietárias é embutido neste repositório. Todas as ferramentas externas de segurança (como Burp Suite, OpenTRAP, Caido, OWASP ZAP, Nuclei, ffuf, Nmap, Wireshark, Ghidra, JADX, KeyHunter, CyberChef e binários Kali WSL2) são instaladas externamente pelo utilizador fora do repositório e operadas via **Arsenal Slots** (`shell=false` / Web UI local / WSL2 bridge).

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

Os seguintes módulos nativos em `cyberlab/` e `integrations/` são implementações originais `MIT` do **CyberLab OS**, registradas em `vendor/manifests/`:

- **`cyberlab-arsenal-slots`** (`cyberlab/arsenal/catalog.ts`, `cyberlab/arsenal/slot-manager.ts`, `cyberlab/proxy/browser-launcher.ts`) — Gerenciador de Slots Externos Reais (Windows PowerShell + WSL2 Kali Linux + Web UIs locais + Custom Slots + navegador isolado pré-configurado para proxies externos) (`MIT`).
- **`cyberlab-workspace-audit`** (`integrations/code-analysis/workspace-audit-executor.ts`) — Auditoria rápida local somente leitura de configuração e higiene de workspace (`MIT`).
- **`cyberlab-external-control-plane`** (`cyberlab/external/control-plane.ts`) — Plano de controle `MIT` (`shell=false` + kill-switch + custódia `SHA-256` + sincronização `.cyberlab/inbox/`) (`MIT`).
- **`cyberlab-cdi-hub`** (`cyberlab/partners/cdi-hub.ts` e `integrations/partners/chat_py_bridge.py`) — Hub Multi-CDI e Gateway Bidirecional `HMAC-SHA256` (`Kairós:8788`, `Naia:8789`, `Salem:8790`, `Nova:8791`) com autonomia horizontal plena e 5 Laboratórios de Treinamento interativos (`MIT`).

Conectores externos opcionais sob licenças permissivas registrados em `vendor/manifests/` (invocados via `shell=false` sem incorporação binária no repositório): `dalfox-external-connector` (`MIT`), `ghidra-headless-connector` (`Apache-2.0`), `jadx-external-connector` (`Apache-2.0`), `yarax-external-connector` (`BSD-3-Clause`), `trivy-external-connector` (`Apache-2.0`) e `keyhunter-external-connector` (`MIT`, `fadidevv/keyhunter`).

---

## 3. Principais Dependências Runtime Permissivas

- **Effect (`effect@4.0.1`)** — `MIT` (`https://github.com/Effect-TS/effect`)
- **SolidJS (`solid-js@1.9.15`)** — `MIT` (`https://github.com/solidjs/solid`)
- **Hono (`hono@4.10.7`)** — `MIT` (`https://github.com/honojs/hono`)
- **Drizzle ORM (`drizzle-orm@1.0.0-rc.5`)** — `Apache-2.0` (`https://github.com/drizzle-team/drizzle-orm`)
