# Playbook Oficial — CyberLab OS v7.0
## Kali nativo: método, escopo e custódia

Este guia tem **todos os comandos prontos para copiar e colar** no terminal do seu
**Kali Linux**. Não há Windows, WSL2, VM convidada nem ponte de sistema operacional:
as ferramentas são as que **você** já tem instaladas, e o CyberLab entra com a
governança — trava de escopo, redação de segredos e custódia `SHA-256`.

---

## 1. Instalação (uma vez)

```bash
# 1. Dependência de runtime
curl -fsSL https://bun.sh/install | bash
exec $SHELL          # recarrega o PATH

# 2. Clonar e instalar
git clone https://github.com/vitorveloster18-lang/CyberLab-OS.git
cd CyberLab-OS
bun install --ignore-scripts
bun run --cwd packages/core fix-node-pty

# 3. Conferir que está tudo no lugar
bun run cyberlab status
bun run script/check-cyberlab-licenses.ts
```

### Atualizar depois

```bash
cd ~/CyberLab-OS
git pull --ff-only
bun install --ignore-scripts
```

---

## 2. O ciclo de uma investigação

### 2.1 Declarar o escopo — sempre o primeiro passo

Nada sai do papel enquanto o escopo não estiver declarado. O comando é **tudo ou
nada**: você passa a lista inteira de uma vez.

```bash
# alvos internos / laboratório
bun run cyberlab scope 10.0.0.0/24 127.0.0.1

# alvo público (bug bounty autorizado) — exige --external
bun run cyberlab scope --external exemplo.com *.exemplo.com

bun run cyberlab scope                 # mostra o escopo vigente
bun run cyberlab scope --json          # para o agente consumir
bun run cyberlab scope --clear         # encerra a autorização
```

Sem `--external`, domínios públicos/roteáveis são recusados: o padrão é falha fechada.

### 2.2 Rodar ferramentas sob guarda

```bash
bun run cyberlab exec -- nmap -sV -p 80,443 10.0.0.10
bun run cyberlab exec -- nuclei -u https://exemplo.com -t exposures/ -rate-limit 20
bun run cyberlab exec --timeout 120 -- curl -s -i https://exemplo.com/login
bun run cyberlab exec --json -- ffuf -u https://exemplo.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

O `stdout` é a saída **crua** da ferramenta — nada é reformatado. No `stderr` você
recebe o rodapé de custódia:

```text
— cyberlab exec · exit=0 · 3.2s · (saída redigida) · evidência=evt_01J...
```

Bloqueios (alvo fora de escopo) e falhas da ferramenta devolvem **exit 1**.

### 2.3 Evidências, achados e relatório

```bash
bun run cyberlab evidence                             # lista os registros com SHA-256
bun run cyberlab evidence --verify <id da evidência>  # reconfere a custódia
bun run cyberlab findings                             # achados e status de revisão
bun run cyberlab report > relatorio.md                # relatório reproduzível
```

Cada evidência carrega o comando, o alvo, o carimbo de tempo, o `SHA-256` do conteúdo
e o status de redação — é isso que sustenta a Fase I (documentação reproduzível).

---

## 3. Laboratórios de treino

Cinco alvos vulneráveis de propósito, **só em loopback**, para treinar o método sem
tocar em nada que não seja seu.

```bash
bun run cyberlab lab list

bun run cyberlab lab start lab-owasp-api-bola --daemon
bun run cyberlab lab status lab-owasp-api-bola      # porta confirmada + próximos passos
bun run cyberlab lab seed   lab-owasp-api-bola      # grava missão/escopo/hipóteses
bun run cyberlab lab model  lab-owasp-api-bola      # Fase B

# Ciclo C→I
bun run cyberlab lab research     lab-owasp-api-bola --register
bun run cyberlab lab hypothesize  lab-owasp-api-bola --register
bun run cyberlab lab experiment   lab-owasp-api-bola --run --register
bun run cyberlab lab evaluate     lab-owasp-api-bola
bun run cyberlab lab validate     lab-owasp-api-bola
bun run cyberlab lab report       lab-owasp-api-bola

bun run cyberlab lab evidence lab-owasp-api-bola --register
bun run cyberlab lab stop lab-owasp-api-bola
```

Sem `--daemon` o laboratório morre com o terminal. Com `--daemon` ele sobrevive e
`lab stop` encerra **de qualquer terminal**.

### 3.1 Apontando o Burp (ou qualquer proxy) para o alvo

```bash
bun run cyberlab lab start lab-owasp-api-bola --daemon
bun run cyberlab lab status lab-owasp-api-bola     # anote a porta do alvo

# No Burp: Proxy > Proxy settings > listener em 127.0.0.1:8080
# Depois aponte o navegador (ou o curl) para esse proxy:
bun run cyberlab scope 127.0.0.1
bun run cyberlab exec -- curl -s -x http://127.0.0.1:8080 http://127.0.0.1:19081/api/v1/accounts/1002
```

---

## 4. Biblioteca de conhecimento

```bash
bun run cyberlab knowledge                # plano (não escreve nada)
bun run cyberlab knowledge --apply        # aplica, com .bak antes de cada troca
bun run cyberlab knowledge --json         # plano em JSON
```

O cofre nasce em `<workspace>/vault/CyberLab-Knowledge/` na primeira execução, com a
semeadura idempotente — nunca sobrescreve uma nota que você tenha editado. Onde o
cofre é criado depende de `CYBERLAB_WORKSPACE_ROOT` (padrão: o diretório atual).

Para servir a biblioteca via MCP (ex.: para outro cliente que fale MCP):

```bash
bun run cyberlab/mcp/knowledge-mcp-stdio.ts --workspace /caminho/do/projeto
```

| Ferramenta MCP | O que faz |
|---|---|
| `search_knowledge` | Busca full-text na biblioteca curada |
| `read_document` | Lê um documento por `id`/caminho |
| `list_documents` | Lista a árvore curada por categoria |
| `get_related_documents` | Navega o grafo `[[WikiLinks]]` |
| `record_investigation_note` | Grava nota da sessão (Camada 2) |
| `search_investigation_notes` | Recupera notas da sessão |
| `promote_note_to_curated` | Promove uma nota validada para a Camada 1 |
| `get_knowledge_status` | Estado da biblioteca e contagens por camada |

---

## 5. Parceiros cognitivos (CDI)

```bash
bun run cyberlab partner --help
```

O gateway é `HMAC-SHA256` bidirecional. Configure o segredo por variável de ambiente
(mínimo de 16 caracteres) antes de subir:

```bash
export CYBERLAB_PARTNER_SECRET="$(openssl rand -hex 32)"
bun run cyberlab status
```

---

## 6. Resolvendo problemas

| Sintoma | Causa | Solução |
|---|---|---|
| `comando bloqueado pelo escopo` | alvo fora da lista autorizada (ou público sem `--external`) | `bun run cyberlab scope <alvos>` |
| `binário não encontrado` | a ferramenta não está no `PATH` do seu Kali | `sudo apt install -y <pacote>` ou chame pelo caminho absoluto |
| Pacote instalado mas binário ausente | a distro não publica o binário no `PATH` | use o caminho absoluto: `bun run cyberlab exec -- /usr/share/ghidra/support/analyzeHeadless ...` |
| `lab status` diz "parado" mas o alvo responde | o daemon subiu em outro terminal | é esperado: use `bun run cyberlab lab stop <labId>` e suba de novo |
| Cofre vazio | `cyberlab knowledge` nunca rodou | `bun run cyberlab knowledge --apply` |

---

## 7. O que o CyberLab NÃO faz mais

Para evitar surpresa, a lista explícita do que saiu na v7.0:

- ❌ Não instala ferramenta — nem `apt`, nem `pipx`, nem download de release.
- ❌ Não embute navegador, proxy ou CA própria.
- ❌ Não alcança Windows/WSL2 nem faz tradução de caminhos entre sistemas.
- ❌ Não sobe interface web: `bun run cyberlab` sem argumentos mostra a ajuda.
- ❌ Não existe mais `cyberlab up`, `cyberlab studio`, `cyberlab external`,
  `cyberlab app`, `cyberlab serve`, `lab slots` nem `lab tools`.

O que ele faz: **método, escopo e custódia**.
