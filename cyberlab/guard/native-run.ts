import { spawnSync } from "node:child_process"
import { randomUUID } from "node:crypto"
import { readFileSync, statSync } from "node:fs"
import net from "node:net"
import path from "node:path"

import type { EvidenceDraft } from "../contracts/evidence.js"
import { redactSensitiveContent } from "../evidence/provenance.js"
import type { EvidenceStore } from "../evidence/store.js"
import type { ExtractedTargets, ScopeController } from "../policy/scope.js"

/**
 * Execução nativa com governança — o núcleo do CyberLab quando ele roda
 * DENTRO do Kali, em vez de dirigir o Kali de fora.
 *
 * MOTIVAÇÃO: a arquitetura antiga empacotava 48 ferramentas e as executava
 * através de uma ponte (`wsl.exe -d <distro> -- bin args`). Isso obrigava a
 * traduzir caminhos, montar argv e detectar binários em dois sistemas
 * operacionais — e ainda assim não entregava kernel real.
 *
 * Com o CyberLab rodando dentro do Kali, essa ponte simplesmente desaparece:
 * a ferramenta é executada direto, como se você tivesse digitado no terminal.
 * O que o CyberLab passa a fazer é só aquilo que NÃO dá para obter rodando o
 * comando cru:
 *
 *   1. checar o escopo ANTES de executar (e recusar se estiver fora)
 *   2. redigir segredos do stdout/stderr
 *   3. gravar a evidência com SHA-256 e cadeia de custódia
 *
 * Os três dependem de haver um ponto por onde o comando passe. Sem este
 * wrapper, "manter o scope guard" seria decorativo: o código continuaria
 * existindo, mas nunca seria chamado.
 *
 * Só depende de `node:child_process` + os três módulos acima, para poder ser
 * importado por um CLI mínimo sem puxar Effect nem o arsenal.
 */

export interface GuardedRunOptions {
  projectId: string
  /** `argv[0]` é o binário; o resto são os argumentos. Nunca passe o `--` aqui. */
  argv: readonly string[]
  cwd?: string
  scope: ScopeController
  store: EvidenceStore
  /** Quem está executando, para a cadeia de custódia. */
  actor?: string
  /** Identificador do executor (ex.: "kali-vm", "wsl-kali"). */
  executorId?: string
  /** Timeout em ms. Padrão: 30 min. Sem timeout, um scan travaria o terminal. */
  timeoutMs?: number
  /** Rótulo legível da ferramenta, para o título da evidência. */
  label?: string
}

export interface GuardedRunResult {
  /** `true` quando o escopo recusou — nesse caso NADA foi executado. */
  blocked: boolean
  blockReason: string | null
  command: string
  exitCode: number | null
  /** stdout já redigido. Seguro para exibir, logar e compartilhar. */
  stdout: string
  /** stderr já redigido. */
  stderr: string
  redacted: boolean
  evidenceId: string | null
  durationMs: number
  timedOut: boolean
}

/** Falha de uso, não de execução: argv vazio, etc. */
export class GuardedRunUsageError extends Error {}

/**
 * Extrai alvos de rede de um argv cru.
 *
 * EXISTE POR UM MOTIVO ESPECÍFICO: `extractTargetsFromInput` só entende objeto
 * estruturado (campos `target`, `url`, `host`...) e devolve VAZIO para qualquer
 * coisa que não seja objeto — inclusive uma string de comando. Passar a linha
 * de comando direto para ela faria o escopo não ver alvo nenhum e liberar tudo,
 * que é exatamente a falha silenciosa que este wrapper existe para evitar.
 *
 * Cuidados tomados:
 * - argumentos começando com `-` são ignorados (flags como `-sV` não são alvos)
 * - IPv4 exige 4 octetos válidos, então `1.2.3` (número de versão) não casa
 * - domínio exige ponto e TLD alfabético, então `wordlist.txt` não casa
 */
/** Binários que falam com a rede: sem alvo verificável, não podem rodar. */
const NETWORK_TOOLS = new Set([
  "nmap",
  "masscan",
  "nuclei",
  "naabu",
  "httpx",
  "ffuf",
  "feroxbuster",
  "gobuster",
  "dirb",
  "dirsearch",
  "nikto",
  "sqlmap",
  "curl",
  "wget",
  "dig",
  "host",
  "nslookup",
  "whois",
  "ping",
  "nc",
  "ncat",
  "netcat",
  "ssh",
  "scp",
  "sftp",
  "smbclient",
  "smbmap",
  "crackmapexec",
  "nxc",
  "hydra",
  "medusa",
  "wpscan",
  "subfinder",
  "amass",
  "dnsx",
  "katana",
  "zap",
  "zaproxy",
])

/** Invólucros que precedem o binário real (`sudo nmap ...`). */
const WRAPPER_COMMANDS = new Set(["sudo", "doas", "env", "nice", "ionice", "timeout", "time", "command", "stdbuf"])

/** Intérpretes que recebem o comando real dentro de um único argumento. */
const SHELL_WRAPPERS = new Set([
  "sh",
  "bash",
  "dash",
  "zsh",
  "ksh",
  "fish",
  "busybox",
  "cmd",
  "cmd.exe",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
])

/** Flags que apontam para um arquivo cujo conteúdo são alvos, por ferramenta. */
const TARGET_LIST_FLAGS: Record<string, readonly string[]> = {
  nmap: ["-iL", "--input-file"],
  masscan: ["-iL", "--includefile"],
  nuclei: ["-l", "-list", "--list"],
  httpx: ["-l", "-list", "--list"],
  sqlmap: ["-r", "--request-file"],
}

/** Flags que não geram tráfego de rede: pedir ajuda/versão não precisa de alvo. */
const INFORMATIONAL_FLAGS = new Set(["-h", "--help", "-help", "--version", "-version", "-V"])

const MAX_TARGET_LIST_BYTES = 4 * 1024 * 1024
const MAX_TARGET_LIST_LINES = 5000

const ipv4Source = "(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)"
const cidrRe = new RegExp(`^(${ipv4Source})/(\\d{1,2})$`)
const cidr6Re = /^(.+)\/(\d{1,3})$/
const hostPortRe = new RegExp(`^(${ipv4Source}):(\\d{1,5})$`)
const genericHostPortRe = /^([^:/]+):(\d{1,5})$/
const urlRe = /^[a-z][a-z0-9+.-]*:\/\//i
const domainRe = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i
const FILE_LIKE_RE =
  /\.(txt|json|ya?ml|xml|csv|md|log|conf|cfg|ini|sh|bash|py|js|mjs|cjs|ts|tsx|jsx|exe|dll|bin|tar|tgz|gz|bz2|xz|zip|7z|rar|pdf|png|jpe?g|gif|svg|html?|css|bak|old|tmp|lock|toml|sql|db|sqlite|key|pem|crt|cer|der|p12|pfx|pcap|cap|lst|list|wordlist|gz|iso|img|ova|vdi|qcow2|deb|rpm|apk|jar|war|so|o|a|class|go|rs|c|h|cpp|hpp|rb|pl|php|lua|swift|kt|java|scala|clj|ex|exs|erl|beam)$/i

export interface TargetInspection extends ExtractedTargets {
  /** Arquivos de lista citados no comando que não puderam ser lidos. */
  unresolvedTargetSources?: string[]
}

export function extractTargetsFromArgv(argv: readonly string[]): TargetInspection {
  const found = new Set<string>()
  const unresolved: string[] = []
  const cwd = process.cwd()

  collectTargets(argv, detectTool(argv), found, unresolved, cwd)
  // `sh -c "nmap 10.0.0.5"` esconde o comando real dentro de um argumento só.
  for (const payload of shellPayloads(argv)) {
    collectTargets(payload.split(/\s+/), detectTool([payload]), found, unresolved, cwd)
  }

  return {
    networkTargets: [...found],
    workspacePaths: [],
    ...(unresolved.length > 0 ? { unresolvedTargetSources: [...new Set(unresolved)] } : {}),
  }
}

/** Nome do binário efetivo, ignorando invólucros como `sudo`/`timeout`. */
export function detectTool(argv: readonly string[]): string | undefined {
  const first = basenameOf(argv[0] ?? "")
  if (NETWORK_TOOLS.has(first)) return first
  if (!WRAPPER_COMMANDS.has(first)) return undefined
  for (const token of argv.slice(1)) {
    const candidate = basenameOf(token)
    if (NETWORK_TOOLS.has(candidate)) return candidate
  }
  return undefined
}

function basenameOf(value: string): string {
  const clean = stripQuotes(value).replace(/\\/g, "/")
  return clean.slice(clean.lastIndexOf("/") + 1).toLowerCase()
}

function stripQuotes(value: string): string {
  return value.replace(/^["'`]+|["'`]+$/g, "")
}

/** Payload de `sh -c`, `/bin/sh -c`, `powershell -Command`, `cmd /c`. */
function shellPayloads(argv: readonly string[]): string[] {
  if (!SHELL_WRAPPERS.has(basenameOf(argv[0] ?? ""))) return []
  const payload: string[] = []
  for (let index = 1; index < argv.length; index++) {
    const token = stripQuotes(argv[index] ?? "").toLowerCase()
    if (token === "-c" || token === "/c" || token === "-command") {
      const rest = argv.slice(index + 1).join(" ").trim()
      if (rest) payload.push(rest)
      break
    }
  }
  return payload
}

function collectTargets(
  tokens: readonly string[],
  tool: string | undefined,
  found: Set<string>,
  unresolved: string[],
  cwd: string,
): void {
  const listFlags = tool !== undefined ? (TARGET_LIST_FLAGS[tool] ?? []) : []

  for (let index = 0; index < tokens.length; index++) {
    const token = stripQuotes(tokens[index] ?? "")
    if (!token) continue

    const equalsAt = token.indexOf("=")
    const flagToken = equalsAt > 0 ? token.slice(0, equalsAt) : token
    const inlineValue = equalsAt > 0 ? token.slice(equalsAt + 1) : undefined

    if (listFlags.includes(flagToken)) {
      const reference = inlineValue ?? stripQuotes(tokens[index + 1] ?? "")
      if (inlineValue === undefined && reference) index++
      if (!reference) {
        unresolved.push(flagToken)
        continue
      }
      const listed = readTargetList(reference, cwd)
      if (!listed.ok) unresolved.push(reference)
      for (const listed_target of listed.targets) found.add(listed_target)
      continue
    }

    const target = classifyToken(token)
    if (target !== undefined) found.add(target)
  }
}

function classifyToken(raw: string): string | undefined {
  const candidate = stripQuotes(raw).trim()
  if (!candidate || candidate.startsWith("-")) return undefined

  if (urlRe.test(candidate)) return classifyHost(hostFromUrl(candidate))

  const ipv4Cidr = cidrRe.exec(candidate)
  if (ipv4Cidr) {
    const base = classifyHost(ipv4Cidr[1]!)
    return base !== undefined ? `${base}/${ipv4Cidr[2]}` : undefined
  }

  const anyCidr = cidr6Re.exec(candidate)
  if (anyCidr) {
    const base = classifyHost(anyCidr[1]!)
    const prefix = Number(anyCidr[2])
    if (base !== undefined && net.isIP(base) === 6 && prefix >= 0 && prefix <= 128) return `${base}/${prefix}`
    return undefined
  }

  const ipv4HostPort = hostPortRe.exec(candidate)
  if (ipv4HostPort) return classifyHost(ipv4HostPort[1]!)

  // IPv6 entre colchetes, com porta opcional: [2001:db8::1]:8443
  const bracketed = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(candidate)
  if (bracketed) return classifyHost(bracketed[1]!)

  const genericHostPort = genericHostPortRe.exec(candidate)
  if (genericHostPort) return classifyHost(genericHostPort[1]!)

  return classifyHost(candidate)
}

function hostFromUrl(value: string): string {
  try {
    return new URL(value.replace(/§[^§]*§/g, "marker")).hostname
  } catch {
    // URL malformada: parser manual, que não exige URL completa.
    const withoutScheme = value.replace(urlRe, "")
    const hostPart = withoutScheme.split(/[/?#]/)[0] ?? ""
    const at = hostPart.lastIndexOf("@")
    return at >= 0 ? hostPart.slice(at + 1) : hostPart
  }
}

function classifyHost(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined
  const host = stripQuotes(raw).replace(/^\[|\]$/g, "").replace(/\.$/, "").trim().toLowerCase()
  if (!host) return undefined

  // IPv6 literal (o escopo compara a forma canônica do `net`).
  if (net.isIP(host) === 6) return host

  // IPv4 em representação não canônica: decimal/hex inteiro ou octetos hex/octal.
  const normalized = normalizeIpv4Octets(host) ?? normalizeIpv4Literal(host)
  if (normalized !== undefined) return normalized
  if (net.isIP(host) === 4) return host

  if (host === "localhost") return host

  // Extensões de arquivo que parecem TLD. Sem isto, `wordlist.txt` viraria
  // alvo de rede e o comando seria bloqueado por engano.
  if (FILE_LIKE_RE.test(host)) return undefined

  return domainRe.test(host) ? host : undefined
}

/** `0xc0a80101` ou `3232235521` → `192.168.1.1`. */
function normalizeIpv4Literal(candidate: string): string | undefined {
  if (/^\d{1,10}$/.test(candidate)) return dottedFromNumber(Number(candidate))
  if (/^0x[0-9a-f]{1,8}$/i.test(candidate)) return dottedFromNumber(Number.parseInt(candidate.slice(2), 16))
  return undefined
}

function dottedFromNumber(value: number): string | undefined {
  // Abaixo de 0x1000000 são valores comuns (portas, timeouts), não endereços.
  if (!Number.isInteger(value) || value <= 0xffffff || value > 0xffffffff) return undefined
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".")
}

/** `010.0.0.1`, `0x0a.0.0.1`, `10.0.0.1` → forma canônica. */
function normalizeIpv4Octets(candidate: string): string | undefined {
  const parts = candidate.split(".")
  if (parts.length !== 4) return undefined

  const octets: number[] = []
  for (const part of parts) {
    const octet = parseOctet(part)
    if (octet === undefined) return undefined
    octets.push(octet)
  }
  return octets.join(".")
}

function parseOctet(part: string): number | undefined {
  if (/^0x[0-9a-f]{1,2}$/i.test(part)) return Number.parseInt(part.slice(2), 16)
  if (/^0[0-7]{1,3}$/.test(part)) return Number.parseInt(part, 8)
  if (/^\d{1,3}$/.test(part)) {
    const value = Number(part)
    return value <= 255 ? value : undefined
  }
  return undefined
}

/** Lê um arquivo de lista de alvos (`-iL`, `-l`, `-r`) sem estourar memória. */
function readTargetList(reference: string, cwd: string): { targets: string[]; ok: boolean } {
  const resolved = path.isAbsolute(reference) ? reference : path.resolve(cwd, reference)
  try {
    const stat = statSync(resolved, { throwIfNoEntry: false })
    if (!stat || !stat.isFile() || stat.size > MAX_TARGET_LIST_BYTES) return { targets: [], ok: false }

    const lines = readFileSync(resolved, "utf8").split(/\r?\n/).slice(0, MAX_TARGET_LIST_LINES)
    const targets: string[] = []
    for (const line of lines) {
      const text = line.trim()
      if (!text || text.startsWith("#")) continue
      // Arquivo de requisição HTTP (sqlmap -r): o alvo está no Host.
      const hostHeader = /^host\s*:\s*(\S+)/i.exec(text)
      const target = classifyToken(hostHeader ? hostHeader[1]! : text)
      if (target !== undefined) targets.push(target)
    }
    return { targets, ok: true }
  } catch {
    return { targets: [], ok: false }
  }
}

function formatCommand(argv: readonly string[]): string {
  return argv
    .map((part) => (/\s/.test(part) ? JSON.stringify(part) : part))
    .join(" ")
}

function blockedResult(command: string, reason: string, startedAt: number): GuardedRunResult {
  return {
    blocked: true,
    blockReason: reason,
    command,
    exitCode: null,
    stdout: "",
    stderr: "",
    redacted: false,
    evidenceId: null,
    durationMs: Date.now() - startedAt,
    timedOut: false,
  }
}

/**
 * Falha fechada para binários de rede.
 *
 * O escopo só pode julgar o que consegue enxergar. Quando o alvo não está no
 * argv em forma reconhecível (lista em arquivo, `sh -c`, endereço não
 * canônico), "nenhum alvo extraído" NÃO significa "nada vai sair da máquina":
 * significa que a checagem não teve o que checar. Nesse caso a execução é
 * recusada em vez de liberada.
 */
function describeUnverifiableTargets(
  networkTool: string | undefined,
  targets: TargetInspection,
  informational: boolean,
  command: string,
  startedAt: number,
): GuardedRunResult | undefined {
  if (networkTool === undefined || informational) return undefined

  const unresolved = targets.unresolvedTargetSources ?? []
  if (unresolved.length > 0) {
    return blockedResult(
      command,
      `A lista de alvos (${unresolved.join(", ")}) não pôde ser lida; o escopo não pode ser verificado. Corrija o caminho ou declare os alvos diretamente.`,
      startedAt,
    )
  }
  if (targets.networkTargets.length === 0) {
    return blockedResult(
      command,
      `"${networkTool}" é um binário de rede e nenhum alvo verificável foi extraído do comando. Declare o alvo explicitamente (ex.: ${networkTool} <host|CIDR>) para que o escopo seja checado.`,
      startedAt,
    )
  }
  return undefined
}

/**
 * Executa um comando nativo sob governança.
 *
 * Ordem deliberada: o escopo é verificado ANTES do spawn. Verificar depois
 * seria inútil — o pacote já teria saído da máquina.
 */
export function runGuardedNative(options: GuardedRunOptions): GuardedRunResult {
  const {
    projectId,
    argv,
    cwd,
    scope,
    store,
    actor = "operator",
    executorId = "local",
    timeoutMs = 30 * 60 * 1000,
    label,
  } = options

  if (!Array.isArray(argv) || argv.length === 0 || !argv[0]?.trim()) {
    throw new GuardedRunUsageError("Informe ao menos um binário para executar.")
  }

  const bin = argv[0]!
  const args = argv.slice(1)
  const command = formatCommand(argv)
  const startedAt = Date.now()

  // --- 1. Escopo, antes de qualquer spawn ---
  // Extrai do ARGV, não da string: extractTargetsFromInput ignora tudo que não
  // seja objeto estruturado, e usar a string aqui faria o escopo não ver alvo
  // nenhum e liberar a execução (falha silenciosa, o oposto do objetivo).
  const targets = extractTargetsFromArgv(argv)
  const networkTool =
    detectTool(argv) ?? shellPayloads(argv).map((payload) => detectTool([payload])).find((tool) => tool !== undefined)
  const informational = argv.some((token) => INFORMATIONAL_FLAGS.has(stripQuotes(token)))
  const unverifiable = describeUnverifiableTargets(
    networkTool,
    targets,
    informational,
    command,
    startedAt,
  )
  if (unverifiable !== undefined) return unverifiable

  const verdict = scope.verifyTargets(projectId, targets)
  if (!verdict.allowed) {
    return blockedResult(command, verdict.reason ?? "Alvo fora do escopo autorizado.", startedAt)
  }

  // --- 2. Execução nativa ---
  const res = spawnSync(bin, args, {
    cwd: cwd ?? process.cwd(),
    encoding: "utf8",
    timeout: timeoutMs,
    // Sem shell: evita que metacaracteres do argumento virem comandos.
    shell: false,
    maxBuffer: 64 * 1024 * 1024,
  })

  const durationMs = Date.now() - startedAt
  const timedOut = res.error != null && "code" in (res.error as object) && (res.error as NodeJS.ErrnoException).code === "ETIMEDOUT"

  const rawOut = res.stdout ?? ""
  const rawErr = res.stderr ?? ""

  // --- 3. Redação ---
  // Redige o que sai do comando. O que entra (argv) não é redigido de
  // propósito: o operador precisa ver o comando que pediu para rodar, e
  // mascarar isso atrapalharia mais do que protegeria.
  const outRedaction = redactSensitiveContent(rawOut)
  const errRedaction = redactSensitiveContent(rawErr)
  const redacted = outRedaction.redacted || errRedaction.redacted

  // --- 4. Evidência ---
  const executionId = randomUUID()
  const combined = [outRedaction.text, errRedaction.text].filter(Boolean).join("\n")
  const draft: EvidenceDraft = {
    kind: "stdout",
    title: label ? `${label} — ${bin}` : `Execução nativa: ${bin}`,
    source: {
      toolId: bin,
      executorId,
      executionId,
    },
    content: {
      mediaType: "text/plain",
      inlineText: combined,
      byteLength: Buffer.byteLength(combined, "utf8"),
    },
    observedAt: new Date().toISOString(),
    labels: ["native_run", bin],
    redactionApplied: redacted,
  }

  let evidenceId: string | null = null
  try {
    const record = store.storeEvidence(projectId, draft, {
      actor,
      retentionClass: "project",
      applyRedactionBeforeStore: false, // já redigido acima
    })
    evidenceId = record.evidenceId
  } catch {
    // A evidência não pode derrubar a execução: o operador já rodou o comando
    // e perder a saída seria pior que perder o registro.
    evidenceId = null
  }

  return {
    blocked: false,
    blockReason: null,
    command,
    exitCode: res.status,
    stdout: outRedaction.text,
    stderr: errRedaction.text,
    redacted,
    evidenceId,
    durationMs,
    timedOut,
  }
}

/**
 * Mensagem de recusa para o terminal. Existe separada porque o tom importa:
 * "não executei" é diferente de "deu errado", e o operador precisa saber que
 * NADA saiu da máquina.
 */
export function formatBlockedMessage(result: GuardedRunResult): string {
  return [
    "⛔ Execução bloqueada pelo escopo — nada foi executado.",
    "",
    `  comando : ${result.command}`,
    `  motivo  : ${result.blockReason ?? "alvo fora do escopo autorizado"}`,
    "",
    "Se este alvo deveria estar autorizado, atualize o escopo do projeto",
    "antes de rodar. O bloqueio é intencional e não pode ser ignorado aqui.",
  ].join("\n")
}
