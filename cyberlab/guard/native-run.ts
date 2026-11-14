import { spawnSync } from "node:child_process"
import { randomUUID } from "node:crypto"

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
export function extractTargetsFromArgv(argv: readonly string[]): ExtractedTargets {
  const found = new Set<string>()

  const ipv4Source = "(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)"
  const ipv4Re = new RegExp(`^${ipv4Source}$`)
  const cidrRe = new RegExp(`^(${ipv4Source})/(\\d{1,2})$`)
  const hostPortRe = new RegExp(`^(${ipv4Source}):(\\d{1,5})$`)
  const urlRe = /^[a-z][a-z0-9+.-]*:\/\//i
  const domainRe = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i
  const FILE_LIKE_RE =
    /\.(txt|json|ya?ml|xml|csv|md|log|conf|cfg|ini|sh|bash|py|js|mjs|cjs|ts|tsx|jsx|exe|dll|bin|tar|tgz|gz|bz2|xz|zip|7z|rar|pdf|png|jpe?g|gif|svg|html?|css|bak|old|tmp|lock|toml|sql|db|sqlite|key|pem|crt|cer|der|p12|pfx|pcap|cap|lst|list|wordlist|gz|iso|img|ova|vdi|qcow2|deb|rpm|apk|jar|war|so|o|a|class|go|rs|c|h|cpp|hpp|rb|pl|php|lua|swift|kt|java|scala|clj|ex|exs|erl|beam)$/i

  for (const raw of argv) {
    if (typeof raw !== "string" || raw.length === 0) continue
    // Flag de ferramenta nunca é alvo.
    if (raw.startsWith("-")) continue

    let candidate = raw

    // URL: pega só o host, descartando caminho, query e porta.
    if (urlRe.test(candidate)) {
      const withoutScheme = candidate.replace(urlRe, "")
      candidate = withoutScheme.split(/[/?#]/)[0] ?? ""
      // Remove credenciais embutidas (http://user:pass@host).
      const at = candidate.lastIndexOf("@")
      if (at >= 0) candidate = candidate.slice(at + 1)
      // Remove porta.
      const colon = candidate.indexOf(":")
      if (colon > 0) candidate = candidate.slice(0, colon)
    }

    if (candidate.length === 0) continue

    if (ipv4Re.test(candidate) || cidrRe.test(candidate) || hostPortRe.test(candidate)) {
      // host:porta → guarda o IP puro, que é o que o escopo compara.
      const asHostPort = hostPortRe.exec(candidate)
      found.add(asHostPort ? asHostPort[1]! : candidate)
      continue
    }

    // Extensões de arquivo que parecem TLD. Sem isto, `wordlist.txt` viraria
    // alvo de rede e o comando seria bloqueado por engano.
    if (FILE_LIKE_RE.test(candidate)) continue

    if (domainRe.test(candidate)) {
      found.add(candidate)
    }
  }

  return { networkTargets: [...found], workspacePaths: [] }
}

function formatCommand(argv: readonly string[]): string {
  return argv
    .map((part) => (/\s/.test(part) ? JSON.stringify(part) : part))
    .join(" ")
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
  const verdict = scope.verifyTargets(projectId, targets)
  if (!verdict.allowed) {
    return {
      blocked: true,
      blockReason: verdict.reason ?? "Alvo fora do escopo autorizado.",
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
