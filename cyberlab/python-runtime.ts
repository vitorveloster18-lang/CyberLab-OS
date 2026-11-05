import { spawnSync } from "node:child_process"

/**
 * Resolução do interpretador Python usado pelo CyberLab OS.
 *
 * Por que este arquivo existe: o runtime dos CDIs roda num interpretador específico
 * (3.11) **onde os pacotes estão instalados**. Instalar um Python novo (3.12) fez o
 * runtime parar, porque `python3` passou a apontar para o interpretador sem pacotes.
 * Nada no código reclamou — simplesmente passou a usar o errado.
 *
 * Regra daqui para frente: **o CyberLab nunca escolhe o Python por adivinhação
 * silenciosa**. A seleção é, nesta ordem:
 *
 *   1. `CYBERLAB_PYTHON`          — ordem explícita do operador. Se não funcionar,
 *                                   FALHA ALTO: nunca ignore a intenção declarada.
 *   2. `CYBERLAB_PYTHON_VERSION`  — fixa a série (ex.: `3.11`). Se nenhum candidato
 *                                   tiver essa versão, FALHA ALTO listando os que
 *                                   existem — não cai silenciosamente para o 3.12.
 *   3. Sonda `python3` → `python` → `py` — apenas quando nada foi declarado.
 *
 * O ponto central é o caso 2: uma versão nova aparecendo não pode mudar sozinha qual
 * interpretador o sistema usa. Ou o operador declara, ou a ausência da versão
 * esperada é um erro visível.
 */

export interface PythonCandidate {
  /** Executável. */
  command: string
  /** Argumentos fixos que precedem o script (ex.: `py -3.11`). */
  prefixArgs: string[]
  /** Como este candidato foi escolhido. */
  source: "env-override" | "version-pin" | "probe"
}

export interface PythonRuntimeInfo extends PythonCandidate {
  /** Versão completa, ex.: `3.11.9`. */
  version: string
  /** Série, ex.: `3.11`. */
  majorMinor: string
}

interface ProbeResult {
  version: string
  majorMinor: string
}

const PROBE_SCRIPT = "import sys;print('%d.%d.%d' % sys.version_info[:3])"

function run(command: string, args: string[]): ProbeResult | null {
  try {
    const res = spawnSync(command, args, {
      encoding: "utf8",
      timeout: 20_000,
      windowsHide: true,
    })
    if (res.error || res.status !== 0) return null
    const out = (res.stdout ?? "").trim().split(/\r?\n/).pop() ?? ""
    const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(out)
    if (!m) return null
    const majorMinor = `${m[1]}.${m[2]}`
    return { version: out, majorMinor }
  } catch {
    return null
  }
}

function probe(candidate: PythonCandidate, probeFn?: (c: PythonCandidate) => ProbeResult | null): PythonRuntimeInfo | null {
  const r = probeFn ? probeFn(candidate) : run(candidate.command, [...candidate.prefixArgs, "-c", PROBE_SCRIPT])
  return r ? { ...candidate, ...r } : null
}

/**
 * Candidatos nativos, em ordem de preferência quando nada foi declarado.
 * `python3` vem primeiro por ser o shebang do `chat_py_bridge.py`; `py` entra como
 * última opção por ser o launcher do Windows.
 */
export function defaultCandidates(): PythonCandidate[] {
  return [
    { command: "python3", prefixArgs: [], source: "probe" },
    { command: "python", prefixArgs: [], source: "probe" },
    { command: "py", prefixArgs: ["-3"], source: "probe" },
  ]
}

/** Candidatos extras que miram uma série específica (Windows Python Launcher). */
function versionPinnedCandidates(majorMinor: string): PythonCandidate[] {
  return [
    { command: `python${majorMinor}`, prefixArgs: [], source: "version-pin" },
    { command: "py", prefixArgs: [`-${majorMinor}`], source: "version-pin" },
  ]
}

export interface ResolveOptions {
  /** Sobrepõe a lista de candidatos (usado nos testes). */
  candidates?: PythonCandidate[]
  /** Força a série (sobrepõe `CYBERLAB_PYTHON_VERSION`). */
  requiredMajorMinor?: string
  /** Lê as variáveis de ambiente no momento da chamada (testes). */
  env?: NodeJS.ProcessEnv
  /** Substitui a sonda real (testes): evita depender do PATH da máquina. */
  probeFn?: (candidate: PythonCandidate) => ProbeResult | null
}

export class PythonRuntimeUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "PythonRuntimeUnavailableError"
  }
}

function describe(found: Array<{ command: string; prefixArgs: string[]; version: string }>): string {
  if (found.length === 0) return "nenhum interpretador Python encontrado no PATH"
  return found.map((f) => `${[f.command, ...f.prefixArgs].join(" ")} (${f.version})`).join(", ")
}

/**
 * Resolve o interpretador Python a usar.
 * Lança `PythonRuntimeUnavailableError` com mensagem acionável quando a intenção
 * declarada não pode ser satisfeita — nunca escolhe outra versão em silêncio.
 */
export function resolvePythonRuntime(options: ResolveOptions = {}): PythonRuntimeInfo {
  const env = options.env ?? process.env

  // 1. Ordem explícita do operador.
  const explicit = env.CYBERLAB_PYTHON?.trim()
  if (explicit) {
    const found = probe({ command: explicit, prefixArgs: [], source: "env-override" }, options.probeFn)
    if (found) return found
    throw new PythonRuntimeUnavailableError(
      `CYBERLAB_PYTHON aponta para "${explicit}", que não executa. ` +
        `Corrija a variável ou remova-a para voltar à detecção automática. ` +
        `Encontrado no PATH: ${describe(probeAll(options.candidates ?? defaultCandidates(), options.probeFn))}.`,
    )
  }

  // 2. Série fixada pelo operador.
  const pinned = (options.requiredMajorMinor ?? env.CYBERLAB_PYTHON_VERSION ?? "").trim()
  if (pinned) {
    for (const candidate of versionPinnedCandidates(pinned)) {
      const found = probe(candidate, options.probeFn)
      if (found && found.majorMinor === pinned) return found
    }
    // Também aceita a série entre os candidatos padrão, mas SÓ se bater a versão.
    for (const candidate of options.candidates ?? defaultCandidates()) {
      const found = probe(candidate, options.probeFn)
      if (found && found.majorMinor === pinned) return { ...found, source: "version-pin" }
    }
    throw new PythonRuntimeUnavailableError(
      `CYBERLAB_PYTHON_VERSION=${pinned}, mas nenhum interpretador dessa série foi encontrado. ` +
        `Encontrado no PATH: ${describe(probeAll(options.candidates ?? defaultCandidates(), options.probeFn))}. ` +
        `Aponte o interpretador correto com CYBERLAB_PYTHON (ex.: CYBERLAB_PYTHON=C:\\Python311\\python.exe).`,
    )
  }

  // 3. Detecção automática — só quando o operador não declarou nada.
  for (const candidate of options.candidates ?? defaultCandidates()) {
    const found = probe(candidate, options.probeFn)
    if (found) return found
  }

  throw new PythonRuntimeUnavailableError(
    `Nenhum interpretador Python funcional no PATH. Instale o Python ou defina CYBERLAB_PYTHON.`,
  )
}

function probeAll(
  candidates: PythonCandidate[],
  probeFn?: (c: PythonCandidate) => ProbeResult | null,
): Array<{ command: string; prefixArgs: string[]; version: string }> {
  const out: Array<{ command: string; prefixArgs: string[]; version: string }> = []
  for (const c of candidates) {
    const found = probe(c, probeFn)
    if (found) out.push({ command: c.command, prefixArgs: c.prefixArgs, version: found.version })
  }
  return out
}

/**
 * Cache por processo: a resolução executa subprocessos e não muda durante a execução.
 * `undefined` = ainda não calculado; `null` = calculado e indisponível.
 */
let cached: PythonRuntimeInfo | null | undefined = undefined

/** Mesma resolução, memoizada por processo. Devolve `null` se não houver Python. */
export function pythonRuntime(): PythonRuntimeInfo | null {
  if (cached === undefined) {
    try {
      cached = resolvePythonRuntime()
    } catch {
      cached = null
    }
  }
  return cached
}

/** Limpa o cache (testes). */
export function resetPythonRuntimeCache(): void {
  cached = undefined
}

/**
 * Interpretador usado DENTRO do WSL2 (Kali), onde o arsenal roda scanners Python.
 *
 * Mesma lógica do caso nativo: o padrão é o `python3` do distro, mas
 * `CYBERLAB_WSL_PYTHON` permite fixar. Uma atualização do distro não deve trocar
 * sozinha qual interpretador as ferramentas do arsenal usam.
 */
export function wslPythonCommand(env: NodeJS.ProcessEnv = process.env): string {
  return env.CYBERLAB_WSL_PYTHON?.trim() || "python3"
}
