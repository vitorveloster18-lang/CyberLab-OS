import { describe, expect, it } from "bun:test"
import {
  PythonRuntimeUnavailableError,
  defaultCandidates,
  resolvePythonRuntime,
  type PythonCandidate,
  type PythonRuntimeInfo,
} from "../../cyberlab/python-runtime.js"

/**
 * Resolução do interpretador Python — o incidente que motivou este módulo:
 *
 * O runtime dos CDIs usa o 3.11, **onde os pacotes estão instalados**. Ao instalar o
 * 3.12, o `python3` passou a apontar para o interpretador novo e o runtime parou —
 * sem nenhum erro que explicasse a causa.
 *
 * A regra que estes testes protegem: **o CyberLab nunca troca de interpretador em
 * silêncio**. Se o operador fixou uma série e ela não está lá, isso é erro visível —
 * nunca um fallback discreto para a versão que por acaso apareceu.
 */

/** Ambiente falso: `python3` = 3.12 (novo, sem pacotes), `python` = 3.11 (runtime). */
const CANDIDATES: PythonCandidate[] = [
  { command: "python3", prefixArgs: [], source: "probe" },
  { command: "python", prefixArgs: [], source: "probe" },
]

const VERSIONS: Record<string, string> = {
  python3: "3.12.0",
  python: "3.11.9",
  "/opt/venv311/bin/python": "3.11.9",
}

function fakeProbe(candidate: PythonCandidate) {
  // Chaveia por "comando + args" para que `py -3.11` seja distinguível de `py`.
  const version = VERSIONS[[candidate.command, ...candidate.prefixArgs].join(" ")] ?? VERSIONS[candidate.command]
  if (!version) return null
  const [maj, min] = version.split(".")
  return { version, majorMinor: `${maj}.${min}` }
}

function resolve(env: NodeJS.ProcessEnv, extra: { requiredMajorMinor?: string } = {}): PythonRuntimeInfo {
  return resolvePythonRuntime({
    candidates: CANDIDATES,
    env,
    probeFn: fakeProbe,
    ...extra,
  })
}

describe("Runtime Python — seleção do interpretador (v6.7)", () => {
  it("sem nada declarado, usa o primeiro candidato que funciona", () => {
    const r = resolve({})
    expect(r.command).toBe("python3")
    expect(r.version).toBe("3.12.0")
    expect(r.source).toBe("probe")
  })

  it("REGRESSÃO: série fixada vence a ordem dos candidatos", () => {
    // É o caso real: `python3` é o 3.12 novo, mas o runtime precisa do 3.11.
    // Sem o pino, a detecção escolheria o 3.12 e o runtime quebraria.
    const r = resolve({ CYBERLAB_PYTHON_VERSION: "3.11" })
    expect(r.command).toBe("python")
    expect(r.majorMinor).toBe("3.11")
    expect(r.source).toBe("version-pin")
  })

  it("REGRESSÃO: série fixada ausente FALHA ALTO, sem fallback silencioso", () => {
    // O pior desfecho seria cair no 3.12 calado. Tem que dar erro dizendo o que achou.
    let thrown: unknown
    try {
      resolve({ CYBERLAB_PYTHON_VERSION: "3.10" })
    } catch (err) {
      thrown = err
    }
    expect(thrown).toBeInstanceOf(PythonRuntimeUnavailableError)
    const msg = (thrown as Error).message
    expect(msg).toContain("3.10")
    expect(msg).toContain("python3 (3.12.0)")
    expect(msg).toContain("python (3.11.9)")
    expect(msg).toContain("CYBERLAB_PYTHON")
  })

  it("CYBERLAB_PYTHON explícito tem prioridade sobre tudo", () => {
    const r = resolve({ CYBERLAB_PYTHON: "/opt/venv311/bin/python", CYBERLAB_PYTHON_VERSION: "3.11" })
    expect(r.command).toBe("/opt/venv311/bin/python")
    expect(r.source).toBe("env-override")
  })

  it("CYBERLAB_PYTHON quebrado falha alto — nunca ignora a intenção", () => {
    let thrown: unknown
    try {
      resolve({ CYBERLAB_PYTHON: "C:\\Python99\\python.exe" })
    } catch (err) {
      thrown = err
    }
    expect(thrown).toBeInstanceOf(PythonRuntimeUnavailableError)
    expect((thrown as Error).message).toContain("C:\\Python99\\python.exe")
    expect((thrown as Error).message).toContain("Corrija a variável")
  })

  it("a linha de invocação inclui os argumentos do launcher", () => {
    // No Windows o launcher é `py -3.11`: o comando sozinho não basta para invocar.
    const r = resolvePythonRuntime({
      candidates: [{ command: "py", prefixArgs: ["-3.11"], source: "version-pin" }],
      env: { CYBERLAB_PYTHON_VERSION: "3.11" },
      probeFn: (c) => (c.prefixArgs.includes("-3.11") ? { version: "3.11.9", majorMinor: "3.11" } : null),
    })
    expect(r.command).toBe("py")
    expect(r.prefixArgs).toEqual(["-3.11"])
  })

  it("nenhum interpretador funcional => erro acionável", () => {
    expect(() =>
      resolvePythonRuntime({ candidates: CANDIDATES, env: {}, probeFn: () => null }),
    ).toThrow(/Nenhum interpretador Python funcional/)
  })

  it("os candidatos padrão cobrem python3, python e o launcher do Windows", () => {
    const commands = defaultCandidates().map((c) => c.command)
    expect(commands).toContain("python3")
    expect(commands).toContain("python")
    expect(commands).toContain("py")
  })
})
