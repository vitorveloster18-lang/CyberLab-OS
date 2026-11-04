import { spawnSync } from "node:child_process"
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"

/**
 * Gates de ambiente para a suíte CyberLab.
 *
 * A suíte roda em Linux (CI `verify`), Windows (CI `verify-windows`) e na máquina do
 * operador — que pode não ter Python, não ter permissão de symlink (Windows sem
 * Developer Mode) ou não conseguir executar um script com shebang bash.
 *
 * A regra aqui NÃO é "fazer o teste passar": é **distinguir "o código está errado" de
 * "a máquina não tem o pré-requisito"**. Quando falta pré-requisito, o teste é PULADO
 * com o motivo explícito — nunca aprovado silenciosamente, nunca falho por ambiente.
 *
 * Em Linux/macOS nada é pulado: a cobertura integral continua na CI `verify`.
 */

const memo = new Map<string, unknown>()

function memoized<T>(key: string, compute: () => T): T {
  if (!memo.has(key)) memo.set(key, compute())
  return memo.get(key) as T
}

/** Dorme sem dependência de globals do Bun (funciona em qualquer runtime). */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

/**
 * Interpretador Python utilizável (`python3` ou `python`), ou `null`.
 *
 * Por que não fixar `python3`: no Windows o instalador oficial registra `python`;
 * `python3` só existe se o "Python Launcher" estiver instalado. E quando o Windows
 * não tem Python nenhum, o atalho da Microsoft Store devolve status 49 e imprime uma
 * mensagem — é exatamente isso que fazia 4 testes estourarem o timeout de 5 s.
 */
export function pythonCommand(): string | null {
  return memoized("pythonCommand", () => {
    for (const candidate of ["python3", "python"]) {
      try {
        const res = spawnSync(candidate, ["-c", "print(1)"], {
          stdio: "ignore",
          timeout: 15_000,
          windowsHide: true,
        })
        if (!res.error && res.status === 0) return candidate
      } catch {
        // Candidato inexistente: tenta o próximo.
      }
    }
    return null
  })
}

export function hasPython(): boolean {
  return pythonCommand() !== null
}

export const PYTHON_MISSING_REASON = "Python nao encontrado no PATH (instale com: winget install Python.Python.3.12)"

// ---------------------------------------------------------------------------
// Symlink
// ---------------------------------------------------------------------------

/**
 * `true` se o processo consegue criar symlink agora.
 *
 * No Windows isso exige Developer Mode ou privilégio de administrador; sem eles,
 * `symlinkSync` lança EPERM. O teste de rejeição de symlink na inbox mede uma
 * proteção real do produto — mas só pode ser exercitado onde a máquina permite
 * criar o symlink que ele tenta rejeitar.
 */
export function canCreateSymlink(): boolean {
  return memoized("canCreateSymlink", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-symlink-probe-"))
    const target = path.join(dir, "target.txt")
    const link = path.join(dir, "link.txt")
    try {
      writeFileSync(target, "probe")
      symlinkSync(target, link)
      return true
    } catch {
      return false
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
}

export const SYMLINK_DENIED_REASON =
  "SO nao permite criar symlink (no Windows: ative o Developer Mode ou rode como administrador)"

// ---------------------------------------------------------------------------
// Execução de binário externo falso
// ---------------------------------------------------------------------------

export interface FakeExecutable {
  /** Arquivo efetivamente criado. */
  path: string
  /** Caminho que a descoberta do control-plane deve devolver para este binário. */
  resolvedPath: string
}

/**
 * `true` quando a plataforma consegue executar um binário falso gerado pelo teste.
 *
 * O produto já é multiplataforma aqui (`expandPlatformNames` procura `.exe`, `.cmd` e
 * `.bat` no Windows), então o teste também deve ser: em Windows escrevemos um `.cmd`.
 */
export function canExecuteShellScriptBinary(): boolean {
  return true
}

/**
 * Escreve um "binário" executável falso em `binDir`, na forma que cada plataforma
 * aceita:
 *   - POSIX  -> `<binDir>/<name>` com shebang `bash` e modo 0755
 *   - Windows -> `<binDir>/<name>.cmd` (batch), que `expandPlatformNames` localiza
 *
 * `stdoutLines` é emitido na saída padrão; `$ARGS` é substituído pelos argumentos
 * recebidos (`$@` no bash, `%*` no batch).
 */
export function writeFakeExecutable(binDir: string, name: string, stdoutLines: string[]): FakeExecutable {
  if (process.platform === "win32") {
    const file = path.join(binDir, `${name}.cmd`)
    const body = ["@echo off", ...stdoutLines.map((l) => `echo ${l.replace(/\$ARGS/g, "%*")}`), ""].join("\r\n")
    writeFileSync(file, body, "utf8")
    return { path: file, resolvedPath: file }
  }
  const file = path.join(binDir, name)
  const body = ["#!/usr/bin/env bash", ...stdoutLines.map((l) => `echo "${l.replace(/\$ARGS/g, '$@')}"`), ""].join("\n")
  writeFileSync(file, body, "utf8")
  chmodSync(file, 0o755)
  return { path: file, resolvedPath: file }
}

/**
 * Escreve um "binário" falso que só dorme por `seconds` — usado pelo teste de
 * kill/cancel, que precisa de um processo longo em execução para poder matá-lo.
 */
export function writeFakeSleepBinary(binDir: string, name: string, seconds: number): FakeExecutable {
  if (process.platform === "win32") {
    const file = path.join(binDir, `${name}.cmd`)
    writeFileSync(file, `@echo off\r\ntimeout /t ${seconds} /nobreak >nul\r\n`, "utf8")
    return { path: file, resolvedPath: file }
  }
  const file = path.join(binDir, name)
  writeFileSync(file, `#!/usr/bin/env bash\nsleep ${seconds}\n`, "utf8")
  chmodSync(file, 0o755)
  return { path: file, resolvedPath: file }
}

// ---------------------------------------------------------------------------
// Remoção resiliente (Windows mantém handles abertos)
// ---------------------------------------------------------------------------

/**
 * `rmSync` que tolera EBUSY/EPERM do Windows.
 *
 * No Windows o antivírus e o indexador seguram handles por alguns milissegundos
 * depois que o teste termina, e um `rmSync` no `finally` estoura com EBUSY —
 * transformando um teste que PASSOU em falha. Tenta algumas vezes e, se não
 * conseguir, desiste em silêncio: lixo em `%TEMP%` não é falha de produto.
 */
export function rmWithRetry(target: string, attempts = 8, baseDelayMs = 50): void {
  for (let i = 0; i < attempts; i++) {
    try {
      rmSync(target, { recursive: true, force: true })
      return
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | null)?.code
      if (code !== "EBUSY" && code !== "EPERM" && code !== "ENOTEMPTY" && code !== "EACCES") throw err
      if (i === attempts - 1) return
      sleepSync(baseDelayMs * (i + 1))
    }
  }
}
