import { describe, expect, test } from "bun:test"
import path from "node:path"
import {
  escapeCmdArgument,
  escapeCmdCommand,
  resolveSpawnTarget,
} from "../../../cyberlab/external/control-plane.js"

/**
 * Regressão: no Windows o produto achava o binário e não conseguia executá-lo.
 *
 * `expandPlatformNames` procura `.exe`, `.cmd` e `.bat`. Só que `spawn` com
 * `shell: false` **rejeita** `.cmd`/`.bat` com EINVAL — aceita apenas `.com`/`.exe`.
 * Resultado: o control-plane localizava o binário externo e a execução falhava com
 * "status: failed", sem nenhum erro que apontasse para a causa.
 *
 * O sintoma só apareceu quando `external/` entrou no job `verify-windows` — antes
 * disso essa pasta nunca rodava em Windows e o bug ficou invisível.
 */

describe("Execução de binário externo multiplataforma (regressão: .cmd dava EINVAL no Windows)", () => {
  test("em POSIX o comando vai direto, sem shell", () => {
    const t = resolveSpawnTarget("/usr/bin/nmap", ["-sV", "127.0.0.1"], "linux")
    expect(t.file).toBe("/usr/bin/nmap")
    expect(t.args).toEqual(["-sV", "127.0.0.1"])
    expect(t.windowsVerbatimArguments).toBe(false)
  })

  test("no Windows um .exe vai direto (não precisa de shell)", () => {
    const t = resolveSpawnTarget("C:\\tools\\nmap.exe", ["-sV"], "win32")
    expect(t.file).toBe(path.normalize("C:\\tools\\nmap.exe"))
    expect(t.args).toEqual(["-sV"])
    expect(t.windowsVerbatimArguments).toBe(false)
  })

  test("REGRESSÃO: no Windows um .cmd passa por cmd.exe /d /s /c", () => {
    const t = resolveSpawnTarget("C:\\tools\\mvt-android.cmd", ["backup.ab"], "win32")
    expect(t.file).toBe(process.env.comspec ?? "cmd.exe")
    expect(t.args.slice(0, 3)).toEqual(["/d", "/s", "/c"])
    expect(t.args[3]).toContain("mvt-android.cmd")
    expect(t.args[3]).toContain("backup.ab")
    // Sem isso o Node reescapa e a linha de comando chega corrompida ao cmd.
    expect(t.windowsVerbatimArguments).toBe(true)
  })

  test(".bat recebe o mesmo tratamento do .cmd", () => {
    const t = resolveSpawnTarget("C:\\tools\\scan.bat", [], "win32")
    expect(t.file).toBe(process.env.comspec ?? "cmd.exe")
    expect(t.windowsVerbatimArguments).toBe(true)
  })

  test("caminho com espaço é escapado — senão o cmd parte o caminho no meio", () => {
    const t = resolveSpawnTarget("C:\\Program Files\\Tool\\tool.cmd", [], "win32")
    const line = t.args[3] ?? ""
    expect(line).toContain("Program^ Files")
    expect(line).not.toContain("Program Files")
  })

  test("metacaracteres do cmd no argumento são escapados", () => {
    // `a&b` sem escape faria o cmd tratar `b` como um segundo comando.
    const line = resolveSpawnTarget("tool.cmd", ["a&b", "x|y", "p>q"], "win32").args[3] ?? ""
    expect(line).toContain("a^&b")
    expect(line).toContain("x^|y")
    expect(line).toContain("p^>q")
  })

  test("o escaping é o algoritmo canônico (qntm/cross-spawn), não uma invenção", () => {
    expect(escapeCmdArgument("a b")).toBe('^"a^ b^"')
    expect(escapeCmdArgument("a&b")).toBe('^"a^&b^"')
    expect(escapeCmdArgument("backup.ab")).toBe('^"backup.ab^"')
    expect(escapeCmdArgument("")).toBe('^"^"')
    // Barras antes de aspas são dobradas: é o que impede o escape de vazar.
    expect(escapeCmdArgument('q"q')).toBe('^"q\\^"q^"')
    expect(escapeCmdCommand("C:\\a b\\tool.cmd")).toBe("C:\\a^ b\\tool.cmd")
  })
})
