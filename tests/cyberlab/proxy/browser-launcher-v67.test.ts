import { afterEach, describe, expect, test } from "bun:test"
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
  buildManualBrowserLaunchCommands,
  launchPreconfiguredProxyBrowser,
} from "../../../cyberlab/proxy/browser-launcher.js"

/**
 * O botão 🌐 (Navegador Isolado no Proxy) dependia de uma lista FIXA de caminhos
 * que ignorava a instalação por usuário — o padrão do instalador do Chrome.
 * Estes testes cobrem o override do operador e o comando manual, que são as duas
 * saídas quando a detecção automática não acha nada.
 */
describe("CyberLab OS v6.7 — Navegador Isolado no Proxy (browser-launcher)", () => {
  const tempDirs: string[] = []
  const originalDisplay = process.env.DISPLAY

  const makeWorkspace = () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-browser-"))
    tempDirs.push(dir)
    return dir
  }

  /**
   * Em ambiente headless o launcher retorna antes de chegar na lógica de escolha
   * do navegador (e avisa para usar o comando manual). Para testar a seleção em
   * si, fingimos um Linux com sessão gráfica.
   */
  const withDisplay = () => {
    process.env.DISPLAY = ":0"
  }

  afterEach(() => {
    if (originalDisplay === undefined) delete process.env.DISPLAY
    else process.env.DISPLAY = originalDisplay
    for (const dir of tempDirs.splice(0)) {
      try {
        rmSync(dir, { recursive: true, force: true })
      } catch {
        // best effort
      }
    }
  })

  test("comando manual tenta %LOCALAPPDATA% antes de Program Files", () => {
    const { powershell } = buildManualBrowserLaunchCommands({
      proxyPort: 8080,
      startUrl: "http://example.test",
    })

    // A instalação por usuário é o padrão do site da Google; vinha sendo ignorada.
    expect(powershell).toContain("$env:LOCALAPPDATA\\Google\\Chrome\\Application\\chrome.exe")

    const localAppDataIdx = powershell.indexOf("$env:LOCALAPPDATA")
    const programFilesIdx = powershell.indexOf("$env:ProgramFiles\\Google")
    expect(localAppDataIdx).toBeGreaterThan(-1)
    expect(programFilesIdx).toBeGreaterThan(-1)
    expect(localAppDataIdx).toBeLessThan(programFilesIdx)

    // Continua apontando para o proxy e isolando o perfil.
    expect(powershell).toContain('--proxy-server="http://127.0.0.1:8080"')
    expect(powershell).toContain("--user-data-dir=")
    expect(powershell).toContain("http://example.test")
  })

  test("comando manual avisa o operador sobre browserExecutablePath quando nada é achado", () => {
    const { powershell } = buildManualBrowserLaunchCommands({
      proxyPort: 8080,
      startUrl: "about:blank",
    })
    expect(powershell).toContain("browserExecutablePath")
  })

  test("caminho fixado pelo operador tem prioridade e FALHA ALTO se não existir", () => {
    withDisplay()
    const workspaceRoot = makeWorkspace()
    const missing = path.join(workspaceRoot, "nao-existe", "chrome.exe")

    const res = launchPreconfiguredProxyBrowser({
      proxyPort: 8080,
      workspaceRoot,
      browserExecutablePath: missing,
    })

    expect(res.launched).toBe(false)
    // Não deve cair silenciosamente para a detecção automática.
    expect(res.executablePath).toBe(missing)
    expect(res.message).toContain(missing)
    expect(res.message).toContain("browserExecutablePath")
    expect(res.message).toContain("arsenal-config.json")
  })

  test("caminho fixado e existente é usado mesmo quando a detecção acharia outro", () => {
    withDisplay()
    const workspaceRoot = makeWorkspace()
    // Um "navegador" falso: um executável que só dorme. O launcher faz spawn
    // detached e dá unref, então isto não trava o teste.
    const fakeBrowser = path.join(workspaceRoot, "meu-chrome.exe")
    writeFileSync(fakeBrowser, "#!/bin/sh\nsleep 0.2\n", "utf8")
    try {
      chmodSync(fakeBrowser, 0o755)
    } catch {
      // some filesystems reject chmod; o teste ainda valida a seleção do caminho
    }

    const res = launchPreconfiguredProxyBrowser({
      proxyPort: 8080,
      workspaceRoot,
      startUrl: "http://alvo.test",
      browserExecutablePath: fakeBrowser,
    })

    // O importante não é o spawn em si (depende do SO), e sim que o caminho do
    // operador foi o escolhido, nunca o da detecção automática.
    expect(res.executablePath).toBe(fakeBrowser)
    expect(res.startUrl).toBe("http://alvo.test")
    expect(res.proxyUrl).toBe("http://127.0.0.1:8080")
    expect(res.profileDirectory).toContain("browser-profile-8080")
    // Se lançou, o nome vem do basename do caminho fixado.
    if (res.launched) expect(res.browserName).toBe("meu-chrome.exe")
  })

  test("sem navegador utilizável: mensagem acionável com comando manual", () => {
    withDisplay()
    const workspaceRoot = makeWorkspace()
    const res = launchPreconfiguredProxyBrowser({
      proxyPort: 8081,
      workspaceRoot,
      // Força o cenário "nada encontrado" sem depender do SO onde roda o teste.
      browserExecutablePath: path.join(workspaceRoot, "ausente.exe"),
    })

    expect(res.launched).toBe(false)
    expect(res.manualPowershellCommand).toContain('--proxy-server="http://127.0.0.1:8081"')
    expect(res.manualBashCommand).toContain('--proxy-server="http://127.0.0.1:8081"')
    expect(res.message.length).toBeGreaterThan(20)
  })
})
