import { afterEach, describe, expect, test } from "bun:test"
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import {
  buildManualBrowserLaunchCommands,
  buildProxyUnreachableGuidance,
  launchPreconfiguredProxyBrowser,
  probeTcpPort,
  resolveReachableProxyHost,
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

/**
 * O Chrome mostrava ERR_PROXY_CONNECTION_FAILED sem o CyberLab dizer nada: o
 * navegador era aberto apontando para uma porta em que ninguém escutava.
 */
describe("CyberLab OS v6.7 — alcançabilidade do proxy antes de abrir o navegador", () => {
  const servers: net.Server[] = []

  const listenOnEphemeralPort = async (): Promise<number> =>
    new Promise((resolve, reject) => {
      const server = net.createServer((socket) => socket.end())
      server.once("error", reject)
      server.listen(0, "127.0.0.1", () => {
        servers.push(server)
        const addr = server.address()
        resolve(typeof addr === "object" && addr ? addr.port : 0)
      })
    })

  afterEach(async () => {
    for (const server of servers.splice(0)) {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })

  test("probeTcpPort detecta porta aberta e porta fechada", async () => {
    const openPort = await listenOnEphemeralPort()
    expect(await probeTcpPort("127.0.0.1", openPort)).toBe(true)

    // Porta efêmera sem ninguém escutando: não deve lançar, só devolver false.
    const closedServer = net.createServer()
    await new Promise<void>((resolve) => closedServer.listen(0, "127.0.0.1", () => resolve()))
    const closedPort = (closedServer.address() as net.AddressInfo).port
    await new Promise<void>((resolve) => closedServer.close(() => resolve()))

    expect(await probeTcpPort("127.0.0.1", closedPort)).toBe(false)
  })

  test("resolveReachableProxyHost acha o proxy quando ele está de pé", async () => {
    const openPort = await listenOnEphemeralPort()
    const res = await resolveReachableProxyHost({ port: openPort })

    expect(res.reachable).toBe(true)
    expect(res.host).toBe("127.0.0.1")
    expect(res.triedHosts).toContain("127.0.0.1")
  })

  test("sem proxy de pé: reachable=false e lista os endereços tentados", async () => {
    // Porta alta e livre — nada vai responder.
    const res = await resolveReachableProxyHost({ port: 59999, timeoutMs: 250 })

    expect(res.reachable).toBe(false)
    expect(res.triedHosts.length).toBeGreaterThan(0)
    expect(res.triedHosts).toContain("127.0.0.1")
  })

  test("host preferido do operador é tentado primeiro", async () => {
    const res = await resolveReachableProxyHost({
      port: 59998,
      preferredHost: "10.0.0.7",
      timeoutMs: 250,
    })

    expect(res.triedHosts[0]).toBe("10.0.0.7")
    expect(res.reachable).toBe(false)
  })

  test("orientação cita a porta, o Burp parado, o WSL2 e a rede espelhada", () => {
    const guidance = buildProxyUnreachableGuidance(8080, ["127.0.0.1", "172.20.1.5"])

    expect(guidance).toContain("8080")
    expect(guidance).toContain("127.0.0.1")
    expect(guidance).toContain("172.20.1.5")
    expect(guidance).toContain("ERR_PROXY_CONNECTION_FAILED")
    // As três causas que realmente acontecem, na ordem de probabilidade.
    expect(guidance).toContain("Burp")
    expect(guidance).toContain("WSL2")
    expect(guidance).toContain("networkingMode=mirrored")
    expect(guidance).toContain("PortSwigger.BurpSuite.Community")
  })
})
