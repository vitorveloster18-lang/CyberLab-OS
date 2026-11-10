import { describe, expect, test } from "bun:test"
import {
  buildWslgLaunchArgs,
  probeWslg,
  type WslgInfo,
} from "../../../cyberlab/external/wsl-runtime.js"

/**
 * Sem WSLg, apps Linux do WSL2 só aparecem streamados por noVNC dentro da coluna
 * central — o que causou o Burp ser coberto pelo próprio navegador e a área de
 * transferência do Windows não chegar na sessão. Estes testes cobrem a montagem
 * do argv de janela nativa, que é pura e testável em qualquer SO.
 */
describe("CyberLab OS v6.7 — abertura em janela nativa via WSLg", () => {
  const wslg: WslgInfo = {
    available: true,
    reason: "WSLg ativo",
    display: ":0",
    xdgRuntimeDir: "/mnt/wslg/runtime-dir",
    pulseServer: "/mnt/wslg/PulseServer",
  }

  test("monta argv com distro, env, DISPLAY e o binário", () => {
    const args = buildWslgLaunchArgs({
      distro: "kali-linux",
      binary: "/usr/bin/burpsuite",
      args: ["--foo", "bar"],
      wslg,
    })

    expect(args[0]).toBe("-d")
    expect(args[1]).toBe("kali-linux")
    expect(args).toContain("--")
    expect(args).toContain("env")
    expect(args).toContain("DISPLAY=:0")
    expect(args).toContain("XDG_RUNTIME_DIR=/mnt/wslg/runtime-dir")
    expect(args).toContain("PULSE_SERVER=/mnt/wslg/PulseServer")

    // O binário vem DEPOIS do `env`, nunca antes.
    expect(args.indexOf("/usr/bin/burpsuite")).toBeGreaterThan(args.indexOf("env"))
    expect(args.slice(-2)).toEqual(["--foo", "bar"])
  })

  test("não força -u root: app gráfico como root briga com o dono do XDG_RUNTIME_DIR", () => {
    const args = buildWslgLaunchArgs({
      distro: "kali-linux",
      binary: "/usr/bin/wireshark",
      args: [],
      wslg,
    })
    expect(args).not.toContain("-u")
    expect(args).not.toContain("root")
  })

  test("omite as variáveis que não foram detectadas", () => {
    const bare: WslgInfo = {
      available: true,
      reason: "WSLg ativo",
      display: ":0",
      xdgRuntimeDir: null,
      pulseServer: null,
    }
    const args = buildWslgLaunchArgs({
      distro: "kali-linux",
      binary: "/usr/bin/xterm",
      args: [],
      wslg: bare,
    })

    expect(args).toContain("DISPLAY=:0")
    expect(args.join(" ")).not.toContain("XDG_RUNTIME_DIR")
    expect(args.join(" ")).not.toContain("PULSE_SERVER")
  })

  test("fora do Windows o WSLg é reportado como indisponível, com motivo acionável", () => {
    const info = probeWslg("kali-linux")
    // Em Linux/CI não existe WSLg; o importante é falar COM motivo, não só "false".
    expect(info.available).toBe(false)
    expect(info.reason.length).toBeGreaterThan(20)
  })
})
