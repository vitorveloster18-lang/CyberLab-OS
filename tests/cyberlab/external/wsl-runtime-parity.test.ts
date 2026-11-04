import { describe, expect, test } from "bun:test"
import {
  BUILTIN_EXTERNAL_TOOL_CATALOG,
  describeLaunch,
  inspectExternalToolStatuses,
  resolvePosixCandidates,
  type ResolvedExternalBinary,
} from "../../../cyberlab/external/control-plane.js"
import {
  buildProcessLaunch,
  decodePotentialUtf16Le,
  probeWslEnvironment,
  resetWslRuntimeCaches,
  toWslArg,
  windowsPathToWslPath,
} from "../../../cyberlab/external/wsl-runtime.js"

function wslResolved(distro: string, linuxPath: string): ResolvedExternalBinary {
  return { resolvedPath: linuxPath, sourceLocation: "wsl_distro", wslDistro: distro, wslPath: linuxPath }
}

function windowsResolved(p: string): ResolvedExternalBinary {
  return { resolvedPath: p, sourceLocation: "system_path", wslDistro: null, wslPath: null }
}

describe("CyberLab v6.3 — Paridade de Runtime WSL2 (slot INSTALLED == capability READY)", () => {
  test("windowsPathToWslPath traduz drives Windows para /mnt/<drive>", () => {
    expect(windowsPathToWslPath("C:\\CyberLab\\ws\\wordlist.txt")).toBe("/mnt/c/CyberLab/ws/wordlist.txt")
    expect(windowsPathToWslPath("D:/artifacts/app.apk")).toBe("/mnt/d/artifacts/app.apk")
    // Caminho relativo/POSIX permanece inalterado
    expect(windowsPathToWslPath(".cyberlab/artifacts/jadx")).toBe(".cyberlab/artifacts/jadx")
  })

  test("toWslArg converte apenas caminhos Windows e preserva flags, URLs e números", () => {
    expect(toWslArg("C:\\ws\\list.txt")).toBe("/mnt/c/ws/list.txt")
    expect(toWslArg("output=C:\\ws\\out.json")).toBe("output=/mnt/c/ws/out.json")
    // Valores que NÃO são caminhos devem passar intactos (evita corromper comandos)
    expect(toWslArg("-jsonl")).toBe("-jsonl")
    expect(toWslArg("-rl")).toBe("-rl")
    expect(toWslArg("10")).toBe("10")
    expect(toWslArg("https://exemplo.alvo/api/v1")).toBe("https://exemplo.alvo/api/v1")
    expect(toWslArg("-tags")).toBe("-tags")
    expect(toWslArg("-u")).toBe("-u")
  })

  test("buildProcessLaunch encapsula em wsl.exe somente quando o binário vive na distro", () => {
    const win = buildProcessLaunch({
      binaryPath: "C:\\tools\\nuclei.exe",
      args: ["-u", "https://alvo.tld", "-rl", "10"],
      cwd: "C:\\ws",
      wsl: null,
    })
    expect(win.command).toBe("C:\\tools\\nuclei.exe")
    expect(win.args).toEqual(["-u", "https://alvo.tld", "-rl", "10"])
    expect(win.wsl).toBeNull()

    const wsl = buildProcessLaunch({
      binaryPath: "/usr/bin/nuclei",
      args: ["-u", "https://alvo.tld", "-o", "C:\\ws\\out.json"],
      cwd: "C:\\ws",
      wsl: { distro: "kali-linux", linuxBinary: "/usr/bin/nuclei" },
    })
    expect(wsl.command).toBe("wsl.exe")
    expect(wsl.args.slice(0, 5)).toEqual(["-d", "kali-linux", "-u", "root", "--"])
    expect(wsl.args[5]).toBe("/usr/bin/nuclei")
    // Caminho do workspace obrigatoriamente traduzido para /mnt/c
    expect(wsl.args).toContain("/mnt/c/ws/out.json")
    expect(wsl.wsl?.distro).toBe("kali-linux")
  })

  test("decodePotentialUtf16le suporta saída UTF-16LE do wsl.exe e UTF-8 puro", () => {
    const utf16 = Buffer.from("kali-linux\r\n", "utf16le")
    expect(decodePotentialUtf16Le(utf16).trim()).toBe("kali-linux")
    expect(decodePotentialUtf16Le(Buffer.from("Ubuntu-22.04\n", "utf8")).trim()).toBe("Ubuntu-22.04")
    expect(decodePotentialUtf16Le(Buffer.alloc(0))).toBe("")
  })

  test("catálogo: toda capability governada possui candidatos POSIX para o probe WSL2", () => {
    const governed = BUILTIN_EXTERNAL_TOOL_CATALOG.filter((e) => e.governedCapabilityId)
    expect(governed.length).toBeGreaterThanOrEqual(10)
    for (const entry of governed) {
      const posix = resolvePosixCandidates([...entry.binaryCandidates])
      expect(posix.length).toBeGreaterThan(0)
      // Nenhum candidato POSIX pode conter separador de caminho do Windows
      for (const p of posix) expect(p).not.toMatch(/\\|\.(exe|cmd|bat)$/)
    }
  })

  test("aliases POSIX cobrem os 7 binários que antes divergiam (nuclei/tshark/ghidra/jadx/yarax/dalfox/keyhunter)", () => {
    const cases: Array<[string[], string]> = [
      [["nuclei"], "nuclei"],
      [["tshark"], "tshark"],
      [["analyzeHeadless", "analyzeHeadless.bat", "ghidra-analyzeHeadless"], "analyzeHeadless"],
      [["jadx", "jadx.bat"], "jadx"],
      [["yr", "yara64", "yara"], "yr"],
      [["dalfox"], "dalfox"],
      [["keyhunter", "github-keyhunter"], "keyhunter"],
    ]
    for (const [candidates, expected] of cases) {
      expect(resolvePosixCandidates(candidates)).toContain(expected)
    }
    // YARA clássico também precisa ser tentado (Kali empacota 'yara')
    expect(resolvePosixCandidates(["yr", "yara64", "yara"])).toContain("yara")
  })

  test("describeLaunch reflete a origem real do binário (diagnóstico exibido ao agente)", () => {
    const wslLaunch = describeLaunch(wslResolved("kali-linux", "/usr/bin/jadx"), ["-d", "C:\\ws\\out"], "C:\\ws")
    expect(wslLaunch.command).toBe("wsl.exe")
    expect(wslLaunch.wsl?.linuxBinary).toBe("/usr/bin/jadx")

    const winLaunch = describeLaunch(windowsResolved("C:\\bin\\trivy.exe"), ["fs", "C:\\ws"], "C:\\ws")
    expect(winLaunch.command).toBe("C:\\bin\\trivy.exe")
    expect(winLaunch.wsl).toBeNull()
  })

  test("inspectExternalToolStatuses sempre expõe dica de instalação WSL2 e campos de distro", () => {
    resetWslRuntimeCaches()
    const statuses = inspectExternalToolStatuses(process.cwd())
    expect(statuses.length).toBe(BUILTIN_EXTERNAL_TOOL_CATALOG.length)
    for (const s of statuses) {
      expect(typeof s.installHintWsl).toBe("string")
      expect(s.installHintWsl.length).toBeGreaterThan(0)
      expect(s.wslDistro === null || typeof s.wslDistro === "string").toBe(true)
      // Invariante que motivou o v6.3: nunca reportar origem WSL sem distro
      if (s.sourceLocation === "wsl_distro") {
        expect(s.wslDistro).toBeTruthy()
        expect(s.wslPath).toBeTruthy()
        expect(s.available).toBe(true)
      }
    }
  })

  test("probeWslEnvironment degrada gracefully fora do Windows (CI Linux)", () => {
    resetWslRuntimeCaches()
    const env = probeWslEnvironment()
    if (process.platform !== "win32") {
      expect(env.available).toBe(false)
      expect(env.distros).toEqual([])
      expect(env.preferredDistro).toBeNull()
    } else {
      expect(Array.isArray(env.distros)).toBe(true)
    }
  })
})
