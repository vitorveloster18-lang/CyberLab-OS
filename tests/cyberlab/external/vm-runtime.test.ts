import { describe, expect, it } from "bun:test"
import {
  buildSshBaseArgs,
  buildVmLaunchArgs,
  isVmTargetConfigured,
  parseVmProbeOutput,
  probeVmTarget,
  resetVmRuntimeCaches,
  type VmTarget,
} from "../../../cyberlab/external/vm-runtime.js"

const target: VmTarget = {
  host: "192.168.56.10",
  user: "kali",
  identityFile: "C:\\Users\\vitor\\.ssh\\cyberlab_vm",
}

describe("vm-runtime: configuração", () => {
  it("exige host e usuário antes de tentar qualquer conexão", () => {
    expect(isVmTargetConfigured(target)).toBe(true)
    expect(isVmTargetConfigured({ host: "192.168.56.10", user: "  " })).toBe(false)
    expect(isVmTargetConfigured({ host: "", user: "kali" })).toBe(false)
    expect(isVmTargetConfigured(null)).toBe(false)
    expect(isVmTargetConfigured(undefined)).toBe(false)
  })
})

describe("vm-runtime: argv do SSH", () => {
  it("monta as opções que impedem o processo de travar pedindo senha", () => {
    const args = buildSshBaseArgs(target)
    // BatchMode é o que garante que um processo sem terminal não fique esperando
    // input eterno quando a chave não foi instalada na VM.
    expect(args).toContain("BatchMode=yes")
    expect(args).toContain("ConnectTimeout=8")
    expect(args[args.length - 1]).toBe("kali@192.168.56.10")
    expect(args).toContain("C:\\Users\\vitor\\.ssh\\cyberlab_vm")
  })

  it("usa accept-new: aceita VM nova, mas rejeita chave de host que mudou", () => {
    // accept-new e não "no": o segundo silenciosamente aceitaria MITM, e o
    // "yes" estrito travaria numa VM recém-criada.
    expect(buildSshBaseArgs(target)).toContain("StrictHostKeyChecking=accept-new")
  })

  it("omite -p e -i quando não foram configurados", () => {
    const args = buildSshBaseArgs({ host: "10.0.0.5", user: "root" })
    expect(args).not.toContain("-p")
    expect(args).not.toContain("-i")
    expect(args[args.length - 1]).toBe("root@10.0.0.5")
  })

  it("honra a porta quando informada", () => {
    expect(buildSshBaseArgs({ ...target, port: 2222 })).toContain("2222")
  })
})

describe("vm-runtime: argv de execução", () => {
  it("separa o binário do ssh com -- , para que flags da ferramenta não virem flags do ssh", () => {
    const argv = buildVmLaunchArgs({ target, binary: "airmon-ng", args: ["start", "wlan0"] })
    expect(argv[0]).toBe("ssh")
    const sep = argv.indexOf("--")
    expect(sep).toBeGreaterThan(0)
    expect(argv.slice(sep + 1)).toEqual(["airmon-ng", "start", "wlan0"])
  })

  it("funciona sem argumentos", () => {
    const argv = buildVmLaunchArgs({ target, binary: "uname" })
    expect(argv.slice(argv.indexOf("--") + 1)).toEqual(["uname"])
  })
})

describe("vm-runtime: interpretação do probe", () => {
  it("reconhece VM de pé e extrai a distro", () => {
    const r = parseVmProbeOutput(
      'CYBERLAB_VM_OK=1\nHOSTNAME=kali\nDISTRO=Kali GNU/Linux 2025.3\n',
      0,
    )
    expect(r.reachable).toBe(true)
    expect(r.distro).toBe("Kali GNU/Linux 2025.3")
  })

  it("distingue 'recusou a chave' de 'VM desligada' — as correções são diferentes", () => {
    const denied = parseVmProbeOutput("kali@192.168.56.10: Permission denied (publickey).", 255)
    expect(denied.reachable).toBe(false)
    expect(denied.reason).toContain("authorized_keys")

    const down = parseVmProbeOutput("", null)
    expect(down.reachable).toBe(false)
    expect(down.reason).toContain("não respondeu")
  })

  it("não reporta sucesso quando o exit é 0 mas o marcador não veio", () => {
    const r = parseVmProbeOutput("alguma outra coisa", 0)
    expect(r.reachable).toBe(false)
  })
})

describe("vm-runtime: probe sem configuração", () => {
  it("devolve motivo acionável em vez de estourar", () => {
    resetVmRuntimeCaches()
    const r = probeVmTarget(null)
    expect(r.reachable).toBe(false)
    expect(r.reason).toContain("vmTarget")
  })
})

describe("vm-runtime: reflexo na saúde dos slots", () => {
  const { computeArsenalSlotHealth } = require("../../../cyberlab/arsenal/slot-manager.js") as {
    computeArsenalSlotHealth: (
      slots: unknown[],
      overrides?: Record<string, unknown>,
      vmProbe?: { reachable: boolean; reason: string; distro: string | null },
    ) => { slotId: string; kind: string }[]
  }
  const { OFFICIAL_ARSENAL_SLOTS } = require("../../../cyberlab/arsenal/catalog.js") as {
    OFFICIAL_ARSENAL_SLOTS: { slotId: string; requiresRealKernel?: boolean }[]
  }

  const kernelSlots = OFFICIAL_ARSENAL_SLOTS.filter((d) => d.requiresRealKernel)
  const fakeStatus = (slotId: string) => ({ slotId, name: slotId, isCustom: false })

  it("o catálogo marca os slots que o WSL2 estruturalmente não entrega", () => {
    // Se isto cair para zero, a classificação foi apagada sem querer.
    expect(kernelSlots.length).toBeGreaterThan(0)
    expect(kernelSlots.map((d) => d.slotId)).toContain("wireshark")
  })

  it("avisa quando o slot exige kernel real e não há VM de pé", () => {
    const issues = computeArsenalSlotHealth(
      kernelSlots.map((d) => fakeStatus(d.slotId)),
      {},
      { reachable: false, reason: "Nenhuma VM configurada.", distro: null },
    )
    expect(issues.map((i) => i.kind)).toEqual(kernelSlots.map(() => "requires_real_kernel"))
  })

  it("fica em silêncio quando a VM responde — o slot passa a ser legítimo", () => {
    const issues = computeArsenalSlotHealth(
      kernelSlots.map((d) => fakeStatus(d.slotId)),
      {},
      { reachable: true, reason: "", distro: "Kali GNU/Linux" },
    )
    expect(issues).toEqual([])
  })

  it("não inventa aviso quando o chamador não sondou a VM", () => {
    // Evita que qualquer tela que chame a função sem probe dispare SSH de 8s.
    expect(computeArsenalSlotHealth(kernelSlots.map((d) => fakeStatus(d.slotId)))).toEqual([])
  })
})
