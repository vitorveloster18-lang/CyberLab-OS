import { spawnSync } from "node:child_process"

/**
 * Ponte de runtime para uma VM Linux (VirtualBox/Hyper-V) rodando no próprio host.
 *
 * MOTIVAÇÃO: existe uma classe de ferramentas que o WSL2 **nunca** vai conseguir
 * executar, porque depende de hardware e rede que o WSL2 não expõe:
 *   - modo monitor / injeção de pacotes em Wi-Fi (fluxion, aircrack-ng em Wi-Fi)
 *   - dispositivos USB (MVT/ADB, Proxmark, HackRF, RTL-SDR)
 *   - bridge de LAN de verdade, para ARP spoofing/MITM na rede física (Responder)
 *   - captura crua na placa física do host (Wireshark promíscuo)
 *   - GPU para quebra de hashes (hashcat)
 *
 * A VM roda SEPARADA do CyberLab (ela tem boot, snapshot e ciclo de vida próprios);
 * o CyberLab apenas a DIRIGE, executando ferramentas sobre SSH e trazendo o stdout
 * de volta para o mesmo pipeline de evidência (redação -> SHA-256 -> custódia).
 *
 * Este módulo só depende de `node:child_process` para poder ser importado com
 * segurança por testes e pelo MCP stdio sem puxar Effect.
 */

export interface VmTarget {
  /** IP ou hostname — com adaptador host-only, algo estático como 192.168.56.10. */
  host: string
  user: string
  port?: number
  /** Chave privada. Sem ela o SSH pede senha e trava um processo não interativo. */
  identityFile?: string
  /** Rótulo só para mensagens (ex.: "Kali VM (VirtualBox)"). */
  label?: string
}

export interface VmProbeResult {
  reachable: boolean
  reason: string
  /** Distro reportada pela VM, quando o probe foi além do handshake. */
  distro: string | null
}

/** true quando há host e usuário suficientes para tentar uma conexão. */
export function isVmTargetConfigured(target: VmTarget | null | undefined): target is VmTarget {
  return Boolean(target && target.host.trim() && target.user.trim())
}

/**
 * Opções base do SSH. Cada uma existe por um motivo concreto:
 * - `BatchMode=yes`: sem isso o SSH para e PEDE SENHA, travando o processo do
 *   CyberLab para sempre (o CyberLab roda sem terminal).
 * - `ConnectTimeout`: VM desligada não deve segurar a interface.
 * - `StrictHostKeyChecking=accept-new`: aceita host novo (VM recém-criada) mas
 *   REJEITA host que mudou de chave, o que é o mínimo aceitável num lab local.
 */
export function buildSshBaseArgs(target: VmTarget): string[] {
  const args: string[] = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=8",
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "LogLevel=ERROR",
  ]
  if (target.port && target.port > 0) {
    args.push("-p", String(target.port))
  }
  if (target.identityFile && target.identityFile.trim()) {
    args.push("-i", target.identityFile.trim())
  }
  args.push(`${target.user}@${target.host}`)
  return args
}

/**
 * Monta o argv para EXECUTAR um binário dentro da VM.
 *
 * O `--` antes do binário é obrigatório: sem ele o SSH interpretaria flags da
 * ferramenta (ex.: `-u`) como opções do próprio SSH.
 */
export function buildVmLaunchArgs(params: {
  target: VmTarget
  binary: string
  args?: readonly string[]
}): string[] {
  return ["ssh", ...buildSshBaseArgs(params.target), "--", params.binary, ...(params.args ?? [])]
}

/**
 * Monta o argv para SONDAR a VM com um script enviado por stdin.
 * Mesma técnica do probe WSL: nada de interpolação de shell na linha de comando.
 */
export function buildVmProbeArgs(target: VmTarget): string[] {
  return ["ssh", ...buildSshBaseArgs(target), "--", "bash", "-s"]
}

/** Script de sondagem: reachability + identificação da distro. */
export const VM_PROBE_SCRIPT = [
  'echo "CYBERLAB_VM_OK=1"',
  'echo "HOSTNAME=$(hostname 2>/dev/null || echo desconhecido)"',
  'if [ -f /etc/os-release ]; then . /etc/os-release; echo "DISTRO=${PRETTY_NAME:-${ID:-desconhecida}}"; fi',
].join("\n")

/**
 * Interpreta a saída do probe. Separa "VM desligada" de "VM de pé mas sem chave"
 * porque as duas exigem ações completamente diferentes do operador.
 */
export function parseVmProbeOutput(raw: string, exitStatus: number | null): VmProbeResult {
  const read = (key: string): string | null => {
    const match = new RegExp(`^${key}=(.*)$`, "m").exec(raw || "")
    const value = match?.[1]?.trim()
    return value && value.length > 0 ? value : null
  }

  if (exitStatus === 0 && read("CYBERLAB_VM_OK") === "1") {
    return {
      reachable: true,
      reason: "VM acessível por SSH.",
      distro: read("DISTRO"),
    }
  }

  const output = (raw || "").toLowerCase()
  if (output.includes("permission denied") || output.includes("publickey")) {
    return {
      reachable: false,
      reason:
        "A VM respondeu mas recusou a autenticação. Copie sua chave pública para " +
        "~/.ssh/authorized_keys dentro da VM — sem isso o SSH fica travado pedindo senha.",
      distro: null,
    }
  }
  if (output.includes("timed out") || output.includes("timeout") || exitStatus === null) {
    return {
      reachable: false,
      reason:
        "A VM não respondeu no tempo limite: ela está desligada, ou o adaptador host-only " +
        "não está de pé, ou o IP mudou.",
      distro: null,
    }
  }

  return {
    reachable: false,
    reason: `Não foi possível alcançar a VM por SSH (exit ${exitStatus ?? "?"}). Verifique se ela está ligada e se o sshd está rodando.`,
    distro: null,
  }
}

let vmCache: { key: string; result: VmProbeResult; at: number } | null = null
const VM_TTL_MS = 60_000

export function resetVmRuntimeCaches(): void {
  vmCache = null
}

/** Sonda a VM (com cache curto — não é para travar a interface a cada clique). */
export function probeVmTarget(target: VmTarget | null | undefined, force = false): VmProbeResult {
  if (!isVmTargetConfigured(target)) {
    return {
      reachable: false,
      reason:
        "Nenhuma VM configurada. Defina `vmTarget` (host, user, identityFile) em " +
        "%USERPROFILE%\\.cyberlab\\arsenal-config.json.",
      distro: null,
    }
  }

  const key = `${target.user}@${target.host}:${target.port ?? 22}:${target.identityFile ?? ""}`
  if (!force && vmCache && vmCache.key === key && Date.now() - vmCache.at < VM_TTL_MS) {
    return vmCache.result
  }

  let result: VmProbeResult
  try {
    const res = spawnSync("ssh", buildVmProbeArgs(target).slice(1), {
      input: VM_PROBE_SCRIPT,
      encoding: "utf8",
      timeout: 15_000,
    })
    result = parseVmProbeOutput(res.stdout ?? "", res.status)
  } catch (err) {
    result = {
      reachable: false,
      reason: `Falha ao executar ssh: ${err instanceof Error ? err.message : String(err)}. O OpenSSH do Windows está instalado?`,
      distro: null,
    }
  }

  vmCache = { key, result, at: Date.now() }
  return result
}

/**
 * Acesso ao `vmTarget` persistido no arsenal-config.json, para processos que não
 * têm a instância do ArsenalSlotManager na mão (o MCP stdio roda separado e só
 * enxerga o cache de probe). Leitura tolerante: qualquer coisa fora do formato
 * devolve `null` em vez de estourar.
 */
export function readPersistedVmTarget(customPath?: string): VmTarget | null {
  const configPath =
    customPath ??
    (process.platform === "win32"
      ? `${process.env.USERPROFILE ?? ""}\\.cyberlab\\arsenal-config.json`
      : `${process.env.HOME ?? ""}/.cyberlab/arsenal-config.json`)
  if (!configPath) return null
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const fs = require("node:fs") as typeof import("node:fs")
    if (!fs.existsSync(configPath)) return null
    const parsed = JSON.parse(fs.readFileSync(configPath, "utf8")) as { vmTarget?: unknown }
    const t = parsed.vmTarget as VmTarget | undefined
    if (!t || typeof t !== "object") return null
    if (typeof t.host !== "string" || typeof t.user !== "string") return null
    return isVmTargetConfigured(t) ? t : null
  } catch {
    return null
  }
}
