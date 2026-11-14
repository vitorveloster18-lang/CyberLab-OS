import { Effect } from "effect"
import { EOL } from "node:os"
import { formatBlockedMessage, runGuardedNative } from "@cyberlab/core/guard/native-run"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace, resolveLocalCyberLabProjectId } from "./_workspace"

const DEFAULT_TIMEOUT_SEC = 1800

function parseTimeoutSec(raw: string | undefined): number {
  if (!raw) return DEFAULT_TIMEOUT_SEC
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`--timeout inválido: "${raw}". Informe um número de segundos maior que zero.`)
  }
  return parsed
}

/**
 * `cyberlab exec -- <comando>` — executa NATIVO, sob governança.
 *
 * Este é o coração do CyberLab rodando dentro do Kali: não há ponte, tradução
 * de caminho nem empacotamento de ferramenta. O binário é spawnado direto, e o
 * CyberLab faz só o que não dá para obter rodando o comando cru — checa escopo
 * antes, redige a saída e registra a evidência.
 */
export default Runtime.handler(
  Commands.commands.cyberlab.commands.exec,
  Effect.fn("cli.cyberlab.exec")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.exec>,
  ) {
    const argv = input.command ?? []
    if (argv.length === 0) {
      process.stdout.write(
        [
          "Uso: cyberlab exec -- <comando> [argumentos...]",
          "",
          "  Ex.: cyberlab exec -- nmap -sV 10.0.0.5",
          "       cyberlab exec -- ffuf -u https://alvo.exemplo/FUZZ -w /usr/share/wordlists/...",
          "",
          "O comando roda nativo. O CyberLab checa o escopo antes, redige a saída",
          "e grava a evidência com SHA-256.",
        ].join(EOL) + EOL,
      )
      process.exitCode = 1
      return
    }

    const timeoutSec = parseTimeoutSec(
      input.timeout && typeof input.timeout === "string" ? input.timeout : undefined,
    )

    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())

    const result = runGuardedNative({
      projectId: resolveLocalCyberLabProjectId(),
      argv,
      scope: ws.scopes,
      store: ws.evidenceStore,
      actor: "cli-operator",
      executorId: `local:${process.platform}`,
      timeoutMs: timeoutSec * 1000,
    })

    if (input.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + EOL)
      if (result.blocked || result.exitCode !== 0) process.exitCode = 1
      return
    }

    if (result.blocked) {
      process.stdout.write(formatBlockedMessage(result) + EOL)
      process.exitCode = 1
      return
    }

    // A saída vai direto para o stdout do terminal, sem prefixo nem
    // reembrulho: o operador precisa poder redirecionar e pipe-ar.
    if (result.stdout.length > 0) process.stdout.write(result.stdout)
    if (result.stderr.length > 0) process.stderr.write(result.stderr)

    const duration = (result.durationMs / 1000).toFixed(1)
    const footer: string[] = [
      "",
      `— cyberlab exec · exit=${result.exitCode} · ${duration}s` +
        (result.redacted ? " · saída redigida" : "") +
        (result.timedOut ? " · TIMEOUT" : ""),
    ]
    footer.push(
      result.evidenceId
        ? `  evidência: ${result.evidenceId}`
        : "  evidência: NÃO registrada (verifique o workspace)",
    )
    process.stderr.write(footer.join(EOL) + EOL)

    if (result.exitCode !== 0) process.exitCode = 1
  }),
)
