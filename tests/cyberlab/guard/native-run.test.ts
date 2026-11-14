import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { afterAll, beforeAll, describe, expect, it } from "bun:test"

import type { ProjectScope } from "../../../cyberlab/contracts/policy.js"
import { EvidenceStore } from "../../../cyberlab/evidence/store.js"
import {
  extractTargetsFromArgv,
  GuardedRunUsageError,
  formatBlockedMessage,
  runGuardedNative,
} from "../../../cyberlab/guard/native-run.js"
import { ScopeController } from "../../../cyberlab/policy/scope.js"

function makeScope(overrides: Partial<ProjectScope> = {}): ProjectScope {
  return {
    scopeId: "scope-test",
    projectId: "proj-test",
    name: "Lab de teste",
    workspaceRoot: process.cwd(),
    allowedTargets: [{ kind: "cidr", value: "192.168.56.0/24" }],
    blockedTargets: [],
    allowExternalTargets: false,
    active: true,
    updatedAt: new Date().toISOString(),
    ...overrides,
  }
}

let artifactsDir: string
let store: EvidenceStore

beforeAll(() => {
  artifactsDir = mkdtempSync(path.join(tmpdir(), "cyberlab-native-run-"))
  store = new EvidenceStore({
    databasePath: ":memory:",
    artifactsDir,
  })
})

afterAll(() => {
  try {
    store.close()
  } catch {
    // ignore
  }
  try {
    rmSync(artifactsDir, { recursive: true, force: true })
  } catch {
    // ignore
  }
})

function run(argv: string[], options: Partial<ProjectScope> = {}) {
  const scope = new ScopeController()
  scope.setProjectScope(makeScope(options))
  return runGuardedNative({
    projectId: "proj-test",
    argv,
    scope,
    store,
    actor: "test:operator",
    executorId: "kali-vm",
    cwd: process.cwd(),
  })
}

describe("native-run: execução nativa", () => {
  it("roda o binário direto, sem ponte nem shell", () => {
    const r = run(["echo", "ola-cyberlab"])
    expect(r.blocked).toBe(false)
    expect(r.exitCode).toBe(0)
    expect(r.stdout.trim()).toBe("ola-cyberlab")
  })

  it("não interpreta metacaracteres — o argumento não vira outro comando", () => {
    // Se houvesse shell, isto executaria dois comandos. Com shell:false,
    // o ponto-e-vírgula é só texto.
    const r = run(["echo", "a; echo b"])
    expect(r.stdout.trim()).toBe("a; echo b")
  })

  it("propaga o exit code de falha sem travar", () => {
    const r = run(["sh", "-c", "exit 7"])
    expect(r.blocked).toBe(false)
    expect(r.exitCode).toBe(7)
  })
})

describe("native-run: escopo", () => {
  it("recusa ANTES de executar, e não executa nada", () => {
    // 8.8.8.8 está fora de 192.168.56.0/24 e allowExternalTargets é false.
    const r = run(["ping", "-c", "1", "8.8.8.8"])
    expect(r.blocked).toBe(true)
    expect(r.exitCode).toBeNull()
    expect(r.stdout).toBe("")
    expect(r.evidenceId).toBeNull()
  })

  it("permite alvo dentro do escopo", () => {
    const r = run(["echo", "192.168.56.10"])
    expect(r.blocked).toBe(false)
  })

  it("a mensagem de bloqueio diz que nada foi executado", () => {
    const r = run(["ping", "-c", "1", "1.1.1.1"])
    const msg = formatBlockedMessage(r)
    expect(msg).toContain("nada foi executado")
    expect(msg).toContain("ping")
  })

  it("bloqueia tudo quando não há escopo ativo para o projeto", () => {
    const r = run(["echo", "x"], { active: false })
    expect(r.blocked).toBe(true)
  })
})

describe("native-run: redação", () => {
  it("redige segredo que apareça na saída", () => {
    const r = run(["echo", "password=supersecreto123"])
    expect(r.redacted).toBe(true)
    expect(r.stdout).toContain("[REDACTED:SECRET]")
    expect(r.stdout).not.toContain("supersecreto123")
  })

  it("não marca redação quando não há o que redigir", () => {
    const r = run(["echo", "nada-sensivel-aqui"])
    expect(r.redacted).toBe(false)
    expect(r.stdout.trim()).toBe("nada-sensivel-aqui")
  })
})

describe("native-run: evidência", () => {
  it("grava a evidência da execução permitida", () => {
    const r = run(["echo", "evidencia-teste"])
    expect(r.evidenceId).toBeTruthy()

    const record = store.getEvidence(r.evidenceId!)
    expect(record).toBeDefined()
    expect(record!.content.inlineText).toContain("evidencia-teste")
  })

  it("registra cadeia de custódia para a evidência gravada", () => {
    const r = run(["echo", "custodia-teste"])
    const chain = store.getCustodyChain(r.evidenceId!)
    expect(chain.length).toBeGreaterThan(0)
  })

  it("não derruba a execução se a evidência falhar", () => {
    // Um store fechado estoura ao gravar; a saída do comando ainda é válida.
    const closedStore = new EvidenceStore({
      databasePath: ":memory:",
      artifactsDir,
    })
    closedStore.close()

    const scope = new ScopeController()
    scope.setProjectScope(makeScope())
    const r = runGuardedNative({
      projectId: "proj-test",
      argv: ["echo", "sem-store"],
      scope,
      store: closedStore,
    })

    expect(r.exitCode).toBe(0)
    expect(r.stdout.trim()).toBe("sem-store")
    expect(r.evidenceId).toBeNull()
  })
})

describe("native-run: uso", () => {
  it("rejeita argv vazio em vez de spawnar algo indefinido", () => {
    expect(() => run([], {})).toThrow(GuardedRunUsageError)
  })
})

describe("extractTargetsFromArgv: extração de alvos do argv cru", () => {
  it("acha IPv4, CIDR e host:porta", () => {
    expect(extractTargetsFromArgv(["nmap", "10.0.0.5"]).networkTargets).toEqual(["10.0.0.5"])
    expect(extractTargetsFromArgv(["nmap", "10.0.0.0/24"]).networkTargets).toEqual(["10.0.0.0/24"])
    // host:porta → guarda o IP puro, que é o que o escopo compara.
    expect(extractTargetsFromArgv(["curl", "10.0.0.5:8443"]).networkTargets).toEqual(["10.0.0.5"])
  })

  it("extrai o host de uma URL, descartando credenciais, porta e caminho", () => {
    const out = extractTargetsFromArgv([
      "ffuf",
      "-u",
      "https://user:senha123@api.exemplo.com:8443/v1/login?x=1",
    ])
    expect(out.networkTargets).toEqual(["api.exemplo.com"])
  })

  it("ignora flags — -sV e --top-ports não são alvos", () => {
    // Se flags fossem tratados como alvo, todo comando seria bloqueado.
    const out = extractTargetsFromArgv(["nmap", "-sV", "-O", "--top-ports=1000", "-p-"])
    expect(out.networkTargets).toEqual([])
  })

  it("não confunde número de versão nem nome de arquivo com alvo", () => {
    // 1.2.3 tem só 3 octetos; wordlist.txt tem TLD que não é alfabético puro.
    expect(extractTargetsFromArgv(["tool", "--version", "1.2.3"]).networkTargets).toEqual([])
    expect(extractTargetsFromArgv(["ffuf", "-w", "wordlist.txt"]).networkTargets).toEqual([])
  })

  it("acha domínio quando ele é um argumento solto", () => {
    expect(extractTargetsFromArgv(["dig", "exemplo.com.br"]).networkTargets).toEqual([
      "exemplo.com.br",
    ])
  })

  it("não duplica o mesmo alvo repetido", () => {
    const out = extractTargetsFromArgv(["tool", "10.0.0.5", "10.0.0.5"])
    expect(out.networkTargets).toEqual(["10.0.0.5"])
  })
})
