import { afterEach, describe, expect, it } from "bun:test"
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { collapseForTarget, normalizeAdvisories, runLabResearch } from "../../../cyberlab/labs/research-phase.js"
import {
  ADVISORY_ECOSYSTEMS,
  deriveProfile,
  getLabResearchProfile,
  hasCuratedResearchProfile,
  listCuratedResearchProfileIds,
  type AdvisoryTarget,
} from "../../../cyberlab/labs/research-profile.js"

/**
 * Fase C — Pesquisa (v6.7).
 *
 * A Fase C era só instrução no prompt do agente: "consulte CyberLab-Knowledge/ e
 * fontes primárias". Sem ferramenta, cada operador montava a pesquisa à mão e nada
 * ficava arquivado. Estes testes fixam as duas partes que podem apodrecer em silêncio:
 * a normalização do payload da GitHub Advisory Database (que é terceiro e muda) e o
 * perfil curado (que é digitado à mão e pode apontar para pacote inexistente).
 */

const TARGET: AdvisoryTarget = {
  ecosystem: "npm",
  package: "jsonwebtoken",
  rationale: "teste",
}

/**
 * Fixture REAL capturada de `GET /advisories?ecosystem=npm&affects=jsonwebtoken`
 * (gh api, 2026-11-04). Mantida de propósito: se a API mudar de forma, o teste avisa.
 */
const REAL_FIXTURE = [
  {
    cve_id: "CVE-2022-23541",
    cvss: { score: 5, vector_string: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L" },
    ghsa_id: "GHSA-hjrf-2m68-5959",
    html_url: "https://github.com/advisories/GHSA-hjrf-2m68-5959",
    published_at: "2022-12-22T03:33:19Z",
    references: [
      "https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959",
      "https://nvd.nist.gov/vuln/detail/CVE-2022-23541",
    ],
    severity: "medium",
    summary: "jsonwebtoken's insecure implementation of key retrieval function",
    updated_at: "2024-06-24T21:24:07Z",
    withdrawn_at: null,
    vulnerabilities: [
      {
        first_patched_version: "9.0.0",
        package: { ecosystem: "npm", name: "jsonwebtoken" },
        vulnerable_version_range: "<= 8.5.1",
      },
    ],
  },
  {
    cve_id: "CVE-2022-23540",
    cvss: { score: 6.4, vector_string: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L" },
    ghsa_id: "GHSA-qwph-4952-7xr6",
    html_url: "https://github.com/advisories/GHSA-qwph-4952-7xr6",
    published_at: "2022-12-22T03:32:59Z",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-23540"],
    severity: "medium",
    summary: "jsonwebtoken vulnerable to signature validation bypass",
    updated_at: "2025-02-13T18:33:13Z",
    withdrawn_at: null,
    vulnerabilities: [
      {
        first_patched_version: "9.0.0",
        package: { ecosystem: "npm", name: "jsonwebtoken" },
        vulnerable_version_range: "< 9.0.0",
      },
    ],
  },
]

const dirs: string[] = []
function tmpDir(): string {
  const d = mkdtempSync(path.join(os.tmpdir(), "cyberlab-fase-c-"))
  dirs.push(d)
  return d
}
afterEach(() => {
  // Windows mantém lock em arquivo recém-escrito; sem retry o afterEach falha.
  for (const d of dirs.splice(0)) {
    for (let i = 0; i < 5; i++) {
      try {
        rmSync(d, { recursive: true, force: true })
        break
      } catch {
        Bun.sleepSync(30)
      }
    }
  }
})

describe("Fase C — normalização de advisories (v6.7)", () => {
  it("converte o payload real da GitHub Advisory Database", () => {
    const recs = normalizeAdvisories(REAL_FIXTURE, TARGET)
    expect(recs.length).toBe(2)
    const first = recs[0]!
    expect(first.ghsaId).toBe("GHSA-hjrf-2m68-5959")
    expect(first.cveId).toBe("CVE-2022-23541")
    expect(first.severity).toBe("medium")
    expect(first.cvssScore).toBe(5)
    expect(first.vulnerableVersionRange).toBe("<= 8.5.1")
    expect(first.firstPatchedVersion).toBe("9.0.0")
    expect(first.packageName).toBe("jsonwebtoken")
    // A API devolve `references` como array de strings na prática.
    expect(first.references.length).toBe(2)
    expect(first.references.join(" ")).toContain("nvd.nist.gov")
    expect(first.withdrawnAt).toBeNull()
  })

  it("aceita `references` no formato documentado (array de { url })", () => {
    const recs = normalizeAdvisories(
      [
        {
          ghsa_id: "GHSA-xxxx-yyyy-zzzz",
          references: [{ url: "https://example.com/a" }, { url: null }, "https://example.com/b"],
        },
      ],
      TARGET,
    )
    expect(recs.length).toBe(1)
    expect(recs[0]!.references).toEqual(["https://example.com/a", "https://example.com/b"])
  })

  it("gera um registro por pacote afetado (não atribui falha ao pacote errado)", () => {
    const recs = normalizeAdvisories(
      [
        {
          ghsa_id: "GHSA-multi-0000-0001",
          cve_id: "CVE-2099-0001",
          vulnerabilities: [
            {
              package: { ecosystem: "npm", name: "aaa" },
              vulnerable_version_range: "< 1.0.0",
              first_patched_version: "1.0.0",
            },
            {
              package: { ecosystem: "pip", name: "bbb" },
              vulnerable_version_range: "< 2.0.0",
            },
          ],
        },
      ],
      TARGET,
    )
    expect(recs.length).toBe(2)
    expect(recs.map((r) => r.packageName)).toEqual(["aaa", "bbb"])
    expect(recs.map((r) => r.ecosystem)).toEqual(["npm", "pip"])
    expect(recs[1]!.firstPatchedVersion).toBeNull()
  })

  it("não inventa registro quando o payload é lixo", () => {
    expect(normalizeAdvisories(null, TARGET)).toEqual([])
    expect(normalizeAdvisories({}, TARGET)).toEqual([])
    expect(normalizeAdvisories([{ sem_ghsa: true }], TARGET)).toEqual([])
    expect(normalizeAdvisories([null, 42, "x"], TARGET)).toEqual([])
  })

  it("colapsa faixas repetidas e ignora pacotes irmãos (1 linha por advisory)", () => {
    // Caso real: `affects=jose` devolve 3 advisories que viravam 17 registros —
    // 9 de faixas repetidas do próprio jose e 8 dos pacotes irmãos.
    const raw = [
      {
        ghsa_id: "GHSA-jose-0001",
        cve_id: "CVE-2099-1001",
        severity: "high",
        vulnerabilities: [
          { package: { ecosystem: "npm", name: "jose" }, vulnerable_version_range: "< 4.9.2" },
          { package: { ecosystem: "npm", name: "jose" }, vulnerable_version_range: ">= 5.0.0, < 5.2.11" },
          { package: { ecosystem: "npm", name: "jose-node-cjs-runtime" }, vulnerable_version_range: "< 4.9.2" },
          { package: { ecosystem: "npm", name: "jose-browser-runtime" }, vulnerable_version_range: "< 4.9.2" },
        ],
      },
    ]
    const expanded = normalizeAdvisories(raw, { ecosystem: "npm", package: "jose", rationale: "t" })
    expect(expanded.length).toBe(4)

    const collapsed = collapseForTarget(expanded, { ecosystem: "npm", package: "jose", rationale: "t" })
    expect(collapsed.length).toBe(1)
    expect(collapsed[0]!.packageName).toBe("jose")
    expect(collapsed[0]!.vulnerableVersionRange).toContain("< 4.9.2")
    expect(collapsed[0]!.vulnerableVersionRange).toContain(">= 5.0.0, < 5.2.11")
  })

  it("colapsa as grafias diferentes do mesmo pacote (pyjwt / PyJWT / pyJWT)", () => {
    const raw = [
      {
        ghsa_id: "GHSA-pyjwt-0001",
        vulnerabilities: [
          { package: { ecosystem: "pip", name: "pyjwt" }, vulnerable_version_range: "< 2.4.0", first_patched_version: "2.4.0" },
          { package: { ecosystem: "pip", name: "PyJWT" }, vulnerable_version_range: "< 2.4.0", first_patched_version: "2.4.0" },
          { package: { ecosystem: "pip", name: "pyJWT" }, vulnerable_version_range: "<= 2.4.0" },
        ],
      },
    ]
    const collapsed = collapseForTarget(
      normalizeAdvisories(raw, { ecosystem: "pip", package: "pyjwt", rationale: "t" }),
      { ecosystem: "pip", package: "pyjwt", rationale: "t" },
    )
    // 2 faixas distintas (< 2.4.0 e <= 2.4.0), não 3 linhas idênticas.
    expect(collapsed.length).toBe(1)
    expect(collapsed[0]!.vulnerableVersionRange).toBe("< 2.4.0; <= 2.4.0")
    expect(collapsed[0]!.firstPatchedVersion).toBe("2.4.0")
  })

  it("preserva advisories retirados (withdrawn) em vez de descartá-los", () => {
    const recs = normalizeAdvisories(
      [{ ghsa_id: "GHSA-ret-0000-0001", withdrawn_at: "2023-01-01T00:00:00Z" }],
      TARGET,
    )
    expect(recs.length).toBe(1)
    expect(recs[0]!.withdrawnAt).toBe("2023-01-01T00:00:00Z")
  })
})

describe("Fase C — perfis de pesquisa (v6.7)", () => {
  it("o lab de API OWASP tem perfil curado", () => {
    expect(hasCuratedResearchProfile("lab-owasp-api-bola")).toBe(true)
    expect(listCuratedResearchProfileIds()).toContain("lab-owasp-api-bola")
  })

  it("todo pacote do perfil usa um ecossistema válido", () => {
    for (const labId of listCuratedResearchProfileIds()) {
      const p = getLabResearchProfile(labId)
      expect(p.advisoryTargets.length).toBeGreaterThan(0)
      for (const t of p.advisoryTargets) {
        expect(ADVISORY_ECOSYSTEMS).toContain(t.ecosystem)
        expect(t.package.length).toBeGreaterThan(0)
        // Rationale é o que impede o relatório de virar uma lista sem sentido.
        expect(t.rationale.length).toBeGreaterThan(30)
      }
    }
  })

  it("toda fraqueza tem CWE e justificativa; toda fonte primária é https", () => {
    const p = getLabResearchProfile("lab-owasp-api-bola")
    expect(p.weaknesses.length).toBeGreaterThan(0)
    for (const w of p.weaknesses) {
      expect(w.cwe).toMatch(/^CWE-\d+$/)
      expect(w.name.length).toBeGreaterThan(3)
      expect(w.why.length).toBeGreaterThan(30)
    }
    expect(p.primarySources.length).toBeGreaterThan(0)
    for (const s of p.primarySources) {
      expect(s.url.startsWith("https://")).toBe(true)
      expect(s.note.length).toBeGreaterThan(20)
    }
  })

  it("declara explicitamente que os advisories NÃO são CVEs do lab", () => {
    const p = getLabResearchProfile("lab-owasp-api-bola")
    expect(p.limitations.join(" ").toLowerCase()).toContain("não são cves do próprio lab")
  })

  it("perfil derivado não inventa pacotes", () => {
    const p = deriveProfile("lab-inexistente")
    expect(p.advisoryTargets).toEqual([])
    expect(p.weaknesses).toEqual([])
    expect(p.limitations.join(" ")).toContain("não tem perfil de pesquisa curado")
  })
})

describe("Fase C — execução ponta a ponta (v6.7)", () => {
  /**
   * Reescreve o nome do pacote afetado para o pacote REALMENTE consultado na URL —
   * senão `jose`/`pyjwt` não casam com o fixture do `jsonwebtoken` e o colapso por
   * pacote devolve zero. Payload que não é lista (ex.: corpo de erro) passa intacto.
   */
  function rewriteFor(url: string, payload: unknown): unknown {
    if (!Array.isArray(payload)) return payload
    const match = /affects=([^&]+)/.exec(url)
    const pkg = decodeURIComponent(match?.[1] ?? "")
    return payload.map((adv) => ({
      ...adv,
      vulnerabilities: ((adv?.vulnerabilities ?? []) as Array<Record<string, unknown>>).map(
        (v) => ({ ...v, package: { ...(v.package as object), name: pkg } }),
      ),
    }))
  }

  const fakeFetch = (payload: unknown, status = 200) =>
    (async (input: unknown) => {
      const url = typeof input === "string" ? input : String((input as Request).url)
      return new Response(JSON.stringify(rewriteFor(url, payload)), {
        status,
        headers: { "content-type": "application/json" },
      })
    }) as unknown as typeof fetch

  it("grava RESEARCH.md, research.json, o bruto e o manifesto com SHA-256", async () => {
    const ws = tmpDir()
    const out = path.join(ws, "out")
    const report = await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: ws,
      outDir: out,
      fetchImpl: fakeFetch(REAL_FIXTURE),
    })

    expect(report.curated).toBe(true)
    expect(report.offline).toBe(false)
    expect(report.advisories.length).toBe(3) // 3 pacotes no perfil
    expect(report.advisories.every((a) => a.status === "ok")).toBe(true)
    const total = report.advisories.reduce((n, a) => n + a.advisories.length, 0)
    expect(total).toBeGreaterThan(0)

    for (const name of ["RESEARCH.md", "research.json", "research-manifest.json"]) {
      expect(existsSync(path.join(out, name))).toBe(true)
    }
    // O bruto de cada pacote precisa estar arquivado, senão nada é auditável.
    for (const a of report.advisories) {
      expect(a.rawFile).toBeTruthy()
      expect(a.rawSha256).toMatch(/^[0-9a-f]{64}$/)
      expect(existsSync(path.join(out, a.rawFile!))).toBe(true)
    }

    const md = readFileSync(path.join(out, "RESEARCH.md"), "utf8")
    expect(md).toContain("# Fase C")
    expect(md).toContain("CWE-639")
    expect(md).toContain("GHSA-hjrf-2m68-5959")
    expect(md).toContain("Limitações declaradas")
    expect(md).toContain("não são CVEs do próprio lab")

    const manifest = JSON.parse(readFileSync(path.join(out, "research-manifest.json"), "utf8"))
    expect(manifest.seal).toMatch(/^[0-9a-f]{64}$/)
    expect(manifest.files.length).toBeGreaterThanOrEqual(2 + report.advisories.length)
    for (const f of manifest.files) expect(f.sha256).toMatch(/^[0-9a-f]{64}$/)
  })

  it("em modo offline não toca a rede e marca o status", async () => {
    const ws = tmpDir()
    let called = 0
    const spy = (async () => {
      called += 1
      return new Response("[]", { status: 200 })
    }) as unknown as typeof fetch

    const report = await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: ws,
      outDir: path.join(ws, "offline"),
      offline: true,
      fetchImpl: spy,
    })
    expect(called).toBe(0)
    expect(report.offline).toBe(true)
    expect(report.advisories.every((a) => a.status === "offline")).toBe(true)
    expect(report.advisories.every((a) => a.rawFile === null)).toBe(true)
  })

  it("erro de rede não derruba a Fase C: fica registrado no relatório", async () => {
    const ws = tmpDir()
    const report = await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: ws,
      outDir: path.join(ws, "erro"),
      fetchImpl: fakeFetch({ message: "rate limit" }, 403),
    })
    expect(report.advisories.every((a) => a.status === "error")).toBe(true)
    for (const a of report.advisories) {
      expect(a.httpStatus).toBe(403)
      // A mensagem precisa ser acionável, não um "403" cru.
      expect(a.error).toContain("GITHUB_TOKEN")
    }
    const md = readFileSync(path.join(report.outputDir, "RESEARCH.md"), "utf8")
    expect(md).toContain("Erro:")
  })

  it("cache: segunda execução não repete a consulta", async () => {
    const ws = tmpDir()
    let calls = 0
    const spy = (async (input: unknown) => {
      calls += 1
      const url = typeof input === "string" ? input : String((input as Request).url)
      return new Response(JSON.stringify(rewriteFor(url, REAL_FIXTURE)), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }) as unknown as typeof fetch

    await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: ws,
      outDir: path.join(ws, "r1"),
      fetchImpl: spy,
    })
    expect(calls).toBe(3) // 3 pacotes

    const second = await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: ws,
      outDir: path.join(ws, "r2"),
      fetchImpl: spy,
    })
    expect(calls).toBe(3) // veio do cache
    expect(second.advisories.every((a) => a.status === "cached")).toBe(true)
  })

  it("refresh ignora o cache", async () => {
    const ws = tmpDir()
    let calls = 0
    const spy = (async (input: unknown) => {
      calls += 1
      const url = typeof input === "string" ? input : String((input as Request).url)
      return new Response(JSON.stringify(rewriteFor(url, REAL_FIXTURE)), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }) as unknown as typeof fetch

    await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: ws,
      outDir: path.join(ws, "a"),
      fetchImpl: spy,
    })
    await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: ws,
      outDir: path.join(ws, "b"),
      refresh: true,
      fetchImpl: spy,
    })
    expect(calls).toBe(6)
  })

  it("mesmo conteúdo em pastas diferentes gera o mesmo lacre (o lacre não depende do caminho)", async () => {
    // Workspaces separados: se fosse o mesmo, a 2ª execução viria do cache e mudaria
    // a proveniência (`ok` -> `cached`), o que legitimamente altera o relatório.
    const wsA = tmpDir()
    const wsB = tmpDir()
    const stamp = new Date("2026-11-04T12:00:00.000Z")
    const a = await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: wsA,
      outDir: path.join(wsA, "saida-A"),
      fetchImpl: fakeFetch(REAL_FIXTURE),
      now: stamp,
    })
    const b = await runLabResearch({
      labId: "lab-owasp-api-bola",
      workspaceRoot: wsB,
      outDir: path.join(wsB, "pasta-totalmente-diferente"),
      fetchImpl: fakeFetch(REAL_FIXTURE),
      now: stamp,
    })
    expect(a.outputDir).not.toBe(b.outputDir)
    expect(a.seal).toBe(b.seal)
  })
})
