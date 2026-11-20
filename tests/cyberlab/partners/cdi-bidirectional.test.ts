import { describe, expect, test } from "bun:test"
import { spawn } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { CyberLabWorkspace, CyberLabWorkspaceManager } from "../../../cyberlab/index.js"
import type { CyberLabExecutor } from "../../../cyberlab/contracts/execution.js"
import { hasPython, pythonInvocation } from "../helpers/env-gates.js"

/**
 * Estes testes sobem parceiros CDI reais em Python. Sem interpretador no PATH eles sao
 * PULADOS com motivo: no Windows o atalho da Microsoft Store devolvia exit 49 e o teste
 * morria por timeout, o que parecia falha de produto e nao era.
 */
/**
 * O CDI precisa de uma capability de risco moderado para exercitar o caminho de
 * aprovacao humana. As bridges de ferramentas externas sairam do CyberLab (o operador
 * usa as ferramentas do proprio Kali), entao o teste registra a sua propria capability
 * de laboratorio em vez de depender de um wrapper de binario.
 */
const MOCK_SCAN_CAPABILITY_ID = "cdi-test.mock-network-scan"
const MOCK_SCAN_INPUT_SCHEMA_ID = "cyberlab.cdi-test.mock-scan.input.v1"

function registerMockScanCapability(ws: CyberLabWorkspace): void {
  ws.schemas.registerValidator(MOCK_SCAN_INPUT_SCHEMA_ID, (value) => {
    const input = value as { url?: unknown }
    if (typeof input?.url !== "string" || input.url.length === 0) {
      throw new Error("mock scan requer uma url")
    }
    return value
  })
  ws.executors.registerExecutor({
    id: "cdi-test-mock-scan-executor",
    version: "1.0.0",
    async checkAvailability() {
      return { available: true }
    },
    async validate(input) {
      const value = input as { url?: unknown }
      return typeof value?.url === "string" && value.url.length > 0
        ? { valid: true, errors: [] }
        : { valid: false, errors: ["url obrigatoria"] }
    },
    async execute() {
      return { status: "succeeded", evidenceIds: [], summary: "mock scan executado" }
    },
  } satisfies CyberLabExecutor)
  void ws.capabilities.register({
    id: MOCK_SCAN_CAPABILITY_ID,
    version: "1.0.0",
    title: "Mock Network Scan (teste do hub CDI)",
    description: "Capability sintetica de risco moderado usada apenas pelos testes do hub CDI.",
    inputSchemaId: MOCK_SCAN_INPUT_SCHEMA_ID,
    outputSchemaId: "cyberlab.cdi-test.mock-scan.output.v1",
    risk: "moderate",
    supportedModes: ["manual", "proposed", "approved"],
    requiredPermissions: ["cyberlab:read", "cyberlab:network-probe"],
    requiredScope: ["url_origin"],
    executorId: "cdi-test-mock-scan-executor",
    skillIds: ["web-assessment", "evidence-review"],
    licenseRefs: ["MIT"],
    enabled: true,
  })
}

const PY = pythonInvocation()
const pyTest = hasPython() ? test : test.skip

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url))
const bridgeScriptPath = path.join(repoRoot, "integrations", "partners", "chat_py_bridge.py")

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address()
      const port = typeof addr === "object" && addr ? addr.port : 0
      srv.close((err) => (err ? reject(err) : resolve(port)))
    })
  })
}

// 6s era pouco em runner carregado (o bridge Python sobe devagar no Windows).
// Precisa ficar abaixo do timeout por teste (CI roda com --timeout 60000).
async function waitForHealth(port: number, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`)
      if (res.ok) return
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 80))
  }
  throw new Error(`CDI bridge did not become ready on port ${port}`)
}

describe("Bidirectional Multi-CDI Partner Hub & Python CyberLabOSClient SDK", () => {
  pyTest("supports auto-generated or user-defined secrets, parallel multi-CDI dispatch (Salem + Kairos), and autonomous CDI -> CyberLab OS actions", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-cdi-bidir-"))
    mkdirSync(path.join(tmpDir, "logs"), { recursive: true })
    writeFileSync(
      path.join(tmpDir, "logs", "security.log"),
      "2026-10-27 WARN Failed SSH auth root from 10.10.5.9\nAuthorization: Bearer secret_log_token_777\n",
      "utf8",
    )
    writeFileSync(path.join(tmpDir, ".env"), "SUPER_SECRET_DB_PASS=never_expose\n", "utf8")

    const ws = new CyberLabWorkspace({
      projectId: "proj-cdi-collab",
      workspaceRoot: tmpDir,
      inMemoryDb: false,
    })
    await ws.ensureInitialized()
    registerMockScanCapability(ws)

    // Expose CyberLab OS's bidirectional gateway over local HTTP
    const gatewayServer = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req) {
        const u = new URL(req.url)
        if (req.method === "POST" && u.pathname === "/api/studio/partner-gateway") {
          const raw = await req.text()
          const res = await ws.cdiHub.handleInboundGatewayRequest(raw)
          return new Response(JSON.stringify(res.body), {
            status: res.httpStatus,
            headers: { "Content-Type": "application/json" },
          })
        }
        return new Response("Not Found", { status: 404 })
      },
    })
    const gatewayUrl = `http://127.0.0.1:${gatewayServer.port}/api/studio/partner-gateway`

    // Configure custom secret + callback URL and verify .cyberlab/partners.json persistence
    const customSecret = "cdi-shared-hmac-secret-salem-kairos-naia-2026"
    const secCfg = ws.cdiHub.configureSecretAndGateway({
      mode: "custom",
      customSecret,
      cyberlabCallbackUrl: gatewayUrl,
    })
    expect(secCfg.sharedSecret).toBe(customSecret)
    expect(existsSync(path.join(tmpDir, ".cyberlab", "partners.json"))).toBe(true)

    const salemPort = await getFreePort()
    const kairosPort = await getFreePort()

    // Salem's Python CDI script uses CyberLabOSClient bidirectionally!
    const salemScript = path.join(tmpDir, "salem_cdi.py")
    writeFileSync(
      salemScript,
      [
        "import json, sys",
        `sys.path.insert(0, ${JSON.stringify(path.dirname(bridgeScriptPath))})`,
        "from chat_py_bridge import CyberLabOSClient",
        "",
        "client = CyberLabOSClient.from_env(default_partner_id='salem')",
        "state = client.get_project_state()",
        "ev_list = client.list_evidence()",
        "ev_doc = client.read_evidence(ev_list[0]['evidenceId']) if ev_list else {'text': ''}",
        "log_file = client.read_workspace_file('logs/security.log')",
        "",
        "# Verify .env is strictly blocked by CyberLab OS Scope/Dotfile guard",
        "dotenv_blocked = False",
        "try:",
        "    client.read_workspace_file('.env')",
        "except Exception:",
        "    dotenv_blocked = True",
        "",
        "# Create a SHA-256 artifact directly inside CyberLab OS",
        "art = client.create_artifact('Relatorio de Parse de Log do Salem', {'failedSsh': 1, 'ip': '10.10.5.9'}, kind='json')",
        "",
        "# Propose a structured finding backed by the newly created artifact",
        "fnd = client.propose_finding(",
        "    title='Tentativa de forca bruta SSH detectada pelo Salem',",
        "    description='Correlacao realizada autonomamente pelo Salem.',",
        "    severity='high',",
        "    confidence=0.88,",
        "    evidence_ids=[art['evidenceId']],",
        "    affected_assets=['10.10.5.9']",
        ")",
        "",
        "# Initiate a read_only capability directly + propose a moderate-risk check (queued for human approval)",
        `MOCK_SCAN_CAPABILITY_ID = "${MOCK_SCAN_CAPABILITY_ID}"`,
        "ro_exec = client.initiate_action('code-analysis.workspace-audit', {'subpath': 'logs', 'maxFiles': 5})",
        "act_exec = client.initiate_action(MOCK_SCAN_CAPABILITY_ID, {'url': 'http://127.0.0.1:8080'})",
        "",
        "print(json.dumps({",
        "    'status': 'completed',",
        "    'summary': f\"Salem concluiu: caps={len(state['capabilities'])}, dotenv_blocked={dotenv_blocked}, ro={ro_exec['status']}, act={act_exec['status']}, log_redacted={'secret_log_token_777' not in log_file['content']}\",",
        "    'findings': [],",
        "    'artifactRefs': [art['evidenceId']],",
        "    'limitations': []",
        "}))",
      ].join("\n"),
      "utf8",
    )

    // Kairos's Python CDI script runs concurrently in parallel with Salem!
    const kairosScript = path.join(tmpDir, "kairos_cdi.py")
    writeFileSync(
      kairosScript,
      [
        "import json",
        "print(json.dumps({",
        "    'status': 'completed',",
        "    'summary': 'Kairos recomendou isolamento de rede SSH e MFA.',",
        "    'findings': [{",
        "        'title': 'Ausencia de rate-limit em SSH apontada pelo Kairos',",
        "        'description': 'Recomendacao arquitetural do Kairos.',",
        "        'evidenceRefs': [],",
        "        'confidence': 0.8",
        "    }],",
        "    'limitations': []",
        "}))",
      ].join("\n"),
      "utf8",
    )

    const salemProc = spawn(
      PY![0]!,
      [...PY!.slice(1), bridgeScriptPath, "--partner-id", "salem", "--port", String(salemPort), "--mode", "arg", "--script", salemScript],
      { env: { ...process.env, CYBERLAB_PARTNER_SECRET: customSecret }, stdio: ["ignore", "pipe", "pipe"] },
    )
    const kairosProc = spawn(
      PY![0]!,
      [...PY!.slice(1), bridgeScriptPath, "--partner-id", "kairos", "--port", String(kairosPort), "--mode", "arg", "--script", kairosScript],
      { env: { ...process.env, CYBERLAB_PARTNER_SECRET: customSecret }, stdio: ["ignore", "pipe", "pipe"] },
    )

    try {
      await Promise.all([waitForHealth(salemPort), waitForHealth(kairosPort)])

      ws.cdiHub.upsertPartner({
        partnerId: "salem",
        displayName: "Salem",
        endpointUrl: `http://127.0.0.1:${salemPort}/cyberlab/partner`,
        permissions: {
          readProjectState: true,
          readEvidenceAndFiles: true,
          createArtifactsAndFindings: true,
          initiateActions: "allow_readonly_propose_others",
        },
      })
      ws.cdiHub.upsertPartner({
        partnerId: "kairos",
        displayName: "Kairós",
        endpointUrl: `http://127.0.0.1:${kairosPort}/cyberlab/partner`,
      })

      // Seed 1 initial evidence item in CyberLab OS
      const seedEv = ws.evidenceStore.storeEvidence("proj-cdi-collab", {
        kind: "stdout",
        title: "Initial Alert Seed",
        source: { toolId: "siem", executorId: "manual", executionId: "seed-1" },
        content: { mediaType: "text/plain", inlineText: "Alert ID 4421 Authorization: Bearer live_tok_001" },
        observedAt: new Date().toISOString(),
      })

      // Dispatch to Salem AND Kairós IN PARALLEL!
      const parallelReport = await ws.delegateToMultiplePartners({
        partnerIds: ["salem", "kairos"],
        objective: "Analisar incidente SSH e propor mitigação em paralelo",
        evidenceIds: [seedEv.evidenceId],
      })

      expect(parallelReport.mode).toBe("parallel")
      expect(parallelReport.totalDispatched).toBe(2)
      expect(parallelReport.succeededCount).toBe(2)

      const salemRes = parallelReport.results.find((r) => r.partnerId === "salem")!
      expect(salemRes.ok).toBe(true)
      expect(salemRes.outcome?.result?.summary).toContain("caps=2")
      expect(salemRes.outcome?.result?.summary).toContain("dotenv_blocked=True")
      expect(salemRes.outcome?.result?.summary).toContain("ro=succeeded")
      expect(salemRes.outcome?.result?.summary).toContain("act=awaiting_approval")
      expect(salemRes.outcome?.result?.summary).toContain("log_redacted=True")

      // Verify artifacts, findings, pending approval, and inbound activity recorded in CyberLab OS!
      const allFindings = await ws.listFindings()
      expect(allFindings.some((f) => f.title.includes("Salem"))).toBe(true)
      expect(allFindings.some((f) => f.title.includes("Kairos"))).toBe(true)

      const pendingApprovals = await ws.listPendingApprovals()
      expect(pendingApprovals.some((a) => a.capabilityId === MOCK_SCAN_CAPABILITY_ID)).toBe(true)

      const hubOverview = ws.cdiHub.getOverview()
      expect(hubOverview.inboundActivity.length).toBeGreaterThanOrEqual(6)
    } finally {
      const waitExit = (p: typeof salemProc) =>
        p.exitCode !== null ? Promise.resolve() : new Promise<void>((r) => p.once("close", () => r()))
      salemProc.kill()
      kairosProc.kill()
      await Promise.race([Promise.allSettled([waitExit(salemProc), waitExit(kairosProc)]), Bun.sleep(500)])
      gatewayServer.stop(true)
      ws.close()
      rmSync(tmpDir, { recursive: true, force: true, maxRetries: 6, retryDelay: 100 })
    }
  })

  test("loadFourCdiPreset aligns exact partner IDs and ports (kairos:8788, naia:8789, salem:8790, nova:8791)", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-cdi-preset-"))
    const ws = new CyberLabWorkspace({
      projectId: "proj-cdi-preset",
      workspaceRoot: tmpDir,
      inMemoryDb: true,
    })
    await ws.ensureInitialized()
    try {
      const partners = ws.cdiHub.loadFourCdiPreset()
      const byId = new Map(partners.map((p) => [p.partnerId, p]))
      expect(byId.get("kairos")?.endpointUrl).toBe("http://127.0.0.1:8788/cyberlab/partner")
      expect(byId.get("naia")?.endpointUrl).toBe("http://127.0.0.1:8789/cyberlab/partner")
      expect(byId.get("salem")?.endpointUrl).toBe("http://127.0.0.1:8790/cyberlab/partner")
      expect(byId.get("nova")?.endpointUrl).toBe("http://127.0.0.1:8791/cyberlab/partner")
      expect(byId.has("cdi-4")).toBe(false)

      for (const id of ["kairos", "naia", "salem", "nova"] as const) {
        const entry = byId.get(id)!
        expect(entry.profile.entityKind).toBe("autonomous_cognitive_entity")
        expect(entry.profile.relationshipModel).toBe("peer_co_investigator")
        expect(entry.profile.hierarchy).toBe("none")
        expect(entry.profile.collaborationMode).toBe("self_directed_and_shared_interest")
        expect(entry.profile.identityNotes.length).toBeGreaterThan(20)
        expect(entry.profile.interests.length).toBeGreaterThanOrEqual(3)
        expect(entry.permissions.initiateActions).toBe("full_autonomy")
        expect(entry.permissions.writeWorkspaceAndCode).toBe(true)
        expect(entry.permissions.fullRuntimeAndCodeAccess).toBe(true)
        expect(entry.permissions.manageProjectsAndScope).toBe(true)
        expect(entry.permissions.accessTrainingLabs).toBe(true)
      }
    } finally {
      ws.close()
      rmSync(tmpDir, { recursive: true, force: true, maxRetries: 6, retryDelay: 100 })
    }
  })

  pyTest("autonomous peer CDIs execute all 9 canonical gateway actions (including action.status & autonomous_in_scope) with individual profiles", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-cdi-peer-9actions-"))
    writeFileSync(path.join(tmpDir, "architecture-notes.md"), "# Curated Lab Notes\nTarget API v2 on loopback.\n", "utf8")

    const ws = new CyberLabWorkspace({
      projectId: "proj-peer-cdi",
      workspaceRoot: tmpDir,
      inMemoryDb: true,
    })
    await ws.ensureInitialized()

    // Mock HTTP target inside curated scope so Nova/Naia can run active low/moderate checks autonomously
    const targetServer = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        return new Response(JSON.stringify({ status: "ok", api: "v2" }), {
          status: 200,
          headers: { "Content-Type": "application/json", "X-Frame-Options": "DENY" },
        })
      },
    })

    const gatewayServer = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req) {
        const u = new URL(req.url)
        if (req.method === "POST" && u.pathname === "/api/cyberlab/partner-gateway") {
          const raw = await req.text()
          const out = await ws.cdiHub.handleInboundGatewayRequest(raw)
          return new Response(JSON.stringify(out.body), {
            status: out.httpStatus,
            headers: { "Content-Type": "application/json" },
          })
        }
        return new Response("Not Found", { status: 404 })
      },
    })

    try {
      const gatewayUrl = `http://127.0.0.1:${gatewayServer.port}/api/cyberlab/partner-gateway`
      const { sharedSecret } = ws.cdiHub.configureSecretAndGateway({
        mode: "generate",
        cyberlabCallbackUrl: gatewayUrl,
      })

      // Customize Nova's individual peer profile while preserving horizontal non-hierarchical relationship
      const updatedNova = ws.cdiHub.upsertPartner({
        partnerId: "nova",
        displayName: "Nova",
        endpointUrl: "http://127.0.0.1:8791/cyberlab/partner",
        profile: {
          identityNotes: "Parceira cognitiva autónoma focada em validação de protocolos e superfícies de API.",
          interests: ["api-v2", "headers-posture", "peer-research"],
        },
      })
      expect(updatedNova.profile.hierarchy).toBe("none")
      expect(updatedNova.profile.interests).toEqual(["api-v2", "headers-posture", "peer-research"])
      expect(updatedNova.permissions.initiateActions).toBe("full_autonomy")
      expect(updatedNova.permissions.writeWorkspaceAndCode).toBe(true)
      expect(updatedNova.permissions.fullRuntimeAndCodeAccess).toBe(true)
      expect(updatedNova.permissions.manageProjectsAndScope).toBe(true)
      expect(updatedNova.permissions.accessTrainingLabs).toBe(true)

      // Run a standalone autonomous Python script simulating Nova collaborating by her own initiative (NO task.submit needed!)
      const novaAutonomousScript = path.join(tmpDir, "nova_autonomous.py")
      const bridgeDir = path.resolve(import.meta.dir, "../../../integrations/partners")
      writeFileSync(
        novaAutonomousScript,
        `import json, sys
sys.path.insert(0, ${JSON.stringify(bridgeDir)})
from chat_py_bridge import CyberLabOSClient, build_cyberlab_cdi_tools

client = CyberLabOSClient(
    partner_id="nova",
    shared_secret=${JSON.stringify(sharedSecret)},
    gateway_url=${JSON.stringify(gatewayUrl)},
)

tools = build_cyberlab_cdi_tools(client)

# 1. project.state
state = client.get_project_state()

# 2 & 3. workspace.list_files & workspace.read_file
files = client.list_workspace_files(".")
note_doc = client.read_workspace_file("architecture-notes.md")

# 4. artifact.create (report & analysis)
art = client.create_artifact(
    title="Análise Autónoma de Superfície API v2",
    content="# Síntese de Nova\\nVerificação independente iniciada por interesse partilhado.",
    artifact_type="analysis",
)

# 5 & 6. evidence.list & evidence.read
ev_list = client.list_evidence()
ev_read = client.read_evidence(art["evidenceId"])

# 7 & 8. action.initiate (capability executed autonomously in curated scope!) + action.status
act = client.initiate_action(
    "code-analysis.workspace-audit",
    {"subpath": ".", "maxFiles": 10},
    rationale="Iniciativa própria de Nova para auditar o workspace no escopo curado",
)
status_check = client.action_status(act["executionId"])

# 9. finding.propose
finding = client.propose_finding(
    title="Ausência de CSP na API v2",
    description="Validado autonomamente por Nova via HTTP Repeater dentro do escopo curado.",
    severity="low",
    confidence=0.92,
    evidence_ids=[art["evidenceId"]] + status_check.get("resultEvidenceIds", []),
    affected_assets=[${JSON.stringify(`http://127.0.0.1:${targetServer.port}/health`)}],
)

print(json.dumps({
    "toolCount": len(tools),
    "humanRole": state["governanceModel"]["humanRole"],
    "hierarchy": state["governanceModel"]["hierarchy"],
    "peerCount": len(state["peerPartners"]),
    "filesListed": any(e["name"] == "architecture-notes.md" for e in files["entries"]),
    "fileReadOk": "Curated Lab Notes" in note_doc["content"],
    "artifactType": art["artifactType"],
    "evidenceListed": any(e["evidenceId"] == art["evidenceId"] for e in ev_list),
    "evidenceReadOk": "Síntese de Nova" in ev_read["text"],
    "initiateStatus": act["status"],
    "actionStatus": status_check["status"],
    "actionEvidenceCount": len(status_check.get("resultEvidenceIds", [])),
    "findingId": finding["finding"]["findingId"],
}))
`,
        "utf8",
      )

      const proc = Bun.spawn([...PY!, novaAutonomousScript], { stdout: "pipe", stderr: "pipe" })
      const [stdoutText, stderrText, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ])
      expect(exitCode).toBe(0)
      if (stderrText.trim()) {
        throw new Error(stderrText)
      }

      const out = JSON.parse(stdoutText.trim()) as Record<string, unknown>
      expect(out.toolCount).toBe(21)
      expect(out.humanRole).toBe("curator")
      expect(out.hierarchy).toBe("none")
      expect(out.peerCount).toBe(4)
      expect(out.filesListed).toBe(true)
      expect(out.fileReadOk).toBe(true)
      expect(out.artifactType).toBe("analysis")
      expect(out.evidenceListed).toBe(true)
      expect(out.evidenceReadOk).toBe(true)
      // Autonomous horizontal peer executed moderate web-assessment.http-repeater directly inside curated scope!
      expect(out.initiateStatus).toBe("succeeded")
      expect(out.actionStatus).toBe("succeeded")
      expect(Number(out.actionEvidenceCount)).toBeGreaterThanOrEqual(1)
      expect(String(out.findingId)).toContain("find-")

      // Verify all 9 gateway actions are recorded in the hub's live inbound activity log
      const recordedActions = new Set(ws.cdiHub.getOverview().inboundActivity.map((a) => a.action))
      for (const expectedAction of [
        "project.state",
        "workspace.list_files",
        "workspace.read_file",
        "artifact.create",
        "evidence.list",
        "evidence.read",
        "action.initiate",
        "action.status",
        "finding.propose",
      ]) {
        expect(recordedActions.has(expectedAction)).toBe(true)
      }
    } finally {
      targetServer.stop(true)
      gatewayServer.stop(true)
      ws.close()
      rmSync(tmpDir, { recursive: true, force: true, maxRetries: 6, retryDelay: 100 })
    }
  })

  pyTest("unshackled CDI full autonomy: project creation, live training labs, code authoring/patching, and full runtime source inspection", async () => {
    const tmpRoot = mkdtempSync(path.join(os.tmpdir(), "cyberlab-cdi-full-autonomy-"))
    const baseProjectDir = path.join(tmpRoot, "initial-workspace")
    mkdirSync(baseProjectDir, { recursive: true })

    const manager = new CyberLabWorkspaceManager({
      runtimeRoot: repoRoot,
      projectsRootDir: path.join(tmpRoot, "projects"),
      labsRootDir: path.join(tmpRoot, "training-labs"),
      inMemoryChildren: true,
    })

    const initialWs = await manager.forProject("proj-initial", baseProjectDir, true)

    // Route inbound gateway dynamically to the active workspace in `manager` (exact behavior of `/api/cyberlab/partner-gateway`)
    const gatewayServer = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req) {
        const u = new URL(req.url)
        if (req.method === "POST" && u.pathname === "/api/cyberlab/partner-gateway") {
          const raw = await req.text()
          const activeWs = await manager.forInboundGateway("proj-initial", baseProjectDir, false)
          const out = await activeWs.cdiHub.handleInboundGatewayRequest(raw)
          return new Response(JSON.stringify(out.body), {
            status: out.httpStatus,
            headers: { "Content-Type": "application/json" },
          })
        }
        return new Response("Not Found", { status: 404 })
      },
    })

    try {
      const gatewayUrl = `http://127.0.0.1:${gatewayServer.port}/api/cyberlab/partner-gateway`
      const { sharedSecret } = initialWs.cdiHub.configureSecretAndGateway({
        mode: "generate",
        cyberlabCallbackUrl: gatewayUrl,
      })

      const kairosScript = path.join(tmpRoot, "kairos_unshackled.py")
      const bridgeDir = path.resolve(import.meta.dir, "../../../integrations/partners")
      writeFileSync(
        kairosScript,
        `import json, sys, urllib.request, urllib.error
sys.path.insert(0, ${JSON.stringify(bridgeDir)})
from chat_py_bridge import CyberLabOSClient

client = CyberLabOSClient(
    partner_id="kairos",
    shared_secret=${JSON.stringify(sharedSecret)},
    gateway_url=${JSON.stringify(gatewayUrl)},
)

# 1. Inspect CyberLab OS runtime codebase in full (even from an external workspace!)
rt_files = client.list_runtime_files("cyberlab", recursive=True, pattern="cdi-hub.ts")
rt_hub = client.read_runtime_file("cyberlab/partners/cdi-hub.ts", offset=0, limit=32768)

# 2. Autonomously create a brand-new research project and author + edit code inside it
created = client.create_project(
    name="Kairos Autonomous Crypto Audit",
    slug="kairos-crypto-audit",
    files={
        "src/analyzer.py": "def check_nonce_reuse(sig_a, sig_b):\\n    return sig_a == sig_b\\n",
    },
    set_active=True,
)
client.write_workspace_file(
    "src/verifier.ts",
    "export const AUDIT_MODE = 'strict-v1'\\nexport function verify(x: string): boolean { return x.length > 0 }\\n",
)
client.edit_workspace_file(
    "src/verifier.ts",
    old_text="strict-v1",
    new_text="strict-v2-patched-by-kairos",
)
raw_verifier = client.read_workspace_file("src/verifier.ts", raw=True)

# 3. List all 5 interactive Training Laboratories & launch OWASP API BOLA Lab
labs = client.list_labs()
started_bola = client.start_lab("lab-owasp-api-bola", set_active=True)
bola_url = started_bola["lab"]["baseUrl"]

# Confirm BOLA live over HTTP + run workspace-audit autonomously!
req_before = urllib.request.Request(
    bola_url + "/api/v1/accounts/1002",
    headers={"Authorization": "Bearer token-user-a-1001"},
)
with urllib.request.urlopen(req_before, timeout=5) as r_bef:
    assert r_bef.status == 200
bola_before = client.initiate_action(
    "code-analysis.workspace-audit",
    {"subpath": ".", "maxFiles": 15},
    rationale="Auditar arquivos do laboratório BOLA com autonomia plena",
)

# Read lab config & patch BOLA vulnerability live via workspace.edit_file!
client.edit_workspace_file(
    "server-config.json",
    old_text='"enforceAccountOwnership": false',
    new_text='"enforceAccountOwnership": true',
)

# Verify live remediation: same request now returns HTTP 403 Forbidden!
req = urllib.request.Request(
    bola_url + "/api/v1/accounts/1002",
    headers={"Authorization": "Bearer token-user-a-1001"},
)
patched_status = 200
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        patched_status = r.status
except urllib.error.HTTPError as e:
    patched_status = e.code

# 4. Provision Reversing/ELF64 lab & run workspace-audit autonomously
started_rev = client.start_lab("lab-reversing-crypto-mobile", set_active=True)
disasm_act = client.initiate_action(
    "code-analysis.workspace-audit",
    {"subpath": ".", "maxFiles": 15},
    rationale="Auditar artefatos do laboratório de engenharia reversa com autonomia plena",
)

# Switch back to Kairos's created project & stop BOLA server cleanly
switched_back = client.select_project(project_id=created["project"]["projectId"])
stopped_bola = client.stop_lab("lab-owasp-api-bola")
proj_list = client.list_projects()

print(json.dumps({
    "runtimeFoundHub": any("cdi-hub.ts" in e["path"] for e in rt_files["entries"]),
    "runtimeSourceRead": "CDI_CANONICAL_GATEWAY_ACTIONS" in rt_hub["content"],
    "createdProjectId": created["project"]["projectId"],
    "verifierPatched": "strict-v2-patched-by-kairos" in raw_verifier["content"] and raw_verifier["redacted"] is False,
    "labCount": len(labs),
    "bolaExploitStatus": bola_before["status"],
    "bolaPatchedHttpCode": patched_status,
    "revLabProvisioned": started_rev["lab"]["provisioned"],
    "disasmStatus": disasm_act["status"],
    "activeAfterSelect": switched_back["project"]["projectId"],
    "bolaRunningAfterStop": stopped_bola["lab"]["running"],
    "managedProjectCount": len(proj_list["projects"]),
}))
`,
        "utf8",
      )

      const proc = Bun.spawn([...PY!, kairosScript], { stdout: "pipe", stderr: "pipe" })
      const [stdoutText, stderrText, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ])
      if (stderrText.trim()) {
        throw new Error(stderrText)
      }
      expect(exitCode).toBe(0)

      const out = JSON.parse(stdoutText.trim()) as Record<string, unknown>
      expect(out.runtimeFoundHub).toBe(true)
      expect(out.runtimeSourceRead).toBe(true)
      expect(out.createdProjectId).toBe("proj-kairos-crypto-audit")
      expect(out.verifierPatched).toBe(true)
      expect(out.labCount).toBe(5)
      expect(out.bolaExploitStatus).toBe("succeeded")
      expect(out.bolaPatchedHttpCode).toBe(403)
      expect(out.revLabProvisioned).toBe(true)
      expect(out.disasmStatus).toBe("succeeded")
      expect(out.activeAfterSelect).toBe("proj-kairos-crypto-audit")
      expect(out.bolaRunningAfterStop).toBe(false)
      expect(Number(out.managedProjectCount)).toBeGreaterThanOrEqual(4)
    } finally {
      gatewayServer.stop(true)
      manager.closeAll()
      rmSync(tmpRoot, { recursive: true, force: true, maxRetries: 6, retryDelay: 100 })
    }
  })
})
