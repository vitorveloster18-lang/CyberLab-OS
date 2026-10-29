import { describe, expect, test } from "bun:test"
import { spawn } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"

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

async function waitForHealth(port: number, timeoutMs = 6_000): Promise<void> {
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
  test("supports auto-generated or user-defined secrets, parallel multi-CDI dispatch (Salem + Kairos), and autonomous CDI -> CyberLab OS actions", async () => {
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
        "# Initiate a read_only capability directly + propose an active HTTP check (queued for human approval)",
        "ro_exec = client.initiate_action('code-analysis.workspace-audit', {'subpath': 'logs', 'maxFiles': 5})",
        "act_exec = client.initiate_action('web-assessment.http-repeater', {'url': 'http://127.0.0.1:8080/health'})",
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
      "python3",
      [bridgeScriptPath, "--partner-id", "salem", "--port", String(salemPort), "--mode", "arg", "--script", salemScript],
      { env: { ...process.env, CYBERLAB_PARTNER_SECRET: customSecret }, stdio: ["ignore", "pipe", "pipe"] },
    )
    const kairosProc = spawn(
      "python3",
      [bridgeScriptPath, "--partner-id", "kairos", "--port", String(kairosPort), "--mode", "arg", "--script", kairosScript],
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
      expect(salemRes.outcome?.result?.summary).toContain("caps=31")
      expect(salemRes.outcome?.result?.summary).toContain("dotenv_blocked=True")
      expect(salemRes.outcome?.result?.summary).toContain("ro=succeeded")
      expect(salemRes.outcome?.result?.summary).toContain("act=awaiting_approval")
      expect(salemRes.outcome?.result?.summary).toContain("log_redacted=True")

      // Verify artifacts, findings, pending approval, and inbound activity recorded in CyberLab OS!
      const allFindings = await ws.listFindings()
      expect(allFindings.some((f) => f.title.includes("Salem"))).toBe(true)
      expect(allFindings.some((f) => f.title.includes("Kairos"))).toBe(true)

      const pendingApprovals = await ws.listPendingApprovals()
      expect(pendingApprovals.some((a) => a.capabilityId === "web-assessment.http-repeater")).toBe(true)

      const hubOverview = ws.cdiHub.getOverview()
      expect(hubOverview.inboundActivity.length).toBeGreaterThanOrEqual(6)
    } finally {
      salemProc.kill("SIGTERM")
      kairosProc.kill("SIGTERM")
      gatewayServer.stop(true)
      ws.close()
      rmSync(tmpDir, { recursive: true, force: true })
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
        expect(entry.permissions.initiateActions).toBe("autonomous_in_scope")
      }
    } finally {
      ws.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("autonomous peer CDIs execute all 9 canonical gateway actions (including action.status & autonomous_in_scope) with individual profiles", async () => {
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
      expect(updatedNova.permissions.initiateActions).toBe("autonomous_in_scope")

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

# 7 & 8. action.initiate (moderate capability executed autonomously in curated scope!) + action.status
act = client.initiate_action(
    "web-assessment.http-repeater",
    {"url": ${JSON.stringify(`http://127.0.0.1:${targetServer.port}/health`)}, "method": "GET"},
    rationale="Iniciativa própria de Nova para validar cabeçalhos da API v2 no escopo curado",
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

      const proc = Bun.spawn(["python3", novaAutonomousScript], { stdout: "pipe", stderr: "pipe" })
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
      expect(out.toolCount).toBe(9)
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
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
