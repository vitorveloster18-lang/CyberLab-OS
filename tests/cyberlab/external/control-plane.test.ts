import { describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { CyberLabWorkspace } from "../../../cyberlab/index.js"
import { canCreateSymlink, rmWithRetry, writeFakeExecutable, writeFakeSleepBinary } from "../helpers/env-gates.js"

/**
 * Estes testes exercitam a execução de binários externos de verdade. O produto já é
 * multiplataforma (`expandPlatformNames` procura `.exe`/`.cmd`/`.bat` no Windows), por
 * isso o "binário falso" também precisa ser: em POSIX um script com shebang bash, em
 * Windows um `.cmd`. Sem isso o `spawn` estoura ENOENT e o teste acusa uma falha que
 * na verdade é do ambiente de teste, não do produto.
 */
const KILL_UNVERIFIABLE_ON_WINDOWS = process.platform === "win32"
const KILL_SKIP_TAG = KILL_UNVERIFIABLE_ON_WINDOWS
  ? " [PULADO: kill de processo neto nao e verificavel via .cmd no Windows]"
  : ""

describe("CyberLab Unified External Control Plane (Single Cockpit for External Tools & Manual Runs)", () => {
  test("discovers local external binaries in .cyberlab/bin, gates moderate runs via ApprovalTicket, and captures SHA-256 evidence", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ext-ctrl-"))
    try {
      const localBin = path.join(tmpDir, ".cyberlab", "bin")
      mkdirSync(localBin, { recursive: true })

      // Simulate an externally installed nmap binary inside .cyberlab/bin/nmap
      const fakeNmap = writeFakeExecutable(localBin, "nmap", [
        "Nmap scan report for $ARGS",
        "8080/tcp open http-proxy",
      ])

      const ws = new CyberLabWorkspace({ projectId: "proj-ext-nmap", workspaceRoot: tmpDir, inMemoryDb: true })

      const tools = await ws.listExternalTools()
      const nmapStatus = tools.find((t) => t.toolId === "nmap")
      expect(nmapStatus?.available).toBe(true)
      expect(nmapStatus?.sourceLocation).toBe("workspace_local_bin")
      expect(nmapStatus?.resolvedPath).toBe(fakeNmap.resolvedPath)

      // 1. Out-of-scope public IP is blocked BEFORE external binary is ever spawned
      const blocked = await ws.submitExecution({
        capabilityId: "external.nmap-service-probe",
        input: { host: "8.8.8.8", ports: "80,443" },
        mode: "manual",
      })
      expect(blocked.status).toBe("blocked")

      // 2. Proposed run (e.g. from AI/MCP/operator proposal) on in-scope 127.0.0.1 requires single-use human approval (risk=moderate)
      const queued = await ws.submitExecution({
        capabilityId: "external.nmap-service-probe",
        input: { host: "127.0.0.1", ports: "8080", serviceVersion: true },
        mode: "proposed",
        requestedBy: { type: "assistant", id: "opencode-agent" },
      })
      expect(queued.status).toBe("awaiting_approval")

      const pending = await ws.listPendingApprovals()
      expect(pending.length).toBe(1)

      const completed = await ws.approveExecution({
        approvalId: pending[0]!.approvalId,
        decidedBy: "cockpit-operator",
        reason: "Authorized local lab service probe",
      })
      expect(completed.status).toBe("succeeded")
      expect(completed.resultEvidenceIds.length).toBe(1)

      const ev = await ws.listEvidence(completed.executionId)
      expect(ev[0]?.content.inlineText).toContain("8080/tcp open http-proxy")

      ws.close()
    } finally {
      rmWithRetry(tmpDir)
    }
  })

  test.skipIf(KILL_UNVERIFIABLE_ON_WINDOWS)(
    `terminates a running external OS process immediately when operator triggers Kill/Cancel from CyberLab OS${KILL_SKIP_TAG}`,
    async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ext-kill-"))
    try {
      const localBin = path.join(tmpDir, ".cyberlab", "bin")
      mkdirSync(localBin, { recursive: true })

      // Simulate a long-running external tshark dissection
      writeFakeSleepBinary(localBin, "tshark", 15)
      writeFileSync(path.join(tmpDir, "traffic.pcap"), "placeholder")

      const ws = new CyberLabWorkspace({ projectId: "proj-ext-kill", workspaceRoot: tmpDir, inMemoryDb: true })

      const startedAt = Date.now()
      const runningPromise = ws.submitExecution({
        capabilityId: "external.tshark-pcap-summary",
        input: { pcapPath: "traffic.pcap" },
        mode: "manual",
      })

      // Wait briefly for child process to spawn, then trigger unified kill-switch
      await new Promise((r) => setTimeout(r, 80))
      const activeExecs = await ws.listExecutions()
      expect(activeExecs.length).toBe(1)
      await ws.cancelExecution(activeExecs[0]!.executionId, "Operator clicked Kill in Unified Control Plane")

      const finalRec = await runningPromise
      const elapsedMs = Date.now() - startedAt
      expect(finalRec.status).toBe("cancelled")
      expect(elapsedMs).toBeLessThan(3_000)

      ws.close()
    } finally {
      rmWithRetry(tmpDir)
    }
  })

  test("supervises manual CLI external wrapper (blocking out-of-scope targets before launch and recording SHA-256 on allowed targets)", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ext-wrap-"))
    try {
      const localBin = path.join(tmpDir, ".cyberlab", "bin")
      mkdirSync(localBin, { recursive: true })
      const fakeTool = writeFakeExecutable(localBin, "mvt-android", [
        "MVT scan completed on $ARGS",
        "Authorization: Bearer secret_leak_token_999",
      ])
      writeFileSync(path.join(tmpDir, "backup.ab"), "android-backup")

      const ws = new CyberLabWorkspace({ projectId: "proj-ext-wrap", workspaceRoot: tmpDir, inMemoryDb: true })

      // Attempt to wrap a command targeting cloud metadata IP -> MUST BLOCK BEFORE LAUNCH
      const blockedWrap = await ws.runSupervisedExternalCommand({
        toolId: "curl-manual",
        binary: fakeTool.path,
        args: ["http://169.254.169.254/latest/meta-data/"],
        target: "http://169.254.169.254/latest/meta-data/",
      })
      expect(blockedWrap.blocked).toBe(true)
      expect(blockedWrap.reason).toContain("Blocked by CyberLab ScopeController")

      // Supervised manual run on in-scope workspace artifact -> executes, redacts Bearer token, and stores SHA-256
      const okWrap = await ws.runSupervisedExternalCommand({
        toolId: "mvt-android",
        binary: "mvt-android",
        args: ["backup.ab"],
        target: "backup.ab",
      })
      expect(okWrap.blocked).toBe(false)
      expect(okWrap.exitCode).toBe(0)
      expect(okWrap.ingested?.scopeAuditStatus).toBe("in_scope")
      expect(okWrap.ingested?.redactionStatus).toBe("redacted")

      const allEv = await ws.listEvidence()
      expect(allEv[0]?.content.inlineText).not.toContain("secret_leak_token_999")
      const integrity = await ws.verifyEvidence(okWrap.ingested!.evidenceId)
      expect(integrity.valid).toBe(true)

      ws.close()
    } finally {
      rmWithRetry(tmpDir)
    }
  })

  test("ingests manual external GUI outputs (OpenTRAP/Burp) and synchronizes .cyberlab/inbox while rejecting symlinks", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ext-inbox-"))
    try {
      const ws = new CyberLabWorkspace({ projectId: "proj-ext-inbox", workspaceRoot: tmpDir, inMemoryDb: true })

      // 1. Direct manual external ingestion (flagging out-of-scope targets explicitly in provenance!)
      const flagged = await ws.ingestExternalAction({
        toolId: "opentrap",
        target: "https://out-of-scope-corp.example/admin",
        rawOutput: "HTTP/1.1 200 OK\r\nAuthorization: Bearer super_secret_abc123456789\r\n\r\nok",
      })
      expect(flagged.scopeAuditStatus).toBe("out_of_scope_flagged")
      expect(flagged.redactionStatus).toBe("redacted")

      // 2. Drop external files + rogue symlink into .cyberlab/inbox/
      mkdirSync(ws.externalControl.inboxDir, { recursive: true })
      writeFileSync(
        path.join(ws.externalControl.inboxDir, "opentrap_session_01.http"),
        "GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\nHTTP/1.1 200 OK\r\n",
      )
      writeFileSync(
        path.join(ws.externalControl.inboxDir, "nuclei_results.json"),
        JSON.stringify({ template: "git-config", host: "http://127.0.0.1:8080" }),
      )
      // No Windows isso exige Developer Mode/admin; sem permissão, o symlink não é
      // criado e a proteção correspondente simplesmente não é exercitada aqui.
      const symlinkAllowed = canCreateSymlink()
      const outsideSecret = path.join(os.tmpdir(), `outside-secret-${Date.now()}.txt`)
      if (symlinkAllowed) {
        writeFileSync(outsideSecret, "TOP_SECRET_HOST_FILE")
        symlinkSync(outsideSecret, path.join(ws.externalControl.inboxDir, "rogue-link.txt"))
      }

      expect(ws.externalControl.countPendingInboxFiles()).toBe(2)

      const syncRes = await ws.syncExternalInbox()
      expect(syncRes.ingested.length).toBe(2)
      expect(syncRes.skippedReasons.some((s) => s.includes("rogue-link.txt"))).toBe(symlinkAllowed)
      expect(ws.externalControl.countPendingInboxFiles()).toBe(0)

      // Both real artifacts are archived in .cyberlab/inbox/processed/ and verified in EvidenceStore
      for (const item of syncRes.ingested) {
        expect(existsSync(path.join(tmpDir, item.archivedTo))).toBe(true)
        const check = await ws.verifyEvidence(item.evidenceId)
        expect(check.valid).toBe(true)
      }

      rmWithRetry(outsideSecret)
      ws.close()
    } finally {
      rmWithRetry(tmpDir)
    }
  })
})
