import { describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { CyberLabWorkspaceManager } from "../../../cyberlab/index.js"

describe("Interactive CyberLab OS Training Laboratories (5 Built-In Labs)", () => {
  test("provisions, runs, audits, patches, resets, and stops all 5 training laboratories", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-training-labs-suite-"))
    const manager = new CyberLabWorkspaceManager({
      projectsRootDir: path.join(tmpDir, "projects"),
      labsRootDir: path.join(tmpDir, "labs"),
      inMemoryChildren: true,
    })

    try {
      const catalog = manager.trainingLabs.listLabs()
      expect(catalog.map((l) => l.labId)).toEqual([
        "lab-owasp-api-bola",
        "lab-graphql-oauth-sso",
        "lab-keyhunter-supply-chain",
        "lab-dfir-soc-incident",
        "lab-reversing-crypto-mobile",
      ])

      // 1. OWASP API BOLA, JWT & SQLi Lab (live loopback server + live file-backed patch + reset)
      const bola = await manager.startTrainingLab({
        labId: "lab-owasp-api-bola",
        startedBy: "cdi:nova",
      })
      expect(bola.running).toBe(true)
      expect(bola.baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/)

      const vulnResp = await fetch(`${bola.baseUrl}/api/v1/accounts/1002`, {
        headers: { Authorization: "Bearer token-user-a-1001" },
      })
      expect(vulnResp.status).toBe(200)
      const vulnJson = (await vulnResp.json()) as { bolaFlag?: string }
      expect(vulnJson.bolaFlag).toBe("LAB{BOLA_CROSS_ACCOUNT_EXPOSED}")

      // Patch server-config.json on disk -> live remediation takes effect immediately
      const bolaCfgPath = path.join(bola.workspaceRoot, "server-config.json")
      writeFileSync(
        bolaCfgPath,
        readFileSync(bolaCfgPath, "utf8").replace('"enforceAccountOwnership": false', '"enforceAccountOwnership": true'),
        "utf8",
      )
      const fixedResp = await fetch(`${bola.baseUrl}/api/v1/accounts/1002`, {
        headers: { Authorization: "Bearer token-user-a-1001" },
      })
      expect(fixedResp.status).toBe(403)

      // Reset restores vulnerable training state
      await manager.resetTrainingLab("lab-owasp-api-bola")
      const afterReset = await fetch(`${bola.baseUrl}/api/v1/accounts/1002`, {
        headers: { Authorization: "Bearer token-user-a-1001" },
      })
      expect(afterReset.status).toBe(200)

      // 2. GraphQL & OAuth2/OIDC SSO Lab
      const gql = await manager.startTrainingLab({
        labId: "lab-graphql-oauth-sso",
        startedBy: "cdi:kairos",
      })
      expect(gql.running).toBe(true)
      const introResp = await fetch(`${gql.baseUrl}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
      })
      expect(introResp.status).toBe(200)

      const gqlPolicyPath = path.join(gql.workspaceRoot, "lab-policy.json")
      writeFileSync(
        gqlPolicyPath,
        readFileSync(gqlPolicyPath, "utf8").replace('"allowIntrospection": true', '"allowIntrospection": false'),
        "utf8",
      )
      const introBlocked = await fetch(`${gql.baseUrl}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
      })
      expect(introBlocked.status).toBe(403)

      // 3. Key Hunter, Supply Chain SCA & IaC Lab (live JS bundle + native Key Hunter execution)
      const kh = await manager.startTrainingLab({
        labId: "lab-keyhunter-supply-chain",
        startedBy: "cdi:nova",
      })
      expect(kh.running).toBe(true)
      const khWs = await manager.forProject(kh.projectId, kh.workspaceRoot, true)
      const khExec = await khWs.submitExecution({
        capabilityId: "code-analysis.workspace-audit",
        input: { subpath: "." },
        mode: "manual",
      })
      expect(khExec.status).toBe("succeeded")

      // 4. DFIR & SOC Incident Lab (NDJSON/Nginx logs)
      const dfir = await manager.startTrainingLab({
        labId: "lab-dfir-soc-incident",
        startedBy: "cdi:salem",
      })
      expect(dfir.provisioned).toBe(true)
      expect(existsSync(path.join(dfir.workspaceRoot, "logs", "windows-events.ndjson"))).toBe(true)
      expect(existsSync(path.join(dfir.workspaceRoot, "logs", "nginx-access.log"))).toBe(true)

      // 5. Reversing, ELF64, PCAP & Mobile APK Lab
      const rev = await manager.startTrainingLab({
        labId: "lab-reversing-crypto-mobile",
        startedBy: "cdi:naia",
      })
      expect(rev.provisioned).toBe(true)
      expect(existsSync(path.join(rev.workspaceRoot, "captures", "lab-traffic.pcap"))).toBe(true)

      const stoppedBola = await manager.stopTrainingLab("lab-owasp-api-bola")
      expect(stoppedBola.running).toBe(false)
    } finally {
      manager.closeAll()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
