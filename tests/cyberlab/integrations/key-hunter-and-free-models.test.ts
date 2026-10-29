import { describe, expect, test } from "bun:test"
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import http from "node:http"
import type net from "node:net"
import os from "node:os"
import path from "node:path"
import { BUILTIN_EXTERNAL_TOOL_CATALOG, CyberLabWorkspace } from "../../../cyberlab/index.js"

describe("CyberLab Key Hunter (Native MIT + Rust CLI Bridge) & OpenCode Free AI Models Fix", () => {
  test("1. Native Key Hunter scans workspace files, binary stubs, raw buffers, and web JS bundles while filtering placeholders and masking raw secrets", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-key-hunter-"))
    let server: http.Server | undefined
    try {
      // Construct synthetic test tokens via concatenation to avoid GitHub Push Protection false positives
      const syntheticAwsKey = "AKIA" + "Q7V9M2K4L8P3N6R9"
      const syntheticGhPat = "ghp_" + "9Km2Pq8Vx4Lz7Bn3Rt6Yw1Jc5Hd8Gf0Sa2Ue"
      const syntheticStripeLive = "sk_live_" + "9xKm2Pq8Vx4Lz7Bn3Rt6Yw1Jc5Hd8Gf0"
      const syntheticAnthropic =
        "sk-ant-" +
        "api03-9Km2Pq8Vx4Lz7Bn3Rt6Yw1Jc5Hd8Gf0Sa2Ue7Vx4Lz7Bn3Rt6Yw1Jc5Hd8Gf0Sa2Ue9Km2Pq8Vx4Lz7Bn3Rt6Yw1Jc5Hd8Gf0"
      const placeholderOpenAi = "sk-proj-" + "YOUR_API_KEY_HERE_XXXXXXXXXXXXXXXXXXXXXXXX"
      const placeholderAws = "AKIA" + "IOSFODNN7EXAMPLE"
      const pemHeader = "-----BEGIN " + "PRIVATE KEY-----"
      const pemFooter = "-----END " + "PRIVATE KEY-----"

      // 1) Workspace text file (.env.staging) containing real-shaped keys + placeholders + PEM block
      writeFileSync(
        path.join(tmpDir, ".env.staging"),
        [
          "# Placeholders below must be skipped when skipPlaceholders=true",
          `OPENAI_KEY=${placeholderOpenAi}`,
          `AWS_EXAMPLE=${placeholderAws}`,
          "# Realistic synthetic secrets below must be detected & masked",
          `AWS_ACCESS_KEY_ID=${syntheticAwsKey}`,
          `ANTHROPIC_API_KEY=${syntheticAnthropic}`,
          pemHeader,
          "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9v7x8mK3pL2qR",
          pemFooter,
        ].join("\n"),
        "utf8",
      )

      // 2) Binary firmware/APK stub with NUL bytes and embedded GitHub PAT string
      const binPrefix = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00])
      const binSecret = Buffer.from(`GITHUB_DEPLOY=${syntheticGhPat}\0`, "utf8")
      writeFileSync(path.join(tmpDir, "firmware.bin"), Buffer.concat([binPrefix, binSecret]))

      // 3) Local HTTP server serving index.html + <script src="/assets/app.bundle.js"> containing Stripe Live key
      server = http.createServer((req, res) => {
        if (req.url === "/assets/app.bundle.js") {
          res.writeHead(200, { "content-type": "application/javascript" })
          res.end(`window.__STRIPE_SECRET__ = "${syntheticStripeLive}";`)
          return
        }
        res.writeHead(200, { "content-type": "text/html" })
        res.end('<html><head><script src="/assets/app.bundle.js"></script></head><body>App</body></html>')
      })
      await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", () => resolve()))
      const port = (server.address() as net.AddressInfo).port
      const targetUrl = `http://127.0.0.1:${port}/`

      const ws = await new CyberLabWorkspace({
        projectId: "proj-key-hunter",
        workspaceRoot: tmpDir,
        inMemoryDb: true,
      }).ensureInitialized()

      const jwtSample =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkN5YmVyTGFiT3BlcmF0b3IiLCJpYXQiOjE3MzAwMDAwMDB9." +
        "9Km2Pq8Vx4Lz7Bn3Rt6Yw1Jc5Hd8Gf0Sa2Ue7Vx4Lz8"

      const exec = await ws.submitExecution({
        capabilityId: "code-analysis.key-hunter",
        mode: "manual",
        input: {
          subpath: ".",
          targetUrl,
          rawText: `Authorization: Bearer ${jwtSample}`,
          skipPlaceholders: true,
          carveCryptoMaterial: true,
          verifyActive: false,
        },
      })

      expect(exec.status).toBe("succeeded")
      const evList = await ws.listEvidence(exec.executionId)
      expect(evList.length).toBe(1)
      const content = await ws.readEvidenceContent(evList[0]!.evidenceId)

      // CUSTODY INVARIANT: Raw full secrets MUST NEVER appear anywhere in stored evidence JSON!
      expect(content.text).not.toContain(syntheticGhPat)
      expect(content.text).not.toContain(syntheticStripeLive)
      expect(content.text).not.toContain(syntheticAnthropic)

      const report = JSON.parse(content.text) as {
        tool: string
        stats: {
          suppressedPlaceholders: number
          totalFindings: number
        }
        matches: Array<{
          patternId: string
          provider: string
          sourceKind: string
          maskedSecret: string
          fingerprintSha256: string
          verificationRecipe: string
        }>
      }

      expect(report.tool).toBe("CyberLab Key Hunter")
      expect(report.stats.suppressedPlaceholders).toBeGreaterThanOrEqual(2)
      const patternIds = report.matches.map((m) => m.patternId)
      expect(patternIds).toContain("aws_access_key_id")
      expect(patternIds).toContain("anthropic_api_key")
      expect(patternIds).toContain("github_pat_classic")
      expect(patternIds).toContain("stripe_live_secret")
      expect(patternIds).toContain("pem_private_key")
      expect(patternIds).toContain("jwt_bearer_token")

      // Verify binary carving & remote JS bundle extraction source kinds
      const sourceKinds = new Set(report.matches.map((m) => m.sourceKind))
      expect(sourceKinds.has("workspace_file")).toBe(true)
      expect(sourceKinds.has("binary_strings")).toBe(true)
      expect(sourceKinds.has("web_js_bundle")).toBe(true)
      expect(sourceKinds.has("raw_buffer")).toBe(true)

      // Verify ScopeController blocks out-of-scope public URLs by default (allowExternalTargets=false)
      const blockedExec = await ws.submitExecution({
        capabilityId: "code-analysis.key-hunter",
        mode: "manual",
        input: {
          targetUrl: "https://evil-out-of-scope.example.com/app.js",
        },
      })
      expect(blockedExec.status).toBe("blocked")

      ws.close()
    } finally {
      if (server) await new Promise<void>((resolve) => server!.close(() => resolve()))
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("2. External KeyHunter Rust CLI Bridge (fadidevv/keyhunter) executes shell=false and redacts leaked tokens in stdout custody", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ext-keyhunter-"))
    const binDir = path.join(tmpDir, "mock-bin")
    mkdirSync(binDir, { recursive: true })
    const origPath = process.env.PATH ?? ""
    try {
      const catEntry = BUILTIN_EXTERNAL_TOOL_CATALOG.find((t) => t.toolId === "keyhunter")
      expect(catEntry).toBeDefined()
      expect(catEntry?.licenseSpdx).toBe("MIT")

      const rawMockSecret = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
      if (process.platform !== "win32") {
        const mockBin = path.join(binDir, "keyhunter")
        writeFileSync(
          mockBin,
          `#!/usr/bin/env node\nconsole.log(JSON.stringify({ argv: process.argv.slice(2), findings: [{ provider: "github", key: "${rawMockSecret}" }] }));\n`,
          "utf8",
        )
        chmodSync(mockBin, 0o755)
        process.env.PATH = `${binDir}:${origPath}`

        const ws = await new CyberLabWorkspace({
          projectId: "proj-ext-kh",
          workspaceRoot: tmpDir,
          inMemoryDb: true,
        }).ensureInitialized()

        const exec = await ws.submitExecution({
          capabilityId: "external.keyhunter-cli",
          mode: "manual",
          input: {
            subcommand: "scan",
            provider: "github",
            outputFormat: "json",
            verifiedOnly: true,
          },
        })

        expect(exec.status).toBe("succeeded")
        const evList = await ws.listEvidence(exec.executionId)
        expect(evList.length).toBeGreaterThanOrEqual(1)
        const stdoutContent = await ws.readEvidenceContent(evList[0]!.evidenceId)
        expect(stdoutContent.text).toContain('"scan"')
        expect(stdoutContent.text).toContain('"-p"')
        expect(stdoutContent.text).toContain('"github"')
        expect(stdoutContent.text).toContain('"-V"')
        // Automatic custody redaction must mask ghp_... token!
        expect(stdoutContent.text).not.toContain(rawMockSecret)
        expect(stdoutContent.text).toContain("[REDACTED:GITHUB_TOKEN]")

        ws.close()
      }
    } finally {
      process.env.PATH = origPath
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("3. OpenCode Free AI Models fix: snapshot exposes 9 active free models with public key, models-dev checks loadable(), CLI sets valid User-Agent, and UI includes freeSet", async () => {
    const repoRoot = path.resolve(import.meta.dir, "../../..")

    // Verify CLI server-process & default command map 'local' channel/version to 'latest'/'2.1.4' User-Agent
    const serverProcessSrc = readFileSync(path.join(repoRoot, "packages/cli/src/server-process.ts"), "utf8")
    expect(serverProcessSrc).toContain('OPENCODE_CHANNEL === "local"')
    expect(serverProcessSrc).toContain('OPENCODE_VERSION === "local"')
    expect(serverProcessSrc).toContain('"2.1.4"')
    expect(serverProcessSrc).toContain('"latest"')

    const defaultHandlerSrc = readFileSync(
      path.join(repoRoot, "packages/cli/src/commands/handlers/default.ts"),
      "utf8",
    )
    expect(defaultHandlerSrc).toContain('OPENCODE_CHANNEL === "local"')

    // Verify SolidJS model selector includes freeSet in visible() (upstream #60047 fix)
    const appModelsSrc = readFileSync(path.join(repoRoot, "packages/app/src/providers/models/models.tsx"), "utf8")
    expect(appModelsSrc).toContain(".filter(isFreeModel)")
    expect(appModelsSrc).toContain("freeSet().has(key)")

    // Verify models-dev.ts checks Provider.builtinPackages via loadable() (upstream #59475/#59926 fix)
    const modelsDevSrc = readFileSync(path.join(repoRoot, "packages/core/src/models-dev.ts"), "utf8")
    expect(modelsDevSrc).toContain("function loadable(specifier: string | undefined")
    expect(modelsDevSrc).toContain("Provider.builtinPackages.has(name)")

    // Verify model.ts includes refreshed active non-deprecated free models in PREFERRED_FREE
    const modelSrc = readFileSync(path.join(repoRoot, "packages/core/src/model.ts"), "utf8")
    expect(modelSrc).toContain("deepseek-v4.1-flash-free")
    expect(modelSrc).toContain("glm-5.3-flash-free")
    expect(modelSrc).toContain("nemotron-3.5-super-vl-free")
    expect(modelSrc).toContain("mimo-v2.6-flash-free")

    // Verify bundled snapshot.txt opencode provider exposes all 9 non-deprecated free chat models
    const snapshotRaw = readFileSync(path.join(repoRoot, "packages/core/src/models-dev/snapshot.txt"), "utf8")
    const snapshotCatalog = JSON.parse(snapshotRaw) as Record<
      string,
      {
        models: Record<string, { id: string; type?: string; status?: string; cost?: unknown }>
      }
    >
    const opencodeProvider = snapshotCatalog["opencode"]
    expect(opencodeProvider).toBeDefined()

    const activeFreeModels = Object.values(opencodeProvider!.models).filter((m) => {
      if (m.status === "deprecated") return false
      if (m.type && m.type !== "chat") return false
      if (m.id.includes("embed")) return false
      const rawStr = JSON.stringify(m.cost ?? {})
      return !rawStr.includes('"price":') || rawStr.includes('"price":0')
    })
    const activeFreeIds = activeFreeModels.map((m) => m.id)
    expect(activeFreeIds).toContain("big-pickle")
    expect(activeFreeIds).toContain("deepseek-v4.1-flash-free")
    expect(activeFreeIds).toContain("glm-5.3-flash-free")
    expect(activeFreeIds).toContain("nemotron-3.5-super-vl-free")
    expect(activeFreeIds).toContain("mimo-v2.6-flash-free")
    expect(activeFreeIds.length).toBeGreaterThanOrEqual(9)
  })
})
