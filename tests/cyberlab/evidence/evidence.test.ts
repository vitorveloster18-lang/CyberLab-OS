import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
  EvidenceStore,
  exportEvidenceBundle,
  redactSensitiveContent,
  renderAssessmentMarkdownReport,
  verifyExportedBundle,
} from "../../../cyberlab/index.js"

describe("CyberLab Evidence Persistence, Redaction & Integrity", () => {
  test("persists inline & large artifact evidence, verifies SHA-256 integrity, and detects tampering", () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-ev-"))
    try {
      const store = new EvidenceStore({
        databasePath: path.join(tmpDir, "evidence.sqlite"),
        artifactsDir: path.join(tmpDir, "artifacts"),
        inlineMaxBytes: 128,
      })

      // 1. Small inline evidence
      const small = store.storeEvidence("proj-forensics", {
        kind: "http_exchange",
        title: "HTTP Response Headers",
        source: {
          toolId: "http-inspector",
          toolVersion: "1.0.0",
          executorId: "http-headers-executor",
          executionId: "exec-101",
        },
        content: {
          mediaType: "text/plain",
          inlineText: "HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: session=super-secret-value; HttpOnly\r\n",
        },
        observedAt: "2026-10-26T14:00:00.000Z",
      })

      expect(small.integrity.immutable).toBe(true)
      expect(small.redactionStatus).toBe("not_checked")
      expect(store.verifyIntegrity(small.evidenceId).valid).toBe(true)

      // Redacted view strips cookie before sharing with LLM or partner while preserving raw bytes in store
      const shared = store.readRedactedForSharing(small.evidenceId, "partner:review-agent")
      expect(shared.redacted).toBe(true)
      expect(shared.text).toContain("[REDACTED:COOKIE]")
      expect(shared.text).not.toContain("super-secret-value")

      // 2. Large payload (> 128 bytes) automatically offloaded to content-addressed artifact file
      const bigText = "Observed packet trace line\n".repeat(25)
      const large = store.storeEvidence(
        "proj-forensics",
        {
          kind: "network_observation",
          title: "Large Lab Capture Summary",
          source: {
            toolId: "tcp-inspector",
            executorId: "tcp-inspector",
            executionId: "exec-102",
          },
          content: {
            mediaType: "text/plain",
            inlineText: bigText,
          },
          observedAt: "2026-10-26T14:01:00.000Z",
        },
        { retentionClass: "forensic" },
      )

      expect(large.content.storageKey).toBe(large.integrity.sha256)
      expect(large.content.inlineText).toBeUndefined()
      expect(store.verifyIntegrity(large.evidenceId).valid).toBe(true)

      // Corrupt the artifact on disk -> verifyIntegrity MUST detect tampering!
      const artifactPath = path.join(tmpDir, "artifacts", large.content.storageKey!)
      writeFileSync(artifactPath, "TAMPERED_PAYLOAD")
      const checkAfterTamper = store.verifyIntegrity(large.evidenceId, "auditor:vitor")
      expect(checkAfterTamper.valid).toBe(false)
      expect(checkAfterTamper.reason).toMatch(/SHA-256 mismatch/)

      // Custody chain contains collected, redacted_share, integrity_verified/failed
      const custody = store.getCustodyChain(large.evidenceId)
      expect(custody.map((c) => c.action)).toEqual(["collected", "integrity_verified", "integrity_failed"])

      store.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("preserves non-destructive finding review history and exports verifiable evidence bundles", () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-bundle-"))
    try {
      const store = new EvidenceStore({
        databasePath: path.join(tmpDir, "evidence.sqlite"),
        artifactsDir: path.join(tmpDir, "artifacts"),
      })

      const ev = store.storeEvidence("proj-web", {
        kind: "http_exchange",
        title: "Missing CSP & HSTS on lab portal",
        source: {
          toolId: "http-inspector",
          executorId: "http-headers-executor",
          executionId: "exec-200",
        },
        content: {
          mediaType: "application/json",
          inlineText: JSON.stringify({ status: 200, headers: { server: "Apache" }, apiKey: "Authorization: Bearer secret123456" }),
        },
        observedAt: "2026-10-26T15:00:00.000Z",
      })

      const finding = store.createFinding({
        projectId: "proj-web",
        title: "Missing Transport & Content Security Headers",
        description: "Portal responds without Strict-Transport-Security or Content-Security-Policy.",
        severity: "medium",
        confidence: 0.6,
        evidenceIds: [ev.evidenceId],
        affectedAssets: ["http://127.0.0.1:8080"],
        createdBy: "assistant:main",
      })
      expect(finding.status).toBe("unreviewed")

      const needsMore = store.reviewFinding({
        findingId: finding.findingId,
        reviewedBy: "operator:vitor",
        decision: "needs_more_evidence",
        notes: "Verify HTTPS vhost directly",
      })
      expect(needsMore.status).toBe("inconclusive")

      const confirmed = store.reviewFinding({
        findingId: finding.findingId,
        reviewedBy: "operator:vitor",
        decision: "accept",
        notes: "Confirmed on lab target",
      })
      expect(confirmed.status).toBe("confirmed")

      // Revision history retains all 3 states without erasing prior conclusions!
      const history = store.getFindingHistory(finding.findingId)
      expect(history).toHaveLength(3)
      expect(history.map((h) => h.newStatus)).toEqual(["unreviewed", "inconclusive", "confirmed"])

      // Generate Markdown report
      const md = renderAssessmentMarkdownReport({
        projectId: "proj-web",
        projectName: "Lab Web Portal",
        executions: [],
        evidence: store.listEvidence("proj-web"),
        findings: store.listFindings("proj-web"),
      })
      expect(md).toContain("Confirmed Security Findings")
      expect(md).toContain(ev.integrity.sha256)

      // Export redacted evidence bundle & verify manifest hashes
      const bundleDir = path.join(tmpDir, "exported-bundle")
      const manifest = exportEvidenceBundle({
        store,
        projectId: "proj-web",
        outputDir: bundleDir,
        redactPayloads: true,
      })
      expect(manifest.redacted).toBe(true)
      expect(verifyExportedBundle(bundleDir)).toEqual({ valid: true, errors: [] })

      // Tamper exported blob -> bundle verification fails
      writeFileSync(path.join(bundleDir, manifest.items[0]!.fileName), "corrupted")
      const tamperedCheck = verifyExportedBundle(bundleDir)
      expect(tamperedCheck.valid).toBe(false)
      expect(tamperedCheck.errors.length).toBeGreaterThanOrEqual(1)

      store.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("redacts AWS keys, GitHub tokens, JWTs, Bearer tokens and PEM private keys", () => {
    const sample = [
      "Authorization: Bearer super_secret_token_999",
      "aws_key=AKIAIOSFODNN7EXAMPLE",
      "gh=ghp_1234567890abcdefghijklmnopqrstuv",
      "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
    ].join("\n")

    const res = redactSensitiveContent(sample)
    expect(res.redacted).toBe(true)
    expect(res.text).not.toContain("super_secret_token_999")
    expect(res.text).not.toContain("AKIAIOSFODNN7EXAMPLE")
    expect(res.text).not.toContain("ghp_1234567890")
    expect(res.text).not.toContain("MIIEowIBAAKCAQEA")
    expect(res.matchedCategories).toEqual([
      "authorization_header",
      "aws_access_key",
      "github_token",
      "jwt",
      "pem_private_key",
    ])
  })
})
