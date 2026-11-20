import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { EvidenceStore } from "../../../cyberlab/index.js"

/**
 * Migração de identidade de projeto (CLI `proj-<basename>` → ID unificado).
 *
 * O CLI antigo e o servidor partiam o mesmo SQLite em duas partições. Ao
 * unificar a identidade, os dados da partição legada precisam ser movidos
 * (coluna project_id + JSON embutido) para não ficarem órfãos.
 */
describe("CyberLab Project ID Migration (reassignProjectId)", () => {
  test("moves evidence, findings and revisions from legacy to unified ID", () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "cyberlab-migrate-"))
    try {
      const store = new EvidenceStore({
        databasePath: path.join(tmpDir, "evidence.sqlite"),
        artifactsDir: path.join(tmpDir, "artifacts"),
      })

      const legacy = "proj-cl-test"
      const unified = "fe11f1ed5ba839ef8174b41fcbdb0cd658cbb7fb"

      const ev = store.storeEvidence(legacy, {
        kind: "stdout",
        title: "probe",
        source: { toolId: "test", executorId: "test-exec", executionId: "exec-1" },
        content: { mediaType: "text/plain", inlineText: "hello" },
        observedAt: new Date().toISOString(),
      })

      const finding = store.createFinding({
        projectId: legacy,
        title: "bypass",
        description: "d",
        severity: "high",
        evidenceIds: [ev.evidenceId],
        affectedAssets: ["10.0.0.5"],
        createdBy: "test",
      })

      // Antes: invisível sob o ID unificado.
      expect(store.listEvidence(unified)).toEqual([])
      expect(store.listFindings(unified)).toEqual([])

      const moved = store.reassignProjectId(legacy, unified)
      expect(moved).toBeGreaterThanOrEqual(3) // evidence + finding + revision + custody

      // Depois: visível e com projectId consistente no JSON.
      const evList = store.listEvidence(unified)
      expect(evList).toHaveLength(1)
      expect(evList[0]!.projectId).toBe(unified)

      const findingList = store.listFindings(unified)
      expect(findingList).toHaveLength(1)
      expect(findingList[0]!.findingId).toBe(finding.findingId)
      expect(findingList[0]!.projectId).toBe(unified)

      // Revisão também migrada (snapshot incluso).
      const history = store.getFindingHistory(finding.findingId)
      expect(history.length).toBeGreaterThanOrEqual(1)
      expect(history[0]!.projectId).toBe(unified)
      expect(history[0]!.snapshot.projectId).toBe(unified)

      // Partição legada esvaziada.
      expect(store.listEvidence(legacy)).toEqual([])
      expect(store.listFindings(legacy)).toEqual([])

      // Idempotente: segunda chamada não move nada.
      expect(store.reassignProjectId(legacy, unified)).toBe(0)

      // No-op quando origem === destino.
      expect(store.reassignProjectId(unified, unified)).toBe(0)

      store.close()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
