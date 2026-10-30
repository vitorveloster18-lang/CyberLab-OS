import { Database } from "bun:sqlite"
import { chmodSync, existsSync, mkdirSync, openSync, closeSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import {
  validateEvidenceDraft,
  validateEvidenceRecord,
  validateSecurityFinding,
  type EvidenceDraft,
  type EvidenceRecord,
  type FindingSeverity,
  type FindingStatus,
  type RetentionClass,
  type SecurityFinding,
} from "../contracts/evidence.js"
import { sha256Hex } from "./hashing.js"
import { redactSensitiveContent, type CustodyAction, type CustodyEvent, type FindingRevision } from "./provenance.js"

export interface EvidenceStoreOptions {
  databasePath: string
  artifactsDir: string
  inlineMaxBytes?: number
}

export interface StoreEvidenceOptions {
  rawBytes?: Uint8Array
  parentEvidenceIds?: string[]
  derivedBy?: string
  sourceRevision?: string
  retentionClass?: RetentionClass
  applyRedactionBeforeStore?: boolean
  actor?: string
}

export interface IntegrityCheckResult {
  evidenceId: string
  valid: boolean
  expectedSha256: string
  actualSha256?: string
  reason?: string
}

function tightenFilePermissions(filePath: string): void {
  if (process.platform === "win32") return
  try {
    if (!existsSync(filePath)) {
      closeSync(openSync(filePath, "a", 0o600))
    }
    chmodSync(filePath, 0o600)
    for (const suffix of ["-wal", "-shm"]) {
      const sidecar = `${filePath}${suffix}`
      if (existsSync(sidecar)) chmodSync(sidecar, 0o600)
    }
  } catch {
    // Ignore on filesystems without POSIX mode support
  }
}

export class EvidenceStore {
  private readonly db: Database
  private readonly artifactsDir: string
  private readonly inlineMaxBytes: number

  constructor(options: EvidenceStoreOptions) {
    this.artifactsDir = path.resolve(options.artifactsDir)
    this.inlineMaxBytes = options.inlineMaxBytes ?? 16 * 1024

    mkdirSync(this.artifactsDir, { recursive: true, mode: 0o700 })
    if (options.databasePath !== ":memory:") {
      const resolvedDb = path.resolve(options.databasePath)
      mkdirSync(path.dirname(resolvedDb), { recursive: true, mode: 0o700 })
      tightenFilePermissions(resolvedDb)
      this.db = new Database(resolvedDb)
      this.bootstrap()
      tightenFilePermissions(resolvedDb)
    } else {
      this.db = new Database(":memory:")
      this.bootstrap()
    }
  }

  private bootstrap(): void {
    this.db.exec("PRAGMA journal_mode = WAL;")
    this.db.exec("PRAGMA synchronous = NORMAL;")
    this.db.exec("PRAGMA foreign_keys = ON;")
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cyberlab_evidence (
        evidence_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        record_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_cyberlab_evidence_project ON cyberlab_evidence(project_id);
      CREATE INDEX IF NOT EXISTS idx_cyberlab_evidence_execution ON cyberlab_evidence(execution_id);

      CREATE TABLE IF NOT EXISTS cyberlab_custody_events (
        event_id TEXT PRIMARY KEY,
        evidence_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_cyberlab_custody_evidence ON cyberlab_custody_events(evidence_id);

      CREATE TABLE IF NOT EXISTS cyberlab_findings (
        finding_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        status TEXT NOT NULL,
        severity TEXT NOT NULL,
        finding_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_cyberlab_findings_project ON cyberlab_findings(project_id);

      CREATE TABLE IF NOT EXISTS cyberlab_finding_revisions (
        revision_id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        revision_json TEXT NOT NULL,
        timestamp TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_cyberlab_revisions_finding ON cyberlab_finding_revisions(finding_id);
    `)
  }

  close(): void {
    this.db.close()
  }

  private appendCustody(
    evidenceId: string,
    projectId: string,
    action: CustodyAction,
    actor: string,
    details?: string,
  ): CustodyEvent {
    const event: CustodyEvent = {
      eventId: `cust-${crypto.randomUUID()}`,
      evidenceId,
      projectId,
      action,
      actor,
      ...(details !== undefined ? { details } : {}),
      timestamp: new Date().toISOString(),
    }
    this.db
      .query(
        `INSERT INTO cyberlab_custody_events (event_id, evidence_id, project_id, action, actor, details, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.eventId,
        event.evidenceId,
        event.projectId,
        event.action,
        event.actor,
        event.details ?? null,
        event.timestamp,
      )
    return event
  }

  storeEvidence(projectId: string, draft: EvidenceDraft, options: StoreEvidenceOptions = {}): EvidenceRecord {
    const normalizedInputDraft: EvidenceDraft =
      options.rawBytes !== undefined &&
      draft.content.inlineText === undefined &&
      draft.content.storageKey === undefined
        ? {
            ...draft,
            content: {
              ...draft.content,
              storageKey: sha256Hex(options.rawBytes),
            },
          }
        : draft
    const validatedDraft = validateEvidenceDraft(normalizedInputDraft)
    const now = new Date().toISOString()
    const evidenceId = `ev-${crypto.randomUUID()}`

    let rawBytes: Uint8Array
    let inlineText = validatedDraft.content.inlineText
    let redactionApplied = validatedDraft.redactionApplied ?? false
    let redactionStatus: EvidenceRecord["redactionStatus"] = redactionApplied ? "redacted" : "not_checked"

    if (options.rawBytes !== undefined) {
      rawBytes = options.rawBytes
    } else if (inlineText !== undefined) {
      if (options.applyRedactionBeforeStore) {
        const red = redactSensitiveContent(inlineText)
        inlineText = red.text
        redactionApplied = red.redacted
        redactionStatus = red.redacted ? "redacted" : "checked"
      } else {
        const probe = redactSensitiveContent(inlineText)
        redactionStatus = probe.redacted ? "not_checked" : redactionApplied ? "redacted" : "checked"
      }
      rawBytes = new TextEncoder().encode(inlineText)
    } else if (validatedDraft.content.storageKey) {
      const existingPath = this.resolveArtifactPath(validatedDraft.content.storageKey)
      rawBytes = new Uint8Array(readFileSync(existingPath))
    } else {
      throw new Error("Cannot store EvidenceDraft without rawBytes, inlineText, or existing storageKey")
    }

    const computedSha256 = sha256Hex(rawBytes)
    if (validatedDraft.content.sha256 && validatedDraft.content.sha256 !== computedSha256) {
      throw new Error(
        `EvidenceDraft sha256 mismatch: declared ${validatedDraft.content.sha256}, computed ${computedSha256}`,
      )
    }

    let storageKey = validatedDraft.content.storageKey
    let storedInlineText = inlineText

    // Offload large payloads or binary artifacts to local content-addressed storage
    if (options.rawBytes !== undefined || rawBytes.byteLength > this.inlineMaxBytes) {
      storageKey = computedSha256
      const artifactFile = this.resolveArtifactPath(storageKey)
      if (!existsSync(artifactFile)) {
        writeFileSync(artifactFile, rawBytes, { mode: 0o600 })
        tightenFilePermissions(artifactFile)
      }
      if (rawBytes.byteLength > this.inlineMaxBytes) {
        storedInlineText = undefined
      }
    }

    const record = validateEvidenceRecord({
      ...validatedDraft,
      evidenceId,
      projectId,
      createdAt: now,
      redactionApplied,
      content: {
        mediaType: validatedDraft.content.mediaType,
        ...(storageKey !== undefined ? { storageKey } : {}),
        ...(storedInlineText !== undefined ? { inlineText: storedInlineText } : {}),
        sha256: computedSha256,
        byteLength: rawBytes.byteLength,
      },
      provenance: {
        parentEvidenceIds: options.parentEvidenceIds ?? [],
        ...(options.derivedBy !== undefined ? { derivedBy: options.derivedBy } : {}),
        ...(options.sourceRevision !== undefined ? { sourceRevision: options.sourceRevision } : {}),
      },
      integrity: {
        sha256: computedSha256,
        immutable: true,
      },
      retentionClass: options.retentionClass ?? "project",
      redactionStatus,
    })

    this.db
      .query(
        `INSERT INTO cyberlab_evidence (evidence_id, project_id, execution_id, sha256, record_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        record.evidenceId,
        record.projectId,
        record.source.executionId,
        record.integrity.sha256,
        JSON.stringify(record),
        record.createdAt,
      )

    this.appendCustody(
      record.evidenceId,
      record.projectId,
      "collected",
      options.actor ?? `executor:${record.source.executorId}`,
      `sha256=${computedSha256} bytes=${rawBytes.byteLength}`,
    )

    return record
  }

  getEvidence(evidenceId: string, actorForAudit?: string): EvidenceRecord | undefined {
    const row = this.db
      .query(`SELECT record_json FROM cyberlab_evidence WHERE evidence_id = ?`)
      .get(evidenceId) as { record_json: string } | null
    if (!row) return undefined
    const record = validateEvidenceRecord(JSON.parse(row.record_json))
    if (actorForAudit) {
      this.appendCustody(record.evidenceId, record.projectId, "accessed", actorForAudit)
    }
    return record
  }

  listEvidence(projectId: string, executionId?: string): EvidenceRecord[] {
    const rows = executionId
      ? (this.db
          .query(
            `SELECT record_json FROM cyberlab_evidence WHERE project_id = ? AND execution_id = ? ORDER BY created_at ASC`,
          )
          .all(projectId, executionId) as Array<{ record_json: string }>)
      : (this.db
          .query(`SELECT record_json FROM cyberlab_evidence WHERE project_id = ? ORDER BY created_at ASC`)
          .all(projectId) as Array<{ record_json: string }>)
    return rows.map((r) => validateEvidenceRecord(JSON.parse(r.record_json)))
  }

  readRawBytes(evidenceId: string): Uint8Array {
    const record = this.getEvidence(evidenceId)
    if (!record) {
      throw new Error(`Evidence "${evidenceId}" not found`)
    }
    if (record.content.storageKey) {
      const artifactFile = this.resolveArtifactPath(record.content.storageKey)
      return new Uint8Array(readFileSync(artifactFile))
    }
    if (record.content.inlineText !== undefined) {
      return new TextEncoder().encode(record.content.inlineText)
    }
    throw new Error(`Evidence "${evidenceId}" has neither storageKey nor inlineText`)
  }

  /**
   * Produces redacted text safe for sharing with AI models or external partner runtimes.
   */
  readRedactedForSharing(evidenceId: string, recipientActor: string): { text: string; redacted: boolean; sha256: string } {
    const record = this.getEvidence(evidenceId)
    if (!record) {
      throw new Error(`Evidence "${evidenceId}" not found`)
    }
    const rawText = new TextDecoder("utf-8", { fatal: false }).decode(this.readRawBytes(evidenceId))
    const redacted = redactSensitiveContent(rawText)
    this.appendCustody(
      record.evidenceId,
      record.projectId,
      "redacted_share",
      recipientActor,
      `redacted=${redacted.redacted} categories=${redacted.matchedCategories.join(",") || "none"}`,
    )
    return {
      text: redacted.text,
      redacted: redacted.redacted,
      sha256: record.integrity.sha256,
    }
  }

  verifyIntegrity(evidenceId: string, actor: string = "system:verifier"): IntegrityCheckResult {
    const record = this.getEvidence(evidenceId)
    if (!record) {
      return {
        evidenceId,
        valid: false,
        expectedSha256: "",
        reason: "Evidence record not found",
      }
    }

    try {
      const bytes = this.readRawBytes(evidenceId)
      const actual = sha256Hex(bytes)
      const valid = actual === record.integrity.sha256
      this.appendCustody(
        record.evidenceId,
        record.projectId,
        valid ? "integrity_verified" : "integrity_failed",
        actor,
        `expected=${record.integrity.sha256} actual=${actual}`,
      )
      return {
        evidenceId,
        valid,
        expectedSha256: record.integrity.sha256,
        actualSha256: actual,
        ...(valid ? {} : { reason: "SHA-256 mismatch detected on stored evidence payload" }),
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.appendCustody(record.evidenceId, record.projectId, "integrity_failed", actor, message)
      return {
        evidenceId,
        valid: false,
        expectedSha256: record.integrity.sha256,
        reason: message,
      }
    }
  }

  getCustodyChain(evidenceId: string): CustodyEvent[] {
    const rows = this.db
      .query(
        `SELECT event_id, evidence_id, project_id, action, actor, details, timestamp
         FROM cyberlab_custody_events WHERE evidence_id = ? ORDER BY rowid ASC`,
      )
      .all(evidenceId) as Array<{
      event_id: string
      evidence_id: string
      project_id: string
      action: CustodyAction
      actor: string
      details: string | null
      timestamp: string
    }>

    return rows.map((r) => ({
      eventId: r.event_id,
      evidenceId: r.evidence_id,
      projectId: r.project_id,
      action: r.action,
      actor: r.actor,
      ...(r.details !== null ? { details: r.details } : {}),
      timestamp: r.timestamp,
    }))
  }

  createFinding(input: {
    projectId: string
    title: string
    description: string
    severity: FindingSeverity
    status?: FindingStatus
    confidence?: number
    evidenceIds: string[]
    affectedAssets: string[]
    proposedRemediation?: string
    validationEvidenceIds?: string[]
    createdBy?: string
  }): SecurityFinding {
    // Verify referenced evidence belongs to the project
    for (const evId of input.evidenceIds) {
      const ev = this.getEvidence(evId)
      if (!ev || ev.projectId !== input.projectId) {
        throw new Error(`Evidence "${evId}" does not exist in project "${input.projectId}"`)
      }
    }

    const now = new Date().toISOString()
    const finding = validateSecurityFinding({
      findingId: `find-${crypto.randomUUID()}`,
      projectId: input.projectId,
      title: input.title,
      description: input.description,
      severity: input.severity,
      status: input.status ?? "unreviewed",
      ...(input.confidence !== undefined ? { confidence: input.confidence } : {}),
      evidenceIds: input.evidenceIds,
      affectedAssets: input.affectedAssets,
      ...(input.proposedRemediation !== undefined ? { proposedRemediation: input.proposedRemediation } : {}),
      validationEvidenceIds: input.validationEvidenceIds ?? [],
      createdAt: now,
      updatedAt: now,
    })

    this.db
      .query(
        `INSERT INTO cyberlab_findings (finding_id, project_id, status, severity, finding_json, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(finding.findingId, finding.projectId, finding.status, finding.severity, JSON.stringify(finding), now)

    this.recordFindingRevision({
      finding,
      newStatus: finding.status,
      changedBy: input.createdBy ?? "system",
      notes: "Initial finding recorded",
      timestamp: now,
    })

    return finding
  }

  reviewFinding(input: {
    findingId: string
    reviewedBy: string
    decision: "accept" | "reject" | "needs_more_evidence"
    notes?: string
    validationEvidenceIds?: string[]
  }): SecurityFinding {
    const existing = this.getFinding(input.findingId)
    if (!existing) {
      throw new Error(`SecurityFinding "${input.findingId}" not found`)
    }

    const now = new Date().toISOString()
    const nextStatus: FindingStatus =
      input.decision === "accept"
        ? "confirmed"
        : input.decision === "reject"
          ? "rejected"
          : "inconclusive"

    const mergedValidationIds = input.validationEvidenceIds
      ? Array.from(new Set([...existing.validationEvidenceIds, ...input.validationEvidenceIds]))
      : existing.validationEvidenceIds

    const updated = validateSecurityFinding({
      ...existing,
      status: nextStatus,
      validationEvidenceIds: mergedValidationIds,
      updatedAt: now,
      review: {
        reviewedBy: input.reviewedBy,
        decision: input.decision,
        ...(input.notes !== undefined ? { notes: input.notes } : {}),
        reviewedAt: now,
      },
    })

    this.db
      .query(`UPDATE cyberlab_findings SET status = ?, finding_json = ?, updated_at = ? WHERE finding_id = ?`)
      .run(updated.status, JSON.stringify(updated), now, updated.findingId)

    this.recordFindingRevision({
      finding: updated,
      previousStatus: existing.status,
      newStatus: updated.status,
      changedBy: input.reviewedBy,
      notes: input.notes,
      timestamp: now,
    })

    return updated
  }

  getFinding(findingId: string): SecurityFinding | undefined {
    const row = this.db
      .query(`SELECT finding_json FROM cyberlab_findings WHERE finding_id = ?`)
      .get(findingId) as { finding_json: string } | null
    if (!row) return undefined
    return validateSecurityFinding(JSON.parse(row.finding_json))
  }

  listFindings(projectId: string): SecurityFinding[] {
    const rows = this.db
      .query(`SELECT finding_json FROM cyberlab_findings WHERE project_id = ? ORDER BY updated_at DESC`)
      .all(projectId) as Array<{ finding_json: string }>
    return rows.map((r) => validateSecurityFinding(JSON.parse(r.finding_json)))
  }

  getFindingHistory(findingId: string): FindingRevision[] {
    const rows = this.db
      .query(`SELECT revision_json FROM cyberlab_finding_revisions WHERE finding_id = ? ORDER BY rowid ASC`)
      .all(findingId) as Array<{ revision_json: string }>
    return rows.map((r) => JSON.parse(r.revision_json) as FindingRevision)
  }

  private recordFindingRevision(params: {
    finding: SecurityFinding
    previousStatus?: FindingStatus
    newStatus: FindingStatus
    changedBy: string
    notes?: string
    timestamp: string
  }): void {
    const revision: FindingRevision = {
      revisionId: `frev-${crypto.randomUUID()}`,
      findingId: params.finding.findingId,
      projectId: params.finding.projectId,
      ...(params.previousStatus !== undefined ? { previousStatus: params.previousStatus } : {}),
      newStatus: params.newStatus,
      changedBy: params.changedBy,
      ...(params.notes !== undefined ? { notes: params.notes } : {}),
      snapshot: params.finding,
      timestamp: params.timestamp,
    }
    this.db
      .query(
        `INSERT INTO cyberlab_finding_revisions (revision_id, finding_id, project_id, revision_json, timestamp)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(revision.revisionId, revision.findingId, revision.projectId, JSON.stringify(revision), revision.timestamp)
  }

  private resolveArtifactPath(storageKey: string): string {
    if (!/^[a-zA-Z0-9._-]+$/.test(storageKey) || storageKey === "." || storageKey === "..") {
      throw new Error(`Invalid storageKey "${storageKey}"`)
    }
    const resolved = path.resolve(this.artifactsDir, storageKey)
    if (path.dirname(resolved) !== this.artifactsDir) {
      throw new Error(`Artifact path traversal blocked for "${storageKey}"`)
    }
    return resolved
  }
}
