import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import type { EvidenceRecord, SecurityFinding } from "../contracts/evidence.js"
import { computeBundleManifestHash, sha256Hex } from "../evidence/hashing.js"
import type { EvidenceStore } from "../evidence/store.js"

export interface ExportedEvidenceBundleManifest {
  bundleVersion: "1.0"
  projectId: string
  exportedAt: string
  redacted: boolean
  items: Array<{
    evidenceId: string
    fileName: string
    mediaType: string
    sha256: string
    byteLength: number
  }>
  findingsFile: string
  findingsSha256: string
  manifestHash: string
}

export function exportEvidenceBundle(params: {
  store: EvidenceStore
  projectId: string
  outputDir: string
  redactPayloads?: boolean
  actor?: string
}): ExportedEvidenceBundleManifest {
  const outDir = path.resolve(params.outputDir)
  const blobsDir = path.join(outDir, "blobs")
  mkdirSync(blobsDir, { recursive: true, mode: 0o700 })

  const evidenceList = params.store.listEvidence(params.projectId)
  const findings = params.store.listFindings(params.projectId)
  const actor = params.actor ?? "operator:exporter"

  const items: ExportedEvidenceBundleManifest["items"] = []

  for (const ev of evidenceList) {
    let payloadBytes: Uint8Array
    if (params.redactPayloads) {
      const shared = params.store.readRedactedForSharing(ev.evidenceId, actor)
      payloadBytes = new TextEncoder().encode(shared.text)
    } else {
      payloadBytes = params.store.readRawBytes(ev.evidenceId)
    }

    const fileHash = sha256Hex(payloadBytes)
    const fileName = `${ev.evidenceId}.bin`
    writeFileSync(path.join(blobsDir, fileName), payloadBytes, { mode: 0o600 })

    items.push({
      evidenceId: ev.evidenceId,
      fileName: `blobs/${fileName}`,
      mediaType: ev.content.mediaType,
      sha256: fileHash,
      byteLength: payloadBytes.byteLength,
    })
  }

  const metadataPayload = JSON.stringify({ evidence: evidenceList, findings }, null, 2)
  const findingsFile = "findings-and-metadata.json"
  const findingsBytes = new TextEncoder().encode(metadataPayload)
  const findingsSha256 = sha256Hex(findingsBytes)
  writeFileSync(path.join(outDir, findingsFile), findingsBytes, { mode: 0o600 })

  const manifestHash = computeBundleManifestHash([
    ...items.map((i) => ({ id: i.evidenceId, sha256: i.sha256, byteLength: i.byteLength })),
    { id: findingsFile, sha256: findingsSha256, byteLength: findingsBytes.byteLength },
  ])

  const manifest: ExportedEvidenceBundleManifest = {
    bundleVersion: "1.0",
    projectId: params.projectId,
    exportedAt: new Date().toISOString(),
    redacted: Boolean(params.redactPayloads),
    items,
    findingsFile,
    findingsSha256,
    manifestHash,
  }

  writeFileSync(path.join(outDir, "manifest.json"), JSON.stringify(manifest, null, 2), { mode: 0o600 })
  return manifest
}

export function verifyExportedBundle(bundleDir: string): { valid: boolean; errors: string[] } {
  const dir = path.resolve(bundleDir)
  const manifestPath = path.join(dir, "manifest.json")
  if (!existsSync(manifestPath)) {
    return { valid: false, errors: ["manifest.json is missing"] }
  }

  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as ExportedEvidenceBundleManifest
  const errors: string[] = []

  for (const item of manifest.items) {
    const itemPath = path.resolve(dir, item.fileName)
    if (!existsSync(itemPath)) {
      errors.push(`Missing blob file: ${item.fileName}`)
      continue
    }
    const bytes = new Uint8Array(readFileSync(itemPath))
    const actualHash = sha256Hex(bytes)
    if (actualHash !== item.sha256) {
      errors.push(`SHA-256 mismatch for ${item.evidenceId}: expected ${item.sha256}, got ${actualHash}`)
    }
  }

  const findingsPath = path.resolve(dir, manifest.findingsFile)
  let findingsByteLength = 0
  if (!existsSync(findingsPath)) {
    errors.push(`Missing findings metadata file: ${manifest.findingsFile}`)
  } else {
    const fBytes = new Uint8Array(readFileSync(findingsPath))
    findingsByteLength = fBytes.byteLength
    const fHash = sha256Hex(fBytes)
    if (fHash !== manifest.findingsSha256) {
      errors.push(`Findings file SHA-256 mismatch: expected ${manifest.findingsSha256}, got ${fHash}`)
    }
  }

  const expectedManifestHash = computeBundleManifestHash([
    ...manifest.items.map((i) => ({ id: i.evidenceId, sha256: i.sha256, byteLength: i.byteLength })),
    { id: manifest.findingsFile, sha256: manifest.findingsSha256, byteLength: findingsByteLength },
  ])
  if (expectedManifestHash !== manifest.manifestHash) {
    errors.push(`Root manifestHash mismatch: expected ${manifest.manifestHash}, got ${expectedManifestHash}`)
  }

  return {
    valid: errors.length === 0,
    errors,
  }
}

export type { EvidenceRecord, SecurityFinding }
