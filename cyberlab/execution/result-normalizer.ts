import type { EvidenceDraft, EvidenceKind } from "../contracts/evidence.js"
import { capOutputBytes } from "./cancellation.js"

export interface RawOutputNormalizationParams {
  kind: EvidenceKind
  title: string
  toolId: string
  toolVersion?: string
  executorId: string
  executionId: string
  mediaType: string
  rawText: string
  maxOutputBytes: number
  labels?: string[]
}

export function normalizeRawOutputDraft(params: RawOutputNormalizationParams): EvidenceDraft {
  const capped = capOutputBytes(params.rawText, params.maxOutputBytes)
  const labels = [...(params.labels ?? [])]
  if (capped.truncated && !labels.includes("truncated")) {
    labels.push("truncated")
  }

  return {
    kind: params.kind,
    title: params.title,
    source: {
      toolId: params.toolId,
      ...(params.toolVersion !== undefined ? { toolVersion: params.toolVersion } : {}),
      executorId: params.executorId,
      executionId: params.executionId,
    },
    content: {
      mediaType: params.mediaType,
      inlineText: capped.text,
    },
    observedAt: new Date().toISOString(),
    ...(labels.length > 0 ? { labels } : {}),
  }
}
