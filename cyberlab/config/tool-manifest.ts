import { Schema } from "effect"

export const InventoryReviewStatusValues = [
  "candidate",
  "license_review",
  "approved_embed",
  "approved_internal_process",
  "plugin_only",
  "blocked",
  "revalidation_required",
] as const
export type InventoryReviewStatus = (typeof InventoryReviewStatusValues)[number]
export const InventoryReviewStatusSchema = Schema.Literals(InventoryReviewStatusValues)

export const ToolIntegrationModeValues = ["embedded", "internal_process", "plugin_only", "partner"] as const
export type ToolIntegrationMode = (typeof ToolIntegrationModeValues)[number]
export const ToolIntegrationModeSchema = Schema.Literals(ToolIntegrationModeValues)

const NonEmptyString = Schema.String.check(Schema.isMinLength(1))

export interface ToolComponentManifest {
  id: string
  version: string
  source: string
  commit: string
  license: {
    spdx: string
    reviewStatus: InventoryReviewStatus
    reviewNotes: string[]
  }
  integration: {
    mode: ToolIntegrationMode
    executorId?: string
    linuxRequired?: boolean
  }
  dependenciesReviewed: boolean
  noticesRecorded: boolean
  lastReviewedAt: string | null
}

export const ToolComponentManifestSchema = Schema.Struct({
  id: NonEmptyString,
  version: NonEmptyString,
  source: NonEmptyString,
  commit: NonEmptyString,
  license: Schema.Struct({
    spdx: NonEmptyString,
    reviewStatus: InventoryReviewStatusSchema,
    reviewNotes: Schema.Array(Schema.String),
  }),
  integration: Schema.Struct({
    mode: ToolIntegrationModeSchema,
    executorId: Schema.optionalKey(NonEmptyString),
    linuxRequired: Schema.optionalKey(Schema.Boolean),
  }),
  dependenciesReviewed: Schema.Boolean,
  noticesRecorded: Schema.Boolean,
  lastReviewedAt: Schema.Union([NonEmptyString, Schema.Null]),
}).annotate({ identifier: "CyberLab.ToolComponentManifest" })

export interface ManifestComplianceReport {
  validForDistribution: boolean
  violations: string[]
}

const APPROVED_EMBED_SPDX = new Set([
  "MIT",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Apache-2.0",
  "0BSD",
  "Unlicense",
])

export function validateToolManifest(input: unknown): ToolComponentManifest {
  const decoded = Schema.decodeUnknownSync(ToolComponentManifestSchema)(input)
  return {
    ...decoded,
    license: {
      ...decoded.license,
      reviewNotes: [...decoded.license.reviewNotes],
    },
    integration: {
      ...decoded.integration,
    },
  }
}

export function evaluateDistributionCompliance(manifest: ToolComponentManifest): ManifestComplianceReport {
  const violations: string[] = []
  const status = manifest.license.reviewStatus
  const spdx = manifest.license.spdx.trim()

  if (status === "blocked" || status === "revalidation_required") {
    violations.push(`Component "${manifest.id}" has status "${status}" and cannot be enabled in distribution builds`)
  }

  if (
    (status === "approved_embed" || status === "approved_internal_process") &&
    (spdx === "" || spdx.toUpperCase() === "UNKNOWN" || spdx === "LICENSE_IDENTIFIER_OR_UNKNOWN")
  ) {
    violations.push(`Component "${manifest.id}" is marked "${status}" with unknown SPDX identifier "${spdx}"`)
  }

  if (manifest.integration.mode === "embedded") {
    if (status !== "approved_embed") {
      violations.push(
        `Embedded component "${manifest.id}" must have reviewStatus "approved_embed" (found "${status}")`,
      )
    }
    if (!APPROVED_EMBED_SPDX.has(spdx)) {
      violations.push(`Embedded component "${manifest.id}" uses SPDX "${spdx}" not in embedded allowlist`)
    }
    if (!manifest.dependenciesReviewed) {
      violations.push(`Embedded component "${manifest.id}" requires dependenciesReviewed = true`)
    }
    if (!manifest.noticesRecorded) {
      violations.push(`Embedded component "${manifest.id}" requires noticesRecorded = true in THIRD_PARTY_NOTICES.md`)
    }
    if (!manifest.lastReviewedAt) {
      violations.push(`Embedded component "${manifest.id}" requires a non-null lastReviewedAt timestamp`)
    }
  }

  if (status === "approved_embed" && (!manifest.dependenciesReviewed || !manifest.noticesRecorded)) {
    violations.push(
      `Component "${manifest.id}" with status "approved_embed" must have both dependenciesReviewed and noticesRecorded set to true`,
    )
  }

  return {
    validForDistribution: violations.length === 0,
    violations,
  }
}
