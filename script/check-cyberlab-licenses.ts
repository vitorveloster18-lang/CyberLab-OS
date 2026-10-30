#!/usr/bin/env bun

import { readdirSync, readFileSync, existsSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { evaluateDistributionCompliance, validateToolManifest } from "../cyberlab/config/tool-manifest.js"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const manifestsDir = path.join(repoRoot, "vendor", "manifests")
const noticesPath = path.join(repoRoot, "vendor", "THIRD_PARTY_NOTICES.md")

export interface LicenseCheckSummary {
  checkedCount: number
  embeddedCount: number
  violations: string[]
}

export function verifyRepositoryLicenseCompliance(
  customManifestsDir = manifestsDir,
  customNoticesPath = noticesPath,
): LicenseCheckSummary {
  const violations: string[] = []

  if (!existsSync(customManifestsDir)) {
    return {
      checkedCount: 0,
      embeddedCount: 0,
      violations: [`Manifest directory missing: ${customManifestsDir}`],
    }
  }

  if (!existsSync(customNoticesPath)) {
    return {
      checkedCount: 0,
      embeddedCount: 0,
      violations: [`Third-party notices file missing: ${customNoticesPath}`],
    }
  }

  const noticesContent = readFileSync(customNoticesPath, "utf8")
  const files = readdirSync(customManifestsDir)
    .filter((f) => f.endsWith(".json"))
    .sort()

  if (files.length === 0) {
    violations.push(`No manifest JSON files found in ${customManifestsDir}`)
  }

  let embeddedCount = 0

  for (const file of files) {
    const fullPath = path.join(customManifestsDir, file)
    try {
      const parsed = JSON.parse(readFileSync(fullPath, "utf8")) as unknown
      const manifest = validateToolManifest(parsed)
      const report = evaluateDistributionCompliance(manifest)
      if (!report.validForDistribution) {
        for (const v of report.violations) {
          violations.push(`[${file}] ${v}`)
        }
      }
      if (manifest.integration.mode === "embedded" || manifest.license.reviewStatus === "approved_embed") {
        embeddedCount++
        if (!noticesContent.includes(manifest.id)) {
          violations.push(
            `[${file}] Embedded component "${manifest.id}" is not documented in THIRD_PARTY_NOTICES.md`,
          )
        }
      }
    } catch (err) {
      violations.push(`[${file}] Schema validation failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  return {
    checkedCount: files.length,
    embeddedCount,
    violations,
  }
}

if (import.meta.main) {
  const summary = verifyRepositoryLicenseCompliance()
  if (summary.violations.length > 0) {
    console.error("CyberLab License Compliance Check FAILED:")
    for (const v of summary.violations) {
      console.error(`  - ${v}`)
    }
    process.exit(1)
  }
  console.log(
    `CyberLab License Compliance OK: verified ${summary.checkedCount} manifest(s) (${summary.embeddedCount} embedded, 0 violations).`,
  )
}
