import { createHash } from "node:crypto"

export function sha256Hex(data: string | Uint8Array): string {
  const hash = createHash("sha256")
  if (typeof data === "string") {
    hash.update(data, "utf8")
  } else {
    hash.update(data)
  }
  return hash.digest("hex")
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`
  }
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`
}

export interface ManifestEntryHash {
  id: string
  sha256: string
  byteLength: number
}

export function computeBundleManifestHash(entries: readonly ManifestEntryHash[]): string {
  const sorted = [...entries].sort((a, b) => a.id.localeCompare(b.id))
  return sha256Hex(canonicalJson(sorted))
}
