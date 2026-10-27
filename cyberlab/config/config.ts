import os from "node:os"
import path from "node:path"

export interface CyberLabRuntimeConfig {
  dataDirectory: string
  artifactsDirectory: string
  databaseFilename: string
  defaultTimeoutMs: number
  maxOutputBytes: number
  maxPartnerEnvelopeBytes: number
  partnerMaxClockSkewMs: number
  requireLinuxForNativeTools: boolean
}

export interface RuntimeEnvironmentReport {
  platform: NodeJS.Platform
  arch: string
  release: string
  isLinux: boolean
  isWsl2: boolean
  workspaceOnWindowsMount: boolean
}

export function createDefaultCyberLabConfig(workspaceRoot: string): CyberLabRuntimeConfig {
  const dataDirectory = path.join(workspaceRoot, ".cyberlab")
  return {
    dataDirectory,
    artifactsDirectory: path.join(dataDirectory, "artifacts"),
    databaseFilename: path.join(dataDirectory, "cyberlab-evidence.sqlite"),
    defaultTimeoutMs: 30_000,
    maxOutputBytes: 1024 * 1024, // 1 MiB raw output cap per stream
    maxPartnerEnvelopeBytes: 256 * 1024, // 256 KiB envelope cap
    partnerMaxClockSkewMs: 5 * 60 * 1000, // 5 minutes anti-replay window
    requireLinuxForNativeTools: true,
  }
}

export function detectRuntimeEnvironment(workspaceRoot: string): RuntimeEnvironmentReport {
  const platform = os.platform()
  const release = os.release()
  const isLinux = platform === "linux"
  const isWsl2 = isLinux && /microsoft|wsl/i.test(release)
  const normalized = workspaceRoot.replace(/\\/g, "/")
  const workspaceOnWindowsMount = isWsl2 && /^\/mnt\/[a-z]\//i.test(normalized)

  return {
    platform,
    arch: os.arch(),
    release,
    isLinux,
    isWsl2,
    workspaceOnWindowsMount,
  }
}
