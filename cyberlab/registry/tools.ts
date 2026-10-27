import type { CyberLabExecutor } from "../contracts/execution.js"
import type { ToolComponentManifest } from "../config/tool-manifest.js"
import { evaluateDistributionCompliance, validateToolManifest } from "../config/tool-manifest.js"

export interface RegisteredToolMetadata {
  id: string
  version: string
  capabilities: string[]
  systemRequirements: string[]
  inputSchemas: string[]
  outputSchemas: string[]
  skillIds: string[]
  manifest: ToolComponentManifest
  knownLimitations: string[]
}

export class ExecutorRegistry {
  private readonly executors = new Map<string, CyberLabExecutor>()
  private readonly tools = new Map<string, RegisteredToolMetadata>()

  registerExecutor(executor: CyberLabExecutor): void {
    if (!executor.id.trim()) {
      throw new Error("Executor id cannot be empty")
    }
    this.executors.set(executor.id, executor)
  }

  getExecutor(executorId: string): CyberLabExecutor | undefined {
    return this.executors.get(executorId)
  }

  listExecutors(): CyberLabExecutor[] {
    return Array.from(this.executors.values())
  }

  registerToolMetadata(metadata: RegisteredToolMetadata, options?: { enforceDistributionGate?: boolean }): void {
    const manifest = validateToolManifest(metadata.manifest)
    if (options?.enforceDistributionGate) {
      const compliance = evaluateDistributionCompliance(manifest)
      if (!compliance.validForDistribution) {
        throw new Error(`Tool "${metadata.id}" failed license compliance: ${compliance.violations.join("; ")}`)
      }
    }
    this.tools.set(metadata.id, { ...metadata, manifest })
  }

  getToolMetadata(toolId: string): RegisteredToolMetadata | undefined {
    return this.tools.get(toolId)
  }

  listToolMetadata(): RegisteredToolMetadata[] {
    return Array.from(this.tools.values())
  }
}
