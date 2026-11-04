export const SUBAGENT_GUARDRAIL_DEFAULTS = {
  maxDepth: 1,
  maxConcurrentPerSession: 3,
  maxTotalPerSession: 12,
} as const

export function getSubagentGuardrailLimits(experimentalSubagentDepth?: number) {
  const envConcurrent = Number(process.env.CYBERLAB_MAX_CONCURRENT_SUBAGENTS)
  const envTotal = Number(process.env.CYBERLAB_MAX_SESSION_SUBAGENTS)
  return {
    maxDepth: experimentalSubagentDepth ?? SUBAGENT_GUARDRAIL_DEFAULTS.maxDepth,
    maxConcurrentPerSession:
      Number.isFinite(envConcurrent) && envConcurrent > 0
        ? Math.floor(envConcurrent)
        : SUBAGENT_GUARDRAIL_DEFAULTS.maxConcurrentPerSession,
    maxTotalPerSession:
      Number.isFinite(envTotal) && envTotal > 0
        ? Math.floor(envTotal)
        : SUBAGENT_GUARDRAIL_DEFAULTS.maxTotalPerSession,
  }
}

export function checkSubagentGuardrails(params: {
  depth: number
  activeConcurrentCount: number
  totalSpawnedInSession: number
  isExistingChildSession: boolean
  experimentalSubagentDepth?: number
}): { allowed: true } | { allowed: false; reason: string } {
  const limits = getSubagentGuardrailLimits(params.experimentalSubagentDepth)

  if (params.depth >= limits.maxDepth) {
    return {
      allowed: false,
      reason: `Subagent depth limit reached (${limits.maxDepth}). Subagents cannot create nested subagents unless "experimental.subagent_depth" is explicitly increased.`,
    }
  }

  if (params.activeConcurrentCount >= limits.maxConcurrentPerSession) {
    return {
      allowed: false,
      reason: `Subagent concurrency limit reached (${limits.maxConcurrentPerSession} concurrent subagents per session). Wait for active subagents to finish before launching another.`,
    }
  }

  if (!params.isExistingChildSession && params.totalSpawnedInSession >= limits.maxTotalPerSession) {
    return {
      allowed: false,
      reason: `Subagent session budget reached (${limits.maxTotalPerSession} new subagents per parent session). Reuse an existing subagent sessionID or synthesize directly in the Orchestrator.`,
    }
  }

  return { allowed: true }
}
