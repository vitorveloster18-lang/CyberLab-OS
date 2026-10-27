import { validateExecutionRecord, type ExecutionRecord, type ExecutionStatus } from "../contracts/execution.js"

const ALLOWED_TRANSITIONS: Record<ExecutionStatus, ReadonlySet<ExecutionStatus>> = {
  draft: new Set(["awaiting_approval", "queued", "blocked", "cancelled"]),
  awaiting_approval: new Set(["queued", "blocked", "cancelled"]),
  queued: new Set(["running", "blocked", "cancelled", "failed"]),
  running: new Set(["succeeded", "failed", "cancelled", "timed_out"]),
  succeeded: new Set([]),
  failed: new Set([]),
  cancelled: new Set([]),
  blocked: new Set([]),
  timed_out: new Set([]),
}

export function isTerminalExecutionStatus(status: ExecutionStatus): boolean {
  return ALLOWED_TRANSITIONS[status].size === 0
}

export function transitionExecutionRecord(
  current: ExecutionRecord,
  nextStatus: ExecutionStatus,
  patch: Partial<Omit<ExecutionRecord, "executionId" | "request" | "status">> = {},
): ExecutionRecord {
  if (current.status !== nextStatus && !ALLOWED_TRANSITIONS[current.status].has(nextStatus)) {
    throw new Error(`Invalid execution lifecycle transition: "${current.status}" -> "${nextStatus}"`)
  }
  return validateExecutionRecord({
    ...current,
    ...patch,
    status: nextStatus,
  })
}
