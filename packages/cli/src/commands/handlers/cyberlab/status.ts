import { Effect } from "effect"
import { EOL } from "node:os"
import { Commands } from "../../commands"
import { Runtime } from "../../../framework/runtime"
import { openLocalCyberLabWorkspace } from "./_workspace"

export default Runtime.handler(
  Commands.commands.cyberlab.commands.status,
  Effect.fn("cli.cyberlab.status")(function* (
    input: Runtime.Input<typeof Commands.commands.cyberlab.commands.status>,
  ) {
    const ws = yield* Effect.promise(() => openLocalCyberLabWorkspace())
    const status = yield* Effect.promise(() => ws.getStatus())
    if (input.json) {
      process.stdout.write(JSON.stringify(status, null, 2) + EOL)
      return
    }
    const lines = [
      `CyberLab OS Workspace (${status.projectId})`,
      `  Root: ${status.workspaceRoot}`,
      `  Platform: ${status.environment.platform}/${status.environment.arch} (Linux=${status.environment.isLinux}, WSL2=${status.environment.isWsl2})`,
      `  External Targets Allowed: ${status.activeScope?.allowExternalTargets ?? false}`,
      `  Capabilities: ${status.capabilityCount} | Skills: ${status.skillCount}`,
      `  Executions: ${status.executionCount} (Pending Approvals: ${status.pendingApprovalCount})`,
      `  Evidence Records: ${status.evidenceCount} | Findings: ${status.findingCount}`,
    ]
    process.stdout.write(lines.join(EOL) + EOL)
  }),
)
