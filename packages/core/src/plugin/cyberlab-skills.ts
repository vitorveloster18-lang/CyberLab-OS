export * as CyberLabSkillsPlugin from "./cyberlab-skills.js"

import { fileURLToPath } from "node:url"
import { define } from "@opencode/plugin/effect/plugin"
import { FSUtil } from "@opencode/util/fs-util"
import { Effect } from "effect"
import type { Skill } from "../skill.js"
import { SkillFile } from "../config/plugin/skill-file.js"
import { SkillScan } from "../config/plugin/skill-scan.js"

const builtinSkillsDirectory = fileURLToPath(new URL("../../../../skills", import.meta.url))

export const Plugin = define({
  id: "cyberlab.skills",
  effect: Effect.fn("CyberLabSkillsPlugin")(function* (ctx) {
    const fs = yield* FSUtil.Service
    const isDir = yield* fs.isDir(builtinSkillsDirectory).pipe(Effect.orElseSucceed(() => false))
    if (!isDir) return

    const files = yield* SkillScan.scan(builtinSkillsDirectory)
    const skills: Skill.Info[] = []
    for (const filepath of files) {
      const content = yield* fs.readFileStringSafe(filepath).pipe(Effect.orElseSucceed(() => undefined))
      if (!content) continue
      const parsed = SkillFile.parse(builtinSkillsDirectory, filepath, content)
      if (parsed._tag === "Parsed") {
        skills.push(parsed.skill)
      }
    }

    yield* ctx.skill.transform((editor) => {
      for (const skill of skills) {
        if (!editor.get(skill.id)) {
          editor.add(skill)
        }
      }
    })
  }),
})
