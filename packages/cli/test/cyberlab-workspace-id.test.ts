import { describe, expect, test } from "bun:test"
import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdtempSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { resolveLocalCyberLabProjectId } from "../src/commands/handlers/cyberlab/_workspace"

const sha1 = (input: string) => createHash("sha1").update(input).digest("hex")

describe("resolveLocalCyberLabProjectId (identidade unificada CLI/servidor)", () => {
  test("CYBERLAB_PROJECT_ID tem precedência", () => {
    const prev = process.env.CYBERLAB_PROJECT_ID
    process.env.CYBERLAB_PROJECT_ID = "manual-id"
    try {
      expect(resolveLocalCyberLabProjectId("/algum/dir")).toBe("manual-id")
    } finally {
      if (prev === undefined) delete process.env.CYBERLAB_PROJECT_ID
      else process.env.CYBERLAB_PROJECT_ID = prev
    }
  })

  test("sem VCS: hash do diretório (igual ao fallback do servidor)", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "cl-nogit-"))
    try {
      expect(resolveLocalCyberLabProjectId(dir)).toBe(sha1(`directory:${dir}`))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("com remoto git: sha1(git-remote:<host>/<path>) — o mesmo ID do servidor", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "cl-git-"))
    try {
      execFileSync("git", ["init", "-q"], { cwd: dir })
      execFileSync("git", ["remote", "add", "origin", "https://github.com/acme/lab.git"], { cwd: dir })
      expect(resolveLocalCyberLabProjectId(dir)).toBe(sha1("git-remote:github.com/acme/lab"))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("remoto SCP (git@host:path) normaliza igual ao servidor", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "cl-scp-"))
    try {
      execFileSync("git", ["init", "-q"], { cwd: dir })
      execFileSync("git", ["remote", "add", "origin", "git@github.com:acme/lab.git"], { cwd: dir })
      expect(resolveLocalCyberLabProjectId(dir)).toBe(sha1("git-remote:github.com/acme/lab"))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
