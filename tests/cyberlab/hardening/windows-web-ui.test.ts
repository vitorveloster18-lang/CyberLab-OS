import { describe, expect, test } from "bun:test"

const appAssetsUrl = new URL("../../../packages/cli/src/app-assets.ts", import.meta.url).href
const appArchiveUrl = new URL("../../../packages/cli/src/app-archive.ts", import.meta.url).href

describe("Windows Web UI Asset Path Normalization", () => {
  test("converts Windows backslash relative paths to URL forward-slash asset keys", async () => {
    const mod = (await import(appAssetsUrl)) as { normalizeAssetKey: (file: string) => string }
    expect(mod.normalizeAssetKey("_assets\\index-Bk8_2abc.js")).toBe("_assets/index-Bk8_2abc.js")
    expect(mod.normalizeAssetKey("_assets\\styles\\main.css")).toBe("_assets/styles/main.css")
    expect(mod.normalizeAssetKey("icons\\dev\\favicon.ico")).toBe("icons/dev/favicon.ico")
    expect(mod.normalizeAssetKey("\\_assets\\vendor.js")).toBe("_assets/vendor.js")
    expect(mod.normalizeAssetKey("index.html")).toBe("index.html")
  })

  test("AppArchive.decode normalizes any embedded backslash keys", async () => {
    const AppArchive = (await import(appArchiveUrl)) as {
      encode: (entries: ReadonlyArray<readonly [string, Uint8Array]>) => Buffer
      decode: (archive: Uint8Array) => Readonly<Record<string, Uint8Array>>
    }
    const payload = new TextEncoder().encode("console.log('cyberlab');")
    const archive = AppArchive.encode([
      ["_assets\\bundle.js", payload],
      ["icons\\logo.svg", payload],
    ])
    const decoded = AppArchive.decode(archive)
    expect(decoded["_assets/bundle.js"]).toBeDefined()
    expect(decoded["icons/logo.svg"]).toBeDefined()
    expect(new TextDecoder().decode(decoded["_assets/bundle.js"])).toBe("console.log('cyberlab');")
  })
})
