import { Effect, FileSystem, Option } from "effect"
import { readFileSync } from "node:fs"
import path from "node:path"
import { brotliDecompressSync } from "node:zlib"
import { AppArchive } from "./app-archive"
import { OPENCODE_LOCAL } from "./version"

export type AssetMap = Readonly<Record<string, string | Uint8Array>>
/** Each asset's brotli-compressed bytes, when the build embedded them. */
export type BrotliMap = Readonly<Record<string, Uint8Array>>

/** Normalizes OS-specific relative paths (such as Windows `_assets\index.js`) to URL-style `/` asset keys. */
export function normalizeAssetKey(file: string): string {
  return file.replaceAll("\\", "/").replace(/^\/+/, "")
}

const LOCAL_SELF_UNREGISTER_SW = new TextEncoder().encode(
  [
    "self.addEventListener('install', () => { self.skipWaiting(); });",
    "self.addEventListener('activate', (event) => {",
    "  event.waitUntil(",
    "    caches.keys()",
    "      .then((keys) => Promise.all(keys.map((key) => caches.delete(key))))",
    "      .then(() => self.registration.unregister())",
    "      .then(() => self.clients.matchAll({ type: 'window' }))",
    "      .then((clients) => { for (const client of clients) client.navigate(client.url); })",
    "  );",
    "});",
  ].join("\n"),
)

export const load = Effect.fn("cli.app-assets.load")(function* () {
  const embedded = yield* Effect.tryPromise(() => import("virtual:opencode-app-assets")).pipe(
    Effect.map((module) => AppArchive.decode(module.default())),
    Effect.option,
  )
  if (Option.isSome(embedded) && (Object.keys(embedded.value).length > 0 || !OPENCODE_LOCAL))
    return {
      files: lazy(embedded.value, (key) => brotliDecompressSync(embedded.value[key]!)),
      brotli: embedded.value,
    }
  if (!OPENCODE_LOCAL) return yield* Effect.fail(new Error("Web UI assets are missing from the CLI build"))
  return { files: yield* sourceAssets(), brotli: undefined }
})

const sourceAssets = Effect.fnUntraced(function* () {
  const fs = yield* FileSystem.FileSystem
  const root = path.resolve(import.meta.dirname, "../../app/dist")
  // CyberLab OS: o web app é opcional (interface é o terminal). Se `dist` não foi
  // compilado, serve a API normalmente e deixa as rotas web com 404 — em vez de
  // derrubar o servidor inteiro com 500 (que quebrava o TUI).
  const exists = yield* fs.exists(root)
  const files = exists ? yield* fs.readDirectory(root, { recursive: true }) : []
  const assets: Record<string, string> = Object.fromEntries(
    (yield* Effect.forEach(
      files.filter((file) => !file.endsWith(".map") && !path.basename(file).startsWith(".cyberlab-")),
      Effect.fnUntraced(function* (file) {
        const target = path.join(root, file)
        if ((yield* fs.stat(target)).type === "Directory") return
        return [normalizeAssetKey(file), target] as const
      }),
      { concurrency: "unbounded" },
    )).filter((asset) => asset !== undefined),
  )
  assets["sw.js"] = "__local_self_unregister_sw__"
  return lazy(assets, (key) => (key === "sw.js" ? LOCAL_SELF_UNREGISTER_SW : readFileSync(assets[key]!)))
})

function lazy(assets: Readonly<Record<string, unknown>>, load: (key: string) => Uint8Array): AssetMap {
  // Immutable browser caching makes retaining decompressed copies in the server unnecessary.
  return new Proxy(
    {},
    {
      get: (_, key) => {
        if (typeof key !== "string" || assets[key] === undefined) return
        const body = load(key)
        return isText(key) ? Buffer.from(body).toString() : body
      },
    },
  )
}

function isText(file: string) {
  return file === "_headers" || /\.(?:css|html|js|json|svg|txt|webmanifest|xml)$/.test(file)
}
