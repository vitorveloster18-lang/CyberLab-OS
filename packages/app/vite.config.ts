import { sentryVitePlugin } from "@sentry/vite-plugin"
import { fileURLToPath } from "node:url"
import { defineConfig } from "vite"
import desktopPlugin, { channel } from "./vite.js"
import { icons } from "./vite.icons.ts"
import { serviceWorker } from "./vite.pwa.ts"

const localFastBuild =
  process.env.CYBERLAB_LOCAL_UI_BUILD === "1" && process.env.CYBERLAB_ENABLE_PWA !== "1"

const LOCAL_SELF_UNREGISTER_SW_SOURCE = [
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
].join("\n")

const localSwPlugin = {
  name: "cyberlab:local-self-unregister-sw",
  apply: "build" as const,
  generateBundle(this: { emitFile: (asset: { type: "asset"; fileName: string; source: string }) => void }) {
    this.emitFile({
      type: "asset",
      fileName: "sw.js",
      source: LOCAL_SELF_UNREGISTER_SW_SOURCE,
    })
  },
}

const sentry =
  process.env.SENTRY_AUTH_TOKEN && process.env.SENTRY_ORG && process.env.SENTRY_PROJECT
    ? sentryVitePlugin({
        authToken: process.env.SENTRY_AUTH_TOKEN,
        org: process.env.SENTRY_ORG,
        project: process.env.SENTRY_PROJECT,
        telemetry: false,
        release: {
          name: process.env.SENTRY_RELEASE ?? process.env.VITE_SENTRY_RELEASE,
        },
        sourcemaps: {
          assets: "./dist/**",
          filesToDeleteAfterUpload: "./dist/**/*.map",
        },
      })
    : false

export default defineConfig({
  plugins: [
    desktopPlugin,
    icons(channel),
    localFastBuild ? localSwPlugin : serviceWorker(fileURLToPath(new URL("./dist", import.meta.url))),
    sentry,
  ] as any,
  server: {
    host: "0.0.0.0",
    allowedHosts: true,
    port: 3000,
  },
  build: {
    ...(process.env.VITE_OPENCODE_TEST_FIXTURES === "1"
      ? {
          rolldownOptions: {
            input: [
              "index.html",
              "e2e/utils/settings-wsl.html",
              "e2e/utils/app-direction.html",
              "e2e/utils/windows-menu.html",
            ],
          },
        }
      : {}),
    assetsDir: "_assets",
    target: "esnext",
    sourcemap: localFastBuild ? process.env.CYBERLAB_UI_SOURCEMAP === "1" : true,
  },
})
