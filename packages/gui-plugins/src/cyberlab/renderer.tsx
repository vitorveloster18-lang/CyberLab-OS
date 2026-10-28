import { Button } from "@opencode/ui/button"
import {
  Command,
  MenuItem,
  Panel,
  SettingsPage,
  Slot,
  TitlebarItem,
  type ClosedPanelTab,
  type PanelTab,
  type Plugin,
} from "@opencode/plugin/gui"
import { onIdle } from "@opencode/plugin/gui/builtin"
import { lazy, onCleanup, Show, Suspense } from "solid-js"
import type CyberLabPlugin from "./index"

const TAB = "ops"
const KEY = `cyberlab:${TAB}`

const setup: Plugin.Setup<typeof CyberLabPlugin> = (ctx) => {
  const sessions = ctx.sessions
  const layout = ctx.layout

  const CyberLabPanel = lazy(() => import("./panel"))
  const CyberLabSettingsPage = lazy(() => import("./settings"))

  onCleanup(
    onIdle(() => {
      void CyberLabPanel.preload()
      void CyberLabSettingsPage.preload()
    }),
  )

  const tab: PanelTab = {
    id: TAB,
    get title() {
      return ctx.t("tab.title")
    },
  }

  // 1. Native Settings Page inside OpenCode V2 (/settings?tab=cyberlab)
  ctx.add(SettingsPage, {
    id: "cyberlab",
    icon: "shield",
    get title() {
      return ctx.t("settings.title")
    },
    get entries() {
      return [
        {
          id: "cyberlab-scope",
          title: ctx.t("settings.scope.title"),
          description: ctx.t("settings.scope.description"),
          keywords: "cyberlab escopo scope ip dominio alvo seguranca ssrf allow external",
        },
        {
          id: "cyberlab-cdi",
          title: ctx.t("settings.cdi.title"),
          description: ctx.t("settings.cdi.description"),
          keywords: "cdi salem kairos naia partner bridge hmac secret 8788 8789 8790 8791",
        },
        {
          id: "cyberlab-engines",
          title: ctx.t("settings.engines.title"),
          description: ctx.t("settings.engines.description"),
          keywords: "nmap nuclei ffuf tshark inbox ferramentas motores",
        },
      ]
    },
    render: () => (
      <Suspense>
        <CyberLabSettingsPage />
      </Suspense>
    ),
  })

  // 2. Clean Workspace Side Panel (desktop & mobile drawer)
  ctx.add(Panel, {
    id: "main",
    region: "side",
    mobile: {
      get title() {
        return ctx.t("tab.title")
      },
      order: 35,
      kind: "drawer",
      icon: "shield",
    },
    list: (input) => (input.session.project ? [tab] : []),
    closed: (): ClosedPanelTab => ({ title: ctx.t("tab.title"), icon: "shield" }),
    render: (props) => (
      <Show when={props.session.project}>
        <Suspense>
          <CyberLabPanel session={props.session} />
        </Suspense>
      </Show>
    ),
  })

  const togglePanelOrSettings = () => {
    const session = sessions.current()
    if (session?.project) {
      layout.toggle(KEY, session)
      return
    }
    layout.settings("cyberlab")
  }

  // 3. Always-visible Titlebar Pill (opens panel in session, or CyberLab Settings on Home)
  ctx.add(TitlebarItem, (): TitlebarItem => {
    const session = sessions.current()
    const visible = Boolean(session?.project && layout.state(KEY, session) === "visible")
    return {
      id: "cyberlab-pill",
      label: "CyberLab",
      title: session?.project ? ctx.t("command.open") : ctx.t("command.settings"),
      icon: "shield",
      pressed: visible,
      run: togglePanelOrSettings,
    }
  })

  // 4. 1-Click Button right inside every Session Header
  ctx.add(Slot, {
    at: "session.header",
    order: 15,
    render: (input) => (
      <Show when={input.session.project}>
        <Button
          variant={layout.state(KEY, input.session) === "visible" ? "contrast" : "neutral"}
          size="small"
          icon="shield"
          onClick={() => layout.toggle(KEY, input.session)}
        >
          CyberLab
        </Button>
      </Show>
    ),
  })

  const mac = /(Mac|iPhone|iPad)/.test(navigator.platform)

  // 5. Slash command (/cyberlab) + keyboard shortcut + Command Palette entries
  ctx.add(
    Command,
    (): Command => ({
      id: "open",
      title: ctx.t("command.open"),
      description: ctx.t("command.slash.description"),
      keywords: "cyberlab tools security proxy repeater scanner cdi salem kairos naia",
      group: ctx.t("command.category.security"),
      section: "session",
      bind: mac ? "ctrl+meta+l" : "ctrl+alt+l",
      slash: {
        name: "cyberlab",
      },
      featured: true,
      editable: true,
      run: togglePanelOrSettings,
    }),
  )

  ctx.add(
    Command,
    (): Command => ({
      id: "settings",
      title: ctx.t("command.settings"),
      keywords: "cyberlab settings configuracoes cdi salem kairos naia escopo hmac",
      group: ctx.t("command.category.security"),
      section: "general",
      featured: true,
      run: () => layout.settings("cyberlab"),
    }),
  )

  // 6. Side Panel "+" Launcher Menu Item
  ctx.add(MenuItem, (): MenuItem | undefined => {
    const session = sessions.current()
    if (!session?.project) return undefined
    return {
      menu: "session.panel",
      id: "open",
      title: ctx.t("tab.title"),
      opened: layout.state(KEY, session) !== "closed",
      icon: "shield",
      order: 35,
      run: () => layout.open(KEY, session, { tab: "select" }),
    }
  })
}

export default setup
