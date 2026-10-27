import { lazy, onCleanup, Show, Suspense } from "solid-js"
import {
  Command,
  MenuItem,
  Panel,
  type ClosedPanelTab,
  type PanelTab,
  type Plugin,
} from "@opencode/plugin/gui"
import { onIdle } from "@opencode/plugin/gui/builtin"
import type CyberLabPlugin from "./index"

const TAB = "ops"
const KEY = `cyberlab:${TAB}`

const setup: Plugin.Setup<typeof CyberLabPlugin> = (ctx) => {
  const sessions = ctx.sessions
  const layout = ctx.layout

  const CyberLabPanel = lazy(() => import("./panel"))
  onCleanup(onIdle(() => void CyberLabPanel.preload()))

  const tab: PanelTab = {
    id: TAB,
    get title() {
      return ctx.t("tab.title")
    },
  }

  ctx.add(Panel, {
    id: "main",
    region: "side",
    list: (input) => (!layout.narrow() && input.session.project ? [tab] : []),
    closed: (): ClosedPanelTab => ({ title: ctx.t("tab.title"), icon: "info" }),
    render: (props) => (
      <Show when={props.session.project}>
        <Suspense>
          <CyberLabPanel session={props.session} />
        </Suspense>
      </Show>
    ),
  })

  const openPanel = () => {
    const session = sessions.current()
    if (session?.project && !layout.narrow()) {
      layout.open(KEY, session, { tab: "select" })
    }
  }

  const mac = /(Mac|iPhone|iPad)/.test(navigator.platform)

  ctx.add(
    Command,
    (): Command => ({
      id: "open",
      title: ctx.t("command.open"),
      group: ctx.t("command.category.view"),
      bind: mac ? "ctrl+meta+l" : "ctrl+alt+l",
      editable: true,
      enabled: !!sessions.current()?.project && !layout.narrow(),
      run: openPanel,
    }),
  )

  ctx.add(MenuItem, (): MenuItem | undefined => {
    const session = sessions.current()
    if (!session?.project || layout.narrow()) return undefined
    return {
      menu: "session.panel",
      id: "open",
      title: ctx.t("tab.title"),
      opened: layout.state(KEY, session) !== "closed",
      icon: "info",
      order: 35,
      run: openPanel,
    }
  })
}

export default setup
