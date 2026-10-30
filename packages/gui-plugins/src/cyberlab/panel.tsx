import { createResource, For, Show } from "solid-js"

interface ArsenalMiniDto {
  environment: {
    hostPlatform: string
    toolsRootDir: string
    wslAvailable: boolean
    preferredWslDistro: string
  }
  slots: Array<{
    slotId: string
    name: string
    kind: string
    installed: boolean
    activeRuntime: string
  }>
}

async function fetchArsenalMini(directory?: string): Promise<ArsenalMiniDto | null> {
  try {
    const url = new URL("/api/cyberlab/arsenal", window.location.origin)
    if (directory) url.searchParams.set("location[directory]", directory)
    const res = await fetch(url.toString(), { credentials: "include" })
    if (!res.ok) return null
    const json = (await res.json()) as { data?: ArsenalMiniDto }
    return (json && "data" in json ? json.data : json) as ArsenalMiniDto
  } catch {
    return null
  }
}

export default function CyberLabPanel(props: { session: { directory?: string } }) {
  const [arsenal, { refetch }] = createResource(() => props.session.directory, fetchArsenalMini)

  return (
    <div class="flex h-full flex-col gap-3 overflow-y-auto p-3 text-[12px] select-text">
      <div class="flex items-center justify-between">
        <div class="font-semibold text-v2-text-text-strong">CyberLab OS v5.0 — Arsenal Real</div>
        <button
          type="button"
          class="rounded border border-v2-border-border-base px-2 py-0.5 text-[11px] hover:border-emerald-500 cursor-pointer"
          onClick={() => void refetch()}
        >
          Atualizar
        </button>
      </div>

      <p class="text-[11px] text-v2-text-text-muted">
        Use o botão <strong>"Arsenal Real (Modo Antigravity)"</strong> abaixo da caixa de mensagem para abrir o layout de 3 colunas (Pastas à esquerda · Ferramenta Real no centro · Agente OpenCode à direita).
      </p>

      <Show when={arsenal()}>
        {(ov) => (
          <>
            <div class="rounded-lg border border-v2-border-border-base bg-v2-background-bg-deep/50 p-2.5 text-[11px] space-y-1">
              <div>Pasta Externa: <code class="font-mono">{ov().environment.toolsRootDir}</code></div>
              <div>
                WSL2 Kali:{" "}
                <strong class="text-emerald-500">
                  {ov().environment.wslAvailable ? ov().environment.preferredWslDistro : "Não detectado"}
                </strong>
              </div>
            </div>

            <div class="space-y-1">
              <For each={ov().slots}>
                {(s) => (
                  <div class="flex items-center justify-between rounded border border-v2-border-border-base px-2.5 py-1.5 text-[11px]">
                    <span class="truncate font-medium">{s.name}</span>
                    <span class={s.installed ? "text-emerald-500" : "text-v2-text-text-muted"}>
                      {s.installed ? s.activeRuntime : "slot"}
                    </span>
                  </div>
                )}
              </For>
            </div>
          </>
        )}
      </Show>
    </div>
  )
}
