import { Button } from "@opencode/ui/button"
import { Switch } from "@opencode/ui/switch"
import { usePlugin, type ServerRef } from "@opencode/plugin/gui"
import { createEffect, createResource, createSignal, For, Show, type JSX } from "solid-js"
import { cyberlabRequest } from "./api"
import type CyberLabPlugin from "./index"
import type {
  CdiInitiateMode,
  CdiPartnerDto,
  CdiSecretOutputDto,
  ExternalToolsOverviewDto,
  PartnersOverviewDto,
  ScopeRuleDto,
  WorkspaceStatusDto,
} from "./types"

function SettingsRow(props: { title: string; description: string; children: JSX.Element }) {
  return (
    <div data-component="settings-row">
      <div data-slot="settings-row-copy">
        <div data-slot="settings-row-title">{props.title}</div>
        <div data-slot="settings-row-description">{props.description}</div>
      </div>
      <div data-slot="settings-row-control">{props.children}</div>
    </div>
  )
}

export default function CyberLabSettingsPage() {
  const ctx = usePlugin<typeof CyberLabPlugin>()

  const activeServer = (): ServerRef | undefined => {
    const fromSession = ctx.sessions.current()?.server
    if (fromSession) return fromSession
    const list = ctx.servers.list().map((id) => ctx.servers.get(id)).filter((s): s is ServerRef => Boolean(s))
    return list.find((s) => s.connected && s.local) ?? list.find((s) => s.connected) ?? list[0]
  }

  const availableDirectories = (): string[] => {
    const server = activeServer()
    const dirs: string[] = []
    const currentDir = ctx.sessions.current()?.directory
    if (currentDir) dirs.push(currentDir)
    for (const s of ctx.sessions.list()) {
      const dir = s.location?.directory
      if (dir && !dirs.includes(dir)) dirs.push(dir)
    }
    const projects = server?.data.project.list() ?? []
    for (const proj of projects) {
      if (proj.canonical && !dirs.includes(proj.canonical)) dirs.push(proj.canonical)
    }
    return dirs
  }

  const [selectedDir, setSelectedDir] = createSignal<string>("")
  createEffect(() => {
    const current = selectedDir()
    const dirs = availableDirectories()
    if (!current && dirs.length > 0) {
      setSelectedDir(dirs[0]!)
    }
  })

  const effectiveDir = () => selectedDir() || ctx.sessions.current()?.directory || undefined

  const [notice, setNotice] = createSignal<string>("")
  const [errorMsg, setErrorMsg] = createSignal<string>("")
  const [busy, setBusy] = createSignal(false)

  // Scope form controls
  const [newRuleKind, setNewRuleKind] = createSignal<ScopeRuleDto["kind"]>("url_origin")
  const [newRuleValue, setNewRuleValue] = createSignal("")

  // CDI secret & new agent controls
  const [revealedSecret, setRevealedSecret] = createSignal<string>("")
  const [customSecret, setCustomSecret] = createSignal("")
  const [showAddPartner, setShowAddPartner] = createSignal(false)
  const [partnerIdInput, setPartnerIdInput] = createSignal("")
  const [partnerNameInput, setPartnerNameInput] = createSignal("")
  const [partnerSpecialtyInput, setPartnerSpecialtyInput] = createSignal("")
  const [partnerUrlInput, setPartnerUrlInput] = createSignal("http://127.0.0.1:8788/cyberlab/partner")

  const sourceKey = () => {
    const srv = activeServer()
    return srv ? `${srv.id}::${effectiveDir() ?? ""}` : undefined
  }

  const [status, { refetch: refetchStatus }] = createResource(sourceKey, async () =>
    cyberlabRequest<WorkspaceStatusDto>(activeServer(), effectiveDir(), "/api/cyberlab/status"),
  )
  const [partnersData, { refetch: refetchPartners }] = createResource(sourceKey, async () =>
    cyberlabRequest<PartnersOverviewDto>(activeServer(), effectiveDir(), "/api/cyberlab/partners"),
  )
  const [externalTools, { refetch: refetchExternal }] = createResource(sourceKey, async () =>
    cyberlabRequest<ExternalToolsOverviewDto>(activeServer(), effectiveDir(), "/api/cyberlab/external/tools"),
  )

  const refreshAll = () => {
    void refetchStatus()
    void refetchPartners()
    void refetchExternal()
  }

  const runAction = async (label: string, fn: () => Promise<void>) => {
    setBusy(true)
    setErrorMsg("")
    setNotice("")
    try {
      await fn()
      setNotice(label)
      refreshAll()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const toggleExternalTargets = (allow: boolean) => {
    const currentScope = status()?.activeScope
    void runAction(
      allow ? "Alvos externos habilitados no escopo." : "Escopo restrito apenas a alvos locais.",
      async () => {
        await cyberlabRequest(activeServer(), effectiveDir(), "/api/cyberlab/scope", {
          method: "PUT",
          body: JSON.stringify({
            name: currentScope?.name ?? "Escopo Padrão",
            allowExternalTargets: allow,
            allowedTargets: currentScope?.allowedTargets ?? [
              { kind: "ip", value: "127.0.0.1" },
              { kind: "domain", value: "localhost" },
            ],
            blockedTargets: currentScope?.blockedTargets ?? [],
          }),
        })
      },
    )
  }

  const addScopeTarget = () => {
    const val = newRuleValue().trim()
    if (!val) return
    const currentScope = status()?.activeScope
    const existing = currentScope?.allowedTargets ?? [
      { kind: "ip" as const, value: "127.0.0.1" },
      { kind: "domain" as const, value: "localhost" },
    ]
    void runAction(`Alvo "${val}" adicionado ao escopo.`, async () => {
      await cyberlabRequest(activeServer(), effectiveDir(), "/api/cyberlab/scope", {
        method: "PUT",
        body: JSON.stringify({
          name: currentScope?.name ?? "Escopo Padrão",
          allowExternalTargets: currentScope?.allowExternalTargets ?? false,
          allowedTargets: [...existing, { kind: newRuleKind(), value: val }],
          blockedTargets: currentScope?.blockedTargets ?? [],
        }),
      })
      setNewRuleValue("")
    })
  }

  const removeScopeTarget = (index: number) => {
    const currentScope = status()?.activeScope
    if (!currentScope) return
    const updated = currentScope.allowedTargets.filter((_, idx) => idx !== index)
    void runAction("Regra removida do escopo.", async () => {
      await cyberlabRequest(activeServer(), effectiveDir(), "/api/cyberlab/scope", {
        method: "PUT",
        body: JSON.stringify({
          name: currentScope.name,
          allowExternalTargets: currentScope.allowExternalTargets,
          allowedTargets: updated,
          blockedTargets: currentScope.blockedTargets,
        }),
      })
    })
  }

  const applyFourCdiPreset = () =>
    runAction("Preset dos 4 CDIs (Salem :8788, Kairós :8789, Naia :8790, CDI-04 :8791) configurado!", async () => {
      await cyberlabRequest(activeServer(), effectiveDir(), "/api/cyberlab/partners/manage", {
        method: "POST",
        body: JSON.stringify({ operation: "preset_4" }),
      })
    })

  const toggleRevealSecret = async () => {
    if (revealedSecret()) {
      setRevealedSecret("")
      return
    }
    try {
      const res = await cyberlabRequest<CdiSecretOutputDto>(
        activeServer(),
        effectiveDir(),
        "/api/cyberlab/partners/secret",
        {
          method: "POST",
          body: JSON.stringify({ operation: "reveal" }),
        },
      )
      setRevealedSecret(res.sharedSecret)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    }
  }

  const rotateOrSaveSecret = (generateRandom: boolean) =>
    runAction(
      generateRandom ? "Novo CYBERLAB_PARTNER_SECRET gerado e salvo!" : "CYBERLAB_PARTNER_SECRET atualizado!",
      async () => {
        const res = await cyberlabRequest<CdiSecretOutputDto>(
          activeServer(),
          effectiveDir(),
          "/api/cyberlab/partners/secret",
          {
            method: "POST",
            body: JSON.stringify(
              generateRandom
                ? { operation: "generate", cyberlabCallbackUrl: `${window.location.origin}/api/cyberlab/partner-gateway` }
                : {
                    operation: "custom",
                    customSecret: customSecret().trim(),
                    cyberlabCallbackUrl: `${window.location.origin}/api/cyberlab/partner-gateway`,
                  },
            ),
          },
        )
        if (revealedSecret()) setRevealedSecret(res.sharedSecret)
        if (!generateRandom) setCustomSecret("")
      },
    )

  const copyPowerShellSetup = async () => {
    const secRes = await cyberlabRequest<CdiSecretOutputDto>(
      activeServer(),
      effectiveDir(),
      "/api/cyberlab/partners/secret",
      {
        method: "POST",
        body: JSON.stringify({ operation: "reveal" }),
      },
    )
    const gateway = `${window.location.origin}/api/cyberlab/partner-gateway`
    const snippet = [
      `$env:CYBERLAB_PARTNER_SECRET="${secRes.sharedSecret}"`,
      `$env:CYBERLAB_CALLBACK_URL="${gateway}"`,
      `# Subir os 4 CDIs em terminais PowerShell separados:`,
      `python integrations/partners/chat_py_bridge.py --partner-id salem  --port 8788 --mode arg --script C:\\caminho\\salem\\chat.py`,
      `python integrations/partners/chat_py_bridge.py --partner-id kairos --port 8789 --mode arg --script C:\\caminho\\kairos\\chat.py`,
      `python integrations/partners/chat_py_bridge.py --partner-id naia   --port 8790 --mode arg --script C:\\caminho\\naia\\chat.py`,
      `python integrations/partners/chat_py_bridge.py --partner-id cdi-4  --port 8791 --mode arg --script C:\\caminho\\cdi4\\chat.py`,
    ].join("\n")
    await ctx.system.copy(snippet)
    setNotice("Comandos PowerShell copiados para a área de transferência!")
  }

  const updatePartner = (partner: CdiPartnerDto, patch: Partial<CdiPartnerDto>) => {
    const merged: CdiPartnerDto = {
      ...partner,
      ...patch,
      permissions: {
        ...partner.permissions,
        ...(patch.permissions ?? {}),
      },
    }
    void runAction(`Configuração de ${merged.displayName} salva.`, async () => {
      await cyberlabRequest(activeServer(), effectiveDir(), "/api/cyberlab/partners/manage", {
        method: "POST",
        body: JSON.stringify({
          operation: "upsert",
          partnerId: merged.partnerId,
          displayName: merged.displayName,
          specialty: merged.specialty,
          endpointUrl: merged.endpointUrl,
          enabled: merged.enabled,
          permissions: merged.permissions,
        }),
      })
    })
  }

  const addNewPartner = () => {
    const id = partnerIdInput().trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-")
    const name = partnerNameInput().trim()
    const endpoint = partnerUrlInput().trim()
    if (!id || !name || !endpoint) return
    void runAction(`Agente CDI "${name}" adicionado!`, async () => {
      await cyberlabRequest(activeServer(), effectiveDir(), "/api/cyberlab/partners/manage", {
        method: "POST",
        body: JSON.stringify({
          operation: "upsert",
          partnerId: id,
          displayName: name,
          specialty: partnerSpecialtyInput().trim() || "Especialista externo de segurança",
          endpointUrl: endpoint,
          enabled: true,
          permissions: {
            readProjectState: true,
            readEvidenceAndFiles: true,
            createArtifactsAndFindings: true,
            initiateActions: "allow_readonly_propose_others",
          },
        }),
      })
      setPartnerIdInput("")
      setPartnerNameInput("")
      setPartnerSpecialtyInput("")
      setShowAddPartner(false)
    })
  }

  const removePartner = (partnerId: string, name: string) =>
    runAction(`Agente ${name} removido.`, async () => {
      await cyberlabRequest(activeServer(), effectiveDir(), "/api/cyberlab/partners/manage", {
        method: "POST",
        body: JSON.stringify({ operation: "remove", partnerId }),
      })
    })

  const syncInbox = () =>
    runAction("Pasta .cyberlab/inbox sincronizada com verificação SHA-256!", async () => {
      await cyberlabRequest(activeServer(), effectiveDir(), "/api/cyberlab/external/sync", {
        method: "POST",
        body: JSON.stringify({}),
      })
    })

  const inputClass =
    "h-8 rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2.5 text-12-regular text-v2-text-text-base outline-none focus:border-v2-text-text-muted"

  return (
    <>
      <div class="settings-tab-header">
        <div class="settings-tab-header-row">
          <div class="flex flex-col gap-1">
            <h2 class="settings-tab-title">{ctx.t("settings.title")}</h2>
            <span class="text-11-regular text-v2-text-text-muted">{ctx.t("settings.description")}</span>
          </div>
          <Button variant="neutral" size="small" icon="refresh" disabled={busy()} onClick={refreshAll}>
            Atualizar
          </Button>
        </div>
      </div>

      <div class="settings-tab-body settings-tab-body--sectioned">
        <Show when={notice()}>
          <div class="rounded-[8px] border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-12-regular text-emerald-400">
            {notice()}
          </div>
        </Show>
        <Show when={errorMsg()}>
          <div class="rounded-[8px] border border-red-500/30 bg-red-500/10 px-3 py-2 text-12-regular text-red-400" role="alert">
            {errorMsg()}
          </div>
        </Show>

        <Show when={availableDirectories().length > 1}>
          <section class="settings-section" aria-label="Projeto">
            <div data-component="settings-list">
              <SettingsRow
                title="Projeto / Diretório Ativo"
                description="Selecione qual workspace terá o escopo e os agentes CDI configurados."
              >
                <select
                  class={inputClass}
                  value={effectiveDir() ?? ""}
                  onChange={(e) => setSelectedDir(e.currentTarget.value)}
                >
                  <For each={availableDirectories()}>{(dir) => <option value={dir}>{dir}</option>}</For>
                </select>
              </SettingsRow>
            </div>
          </section>
        </Show>

        {/* Seção 1: Escopo & Segurança */}
        <section class="settings-section" aria-label={ctx.t("settings.scope.title")} id="cyberlab-scope">
          <div class="mb-2 flex flex-col gap-0.5 px-1">
            <h3 class="text-13-medium font-medium text-v2-text-text-base">{ctx.t("settings.scope.title")}</h3>
            <p class="text-11-regular text-v2-text-text-muted">
              {status()?.workspaceRoot
                ? `Workspace: ${status()?.workspaceRoot} · ${status()?.capabilityCount ?? 0} ferramentas registradas`
                : ctx.t("settings.scope.description")}
            </p>
          </div>

          <div data-component="settings-list">
            <div class="border-b-[0.5px] border-v2-border-border-base">
              <SettingsRow
                title="Permitir alvos externos fora da rede local"
                description="Quando desligado, qualquer tentativa contra IPs/domínios fora de localhost/127.0.0.1 é bloqueada automaticamente."
              >
                <Switch
                  hideLabel
                  checked={Boolean(status()?.activeScope?.allowExternalTargets)}
                  disabled={busy() || status.loading}
                  onChange={toggleExternalTargets}
                >
                  Permitir alvos externos
                </Switch>
              </SettingsRow>
            </div>

            <div class="flex flex-col gap-3 p-3.5">
              <div class="flex flex-col gap-1">
                <span class="text-12-medium font-medium text-v2-text-text-base">Alvos autorizados no escopo</span>
                <span class="text-11-regular text-v2-text-text-muted">
                  Apenas destinos listados abaixo podem receber pacotes, scans ou requisições das ferramentas e dos CDIs.
                </span>
              </div>

              <div class="flex flex-wrap gap-1.5">
                <For
                  each={
                    status()?.activeScope?.allowedTargets ?? [
                      { kind: "ip" as const, value: "127.0.0.1" },
                      { kind: "domain" as const, value: "localhost" },
                    ]
                  }
                >
                  {(rule, idx) => (
                    <span class="inline-flex items-center gap-1.5 rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2.5 py-1 text-11-regular text-v2-text-text-base">
                      <span class="text-v2-text-text-muted">{rule.kind}:</span>
                      <code class="font-mono">{rule.value}</code>
                      <Show when={Boolean(status()?.activeScope)}>
                        <button
                          type="button"
                          class="ml-0.5 text-v2-text-text-muted hover:text-red-400"
                          title="Remover regra"
                          onClick={() => removeScopeTarget(idx())}
                        >
                          ×
                        </button>
                      </Show>
                    </span>
                  )}
                </For>
              </div>

              <div class="flex flex-wrap items-center gap-2 pt-1">
                <select
                  class={inputClass}
                  value={newRuleKind()}
                  onChange={(e) => setNewRuleKind(e.currentTarget.value as ScopeRuleDto["kind"])}
                >
                  <option value="url_origin">URL / Origem</option>
                  <option value="domain">Domínio</option>
                  <option value="ip">Endereço IP</option>
                  <option value="cidr">Rede CIDR</option>
                  <option value="workspace_path">Pasta local</option>
                </select>
                <input
                  type="text"
                  class={`${inputClass} min-w-[220px] flex-1 font-mono`}
                  placeholder="Ex.: http://127.0.0.1:8080 ou api.cliente.com.br"
                  value={newRuleValue()}
                  onInput={(e) => setNewRuleValue(e.currentTarget.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") addScopeTarget()
                  }}
                />
                <Button variant="neutral" size="small" icon="plus" disabled={busy() || !newRuleValue().trim()} onClick={addScopeTarget}>
                  Adicionar Alvo
                </Button>
              </div>
            </div>
          </div>
        </section>

        {/* Seção 2: Agentes CDI Bidirecionais */}
        <section class="settings-section" aria-label={ctx.t("settings.cdi.title")} id="cyberlab-cdi">
          <div class="mb-2 flex items-center justify-between gap-2 px-1">
            <div class="flex flex-col gap-0.5">
              <h3 class="text-13-medium font-medium text-v2-text-text-base">{ctx.t("settings.cdi.title")}</h3>
              <p class="text-11-regular text-v2-text-text-muted">{ctx.t("settings.cdi.description")}</p>
            </div>
            <div class="flex items-center gap-1.5">
              <Button variant="neutral" size="small" icon="plus" disabled={busy()} onClick={applyFourCdiPreset}>
                Preset 4 CDIs (8788–8791)
              </Button>
              <Button variant="outline" size="small" onClick={() => setShowAddPartner(!showAddPartner())}>
                {showAddPartner() ? "Fechar" : "+ Novo CDI"}
              </Button>
            </div>
          </div>

          <div data-component="settings-list">
            {/* Segredo HMAC & Comandos PowerShell */}
            <div class="border-b-[0.5px] border-v2-border-border-base p-3.5">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex flex-col gap-0.5">
                  <span class="text-12-medium font-medium text-v2-text-text-base">
                    Autenticação Mútua HMAC-SHA256 (CYBERLAB_PARTNER_SECRET)
                  </span>
                  <span class="text-11-regular text-v2-text-text-muted">
                    Gateway único deste aplicativo:{" "}
                    <code class="font-mono text-v2-text-text-base">{window.location.origin}/api/cyberlab/partner-gateway</code>
                  </span>
                </div>
                <div class="flex flex-wrap items-center gap-1.5">
                  <Button variant="ghost" size="small" onClick={() => void toggleRevealSecret()}>
                    {revealedSecret() ? "Ocultar Segredo" : "Mostrar Segredo"}
                  </Button>
                  <Button variant="neutral" size="small" disabled={busy()} onClick={() => rotateOrSaveSecret(true)}>
                    Gerar Novo Segredo
                  </Button>
                  <Button variant="contrast" size="small" icon="copy" onClick={() => void copyPowerShellSetup()}>
                    Copiar Comandos PowerShell
                  </Button>
                </div>
              </div>

              <div class="mt-2.5 flex flex-wrap items-center gap-2">
                <code class="rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2.5 py-1.5 font-mono text-11-regular text-v2-text-text-base">
                  {revealedSecret() || partnersData()?.secretPreview || "••••••••"}
                </code>
                <input
                  type="password"
                  class={`${inputClass} min-w-[200px] flex-1 font-mono`}
                  placeholder="Ou digite seu próprio segredo (mín. 16 caracteres)"
                  value={customSecret()}
                  onInput={(e) => setCustomSecret(e.currentTarget.value)}
                />
                <Show when={customSecret().trim().length >= 16}>
                  <Button variant="neutral" size="small" disabled={busy()} onClick={() => rotateOrSaveSecret(false)}>
                    Salvar Segredo
                  </Button>
                </Show>
              </div>
            </div>

            {/* Formulário Novo CDI */}
            <Show when={showAddPartner()}>
              <div class="border-b-[0.5px] border-v2-border-border-base bg-v2-background-bg-deep/50 p-3.5">
                <div class="mb-2 text-12-medium font-medium text-v2-text-text-base">Cadastrar Agente CDI</div>
                <div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <input
                    type="text"
                    class={inputClass}
                    placeholder="ID (ex.: salem)"
                    value={partnerIdInput()}
                    onInput={(e) => setPartnerIdInput(e.currentTarget.value)}
                  />
                  <input
                    type="text"
                    class={inputClass}
                    placeholder="Nome visível (ex.: Salem)"
                    value={partnerNameInput()}
                    onInput={(e) => setPartnerNameInput(e.currentTarget.value)}
                  />
                  <input
                    type="text"
                    class={`${inputClass} font-mono`}
                    placeholder="URL (ex.: http://127.0.0.1:8788/cyberlab/partner)"
                    value={partnerUrlInput()}
                    onInput={(e) => setPartnerUrlInput(e.currentTarget.value)}
                  />
                  <input
                    type="text"
                    class={inputClass}
                    placeholder="Especialidade (ex.: Triagem de CVEs e Logs)"
                    value={partnerSpecialtyInput()}
                    onInput={(e) => setPartnerSpecialtyInput(e.currentTarget.value)}
                  />
                </div>
                <div class="mt-2.5 flex justify-end gap-2">
                  <Button variant="ghost" size="small" onClick={() => setShowAddPartner(false)}>
                    Cancelar
                  </Button>
                  <Button
                    variant="submit"
                    size="small"
                    disabled={busy() || !partnerIdInput().trim() || !partnerNameInput().trim()}
                    onClick={addNewPartner}
                  >
                    Salvar Agente CDI
                  </Button>
                </div>
              </div>
            </Show>

            {/* Lista de CDIs */}
            <Show
              when={(partnersData()?.partners?.length ?? 0) > 0}
              fallback={
                <div class="p-4 text-12-regular text-v2-text-text-muted">
                  Nenhum CDI cadastrado neste projeto ainda. Clique em <strong>Preset 4 CDIs (8788–8791)</strong> acima para configurar Salem, Kairós, Naia e CDI-04 com 1 clique.
                </div>
              }
            >
              <For each={partnersData()?.partners ?? []}>
                {(partner) => (
                  <div class="flex flex-col gap-2 border-b-[0.5px] border-v2-border-border-base p-3.5 last:border-b-0">
                    <div class="flex flex-wrap items-center justify-between gap-2">
                      <div class="flex items-center gap-2">
                        <span
                          class={`inline-block size-2 rounded-full ${partner.enabled ? "bg-emerald-400" : "bg-zinc-500"}`}
                        />
                        <span class="text-13-medium font-medium text-v2-text-text-base">{partner.displayName}</span>
                        <code class="rounded bg-v2-background-bg-deep px-1.5 py-0.5 font-mono text-11-regular text-v2-text-text-muted">
                          {partner.partnerId}
                        </code>
                        <code class="font-mono text-11-regular text-v2-text-text-muted">{partner.endpointUrl}</code>
                      </div>

                      <div class="flex items-center gap-2">
                        <Switch
                          hideLabel
                          checked={partner.enabled}
                          disabled={busy()}
                          onChange={(enabled) => updatePartner(partner, { enabled })}
                        >
                          Ativar {partner.displayName}
                        </Switch>
                        <Button
                          variant="ghost-danger"
                          size="small"
                          icon="trash"
                          disabled={busy()}
                          onClick={() => void removePartner(partner.partnerId, partner.displayName)}
                        />
                      </div>
                    </div>

                    <div class="flex flex-wrap items-center justify-between gap-2 text-11-regular text-v2-text-text-muted">
                      <span>{partner.specialty}</span>
                      <div class="flex items-center gap-2">
                        <span>Autonomia de ferramentas:</span>
                        <select
                          class="h-7 rounded-[6px] border border-v2-border-border-base bg-v2-background-bg-deep px-2 text-11-regular text-v2-text-text-base"
                          value={partner.permissions.initiateActions}
                          onChange={(e) =>
                            updatePartner(partner, {
                              permissions: {
                                ...partner.permissions,
                                initiateActions: e.currentTarget.value as CdiInitiateMode,
                              },
                            })
                          }
                        >
                          <option value="allow_readonly_propose_others">Leitura direta + propor demais ações (Recomendado)</option>
                          <option value="propose_only">Propor todas para aprovação humana</option>
                          <option value="disabled">Não iniciar ferramentas sozinho</option>
                        </select>
                      </div>
                    </div>
                  </div>
                )}
              </For>
            </Show>
          </div>
        </section>

        {/* Seção 3: Motores Externos Opcionais */}
        <section class="settings-section" aria-label={ctx.t("settings.engines.title")} id="cyberlab-engines">
          <div class="mb-2 flex items-center justify-between gap-2 px-1">
            <div class="flex flex-col gap-0.5">
              <h3 class="text-13-medium font-medium text-v2-text-text-base">{ctx.t("settings.engines.title")}</h3>
              <p class="text-11-regular text-v2-text-text-muted">{ctx.t("settings.engines.description")}</p>
            </div>
            <Button variant="neutral" size="small" icon="folder" disabled={busy()} onClick={() => void syncInbox()}>
              Sincronizar .cyberlab/inbox ({externalTools()?.pendingInboxCount ?? 0})
            </Button>
          </div>

          <div data-component="settings-list">
            <For each={externalTools()?.tools ?? []}>
              {(tool) => (
                <div class="border-b-[0.5px] border-v2-border-border-base last:border-b-0">
                  <SettingsRow
                    title={`${tool.displayName} (${tool.toolId})`}
                    description={
                      tool.available
                        ? `Instalado em: ${tool.resolvedPath ?? tool.toolId}`
                        : `Opcional — CyberLab usa motor nativo integrado. Para instalar: ${tool.installHint}`
                    }
                  >
                    <span
                      class={`rounded-[6px] px-2 py-0.5 text-11-regular font-medium ${
                        tool.available
                          ? "bg-emerald-500/15 text-emerald-400"
                          : "bg-v2-background-bg-deep text-v2-text-text-muted"
                      }`}
                    >
                      {tool.available ? "Instalado" : "Motor Nativo"}
                    </span>
                  </SettingsRow>
                </div>
              )}
            </For>
          </div>
        </section>
      </div>
    </>
  )
}
