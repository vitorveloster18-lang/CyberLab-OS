/**
 * CyberLab OS — Guarda de Ações Destrutivas (v6.7).
 *
 * Regra do projeto: **o agente nunca destrói nada sem antes perguntar.**
 * Isto vale código adentro, não apenas no prompt — prompt pode ser ignorado,
 * código não pode.
 *
 * Como funciona:
 *  - Toda operação destrutiva é registrada aqui com risco, consequências e o que
 *    precisa vir na chamada para liberar.
 *  - Sem a confirmação exigida, a operação **falha fechada** (não executa) e devolve
 *    uma mensagem em pt-BR dizendo exatamente o que seria afetado e o que enviar.
 *  - O humano clicando num botão da interface JÁ é a confirmação: a UI manda
 *    `confirm: true`. O agente (MCP/subagente) não tem como ter esse token, então
 *    recebe o plano e precisa pedir autorização ao operador.
 *
 * Nível `irreversible` exige mais que um booleano: exige digitar de volta um trecho
 * do alvo (`confirmPhrase`), para impossibilitar "confirmar" no automático.
 */

export type RiskLevel = "safe" | "destructive" | "irreversible"

export interface DestructiveConsequence {
  /** O que se perde ou muda, em linguagem direta. */
  item: string
  /** Dá para desfazer? */
  recoverable: boolean
}

export interface ApprovalRequest {
  operation: string
  risk: Exclude<RiskLevel, "safe">
  /** Frase curta: o que a operação faz. */
  verb: string
  /** O que será atingido (slot, arquivo, lab...). */
  target: string
  consequences: DestructiveConsequence[]
  /** O que o chamador precisa enviar para liberar. */
  requirement: string
  /** Presente quando o nível exige frase exata. */
  confirmPhrase?: string
  /** Plano legível, pronto para o agente mostrar ao operador. */
  message: string
}

export type GuardVerdict = { allowed: true } | { allowed: false; approval: ApprovalRequest }

export interface DestructiveOperationSpec {
  risk: Exclude<RiskLevel, "safe">
  verb: string
  /** Descreve o alvo a partir dos argumentos da chamada. */
  targetOf: (args: Record<string, unknown>) => string
  consequences: (args: Record<string, unknown>) => DestructiveConsequence[]
  /** Frase que precisa ser digitada de volta (só para risco `irreversible`). */
  phraseOf?: (args: Record<string, unknown>) => string
}

/**
 * Catálogo das operações destrutivas conhecidas.
 * Se uma operação não está aqui, ela é tratada como `safe` — portanto, QUALQUER
 * nova operação que apague/substitua precisa ser registrada nesta lista.
 */
export const DESTRUCTIVE_OPERATIONS: Record<string, DestructiveOperationSpec> = {
  "cyberlab.arsenal.prune": {
    risk: "destructive",
    verb: "remover slots personalizados quebrados e duplicados",
    targetOf: () => "slots personalizados do arsenal",
    consequences: () => [
      { item: "Slots fantasmas (sem executável nem URL) são apagados da config", recoverable: false },
      { item: "Slots duplicados são apagados, mantendo uma única entrada", recoverable: false },
      { item: "Slots OFICIAIS nunca são removidos (48 slots do catálogo)", recoverable: true },
    ],
  },
  "cyberlab.arsenal.custom.remove": {
    risk: "destructive",
    verb: "remover um slot personalizado",
    targetOf: (args) => String(args.slotId ?? "(slotId não informado)"),
    consequences: (args) => [
      {
        item: `A entrada \`${String(args.slotId ?? "?")}\` sai da config: o caminho/URL precisam ser digitados de novo`,
        recoverable: false,
      },
      { item: "Nenhum binário em disco é apagado — apenas o registro do slot", recoverable: true },
    ],
  },
  "cyberlab.vault.delete": {
    risk: "irreversible",
    verb: "apagar uma nota do cofre",
    targetOf: (args) => String(args.relativePath ?? "(caminho não informado)"),
    consequences: (args) => [
      {
        item: `O arquivo \`${String(args.relativePath ?? "?")}\` é removido do disco`,
        recoverable: false,
      },
      { item: "Não há lixeira: a nota some de vez, inclusive para o Obsidian", recoverable: false },
    ],
    phraseOf: (args) => String(args.relativePath ?? ""),
  },
  "cyberlab.labs.control.stop": {
    risk: "destructive",
    verb: "derrubar o servidor do laboratório",
    targetOf: (args) => String(args.labId ?? "(labId não informado)"),
    consequences: (args) => [
      {
        item: `O alvo \`${String(args.labId ?? "?")}\` para de responder; investigação em curso é interrompida`,
        recoverable: true,
      },
      { item: "Arquivos, kit e evidência já gravados permanecem intactos", recoverable: true },
    ],
  },
  "cyberlab.labs.control.reset": {
    risk: "destructive",
    verb: "regravar os arquivos do laboratório do zero",
    targetOf: (args) => String(args.labId ?? "(labId não informado)"),
    consequences: (args) => [
      {
        item: `\`server-config.json\` e os fontes do lab \`${String(args.labId ?? "?")}\` voltam ao padrão`,
        recoverable: true,
      },
      {
        item: "Edições manuais feitas nesses arquivos (ex.: controles ligados) são PERDIDAS",
        recoverable: false,
      },
    ],
  },
  "cyberlab.knowledge.sync": {
    risk: "destructive",
    verb: "atualizar os documentos curados no cofre do operador",
    targetOf: () => "vault/CyberLab-Knowledge/**",
    consequences: () => [
      { item: "Documentos curados desatualizados são substituídos pela versão do código", recoverable: true },
      { item: "Cada arquivo substituído ganha um backup (.bak) antes da escrita", recoverable: true },
      {
        item: "Notas do operador (_drafts/, Investigacoes/, arquivos pessoais) NUNCA são tocadas",
        recoverable: true,
      },
      { item: "Se o operador editou um doc curado à mão, a edição é sobrescrita", recoverable: true },
    ],
  },
}

/** Verdadeiro quando o chamador marcou `confirm: true`. */
function hasConfirm(args: Record<string, unknown>): boolean {
  return args.confirm === true
}

/** Verdadeiro quando o chamador devolveu exatamente a frase exigida. */
function hasPhrase(args: Record<string, unknown>, expected: string): boolean {
  return typeof args.confirmPhrase === "string" && args.confirmPhrase === expected
}

/**
 * Avalia se a operação pode seguir. Falha fechada: na dúvida, bloqueia e explica.
 */
export function evaluateDestructiveOperation(
  operation: string,
  args: Record<string, unknown> = {},
): GuardVerdict {
  const spec = DESTRUCTIVE_OPERATIONS[operation]
  if (!spec) return { allowed: true }

  const target = spec.targetOf(args)
  const consequences = spec.consequences(args)
  const phrase = spec.risk === "irreversible" ? spec.phraseOf?.(args) ?? target : undefined

  const buildMessage = () => {
    const lines: string[] = []
    lines.push(`🛑 AÇÃO DESTRUTIVA BLOQUEADA — nenhuma alteração foi feita.`)
    lines.push("")
    lines.push(`**Operação**: \`${operation}\` (risco: ${spec.risk})`)
    lines.push(`**O que faria**: ${spec.verb}`)
    lines.push(`**Alvo**: ${target}`)
    lines.push("")
    lines.push("**Consequências:**")
    for (const c of consequences) {
      lines.push(`- ${c.item}${c.recoverable ? "" : "  ⚠️ **(sem volta)**"}`)
    }
    lines.push("")
    lines.push("**Para liberar, o OPERADOR HUMANO precisa confirmar.**")
    if (phrase) {
      lines.push(`Envie \`confirm: true\` **e** \`confirmPhrase\` exatamente igual a:`)
      lines.push("")
      lines.push(`    ${phrase}`)
      lines.push("")
      lines.push("(A frase existe para impedir confirmação automática.)")
    } else {
      lines.push(`Envie \`confirm: true\` na chamada — ou use o botão da interface do CyberLab OS.`)
    }
    lines.push("")
    lines.push(
      "> Regra do projeto: o agente não confirma em nome do operador. Mostre este plano,",
    )
    lines.push("> peça autorização e só então repita a chamada com a confirmação.")
    return lines.join("\n")
  }

  if (!hasConfirm(args)) {
    return {
      allowed: false,
      approval: {
        operation,
        risk: spec.risk,
        verb: spec.verb,
        target,
        consequences,
        requirement: phrase ? "confirm:true + confirmPhrase exata" : "confirm:true",
        ...(phrase ? { confirmPhrase: phrase } : {}),
        message: buildMessage(),
      },
    }
  }

  if (phrase && !hasPhrase(args, phrase)) {
    return {
      allowed: false,
      approval: {
        operation,
        risk: spec.risk,
        verb: spec.verb,
        target,
        consequences,
        requirement: "confirm:true + confirmPhrase exata",
        confirmPhrase: phrase,
        message: buildMessage(),
      },
    }
  }

  return { allowed: true }
}

/**
 * Helper fail-closed para quem executa a operação.
 *
 * Devolve o pedido de aprovação (em vez de só lançar) para que a camada de HTTP
 * possa respondê-lo com a mensagem completa: o agente precisa CONSEGUIR LER o plano
 * para mostrar ao operador. Erro sem corpo não ensina nada a ninguém.
 */
export function assertNotBlocked(operation: string, args: Record<string, unknown> = {}): void {
  const verdict = evaluateDestructiveOperation(operation, args)
  if (!verdict.allowed) {
    const err = new Error(verdict.approval.message)
    err.name = "DestructiveActionBlockedError"
    throw err
  }
}

/** Igual ao `assertNotBlocked`, mas devolve o pedido em vez de lançar (nunca lança). */
export function guardDestructive(
  operation: string,
  args: Record<string, unknown> = {},
): ApprovalRequest | null {
  const verdict = evaluateDestructiveOperation(operation, args)
  return verdict.allowed ? null : verdict.approval
}

/** Lista as operações protegidas — usado no help e nos testes de cobertura. */
export function listProtectedOperations(): string[] {
  return Object.keys(DESTRUCTIVE_OPERATIONS).sort()
}
