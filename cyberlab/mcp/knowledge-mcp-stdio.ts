#!/usr/bin/env bun
/**
 * CyberLab OS — MCP server da Biblioteca de Conhecimento (JSON-RPC 2.0, stdio).
 *
 * Serve as 8 ferramentas de conhecimento e memória investigativa:
 *   search_knowledge · read_document · get_related_documents
 *   get_document_metadata · create_draft_note · propose_document_update
 *   investigation_memory_read · investigation_memory_update
 *
 * POR QUE EXISTE SEPARADO: essas ferramentas moravam dentro do hub MCP do
 * Arsenal. Quando o arsenal saiu (as ferramentas agora vivem no Kali e rodam
 * nativas por `cyberlab exec`), o hub foi removido junto — e a biblioteca
 * ficou sem servidor MCP. Este arquivo devolve a biblioteca ao ar, sem
 * arsenal, sem ponte WSL, sem navegador com proxy e sem bridges de GUI.
 *
 * Roda como um ÚNICO processo leve de stdio. Aceita tanto frames
 * `Content-Length:` quanto JSON linha-a-linha, porque clientes diferentes
 * usam um ou outro.
 */

import path from "node:path"

import { redactSensitiveContent } from "../evidence/provenance.js"
import {
  CyberLabKnowledgeEngine,
  type ExternalReferenceRecord,
  type InvestigationExperimentRecord,
  type InvestigationHypothesis,
} from "../knowledge/curated-library.js"

const argv = process.argv.slice(2)
function readArg(flag: string, fallback = ""): string {
  const idx = argv.indexOf(flag)
  return idx !== -1 && argv[idx + 1] ? argv[idx + 1]! : fallback
}

const workspaceRoot = path.resolve(readArg("--workspace", process.cwd()))

interface JsonRpcRequest {
  jsonrpc?: string
  id?: string | number | null
  method?: string
  params?: Record<string, unknown>
}

let useContentLengthFraming = false

function sendResponse(payload: Record<string, unknown>): void {
  const json = JSON.stringify(payload)
  if (useContentLengthFraming) {
    const byteLen = Buffer.byteLength(json, "utf8")
    process.stdout.write(`Content-Length: ${byteLen}\r\n\r\n${json}`)
  } else {
    process.stdout.write(`${json}\n`)
  }
}

// ---------------------------------------------------------------------------
// Definição das ferramentas
// ---------------------------------------------------------------------------

const KNOWLEDGE_TOOLS = [
  {
    name: "search_knowledge",
    description:
      "Pesquisa na biblioteca curada CyberLab-Knowledge/ (Cofre Obsidian) por conceito, vulnerabilidade, CVE, metodologia, ferramenta ou tecnologia — retornando título, versão, fontes, limitações e seções relevantes.",
    inputSchema: {
      type: "object",
      required: ["query"],
      properties: {
        query: { type: "string", description: "Termo, CVE, técnica ou pergunta de pesquisa." },
        category: { type: "string", description: "Categoria opcional para restringir a busca." },
        includeDrafts: { type: "boolean", description: "Incluir rascunhos do operador na busca." },
        limit: { type: "number", description: "Máximo de resultados (padrão: 10)." },
      },
    },
  },
  {
    name: "read_document",
    description:
      "Lê um documento da biblioteca curada com seus metadados de origem completos (fontes primárias, limitações declaradas, versão e última revisão).",
    inputSchema: {
      type: "object",
      required: ["docPath"],
      properties: {
        docPath: {
          type: "string",
          description: "Caminho do documento (ex.: methodologies/hypothesis-driven-testing).",
        },
      },
    },
  },
  {
    name: "get_related_documents",
    description:
      "Lista os documentos relacionados a um documento da biblioteca, com o tipo de relação e o detalhe de cada vínculo.",
    inputSchema: {
      type: "object",
      required: ["docPath"],
      properties: {
        docPath: { type: "string", description: "Caminho do documento de origem." },
      },
    },
  },
  {
    name: "get_document_metadata",
    description:
      "Retorna apenas os metadados de proveniência de um documento (tier, status, versão, fontes, limitações, relacionados).",
    inputSchema: {
      type: "object",
      required: ["docPath"],
      properties: {
        docPath: { type: "string", description: "Caminho do documento." },
      },
    },
  },
  {
    name: "create_draft_note",
    description:
      "Cria uma nota de rascunho na camada de drafts do operador (nunca toca os documentos curados). Separa fatos observados de hipóteses e inferências.",
    inputSchema: {
      type: "object",
      required: ["slug", "factsObserved"],
      properties: {
        slug: { type: "string", description: "Identificador curto do rascunho (ex.: bola-api-idor)." },
        title: { type: "string", description: "Título da nota." },
        category: { type: "string" },
        factsObserved: { type: "array", items: { type: "string" }, description: "O que foi efetivamente observado." },
        hypotheses: { type: "array", items: { type: "string" } },
        inferences: { type: "array", items: { type: "string" } },
        uncertainties: { type: "array", items: { type: "string" } },
        sources: { type: "array", items: { type: "string" } },
        limitations: { type: "array", items: { type: "string" } },
        relatedDocs: { type: "array", items: { type: "string" } },
        tags: { type: "array", items: { type: "string" } },
        additionalMarkdown: { type: "string" },
      },
    },
  },
  {
    name: "propose_document_update",
    description:
      "Propõe uma atualização em documento curado. Nunca escreve direto: gera proposta com justificativa e fontes primárias para revisão.",
    inputSchema: {
      type: "object",
      required: ["targetDocPath", "rationale", "proposedContent"],
      properties: {
        targetDocPath: { type: "string" },
        targetSection: { type: "string" },
        rationale: { type: "string" },
        proposedContent: { type: "string" },
        primarySources: { type: "array", items: { type: "string" } },
        limitations: { type: "array", items: { type: "string" } },
      },
    },
  },
  {
    name: "investigation_memory_read",
    description:
      "Lê a memória investigativa de uma sessão: sistema modelado, hipóteses, experimentos, resultados negativos e próximos passos.",
    inputSchema: {
      type: "object",
      properties: {
        investigationId: { type: "string", description: "ID da investigação (padrão: sessao-atual)." },
      },
    },
  },
  {
    name: "investigation_memory_update",
    description:
      "Atualiza a memória investigativa. Preserva resultados negativos — eles são evidência do que NÃO é, e apagá-los faz repetir o mesmo teste.",
    inputSchema: {
      type: "object",
      properties: {
        investigationId: { type: "string" },
        mission: { type: "string" },
        authorizedScope: { type: "string" },
        systemModel: {
          type: "object",
          properties: {
            components: { type: "array", items: { type: "string" } },
            technologies: { type: "array", items: { type: "string" } },
            dataFlows: { type: "array", items: { type: "string" } },
            trustBoundaries: { type: "array", items: { type: "string" } },
            identitiesAndPermissions: { type: "array", items: { type: "string" } },
          },
        },
        hypotheses: { type: "array", items: { type: "object" } },
        experiments: { type: "array", items: { type: "object" } },
        negativeResults: { type: "array", items: { type: "string" } },
        decisions: { type: "array", items: { type: "string" } },
        externalReferences: { type: "array", items: { type: "object" } },
        openQuestions: { type: "array", items: { type: "string" } },
        nextSteps: { type: "array", items: { type: "string" } },
      },
    },
  },
] as const

// ---------------------------------------------------------------------------
// Despacho
// ---------------------------------------------------------------------------

function toStrArr(v: unknown): string[] | undefined {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : undefined
}

function handleToolCall(
  id: string | number | null,
  toolName: string,
  callArgs: Record<string, unknown>,
): void {
  try {
    const engine = new CyberLabKnowledgeEngine({ workspaceRoot })

    if (toolName === "search_knowledge") {
      const hits = engine.searchKnowledge({
        query: typeof callArgs.query === "string" ? callArgs.query : "",
        category: typeof callArgs.category === "string" ? callArgs.category : undefined,
        includeDrafts: Boolean(callArgs.includeDrafts),
        limit: typeof callArgs.limit === "number" ? callArgs.limit : 10,
      })
      const text =
        hits.length === 0
          ? "Nenhum documento encontrado para a busca informada na biblioteca CyberLab-Knowledge/."
          : hits
              .map(
                (h, i) =>
                  `${i + 1}. **${h.title}** (\`${h.docPath}\` | tier: \`${h.tier}\` | v${h.version} | rev: ${h.last_reviewed})\n   - Fontes: ${h.sources.join("; ") || "n/d"}\n   - Seções: ${h.matchedSections.join(", ") || "geral"}\n   - Resumo: ${h.excerpt}`,
              )
              .join("\n\n")
      sendResponse({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } })
      return
    }

    if (toolName === "read_document") {
      const doc = engine.readDocument(String(callArgs.docPath ?? ""))
      const m = doc.metadata
      const header = [
        `# Metadados de Origem (\`${m.docPath}\`)`,
        `- **Título**: ${m.title}`,
        `- **Camada Epistemológica**: \`${m.tier}\` (status: \`${m.status}\`)`,
        `- **Versão / Última Revisão**: \`${m.version}\` / \`${m.last_reviewed}\``,
        `- **Fontes Primárias**: ${m.sources.join(" | ") || "n/d"}`,
        `- **Limitações**: ${m.limitations.join(" | ") || "nenhuma declarada"}`,
        `- **Documentos Relacionados**: ${m.related.join(", ") || "nenhum"}`,
        "",
        "---",
        "",
        doc.body,
      ].join("\n")
      sendResponse({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: redactSensitiveContent(header).text }] },
      })
      return
    }

    if (toolName === "get_document_metadata") {
      const meta = engine.getDocumentMetadata(String(callArgs.docPath ?? ""))
      sendResponse({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: JSON.stringify(meta, null, 2) }] },
      })
      return
    }

    if (toolName === "get_related_documents") {
      const rel = engine.getRelatedDocuments(String(callArgs.docPath ?? ""))
      const lines =
        rel.related.length === 0
          ? `Nenhum documento relacionado encontrado para \`${rel.sourceDocPath}\`.`
          : [
              `# Relações a partir de \`${rel.sourceDocPath}\``,
              ...rel.related.map(
                (r) => `- **${r.title}** (\`${r.docPath}\` | \`${r.tier}\` | ${r.relationType}): ${r.detail}`,
              ),
            ].join("\n")
      sendResponse({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: lines }] } })
      return
    }

    if (toolName === "create_draft_note") {
      const out = engine.createDraftNote({
        slug: String(callArgs.slug ?? ""),
        title: String(callArgs.title ?? "Rascunho Técnico"),
        category: typeof callArgs.category === "string" ? callArgs.category : undefined,
        factsObserved: toStrArr(callArgs.factsObserved) ?? [],
        hypotheses: toStrArr(callArgs.hypotheses),
        inferences: toStrArr(callArgs.inferences),
        uncertainties: toStrArr(callArgs.uncertainties),
        sources: toStrArr(callArgs.sources),
        limitations: toStrArr(callArgs.limitations),
        relatedDocs: toStrArr(callArgs.relatedDocs),
        tags: toStrArr(callArgs.tags),
        additionalMarkdown:
          typeof callArgs.additionalMarkdown === "string" ? callArgs.additionalMarkdown : undefined,
      })
      sendResponse({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: out.message }] } })
      return
    }

    if (toolName === "propose_document_update") {
      const out = engine.proposeDocumentUpdate({
        targetDocPath: String(callArgs.targetDocPath ?? ""),
        targetSection: String(callArgs.targetSection ?? "Geral"),
        rationale: String(callArgs.rationale ?? ""),
        proposedContent: String(callArgs.proposedContent ?? ""),
        primarySources: toStrArr(callArgs.primarySources) ?? [],
        limitations: toStrArr(callArgs.limitations) ?? [],
      })
      sendResponse({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: out.message }] } })
      return
    }

    if (toolName === "investigation_memory_read") {
      const mem = engine.readInvestigationMemory(
        typeof callArgs.investigationId === "string" ? callArgs.investigationId : "sessao-atual",
      )
      sendResponse({
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: redactSensitiveContent(JSON.stringify(mem, null, 2)).text }],
        },
      })
      return
    }

    if (toolName === "investigation_memory_update") {
      const nowIso = new Date().toISOString()

      const hypotheses = Array.isArray(callArgs.hypotheses)
        ? (callArgs.hypotheses as Array<Record<string, unknown>>).map(
            (h): InvestigationHypothesis => ({
              id: String(h.id ?? "H1"),
              title: String(h.title ?? ""),
              expectedBehavior: String(h.expectedBehavior ?? ""),
              suspectedBehavior: String(h.suspectedBehavior ?? ""),
              fragileAssumption: String(h.fragileAssumption ?? ""),
              technicalRationale: String(h.technicalRationale ?? ""),
              evidenceNeeded: String(h.evidenceNeeded ?? ""),
              alternativeExplanations: Array.isArray(h.alternativeExplanations)
                ? h.alternativeExplanations.map(String)
                : [],
              status:
                h.status === "testing" ||
                h.status === "supported" ||
                h.status === "refuted" ||
                h.status === "inconclusive"
                  ? h.status
                  : "proposed",
              updatedAt: nowIso,
            }),
          )
        : undefined

      const experiments = Array.isArray(callArgs.experiments)
        ? (callArgs.experiments as Array<Record<string, unknown>>).map(
            (e): InvestigationExperimentRecord => ({
              id: String(e.id ?? "EXP-1"),
              hypothesisId: typeof e.hypothesisId === "string" ? e.hypothesisId : undefined,
              question: String(e.question ?? ""),
              toolUsed: String(e.toolUsed ?? ""),
              initialConditions: String(e.initialConditions ?? ""),
              modifiedVariable: String(e.modifiedVariable ?? ""),
              expectedOutcome: String(e.expectedOutcome ?? ""),
              observedOutcome: String(e.observedOutcome ?? ""),
              verdict:
                e.verdict === "supports_hypothesis" ||
                e.verdict === "weakens_hypothesis" ||
                e.verdict === "negative_result"
                  ? e.verdict
                  : "inconclusive",
              recordedAt: nowIso,
            }),
          )
        : undefined

      const externalReferences = Array.isArray(callArgs.externalReferences)
        ? (callArgs.externalReferences as Array<Record<string, unknown>>).map(
            (r): ExternalReferenceRecord => ({
              title: String(r.title ?? ""),
              sourceUrlOrRef: String(r.sourceUrlOrRef ?? ""),
              versionOrCommit: typeof r.versionOrCommit === "string" ? r.versionOrCommit : undefined,
              accessedAt: nowIso,
              applicabilityNote: String(r.applicabilityNote ?? ""),
            }),
          )
        : undefined

      const sysObj =
        callArgs.systemModel && typeof callArgs.systemModel === "object"
          ? (callArgs.systemModel as Record<string, unknown>)
          : undefined

      const out = engine.updateInvestigationMemory({
        investigationId:
          typeof callArgs.investigationId === "string" ? callArgs.investigationId : "sessao-atual",
        mission: typeof callArgs.mission === "string" ? callArgs.mission : undefined,
        authorizedScope:
          typeof callArgs.authorizedScope === "string" ? callArgs.authorizedScope : undefined,
        systemModel: sysObj
          ? {
              components: toStrArr(sysObj.components) ?? [],
              technologies: toStrArr(sysObj.technologies) ?? [],
              dataFlows: toStrArr(sysObj.dataFlows) ?? [],
              trustBoundaries: toStrArr(sysObj.trustBoundaries) ?? [],
              identitiesAndPermissions: toStrArr(sysObj.identitiesAndPermissions) ?? [],
            }
          : undefined,
        hypotheses,
        experiments,
        negativeResults: toStrArr(callArgs.negativeResults),
        decisions: toStrArr(callArgs.decisions),
        externalReferences,
        openQuestions: toStrArr(callArgs.openQuestions),
        nextSteps: toStrArr(callArgs.nextSteps),
      })

      sendResponse({
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: `Memória investigativa atualizada (${out.memory.investigationId}) e sincronizada em vault/${out.vaultMirrorPath}.`,
            },
          ],
        },
      })
      return
    }

    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        isError: true,
        content: [{ type: "text", text: `Ferramenta desconhecida: ${toolName}` }],
      },
    })
  } catch (err) {
    sendResponse({
      jsonrpc: "2.0",
      id,
      result: {
        isError: true,
        content: [{ type: "text", text: err instanceof Error ? err.message : String(err) }],
      },
    })
  }
}

async function handleRpc(msg: JsonRpcRequest): Promise<void> {
  if (msg.method === "notifications/initialized" || msg.id === undefined) return

  if (msg.method === "initialize") {
    sendResponse({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "cyberlab-knowledge", version: "1.0.0" },
      },
    })
    return
  }

  if (msg.method === "ping") {
    sendResponse({ jsonrpc: "2.0", id: msg.id, result: {} })
    return
  }

  if (msg.method === "tools/list") {
    sendResponse({ jsonrpc: "2.0", id: msg.id, result: { tools: KNOWLEDGE_TOOLS } })
    return
  }

  if (msg.method === "tools/call") {
    const params = msg.params ?? {}
    const toolName = typeof params.name === "string" ? params.name : ""
    const callArgs =
      params.arguments && typeof params.arguments === "object"
        ? (params.arguments as Record<string, unknown>)
        : {}
    handleToolCall(msg.id ?? null, toolName, callArgs)
    return
  }

  sendResponse({
    jsonrpc: "2.0",
    id: msg.id,
    error: { code: -32601, message: `Método não suportado: ${String(msg.method)}` },
  })
}

let rpcQueue: Promise<void> = Promise.resolve()
function enqueueRpc(req: JsonRpcRequest): void {
  rpcQueue = rpcQueue.then(() => handleRpc(req)).catch(() => undefined)
}

let buffer = Buffer.alloc(0)
process.stdin.on("data", (chunk: Buffer) => {
  buffer = Buffer.concat([buffer, chunk])
  while (buffer.length > 0) {
    const preview = buffer.toString("utf8", 0, Math.min(buffer.length, 64))
    if (preview.startsWith("Content-Length:")) {
      useContentLengthFraming = true
      const headerEnd = buffer.indexOf("\r\n\r\n")
      if (headerEnd === -1) return
      const headerStr = buffer.toString("utf8", 0, headerEnd)
      const match = headerStr.match(/Content-Length:\s*(\d+)/i)
      const len = match ? Number.parseInt(match[1]!, 10) : 0
      const totalNeeded = headerEnd + 4 + len
      if (buffer.length < totalNeeded) return
      const bodyStr = buffer.toString("utf8", headerEnd + 4, totalNeeded)
      buffer = buffer.subarray(totalNeeded)
      try {
        enqueueRpc(JSON.parse(bodyStr) as JsonRpcRequest)
      } catch {
        // Frame malformado: ignora.
      }
    } else {
      const nlIdx = buffer.indexOf("\n")
      if (nlIdx === -1) return
      const line = buffer.toString("utf8", 0, nlIdx).trim()
      buffer = buffer.subarray(nlIdx + 1)
      if (!line) continue
      try {
        enqueueRpc(JSON.parse(line) as JsonRpcRequest)
      } catch {
        // Linha malformada: ignora.
      }
    }
  }
})
