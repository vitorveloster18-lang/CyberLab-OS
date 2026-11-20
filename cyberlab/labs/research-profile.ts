/**
 * Fase C — Pesquisa (perfis por laboratório).
 *
 * A Fase C do ciclo metodológico (A–I) é definida em `packages/core/src/plugin/agent.ts`
 * como: consultar `CyberLab-Knowledge/` e **fontes primárias** sobre mecanismos,
 * histórico de falhas, patches anteriores e pressupostos de segurança.
 *
 * Antes tinha instrução mas não tinha ferramenta: o operador precisava sair do CyberLab,
 * abrir o navegador e montar a pesquisa à mão. Aqui a pesquisa passa a ser um artefato
 * versionado, reexecutável e com custódia SHA-256 — igual às evidências de Fase F.
 *
 * Nota metodológica importante (ver `limitations`): os labs do CyberLab são alvos
 * sintéticos escritos em `node:http` puro, **sem dependências de terceiros**. Não existe
 * CVE "do lab". O que a Fase C faz é pesquisar as tecnologias que o lab *emula*
 * (ex.: verificação JWT) para trazer o histórico real daquela classe de falha — que é
 * exatamente o que a metodologia pede ("histórico de falhas, patches anteriores").
 */

import type { LabSystemModel } from "./investigation-kit.js"

/** Ecossistemas aceitos pela GitHub Advisory Database (`GET /advisories`). */
export type AdvisoryEcosystem =
  | "npm"
  | "pip"
  | "go"
  | "maven"
  | "nuget"
  | "rubygems"
  | "rust"
  | "composer"
  | "erlang"
  | "pub"
  | "swift"
  | "actions"

export const ADVISORY_ECOSYSTEMS: readonly AdvisoryEcosystem[] = [
  "npm",
  "pip",
  "go",
  "maven",
  "nuget",
  "rubygems",
  "rust",
  "composer",
  "erlang",
  "pub",
  "swift",
  "actions",
]

export interface AdvisoryTarget {
  ecosystem: AdvisoryEcosystem
  package: string
  /** Por que este pacote é relevante para o lab — vai para o relatório. */
  rationale: string
  /**
   * Termos que ligam os advisories deste pacote a uma hipótese da Fase D.
   * Sem isso a Fase C e a Fase D ficam desconectadas: a pesquisa lista CVEs e
   * nenhuma hipótese cita nenhum.
   *
   * A casa é por PALAVRA (ver `keywordMatches`), não por substring, e os termos
   * precisam ser específicos: com `token` na lista, a hipótese de BOLA — que
   * menciona "o token do User A" — puxava todos os 32 advisories de JWT, um falso
   * positivo que faria o operador crer que BOLA tem CVE de biblioteca.
   */
  anchorKeywords: string[]
}

export interface WeaknessReference {
  /** Identificador CWE (ex.: `CWE-639`). */
  cwe: string
  name: string
  /** Referência OWASP quando houver (ex.: `API1:2023 BOLA`). */
  owasp?: string
  why: string
}

export interface PrimarySource {
  title: string
  url: string
  kind: "rfc" | "owasp" | "cwe" | "advisory" | "spec"
  note: string
  /** Mesma semântica de `AdvisoryTarget.anchorKeywords`: liga a fonte à hipótese. */
  anchorKeywords: string[]
}

/**
 * Marcadores observáveis que, se presentes na resposta bruta, **sustentam** a
 * hipótese. São literais que o lab realmente devolve (conferidos contra o servidor
 * de treino): nada aqui é suposição.
 *
 * Hipótese sem marcador (ex.: ausência de headers de segurança) fica com lista
 * vazia e o relatório diz que a avaliação é manual — inventar um marcador para
 * "ausência" produziria veredito falso.
 */
/**
 * Declaração de impacto POR HIPÓTESE, usada pela Fase H (Validação).
 *
 * Por que declarar em vez de deduzir do texto: a Fase H precisa separar
 * "vulnerabilidade confirmada" de "configuração insegura" — e a diferença é o impacto,
 * não o sintoma. Inferir isso de `severityIfConfirmed` com casamento de palavras
 * produziria classificação que muda quando alguém reescreve uma frase. Aqui o impacto
 * é declarado uma vez, por hipótese, e a Fase H só aplica a regra em cima dele.
 */
export interface ImpactDeclaration {
  /** Dimensão primária afetada caso a hipótese se confirme. */
  dimension: "confidentiality" | "integrity" | "availability" | "none"
  /**
   * `direct`               — vetor explorável contra C/I/A.
   * `information-disclosure` — prova o diferencial, mas o dano é exposição de informação.
   * `none`                 — mecanismo de proteção ausente/desligado, sem vetor direto.
   */
  vector: "direct" | "information-disclosure" | "none"
  /** Por quê — vai para o relatório da Fase H. */
  rationale: string
}

export interface LabResearchProfile {
  labId: string
  /** Marcador(es) por hipótese: `H1 -> ["LAB{BOLA_...}"]`. */
  observationMarkers: Record<string, string[]>
  /** Impacto por hipótese, consumido pela Fase H. */
  impactByHypothesis: Record<string, ImpactDeclaration>
  /** Termos para buscar na biblioteca curada `CyberLab-Knowledge/` (Fase C, parte 1). */
  knowledgeQueries: string[]
  /** Pacotes a consultar na GitHub Advisory Database (Fase C, parte 2). */
  advisoryTargets: AdvisoryTarget[]
  /** Classes de fraqueza exercitadas pelo lab, com a justificativa técnica. */
  weaknesses: WeaknessReference[]
  /** Fontes primárias (RFC/OWASP/CWE) que sustentam a análise. */
  primarySources: PrimarySource[]
  /** Limitações declaradas — a Fase C NÃO deve inflar achados. */
  limitations: string[]
}

const LAB_RESEARCH_PROFILES: Record<string, LabResearchProfile> = {
  "lab-owasp-api-bola": {
    labId: "lab-owasp-api-bola",
    observationMarkers: {
      H1: ["LAB{BOLA_CROSS_ACCOUNT_EXPOSED}", "bob@corp.lab"],
      H2: ["LAB{JWT_ALG_NONE_ACCEPTED}", '"adminAccess": true'],
      H3: ["SQLITE_ERROR"],
      // H4 é AUSÊNCIA de headers: não há marcador de presença possível.
      H4: [],
    },
    impactByHypothesis: {
      H1: {
        dimension: "confidentiality",
        vector: "direct",
        rationale:
          "Leitura de conta alheia (saldo e dados do titular) autenticando-se apenas com o próprio token — acesso direto a dados de outro usuário.",
      },
      H2: {
        dimension: "confidentiality",
        vector: "direct",
        rationale:
          "Forja de identidade administrativa sem segredo: o endpoint administrativo responde com `adminAccess: true` a um token sem assinatura.",
      },
      H3: {
        dimension: "confidentiality",
        vector: "information-disclosure",
        rationale:
          "A resposta de erro revela estrutura interna (nome de tabela e colunas). O diferencial é provado, mas o dano é exposição de informação, não leitura direta de dados.",
      },
      H4: {
        dimension: "none",
        vector: "none",
        rationale:
          "CSP/HSTS/X-Frame-Options ausentes: mecanismos de proteção disponíveis e desligados, sem vetor de exploração direto — é achado de hardening.",
      },
    },
    knowledgeQueries: ["BOLA", "IDOR", "JWT", "OAuth 2.0", "SQL Injection", "API Security"],
    advisoryTargets: [
      {
        ecosystem: "npm",
        package: "jsonwebtoken",
        rationale:
          "O desafio `jwt-alg-none` do lab aceita JWT com `alg:none`. Esta é a biblioteca cujo histórico real documenta essa classe de falha (CVE-2015-9235, bypass de verificação de assinatura).",
        anchorKeywords: ["jwt", "alg:none", "alg=none", "assinatura", "signature"],
      },
      {
        ecosystem: "npm",
        package: "jose",
        rationale:
          "Sucessor moderno de `jsonwebtoken`. Serve como contraponto: como a mesma operação é implementada corretamente (lista explícita de algoritmos permitidos).",
        anchorKeywords: ["jwt", "alg:none", "alg=none", "assinatura", "signature"],
      },
      {
        ecosystem: "pip",
        package: "pyjwt",
        rationale:
          "Mesma classe de falha em outro ecossistema (confusão de algoritmo / `alg` não validado). Confirma que o problema é do padrão, não de uma biblioteca específica.",
        anchorKeywords: ["jwt", "alg:none", "alg=none", "assinatura", "signature"],
      },
    ],
    weaknesses: [
      {
        cwe: "CWE-639",
        name: "Authorization Bypass Through User-Controlled Key",
        owasp: "API1:2023 — BOLA (Broken Object Level Authorization)",
        why: "`/api/v1/accounts/:id` aceita o id direto do cliente e só compara com o titular quando `enforceAccountOwnership` está ligado. Desligado, o id é a única 'autorização'.",
      },
      {
        cwe: "CWE-347",
        name: "Improper Verification of Cryptographic Signature",
        owasp: "API5:2023 — Broken Function Level Authorization (via forja de identidade admin)",
        why: "`/api/v1/admin/debug` confia no campo `alg` do próprio token. Com `alg:none` a assinatura é vazia e o papel `admin` é aceito sem chave.",
      },
      {
        cwe: "CWE-209",
        name: "Generation of Error Message Containing Sensitive Information",
        why: "`/api/v1/search?q='` devolve o erro do motor de consulta ao cliente, revelando estrutura interna quando `sanitizeSqlQuery` está desligado.",
      },
      {
        cwe: "CWE-693",
        name: "Protection Mechanism Failure",
        why: "Com `enableSecurityHeaders` desligado não há CSP, HSTS nem X-Frame-Options — mecanismos de proteção disponíveis e simplesmente ausentes.",
      },
    ],
    primarySources: [
      {
        title: "RFC 8725 — JWT Best Current Practices, §3.1 e §3.2",
        url: "https://www.rfc-editor.org/rfc/rfc8725.html",
        kind: "rfc",
        note: "Exige que o receptor determine explicitamente quais algoritmos aceita; proíbe confiar no `alg` do token. É a fonte primária do desafio `jwt-alg-none`.",
        anchorKeywords: ["jwt", "alg:none", "assinatura", "signature"],
      },
      {
        title: "RFC 7519 — JSON Web Token (JWT)",
        url: "https://www.rfc-editor.org/rfc/rfc7519.html",
        kind: "rfc",
        note: "Define o cabeçalho `alg` e o JWS. O `alg:none` é permitido pela spec e é justamente por isso que o receptor precisa rejeitá-lo.",
        anchorKeywords: ["jwt", "alg:none", "assinatura"],
      },
      {
        title: "OWASP API Security Top 10 2023 — API1 BOLA",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        kind: "owasp",
        note: "Fonte primária do desafio `bola-1002`.",
        anchorKeywords: ["bola", "idor", "api1:2023"],
      },
      {
        title: "MITRE CWE-639 — Authorization Bypass Through User-Controlled Key",
        url: "https://cwe.mitre.org/data/definitions/639.html",
        kind: "cwe",
        note: "Classificação formal da fraqueza exercitada em `/api/v1/accounts/:id`.",
        anchorKeywords: ["bola", "idor", "api1:2023"],
      },
      {
        title: "MITRE CWE-347 — Improper Verification of Cryptographic Signature",
        url: "https://cwe.mitre.org/data/definitions/347.html",
        kind: "cwe",
        note: "Classificação formal do bypass `alg:none`.",
        anchorKeywords: ["jwt", "alg:none", "assinatura", "signature"],
      },
      {
        title: "MITRE CWE-209 — Information Exposure Through an Error Message",
        url: "https://cwe.mitre.org/data/definitions/209.html",
        kind: "cwe",
        note: "Classificação formal do vazamento em `/api/v1/search`.",
        anchorKeywords: ["sql", "erro sql"],
      },
    ],
    limitations: [
      "O lab é um alvo sintético em `node:http` puro, SEM dependências de terceiros. Os advisories listados referem-se às tecnologias que ele EMULA — **não são CVEs do próprio lab**.",
      "A consulta usa a GitHub Advisory Database (`api.github.com/advisories`). Sem token o limite é de 60 requisições/hora; com `GITHUB_TOKEN`/`GH_TOKEN` sobe para 5.000/hora.",
      "A presença de advisories para um pacote NÃO significa que o lab é vulnerável a eles. É contexto histórico da classe de falha, não achado.",
      "Resultado negativo também é resultado: se uma consulta não retornar advisories, isso é registrado explicitamente no relatório.",
    ],
  },
}

/**
 * Perfil curado, ou um perfil derivado do modelo quando o lab ainda não tem curadoria.
 * O perfil derivado não inventa pacotes: fica só com a busca na biblioteca curada.
 */
export function getLabResearchProfile(labId: string): LabResearchProfile {
  return LAB_RESEARCH_PROFILES[labId] ?? deriveProfile(labId)
}

export function hasCuratedResearchProfile(labId: string): boolean {
  return Object.prototype.hasOwnProperty.call(LAB_RESEARCH_PROFILES, labId)
}

export function listCuratedResearchProfileIds(): string[] {
  return Object.keys(LAB_RESEARCH_PROFILES)
}

/**
 * Extrai termos de busca das tecnologias/componentes do modelo (Fase B).
 * Deliberadamente conservador: corta ruído (`http`, `node:http`, parênteses) e mantém
 * só termos com valor de busca real.
 */
export function deriveProfile(labId: string, model?: LabSystemModel | null): LabResearchProfile {
  const noise = new Set([
    "http",
    "https",
    "node",
    "node:http",
    "node.js",
    "api",
    "rest",
    "sem",
    "framework",
    "server",
    "servidor",
    "cliente",
    "handler",
    "com",
    "para",
    "uma",
    "the",
    "and",
  ])
  const terms = new Set<string>()
  const push = (value: string) => {
    for (const raw of value.split(/[^A-Za-z0-9+#.\-]+/)) {
      const t = raw.trim().toLowerCase()
      if (t.length < 3 || noise.has(t)) continue
      if (/^\d+$/.test(t)) continue
      terms.add(t)
    }
  }
  for (const tech of model?.technologies ?? []) push(tech)
  for (const comp of model?.components ?? []) push(comp)

  return {
    labId,
    observationMarkers: {},
    // Sem curadoria não há impacto declarado: a Fase H cai em `nao_classificado`
    // em vez de presumir um vetor.
    impactByHypothesis: {},
    knowledgeQueries: Array.from(terms).slice(0, 12),
    advisoryTargets: [],
    weaknesses: [],
    primarySources: [],
    limitations: [
      "Este lab ainda não tem perfil de pesquisa curado: o relatório foi derivado automaticamente do modelo de Fase B.",
      "Nenhum pacote foi consultado na GitHub Advisory Database — sem curadoria, inferir pacotes a partir do modelo produziria falso positivo.",
    ],
  }
}
