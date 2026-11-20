import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import path from "node:path"
import type {
  ExternalReferenceRecord,
  InvestigationExperimentRecord,
  InvestigationHypothesis,
} from "../knowledge/curated-library.js"

/**
 * Kit de Investigação para Laboratórios de Treino (v6.4).
 *
 * MOTIVAÇÃO (relatório de calibração da Fase A): o orquestrador concluiu que
 * "nenhuma capacidade de execução foi validada com evidência real" porque:
 *   1. o servidor do lab nunca foi iniciado (a nota `Diario-Labs` citava a porta
 *      `4101`, que não existe — a porta real é `19081`);
 *   2. não havia modelo do sistema (Fase B), hipóteses registradas (Fase D)
 *      nem protocolo de experimento (Fase F) — a memória investigativa estava vazia.
 *
 * Este módulo gera, dentro do workspace do lab, os artefatos prontos das Fases
 * B/D/F para que o operador só precise executar e coletar evidência:
 *   - `LAB_SYSTEM_MODEL.md`  + `lab-system-model.json`  (Fase B — Modelagem)
 *   - `HYPOTHESES.md`        + `lab-hypotheses.json`    (Fase D — Hipóteses)
 *   - `EXPERIMENTS.md`       + `lab-experiments.json`   (Fase F — Experimentação)
 *   - `investigation-memory-seed.json` (consumível por `investigation_memory_update`)
 *
 * Zero dependências externas (apenas `node:fs` / `node:path`).
 */

export interface LabEndpointModel {
  id: string
  method: string
  path: string
  purpose: string
  /** Invariante de autorização que deveria valir. */
  invariant: string
  /** Controle em `server-config.json` que repara o problema. */
  controlFlag: string | null
  /** Dados sensíveis expostos quando o invariante falha. */
  sensitiveData: string[]
}

export interface LabIdentityModel {
  id: string
  kind: "user" | "admin" | "anonymous"
  credential: string
  permissions: string[]
}

export interface LabHypothesisSeed {
  id: string
  title: string
  /** Comportamento esperado se o sistema estiver seguro. */
  expectedBehavior: string
  /** Comportamento suspeito a confirmar/refutar. */
  suspectedBehavior: string
  /** Pressuposto frágil que, se falso, produz a falha. */
  fragileAssumption: string
  /** Por que tecnicamente isso pode acontecer. */
  technicalRationale: string
  /** Evidência mínima aceitável (critério de parada). */
  evidenceNeeded: string
  /** Explicações alternativas que também produziriam a observação. */
  alternativeExplanations: string[]
  status: "proposed"
  relatedControlFlag: string | null
  /** Categoria da taxonomia de 5 níveis ([[evidence-validation]]). */
  severityIfConfirmed: string
}

export interface LabExperimentSeed {
  id: string
  hypothesisId: string
  question: string
  toolUsed: string
  initialConditions: string
  /** SOMENTE UMA variável por experimento (método científico). */
  modifiedVariable: string
  expectedOutcome: string
  /** Preenchido pelo operador/agente após execução. */
  observedOutcome: string
  verdict: "inconclusive"
  /** Critério objetivo de parada. */
  stopCriterion: string
  /** Comandos prontos (curl funciona em Windows PowerShell e WSL2). */
  commands: string[]
}

export interface LabSystemModel {
  labId: string
  title: string
  baseUrl: string
  components: string[]
  technologies: string[]
  dataFlows: string[]
  trustBoundaries: string[]
  identitiesAndPermissions: string[]
  endpoints: LabEndpointModel[]
  identities: LabIdentityModel[]
  controlsFile: string | null
  controls: Record<string, boolean>
}

export interface LabInvestigationKit {
  labId: string
  title: string
  baseUrl: string
  systemModel: LabSystemModel
  hypotheses: LabHypothesisSeed[]
  experiments: LabExperimentSeed[]
}

// ---------------------------------------------------------------------------
// lab-owasp-api-bola
// ---------------------------------------------------------------------------

const BOLA_ENDPOINTS: LabEndpointModel[] = [
  {
    id: "ep-health",
    method: "GET",
    path: "/health",
    purpose: "Diagnóstico do lab: lista controles ativos, endpoints e tokens de exemplo.",
    invariant: "Endpoint de diagnóstico não deve expor material de autenticação em produção.",
    controlFlag: null,
    sensitiveData: ["sampleUserAToken", "sampleUserBToken", "sampleForgedAlgNoneJwt"],
  },
  {
    id: "ep-openapi",
    method: "GET",
    path: "/openapi.json",
    purpose: "Especificação OpenAPI 3.0.3 da Banking API de treino.",
    invariant: "Especificação não revela endpoints administrativos não documentados.",
    controlFlag: null,
    sensitiveData: [],
  },
  {
    id: "ep-accounts",
    method: "GET",
    path: "/api/v1/accounts/:accountId",
    purpose: "Retorna titular e saldo de uma conta (1001 = User A, 1002 = User B).",
    invariant:
      "Somente o titular autenticado pode ler a própria conta; qualquer leitura cruzada deve retornar 403.",
    controlFlag: "enforceAccountOwnership",
    sensitiveData: ["owner (e-mail)", "balanceUsd", "bolaFlag"],
  },
  {
    id: "ep-admin-debug",
    method: "GET",
    path: "/api/v1/admin/debug",
    purpose: "Diagnóstico administrativo protegido por JWT.",
    invariant:
      "Apenas JWT com assinatura válida E claim role=admin; token com alg:none deve ser rejeitado.",
    controlFlag: "rejectAlgNoneJwt",
    sensitiveData: ["adminAccess", "flag LAB{JWT_ALG_NONE_ACCEPTED}"],
  },
  {
    id: "ep-search",
    method: "GET",
    path: "/api/v1/search?q=",
    purpose: "Busca de transações por memo.",
    invariant:
      "Entrada maliciosa nunca deve ecoar erro SQL nem a consulta montada; deve retornar erro genérico.",
    controlFlag: "sanitizeSqlQuery",
    sensitiveData: ["Estrutura da consulta SQL", "Nomes de colunas (id, amount, memo, tabela ledger)"],
  },
]

const BOLA_IDENTITIES: LabIdentityModel[] = [
  {
    id: "user-a",
    kind: "user",
    credential: "Authorization: Bearer token-user-a-1001",
    permissions: ["accounts:read:own(1001)", "search:read"],
  },
  {
    id: "user-b",
    kind: "user",
    credential: "Authorization: Bearer token-user-b-1002",
    permissions: ["accounts:read:own(1002)", "search:read"],
  },
  {
    id: "admin",
    kind: "admin",
    credential: "JWT assinado com role=admin (ou forjado com alg:none quando o controle está desligado)",
    permissions: ["admin:debug"],
  },
  {
    id: "anon",
    kind: "anonymous",
    credential: "(sem header Authorization)",
    permissions: [],
  },
]

const BOLA_HYPOTHESES: LabHypothesisSeed[] = [
  {
    id: "H1",
    title: "BOLA/IDOR: o token do User A lê a conta do User B em /api/v1/accounts/1002",
    expectedBehavior: "GET /api/v1/accounts/1002 com o token do User A retorna 403 Forbidden.",
    suspectedBehavior:
      "GET /api/v1/accounts/1002 com o token do User A retorna 200 com e-mail e saldo do User B (bob@corp.lab / 94500.00).",
    fragileAssumption:
      "O handler deriva a identidade do chamador a partir do token e a compara com o :accountId pedido.",
    technicalRationale:
      "Com `enforceAccountOwnership: false` o handler ignora a comparação caller vs. recurso, aceitando qualquer identificador — BOLA canônico (OWASP API Security Top 10 — API1:2023).",
    evidenceNeeded:
      "Par de requisições baseline (1001 com token A → 200 com dados de Alice) e PoC (1002 com token A → 200 com dados de Bob), ambas com corpo completo e SHA-256 arquivado.",
    alternativeExplanations: [
      "O endpoint é público por design (sem dado sensível real) — refutado se `owner`/`balanceUsd` forem retornados.",
      "O retorno 200 é uma resposta genérica sem dados do outro usuário — verificar o corpo antes de confirmar.",
    ],
    status: "proposed",
    relatedControlFlag: "enforceAccountOwnership",
    severityIfConfirmed: "Alta — exposição de dados de outro titular (confidencialidade).",
  },
  {
    id: "H2",
    title: "Bypass de assinatura JWT (alg:none) aceito em /api/v1/admin/debug",
    expectedBehavior:
      "Token com header {\"alg\":\"none\"} e payload {\"role\":\"admin\"} é rejeitado com 401.",
    suspectedBehavior:
      "O mesmo token é aceito com 200 e devolve `flag: LAB{JWT_ALG_NONE_ACCEPTED}`.",
    fragileAssumption:
      "A biblioteca fixa o algoritmo esperado no servidor em vez de confiar no header do token.",
    technicalRationale:
      "Com `rejectAlgNoneJwt: false` o handler apenas decodifica header/payload e confia na claim `role`, sem verificar assinatura (CWE-347).",
    evidenceNeeded:
      "Baseline (token inválido/ausente → 401) e PoC (alg:none → 200 com a flag), com o token exato registrado.",
    alternativeExplanations: [
      "O endpoint não é administrativo de fato (sem privilégio real) — checar o que `adminAccess: true` libera.",
      "A aplicação valida assinatura em outra camada (gateway) que o lab não simula.",
    ],
    status: "proposed",
    relatedControlFlag: "rejectAlgNoneJwt",
    severityIfConfirmed: "Crítica — escalada de privilégio a administrador sem segredo.",
  },
  {
    id: "H3",
    title: "Vazamento de erro SQL em /api/v1/search reflete a consulta e o nome das colunas",
    expectedBehavior: "?q=' retorna erro genérico (ex.: 400) sem detalhes do banco.",
    suspectedBehavior:
      "?q=' retorna 500 com `SQLITE_ERROR: near \"'\": syntax error in SELECT id, amount FROM ledger WHERE memo LIKE '%'%'`.",
    fragileAssumption: "A consulta é montada por concatenação de string e o erro bruto é propagado ao cliente.",
    technicalRationale:
      "Com `sanitizeSqlQuery: false` o handler concatena `q` direto na consulta e devolve o erro do driver, revelando SGBD, tabela e colunas (CWE-209).",
    evidenceNeeded:
      "Baseline (?q=test → 200 com resultados) e PoC (?q=' → 500 com a mensagem SQL) arquivados como evidência.",
    alternativeExplanations: [
      "É apenas mensagem de erro de validação sem conteúdo do banco — checar presença de `SQLITE_ERROR` e nomes de coluna.",
      "Injeção SQL explorável além do erro (ex.: UNION) precisa de experimento separado (H3-b).",
    ],
    status: "proposed",
    relatedControlFlag: "sanitizeSqlQuery",
    severityIfConfirmed: "Média/Alta — informação sensível + forte indicador de SQLi.",
  },
  {
    id: "H4",
    title: "Respostas sem headers de segurança (CSP, HSTS, X-Frame-Options, nosniff)",
    expectedBehavior: "Toda resposta inclui CSP, HSTS, X-Content-Type-Options e X-Frame-Options.",
    suspectedBehavior: "Nenhum desses headers é enviado (controle `enableSecurityHeaders: false`).",
    fragileAssumption: "Os headers são aplicados por middleware global, não rota a rota.",
    technicalRationale:
      "Sem os headers, respostas autenticadas podem ser enquadradas (clickjacking), com sniffing de MIME e sem proteção de transporte declarada.",
    evidenceNeeded: "Cabeçalhos completos de uma resposta autenticada (baseline antes / depois de ligar o controle).",
    alternativeExplanations: [
      "Proxy reverso adicionaria os headers na borda (não existe neste lab).",
      "Endpoints puramente JSON não se beneficiam de todos os headers — avaliar por tipo de conteúdo.",
    ],
    status: "proposed",
    relatedControlFlag: "enableSecurityHeaders",
    severityIfConfirmed: "Baixa/Média — defesa em profundidade; impacto depende do contexto de entrega.",
  },
]

function bolaExperiments(baseUrl: string): LabExperimentSeed[] {
  const u = baseUrl.replace(/\/+$/, "")
  return [
    {
      id: "E1",
      hypothesisId: "H1",
      question: "O endpoint /api/v1/accounts/:id aplica checagem de titularidade entre contas distintas?",
      toolUsed: "curl (Windows PowerShell ou WSL2) e/ou burp_suite_send_http1_request",
      initialConditions:
        `Servidor do lab ativo em ${u}; controles em estado inicial (enforceAccountOwnership: false); contas A=1001 e B=1002 existentes.`,
      modifiedVariable:
        "SOMENTE o :accountId pedido (1001 → 1002), mantendo o token do User A constante.",
      expectedOutcome: "1001 → 200 com dados de Alice; 1002 → 403 (se o controle estivesse ligado).",
      observedOutcome: "",
      verdict: "inconclusive",
      stopCriterion:
        "Par após obter o PAR baseline+PoC com corpos completos. Se 1002 retornar 403, registrar resultado negativo e encerrar H1.",
      commands: [
        `# BASELINE — User A lendo a PRÓPRIA conta (esperado: 200, alice@corp.lab)`,
        `curl -s -i -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/accounts/1001`,
        ``,
        `# PoC — User A lendo a conta do User B (esperado se vulnerável: 200, bob@corp.lab, bolaFlag)`,
        `curl -s -i -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/accounts/1002`,
        ``,
        `# CONTROLE — confirme que a diferença é o token, não o ID (User B lendo a própria conta)`,
        `curl -s -i -H "Authorization: Bearer token-user-b-1002" ${u}/api/v1/accounts/1002`,
      ],
    },
    {
      id: "E2",
      hypothesisId: "H1",
      question: "A falha persiste sem nenhum token (acesso anônimo a dados de contas)?",
      toolUsed: "curl",
      initialConditions: "Mesmas de E1; lab com enforceAccountOwnership: false.",
      modifiedVariable: "Remoção do header Authorization (variável única).",
      expectedOutcome: "401 quando o controle está ligado; 200 com dados quando desligado e sem token.",
      observedOutcome: "",
      verdict: "inconclusive",
      stopCriterion:
        "Um único par (sem token vs. com token) basta. Não repita variações antes de registrar o resultado.",
      commands: [
        `# BASELINE — sem credencial`,
        `curl -s -i ${u}/api/v1/accounts/1001`,
        ``,
        `# PoC — sem credencial em conta alheia`,
        `curl -s -i ${u}/api/v1/accounts/1002`,
      ],
    },
    {
      id: "E3",
      hypothesisId: "H2",
      question: "O endpoint administrativo aceita JWT com alg:none e claim role=admin?",
      toolUsed: "curl + decodificação base64url (Burp Decoder ou CyberChef)",
      initialConditions: `Servidor ativo em ${u}; rejectAlgNoneJwt: false.`,
      modifiedVariable: "SOMENTE o header `alg` do JWT (de um token assinado para `none`).",
      expectedOutcome: "401 para qualquer token sem assinatura válida.",
      observedOutcome: "",
      verdict: "inconclusive",
      stopCriterion:
        "Obter 200 com `flag: LAB{JWT_ALG_NONE_ACCEPTED}` confirma H2. Obter 401 em todas as variantes encerra como resultado negativo.",
      commands: [
        `# BASELINE — sem token (esperado: 401)`,
        `curl -s -i ${u}/api/v1/admin/debug`,
        ``,
        `# BASELINE — token opaco não-JWT (esperado: 401)`,
        `curl -s -i -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/admin/debug`,
        ``,
        `# PoC — JWT forjado: header {"alg":"none","typ":"JWT"} . payload {"sub":"user-1001","role":"admin"} . (assinatura vazia)`,
        `curl -s -i -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyLTEwMDEiLCJyb2xlIjoiYWRtaW4ifQ." ${u}/api/v1/admin/debug`,
        ``,
        `# DICA: o token de exemplo também é devolvido em:`,
        `curl -s ${u}/health`,
      ],
    },
    {
      id: "E4",
      hypothesisId: "H3",
      question: "A busca propaga erro SQL bruto com estrutura da consulta?",
      toolUsed: "curl",
      initialConditions: `Servidor ativo em ${u}; sanitizeSqlQuery: false.`,
      modifiedVariable: "SOMENTE o valor de `q` (de `test` para `'`).",
      expectedOutcome: "Erro genérico, sem mensagem do SGBD nem nomes de coluna.",
      observedOutcome: "",
      verdict: "inconclusive",
      stopCriterion:
        "Um par (q=test → 200 com resultados; q=' → 500 com SQLITE_ERROR) resolve a hipótese.",
      commands: [
        `# BASELINE — consulta benigna (esperado: 200 com resultados)`,
        `curl -s -i "${u}/api/v1/search?q=test"`,
        ``,
        `# PoC — aspa simples (esperado se vulnerável: 500 com SQLITE_ERROR e nome da tabela/colunas)`,
        `curl -s -i "${u}/api/v1/search?q=%27"`,
      ],
    },
    {
      id: "E5",
      hypothesisId: "H4",
      question: "As respostas incluem CSP, HSTS, X-Frame-Options e X-Content-Type-Options?",
      toolUsed: "curl -i",
      initialConditions: `Servidor ativo em ${u}; enableSecurityHeaders: false.`,
      modifiedVariable: "Nenhuma — inspeção de estado (baseline) antes de ligar o controle.",
      expectedOutcome: "Presença dos 4 headers de segurança.",
      observedOutcome: "",
      verdict: "inconclusive",
      stopCriterion: "Uma resposta autenticada com cabeçalhos completos basta.",
      commands: [
        `# BASELINE — headers atuais da resposta`,
        `curl -s -D - -o NUL -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/accounts/1001`,
        ``,
        `# No WSL2/Linux/macOS use -o /dev/null em vez de -o NUL`,
        `curl -s -D - -o /dev/null -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/accounts/1001`,
      ],
    },
    {
      id: "E6",
      hypothesisId: "H1",
      question: "Ligar os controles em server-config.json remove cada comportamento inseguro? (Fase G/H)",
      toolUsed: "editor de texto + curl (o servidor relê server-config.json a CADA requisição)",
      initialConditions:
        `Servidor ativo em ${u}. Todos os 4 controles em FALSE (estado vulnerável já comprovado por E1–E5).`,
      modifiedVariable:
        "SOMENTE os 4 booleanos de server-config.json (todos para true de uma vez), mantendo os mesmos comandos.",
      expectedOutcome:
        "H1 -> 403 | H2 -> 401 | H3 -> 200 sem SQLITE_ERROR | H4 -> 4 headers presentes.",
      observedOutcome: "",
      verdict: "inconclusive",
      stopCriterion:
        "Cada linha da matriz abaixo deve mudar de estado. Se alguma permanecer vulnerável, o controle não cobre aquele caminho (registrar como lacuna de remediação).",
      commands: [
        `# 1) Aplique a remediação (PowerShell)`,
        `Set-Content -Encoding utf8 .\server-config.json '{ "enforceAccountOwnership": true, "rejectAlgNoneJwt": true, "sanitizeSqlQuery": true, "enableSecurityHeaders": true }'`,
        ``,
        `# 1) Alternativa WSL2/Linux`,
        `printf '%s\n' '{ "enforceAccountOwnership": true, "rejectAlgNoneJwt": true, "sanitizeSqlQuery": true, "enableSecurityHeaders": true }' > server-config.json`,
        ``,
        `# 2) Repita EXATAMENTE os mesmos comandos de E1–E5 e compare:`,
        `curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/accounts/1002   # esperado 403`,
        `curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyLTEwMDEiLCJyb2xlIjoiYWRtaW4ifQ." ${u}/api/v1/admin/debug   # esperado 401`,
        `curl -s -o /dev/null -w "%{http_code}\n" "${u}/api/v1/search?q=%27"   # esperado 200 (sem SQLITE_ERROR)`,
        `curl -s -D - -o /dev/null -H "Authorization: Bearer token-user-a-1001" ${u}/api/v1/accounts/1001 | Select-String -Pattern "content-security-policy","strict-transport","x-frame-options","x-content-type"`,
        ``,
        `# 3) Volte ao estado vulnerável para continuar treinando (PowerShell)`,
        `Set-Content -Encoding utf8 .\server-config.json '{ "enforceAccountOwnership": false, "rejectAlgNoneJwt": false, "sanitizeSqlQuery": false, "enableSecurityHeaders": false }'`,
      ],
    },
  ]
}

const LAB_KITS: Record<string, (baseUrl: string) => LabInvestigationKit> = {
  "lab-owasp-api-bola": (baseUrl) => ({
    labId: "lab-owasp-api-bola",
    title: "OWASP API Security Lab (BOLA/IDOR, JWT alg:none & Error Leakage)",
    baseUrl,
    systemModel: {
      labId: "lab-owasp-api-bola",
      title: "CyberLab Training Banking API",
      baseUrl,
      components: [
        "Servidor HTTP Node (loopback 127.0.0.1) servindo a Banking API de treino",
        "Handler de contas (/api/v1/accounts/:id) com checagem de titularidade opcional",
        "Handler administrativo (/api/v1/admin/debug) protegido por JWT",
        "Handler de busca (/api/v1/search) com consulta concatenada",
        "Arquivo de controles server-config.json (editável ao vivo, relido a cada requisição)",
        "openapi.json (especificação 3.0.3 documentando os 4 endpoints)",
      ],
      technologies: ["Node.js http (sem framework)", "OpenAPI 3.0.3", "JWT (HS256/none)", "SQLite-like error strings (simulado)"],
      dataFlows: [
        "Cliente -> GET /api/v1/accounts/:id -> handler lê server-config.json -> compara (ou não) caller com :accountId -> JSON com owner/balanceUsd",
        "Cliente -> GET /api/v1/admin/debug -> handler decodifica header/payload do JWT -> verifica (ou não) assinatura -> JSON admin",
        "Cliente -> GET /api/v1/search?q= -> handler concatena q na consulta -> resultado OU erro SQL bruto",
      ],
      trustBoundaries: [
        "Loopback (127.0.0.1): o lab NÃO deve ser exposto em interface de rede — mantém o laboratório isolado de terceiros",
        "Identidade do chamador: derivada OPCIONALMENTE do header Authorization (desligada por padrão)",
        "Camada de autorização: caller (token) vs. recurso (:accountId) — fronteira onde BOLA ocorre",
        "Camada administrativa: assinatura JWT vs. claim role confiada — fronteira onde alg:none ocorre",
      ],
      identitiesAndPermissions: BOLA_IDENTITIES.map((i) => `${i.id} [${i.kind}]: ${i.permissions.join(", ") || "(nenhuma)"}`),
      endpoints: BOLA_ENDPOINTS,
      identities: BOLA_IDENTITIES,
      controlsFile: "server-config.json",
      controls: {
        enforceAccountOwnership: false,
        rejectAlgNoneJwt: false,
        sanitizeSqlQuery: false,
        enableSecurityHeaders: false,
      },
    },
    hypotheses: BOLA_HYPOTHESES,
    experiments: bolaExperiments(baseUrl),
  }),
}

export function getSupportedKitLabIds(): string[] {
  return Object.keys(LAB_KITS)
}

export function buildLabInvestigationKit(labId: string, port: number | null): LabInvestigationKit | null {
  const builder = LAB_KITS[labId]
  if (!builder) return null
  return builder(`http://127.0.0.1:${port ?? 19081}`)
}

// ---------------------------------------------------------------------------
// Renderizadores Markdown
// ---------------------------------------------------------------------------

function renderSystemModelMd(kit: LabInvestigationKit): string {
  const m = kit.systemModel
  return [
    "---",
    `id: "lab/${kit.labId}/system-model"`,
    `title: "Modelo do Sistema — ${kit.title}"`,
    "tier: session_context",
    "category: investigation",
    'version: "live"',
    `last_reviewed: "${new Date().toISOString().slice(0, 10)}"`,
    "status: active_session",
    "---",
    "",
    `# Modelo do Sistema (Fase B) — ${kit.title}`,
    "",
    "#lab #modelagem #fase-b #session-context",
    "",
    `> **Camada epistemológica**: \`tier: session_context\` — contexto desta investigação, isolado da biblioteca curada \`CyberLab-Knowledge/\`.`,
    "",
    `- **Lab ID**: \`${kit.labId}\``,
    `- **URL base**: ${kit.baseUrl}`,
    `- **Arquivo de controles**: \`${m.controlsFile ?? "—"}\``,
    "",
    "## 1. Componentes",
    ...m.components.map((c) => `- ${c}`),
    "",
    "## 2. Tecnologias",
    ...m.technologies.map((t) => `- ${t}`),
    "",
    "## 3. Fluxos de Dados",
    ...m.dataFlows.map((f) => `- ${f}`),
    "",
    "## 4. Fronteiras de Confiança",
    ...m.trustBoundaries.map((t) => `- ${t}`),
    "",
    "## 5. Identidades & Permissões",
    ...m.identities.map(
      (i) => `- **${i.id}** (\`${i.kind}\`): ${i.permissions.join(", ") || "(nenhuma)"} — credencial: \`${i.credential}\``,
    ),
    "",
    "## 6. Endpoints & Invariantes de Autorização",
    "| ID | Método | Caminho | Invariante esperado | Controle reparador | Dados sensíveis |",
    "|---|---|---|---|---|---|",
    ...m.endpoints.map(
      (e) =>
        `| \`${e.id}\` | ${e.method} | \`${e.path}\` | ${e.invariant} | ${e.controlFlag ? `\`${e.controlFlag}\`` : "—"} | ${e.sensitiveData.join("; ") || "—"} |`,
    ),
    "",
    "## 7. Controles Atuais",
    "```json",
    JSON.stringify(m.controls, null, 2),
    "```",
    "",
    `> Edite \`${m.controlsFile ?? "server-config.json"}\` e repita o experimento para comprovar a remediação — a evidência de correção é o MESMO comando retornando comportamento seguro.`,
    "",
  ].join("\n")
}

function renderHypothesesMd(kit: LabInvestigationKit): string {
  return [
    "---",
    `id: "lab/${kit.labId}/hypotheses"`,
    `title: "Hipóteses (Fase D) — ${kit.title}"`,
    "tier: session_context",
    "category: investigation",
    'version: "live"',
    `last_reviewed: "${new Date().toISOString().slice(0, 10)}"`,
    "status: active_session",
    "---",
    "",
    `# Hipóteses Investigativas (Fase D) — ${kit.title}`,
    "",
    "#hipoteses #fase-d #session-context",
    "",
    "Cada hipótese abaixo já possui os **6 elementos obrigatórios** do [[hypothesis-driven-testing]]:",
    "comportamento esperado, comportamento suspeito, pressuposto frágil, racional técnico, evidência necessária e explicações alternativas.",
    "",
    ...kit.hypotheses.flatMap((h) => [
      `## ${h.id} — ${h.title}`,
      "",
      `- **Status**: \`${h.status}\``,
      `- **Comportamento esperado (se seguro)**: ${h.expectedBehavior}`,
      `- **Comportamento suspeito (a testar)**: ${h.suspectedBehavior}`,
      `- **Pressuposto frágil**: ${h.fragileAssumption}`,
      `- **Racional técnico**: ${h.technicalRationale}`,
      `- **Evidência necessária (critério de parada)**: ${h.evidenceNeeded}`,
      `- **Severidade se confirmada**: ${h.severityIfConfirmed}`,
      `- **Controle reparador**: ${h.relatedControlFlag ? `\`${h.relatedControlFlag}\`` : "—"}`,
      `- **Explicações alternativas**:`,
      ...h.alternativeExplanations.map((a) => `  - ${a}`),
      "",
    ]),
    "---",
    "",
    "## Como registrar na memória investigativa",
    "",
    "```bash",
    `# Copia as hipóteses para a memória da sessão (não altera a biblioteca curada)`,
    `bun run cyberlab lab seed ${kit.labId}`,
    "```",
    "",
  ].join("\n")
}

function renderExperimentsMd(kit: LabInvestigationKit): string {
  return [
    "---",
    `id: "lab/${kit.labId}/experiments"`,
    `title: "Protocolo de Experimentos (Fase F) — ${kit.title}"`,
    "tier: session_context",
    "category: investigation",
    'version: "live"',
    `last_reviewed: "${new Date().toISOString().slice(0, 10)}"`,
    "status: active_session",
    "---",
    "",
    `# Protocolo de Experimentos (Fase F) — ${kit.title}`,
    "",
    "#experimentos #fase-f #session-context",
    "",
    `**URL base**: ${kit.baseUrl}`,
    "",
    "> **Regra do método científico**: modifique **SOMENTE UMA variável** por experimento e sempre capture o par **baseline vs. PoC**.",
    "> Todo resultado (positivo ou negativo) deve ser arquivado como evidência SHA-256 e registrado em `investigation_memory_update`.",
    "",
    "### ⚠️ Sintaxe por ambiente",
    "",
    "| Ambiente | Comando | Descartar corpo |",
    "|---|---|---|",
    "| **Windows PowerShell** | `curl.exe` | `-o NUL` |",
    "| **WSL2 Kali / Linux / macOS** | `curl` | `-o /dev/null` |",
    "",
    "> No Windows PowerShell, `curl` (sem `.exe`) é um **alias de `Invoke-WebRequest`** com sintaxe",
    "> completamente diferente — use sempre `curl.exe`. Para headers, `-D -` funciona nos dois.",
    "> Alternativa em PowerShell puro: `(Invoke-WebRequest -Uri <url> -Headers @{Authorization='Bearer ...'}).Content`.",
    "",
    "",
    ...kit.experiments.flatMap((e) => [
      `## ${e.id} — ${e.question}`,
      "",
      `- **Hipótese**: \`${e.hypothesisId}\``,
      `- **Ferramenta**: ${e.toolUsed}`,
      `- **Condições iniciais**: ${e.initialConditions}`,
      `- **Variável modificada**: ${e.modifiedVariable}`,
      `- **Resultado esperado**: ${e.expectedOutcome}`,
      `- **Critério de parada**: ${e.stopCriterion}`,
      `- **Veredito**: \`${e.verdict}\` (preencher após execução)`,
      "",
      "```bash",
      ...e.commands,
      "```",
      "",
    ]),
    "---",
    "",
    "## Matriz de Remediação (Fase G — Avaliação)",
    "",
    "| Hipótese | Comando PoC | Antes (controle OFF) | Depois (controle ON) | Controle |",
    "|---|---|---|---|---|",
    "| H1 | `GET /api/v1/accounts/1002` c/ token A | 200 + `bob@corp.lab` + `bolaFlag` | 403 Forbidden | `enforceAccountOwnership` |",
    "| H2 | `GET /api/v1/admin/debug` c/ JWT alg:none | 200 + `flag` | 401 | `rejectAlgNoneJwt` |",
    "| H3 | `GET /api/v1/search?q='` | 500 + `SQLITE_ERROR` | 200 sem erro SQL | `sanitizeSqlQuery` |",
    "| H4 | `GET /api/v1/accounts/1001` (headers) | 0 headers de segurança | CSP + HSTS + nosniff + XFO | `enableSecurityHeaders` |",
    "",
    "---",
    "",
    "## Após executar",
    "",
    "1. Arquive a saída como evidência (`.cyberlab/inbox/` ou `cyberlab_evidence_list`).",
    "2. Registre o veredito em `investigation_memory_update` (suporta, enfraquece, negativo ou inconclusivo).",
    "3. Classifique com a taxonomia de 5 níveis de [[evidence-validation]].",
    "4. Só então proponha o finding (`cyberlab_finding_propose`).",
    "",
  ].join("\n")
}

// ---------------------------------------------------------------------------
// Escrita em disco
// ---------------------------------------------------------------------------

export interface LabInvestigationKitFiles {
  systemModelMd: string
  systemModelJson: string
  hypothesesMd: string
  hypothesesJson: string
  experimentsMd: string
  experimentsJson: string
  memorySeedJson: string
}

/**
 * Gera todos os artefatos das Fases B/D/F no workspace do lab.
 * Retorna os caminhos absolutos gravados.
 */
export function writeLabInvestigationKit(
  labId: string,
  workspaceRoot: string,
  port: number | null,
): LabInvestigationKitFiles | null {
  const kit = buildLabInvestigationKit(labId, port)
  if (!kit) return null

  mkdirSync(workspaceRoot, { recursive: true })
  const files: LabInvestigationKitFiles = {
    systemModelMd: path.join(workspaceRoot, "LAB_SYSTEM_MODEL.md"),
    systemModelJson: path.join(workspaceRoot, "lab-system-model.json"),
    hypothesesMd: path.join(workspaceRoot, "HYPOTHESES.md"),
    hypothesesJson: path.join(workspaceRoot, "lab-hypotheses.json"),
    experimentsMd: path.join(workspaceRoot, "EXPERIMENTS.md"),
    experimentsJson: path.join(workspaceRoot, "lab-experiments.json"),
    memorySeedJson: path.join(workspaceRoot, "investigation-memory-seed.json"),
  }

  writeFileSync(files.systemModelMd, renderSystemModelMd(kit), "utf8")
  writeFileSync(files.systemModelJson, `${JSON.stringify(kit.systemModel, null, 2)}\n`, "utf8")
  writeFileSync(files.hypothesesMd, renderHypothesesMd(kit), "utf8")
  writeFileSync(files.hypothesesJson, `${JSON.stringify(kit.hypotheses, null, 2)}\n`, "utf8")
  writeFileSync(files.experimentsMd, renderExperimentsMd(kit), "utf8")
  writeFileSync(files.experimentsJson, `${JSON.stringify(kit.experiments, null, 2)}\n`, "utf8")
  writeFileSync(files.memorySeedJson, `${JSON.stringify(buildMemorySeed(kit), null, 2)}\n`, "utf8")

  return files
}

/** Monta o patch pronto para `CyberLabKnowledgeEngine.updateInvestigationMemory()`. */
export function buildMemorySeed(kit: LabInvestigationKit): {
  investigationId: string
  mission: string
  authorizedScope: string
  systemModel: {
    components: string[]
    technologies: string[]
    dataFlows: string[]
    trustBoundaries: string[]
    identitiesAndPermissions: string[]
  }
  hypotheses: InvestigationHypothesis[]
  experiments: InvestigationExperimentRecord[]
  negativeResults: string[]
  decisions: string[]
  externalReferences: ExternalReferenceRecord[]
  openQuestions: string[]
  nextSteps: string[]
} {
  const now = new Date().toISOString()
  return {
    investigationId: `lab-${kit.labId.replace(/^lab-/, "")}`,
    mission: `Validar, com evidência reproduzível, as vulnerabilidades intencionais do laboratório "${kit.title}" (${kit.baseUrl}) e comprovar a remediação de cada controle.`,
    authorizedScope: `EXCLUSIVAMENTE o servidor de laboratório em loopback ${kit.baseUrl} (127.0.0.1). Nenhum alvo externo está autorizado nesta investigação.`,
    systemModel: {
      components: kit.systemModel.components,
      technologies: kit.systemModel.technologies,
      dataFlows: kit.systemModel.dataFlows,
      trustBoundaries: kit.systemModel.trustBoundaries,
      identitiesAndPermissions: kit.systemModel.identitiesAndPermissions,
    },
    hypotheses: kit.hypotheses.map((h) => ({
      id: h.id,
      title: h.title,
      expectedBehavior: h.expectedBehavior,
      suspectedBehavior: h.suspectedBehavior,
      fragileAssumption: h.fragileAssumption,
      technicalRationale: h.technicalRationale,
      evidenceNeeded: h.evidenceNeeded,
      alternativeExplanations: h.alternativeExplanations,
      status: "proposed" as const,
      updatedAt: now,
    })),
    experiments: kit.experiments.map((e) => ({
      id: e.id,
      hypothesisId: e.hypothesisId,
      question: e.question,
      toolUsed: e.toolUsed,
      initialConditions: e.initialConditions,
      modifiedVariable: e.modifiedVariable,
      expectedOutcome: e.expectedOutcome,
      observedOutcome: e.observedOutcome,
      verdict: "inconclusive" as const,
      recordedAt: now,
    })),
    negativeResults: [],
    decisions: [],
    externalReferences: [
      {
        title: "OWASP API Security Top 10 — API1:2023 BOLA",
        sourceUrlOrRef: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        accessedAt: now,
        applicabilityNote: "Fundamenta H1 (BOLA entre contas 1001 e 1002).",
      },
      {
        title: "CWE-347: Improper Verification of Cryptographic Signature",
        sourceUrlOrRef: "https://cwe.mitre.org/data/definitions/347.html",
        accessedAt: now,
        applicabilityNote: "Fundamenta H2 (JWT alg:none aceito).",
      },
      {
        title: "CWE-209: Generation of Error Message Containing Sensitive Information",
        sourceUrlOrRef: "https://cwe.mitre.org/data/definitions/209.html",
        accessedAt: now,
        applicabilityNote: "Fundamenta H3 (vazamento de erro SQL).",
      },
      {
        title: "OWASP Secure Headers Project",
        sourceUrlOrRef: "https://owasp.org/www-project-secure-headers/",
        accessedAt: now,
        applicabilityNote: "Fundamenta H4 (CSP/HSTS/X-Frame-Options/nosniff).",
      },
    ],
    openQuestions: [
      "H3 é apenas vazamento de erro ou há injeção SQL explorável além da mensagem? (requer experimento H3-b com UNION/time-based)",
      "Existe rate limiting em /api/v1/search e /api/v1/admin/debug? (não modelado — teste separado)",
    ],
    nextSteps: [
      "Executar E1 e E2 (H1 — BOLA) e arquivar o par baseline/PoC com SHA-256.",
      "Executar E3 (H2 — JWT alg:none).",
      "Executar E4 (H3 — erro SQL) e E5 (H4 — headers).",
      "Ligar cada controle em server-config.json e repetir o comando para comprovar a remediação.",
      "Classificar os achados com a taxonomia de 5 níveis de [[evidence-validation]] e redigir o relatório ([[reproducible-writeup-standard]]).",
    ],
  }
}

/** true se o kit já foi gerado no workspace do lab. */
export function labInvestigationKitExists(workspaceRoot: string): boolean {
  return existsSync(path.join(workspaceRoot, "lab-system-model.json"))
}
