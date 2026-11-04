import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs"
import path from "node:path"
import { isPathInsideRoot } from "../policy/scope.js"

export interface KnowledgeFrontmatter {
  id: string
  title: string
  tier: "curated" | "draft" | "proposal" | "session_context" | "note"
  category: string
  version: string
  last_reviewed: string
  status: string
  sources: string[]
  limitations: string[]
  related: string[]
}

export interface KnowledgeDocumentMetadata extends KnowledgeFrontmatter {
  docPath: string
  tags: string[]
  wikiLinks: string[]
  sections: string[]
  sizeBytes: number
  updatedAt: string
}

export interface KnowledgeSearchHit {
  docPath: string
  title: string
  tier: KnowledgeFrontmatter["tier"]
  category: string
  version: string
  last_reviewed: string
  status: string
  score: number
  matchedSections: string[]
  sources: string[]
  limitations: string[]
  excerpt: string
}

export interface RelatedDocumentEdge {
  docPath: string
  title: string
  tier: KnowledgeFrontmatter["tier"]
  relationType: "frontmatter_related" | "wikilink_out" | "backlink_in" | "shared_tags"
  detail: string
}

export interface InvestigationHypothesis {
  id: string
  title: string
  expectedBehavior: string
  suspectedBehavior: string
  fragileAssumption: string
  technicalRationale: string
  evidenceNeeded: string
  alternativeExplanations: string[]
  status: "proposed" | "testing" | "supported" | "refuted" | "inconclusive"
  updatedAt: string
}

export interface InvestigationExperimentRecord {
  id: string
  hypothesisId?: string
  question: string
  toolUsed: string
  initialConditions: string
  modifiedVariable: string
  expectedOutcome: string
  observedOutcome: string
  verdict: "supports_hypothesis" | "weakens_hypothesis" | "negative_result" | "inconclusive"
  recordedAt: string
}

export interface ExternalReferenceRecord {
  title: string
  sourceUrlOrRef: string
  versionOrCommit?: string
  accessedAt: string
  applicabilityNote: string
}

export interface InvestigationSessionMemory {
  investigationId: string
  updatedAt: string
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
}

export const CURATED_KNOWLEDGE_FILES: Array<{ relativePath: string; content: string }> = [
  {
    relativePath: "CyberLab-Knowledge/00-Index.md",
    content: `---
id: knowledge/index
title: Biblioteca Curada CyberLab-Knowledge — Índice e Epistemologia
tier: curated
category: index
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "Arquitetura Epistemológica CyberLab OS v6.2"
  - "OWASP Web Security Testing Guide (WSTG v4.2)"
limitations:
  - "Esta biblioteca contém fundamentos e metodologias curadas; nunca presuma que um padrão se aplica ao alvo atual sem experimento controlado dentro do escopo."
related:
  - "methodologies/hypothesis-driven-testing"
  - "methodologies/evidence-validation"
  - "methodologies/root-cause-analysis"
  - "tools/mcp-tool-catalog"
---

# Biblioteca Curada CyberLab-Knowledge

#cyberlab #knowledge #curated #epistemologia

Esta biblioteca organiza o conhecimento técnico do **Investigative Security Orchestrator** em **3 camadas epistemológicas estritamente separadas**:

1. **Conhecimento Curado (\`CyberLab-Knowledge/\`, \`tier: curated\`)**: fundamentos de protocolos, metodologias científicas de teste, classes de vulnerabilidade, análise de patches e guias de ferramentas. Somente leitura automática para agentes; atualizações exigem rascunho em \`_drafts/\` (\`create_draft_note\`) ou proposta em \`_proposals/\` (\`propose_document_update\`) revisada pelo curador humano.
2. **Contexto da Investigação Atual (\`.cyberlab/investigations/\` + \`Investigacoes/\`, \`tier: session_context\`)**: missão, escopo autorizado, modelo do sistema, hipóteses ativas, experimentos e resultados negativos da sessão corrente.
3. **Conhecimento Externo**: advisories oficiais, commits, patches e documentação primária consultados durante a sessão, sempre acompanhados de fonte, versão e data.

## Mapa da Biblioteca
- **Fundamentos**: [[http]], [[authentication]], [[authorization]], [[sessions]], [[networking]]
- **Metodologias**: [[hypothesis-driven-testing]], [[evidence-validation]], [[root-cause-analysis]]
- **Vulnerabilidades**: [[idor-bola-bfla]], [[context-aware-injection]], [[http-url-json-differentials]], [[state-race-invariants]]
- **Pesquisa Primária**: [[cve-applicability-methodology]], [[patch-diff-methodology]], [[reproducible-writeup-standard]]
- **Ferramentas & Catálogo MCP**: [[mcp-tool-catalog]], [[burp]], [[nuclei]], [[semgrep]]
`,
  },
  {
    relativePath: "CyberLab-Knowledge/fundamentals/http.md",
    content: `---
id: fundamentals/http
title: Semântica HTTP/1.1, HTTP/2, Proxies Reversos e Fronteiras de Parsing
tier: curated
category: fundamentals
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "IETF RFC 9110 (HTTP Semantics) & RFC 9112 (HTTP/1.1)"
  - "IETF RFC 9113 (HTTP/2)"
  - "PortSwigger Web Security Academy — HTTP Request Smuggling & Host Header"
limitations:
  - "A interpretação exata de headers duplicados, path normalization e framing depende da combinação CDN + Reverse Proxy + servidor de aplicação."
related:
  - "vulnerabilities/parser-differential/http-url-json-differentials"
  - "fundamentals/sessions"
  - "tools/burp"
  - "methodologies/hypothesis-driven-testing"
---

# Semântica HTTP/1.1, HTTP/2, Proxies Reversos e Fronteiras de Parsing

#http #http2 #proxies #parsing #fundamentals

## 1. Modelo de Componentes em Cadeia
Quase nenhuma aplicação moderna processa HTTP diretamente na origem. O caminho real costuma envolver:
\`Cliente -> CDN/WAF -> Load Balancer / Reverse Proxy -> API Gateway -> Framework Web -> Serviço Interno\`.

## 2. Invariantes e Pressupostos Frágeis
- **Delimitação de mensagem (\`Content-Length\` vs \`Transfer-Encoding\`)**: divergências entre proxy frontal e origem produzem dessincronização de fila (*request smuggling*) — veja [[http-url-json-differentials]].
- **Normalização de caminho (\`/api/v1/../admin\`, \`;param\`, \`%2f\`)**: proxies que aplicam ACL sobre o URI bruto antes da decodificação do framework criam bypasses de roteamento.
- **Autoridade e \`Host\` / \`:authority\` / \`X-Forwarded-Host\`**: geração de links de reset de senha, redirecionamentos OAuth ou roteamento multi-tenant baseado em cabeçalhos não confiáveis.
- **Downgrade HTTP/2 → HTTP/1.1**: pseudo-headers \`:path\` ou \`:authority\` convertidos em cabeçalhos HTTP/1.1 pelo edge proxy.

## 3. Perguntas Investigativas Chave
1. O proxy frontal e o framework backend concordam sobre qual endpoint e qual tenant estão sendo acessados?
2. Quais cabeçalhos de encaminhamento (\`X-Forwarded-For\`, \`X-Real-IP\`, \`X-Original-URL\`) são sobrescritos vs. concatenados na borda?

## 4. Validação Controlada
Utilize \`burp_suite_send_http1_request\` ou \`burp_suite_call_tool\` (\`send_http2_request\`) em [[burp]] alterando **uma única variável sintática por vez** e comparando status, headers de cache e tempo de resposta.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/fundamentals/authentication.md",
    content: `---
id: fundamentals/authentication
title: Mecanismos de Autenticação, OIDC/OAuth 2.0, MFA e Recuperação de Conta
tier: curated
category: fundamentals
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "IETF RFC 6749 (OAuth 2.0), RFC 7636 (PKCE) & RFC 8725 (JWT Best Current Practices)"
  - "OpenID Connect Core 1.0 Specification"
  - "OWASP Authentication Cheat Sheet"
limitations:
  - "Fluxos SSO corporativos (SAML/OIDC) frequentemente delegam políticas a IdPs externos fora do escopo autorizado; valide o escopo antes de enviar tráfego ao IdP."
related:
  - "fundamentals/sessions"
  - "fundamentals/authorization"
  - "vulnerabilities/business-logic/state-race-invariants"
  - "tools/burp"
---

# Mecanismos de Autenticação, OIDC/OAuth 2.0, MFA e Recuperação de Conta

#authentication #oauth #oidc #jwt #mfa #fundamentals

## 1. Superfícies Críticas de Identidade
Autenticação não é um único endpoint de login; é a união de **todos os fluxos capazes de emitir uma sessão ou credencial**:
- Login primário (senha, passkey/WebAuthn, magic link, OTP)
- Federação OAuth 2.0 / OIDC / SAML
- Recuperação de senha / troca de e-mail / re-vinculação de identificador
- Emissão de API Keys / Personal Access Tokens / Refresh Tokens

## 2. Pressupostos Frágeis Recorrentes
- **Vinculação de identidade pré-autenticada (*Pre-hijacking / Account Linking*)**: conta criada via e-mail/senha sem verificação sendo mesclada automaticamente quando a vítima entra via Google/SSO.
- **Validação de \`redirect_uri\`, \`state\` e \`nonce\` em OAuth/OIDC**: ausência de vínculo criptográfico entre \`state\` e a sessão do navegador (CSRF de login/account linking) ou \`redirect_uri\` permissivo.
- **Verificação de JWT (RFC 8725)**: confusão \`alg\`/chave pública, ausência de validação de \`iss\` e \`aud\` entre microsserviços distintos do mesmo ecossistema.
- **MFA em múltiplas etapas**: estado intermediário pós-senha permitindo chamar endpoints autenticados diretamente antes de concluir o segundo fator.

## 3. Relação com Sessão e Autorização
Consulte [[sessions]] para ciclo de vida do token emitido e [[authorization]] para separação entre *quem o usuário é* (AuthN) e *o que ele pode fazer* (AuthZ).
`,
  },
  {
    relativePath: "CyberLab-Knowledge/fundamentals/authorization.md",
    content: `---
id: fundamentals/authorization
title: Modelos de Autorização (RBAC, ABAC, ReBAC, Multi-Tenancy) e Invariantes de Acesso
tier: curated
category: fundamentals
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP API Security Top 10 (2023) — API1 BOLA, API3 BOPLA, API5 BFLA"
  - "NIST SP 800-162 (Guide to Attribute Based Access Control)"
limitations:
  - "Testes reais de controle de acesso exigem duas contas próprias controladas pelo investigador (Conta A e Conta B); nunca tente acessar objetos de terceiros reais."
related:
  - "vulnerabilities/access-control/idor-bola-bfla"
  - "fundamentals/authentication"
  - "methodologies/evidence-validation"
---

# Modelos de Autorização e Invariantes de Acesso

#authorization #rbac #abac #multitenant #bola #fundamentals

## 1. As Três Dimensões da Autorização
Toda decisão de autorização responde simultaneamente a três perguntas:
1. **Sujeito (*Principal*)**: usuário, service account, role ou escopo de API Token?
2. **Ação (*Operation*)**: leitura, mutação parcial, aprovação, exclusão, exportação administrativa (BFLA)?
3. **Objeto & Campo (*Resource & Property*)**: o objeto pertence ao tenant/usuário autenticado (BOLA/IDOR) e cada propriedade lida/alterada é permitida para aquele papel (BOPLA/Mass Assignment)?

## 2. Onde as Fronteiras de Confiança Quebram
- **Autorização aplicada no Gateway mas ausente no serviço interno** (GraphQL resolvers aninhados, endpoints batch/export, jobs assíncronos).
- **Resolução de tenant por parâmetro do cliente** (\`X-Org-Id\`, \`organization_id\` no JSON) enquanto a sessão apenas valida autenticação global.
- **Assimetria entre leitura e escrita**: \`GET /resource/{id}\` verifica ownership, mas \`PATCH /resource/{id}\` ou \`POST /export\` busca apenas pelo ID primário.

Consulte [[idor-bola-bfla]] para desenho experimental com duas contas de teste controladas.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/fundamentals/sessions.md",
    content: `---
id: fundamentals/sessions
title: Gestão de Sessões, Cookies, Refresh Tokens e Revogação de Estado
tier: curated
category: fundamentals
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "IETF RFC 6265bis (Cookies: HTTP State Management Mechanism)"
  - "OWASP Session Management Cheat Sheet"
limitations:
  - "Tokens stateless (JWT de curta duração) possuem janela natural até expiração; diferencie ausência de revogação imediata esperada por arquitetura vs. falha real em refresh tokens."
related:
  - "fundamentals/authentication"
  - "fundamentals/http"
  - "methodologies/evidence-validation"
---

# Gestão de Sessões, Cookies, Refresh Tokens e Revogação de Estado

#sessions #cookies #samesite #csrf #tokens #fundamentals

## 1. Propriedades de Segurança de Sessão
- **Geração & Entropia**: imprevisibilidade criptográfica de identificadores de sessão.
- **Transporte & Escopo de Cookie**: atributos \`Secure\`, \`HttpOnly\`, \`SameSite=Lax|Strict|None\`, \`Domain\` (risco de *cookie tossing* por subdomínios irmãos) e \`Path\`.
- **Rotação em Transição de Privilégio**: regeneração do ID de sessão após login ou elevação MFA (prevenção de *Session Fixation*).
- ** Invalidação Efetiva**: revogação real de *refresh tokens* no backend após logout, troca de senha ou remoção de membro de organização.

## 2. Armadilhas Investigativas Comuns
- Reportar ausência de \`SameSite\` sem demonstrar ação sensível autenticada apenas por cookie sem token anti-CSRF ou header customizado exigindo preflight CORS. Sempre aplique [[evidence-validation]].
`,
  },
  {
    relativePath: "CyberLab-Knowledge/fundamentals/networking.md",
    content: `---
id: fundamentals/networking
title: Superfície de Rede, DNS, TLS, SSRF e Isolamento de Metadados Cloud
tier: curated
category: fundamentals
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "IETF RFC 1035 (DNS), RFC 8446 (TLS 1.3)"
  - "OWASP Server-Side Request Forgery Prevention Cheat Sheet"
limitations:
  - "Varreduras ativas de portas/rede devem respeitar rigorosamente os IPs/domínios e limites de taxa permitidos em .cyberlab/scope.json."
related:
  - "fundamentals/http"
  - "tools/nuclei"
  - "tools/mcp-tool-catalog"
---

# Superfície de Rede, DNS, TLS, SSRF e Isolamento de Metadados Cloud

#networking #dns #tls #ssrf #cloud #fundamentals

## 1. Camadas Relevantes na Investigação
- **Resolução DNS & Subdomínios**: registros \`CNAME\` órfãos (*dangling DNS*), split-horizon DNS e *DNS Rebinding* (TOCTOU entre validação de IP e conexão efetiva do cliente HTTP backend).
- **TLS & SNI**: certificados multi-SAN revelando origens internas, mTLS mal configurado no reverse proxy.
- **Clientes HTTP Server-Side (Webhooks, Importadores de URL, Renderizadores PDF/Headless)**:
  - Seguem redirecionamentos \`302\` para IPs privados (\`127.0.0.1\`, \`10.0.0.0/8\`, \`169.254.169.254\`) após checagem inicial?
  - Aceitam esquemas alternativos (\`file://\`, \`gopher://\`, \`dict://\`) ou representações alternativas de IP?
`,
  },
  {
    relativePath: "CyberLab-Knowledge/methodologies/hypothesis-driven-testing.md",
    content: `---
id: methodologies/hypothesis-driven-testing
title: Investigação de Segurança Orientada por Hipóteses
tier: curated
category: methodologies
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "Método Científico Aplicado à Engenharia de Segurança — CyberLab OS"
  - "PortSwigger Research Methodology (James Kettle)"
limitations:
  - "Hipóteses dependem da fidelidade do modelo do sistema; revise o modelo sempre que surgir evidência empírica contraditória."
related:
  - "methodologies/evidence-validation"
  - "methodologies/root-cause-analysis"
  - "tools/mcp-tool-catalog"
---

# Investigação de Segurança Orientada por Hipóteses

#methodology #hypothesis #experiments #scientific-method

## 1. Regra de Ouro
**Nunca execute uma ferramenta antes de formular explicitamente a pergunta investigativa que ela deve responder.**

## 2. Anatomia de uma Hipótese Testável
Toda hipótese registrada em \`investigation_memory_update\` deve conter 6 elementos:
1. **Comportamento esperado**: qual invariante de segurança o sistema deveria manter?
2. **Comportamento suspeito**: como o sistema pode violar essa invariante?
3. **Pressuposto frágil**: qual suposição implícita do desenvolvedor/arquitetura pode falhar?
4. **Justificativa técnica**: sinal arquitetural observável que motiva a hipótese.
5. **Evidência necessária**: qual observação confirmaria e qual refutaria a hipótese?
6. **Explicações alternativas**: WAF, cache CDN, feature intencional ou erro de sintaxe que produziriam sintoma parecido sem ser vulnerabilidade.

## 3. Desenho de Experimento Diferenciador
Bons experimentos mudam **apenas uma variável independente** entre uma requisição de controle (*baseline*) e a requisição experimental, definindo de antemão o **critério de interrupção** (*stop condition*).

## 4. Tarefa Inicial Recomendada de Calibração do Agente
Antes de investigar um alvo real, calibre o orquestrador com:
> *"Mapeie o conhecimento técnico e as ferramentas MCP disponíveis. Identifique quais capacidades estão comprovadas, quais ainda não foram validadas e quais lacunas de conhecimento limitam uma investigação orientada por hipóteses."*
`,
  },
  {
    relativePath: "CyberLab-Knowledge/methodologies/evidence-validation.md",
    content: `---
id: methodologies/evidence-validation
title: Validação Rigorosa de Evidências e Eliminação de Falsos Positivos
tier: curated
category: methodologies
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "Bugcrowd VRT & HackerOne Triage Standards"
  - "CVSS v3.1 / v4.0 Specification — FIRST.org"
limitations:
  - "A validação deve demonstrar impacto real com carga mínima benigna (PoC não destrutivo), sem exfiltrar dados sensíveis reais de terceiros."
related:
  - "methodologies/hypothesis-driven-testing"
  - "methodologies/root-cause-analysis"
  - "research/technical-writeups/reproducible-writeup-standard"
---

# Validação Rigorosa de Evidências e Eliminação de Falsos Positivos

#validation #evidence #false-positives #triage #methodology

## 1. Taxonomia Obrigatória de Classificação (Fase H)
O Orquestrador e o \`evidence-reviewer-agent\` devem classificar cada achado estritamente em uma das 5 categorias:
1. **Comportamento inesperado**: resposta atípica ainda sem violação de propriedade de segurança demonstrada.
2. **Falha funcional**: bug de produto (\`500 Internal Server Error\`, erro de UI) sem impacto explorável em confidencialidade, integridade ou disponibilidade.
3. **Configuração insegura (*Hardening*)**: cabeçalho ausente ou versão exposta sem vetor prático direto.
4. **Vulnerabilidade potencial**: indício forte (ex.: diferencial de tempo ou reflexão parcial) pendente de prova determinística.
5. **Vulnerabilidade confirmada**: violação reproduzível e inequívoca de uma propriedade de segurança com par de requisições *baseline vs. PoC* verificável.

## 2. Checklist Anti-Falso-Positivo
- O código \`200 OK\` veio da origem ou é uma página HTML genérica de SPA/WAF (*soft-200*)?
- O dado retornado é realmente privado de outro tenant ou é público por design (ex.: perfil público, ID de catálogo)?
- A saída de scanner (\`nuclei\`, \`semgrep\`) bateu apenas em versão/regex superficial sem atingir o *sink* vulnerável?
`,
  },
  {
    relativePath: "CyberLab-Knowledge/methodologies/root-cause-analysis.md",
    content: `---
id: methodologies/root-cause-analysis
title: Análise de Causa Raiz (Root Cause Analysis) em Engenharia de Segurança
tier: curated
category: methodologies
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "IEEE Secure Design Principles (Center for Secure Design)"
  - "Google Project Zero Root Cause Analyses"
limitations:
  - "Em testes black-box, a causa raiz exata no código-fonte é inferida por comportamento observável; declare explicitamente o grau de certeza."
related:
  - "research/patch-analysis/patch-diff-methodology"
  - "methodologies/hypothesis-driven-testing"
  - "tools/semgrep"
---

# Análise de Causa Raiz em Engenharia de Segurança

#rca #root-cause #architecture #variants #methodology

## 1. Sintoma vs. Mecanismo vs. Causa Raiz Sistêmica
- **Sintoma**: \`GET /api/invoices/1042\` retornou fatura de outro cliente.
- **Mecanismo técnico**: a query ORM buscou \`Invoice.findById(id)\` sem predicado \`tenant_id = session.tenantId\`.
- **Causa raiz arquitetural**: o repositório de dados exige filtragem manual de tenant em cada rota em vez de isolamento por contexto/Row-Level Security — o que imediatamente gera **hipóteses de variantes** em outros endpoints do mesmo módulo!

## 2. Análise de Variantes (*Variant Hunting*)
Toda causa raiz identificada deve alimentar novas hipóteses sobre:
1. Outros métodos HTTP ou formatos (\`JSON\`, \`GraphQL\`, \`CSV export\`) no mesmo controlador.
2. Outras entidades que compartilham o mesmo helper/middleware.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/access-control/idor-bola-bfla.md",
    content: `---
id: vulnerabilities/access-control/idor-bola-bfla
title: Quebra de Controle de Acesso — BOLA/IDOR, BFLA e BOPLA
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP API Security Top 10 (2023): API1, API3, API5"
  - "OWASP WSTG-ATHZ-04 (Testing for Insecure Direct Object References)"
limitations:
  - "UUIDv4 não é controle de acesso; porém, para confirmar BOLA em recursos com UUID, demonstre também se o UUID vaza em endpoints de listagem, logs, convites ou webhooks — ou documente a pré-condição de conhecimento do ID."
related:
  - "fundamentals/authorization"
  - "methodologies/evidence-validation"
  - "tools/burp"
---

# Quebra de Controle de Acesso — BOLA/IDOR, BFLA e BOPLA

#bola #idor #bfla #bopla #access-control #vulnerabilities

## 1. Protocolo Experimental Seguro (Duas Contas Próprias)
1. Crie **Conta A (Atacante de Teste)** e **Conta B (Vítima de Teste)** dentro do ambiente autorizado.
2. Na Conta B, crie um recurso privado de teste contendo um marcador único benigno (\`cyberlab-canary-B\`).
3. Capture a requisição legítima no Proxy de [[burp]] (\`burp_suite_get_proxy_history\`).
4. Envie para o Repeater (\`burp_suite_create_repeater_tab\`) substituindo **apenas** a credencial da Conta B pela da Conta A.
5. Compare resposta, efeitos colaterais em banco e escopo de propriedades (BOPLA/Mass Assignment como \`role\`, \`org_id\`, \`verified\`).
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/injection/context-aware-injection.md",
    content: `---
id: vulnerabilities/injection/context-aware-injection
title: Injeção Sensível ao Contexto (SQLi, Template/SSTI, Command, XSS/DOM, GraphQL/NoSQL)
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP Injection Prevention Cheat Sheet"
  - "CWE-89 (SQLi), CWE-79 (XSS), CWE-94/1336 (SSTI), CWE-78 (OS Command Injection)"
limitations:
  - "Nunca utilize payloads destrutivos (DROP, rm, escrita arbitrária). Prefira provas booleanas, aritméticas ou diferenciais determinísticos."
related:
  - "fundamentals/http"
  - "methodologies/evidence-validation"
  - "tools/semgrep"
  - "tools/burp"
---

# Injeção Sensível ao Contexto

#injection #sqli #xss #ssti #nosql #vulnerabilities

## 1. Princípio Estrutural
Injeção ocorre quando **dados controlados pelo usuário atravessam uma fronteira para um interpretador sem separação estrita entre código/estrutura e dados** (parametrização ou codificação específica do contexto de saída).

## 2. Testes Diferenciais Mínimos (Não Destrutivos)
- **SQL/NoSQL**: pares booleanos equivalentes vs. contraditórios (\`id=10\` vs expressões que preservam/invertem predicado; ordenação \`ORDER BY 1\` vs coluna inválida) antes de qualquer automação pesada.
- **XSS / DOM**: identifique primeiro o contexto exato de reflexão (corpo HTML, atributo com/sem aspas, string JS, \`href\`/\`src\`, \`innerHTML\` no cliente) antes de testar caracteres estruturais (\`" ' < > \\\`).
- **SSTI**: expressões puramente matemáticas benignas específicas da engine suspeita, diferenciando de simples interpolação client-side.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/parser-differential/http-url-json-differentials.md",
    content: `---
id: vulnerabilities/parser-differential/http-url-json-differentials
title: Diferenciais de Parser (URL, JSON Duplicado, Path Normalization e HTTP Framing)
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "RFC 8259 (JSON) — Seção 4 (Duplicate Member Names)"
  - "Orange Tsai — A New Era of SSRF (URL Parser Differentials)"
  - "Jake Miller — An Exploration of JSON Interoperability Vulnerabilities"
limitations:
  - "Testes de HTTP Request Smuggling compartilhados em produção podem afetar outros usuários; nunca execute ataques de fila compartilhada fora de laboratório isolado ou autorização explícita."
related:
  - "fundamentals/http"
  - "fundamentals/authorization"
  - "tools/burp"
---

# Diferenciais de Parser (URL, JSON, Path e Framing)

#parser-differential #json #url-parsing #smuggling #vulnerabilities

## 1. Causa Raiz
Dois componentes consecutivos validam e consomem a **mesma entrada serializada usando gramáticas ou precedências diferentes**:
- **Chaves JSON duplicadas** (\`{"role":"user","role":"admin"}\`): o validador lê a primeira chave (*first-wins*), mas o deserializador do backend aplica a última (*last-wins*), ou vice-versa; inteiros grandes vs. float (\`IEEE-754\`).
- **URL Parsers**: \`https://expected.host@attacker.test\` ou backslashes \`\\\` tratados de modo divergente entre \`urllib\`, \`WHATWG URL\` e \`curl\`.
- **Path Matrix Parameters (\`/public;x=/../admin\`)**: Nginx repassa literal enquanto Spring/Tomcat resolve segmentos \`;\` e \`..\`.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/business-logic/state-race-invariants.md",
    content: `---
id: vulnerabilities/business-logic/state-race-invariants
title: Falhas de Lógica de Negócio, Máquinas de Estado e Condições de Corrida (TOCTOU)
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP WSTG-BUSL (Business Logic Testing)"
  - "PortSwigger Research — Smashing the State Machine (Single-Packet Attack)"
limitations:
  - "Testes de concorrência devem usar contagens mínimas (ex.: 2–5 requisições paralelas em conta de teste própria) para provar falta de lock atômico sem causar degradação de serviço."
related:
  - "fundamentals/authorization"
  - "methodologies/hypothesis-driven-testing"
  - "tools/burp"
---

# Falhas de Lógica de Negócio, Máquinas de Estado e Condições de Corrida

#business-logic #race-condition #toctou #state-machine #vulnerabilities

## 1. Modelagem de Invariantes de Domínio
Scanners automáticos quase nunca detectam falhas de negócio porque cada requisição individual é sintaticamente válida. Modele:
- **Transições de estado proibidas**: pular etapa \`pending_verification -> approved\`, reutilizar cupom/convite de uso único, cancelar pedido após despacho mantendo reembolso.
- **Valores limítrofes e sinais**: quantidades negativas, arredondamento fracionário, moedas distintas na mesma transação.
- **Janela TOCTOU (*Check-Then-Act*)**: leitura de saldo/limite sem \`SELECT ... FOR UPDATE\` ou chave de idempotência atômica.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/research/cve-analysis/cve-applicability-methodology.md",
    content: `---
id: research/cve-analysis/cve-applicability-methodology
title: Metodologia de Avaliação de Aplicabilidade de CVEs e Advisories
tier: curated
category: research
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "FIRST CVSS v4.0 & CISA KEV Methodology"
  - "GitHub Security Advisories (GHSA) & NVD Primary References"
limitations:
  - "Banners de versão em pacotes Debian/Ubuntu/RHEL frequentemente mantêm o número base com backports de segurança aplicados; nunca confirme CVE apenas por banner."
related:
  - "research/patch-analysis/patch-diff-methodology"
  - "methodologies/evidence-validation"
  - "tools/nuclei"
---

# Metodologia de Avaliação de Aplicabilidade de CVEs

#cve #advisories #reachability #research

## 1. Os 4 Critérios de Aplicabilidade Real
Nunca declare que um CVE afeta o alvo apenas porque o nome ou versão parecem próximos. Verifique:
1. **Componente e Edição Exatos**: pacote upstream vs. distribuição com *backport* de segurança.
2. **Condição de Configuração**: a feature/módulo vulnerável está habilitada?
3. **Alcançabilidade (*Reachability*)**: o caminho de código vulnerável é alcançável a partir de uma fronteira acessível no escopo (pré-autenticado vs. pós-admin)?
4. **Mitigações Compensatórias**: proxy/WAF/isolamento de rede neutraliza o vetor ou existe bypass demonstrável?
`,
  },
  {
    relativePath: "CyberLab-Knowledge/research/patch-analysis/patch-diff-methodology.md",
    content: `---
id: research/patch-analysis/patch-diff-methodology
title: Análise de Patches, Commits de Segurança e Correções Incompletas
tier: curated
category: research
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "Maddie Stone — 0-day In-the-Wild & Patch Diffing Methodology"
  - " Semgrep Variant Analysis Handbook"
limitations:
  - "Um patch que bloqueia apenas o payload do PoC público (blocklist superficial) frequentemente deixa a causa raiz intacta."
related:
  - "methodologies/root-cause-analysis"
  - "research/cve-analysis/cve-applicability-methodology"
  - "tools/semgrep"
---

# Análise de Patches e Correções Incompletas

#patch-analysis #diff #variants #research

## 1. Perguntas Obrigatórias ao Ler um Commit de Segurança
1. O patch corrigiu a **propriedade estrutural** (ex.: parametrização / canonicalização pós-decodificação) ou adicionou um filtro de string/regex contornável?
2. Existem **caminhos irmãos** no mesmo repositório (outros endpoints, API v1 vs v2, handlers WebSocket/CLI) que não receberam a mesma checagem?
3. Os testes unitários adicionados no commit cobrem entradas canônicas alternativas (case, encoding duplo, arrays, tipos inesperados)?
`,
  },
  {
    relativePath: "CyberLab-Knowledge/research/technical-writeups/reproducible-writeup-standard.md",
    content: `---
id: research/technical-writeups/reproducible-writeup-standard
title: Padrão de Relatório Técnico Reproduzível e Verificável
tier: curated
category: research
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP Reporting Best Practices & Bug Bounty Triage Guidelines"
limitations:
  - "Todo token, cookie ou chave real deve ser redigido (padrão SHA-256 do CyberLab OS) antes de compartilhar artefatos."
related:
  - "methodologies/evidence-validation"
  - "methodologies/root-cause-analysis"
---

# Padrão de Relatório Técnico Reproduzível

#report #writeup #reproducibility #custody

## Estrutura Mínima Verificável (Fase I)
1. **Resumo Executivo & Classificação Honesta** (Vulnerabilidade Confirmada / Potencial / Configuração / Falha Funcional).
2. **Ativo, Escopo e Condições de Teste** (versão, pré-condições de privilégio, contas de teste usadas).
3. **Modelo do Mecanismo e Causa Raiz**.
4. **Passos Exatos de Reprodução** (*Baseline* de controle vs. *Experimento/PoC* mínimo benigno).
5. **Evidências Custodiadas** (hashes \`SHA-256\`, pares HTTP request/response com segredos redigidos).
6. **Impacto Real, Limitações Conhecidas e Recomendação Estrutural de Correção**.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/tools/burp.md",
    content: `---
id: tools/burp
title: Guia Investigativo — Burp Suite MCP (:9876 SSE) no CyberLab OS
tier: curated
category: tools
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "PortSwigger Official MCP Server (PortSwigger/mcp-server v1.3+)"
  - "CyberLab OS Arsenal MCP Hub v6.2"
limitations:
  - "Na edição Burp Suite Community, tools exclusivas do Pro (Active Scanner / Collaborator) não estão disponíveis; use Repeater, Proxy History, HTTP/1.1 & HTTP/2 sender e Interactsh (slot interactsh) para OAST."
related:
  - "tools/mcp-tool-catalog"
  - "fundamentals/http"
  - "vulnerabilities/access-control/idor-bola-bfla"
---

# Guia Investigativo — Burp Suite MCP (:9876)

#burp #mcp #proxy #repeater #tools

## Quando Selecionar o Burp Suite MCP
Selecione o Burp quando a pergunta investigativa exigir **inspeção de tráfego real autenticado do operador** ou **experimentos HTTP controlados de alta precisão** (1 variável por vez):
- \`burp_suite_status\`: confirma conexão SSE em \`:9876\` e lista capacidades ativas.
- \`burp_suite_get_proxy_history\`: consulta tráfego real navegado pelo operador (prefira \`regex\` específico e \`count\` enxuto para economizar contexto).
- \`burp_suite_send_http1_request\` / \`burp_suite_call_tool\` (\`send_http2_request\`): executa experimento diferencial direto dentro do escopo autorizado.
- \`burp_suite_create_repeater_tab\`: entrega uma requisição preparada na tela central para revisão visual conjunta com o operador humano.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/tools/nuclei.md",
    content: `---
id: tools/nuclei
title: Guia Investigativo — ProjectDiscovery Nuclei via MCP no CyberLab OS
tier: curated
category: tools
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "ProjectDiscovery Nuclei Documentation & Template Specification"
limitations:
  - "Saídas do Nuclei são evidências preliminares; templates baseados apenas em status code ou versão exigem validação manual antes de confirmar vulnerabilidade."
related:
  - "tools/mcp-tool-catalog"
  - "research/cve-analysis/cve-applicability-methodology"
  - "methodologies/evidence-validation"
---

# Guia Investigativo — Nuclei via MCP

#nuclei #mcp #templates #cve #tools

## Uso Cirúrgico vs. Ruído Indiscriminado
- **Incorreto**: disparar milhares de templates genéricos contra um alvo sem conhecer a stack.
- **Correto (Orientado por Hipótese)**: após identificar na Fase B/C a tecnologia exata (ex.: Actuator, GraphQL, Nginx, tecnologia específica), invoque \`arsenal_run_tool\` com \`slotId: "nuclei"\` filtrando tags/templates pertinentes (\`-tags\`, \`-t\`, \`-rl 15\`, \`-silent\`) e valide todo match positivo conforme [[evidence-validation]].
`,
  },
  {
    relativePath: "CyberLab-Knowledge/tools/semgrep.md",
    content: `---
id: tools/semgrep
title: Guia Investigativo — OpenGrep / Semgrep (SAST & Variant Analysis) via MCP
tier: curated
category: tools
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OpenGrep / Semgrep Rule Writing & Dataflow Documentation"
limitations:
  - "Análise estática sem rastreamento completo inter-arquivos pode gerar falsos positivos quando a sanitização ocorre em middleware/decorator externo."
related:
  - "tools/mcp-tool-catalog"
  - "methodologies/root-cause-analysis"
  - "research/patch-analysis/patch-diff-methodology"
---

# Guia Investigativo — OpenGrep / Semgrep via MCP

#semgrep #opengrep #sast #variants #tools

## Quando Selecionar em Auditoria White-Box / Grey-Box
- Mapear rapidamente rotas, middlewares de autenticação e *sinks* perigosos na Fase B (Modelagem).
- Caçar **variantes estruturais** em todo o repositório após encontrar 1 bug real ou analisar um patch em [[patch-diff-methodology]].
- Execute via \`arsenal_run_tool\` (\`slotId: "semgrep"\`) sobre diretórios locais do workspace.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/tools/mcp-tool-catalog.md",
    content: `---
id: tools/mcp-tool-catalog
title: Catálogo Mestre de Ferramentas MCP do CyberLab OS (Conhecimento, Memória & Arsenal)
tier: curated
category: tools
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "CyberLab OS Unified MCP Hub v6.2 (cyberlab/mcp/arsenal-mcp-stdio.ts)"
limitations:
  - "Ferramentas de execução externa obedecem estritamente a .cyberlab/scope.json e só executam slots com botão 🟢 MCP ativo e binário instalado."
related:
  - "tools/burp"
  - "tools/nuclei"
  - "tools/semgrep"
  - "methodologies/hypothesis-driven-testing"
---

# Catálogo Mestre de Ferramentas MCP do CyberLab OS

#mcp #catalog #arsenal #knowledge #tools

## 1. Biblioteca de Conhecimento (\`CyberLab-Knowledge/\`)
- \`search_knowledge\`: pesquisa conceitos, vulnerabilidades, CVEs, metodologias e guias de ferramentas.
- \`read_document\`: lê documento completo com metadados de fonte, versão, data de revisão e limitações.
- \`get_document_metadata\`: consulta metadados e seções sem carregar o corpo inteiro no contexto.
- \`get_related_documents\`: navega relações (\`related\`, \`[[WikiLinks]]\`, backlinks e tags) entre falha → causa raiz → validação → ferramenta.
- \`create_draft_note\`: grava novas descobertas como rascunho em \`CyberLab-Knowledge/_drafts/\` (separa fatos, hipóteses, inferências e incertezas sem alterar documentos curados).
- \`propose_document_update\`: registra proposta estruturada de revisão em \`CyberLab-Knowledge/_proposals/\` para aprovação do operador humano.

## 2. Memória Investigativa da Sessão (Contexto Isolado do Alvo Atual)
- \`investigation_memory_read\`: lê o estado estruturado da investigação atual (missão, escopo, modelo, hipóteses, testes e resultados negativos).
- \`investigation_memory_update\`: atualiza modelo, hipóteses, experimentos, resultados negativos e próximos passos sem poluir a biblioteca curada.

## 3. Hub Unificado do Arsenal Externo (48+ Slots Oficiais + Customizados)
- \`arsenal_mcp_status\`: inventário instantâneo em tempo real de todas as ferramentas com \`🟢 MCP\` ativo (GUI ao vivo, Windows, WSL2 Kali e Web Embed).
- \`arsenal_tool_help\`: verifica versão, caminho resolvido e flags de qualquer slot antes de montar um experimento.
- \`arsenal_run_tool\`: executa ferramenta CLI autorizada com zero interpolação de shell, Trava de Escopo Bug Bounty e redação \`SHA-256\`.

## 4. Pontes GUI em Tempo Real
- **Burp Suite (\`:9876\` SSE)**: \`burp_suite_status\`, \`burp_suite_get_proxy_history\`, \`burp_suite_send_http1_request\`, \`burp_suite_create_repeater_tab\`, \`burp_suite_send_to_intruder\`, \`burp_suite_set_intercept\`, \`burp_suite_call_tool\`.
- **Ghidra (\`:8080\` HTTP — \`LaurieWired/GhidraMCP\`)**: \`ghidra_mcp_status\`, \`ghidra_mcp_decompile\`, \`ghidra_mcp_call\`.
- **JADX-GUI (\`:8650\` HTTP — \`zinja-coder/jadx-ai-mcp\`)**: \`jadx_mcp_status\`, \`jadx_mcp_get_class_source\`, \`jadx_mcp_call\`.
`,
  },
]

function extractTagsClean(markdown: string): string[] {
  const withoutFm = stripYamlFrontmatter(markdown).body
  const withoutCode = withoutFm.replace(/```[\s\S]*?```/g, "")
  const tags = new Set<string>()
  const regex = /(?:^|[\s(])#([a-zA-ZÀ-ÿ0-9_-]{2,40})\b/g
  let m: RegExpExecArray | null
  while ((m = regex.exec(withoutCode)) !== null) {
    if (m[1]) tags.add(m[1].toLowerCase())
  }
  return Array.from(tags).sort()
}

function extractWikiLinksClean(markdown: string): string[] {
  const withoutFm = stripYamlFrontmatter(markdown).body
  const withoutCode = withoutFm.replace(/```[\s\S]*?```/g, "")
  const links = new Set<string>()
  const regex = /\[\[([^\]|#\n]+)(?:[|#][^\]]*)?\]\]/g
  let m: RegExpExecArray | null
  while ((m = regex.exec(withoutCode)) !== null) {
    const target = m[1]?.trim()
    if (target) links.add(target)
  }
  return Array.from(links)
}

function extractSections(markdown: string): string[] {
  const { body } = stripYamlFrontmatter(markdown)
  const withoutCode = body.replace(/```[\s\S]*?```/g, "")
  const out: string[] = []
  for (const line of withoutCode.split(/\r?\n/)) {
    const m = line.match(/^(#{1,3})\s+(.+)$/)
    if (m?.[2]) out.push(m[2].trim())
  }
  return out
}

export function stripYamlFrontmatter(raw: string): { frontmatterRaw: string | null; body: string } {
  const norm = raw.replace(/^\uFEFF/, "")
  if (!norm.startsWith("---\n") && !norm.startsWith("---\r\n")) {
    return { frontmatterRaw: null, body: raw }
  }
  const match = norm.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)
  if (!match) return { frontmatterRaw: null, body: raw }
  return {
    frontmatterRaw: match[1] ?? "",
    body: norm.slice(match[0].length),
  }
}

export function parseDocumentFrontmatter(docPath: string, raw: string): KnowledgeFrontmatter {
  const { frontmatterRaw, body } = stripYamlFrontmatter(raw)
  const h1 = body.match(/^#\s+(.+)$/m)?.[1]?.trim()
  const fallbackTier: KnowledgeFrontmatter["tier"] = docPath.includes("/_drafts/")
    ? "draft"
    : docPath.includes("/_proposals/")
      ? "proposal"
      : docPath.startsWith("Investigacoes/")
        ? "session_context"
        : docPath.startsWith("CyberLab-Knowledge/")
          ? "curated"
          : "note"

  const fm: KnowledgeFrontmatter = {
    id: docPath.replace(/^CyberLab-Knowledge\//, "").replace(/\.md$/i, ""),
    title: h1 || path.posix.basename(docPath, ".md"),
    tier: fallbackTier,
    category: docPath.split("/")[1] || "general",
    version: "1.0.0",
    last_reviewed: "n/a",
    status: fallbackTier === "curated" ? "validated" : "unreviewed",
    sources: [],
    limitations: [],
    related: [],
  }

  if (!frontmatterRaw) return fm

  let currentArrayKey: "sources" | "limitations" | "related" | null = null
  for (const rawLine of frontmatterRaw.split(/\r?\n/)) {
    const listMatch = rawLine.match(/^\s*-\s+(.+)$/)
    if (listMatch && currentArrayKey) {
      const val = listMatch[1]!.trim().replace(/^["']|["']$/g, "")
      if (val) fm[currentArrayKey].push(val)
      continue
    }
    const kv = rawLine.match(/^([a-zA-Z0-9_]+):\s*(.*)$/)
    if (!kv) continue
    const key = kv[1]!
    const rawVal = kv[2]!.trim()
    currentArrayKey = null
    if (key === "sources" || key === "limitations" || key === "related") {
      if (!rawVal) {
        currentArrayKey = key
      } else if (rawVal.startsWith("[") && rawVal.endsWith("]")) {
        const inner = rawVal.slice(1, -1).trim()
        if (inner) {
          fm[key] = inner
            .split(",")
            .map((s) => s.trim().replace(/^["']|["']$/g, ""))
            .filter(Boolean)
        }
      }
      continue
    }
    const val = rawVal.replace(/^["']|["']$/g, "")
    if (key === "id" && val) fm.id = val
    else if (key === "title" && val) fm.title = val
    else if (
      key === "tier" &&
      (val === "curated" || val === "draft" || val === "proposal" || val === "session_context" || val === "note")
    ) {
      fm.tier = val
    } else if (key === "category" && val) fm.category = val
    else if (key === "version" && val) fm.version = val
    else if (key === "last_reviewed" && val) fm.last_reviewed = val
    else if (key === "status" && val) fm.status = val
  }

  return fm
}

export function ensureKnowledgeLibrarySeeded(vaultRootDir: string): void {
  mkdirSync(vaultRootDir, { recursive: true })
  for (const item of CURATED_KNOWLEDGE_FILES) {
    const dest = path.join(vaultRootDir, ...item.relativePath.split("/"))
    if (!existsSync(dest)) {
      mkdirSync(path.dirname(dest), { recursive: true })
      writeFileSync(dest, item.content, "utf8")
    }
  }
}

function resolveVaultRootForWorkspace(workspaceRoot: string, projectId?: string): string {
  const globalDir =
    process.env.CYBERLAB_GLOBAL_CONFIG_DIR ?? path.join(os.homedirFallback(), ".cyberlab")
  const cfgFile = path.join(globalDir, "vault-config.json")
  if (existsSync(cfgFile)) {
    try {
      const parsed = JSON.parse(readFileSync(cfgFile, "utf8")) as {
        customVaultRootByProject?: Record<string, string>
      }
      const map = parsed.customVaultRootByProject ?? {}
      if (projectId && map[projectId]) return path.resolve(map[projectId]!)
    } catch {
      // Ignore malformed vault-config.json
    }
  }
  return path.join(workspaceRoot, "vault")
}

const os = {
  homedirFallback(): string {
    return process.env.HOME || process.env.USERPROFILE || "."
  },
}

function sanitizeSafeSlug(raw: string): string {
  const cleaned = raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80)
  return cleaned || `draft-${Date.now()}`
}

export class CyberLabKnowledgeEngine {
  private readonly workspaceRoot: string
  private readonly vaultRootDir: string

  constructor(options: { workspaceRoot: string; vaultRootDir?: string; projectId?: string }) {
    this.workspaceRoot = path.resolve(options.workspaceRoot)
    this.vaultRootDir = options.vaultRootDir
      ? path.resolve(options.vaultRootDir)
      : resolveVaultRootForWorkspace(this.workspaceRoot, options.projectId)
    ensureKnowledgeLibrarySeeded(this.vaultRootDir)
  }

  getVaultRootDir(): string {
    return this.vaultRootDir
  }

  private listAllMarkdownDocs(): string[] {
    const realRoot = existsSync(this.vaultRootDir)
      ? realpathSync(this.vaultRootDir)
      : this.vaultRootDir
    const out: string[] = []
    const walk = (dir: string, prefix: string) => {
      if (out.length >= 600) return
      let entries
      try {
        entries = readdirSync(dir, { withFileTypes: true })
      } catch {
        return
      }
      for (const ent of entries) {
        if (out.length >= 600) break
        if (ent.name.startsWith(".") || ent.name === "node_modules") continue
        const full = path.join(dir, ent.name)
        try {
          const lst = lstatSync(full)
          if (lst.isSymbolicLink()) continue
          const rel = prefix ? `${prefix}/${ent.name}` : ent.name
          if (lst.isDirectory()) walk(full, rel)
          else if (lst.isFile() && ent.name.toLowerCase().endsWith(".md") && isPathInsideRoot(full, realRoot)) {
            out.push(rel)
          }
        } catch {
          // Ignore unreadable
        }
      }
    }
    walk(realRoot, "")
    return out.sort()
  }

  private resolveDocPath(inputPath: string): { docPath: string; absPath: string } {
    const cleaned = inputPath
      .replace(/\\/g, "/")
      .trim()
      .replace(/^\/+/, "")
      .replace(/\/+/g, "/")
    if (!cleaned || cleaned.includes("\0") || cleaned.split("/").some((s) => s === "." || s === "..")) {
      throw new Error(`Caminho de documento inválido: ${inputPath}`)
    }
    const realRoot = realpathSync(this.vaultRootDir)
    const candidates = [
      cleaned.endsWith(".md") ? cleaned : `${cleaned}.md`,
      cleaned.startsWith("CyberLab-Knowledge/")
        ? cleaned.endsWith(".md")
          ? cleaned
          : `${cleaned}.md`
        : `CyberLab-Knowledge/${cleaned.endsWith(".md") ? cleaned : `${cleaned}.md`}`,
    ]
    for (const rel of candidates) {
      const abs = path.resolve(realRoot, ...rel.split("/"))
      if (!isPathInsideRoot(abs, realRoot)) {
        throw new Error(`Escape de caminho bloqueado: ${inputPath}`)
      }
      if (existsSync(abs)) {
        const st = lstatSync(abs)
        if (!st.isSymbolicLink() && st.isFile()) {
          return { docPath: rel, absPath: abs }
        }
      }
    }
    // Search by basename, short path, or unique folder prefix across CyberLab-Knowledge
    const needle = cleaned.replace(/\/+$/, "").replace(/\.md$/i, "").toLowerCase()
    const allDocs = this.listAllMarkdownDocs()
    for (const rel of allDocs) {
      const noExt = rel.replace(/\.md$/i, "").toLowerCase()
      const shortNoPrefix = noExt.replace(/^cyberlab-knowledge\//, "")
      const base = path.posix.basename(noExt)
      if (noExt === needle || shortNoPrefix === needle || base === needle) {
        const abs = path.resolve(realRoot, ...rel.split("/"))
        return { docPath: rel, absPath: abs }
      }
    }
    const folderMatches = allDocs.filter((rel) => {
      const shortNoPrefix = rel.replace(/\.md$/i, "").toLowerCase().replace(/^cyberlab-knowledge\//, "")
      return shortNoPrefix.startsWith(`${needle}/`)
    })
    if (folderMatches.length > 0) {
      const chosen = folderMatches[0]!
      const abs = path.resolve(realRoot, ...chosen.split("/"))
      return { docPath: chosen, absPath: abs }
    }
    throw new Error(`Documento não encontrado na biblioteca CyberLab-Knowledge: ${inputPath}`)
  }

  searchKnowledge(options: {
    query: string
    category?: string
    includeDrafts?: boolean
    includeSessionContext?: boolean
    limit?: number
  }): KnowledgeSearchHit[] {
    const rawQuery = options.query.trim().toLowerCase()
    const terms = rawQuery.split(/\s+/).filter(Boolean)
    const maxHits = Math.max(1, Math.min(options.limit ?? 10, 30))
    const hits: KnowledgeSearchHit[] = []

    for (const rel of this.listAllMarkdownDocs()) {
      const abs = path.join(this.vaultRootDir, ...rel.split("/"))
      const raw = readFileSync(abs, "utf8")
      const fm = parseDocumentFrontmatter(rel, raw)
      if (!options.includeDrafts && (fm.tier === "draft" || fm.tier === "proposal")) continue
      if (!options.includeSessionContext && fm.tier === "session_context") continue
      if (options.category && fm.category.toLowerCase() !== options.category.toLowerCase()) continue

      const tags = extractTagsClean(raw)
      const sections = extractSections(raw)
      const { body } = stripYamlFrontmatter(raw)
      const hayTitle = `${fm.title} ${fm.id} ${rel} ${tags.join(" ")}`.toLowerCase()
      const hayBody = body.toLowerCase()

      let score = 0
      if (terms.length === 0) {
        score = fm.tier === "curated" ? 10 : 5
      } else {
        for (const t of terms) {
          if (fm.title.toLowerCase().includes(t)) score += 12
          if (rel.toLowerCase().includes(t)) score += 10
          if (tags.some((tag) => tag.includes(t))) score += 8
          if (sections.some((sec) => sec.toLowerCase().includes(t))) score += 6
          if (hayBody.includes(t)) score += 3
          if (fm.sources.some((s) => s.toLowerCase().includes(t))) score += 4
        }
        if (hayTitle.includes(rawQuery)) score += 10
      }

      if (score <= 0) continue
      const matchedSections =
        terms.length > 0
          ? sections.filter((s) => terms.some((t) => s.toLowerCase().includes(t)))
          : sections.slice(0, 3)

      let excerpt = body.replace(/```[\s\S]*?```/g, " ").replace(/\s+/g, " ").trim().slice(0, 220)
      if (terms.length > 0) {
        const idx = hayBody.indexOf(terms[0]!)
        if (idx >= 0) {
          const start = Math.max(0, idx - 60)
          excerpt = body.slice(start, start + 220).replace(/\s+/g, " ").trim()
        }
      }

      hits.push({
        docPath: rel,
        title: fm.title,
        tier: fm.tier,
        category: fm.category,
        version: fm.version,
        last_reviewed: fm.last_reviewed,
        status: fm.status,
        score,
        matchedSections,
        sources: fm.sources,
        limitations: fm.limitations,
        excerpt,
      })
    }

    return hits.sort((a, b) => b.score - a.score || a.docPath.localeCompare(b.docPath)).slice(0, maxHits)
  }

  getDocumentMetadata(docPathInput: string): KnowledgeDocumentMetadata {
    const { docPath, absPath } = this.resolveDocPath(docPathInput)
    const raw = readFileSync(absPath, "utf8")
    const st = statSync(absPath)
    const fm = parseDocumentFrontmatter(docPath, raw)
    return {
      ...fm,
      docPath,
      tags: extractTagsClean(raw),
      wikiLinks: extractWikiLinksClean(raw),
      sections: extractSections(raw),
      sizeBytes: st.size,
      updatedAt: st.mtime.toISOString(),
    }
  }

  readDocument(docPathInput: string): {
    metadata: KnowledgeDocumentMetadata
    body: string
    rawContent: string
  } {
    const { docPath, absPath } = this.resolveDocPath(docPathInput)
    const raw = readFileSync(absPath, "utf8")
    const st = statSync(absPath)
    const fm = parseDocumentFrontmatter(docPath, raw)
    const { body } = stripYamlFrontmatter(raw)
    return {
      metadata: {
        ...fm,
        docPath,
        tags: extractTagsClean(raw),
        wikiLinks: extractWikiLinksClean(raw),
        sections: extractSections(raw),
        sizeBytes: st.size,
        updatedAt: st.mtime.toISOString(),
      },
      body: body.trim(),
      rawContent: raw,
    }
  }

  getRelatedDocuments(docPathInput: string): {
    sourceDocPath: string
    related: RelatedDocumentEdge[]
  } {
    const { metadata: srcMeta } = this.readDocument(docPathInput)
    const edges = new Map<string, RelatedDocumentEdge>()
    const allDocs = this.listAllMarkdownDocs()

    // 1. Explicit frontmatter `related`
    for (const relRef of srcMeta.related) {
      try {
        const target = this.getDocumentMetadata(relRef)
        if (target.docPath !== srcMeta.docPath) {
          edges.set(target.docPath, {
            docPath: target.docPath,
            title: target.title,
            tier: target.tier,
            relationType: "frontmatter_related",
            detail: `Relação curada direta (${relRef})`,
          })
        }
      } catch {
        // Ignore unresolved external ref
      }
    }

    // 2. Outgoing [[WikiLinks]]
    for (const wl of srcMeta.wikiLinks) {
      try {
        const target = this.getDocumentMetadata(wl)
        if (target.docPath !== srcMeta.docPath && !edges.has(target.docPath)) {
          edges.set(target.docPath, {
            docPath: target.docPath,
            title: target.title,
            tier: target.tier,
            relationType: "wikilink_out",
            detail: `Citado via [[${wl}]]`,
          })
        }
      } catch {
        // Ignore
      }
    }

    // 3. Incoming backlinks + shared tags across curated docs
    const srcBase = path.posix.basename(srcMeta.docPath, ".md").toLowerCase()
    const srcIdLower = srcMeta.id.toLowerCase()
    for (const candidateRel of allDocs) {
      if (candidateRel === srcMeta.docPath || edges.has(candidateRel)) continue
      const abs = path.join(this.vaultRootDir, ...candidateRel.split("/"))
      const raw = readFileSync(abs, "utf8")
      const fm = parseDocumentFrontmatter(candidateRel, raw)
      if (fm.tier === "session_context") continue
      const wls = extractWikiLinksClean(raw).map((x) => x.toLowerCase())
      const fmRels = fm.related.map((x) => x.toLowerCase())
      if (
        wls.includes(srcBase) ||
        wls.includes(srcIdLower) ||
        fmRels.includes(srcIdLower) ||
        fmRels.includes(srcBase)
      ) {
        edges.set(candidateRel, {
          docPath: candidateRel,
          title: fm.title,
          tier: fm.tier,
          relationType: "backlink_in",
          detail: `Referencia ${srcMeta.id}`,
        })
        continue
      }
      const otherTags = extractTagsClean(raw).filter(
        (t) => !["cyberlab", "curated", "knowledge", "fundamentals", "methodology", "tools", "vulnerabilities", "research"].includes(t),
      )
      const shared = srcMeta.tags.filter((t) => otherTags.includes(t))
      if (shared.length >= 2) {
        edges.set(candidateRel, {
          docPath: candidateRel,
          title: fm.title,
          tier: fm.tier,
          relationType: "shared_tags",
          detail: `Tags em comum: #${shared.join(", #")}`,
        })
      }
    }

    return {
      sourceDocPath: srcMeta.docPath,
      related: Array.from(edges.values()),
    }
  }

  createDraftNote(input: {
    slug: string
    title: string
    category?: string
    factsObserved: string[]
    hypotheses?: string[]
    inferences?: string[]
    uncertainties?: string[]
    sources?: string[]
    limitations?: string[]
    relatedDocs?: string[]
    tags?: string[]
    additionalMarkdown?: string
  }): { draftDocPath: string; message: string } {
    const safeSlug = sanitizeSafeSlug(input.slug || input.title)
    const relPath = `CyberLab-Knowledge/_drafts/${safeSlug}.md`
    const realRoot = realpathSync(this.vaultRootDir)
    const dest = path.resolve(realRoot, ...relPath.split("/"))
    if (!isPathInsideRoot(dest, realRoot)) {
      throw new Error("Caminho de rascunho inválido.")
    }
    mkdirSync(path.dirname(dest), { recursive: true })
    const today = new Date().toISOString().slice(0, 10)
    const tagLine = ["draft", ...(input.tags ?? [])]
      .map((t) => `#${t.replace(/^#+/, "").replace(/[^a-zA-Z0-9_-]/g, "")}`)
      .filter((t) => t.length > 1)
      .join(" ")

    const fmtList = (items?: string[], emptyMsg = "- *(Nenhum item registrado)*") =>
      items && items.length > 0 ? items.map((x) => `- ${x}`).join("\n") : emptyMsg

    const content = [
      "---",
      `id: "_drafts/${safeSlug}"`,
      `title: "${input.title.replace(/"/g, "'")}"`,
      `tier: draft`,
      `category: "${(input.category || "research").replace(/"/g, "'")}"`,
      `version: "0.1.0-draft"`,
      `last_reviewed: "${today}"`,
      `status: unverified_draft`,
      ...(input.sources?.length
        ? ["sources:", ...input.sources.map((s) => `  - "${s.replace(/"/g, "'")}"`)]
        : ["sources: []"]),
      ...(input.limitations?.length
        ? ["limitations:", ...input.limitations.map((l) => `  - "${l.replace(/"/g, "'")}"`)]
        : ['limitations:\n  - "Rascunho gerado durante investigação; requer revisão e validação humana antes de promoção para conhecimento curado."']),
      ...(input.relatedDocs?.length
        ? ["related:", ...input.relatedDocs.map((r) => `  - "${r.replace(/"/g, "'")}"`)]
        : ["related: []"]),
      "---",
      "",
      `# [RASCUNHO] ${input.title}`,
      "",
      tagLine,
      "",
      "> ⚠️ **Nota Epistemológica (`tier: draft`)**: Este documento é um rascunho não curado. Não trate hipóteses ou inferências abaixo como conhecimento confirmado da biblioteca.",
      "",
      "## 1. Fatos Observados Empiricamente",
      fmtList(input.factsObserved),
      "",
      "## 2. Hipóteses em Aberto",
      fmtList(input.hypotheses),
      "",
      "## 3. Inferências Técnicas",
      fmtList(input.inferences),
      "",
      "## 4. Incertezas e Limitações",
      fmtList(input.uncertainties),
      ...(input.additionalMarkdown?.trim()
        ? ["", "## 5. Detalhamento Adicional", input.additionalMarkdown.trim()]
        : []),
      "",
    ].join("\n")

    writeFileSync(dest, content, "utf8")
    return {
      draftDocPath: relPath,
      message: `Rascunho registrado com sucesso em "${relPath}" (tier: draft, sem alterar nenhum documento curado).`,
    }
  }

  proposeDocumentUpdate(input: {
    targetDocPath: string
    targetSection: string
    rationale: string
    proposedContent: string
    primarySources: string[]
    limitations?: string[]
  }): { proposalDocPath: string; targetDocPath: string; message: string } {
    const cleanSources = (input.primarySources ?? []).map((s) => s.trim()).filter(Boolean)
    if (cleanSources.length === 0) {
      throw new Error(
        "propose_document_update exige pelo menos uma fonte primária verificável em primarySources.",
      )
    }
    const targetMeta = this.getDocumentMetadata(input.targetDocPath)
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)
    const baseSlug = sanitizeSafeSlug(`${targetMeta.id.replace(/\//g, "-")}-${stamp}`)
    const relPath = `CyberLab-Knowledge/_proposals/${baseSlug}.md`
    const realRoot = realpathSync(this.vaultRootDir)
    const dest = path.resolve(realRoot, ...relPath.split("/"))
    if (!isPathInsideRoot(dest, realRoot)) {
      throw new Error("Caminho de proposta inválido.")
    }
    mkdirSync(path.dirname(dest), { recursive: true })
    const today = new Date().toISOString().slice(0, 10)
    const content = [
      "---",
      `id: "_proposals/${baseSlug}"`,
      `title: "Proposta de Atualização -> ${targetMeta.id} (${input.targetSection.replace(/"/g, "'")})"`,
      `tier: proposal`,
      `category: proposal`,
      `version: "${targetMeta.version}-proposed"`,
      `last_reviewed: "${today}"`,
      `status: pending_human_review`,
      ...(input.primarySources.length > 0
        ? ["sources:", ...input.primarySources.map((s) => `  - "${s.replace(/"/g, "'")}"`)]
        : ["sources: []"]),
      ...(input.limitations?.length
        ? ["limitations:", ...input.limitations.map((l) => `  - "${l.replace(/"/g, "'")}"`)]
        : ["limitations: []"]),
      "related:",
      `  - "${targetMeta.id}"`,
      "---",
      "",
      `# Proposta de Atualização Curada: \`${targetMeta.docPath}\``,
      "",
      "#proposal #review-needed",
      "",
      `- **Documento Alvo**: [[${targetMeta.id}]] (\`${targetMeta.docPath}\`, versão atual \`${targetMeta.version}\`)`,
      `- **Seção Alvo**: \`${input.targetSection}\``,
      `- **Status**: \`pending_human_review\` *(O documento original curado permaneceu 100% intacto)*`,
      "",
      "## Justificativa Técnica",
      input.rationale.trim(),
      "",
      "## Fontes Primárias Verificáveis",
      ...(input.primarySources.length > 0
        ? input.primarySources.map((s) => `- ${s}`)
        : ["- *(Nenhuma fonte informada — revisar antes de aprovar)*"]),
      "",
      "## Conteúdo Proposto para Revisão do Operador",
      input.proposedContent.trim(),
      "",
    ].join("\n")

    writeFileSync(dest, content, "utf8")
    return {
      proposalDocPath: relPath,
      targetDocPath: targetMeta.docPath,
      message: `Proposta de atualização gravada em "${relPath}" para revisão humana (documento curado "${targetMeta.docPath}" mantido intacto).`,
    }
  }

  private getInvestigationJsonPath(investigationId: string): string {
    const safeId = sanitizeSafeSlug(investigationId || "sessao-atual")
    return path.join(this.workspaceRoot, ".cyberlab", "investigations", `${safeId}.json`)
  }

  readInvestigationMemory(investigationId = "sessao-atual"): InvestigationSessionMemory {
    const safeId = sanitizeSafeSlug(investigationId || "sessao-atual")
    const jsonPath = this.getInvestigationJsonPath(safeId)
    if (existsSync(jsonPath)) {
      try {
        return JSON.parse(readFileSync(jsonPath, "utf8")) as InvestigationSessionMemory
      } catch {
        // Fall through to default
      }
    }
    return {
      investigationId: safeId,
      updatedAt: new Date().toISOString(),
      mission: "",
      authorizedScope: "",
      systemModel: {
        components: [],
        technologies: [],
        dataFlows: [],
        trustBoundaries: [],
        identitiesAndPermissions: [],
      },
      hypotheses: [],
      experiments: [],
      negativeResults: [],
      decisions: [],
      externalReferences: [],
      openQuestions: [],
      nextSteps: [],
    }
  }

  updateInvestigationMemory(
    patch: Partial<InvestigationSessionMemory> & { investigationId?: string },
  ): { memory: InvestigationSessionMemory; vaultMirrorPath: string } {
    const safeId = sanitizeSafeSlug(patch.investigationId || "sessao-atual")
    const current = this.readInvestigationMemory(safeId)

    const merged: InvestigationSessionMemory = {
      investigationId: safeId,
      updatedAt: new Date().toISOString(),
      mission: patch.mission !== undefined ? patch.mission : current.mission,
      authorizedScope:
        patch.authorizedScope !== undefined ? patch.authorizedScope : current.authorizedScope,
      systemModel: {
        components: patch.systemModel?.components ?? current.systemModel.components,
        technologies: patch.systemModel?.technologies ?? current.systemModel.technologies,
        dataFlows: patch.systemModel?.dataFlows ?? current.systemModel.dataFlows,
        trustBoundaries: patch.systemModel?.trustBoundaries ?? current.systemModel.trustBoundaries,
        identitiesAndPermissions:
          patch.systemModel?.identitiesAndPermissions ?? current.systemModel.identitiesAndPermissions,
      },
      hypotheses: patch.hypotheses ?? current.hypotheses,
      experiments: patch.experiments ?? current.experiments,
      negativeResults: patch.negativeResults ?? current.negativeResults,
      decisions: patch.decisions ?? current.decisions,
      externalReferences: patch.externalReferences ?? current.externalReferences,
      openQuestions: patch.openQuestions ?? current.openQuestions,
      nextSteps: patch.nextSteps ?? current.nextSteps,
    }

    const jsonPath = this.getInvestigationJsonPath(safeId)
    mkdirSync(path.dirname(jsonPath), { recursive: true })
    writeFileSync(jsonPath, `${JSON.stringify(merged, null, 2)}\n`, "utf8")

    // Also render human-readable Markdown mirror in `vault/Investigacoes/<safeId>.md` (`tier: session_context`)
    const relMd = `Investigacoes/${safeId}.md`
    const realRoot = realpathSync(this.vaultRootDir)
    const mdDest = path.resolve(realRoot, ...relMd.split("/"))
    if (isPathInsideRoot(mdDest, realRoot)) {
      mkdirSync(path.dirname(mdDest), { recursive: true })
      const mdLines = [
        "---",
        `id: "Investigacoes/${safeId}"`,
        `title: "Memória Investigativa — ${safeId}"`,
        `tier: session_context`,
        `category: investigation`,
        `version: "live"`,
        `last_reviewed: "${merged.updatedAt.slice(0, 10)}"`,
        `status: active_session`,
        "---",
        "",
        `# Memória Investigativa da Sessão: \`${safeId}\``,
        "",
        "#investigacao #session-context #hipoteses",
        "",
        `> **Camada Epistemológica**: \`tier: session_context\` — Contexto exclusivo desta investigação (isolado da biblioteca curada \`CyberLab-Knowledge/\`).`,
        "",
        `- **Missão**: ${merged.mission || "*(não definida)*"}`,
        `- **Escopo Autorizado**: ${merged.authorizedScope || "*(consultar .cyberlab/scope.json)*"}`,
        `- **Última Atualização**: ${merged.updatedAt}`,
        "",
        "## Modelo do Sistema",
        `- **Componentes**: ${merged.systemModel.components.join(", ") || "—"}`,
        `- **Tecnologias**: ${merged.systemModel.technologies.join(", ") || "—"}`,
        `- **Fluxos de Dados**: ${merged.systemModel.dataFlows.join(" | ") || "—"}`,
        `- **Fronteiras de Confiança**: ${merged.systemModel.trustBoundaries.join(" | ") || "—"}`,
        `- **Identidades & Permissões**: ${merged.systemModel.identitiesAndPermissions.join(", ") || "—"}`,
        "",
        "## Hipóteses",
        ...(merged.hypotheses.length > 0
          ? merged.hypotheses.map(
              (h) =>
                `- **[${h.status.toUpperCase()}] ${h.id} — ${h.title}**: Esperado: ${h.expectedBehavior} | Suspeito: ${h.suspectedBehavior} | Pressuposto frágil: ${h.fragileAssumption} | Evidência necessária: ${h.evidenceNeeded}`,
            )
          : ["- *(Nenhuma hipótese registrada ainda)*"]),
        "",
        "## Experimentos Realizados",
        ...(merged.experiments.length > 0
          ? merged.experiments.map(
              (e) =>
                `- **[${e.verdict}] ${e.id}** (${e.toolUsed}): Pergunta: ${e.question} | Variável: ${e.modifiedVariable} | Observado: ${e.observedOutcome}`,
            )
          : ["- *(Nenhum experimento registrado ainda)*"]),
        "",
        "## Resultados Negativos (Preservados p/ Evitar Retestes)",
        ...(merged.negativeResults.length > 0
          ? merged.negativeResults.map((n) => `- ${n}`)
          : ["- *(Nenhum resultado negativo registrado)*"]),
        "",
        "## Próximos Passos & Questões Pendentes",
        ...(merged.openQuestions.map((q) => `- [ ] Dúvida: ${q}`)),
        ...(merged.nextSteps.map((s) => `- [ ] Próximo passo: ${s}`)),
        "",
      ]
      writeFileSync(mdDest, mdLines.join("\n"), "utf8")
    }

    return { memory: merged, vaultMirrorPath: relMd }
  }
}
