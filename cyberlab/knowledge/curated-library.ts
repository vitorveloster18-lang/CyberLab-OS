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
    relativePath: "CyberLab-Knowledge/fundamentals/jwt-oauth-oidc.md",
    content: `---
id: fundamentals/jwt-oauth-oidc
title: JWT, OAuth 2.1 e OIDC — Modelo de Ameaças e Diferenciais de Validação
tier: curated
category: fundamentals
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "IETF RFC 7519 (JWT), RFC 7517 (JWK), RFC 8725 (JWT BCP)"
  - "IETF RFC 6749 / 6750 (OAuth 2.0) & draft-ietf-oauth-security-topics"
  - "OWASP WSTG v4.2 — Testing for OAuth / JWT weaknesses"
limitations:
  - "Bibliotecas modernas bloqueiam 'alg: none' por padrão; explore a configuração da aplicação, não o algoritmo isoladamente."
  - "Aceitar um token inválido não prova impacto: prove a transição de privilégio ou o acesso a dados de outro tenant."
related:
  - "fundamentals/authentication"
  - "fundamentals/authorization"
  - "vulnerabilities/idor-bola-bfla"
  - "tools/burp"
---

# JWT, OAuth 2.1 e OIDC — Modelo de Ameaças

#jwt #oauth #oidc #tokens #fundamentals

## 1. Invariantes que deveriam valer
1. O **algoritmo** é fixado pelo servidor, nunca lido do header do token.
2. A **assinatura** é verificada antes de qualquer leitura de claim.
3. \`iss\`, \`aud\`, \`exp\`, \`nbf\` e \`sub\` são validados contra a configuração do serviço.
4. A **fonte da chave** (\`kid\`/\`jku\`/\`x5u\`) vem de um allowlist local, não do token.

## 2. Pressupostos frágeis (Fase C/D de [[hypothesis-driven-testing]])
- **\`alg: none\` / strip de assinatura**: token aceito sem assinatura.
- **\`alg\` confuso RS256 -> HS256**: a chave pública RSA é reutilizada como segredo HMAC.
- **\`kid\` manipulado**: path traversal, \`kid\` apontando para arquivo controlado, injeção SQL/NoSQL na busca da chave, ou \`kid\` = URL interna (SSRF).
- **\`jku\` / \`x5u\` aberto**: servidor baixa JWKS de host do atacante.
- **Claim confusion**: \`sub\` vs \`user_id\` vs \`username\`; validar apenas \`sub\` enquanto a autorização usa outro campo.
- **OAuth**: \`redirect_uri\` com correspondência frouxa (prefixo, substring, \`\\@\`, open redirect em parâmetro de path), ausência de \`state\` (CSRF de login), ausência de PKCE em cliente público, \`response_mode\`/\`response_type\` mixado (code injection), token de acesso trocado por **audience** diferente.

## 3. Protocolo de experimento (variável única)
| Experimento | Variável modificada | Observável |
|---|---|---|
| E1 | \`alg: none\`, assinatura vazia | 200 vs 401 |
| E2 | \`alg\` HS256 assinado com a chave pública | 200 vs 401 |
| E3 | \`kid\` = caminho de arquivo inexistente | Mensagem de erro (vaza FS?) |
| E4 | \`sub\` de outro usuário, assinatura válida do próprio | Dados do outro tenant? |
| E5 | \`redirect_uri\` = \`https://alvo/callback/../../evil\` | Código entregue fora do domínio? |

Use \`burp_suite_send_http1_request\` ([[burp]]) alterando **somente** a variável da linha.

## 4. Critério de evidência
Aceitar token inválido em endpoint que não expõe dado nem privilégio é **informativo**, não vulnerabilidade. Classifique em [[evidence-validation]] e registre o impacto observado com par baseline vs. PoC.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/fundamentals/csrf-cors-samesite.md",
    content: `---
id: fundamentals/csrf-cors-samesite
title: CSRF, CORS e SameSite — Invariantes de Ações Autenticadas por Cookie
tier: curated
category: fundamentals
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP WSTG v4.2 — Testing for CSRF / CORS"
  - "IETF RFC 6265bis (Cookies: HTTP State Management Mechanism)"
  - "MDN — Cross-Origin Resource Sharing (CORS)"
limitations:
  - "CORS é um mecanismo de LEITURA da resposta; o bloqueio de CORS não impede que a requisição seja enviada (o impacto real costuma ser CSRF ou vazamento via side effects)."
  - "\`SameSite=Lax\` já neutraliza a maioria dos CSRF baseados em GET/submissão cross-site; foque em endpoints que aceitam content-type incomum."
related:
  - "fundamentals/http"
  - "fundamentals/sessions"
  - "fundamentals/authentication"
  - "vulnerabilities/state-race-invariants"
---

# CSRF, CORS e SameSite — Invariantes de Ações Autenticadas

#csrf #cors #samesite #cookies #fundamentals

## 1. Invariante central
Uma **ação com efeito colateral** (troca de e-mail, criação de chave de API, transferência, exclusão) deve exigir uma credencial que um site de terceiros **não consiga reproduzir automaticamente**: token anti-CSRF vinculado à sessão, cabeçalho customizado, ou reautenticação.

## 2. Onde o invariante quebra
- Cookie de sessão com \`SameSite=None\` (ou ausente em navegadores que defaultam para Lax apenas em alguns contextos) + sem token anti-CSRF.
- Validação de \`Origin\`/\`Referer\` que aceita **prefixo** (\`https://alvo.com.evil.com\`), ausência do header, ou regex ancorada errado.
- Endpoint que aceita \`Content-Type: text/plain\` ou \`application/x-www-form-urlencoded\` construído por formulário HTML simples (não dispara preflight).
- GET usado para mutação de estado (imagem/fetch sem preflight).
- **CORS**: \`Access-Control-Allow-Origin\` refletindo o \`Origin\` do atacante **junto com** \`Access-Control-Allow-Credentials: true\` — permite leitura cross-origin de resposta autenticada.
- \`Access-Control-Allow-Origin: null\` (sandbox iframe) com credenciais.

## 3. Matriz de experimento
| # | Variável | Resultado esperado se seguro |
|---|---|---|
| E1 | Requisição cross-site sem token | 403 / 401 |
| E2 | \`Origin: https://evil.tld\` | Rejeitado |
| E3 | \`Origin: https://alvo.com.evil.tld\` | Rejeitado |
| E4 | \`Content-Type: text/plain\` | Rejeitado (ou ignorado) |
| E5 | \`Origin\` refletido + credenciais | Nunca ambos verdadeiros |

## 4. Anti-falso-positivo
- Resposta 200 em endpoint **idempotente** (leitura) não é CSRF.
- Se o estado real não mudou (verifique com segunda leitura autenticada), não há impacto — registre como resultado negativo em \`investigation_memory_update\`.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/fundamentals/tls-crypto.md",
    content: `---
id: fundamentals/tls-crypto
title: TLS, PKI e Falhas Criptográficas Aplicadas
tier: curated
category: fundamentals
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "IETF RFC 8446 (TLS 1.3) & RFC 9325 (TLS BCP)"
  - "OWASP Testing Guide — Testing for Weak Transport Layer Security"
limitations:
  - "Relatórios automatizados de cipher suite geram muito ruído: reporte apenas o que é explorável no contexto (downgrade, renegociação, mTLS ausente)."
related:
  - "fundamentals/http"
  - "fundamentals/networking"
  - "domains/cloud-iam-containers"
  - "tools/burp"
---

# TLS, PKI e Falhas Criptográficas Aplicadas

#tls #crypto #pki #mtls #fundamentals

## 1. Camadas a modelar (Fase B)
\`Cliente -> terminador TLS (CDN/LB) -> hop interno (mTLS?) -> serviço\`. O handshake que você observa na borda **não é** necessariamente o handshake fim-a-fim.

## 2. Hipóteses testáveis
- **Downgrade / protocolos antigos**: TLS 1.0/1.1 habilitados; fallback inseguro.
- **Validação de certificado em cliente não-browser (mobile/desktop)**: app aceita certificado inválido/autoassinado → MITM possível.
- **Certificate pinning** ausente ou aplicado apenas ao domínio principal (bypass via subdomínio/CDN).
- **mTLS ausente** em serviço interno exposto por erro de roteamento.
- **Hostname/cert mismatch** em segundo hop (app valida a borda, não o destino real).
- **Materiais criptográficos no cliente**: chaves hardcoded, IV/nonce reutilizado, ECB, criptografia de senha reversível, JWT com segredo fraco.

## 3. Experimentos controlados (escopo autorizado)
| Ferramenta | Experimento |
|---|---|
| \`nmap --script ssl-enum-ciphers\` (\`external.nmap-service-probe\`) | Enumera protocolos/suites aceitos |
| \`mitmweb\` (slot) | Tenta interceptar tráfego do app sob teste |
| \`burp_suite_send_http1_request\` | Verifica se o backend aceita HTTP simples vs. redireciona |
| \`openssl s_client\` (WSL2) | Inspeciona cadeia, SNI e validade |

## 4. Critério de severidade
Ausência de HSTS ou cipher fraco **sem** caminho de exploração observado é hardening, não vulnerabilidade. Reserve severidade alta para: interceptação demonstrada, downgrade aceito com dados sensíveis em trânsito, ou segredo criptográfico recuperado do cliente.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/ssrf.md",
    content: `---
id: vulnerabilities/ssrf
title: SSRF — Server-Side Request Forgery (Diferenciais de Parser, Allowlists e Pivô Interno)
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP WSTG v4.2 — Testing for SSRF"
  - "PortSwigger Web Security Academy — SSRF"
  - "CWE-918: Server-Side Request Forgery"
limitations:
  - "SSRF cego sem OAST próprio só pode ser provado por diferença de tempo/status; use o slot 'interactsh' antes de afirmar impacto."
  - "Bloqueios por IP blocking podem ser contornados por DNS rebinding — isso é uma variante, não um bug separado."
related:
  - "fundamentals/networking"
  - "vulnerabilities/http-url-json-differentials"
  - "fundamentals/http"
  - "tools/burp"
---

# SSRF — Server-Side Request Forgery

#ssrf #cloud #metadata #parser-differential #vulnerabilities

## 1. Invariante
O servidor deve buscar **apenas** hosts/URLs previamente autorizados, resolvidos e validados **após** cada redirecionamento, sem permitir que o usuário escolha esquema, host, porta ou caminho livremente.

## 2. Superfícies típicas
Importação de URL (webhook, avatar, PDF/HTML renderer), integração de SSO/OIDC (JWKS/\`jku\`), conversores de documento, pré-visualização de link, e-mail/PDF export, \`url=\` em APIs de clonagem de repositório.

## 3. Diferenciais que produzem bypass (Fase C)
- **Parser de URL divergente**: \`http://alvo.com#@169.254.169.254/\`, \`http://169.254.169.254\\@alvo.com\`, \`http://[::ffff:169.254.169.254]\`, \`http://0xa9.0xfe.0xa9.0xfe\` (hex), \`http://2852039166\` (decimal), \`http://spoofed.burpcollaborator.net\`.
- **Validação antes do redirect**: allowlist aplicada só na primeira requisição; \`302\` para metadata.
- **DNS rebinding**: nome que resolve público (passa na checagem) e interno no segundo lookup (muda a conexão).
- **Esquemas não-HTTP**: \`file://\`, \`gopher://\` (SMTP/Redis), \`dict://\`, \`jar://\`, \`netdoc://\`.
- **Portas/scheme internos**: \`http://127.0.0.1:8500\` (Consul), \`:2375\` (Docker), \`:9200\` (Elasticsearch), \`:11211\` (Memcached).

## 4. Alvos de alto valor
\`169.254.169.254\` (AWS/Azure/GCP metadata), \`metadata.google.internal\`, endpoints de IAM e credenciais temporárias, serviços de admin sem auth em \`localhost\`.

## 5. Protocolo experimental
1. Estabeleça **baseline**: URL externa permitida -> status/tempo/corpo.
2. Varie **um** elemento por vez (host, esquema, porta, redirect, encoding).
3. Confirme OAST com \`interactsh\` antes de classificar SSRF cego.
4. Classifique em [[evidence-validation]]: SSRF que lê metadata com credencial é crítico; SSRF que só confirma tempo é informativo até provar leitura.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/deserialization-xxe-upload.md",
    content: `---
id: vulnerabilities/deserialization-xxe-upload
title: Desserialização Insegura, XXE e Validação de Upload de Arquivos
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP WSTG v4.2 — Testing for XML Injection / File Upload"
  - "CWE-502 (Deserialization), CWE-611 (XXE), CWE-434 (Unrestricted Upload)"
  - "OWASP Top 10 2021 — A08 Software and Data Integrity Failures"
limitations:
  - "Gadgets de desserialização dependem das bibliotecas presentes no classpath/ambiente — confirme a dependência antes de reportar RCE teórico."
  - "XXE cego exige OAST (slot 'interactsh') ou canal de erro; sem isso é apenas 'parser aceita entidade externa'."
related:
  - "vulnerabilities/context-aware-injection"
  - "fundamentals/http"
  - "vulnerabilities/ssrf"
  - "tools/burp"
---

# Desserialização Insegura, XXE e Upload

#deserialization #xxe #upload #integrity #vulnerabilities

## 1. Desserialização insegura (CWE-502)
**Invariante**: dados serializados vindos do cliente são *dados*, nunca código. O servidor deve usar formato puramente descritivo (JSON) com tipos explicitamente esperados.
**Pressupostos frágeis**: assinatura/criptografia do payload verificada *depois* da desserialização; allowlist de classes baseada em denylist; desserialização de cookies/sessões/\`__VIEWSTATE\`/caches/Jobs.
**Experimento**: envie payload assinado inválido e observa se o erro ocorre antes ou depois da desserialização (diferença de tempo / stack trace).

## 2. XXE (CWE-611)
**Invariante**:解析器 XML deve ter DTD/entidades externas desabilitados.
**Variações**: clássico (retorno no corpo), **cego** (entidade externa para \`http://<oast>\`), **out-of-band via DTD externa**, **billion laughs** (DoS), **XInclude**, ataques via upload de SVG/DOCX/XLSX (qualquer XML aceito).
**Experimento**: \`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>\` e depois a variante com URL OAST.

## 3. Upload de arquivo (CWE-434)
**Invariante**: conteúdo é reescrito/validado por tipo real (magic bytes), nome é gerado pelo servidor, execução desabilitada no diretório de destino e o arquivo é servido de origem separada.
**Diferenciais a testar**: extensão dupla (\`a.php.png\`), \`;\`/\`%00\`/newline no nome, \`Content-Type\` confiável vs. sniffing, path traversal no nome, upload de SVG com \`<script>\`, ZIP slip (path traversal ao extrair), polyglot (imagem + código), e arquivos de config (\`.htaccess\`, \`.user.ini\`, \`web.config\`) quando o servidor os honra.

## 4. Critério de evidência
- Leitura de arquivo interno comprovada (conteúdo no corpo ou no OAST) => severidade alta.
- Upload que grava mas **não é interpretado nem executado** pelo servidor => hardening, salvo se o diretório for servidor de conteúdo ativo.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/graphql-websocket.md",
    content: `---
id: vulnerabilities/graphql-websocket
title: GraphQL e WebSocket — Autorização em Resolvers Aninhados e Canais Persistentes
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP WSTG v4.2 — Testing GraphQL / WebSockets"
  - "GraphQL Foundation — Security best practices (depth & complexity limiting)"
limitations:
  - "Introspection desabilitada não significa segurança; obtenha o schema por erros, sugestões de campo e arquivos de cliente (persisted queries)."
related:
  - "vulnerabilities/idor-bola-bfla"
  - "fundamentals/authorization"
  - "vulnerabilities/state-race-invariants"
  - "tools/burp"
---

# GraphQL e WebSocket — Autorização em Profundidade

#graphql #websocket #authorization #realtime #vulnerabilities

## 1. GraphQL
**Invariante**: a checagem de autorização acontece no **resolver**, por campo/objeto, e não apenas no gateway para a operação inteira.
**Superfícies**:
- **Introspection aberta** (\`__schema\`) → mapa completo de tipos, campos e mutações.
- **Autorização por operação**: \`query { adminPanel { users { email } } }\` rejeitada, mas \`query { me { organization { members { email } } } }\` autorizada sem checagem de papel.
- **Aliases + batching**: \`a: login(u:"x",p:"1") b: login(u:"x",p:"2") ...\` burla rate limit por requisição (não por tentativa).
- **Profundidade/complexidade**: query recursiva \`{ a { a { a { ... } } } }\` → DoS.
- **Injeção em argumento**: campos repassados a SQL/NoSQL/CLI (ver [[context-aware-injection]]).
- **CSRF**: mutações via \`GET\` ou \`application/x-www-form-urlencoded\` sem token.

## 2. WebSocket / SSE
**Invariante**: a autorização do handshake **não** substitui a autorização por mensagem e por canal.
- **Origin** não validado → cross-site WebSocket hijacking (cookie enviado automaticamente).
- **Autorização por mensagem ausente**: subscrever canal \`user.<outro_id>\` após handshake válido.
- **Estado pós-handshake**: permissão revogada mas sessão WS permanece viva.
- **Mensagens em massa**: ausência de limite por conexão.

## 3. Protocolo de experimento
1. Capture uma assinatura/mutação legítima.
2. Modifique **somente o identificador** do recurso (ID de usuário/organização/canal).
3. Compare payload recebido vs. esperado; confirme com segunda conta.
4. Classifique com [[evidence-validation]] e registre o par baseline/PoC.

## 4. Ferramenta
\`burp_suite_send_http1_request\` cobre GraphQL sobre HTTP. Para WS use o slot \`caido\`/\`mitmweb\` ou o script do laboratório; todo resultado deve virar evidência SHA-256 antes de virar finding.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/cache-poisoning-deception.md",
    content: `---
id: vulnerabilities/cache-poisoning-deception
title: Web Cache Poisoning e Cache Deception — Invariante de Chave de Cache
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "PortSwigger Research — Practical Web Cache Poisoning / Web Cache Deception"
  - "OWASP WSTG v4.2 — Testing for Cache Poisoning"
limitations:
  - "Requer entender a topologia real de cache (CDN, proxy reverso, cache de aplicação); sem confirmar a camada, o achado é teórico."
related:
  - "fundamentals/http"
  - "vulnerabilities/http-url-json-differentials"
  - "tools/burp"
---

# Web Cache Poisoning e Cache Deception

#cache #poisoning #deception #cdn #vulnerabilities

## 1. Invariante da chave de cache
Uma resposta só pode ser servida do cache se a **chave de cache** contiver **todas** as entradas que influenciam o corpo da resposta: caminho, \`Host\`/\`:authority\`, headers que alteram conteúdo (\`X-Forwarded-Host\`, \`X-Forwarded-Scheme\`, \`Accept-Language\`, cookies relevantes) e query string usada pelo backend.

## 2. Cache Poisoning (resposta envenenada para TODOS)
Caminho: encontre **entrada não-chaveada** que aparece refletida na resposta → dispare a requisição até a entrada de cache ser gravada → vítimas recebem a resposta envenenada.
- Headers não-chaveados refletidos: \`X-Forwarded-Host\`, \`X-Host\`, \`X-Forwarded-Scheme\`, \`X-Original-URL\`, \`X-Rewrite-URL\`.
- Query string não-chaveada mas usada pelo backend.
- **Cache key normalization**: \`//\`, \`%2f\`, \`;\`, parâmetro duplicado, ordem de parâmetros.
- **Fat GET / parameter cloaking**: corpo enviado em GET que o backend lê mas a chave de cache ignora.
- **Poisoning de JS/CSS/import** (mais grave): envenenar recurso estático redirecionado para origem controlada.

## 3. Cache Deception (resposta da VÍTIMA para o atacante)
Caminho: faça a vítima acessar uma URL que o **cache** acredita ser estática (ex.: \`/account/settings/nonexistent.css\` ou \`/api/me/x.js\`) enquanto o **roteador da aplicação** resolve para conteúdo dinâmico autenticado → o atacante recupera a resposta cacheada.
- Depende de divergência de roteamento entre camada de cache e framework.
- Mitigação correta: header \`Cache-Control: no-store\` nas respostas autenticadas + regra de cache apenas em extensões realmente estáticas.

## 4. Protocolo de validação
1. Identifique header de diagnóstico (\`Age\`, \`X-Cache\`, \`CF-Cache-Status\`).
2. Baseline: requisição limpa → observe \`X-Cache: MISS/HIT\`.
3. Injete a entrada candidata → repita até \`HIT\` com o payload refletido.
4. Confirme com **segundo navegador/sessão sem cookies** (prova de impacto a terceiros).
5. \`Vary\` correto e \`Cache-Control: private/no-store\` ausentes são a causa raiz em [[root-cause-analysis]].
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/race-conditions-toctou.md",
    content: `---
id: vulnerabilities/race-conditions-toctou
title: Race Conditions e TOCTOU — Protocolo de Experimento Concorrente
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "PortSwigger Research — Smashing the state machine: exploiting web race conditions"
  - "CWE-362 (Race Condition), CWE-367 (TOCTOU)"
limitations:
  - "Race conditions são probabilísticas: um único teste negativo NÃO refuta a hipótese. Exija N repetições e taxa de sucesso antes de concluir."
  - "Latência de rede do WSL2/lab mascara janelas muito estreitas; use single-packet attack quando disponível."
related:
  - "vulnerabilities/state-race-invariants"
  - "methodologies/hypothesis-driven-testing"
  - "methodologies/evidence-validation"
  - "tools/burp"
---

# Race Conditions e TOCTOU — Protocolo de Experimento Concorrente

#race-condition #toctou #concurrency #vulnerabilities

## 1. Invariante
Operações que **lêem um estado e então agem sobre ele** (verificar saldo → debitar; verificar cupom → aplicar; verificar pertence ao usuário → transferir) devem ser **atômicas** no mesmo domínio de consistência (transação, lock, ou constraint de banco).

## 2. Janela (TOCTOU)
\`CHECK ------ janela ------ ACT\`. Tudo que aumenta o tempo entre o *check* e o *act* amplia a janela: upload de arquivo grande, validação externa, fila, e-mail, geração de token.

## 3. Protocolo experimental obrigatório
1. **Baseline sequencial**: execute a operação 1x e registre o resultado esperado.
2. **Defina N**: mínimo 20 execuções concorrentes por tentativa.
3. **Sincronize a chegada**: use a técnica *single-packet attack* (HTTP/2: último byte de todas as requisições no mesmo pacote TCP) ou \`burp_suite_call_tool\` com grupo paralelo; sem sincronização a janela raramente é atingida.
4. **Meça**: registre a taxa de sucesso (ex.: 3 de 20 com saldo negativo).
5. **Repita** para descartar flakiness de rede.
6. **Critério de parada**: 0 sucessos em 3 baterias de N=20 → declare **resultado negativo** e registre em \`investigation_memory_update\` (não é refutação absoluta, é evidência de baixa explorabilidade).

## 4. Alvos típicos
- Cupons/descontos aplicáveis múltiplas vezes; limite de uso excedido.
- Transferência/estorno com saldo; leilão/lances.
- Convite/ativação de conta reutilizável; e-mail duplicado.
- Criação de recurso com ID derivado de contagem (\`count+1\`).
- Upload + processamento assíncrono (arquivo substituído entre validação e uso).
- Refresh token rotacionado concorrentemente (reuso aceito).

## 5. Causa raiz
Falta de constraint no banco (UNIQUE/limite), leitura fora da transação, ou validação em camada diferente da escrita. Reporte a remediação estrutural em [[root-cause-analysis]], não "adicionar sleep".
`,
  },
  {
    relativePath: "CyberLab-Knowledge/vulnerabilities/mass-assignment-rate-limit.md",
    content: `---
id: vulnerabilities/mass-assignment-rate-limit
title: Mass Assignment, BOPLA e Ausência de Rate Limiting
tier: curated
category: vulnerabilities
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP API Security Top 10 2023 — API3:BOPLA, API6:Unrestricted Access to Sensitive Business Flows, API4:Unrestricted Resource Consumption"
  - "CWE-915 (Mass Assignment), CWE-770 (Allocation Without Limits)"
limitations:
  - "Rate limiting ausente em endpoints baratos é ruído; o impacto existe quando o fluxo é sensível (login, OTP, convite, checkout) ou consumidor de recurso caro."
related:
  - "vulnerabilities/idor-bola-bfla"
  - "fundamentals/authorization"
  - "vulnerabilities/state-race-invariants"
  - "tools/burp"
---

# Mass Assignment, BOPLA e Rate Limiting

#mass-assignment #bopla #rate-limit #api #vulnerabilities

## 1. Mass Assignment (CWE-915)
**Invariante**: o servidor aceita **apenas** a allowlist de campos que o usuário pode definir. Campos de controle (\`role\`, \`is_admin\`, \`balance\`, \`verified\`, \`tenant_id\`, \`price\`) são definidos pelo servidor.
**Experimento**: adicione **um** campo sensível por vez ao corpo legítimo e releia o objeto (GET) para confirmar persistência. Aceitar o campo sem persistir é inócuo.

## 2. BOPLA (Broken Object Property Level Authorization)
Variante sutil de [[idor-bola-bfla]]: o objeto é o correto, mas **propriedades** internas são expostas ou graváveis.
- Resposta de \`GET /users/me\` contendo \`passwordHash\`, \`mfaSecret\`, \`internalNotes\`, \`stripeCustomerId\`.
- Escrita permitida em propriedades derivadas (ex.: \`discountPercent\`, \`planTier\`).
- Campos diferentes por rota: \`GET /orders/:id\` (público) vs \`GET /admin/orders/:id\` — o mesmo serializador reaproveitado.

## 3. Rate Limiting / Consumo irrestrito (API4)
**Invariante**: limites por **identidade e por fluxo sensível**, não apenas por IP.
- Login / "esqueci a senha" / OTP sem limite → força bruta e fadiga de SMS/e-mail.
- Endpoints caros (geração de PDF, export, busca full-text, IA) sem cota → DoS econômico.
- Paginação sem teto (\`limit=999999999\`) → exaustão.
- Bypass comum: header \`X-Forwarded-For\` confiado, variação de caixa no path, ID duplicado em massa (GraphQL alias, ver [[graphql-websocket]]).

## 4. Protocolo de medicação
1. Baseline: 5 requisições legítimas → registre status/tempo.
2. Bateria: N=50 requisições rápidas → observe 429 vs 200.
3. Bateria com \`X-Forwarded-For\` rotativo → o limite muda? (prova que o limite é por IP e contornável).
4. Registre a contagem exata até o bloqueio como evidência quantitativa.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/domains/mobile-android-ios.md",
    content: `---
id: domains/mobile-android-ios
title: Investigação de Segurança Mobile (Android/iOS) — JADX, Frida, MVT
tier: curated
category: domains
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP Mobile Application Security (MASVS / MASTG)"
  - "OWASP Mobile Top 10 2024"
limitations:
  - "Requer APK/IPA legítimo para análise e dispositivo autorizado; nunca analise aplicativo de terceiro fora de um programa com autorização escrita."
  - "Bypass de root/frida detection é meio, não fim — o finding é o dado ou a autorização exposta depois do bypass."
related:
  - "tools/mcp-tool-catalog"
  - "vulnerabilities/idor-bola-bfla"
  - "fundamentals/tls-crypto"
  - "domains/binary-reverse-engineering"
---

# Investigação de Segurança Mobile (Android/iOS)

#mobile #android #ios #jadx #frida #mvt #domains

## 1. Pipeline investigativo (Fases B→F)
1. **Modelagem estática**: \`external.jadx-decompile\` (JADX) → Java/Kotlin近似; \`AndroidManifest.xml\` (permissões, \`exported\`, \`debuggable\`, \`allowBackup\`, esquemas de deep link, \`networkSecurityConfig\`).
2. **Superfície de dados**: \`SharedPreferences\`, SQLite, Realm, arquivos em \`getExternalStorage\`, backups (\`allowBackup=true\`), logs, clipboard.
3. **Superfície de rede**: HTTP claro (\`cleartextTrafficPermitted\`), pinning ([[tls-crypto]]), certificados embutidos, endpoints hardcoded, WebView com \`setJavaScriptEnabled\` + \`addJavascriptInterface\`.
4. **Dinâmico**: Frida (\`frida-apktool\` slot) para hooks de crypto, SSL pinning, verificação de assinatura e leitura de memória de segredos.

## 2. Hipóteses frequentes
- **H1**: o app hardcoded um segredo de API/chave de criptografia recuperável por strings/decompilação.
- **H2**: \`android:exported="true"\` em Content Provider/Activity/Service sem permissão → acesso a dados por outro app instalado.
- **H3**: deep link sem validação de origem → navegação forçada/roubo de token OAuth.
- **H4**: pinning ausente → interceptação demonstrada com \`mitmweb\`.
- **H5**: WebView expõe bridge JS nativo a qualquer página carregada.
- **H6**: armazenamento inseguro de token de sessão/refresh legível por backup ou por outro app.

## 3. iOS (quando aplicável)
Keychain (\`kSecAttrAccessible\`), \`NSURLSession\` ATS exceptions, plist com segredos, screenshot caching, jailbreak detection apenas cosmética.

## 4. Forense defensiva
O slot \`mvt-android\` (Mobile Verification Toolkit) cruza indicadores de comprometimento — útil para investigação de dispositivo, não para ataque.

## 5. Evidência
Todo achado deve virar evidência SHA-256 (trecho do manifest/decompilação/output do hook), nunca apenas uma captura de tela. Use \`create_draft_note\` para o rascunho e só então \`cyberlab_finding_propose\`.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/domains/binary-reverse-engineering.md",
    content: `---
id: domains/binary-reverse-engineering
title: Engenharia Reversa Investigativa — Ghidra, Rizin, CAPA, GEF
tier: curated
category: domains
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "NSA Ghidra Documentation (Apache-2.0)"
  - "MITRE ATT&CK & CAPA (mandiant/capa) capability taxonomy"
  - "Rizin/Cutter book (LGPL-3.0)"
limitations:
  - "RE é caro em tempo: aplique somente quando a hipótese exige entender uma decisão interna do binário (licença, protocolo, criptografia ofuscada)."
  - "Decompilação é aproximada — confirme comportamento dinamicamente antes de afirmar."
related:
  - "tools/mcp-tool-catalog"
  - "methodologies/patch-diff-methodology"
  - "methodologies/root-cause-analysis"
  - "domains/mobile-android-ios"
---

# Engenharia Reversa Investigativa

#re #ghidra #rizin #capa #gef #malware #domains

## 1. Quando escalar para RE
Use o MCP \`GhidraMCP\` (\`:8080\`) ou \`JADX-AI-MCP\` (\`:8650\`) quando:
- A aplicação é **closed-source** e a decisão de segurança acontece dentro dela (validação de licença, rotina de criptografia, protocolo proprietário).
- Você precisa **comparar binários** antes/depois de um patch ([[patch-diff-methodology]]).
- Há suspeita de backdoor/tampering em artefato de terceiros.

## 2. Pipeline (Fase B→D)
1. **Triage estático** (\`capa\`): capacidades ATT&CK detectadas — direciona onde olhar.
2. **Strings + imports + seções**: \`strings\`, símbolos, entropia (packer?), imports suspeitos (\`VirtualAlloc\`, \`ptrace\`, \`dlopen\`).
3. **Decompilação** (\`external.ghidra-decompile\` Ghidra headless): localize o *sink* (função perigosa) e caminhe para trás até a *source* controlável.
4. **Dinâmico** (GDB/GEF, Rizin debug, Frida): confirme a hipótese observando estado real (registradores, memória, syscalls).

## 3. Hipóteses típicas
- **H1 (cripto fraca/errada)**: chave/IV fixo, \`rand()\` sem semeadura, ECB, comparação de segredo com \`strcmp\` (timing).
- **H2 (parsing inseguro)**: \`strcpy\`/\`sprintf\`/\`memcpy\` com tamanho controlado; loop de cópia sem limite; off-by-one.
- **H3 (autenticação local)**: verificação de licença/serial em branch comparável (patch diff de 1 byte).
- **H4 (hardcoded secret)**: credencial embutida recuperável por strings/decompilação.
- **H5 (anti-analysis)**: detecção de debugger que altera comportamento (isso muda suas conclusões — descarte antes de medir).

## 4. Rigor
- Nomeie funções/variáveis conforme descobre (\`FUN_00401230\` → \`check_license\`) e registre o mapeamento.
- Separe **fato** (bytes, instruções) de **inferência** (semântica atribuída) no rascunho.
- Confirme dinamicamente: uma hipótese estática não validada é \`inconclusive\` em [[evidence-validation]].

## 5. Ferramentas MCP no CyberLab OS
\`ghidra\` (\`:8080\` HTTP, ~30 tools de análise), \`jadx\` (\`:8650\`), \`rizin-cutter\`, \`capa\`, \`gef\`, \`frida-apktool\`, e REA (56 tools) via \`arsenal_run_tool\`/\`arsenal_mcp_status\`.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/domains/cloud-iam-containers.md",
    content: `---
id: domains/cloud-iam-containers
title: Superfície Cloud, IAM e Contêineres — Modelo de Confiança e Escalada
tier: curated
category: domains
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "OWASP Cloud-Native Application Security Top 10"
  - "MITRE ATT&CK Cloud Matrix (IaaS/Containers)"
  - "CIS Benchmarks (Kubernetes / Docker)"
limitations:
  - "Somente dentro de escopo autorizado por escrito; ações em ambiente cloud de terceiro sem autorização são crime."
  - "Achados de configuração (hardening) devem ser separados de exploração demonstrada."
related:
  - "domains/logging-forensics-detection"
  - "fundamentals/authorization"
  - "vulnerabilities/ssrf"
  - "tools/mcp-tool-catalog"
---

# Superfície Cloud, IAM e Contêineres

#cloud #iam #kubernetes #containers #trivy #domains

## 1. Modelo de confiança a mapear (Fase B)
\`Identidade (usuário/serviço) -> Política (IAM) -> Recurso -> Rede -> Dados\`. Cada seta é uma fronteira onde uma checagem pode faltar.

## 2. Hipóteses de alto valor
- **H1 — Metadata/IMDS acessível**: \`169.254.169.254\` vaza credencial temporária (veja [[ssrf]]).
- **H2 — Escopo de credencial amplo**: chave de leitura consegue escrever; \`Action: *\` com \`Resource: *\`; permissão \`iam:PassRole\` + \`lambda:CreateFunction\` = escalada clássica.
- **H3 — Confusão de agente**: serviço que aceita *role* escolhida pelo chamador.
- **H4 — Bucket/container público ou com ACL permissiva**: leitura/gravação anônima, listagem habilitada.
- **H5 — Contêiner privilegiado / escape**: \`privileged: true\`, \`hostPID\`, montagem de \`/var/run/docker.sock\`, \`cap_sys_admin\`.
- **H6 — Segredo em imagem/env**: \`docker history\`, variáveis de ambiente, \`.git\` embutido, chave em layer.
- **H7 — Dependência vulnerável em imagem**: \`external.trivy-scan\` sobre a imagem/filesystem.

## 3. Experimentos controlados
| Experimento | Observável esperado se vulnerável |
|---|---|
| \`curl http://169.254.169.254/latest/meta-data/iam/...\` | JSON com credencial |
| Assumir role externa à do chamador | \`AssumeRole\` aceito |
| Escrever objeto em bucket com credencial de leitura | \`200 OK\` |
| \`docker run --rm -v /:/host alpine chroot /host\` em container privilegiado | Acesso ao FS do host |

## 4. Trivy no CyberLab OS
\`external.trivy-scan\` (\`trivy fs|image|config|repo\`) varre filesystem/imagem e IaC (Dockerfile, K8s YAML, Terraform) dentro do workspace, gerando evidência SHA-256. Execute sobre **cópia local autorizada**, nunca direto na infraestrutura de produção sem janela aprovada.

## 5. Evidência
Credencial obtida é dado sensível: registre apenas o prefixo/ARN no relatório e use \`redactSensitiveContent\` (o control plane já aplica redação automática em KeyHunter e equivalentes).
`,
  },
  {
    relativePath: "CyberLab-Knowledge/domains/logging-forensics-detection.md",
    content: `---
id: domains/logging-forensics-detection
title: Logging, Detecção e Forense — Hayabusa, YARA-X, MVT e Cadeia de Custódia
tier: curated
category: domains
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "MITRE ATT&CK — Detection & Analytics"
  - "Yamato Security Hayabusa documentation"
  - "VirusTotal YARA-X documentation (BSD-3-Clause)"
  - "OWASP Logging Cheat Sheet"
limitations:
  - "Sem linha de base do ambiente, um alerta de YARA/Hayabusa não prova comprometimento — correlacione com telemetria e timing."
  - "Nunca modifique a evidência original; trabalhe em cópia com hash registrado."
related:
  - "domains/cloud-iam-containers"
  - "methodologies/evidence-validation"
  - "tools/mcp-tool-catalog"
  - "domains/binary-reverse-engineering"
---

# Logging, Detecção e Forense

#forensics #detection #hayabusa #yara #mvt #logging #domains

## 1. Invariante de auditabilidade (lado azul)
Todo evento de **autenticação, autorização, alteração de privilégio, exportação de dado e mudança de configuração** deve gerar um registro imutável, com identidade, origem, alvo e resultado — e esse registro deve estar **fora do alcance de quem o gerou**.

## 2. Falhas de logging que viram finding (lado vermelho/auditoria)
- Ação crítica sem log (troca de e-mail, desativação de MFA, criação de chave de API).
- Log sem identidade ou com IP confiado cegamente de \`X-Forwarded-For\`.
- Dados sensíveis (senha, token, PAN) escritos em log → vazamento secundário.
- Log gravado em local gravável pelo usuário afetado → adulteração/ocultação de rastro.
- **Log injection**: entrada do usuário com \`
\`/CRLF inserida em log textual (falsificação de linha, envenenamento de SIEM).
- Ausência de rate limiting em endpoint de login **sem** alerta correspondente.

## 3. Ferramentas no CyberLab OS
| Ferramenta | Uso |
|---|---|
| \`external.yarax-scan\` (\`yr scan\`/\`yara -r\`) | Varre arquivos/diretórios do workspace com regras YARA (triagem de artefato suspeito) |
| \`hayabusa-yarax\` slot (Hayabusa) | Análise de eventos Windows (\`EVTX\`), timeline ATT&CK, detecções |
| \`mvt-android\` / \`mvt-ios\` | Indicadores de comprometimento em dispositivo móvel |
| \`wireshark\`/\`tshark\` (\`external.tshark-pcap-summary\`) | PCAP: protocolos, conversas, extração de objetos |
| \`capa\` ([[binary-reverse-engineering]]) | Capacidades de binário suspeito |

## 4. Cadeia de custódia
1. Calcule SHA-256 **antes** de qualquer análise (\`cyberlab_evidence_list\` / ingestão via \`.cyberlab/inbox/\`).
2. Trabalhe em cópia; registre ferramenta + versão + data.
3. Guarde saída bruta como evidência (\`normalizeRawOutputDraft\`), não só a conclusão.
4. Separe **indicador** de **conclusão**: "regra X casou no arquivo Y" é fato; "houve comprometimento" é inferência.

## 5. Detecção como critério de qualidade do relatório
Em [[reproducible-writeup-standard]], inclua sempre: quais logs o alvo deveria ter gerado, o que ficou registrado, e qual detecção cobriria o abuso.
`,
  },
  {
    relativePath: "CyberLab-Knowledge/tools/ai-assisted-pentest-workflows.md",
    content: `---
id: tools/ai-assisted-pentest-workflows
title: Fluxos com Ferramentas de IA (PentAGI, Shannon, Strix, PentestGPT-CAI, HexStrike, Copilot) — Uso Orientado por Hipótese
tier: curated
category: tools
version: "1.0.0"
last_reviewed: "2026-11-03"
status: validated
sources:
  - "CyberLab OS v6.x — Arsenal Slot Catalog (slots autônomos de IA)"
  - "OWASP Top 10 for LLM Applications & GenAI Security"
limitations:
  - "Agente autônomo NÃO substitui validação humana: toda saída é hipótese até ser reproduzida com evidência SHA-256."
  - "Nunca aponte ferramenta autônoma contra alvo fora de escopo; configure scope.json antes de iniciar."
related:
  - "methodologies/hypothesis-driven-testing"
  - "methodologies/evidence-validation"
  - "tools/mcp-tool-catalog"
  - "vulnerabilities/idor-bola-bfla"
---

# Fluxos com Ferramentas de IA — Uso Orientado por Hipótese

#ai #pentagi #shannon #strix #cai #hexstrike #copilot #tools

## 1. Regra de ouro
Ferramenta de IA é **geradora de hipóteses e de automação de experimento**, nunca fonte de verdade. Toda afirmação que sair dela precisa passar por [[evidence-validation]] antes de virar finding.

## 2. Catálogo e uso recomendado
| Slot | Papel no método (Fases A–I) |
|---|---|
| \`pentagi\` | Orquestração autônoma multi-agente com proxy TLS embutido — use para **recon amplo** (Fase B/C) sob escopo estrito |
| \`shannon\` | Automação de fluxo de teste Web — bom para **repetição disciplinada** de um experimento já desenhado |
| \`strix\` | Varredura/validação assistida por IA — use como **segunda opinião**, compare com seu próprio teste |
| \`pentestgpt-cai\` / \`pentest-copilot\` | Raciocínio assistido: gere **hipóteses alternativas** e listas de variáveis a testar |
| \`hexstrike-ai\` | Automação ofensiva — somente em laboratório isolado ou programa autorizado |

## 3. Protocolo obrigatório
1. **Antes**: defina escopo (\`investigation_memory_update\`) e confirme \`.cyberlab/scope.json\`.
2. **Durante**: peça à ferramenta **uma hipótese por vez**, com a variável a modificar e o critério de parada.
3. **Depois**: **reproduza manualmente** com \`burp_suite_send_http1_request\` ou \`arsenal_run_tool\` e capture evidência própria.
4. **Nunca** reporte texto gerado por IA sem reprodução: LLM alucina CVE, path e parâmetro com frequência.

## 4. Falhas características a checar
- **CVE alucinado**: verifique em [[cve-applicability-methodology]] os 4 critérios antes de citar.
- **Falso positivo de scanner**: confirme exploração real, não presença de banner.
- **Escopo excedido**: agente autônomo pode sair do escopo — revise targets em \`cyberlab_evidence_list\`.
- **Vazamento de dado sensível**: saída de agente pode conter credencial; use redação (\`redactSensitiveContent\`) antes de arquivar.

## 5. Registro
Guarde o prompt, a versão da ferramenta e o output bruto como evidência de **processo** — isso torna o relatório reproduzível ([[reproducible-writeup-standard]]).
`,
  },
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

## Mapa da Biblioteca (34 documentos curados)
- **Fundamentos (8)**: [[http]], [[authentication]], [[authorization]], [[sessions]], [[networking]], [[jwt-oauth-oidc]], [[csrf-cors-samesite]], [[tls-crypto]]
- **Metodologias (3)**: [[hypothesis-driven-testing]], [[evidence-validation]], [[root-cause-analysis]]
- **Vulnerabilidades (9)**: [[idor-bola-bfla]], [[context-aware-injection]], [[http-url-json-differentials]], [[state-race-invariants]], [[ssrf]], [[deserialization-xxe-upload]], [[graphql-websocket]], [[cache-poisoning-deception]], [[race-conditions-toctou]], além de [[mass-assignment-rate-limit]]
- **Pesquisa Primária (3)**: [[cve-applicability-methodology]], [[patch-diff-methodology]], [[reproducible-writeup-standard]]
- **Domínios (4)**: [[mobile-android-ios]], [[binary-reverse-engineering]], [[cloud-iam-containers]], [[logging-forensics-detection]]
- **Ferramentas & Catálogo MCP (5)**: [[mcp-tool-catalog]], [[burp]], [[nuclei]], [[semgrep]], [[ai-assisted-pentest-workflows]]

## Atualização v6.3 (lacunas apontadas na Fase A)
Os 14 documentos abaixo foram adicionados para fechar domínios que limitavam a formulação de hipóteses testáveis:
JWT/OAuth (\`alg:none\`, \`kid\`, \`jku\`, claim confusion), CSRF/CORS/SameSite, TLS & cripto aplicada, SSRF dedicado,
desserialização/XXE/upload, GraphQL & WebSocket, cache poisoning/deception, race conditions com protocolo de
experimento concorrente, mass assignment/BOPLA/rate limiting, mobile (JADX/Frida/MVT), engenharia reversa
(Ghidra/Rizin/CAPA/GEF), cloud/IAM/contêineres (Trivy), logging/forense (Hayabusa/YARA-X/MVT) e fluxos com
ferramentas de IA orientados por hipótese.
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
