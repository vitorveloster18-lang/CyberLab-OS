/**
 * CyberLab OS — Perfis de Alvo Externo Autorizado (v6.5).
 *
 * Um alerta externo só é legítimo quando a AUTORIZAÇÃO vem junto. Este módulo guarda,
 * por alvo: base da autorização, hosts permitidos, o que é proibido, limites de taxa,
 * como apontar as ferramentas e como arquivar evidência. Um `writeTargetScope` gera
 * `SCOPE.md` + `RULES-OF-ENGAGEMENT.md` prontos para imprimir e consultar.
 *
 * Regra do projeto: perfil SEM base de autorização explícita não entra na lista.
 */

import { mkdirSync, writeFileSync } from "node:fs"
import path from "node:path"

export interface TargetHypothesisBridge {
  /** Hipótese calibrada no laboratório local (`lab-owasp-api-bola`). */
  localHypothesisId: string
  localHypothesis: string
  /** Onde a mesma classe aparece no alvo externo. */
  targetTopic: string
  /** Como reproduzir a mesma disciplina de baseline + PoC no alvo. */
  method: string
}

export interface AuthorizedTargetProfile {
  id: string
  name: string
  owner: string
  /** Onde está escrito que podemos testar — sem isto não há engajamento. */
  authorizationBasis: string
  /** Padrões de host permitidos. `*` casa com um rótulo inteiro. */
  allowedHosts: string[]
  allowedHostExamples: string[]
  forbidden: string[]
  rateLimits: string[]
  tooling: string[]
  evidenceRules: string[]
  hypothesisBridge: TargetHypothesisBridge[]
  difficultyLadder: string[]
  /** Limites honestos: o que este alvo NÃO treina. */
  honestLimits: string[]
  /** Referências para conferir a autorização antes de cada sessão. */
  verifyAt: string[]
}

export const AUTHORIZED_TARGET_PROFILES: AuthorizedTargetProfile[] = [
  {
    id: "portswigger-wsa",
    name: "PortSwigger Web Security Academy",
    owner: "PortSwigger Ltd. (autor dos laboratórios e do Burp Suite)",
    authorizationBasis:
      "A Academy declara publicamente que autoriza ataques SOMENTE contra as instâncias de laboratório que ela cria para você. A autorização nasce com o hostname do seu laboratório e morre com ele — não cobre a plataforma, nem terceiros.",
    allowedHosts: ["*.web-security-academy.net", "*.h1-web-security-academy.net"],
    allowedHostExamples: [
      "https://<LAB-ID>.web-security-academy.net — instância do seu laboratório",
      "https://exploit-<ID>.web-security-academy.net — servidor de exploit do laboratório (quando houver)",
    ],
    forbidden: [
      "Qualquer host fora do hostname do SEU laboratório — a autorização é por instância, não por domínio.",
      "Infraestrutura da plataforma: DNS, TLS, CDN, login da PortSwigger, API de progresso, painel da conta.",
      "Varrer/enumerar `web-security-academy.net` como um todo (é a plataforma, não o seu alvo).",
      "Negação de serviço, flood e força bruta volumosa — inclusive em laboratórios de race condition, que se resolvem com técnica de pacote único.",
      "Reutilizar a técnica em site vivo 'só para ver': fora do laboratório é teste não autorizado.",
      "Publicar a solução oficial como se fosse descoberta própria.",
    ],
    rateLimits: [
      "Respeite os limites da plataforma; laboratórios são compartilhados por trás de uma infraestrutura comum.",
      "Em laboratório de race condition use single-packet attack, não rajada de requisições.",
      "Se receber 429 ou timeout, pare — repetir mais rápido é contraproducente e antiético.",
    ],
    tooling: [
      "Burp Suite Community pelo slot do arsenal (`cyberlab-burp-suite`) — proxy em 127.0.0.1:8080.",
      "Navegador dedicado apontando para o proxy, aberto SOMENTE no hostname do seu laboratório.",
      "Burp MCP bridge do CyberLab (`127.0.0.1:9876`) para enviar requisições HTTP/1 do agente.",
      "No Windows+WSL2, resolva o caminho do binário por `cyberlab/external/wsl-runtime.ts` — o IP do gateway do WSL2 muda a cada reinício, nunca hardcode.",
      "Laboratórios que dependem de interação fora de banda exigem Burp Collaborator (Burp Pro) e o firewall de saída do laboratório bloqueia servidores externos arbitrários: sem licença, marque FORA DE ESCOPO.",
    ],
    evidenceRules: [
      "Arquive URL exata do laboratório + requisição e resposta completas do PoC + data/hora + critério de veredito.",
      "O hostname do laboratório EXPIRA: URL sem corpo de resposta não é evidência.",
      "Um experimento por vez, uma variável por vez, sempre com par baseline + PoC.",
      "Resultado negativo (controle funcionando) é resultado — registre como 'seguro', não como fracasso.",
    ],
    hypothesisBridge: [
      {
        localHypothesisId: "H1",
        localHypothesis: "BOLA/IDOR — o endpoint não checa titularidade entre contas distintas",
        targetTopic: "Access control vulnerabilities (Apprentice → Expert)",
        method:
          "Baseline: recurso próprio com a sua sessão. PoC: o mesmo recurso de OUTRO usuário, trocando somente o identificador. Variável única = o ID.",
      },
      {
        localHypothesisId: "H2",
        localHypothesis: "JWT alg:none aceito como admin",
        targetTopic: "JWT attacks",
        method:
          "Baseline: endpoint admin sem token e com token sem role. PoC: token forjado variando SOMENTE o header `alg` (e, depois, a assinatura).",
      },
      {
        localHypothesisId: "H3",
        localHypothesis: "Erro SQL ecoa estrutura da consulta",
        targetTopic: "SQL injection",
        method:
          "Baseline: parâmetro benigno (200 com resultados). PoC: aspa simples. Critério: 500 com mensagem do SGBD e nome de coluna = vulnerável.",
      },
      {
        localHypothesisId: "H4",
        localHypothesis: "Headers de segurança ausentes (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)",
        targetTopic: "Transversal — melhor observado no laboratório local do que na Academy",
        method:
          "Inspeção de estado: uma resposta autenticada com headers completos basta. Na Academy isso varia por laboratório e não é o objetivo didático.",
      },
    ],
    difficultyLadder: [
      "Apprentice — um passo, vulnerabilidade óbvia. Serve para calibrar ferramenta e evidência.",
      "Practitioner — exige encadear dois conceitos. É aqui que o método do laboratório local começa a valer.",
      "Expert — pesquisa/cadeia longa. Só depois de vários Practitioner, com evidência arquivada em cada um.",
    ],
    honestLimits: [
      "A Academy ensina a CLASSE da vulnerabilidade num alvo construído para ser vulnerável.",
      "Ela NÃO treina descoberta em aplicação grande, ruído de WAF, nem escrita de relatório remunerado.",
      "Também NÃO treina escopo difuso de bug bounty real — para isso o próximo passo é um programa com escopo escrito, e o perfil de engajamento muda.",
      "Sem Burp Pro, uma parte dos laboratórios (fora de banda) fica inacessível por desenho, não por falta de habilidade.",
    ],
    verifyAt: [
      "https://portswigger.net/web-security — lições e laboratórios (confira a declaração de autorização antes de cada sessão)",
      "Conhecimento curado do CyberLab: CyberLab-Knowledge/targets/portswigger-web-security-academy.md",
    ],
  },
]

export function listTargetProfiles(): AuthorizedTargetProfile[] {
  return [...AUTHORIZED_TARGET_PROFILES]
}

export function getTargetProfile(id: string): AuthorizedTargetProfile | undefined {
  return AUTHORIZED_TARGET_PROFILES.find((p) => p.id === id)
}

export function renderScopeMd(p: AuthorizedTargetProfile): string {
  const bullets = (items: string[]) => items.map((i) => `- ${i}`).join("\n")
  return [
    `# Escopo autorizado — ${p.name}`,
    "",
    `**Perfil**: \`${p.id}\`  `,
    `**Operador do alvo**: ${p.owner}  `,
    `**Gerado por**: CyberLab OS — \`bun run cyberlab lab scope ${p.id}\``,
    "",
    "## Base da autorização",
    "",
    p.authorizationBasis,
    "",
    "## Hosts permitidos",
    "",
    "```",
    ...p.allowedHosts,
    "```",
    "",
    bullets(p.allowedHostExamples),
    "",
    "## Proibido neste engajamento",
    "",
    bullets(p.forbidden),
    "",
    "## Limites de taxa e convivência",
    "",
    bullets(p.rateLimits),
    "",
    "## Ferramental",
    "",
    bullets(p.tooling),
    "",
    "## Regras de evidência",
    "",
    bullets(p.evidenceRules),
    "",
    "## Ponte com o método calibrado no laboratório local",
    "",
    "| Hip. local | Classe | Tópico no alvo | Método |",
    "| --- | --- | --- | --- |",
    ...p.hypothesisBridge.map(
      (b) => `| ${b.localHypothesisId} | ${b.localHypothesis} | ${b.targetTopic} | ${b.method} |`,
    ),
    "",
    "## Escada de dificuldade",
    "",
    bullets(p.difficultyLadder),
    "",
    "## Onde conferir a autorização",
    "",
    bullets(p.verifyAt),
    "",
    "> Antes de cada sessão: abra estes links e confirme que a declaração de autorização",
    "> continua de pé. Autorização presumida não existe.",
    "",
  ].join("\n")
}

export function renderRulesOfEngagementMd(p: AuthorizedTargetProfile): string {
  return [
    `# Regras de engajamento — ${p.name} (\`${p.id}\`)`,
    "",
    "Imprima e mantenha à vista. Cada linha é uma condição para continuar testando.",
    "",
    "## 1. Autorização",
    "",
    p.authorizationBasis,
    "",
    "## 2. O que está dentro",
    "",
    ...p.allowedHosts.map((h) => `- \`${h}\``),
    "",
    "## 3. Parada imediata (qualquer item = encerrar a sessão)",
    "",
    ...p.forbidden.map((f) => `- [ ] NÃO ${f.charAt(0).toLowerCase()}${f.slice(1)}`),
    "",
    "## 4. Limites de taxa",
    "",
    ...p.rateLimits.map((r) => `- ${r}`),
    "",
    "## 5. Evidência mínima por achado",
    "",
    ...p.evidenceRules.map((r) => `- ${r}`),
    "",
    "## 6. Limites honestos deste alvo",
    "",
    ...p.honestLimits.map((l) => `- ${l}`),
    "",
    "---",
    "",
    "Registro da sessão",
    "",
    "| Campo | Valor |",
    "| --- | --- |",
    "| Data |  |",
    "| Operador |  |",
    "| Hostname do laboratório |  |",
    "| Tópico / dificuldade |  |",
    "| Hipótese testada |  |",
    "| Critério de veredito |  |",
    "| Resultado |  |",
    "",
  ].join("\n")
}

export interface TargetScopeResult {
  profileId: string
  outDir: string
  scopePath: string
  rulesPath: string
}

/** Grava `SCOPE.md` e `RULES-OF-ENGAGEMENT.md` para o perfil informado. */
export function writeTargetScope(profileId: string, outDir: string): TargetScopeResult | null {
  const profile = getTargetProfile(profileId)
  if (!profile) return null
  mkdirSync(outDir, { recursive: true })
  const scopePath = path.join(outDir, "SCOPE.md")
  const rulesPath = path.join(outDir, "RULES-OF-ENGAGEMENT.md")
  writeFileSync(scopePath, renderScopeMd(profile), "utf8")
  writeFileSync(rulesPath, renderRulesOfEngagementMd(profile), "utf8")
  return { profileId: profile.id, outDir, scopePath, rulesPath }
}
