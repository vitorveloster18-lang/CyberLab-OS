# Política de Licenças e Incorporação — CyberLab OS

## 1. Objetivo

Garantir que o CyberLab OS mantenha rastreabilidade completa de propriedade intelectual, avisos de terceiros, commits fixados e compatibilidade entre o núcleo MIT (derivado de `anomalyco/opencode` v2.1.4) e quaisquer ferramentas de segurança integradas.

---

## 2. Distinção Arquitetural Obrigatória

### A. Código Incorporado (`vendor/` ou embutido no pacote)
Exige obrigatoriamente:
1. Estado `approved_embed` no manifesto `vendor/manifests/<id>.json`;
2. `commit` SHA exato e URL de origem registrados;
3. Identificador SPDX compatível com distribuição junto ao núcleo MIT (ex.: `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Apache-2.0`);
4. Revisão concluída de dependências (`dependenciesReviewed: true`);
5. Registro integral de copyright e texto da licença em `vendor/THIRD_PARTY_NOTICES.md` (`noticesRecorded: true`);
6. Patches locais, quando existirem, isolados e documentados em `vendor/patches/`.

### B. Execução de Processo Local Separado (`approved_internal_process`)
Para uso pessoal/laboratorial em Windows + WSL2 + Docker, ferramentas com licenças copyleft fortes ou cláusulas específicas (como GPL, AGPL, NPSL ou licenças com condições adicionais) **não devem ter seu código-fonte copiado nem linkado estaticamente ao CyberLab OS**:
- O CyberLab OS fornece apenas um **adaptador próprio original** em `integrations/` e uma **skill metodológica original** em `skills/`;
- O usuário instala o binário oficial da ferramenta separadamente no ambiente WSL2 ou em container Docker isolado;
- Nenhum binário de terceiros não aprovado é embutido em pacotes de distribuição do CyberLab OS.

### C. Integração Somente por Plugin / Protocolo (`plugin_only`)
Aplicável a softwares proprietários (ex.: Burp Suite Community, Hopper) ou serviços AGPL/externos (ex.: Shannon, Signal):
- Nenhum código, binário ou template restrito entra no repositório;
- A comunicação ocorre exclusivamente por protocolo documentado ou inspeção de artefatos exportados pelo usuário.

---

## 3. Verificação Automatizada no Pipeline (`script/check-cyberlab-licenses.ts`)

O pipeline de verificação bloqueia builds de distribuição sempre que:
1. Um manifesto em `vendor/manifests/*.json` possuir `spdx` vazio ou `"UNKNOWN"` enquanto estiver marcado como `approved_embed` ou `approved_internal_process`;
2. Um componente com `integration.mode === "embedded"` não estiver com `reviewStatus === "approved_embed"`, `dependenciesReviewed === true` e `noticesRecorded === true`;
3. Existir código em `vendor/sources/<id>` sem manifesto correspondente aprovado;
4. Um componente estiver marcado como `blocked` ou `revalidation_required` e habilitado para execução padrão.
