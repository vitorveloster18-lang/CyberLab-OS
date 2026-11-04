# Evidência — lab-owasp-api-bola (suíte E1-E7)

- **Gerado em**: 2026-11-04T12:59:04.868Z
- **Alvo**: http://127.0.0.1:35021
- **Ferramenta**: CyberLab OS linux/x64 — bun 1.4.4
- **Requisições arquivadas**: 19
- **Selo do lote (SHA-256 do manifest.json)**: `c159b2ab5680deca87805a29ca8d7988c51ba0a29824a6ec8f2903580763e75e`

## Vereditos

| Hipótese | Veredito | Critério |
| --- | --- | --- |
| H1 | 🔴 VULNERÁVEL | E1-02 retornou 200 com o corpo de bob@corp.lab e bolaFlag (esperado 403). E1-01 e E1-03 confirmam que o endpoint funciona e que a variável é o token. |
| H2 | 🔴 VULNERÁVEL | E3-03 retornou 200 com flag LAB{JWT_ALG_NONE_ACCEPTED} (esperado 401). E3-01/E3-02 provam que o endpoint recusa ausência de token e token sem role=admin. |
| H3 | 🔴 VULNERÁVEL | E4-02 retornou 500 ecoando SQLITE_ERROR e a estrutura da consulta (esperado erro genérico). E4-01 confirma 200 com q benigno. |
| H4 | 🔴 VULNERÁVEL | E5-01: ausentes → content-security-policy, strict-transport-security, x-frame-options, x-content-type-options. |
| H1@remediado | ✅ REMEDIADO | E6-01-bola → HTTP 403, critério "403" atendido. |
| H2@remediado | ✅ REMEDIADO | E6-02-alg-none → HTTP 401, critério "401/403" atendido. |
| H3@remediado | ✅ REMEDIADO | E6-03-sql-error → HTTP 200, critério "200 sem SQLITE_ERROR" atendido. |
| H4@remediado | ✅ REMEDIADO | E6-04-headers → HTTP 200, critério "os 4 headers" atendido. |

## Arquivos

| Arquivo | Bytes | SHA-256 |
| --- | --- | --- |
| `E1-01-baseline-own-account.txt` | 702 | `16257efbdd35a80bcc2e452a1160a2a8e6086f9a4a623936a6f9cd40066916dd` |
| `E1-02-poc-cross-account.txt` | 755 | `255b601df38636a2ad18662650768e20e9ac094e5efae51432fa082567eab426` |
| `E1-03-control-owner-reads-own.txt` | 729 | `40af37f081d14d00ef2612003358e62e868e3ce059ecd117d15b0b65d984d1b6` |
| `E2-01-anon-own-account.txt` | 609 | `96ebf8dfb4b0a2b848a87501092f9380b87087c067f680f12e0d614bc1e1e795` |
| `E2-02-anon-other-account.txt` | 654 | `2f7a5c3b59f9574718ae6eaeccd36070d4bfb6f7d4e1c5cb0d1136bfefdd0043` |
| `E3-01-no-token.txt` | 548 | `ad0748d1b13109f546399835f3420b07e005afbbe9718ebce74eb66f4735ed36` |
| `E3-02-opaque-token.txt` | 636 | `42b124b9d741485c04b523cdf3d052880e1898a81efe916a414c1d993dd37efe` |
| `E3-03-poc-alg-none.txt` | 824 | `a87cb8e2ee36296a922701f278fa3a350f5ca6d7d62eebd7a6e201db559d6791` |
| `E4-01-benign-query.txt` | 593 | `985e2182aef8a5def1114c1b096f3dda43fbfdb4195a8140923d870c02f5f6ea` |
| `E4-02-poc-single-quote.txt` | 648 | `1ef017ad901ad0d93fc102757d26aebee2cb3db0f63d31b35549694b8082f58e` |
| `E5-01-header-baseline.txt` | 713 | `1b1ef3c42c6a7e85058e5b80918d67e2a87e9ae3e50cb466fc6705538ad600de` |
| `E6-01-bola.txt` | 861 | `42e1a2414b38b4fe887020bb7642414155c82649838a6f7d93a042455093690a` |
| `E6-02-alg-none.txt` | 977 | `2abfe27d4fe4e700cf9bcb76c31c52da5b9c6a3e0ebc1ce1b96a48abe7e024b5` |
| `E6-03-sql-error.txt` | 840 | `daeb1896231d07f3543776fac7e1040452b05fc9eb4251da185e5ee36a2e9c6e` |
| `E6-04-headers.txt` | 877 | `f354328e92563d33a09df77d9a00ff5f16ab83e6994e065f5987702794010676` |
| `E7-01-bola.txt` | 741 | `a84e6890f352642eef9c42ff777bbd06b04f50fe143053e0fa1e47463d256d17` |
| `E7-02-alg-none.txt` | 814 | `7dc28feefb79e3a620c2c1eb988cf12f95720d8c9f5a424918e8bf3699c1bb89` |
| `E7-03-sql-error.txt` | 654 | `1602a8344f74639a2c693a297eb6a5eeb299b8d8f0f1c96c9a8fd9993847245f` |
| `E7-04-headers.txt` | 696 | `1af7c31f3d401d6f4cc202ae07162768626e81fe508d28824b401bc2ce2cb8da` |

> O `manifest.json` é o índice do lote; `SEAL.txt` guarda o SHA-256 dele. Alterar qualquer `.txt` quebra o par `sha256` correspondente em `manifest.json`.
