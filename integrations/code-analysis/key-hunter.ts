import crypto from "node:crypto"
import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { Schema } from "effect"
import {
  EngagementRuntime,
  isPathInsideRoot,
  normalizeRawOutputDraft,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const KEY_HUNTER_INPUT_SCHEMA_ID = "cyberlab.key-hunter.input.v1"
export const KEY_HUNTER_OUTPUT_SCHEMA_ID = "cyberlab.key-hunter.output.v1"

export const KeyHunterInputSchema = Schema.Struct({
  subpath: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  targetUrl: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(2048))),
  rawText: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512 * 1024))),
  githubRepoOrOrg: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(256))),
  githubQuery: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  providerFilter: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  skipPlaceholders: Schema.optionalKey(Schema.Boolean),
  carveCryptoMaterial: Schema.optionalKey(Schema.Boolean),
  verifyActive: Schema.optionalKey(Schema.Boolean),
  maxFiles: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(1000)),
  ),
  maxRemoteScripts: Schema.optionalKey(
    Schema.Int.check(Schema.isGreaterThanOrEqualTo(0), Schema.isLessThanOrEqualTo(30)),
  ),
})

export type KeyHunterInput = typeof KeyHunterInputSchema.Type

export const KeyHunterCapability: CapabilityDefinition = {
  id: "code-analysis.key-hunter",
  version: "1.0.0",
  title: "Key Hunter — Multi-Surface API Key, Token & Cryptographic Material Hunter",
  description:
    "Hunts exposed API keys, cloud tokens, database URIs, JWTs, PEM/JWK private keys, and high-entropy cryptographic secrets across 55+ providers (AI/LLM, Cloud, Payment, VCS, SaaS, DB, Crypto) in workspace files/binaries/APKs, in-scope web pages & JS bundles, pasted buffers, and authorized GitHub repos, featuring smart anti-placeholder filtering, KeyHacks verification recipes, and opt-in read-only liveness checks.",
  inputSchemaId: KEY_HUNTER_INPUT_SCHEMA_ID,
  outputSchemaId: KEY_HUNTER_OUTPUT_SCHEMA_ID,
  risk: "low",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: [],
  executorId: "key-hunter-executor",
  skillIds: ["code-review", "web-assessment", "reverse-engineering", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

export type KeyCategory =
  | "ai_llm"
  | "cloud_infra"
  | "developer_vcs"
  | "payment_commerce"
  | "communication_saas"
  | "database_observability"
  | "crypto_material"

export interface KeyPatternDefinition {
  id: string
  provider: string
  category: KeyCategory
  description: string
  confidence: "high" | "medium" | "low"
  severity: "critical" | "high" | "medium"
  regex: RegExp
  valueGroup?: number
  minEntropy?: number
  verificationRecipe: string
  remediation: string
  supportsLiveVerify?: boolean
}

export interface KeyHunterMatch {
  patternId: string
  provider: string
  category: KeyCategory
  description: string
  confidence: "high" | "medium" | "low"
  severity: "critical" | "high" | "medium"
  sourceKind: "workspace_file" | "binary_strings" | "web_html" | "web_js_bundle" | "raw_buffer" | "github_code"
  location: string
  line: number
  maskedSecret: string
  fingerprintSha256: string
  shannonEntropy: number
  secretLength: number
  verificationStatus: "not_checked" | "active_confirmed" | "inactive_or_revoked" | "check_inconclusive"
  verificationNote?: string
  verificationRecipe: string
  remediation: string
}

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  ".cyberlab",
  "dist",
  "build",
  ".venv",
  "target",
  ".next",
  "coverage",
])

const BINARY_EXTENSIONS = new Set([
  ".apk",
  ".dex",
  ".so",
  ".dll",
  ".exe",
  ".elf",
  ".bin",
  ".dmp",
  ".dylib",
  ".jar",
  ".wasm",
])

const SKIP_BINARY_MEDIA_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".svg",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".mp3",
  ".mp4",
  ".webm",
  ".zip",
  ".gz",
  ".tar",
  ".7z",
  ".pdf",
])

export const KEY_HUNTER_PATTERNS: readonly KeyPatternDefinition[] = [
  // ── AI / LLM PROVIDERS ────────────────────────────────────────────────────
  {
    id: "anthropic_api_key",
    provider: "Anthropic Claude",
    category: "ai_llm",
    description: "Anthropic Claude API Key (sk-ant-api03-*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(sk-ant-api03-[A-Za-z0-9_-]{40,110})\b/g,
    verificationRecipe:
      'curl -sS https://api.anthropic.com/v1/models -H "x-api-key: $REDACTED_KEY" -H "anthropic-version: 2023-06-01"',
    remediation: "Revoke the key immediately in Anthropic Console -> API Keys and rotate environment secrets.",
    supportsLiveVerify: true,
  },
  {
    id: "openai_project_key",
    provider: "OpenAI",
    category: "ai_llm",
    description: "OpenAI Project / Service Account API Key (sk-proj-* / sk-svcacct-*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(sk-(?:proj|svcacct)-[A-Za-z0-9_-]{32,180})\b/g,
    verificationRecipe: 'curl -sS https://api.openai.com/v1/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke the key in OpenAI Platform -> API Keys and enforce per-project scoped permissions.",
    supportsLiveVerify: true,
  },
  {
    id: "openai_legacy_t3blbkfj",
    provider: "OpenAI",
    category: "ai_llm",
    description: "OpenAI API Key containing canonical T3BlbkFJ segment",
    confidence: "high",
    severity: "critical",
    regex: /\b(sk-[A-Za-z0-9]{16,32}T3BlbkFJ[A-Za-z0-9]{16,32})\b/g,
    verificationRecipe: 'curl -sS https://api.openai.com/v1/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke legacy user key in OpenAI Platform and migrate to project-scoped keys.",
    supportsLiveVerify: true,
  },
  {
    id: "google_ai_gcp_api_key",
    provider: "Google AI / Gemini / GCP",
    category: "ai_llm",
    description: "Google AI Studio (Gemini) / Maps / Firebase API Key (AIzaSy*)",
    confidence: "high",
    severity: "high",
    regex: /\b(AIzaSy[A-Za-z0-9_-]{33})\b/g,
    verificationRecipe:
      'curl -sS "https://generativelanguage.googleapis.com/v1beta/models?key=$REDACTED_KEY"',
    remediation: "Restrict API key by HTTP referrer/IP and target API in Google Cloud Console -> Credentials, or rotate.",
    supportsLiveVerify: true,
  },
  {
    id: "xai_grok_key",
    provider: "xAI (Grok)",
    category: "ai_llm",
    description: "xAI Grok API Key (xai-*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(xai-[A-Za-z0-9_-]{40,120})\b/g,
    verificationRecipe: 'curl -sS https://api.x.ai/v1/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Delete exposed xAI key in console.x.ai and issue a replacement stored in a secret manager.",
    supportsLiveVerify: true,
  },
  {
    id: "groq_api_key",
    provider: "Groq",
    category: "ai_llm",
    description: "Groq Cloud LPU API Key (gsk_*)",
    confidence: "high",
    severity: "high",
    regex: /\b(gsk_[A-Za-z0-9]{48,64})\b/g,
    verificationRecipe: 'curl -sS https://api.groq.com/openai/v1/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke key in GroqCloud Console -> API Keys.",
    supportsLiveVerify: true,
  },
  {
    id: "perplexity_api_key",
    provider: "Perplexity AI",
    category: "ai_llm",
    description: "Perplexity Sonar API Key (pplx-*)",
    confidence: "high",
    severity: "high",
    regex: /\b(pplx-[A-Za-z0-9]{40,64})\b/g,
    verificationRecipe: 'curl -sS https://api.perplexity.ai/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke key in Perplexity API Settings and rotate.",
  },
  {
    id: "huggingface_token",
    provider: "HuggingFace",
    category: "ai_llm",
    description: "HuggingFace Hub User Access Token (hf_*)",
    confidence: "high",
    severity: "high",
    regex: /\b(hf_[A-Za-z0-9]{30,45})\b/g,
    verificationRecipe: 'curl -sS https://huggingface.co/api/whoami-v2 -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Invalidate token in huggingface.co/settings/tokens and switch to fine-grained read tokens.",
    supportsLiveVerify: true,
  },
  {
    id: "openrouter_api_key",
    provider: "OpenRouter",
    category: "ai_llm",
    description: "OpenRouter API Key (sk-or-v1-*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(sk-or-v1-[0-9a-f]{64})\b/g,
    verificationRecipe: 'curl -sS https://openrouter.ai/api/v1/auth/key -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke key at openrouter.ai/keys and configure credit limits on replacement keys.",
    supportsLiveVerify: true,
  },
  {
    id: "replicate_api_token",
    provider: "Replicate",
    category: "ai_llm",
    description: "Replicate API Token (r8_*)",
    confidence: "high",
    severity: "high",
    regex: /\b(r8_[A-Za-z0-9]{36,44})\b/g,
    verificationRecipe: 'curl -sS https://api.replicate.com/v1/account -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Delete token at replicate.com/account/api-tokens.",
    supportsLiveVerify: true,
  },
  {
    id: "fireworks_ai_key",
    provider: "Fireworks AI",
    category: "ai_llm",
    description: "Fireworks AI Inference Key (fw_*)",
    confidence: "high",
    severity: "high",
    regex: /\b(fw_[A-Za-z0-9]{24,48})\b/g,
    verificationRecipe: 'curl -sS https://api.fireworks.ai/inference/v1/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke key in Fireworks AI account settings.",
  },
  {
    id: "deepseek_contextual_key",
    provider: "DeepSeek",
    category: "ai_llm",
    description: "DeepSeek API Key (sk-hex assigned to DEEPSEEK_API_KEY)",
    confidence: "high",
    severity: "high",
    regex: /deepseek[_-]?api[_-]?key\s*[:=]\s*["']?(sk-[0-9a-fA-F]{32,48})["']?/gi,
    valueGroup: 1,
    verificationRecipe: 'curl -sS https://api.deepseek.com/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Delete leaked key in platform.deepseek.com/api_keys.",
    supportsLiveVerify: true,
  },
  {
    id: "mistral_contextual_key",
    provider: "Mistral AI",
    category: "ai_llm",
    description: "Mistral AI API Key assigned in configuration",
    confidence: "medium",
    severity: "high",
    regex: /mistral[_-]?api[_-]?key\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?/gi,
    valueGroup: 1,
    verificationRecipe: 'curl -sS https://api.mistral.ai/v1/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke key in console.mistral.ai/api-keys.",
  },
  {
    id: "cohere_contextual_key",
    provider: "Cohere",
    category: "ai_llm",
    description: "Cohere API Key assigned in configuration",
    confidence: "medium",
    severity: "high",
    regex: /cohere[_-]?api[_-]?key\s*[:=]\s*["']?([A-Za-z0-9]{40})["']?/gi,
    valueGroup: 1,
    verificationRecipe: 'curl -sS https://api.cohere.com/v1/models -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke key in dashboard.cohere.com/api-keys.",
  },

  // ── CLOUD & INFRASTRUCTURE ────────────────────────────────────────────────
  {
    id: "aws_access_key_id",
    provider: "AWS IAM",
    category: "cloud_infra",
    description: "AWS Access Key ID (AKIA / ASIA / ABIA / ACCA)",
    confidence: "high",
    severity: "critical",
    regex: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    verificationRecipe:
      "AWS_ACCESS_KEY_ID=$REDACTED_KEY AWS_SECRET_ACCESS_KEY=$REDACTED_SECRET aws sts get-caller-identity",
    remediation: "Deactivate & delete the access key in AWS IAM immediately, audit CloudTrail, and migrate to IAM Roles/OIDC.",
  },
  {
    id: "aws_secret_access_key",
    provider: "AWS IAM",
    category: "cloud_infra",
    description: "AWS Secret Access Key assignment",
    confidence: "high",
    severity: "critical",
    regex: /aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    valueGroup: 1,
    minEntropy: 4.1,
    verificationRecipe:
      "AWS_ACCESS_KEY_ID=$ACCESS_KEY AWS_SECRET_ACCESS_KEY=$REDACTED_KEY aws sts get-caller-identity",
    remediation: "Rotate IAM credentials in AWS Console and inspect CloudTrail for unauthorized API calls.",
  },
  {
    id: "gcp_service_account_json",
    provider: "Google Cloud IAM",
    category: "cloud_infra",
    description: "GCP Service Account Private Key JSON block",
    confidence: "high",
    severity: "critical",
    regex: /"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key_id"\s*:\s*"([0-9a-f]{32,44})"/g,
    valueGroup: 1,
    verificationRecipe: "gcloud auth activate-service-account --key-file=service-account.json (in isolated sandbox only)",
    remediation: "Delete the service account key ID in GCP IAM -> Service Accounts -> Keys and use Workload Identity Federation.",
  },
  {
    id: "azure_storage_account_key",
    provider: "Microsoft Azure",
    category: "cloud_infra",
    description: "Azure Storage Connection String AccountKey",
    confidence: "high",
    severity: "critical",
    regex: /AccountKey=([A-Za-z0-9+/]{86}==)/g,
    valueGroup: 1,
    verificationRecipe: "az storage container list --connection-string \"$REDACTED_CONN_STR\"",
    remediation: "Regenerate key1/key2 in Azure Storage Account -> Access keys and migrate to Entra ID RBAC.",
  },
  {
    id: "azure_sas_token",
    provider: "Microsoft Azure",
    category: "cloud_infra",
    description: "Azure Shared Access Signature (SAS) URL Token",
    confidence: "high",
    severity: "high",
    regex: /\b(sv=20\d{2}-\d{2}-\d{2}&[A-Za-z0-9%&=_.-]{25,220}sig=[A-Za-z0-9%+/=]{32,100})/g,
    verificationRecipe: "Inspect 'se=' expiry and 'sp=' permissions fields in SAS query string without mutating blobs.",
    remediation: "Revoke the stored access policy or rotate the underlying storage account signing key.",
  },
  {
    id: "digitalocean_token",
    provider: "DigitalOcean",
    category: "cloud_infra",
    description: "DigitalOcean Personal Access / OAuth Token (dop_v1_* / doo_v1_*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(do[po]_v1_[0-9a-f]{64})\b/g,
    verificationRecipe: 'curl -sS https://api.digitalocean.com/v2/account -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke token in DigitalOcean Control Panel -> API -> Tokens.",
    supportsLiveVerify: true,
  },
  {
    id: "supabase_access_token",
    provider: "Supabase",
    category: "cloud_infra",
    description: "Supabase Management Access Token / Secret Key (sbp_* / sb_secret_*)",
    confidence: "high",
    severity: "critical",
    regex: /\b((?:sbp_[0-9a-f]{40}|sb_secret_[A-Za-z0-9_-]{30,80}))\b/g,
    verificationRecipe: 'curl -sS https://api.supabase.com/v1/projects -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke token at supabase.com/dashboard/account/tokens and rotate service_role secrets.",
    supportsLiveVerify: true,
  },
  {
    id: "hashicorp_vault_token",
    provider: "HashiCorp Vault",
    category: "cloud_infra",
    description: "HashiCorp Vault Service Token (hvs.*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(hvs\.[A-Za-z0-9_-]{24,120})\b/g,
    verificationRecipe: 'curl -sS "$VAULT_ADDR/v1/auth/token/lookup-self" -H "X-Vault-Token: $REDACTED_KEY"',
    remediation: "Revoke token immediately via 'vault token revoke' and audit Vault access logs.",
  },
  {
    id: "cloudflare_api_token",
    provider: "Cloudflare",
    category: "cloud_infra",
    description: "Cloudflare API Token assignment",
    confidence: "medium",
    severity: "critical",
    regex: /cloudflare[_-]?(?:api[_-]?)?token\s*[:=]\s*["']?([A-Za-z0-9_-]{40})["']?/gi,
    valueGroup: 1,
    verificationRecipe:
      'curl -sS https://api.cloudflare.com/client/v4/user/tokens/verify -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Roll or delete the API token in Cloudflare Dashboard -> My Profile -> API Tokens.",
    supportsLiveVerify: true,
  },

  // ── DEVELOPER & VCS ───────────────────────────────────────────────────────
  {
    id: "github_pat_classic",
    provider: "GitHub",
    category: "developer_vcs",
    description: "GitHub Personal/OAuth/App Access Token (ghp_ / gho_ / ghu_ / ghs_ / ghr_)",
    confidence: "high",
    severity: "critical",
    regex: /\b(gh[pousr]_[A-Za-z0-9]{36,64})\b/g,
    verificationRecipe: 'curl -sS https://api.github.com/user -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke token in GitHub Settings -> Developer settings -> Personal access tokens and inspect security log.",
    supportsLiveVerify: true,
  },
  {
    id: "github_pat_fine_grained",
    provider: "GitHub",
    category: "developer_vcs",
    description: "GitHub Fine-Grained Personal Access Token (github_pat_*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(github_pat_[A-Za-z0-9_]{70,95})\b/g,
    verificationRecipe: 'curl -sS https://api.github.com/user -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke fine-grained PAT in GitHub Developer settings.",
    supportsLiveVerify: true,
  },
  {
    id: "gitlab_pat",
    provider: "GitLab",
    category: "developer_vcs",
    description: "GitLab Personal / Project Access Token (glpat-*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(glpat-[A-Za-z0-9_-]{20,64})\b/g,
    verificationRecipe: 'curl -sS https://gitlab.com/api/v4/user -H "PRIVATE-TOKEN: $REDACTED_KEY"',
    remediation: "Revoke PAT in GitLab User Settings -> Access Tokens.",
    supportsLiveVerify: true,
  },
  {
    id: "npm_access_token",
    provider: "npm Registry",
    category: "developer_vcs",
    description: "npm Automation / Publish Access Token (npm_*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
    verificationRecipe: 'curl -sS https://registry.npmjs.org/-/npm/v1/user -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke token immediately at npmjs.com/settings/~/tokens and audit published package versions.",
    supportsLiveVerify: true,
  },
  {
    id: "pypi_upload_token",
    provider: "PyPI",
    category: "developer_vcs",
    description: "PyPI Package Upload API Token (pypi-AgEIcHlwaS5vcmc*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,220})\b/g,
    verificationRecipe: "Do not test upload; verify token ID and revoke directly in pypi.org/manage/account/token/.",
    remediation: "Remove token on PyPI Account Settings and enable Trusted Publishers (OIDC).",
  },
  {
    id: "dockerhub_pat",
    provider: "Docker Hub",
    category: "developer_vcs",
    description: "Docker Hub Personal Access Token (dckr_pat_*)",
    confidence: "high",
    severity: "high",
    regex: /\b(dckr_pat_[A-Za-z0-9_-]{24,48})\b/g,
    verificationRecipe: "Verify token last-used timestamp in Docker Hub -> Account Settings -> Security.",
    remediation: "Deactivate PAT in Docker Hub Security settings.",
  },
  {
    id: "postman_api_key",
    provider: "Postman",
    category: "developer_vcs",
    description: "Postman Workspace API Key (PMAK-*)",
    confidence: "high",
    severity: "high",
    regex: /\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b/gi,
    verificationRecipe: 'curl -sS https://api.getpostman.com/me -H "X-Api-Key: $REDACTED_KEY"',
    remediation: "Revoke Postman API key as workspaces often contain downstream production credentials.",
    supportsLiveVerify: true,
  },

  // ── PAYMENTS & COMMERCE ───────────────────────────────────────────────────
  {
    id: "stripe_live_secret",
    provider: "Stripe",
    category: "payment_commerce",
    description: "Stripe LIVE Secret / Restricted API Key (sk_live_* / rk_live_*)",
    confidence: "high",
    severity: "critical",
    regex: /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,108})\b/g,
    verificationRecipe: "curl -sS https://api.stripe.com/v1/balance -u $REDACTED_KEY:",
    remediation: "Roll live key immediately in Stripe Dashboard -> Developers -> API keys and audit Stripe logs.",
    supportsLiveVerify: true,
  },
  {
    id: "stripe_webhook_secret",
    provider: "Stripe",
    category: "payment_commerce",
    description: "Stripe Webhook Signing Secret (whsec_*)",
    confidence: "high",
    severity: "high",
    regex: /\b(whsec_[0-9a-zA-Z]{32,80})\b/g,
    verificationRecipe: "Offline signing secret — roll directly in Stripe Dashboard -> Developers -> Webhooks.",
    remediation: "Expire signing secret in Stripe Webhook endpoint settings to prevent forged payment events.",
  },
  {
    id: "shopify_access_token",
    provider: "Shopify",
    category: "payment_commerce",
    description: "Shopify Admin / Custom App / Shared Secret (shpat_ / shpca_ / shpss_)",
    confidence: "high",
    severity: "critical",
    regex: /\b(shp(?:at|ca|ss|pa)_[0-9a-fA-F]{32,48})\b/g,
    verificationRecipe:
      'curl -sS "https://$SHOP.myshopify.com/admin/api/2025-01/shop.json" -H "X-Shopify-Access-Token: $REDACTED_KEY"',
    remediation: "Rotate app credentials in Shopify Admin -> Settings -> Apps and sales channels.",
  },
  {
    id: "square_access_token",
    provider: "Square",
    category: "payment_commerce",
    description: "Square OAuth / Access Secret (sq0atp-* / sq0csp-*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(sq0(?:atp|csp)-[0-9A-Za-z_-]{22,50})\b/g,
    verificationRecipe: 'curl -sS https://connect.squareup.com/v2/locations -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Replace application token in Square Developer Dashboard.",
  },

  // ── COMMUNICATION & SAAS ──────────────────────────────────────────────────
  {
    id: "slack_token",
    provider: "Slack",
    category: "communication_saas",
    description: "Slack Bot / User / App-Level Token (xoxb- / xoxp- / xapp-)",
    confidence: "high",
    severity: "critical",
    regex: /\b(xox(?:b|p|a|r|s)-[0-9]{10,15}-[0-9A-Za-z-]{20,90}|xapp-[0-9]-[A-Z0-9]{10,15}-[0-9]{10,15}-[0-9a-f]{64})\b/g,
    verificationRecipe: 'curl -sS -X POST https://slack.com/api/auth.test -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke Slack token in api.slack.com/apps and enable token rotation.",
    supportsLiveVerify: true,
  },
  {
    id: "slack_webhook_url",
    provider: "Slack",
    category: "communication_saas",
    description: "Slack Incoming Webhook URL",
    confidence: "high",
    severity: "medium",
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,12}\/B[A-Z0-9]{8,12}\/[A-Za-z0-9]{20,30})/g,
    verificationRecipe: "Do not POST test messages unless authorized; revoke webhook URL in Slack App -> Incoming Webhooks.",
    remediation: "Delete and regenerate the Slack Incoming Webhook URL.",
  },
  {
    id: "discord_bot_token",
    provider: "Discord",
    category: "communication_saas",
    description: "Discord Bot / Application Token",
    confidence: "high",
    severity: "high",
    regex: /\b([MN][A-Za-z\d]{23,28}\.[\w-]{6}\.[\w-]{27,40})\b/g,
    verificationRecipe: 'curl -sS https://discord.com/api/v10/users/@me -H "Authorization: Bot $REDACTED_KEY"',
    remediation: "Reset bot token in Discord Developer Portal -> Applications -> Bot.",
    supportsLiveVerify: true,
  },
  {
    id: "discord_webhook_url",
    provider: "Discord",
    category: "communication_saas",
    description: "Discord Channel Webhook URL",
    confidence: "high",
    severity: "medium",
    regex: /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,21}\/[A-Za-z0-9_-]{60,72})/g,
    verificationRecipe: "curl -sS $REDACTED_KEY (GET returns webhook metadata without posting a message)",
    remediation: "Delete the webhook in Discord Server Settings -> Integrations -> Webhooks.",
    supportsLiveVerify: true,
  },
  {
    id: "telegram_bot_token",
    provider: "Telegram",
    category: "communication_saas",
    description: "Telegram BotFather API Token",
    confidence: "high",
    severity: "high",
    regex: /\b(\d{8,11}:AA[A-Za-z0-9_-]{33})\b/g,
    verificationRecipe: 'curl -sS "https://api.telegram.org/bot$REDACTED_KEY/getMe"',
    remediation: "Send /revoke to @BotFather on Telegram to issue a new token.",
    supportsLiveVerify: true,
  },
  {
    id: "sendgrid_api_key",
    provider: "Twilio SendGrid",
    category: "communication_saas",
    description: "SendGrid Mail/API Key (SG.*)",
    confidence: "high",
    severity: "critical",
    regex: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    verificationRecipe: 'curl -sS https://api.sendgrid.com/v3/scopes -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Delete exposed key in SendGrid Settings -> API Keys and restrict scopes.",
    supportsLiveVerify: true,
  },
  {
    id: "twilio_api_key",
    provider: "Twilio",
    category: "communication_saas",
    description: "Twilio Standard/Main API Key SID (SK + 32 hex)",
    confidence: "medium",
    severity: "high",
    regex: /\b(SK[0-9a-f]{32})\b/g,
    minEntropy: 3.4,
    verificationRecipe: "curl -sS https://api.twilio.com/2010-04-01/Accounts.json -u $REDACTED_KEY:$TWILIO_API_SECRET",
    remediation: "Delete API Key SID in Twilio Console -> Account -> API keys & tokens.",
  },
  {
    id: "mailgun_api_key",
    provider: "Mailgun",
    category: "communication_saas",
    description: "Mailgun Private API Key (key-32hex)",
    confidence: "high",
    severity: "high",
    regex: /\b(key-[0-9a-f]{32})\b/g,
    verificationRecipe: "curl -sS --user 'api:$REDACTED_KEY' https://api.mailgun.net/v3/domains",
    remediation: "Rotate private API key in Mailgun Account Security.",
  },

  // ── DATABASES & OBSERVABILITY ─────────────────────────────────────────────
  {
    id: "mongodb_connection_uri",
    provider: "MongoDB / Atlas",
    category: "database_observability",
    description: "MongoDB / Atlas Connection URI with embedded credentials",
    confidence: "high",
    severity: "critical",
    regex: /(mongodb(?:\+srv)?:\/\/[^/\s"':]+:[^@\s"']+@[A-Za-z0-9.-]+(?::\d+)?\/?[A-Za-z0-9_?=&-]*)/gi,
    verificationRecipe: "Inspect host/user offline; never mutate remote collections without explicit DB authorization.",
    remediation: "Rotate database user password in MongoDB Atlas, restrict IP Access List, and move URI to secret store.",
  },
  {
    id: "postgres_connection_uri",
    provider: "PostgreSQL",
    category: "database_observability",
    description: "PostgreSQL Connection URI with embedded password",
    confidence: "high",
    severity: "critical",
    regex: /(postgres(?:ql)?:\/\/[^/\s"':]+:[^@\s"']+@[A-Za-z0-9.-]+(?::\d+)?\/[A-Za-z0-9_?=&.-]*)/gi,
    verificationRecipe: "Inspect host/port/sslmode offline; verify network exposure via ScopeController before connecting.",
    remediation: "ALTER USER ... WITH PASSWORD in PostgreSQL, enforce TLS/pg_hba rules, and inject via Vault/env.",
  },
  {
    id: "mysql_connection_uri",
    provider: "MySQL / MariaDB",
    category: "database_observability",
    description: "MySQL Connection URI with embedded password",
    confidence: "high",
    severity: "critical",
    regex: /(mysql:\/\/[^/\s"':]+:[^@\s"']+@[A-Za-z0-9.-]+(?::\d+)?\/[A-Za-z0-9_?=&.-]*)/gi,
    verificationRecipe: "Inspect host/database offline; rotate MySQL user credentials immediately.",
    remediation: "Rotate MySQL account password and restrict host grants.",
  },
  {
    id: "redis_connection_uri",
    provider: "Redis / Upstash",
    category: "database_observability",
    description: "Redis / Rediss Connection URI with embedded password",
    confidence: "high",
    severity: "critical",
    regex: /(rediss?:\/\/[^@\s"']*:[^@\s"']+@[A-Za-z0-9.-]+:\d+)/gi,
    verificationRecipe: "Inspect TLS ('rediss://') and ACL user offline.",
    remediation: "Rotate Redis ACL password and restrict network bind/security groups.",
  },
  {
    id: "sentry_auth_token",
    provider: "Sentry",
    category: "database_observability",
    description: "Sentry Organization / User Auth Token (sntrys_* / sntryu_*)",
    confidence: "high",
    severity: "high",
    regex: /\b(sntry[su]_[A-Za-z0-9_+/=-]{48,140})\b/g,
    verificationRecipe: 'curl -sS https://sentry.io/api/0/organizations/ -H "Authorization: Bearer $REDACTED_KEY"',
    remediation: "Revoke auth token in Sentry Settings -> Auth Tokens.",
    supportsLiveVerify: true,
  },
  {
    id: "mapbox_secret_token",
    provider: "Mapbox",
    category: "database_observability",
    description: "Mapbox Secret Access Token (sk.eyJ1*)",
    confidence: "high",
    severity: "high",
    regex: /\b(sk\.eyJ1[A-Za-z0-9_-]{40,160}\.[A-Za-z0-9_-]{20,64})\b/g,
    verificationRecipe: 'curl -sS "https://api.mapbox.com/tokens/v2?access_token=$REDACTED_KEY"',
    remediation: "Delete secret token (`sk.*`) in Mapbox Account -> Access tokens; only `pk.*` belongs in frontend JS.",
  },

  // ── CRYPTOGRAPHIC MATERIAL & HIGH-ENTROPY KEYS ────────────────────────────
  {
    id: "pem_private_key",
    provider: "Cryptographic PEM Key",
    category: "crypto_material",
    description: "PEM-encoded Private Key (RSA / EC / DSA / OPENSSH / PGP / PKCS#8)",
    confidence: "high",
    severity: "critical",
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]{32,4096}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)/g,
    verificationRecipe: "openssl pkey -in key.pem -check -noout (offline local verification only)",
    remediation: "Revoke corresponding public key/certificate (CRL/authorized_keys) and generate a new keypair offline.",
  },
  {
    id: "jwk_private_key",
    provider: "Cryptographic JWK Key",
    category: "crypto_material",
    description: "JSON Web Key (JWK) containing private exponent ('d')",
    confidence: "high",
    severity: "critical",
    regex: /(\{[^{}]{0,300}"kty"\s*:\s*"(?:RSA|EC|OKP)"[^{}]{0,400}"d"\s*:\s*"[A-Za-z0-9_-]{20,}"[^{}]{0,400}\})/g,
    verificationRecipe: "Inspect JWK 'kid' and 'alg' offline; check /.well-known/jwks.json for matching active kid.",
    remediation: "Rotate signing keys on the OAuth/OIDC issuer and purge leaked JWK from source history.",
  },
  {
    id: "jwt_bearer_token",
    provider: "JSON Web Token (JWT)",
    category: "crypto_material",
    description: "Hardcoded Signed/Unsigned JSON Web Token (eyJ*)",
    confidence: "medium",
    severity: "medium",
    regex: /\b(eyJ[A-Za-z0-9_-]{10,200}\.eyJ[A-Za-z0-9_-]{15,600}\.[A-Za-z0-9_-]{0,256})\b/g,
    verificationRecipe: "Decode Base64URL header & payload offline to inspect 'iss', 'aud', 'exp', and 'alg' without network calls.",
    remediation: "Invalidate token/session or rotate signing secret if long-lived service JWT (e.g. Supabase service_role).",
  },
  {
    id: "high_entropy_crypto_secret",
    provider: "High-Entropy Secret / Key Schedule",
    category: "crypto_material",
    description: "256-bit / 512-bit High-Entropy Hex or Base64 Secret Key assignment",
    confidence: "medium",
    severity: "high",
    regex:
      /\b(?:secret[_-]?key|private[_-]?key|encryption[_-]?key|aes[_-]?key|hmac[_-]?secret|jwt[_-]?secret|master[_-]?key|api[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{32,128})["']/gi,
    valueGroup: 1,
    minEntropy: 4.15,
    verificationRecipe: "Verify key bit-length (32 hex = 128-bit, 64 hex = 256-bit) and entropy offline.",
    remediation: "Move symmetric/HMAC signing key into KMS/Vault and rotate active ciphertexts/tokens.",
  },
]

const PLACEHOLDER_SUBSTRINGS = [
  "your_api_key",
  "your-api-key",
  "your_key_here",
  "your-key-here",
  "your_actual_token",
  "insert_key",
  "replace_me",
  "changeme",
  "placeholder",
  "example",
  "sample_key",
  "dummy_key",
  "fake_key",
  "todo_replace",
  "xxxxxxxx",
  "0000000000",
  "1111111111",
  "1234567890abcdef1234567890abcdef",
  "abcdef0123456789abcdef0123456789",
  "akiaiosfodnn7example",
  "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
]

export function computeStringEntropy(value: string): number {
  if (value.length === 0) return 0
  const freq = new Map<string, number>()
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1)
  }
  let entropy = 0
  const len = value.length
  for (const count of freq.values()) {
    const p = count / len
    entropy -= p * Math.log2(p)
  }
  return Math.round(entropy * 1000) / 1000
}

export function isLikelyPlaceholderKey(rawValue: string): boolean {
  const lower = rawValue.toLowerCase()
  if (lower.startsWith("-----begin ")) {
    const body = rawValue
      .replace(/-----BEGIN [^-]+-----/g, "")
      .replace(/-----END [^-]+-----/g, "")
      .replace(/\s+/g, "")
    if (body.length < 48 || /^(?:\.\.\.|xxx+|base64|redacted)+$/i.test(body)) return true
    return false
  }
  for (const marker of PLACEHOLDER_SUBSTRINGS) {
    if (lower.includes(marker)) return true
  }
  if (/(.)\1{7,}/.test(rawValue)) return true
  const stripped = rawValue.replace(/^(sk-proj-|sk-ant-api03-|sk_live_|ghp_|github_pat_|glpat-|xoxb-|AIzaSy|AKIA)/, "")
  if (stripped.length >= 12) {
    const uniqueChars = new Set(stripped).size
    if (uniqueChars <= 4) return true
  }
  return false
}

export function maskSecretForCustody(raw: string): string {
  const clean = raw.replace(/\s+/g, " ").trim()
  if (clean.startsWith("-----BEGIN ")) {
    const typeMatch = clean.match(/^-----BEGIN ([A-Z0-9 ]+)-----/)
    const keyKind = typeMatch?.[1] ?? "PRIVATE KEY"
    return `PEM(${keyKind}, [REDACTED ${clean.length} CHARS])`
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:]+:[^@\s]+@/.test(clean)) {
    return clean.replace(/(:\/\/[^/\s:]+):([^@\s]+)@/, "$1:[REDACTED]@")
  }
  if (clean.length <= 12) {
    return `${clean.slice(0, 3)}***${clean.slice(-2)}`
  }
  const head = Math.min(10, Math.max(4, Math.floor(clean.length * 0.2)))
  const tail = Math.min(4, Math.max(3, Math.floor(clean.length * 0.1)))
  return `${clean.slice(0, head)}...${clean.slice(-tail)}`
}

function sha256Short(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex").slice(0, 16)
}

function extractPrintableStringsFromBinary(buf: Buffer, minLen = 12): string {
  const chunks: string[] = []
  let current = ""
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]!
    if ((b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09) {
      current += String.fromCharCode(b)
    } else {
      if (current.length >= minLen) chunks.push(current)
      current = ""
    }
  }
  if (current.length >= minLen) chunks.push(current)
  return chunks.join("\n")
}

function lineNumberAtIndex(text: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++
  }
  return line
}

function matchesProviderFilter(pattern: KeyPatternDefinition, filterRaw: string | undefined): boolean {
  if (!filterRaw || filterRaw.trim() === "" || filterRaw.trim().toLowerCase() === "all") return true
  const tokens = filterRaw
    .toLowerCase()
    .split(/[,;\s]+/)
    .map((t) => t.trim())
    .filter(Boolean)
  if (tokens.length === 0) return true
  const hay = `${pattern.id} ${pattern.provider} ${pattern.category}`.toLowerCase()
  return tokens.some((tok) => hay.includes(tok))
}

async function verifySecretReadOnly(
  patternId: string,
  rawSecret: string,
  signal: AbortSignal,
): Promise<{ status: KeyHunterMatch["verificationStatus"]; note: string }> {
  const timeoutCtrl = new AbortController()
  const timer = setTimeout(() => timeoutCtrl.abort(), 3500)
  const combined = AbortSignal.any([signal, timeoutCtrl.signal])

  try {
    let url = ""
    let method = "GET"
    const headers: Record<string, string> = { Accept: "application/json" }

    switch (patternId) {
      case "openai_project_key":
      case "openai_legacy_t3blbkfj":
        url = "https://api.openai.com/v1/models"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "anthropic_api_key":
        url = "https://api.anthropic.com/v1/models"
        headers["x-api-key"] = rawSecret
        headers["anthropic-version"] = "2023-06-01"
        break
      case "google_ai_gcp_api_key":
        url = `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(rawSecret)}`
        break
      case "xai_grok_key":
        url = "https://api.x.ai/v1/models"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "groq_api_key":
        url = "https://api.groq.com/openai/v1/models"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "huggingface_token":
        url = "https://huggingface.co/api/whoami-v2"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "openrouter_api_key":
        url = "https://openrouter.ai/api/v1/auth/key"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "replicate_api_token":
        url = "https://api.replicate.com/v1/account"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "deepseek_contextual_key":
        url = "https://api.deepseek.com/models"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "github_pat_classic":
      case "github_pat_fine_grained":
        url = "https://api.github.com/user"
        headers["Authorization"] = `Bearer ${rawSecret}`
        headers["User-Agent"] = "CyberLab-OS-KeyHunter/1.0"
        break
      case "gitlab_pat":
        url = "https://gitlab.com/api/v4/user"
        headers["PRIVATE-TOKEN"] = rawSecret
        break
      case "npm_access_token":
        url = "https://registry.npmjs.org/-/npm/v1/user"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "postman_api_key":
        url = "https://api.getpostman.com/me"
        headers["X-Api-Key"] = rawSecret
        break
      case "digitalocean_token":
        url = "https://api.digitalocean.com/v2/account"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "supabase_access_token":
        url = "https://api.supabase.com/v1/projects"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "cloudflare_api_token":
        url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "stripe_live_secret":
        url = "https://api.stripe.com/v1/balance"
        headers["Authorization"] = `Basic ${Buffer.from(`${rawSecret}:`, "utf8").toString("base64")}`
        break
      case "slack_token":
        url = "https://slack.com/api/auth.test"
        method = "POST"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "discord_bot_token":
        url = "https://discord.com/api/v10/users/@me"
        headers["Authorization"] = `Bot ${rawSecret}`
        break
      case "discord_webhook_url":
        url = rawSecret
        break
      case "telegram_bot_token":
        url = `https://api.telegram.org/bot${rawSecret}/getMe`
        break
      case "sendgrid_api_key":
        url = "https://api.sendgrid.com/v3/scopes"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      case "sentry_auth_token":
        url = "https://sentry.io/api/0/organizations/"
        headers["Authorization"] = `Bearer ${rawSecret}`
        break
      default:
        return { status: "not_checked", note: "Offline / manual KeyHacks verification only" }
    }

    const res = await fetch(url, { method, headers, signal: combined })
    if (patternId === "slack_token" && res.ok) {
      const data = (await res.json()) as { ok?: boolean; error?: string }
      return data.ok
        ? { status: "active_confirmed", note: "HTTP 200 (slack auth.test ok=true)" }
        : { status: "inactive_or_revoked", note: `Slack auth.test ok=false (${data.error ?? "invalid_auth"})` }
    }
    if (res.status === 200) {
      return { status: "active_confirmed", note: `Read-only check returned HTTP 200` }
    }
    if (res.status === 401 || res.status === 403 || res.status === 404) {
      return { status: "inactive_or_revoked", note: `Provider rejected key (HTTP ${res.status})` }
    }
    return { status: "check_inconclusive", note: `Provider returned HTTP ${res.status}` }
  } catch (err) {
    return {
      status: "check_inconclusive",
      note: err instanceof Error ? err.message : "Network verification unreachable",
    }
  } finally {
    clearTimeout(timer)
  }
}

export function scanTextWithKeyHunter(params: {
  text: string
  location: string
  sourceKind: KeyHunterMatch["sourceKind"]
  providerFilter?: string
  skipPlaceholders: boolean
  carveCryptoMaterial: boolean
  seenFingerprints: Set<string>
  rawSecretsByFingerprint: Map<string, string>
}): { matches: KeyHunterMatch[]; suppressedPlaceholders: number } {
  const matches: KeyHunterMatch[] = []
  let suppressedPlaceholders = 0

  for (const pattern of KEY_HUNTER_PATTERNS) {
    if (!params.carveCryptoMaterial && pattern.category === "crypto_material") continue
    if (!matchesProviderFilter(pattern, params.providerFilter)) continue

    const re = new RegExp(pattern.regex.source, pattern.regex.flags)
    let m: RegExpExecArray | null
    while ((m = re.exec(params.text)) !== null) {
      const groupIdx = pattern.valueGroup ?? 1
      const rawCandidate = (m[groupIdx] ?? m[0] ?? "").trim()
      if (!rawCandidate) continue

      if (params.skipPlaceholders && isLikelyPlaceholderKey(rawCandidate)) {
        suppressedPlaceholders++
        continue
      }

      const entropy = computeStringEntropy(rawCandidate)
      if (pattern.minEntropy !== undefined && entropy < pattern.minEntropy) {
        continue
      }

      // Extra JWT validation: ensure valid JSON header with alg
      let description = pattern.description
      let severity = pattern.severity
      if (pattern.id === "jwt_bearer_token") {
        const parts = rawCandidate.split(".")
        try {
          const headerJson = JSON.parse(Buffer.from(parts[0] ?? "", "base64url").toString("utf8")) as {
            alg?: string
            typ?: string
          }
          const payloadJson = JSON.parse(Buffer.from(parts[1] ?? "", "base64url").toString("utf8")) as {
            role?: string
            iss?: string
          }
          if (!headerJson || typeof headerJson !== "object" || !headerJson.alg) continue
          const alg = String(headerJson.alg)
          const role = payloadJson?.role ? `, role=${String(payloadJson.role)}` : ""
          description = `JSON Web Token (alg=${alg}${role})`
          if (alg.toLowerCase() === "none" || payloadJson?.role === "service_role") {
            severity = "critical"
          }
        } catch {
          continue
        }
      }

      const fp = sha256Short(`${pattern.id}:${rawCandidate}`)
      const dedupKey = `${fp}@${params.location}`
      if (params.seenFingerprints.has(dedupKey)) continue
      params.seenFingerprints.add(dedupKey)
      params.rawSecretsByFingerprint.set(fp, rawCandidate)

      matches.push({
        patternId: pattern.id,
        provider: pattern.provider,
        category: pattern.category,
        description,
        confidence: pattern.confidence,
        severity,
        sourceKind: params.sourceKind,
        location: params.location,
        line: lineNumberAtIndex(params.text, m.index),
        maskedSecret: maskSecretForCustody(rawCandidate),
        fingerprintSha256: fp,
        shannonEntropy: entropy,
        secretLength: rawCandidate.length,
        verificationStatus: "not_checked",
        verificationRecipe: pattern.verificationRecipe,
        remediation: pattern.remediation,
      })
    }
  }

  return { matches, suppressedPlaceholders }
}

function collectWorkspaceCandidateFiles(rootDir: string, startPath: string, maxFiles: number): string[] {
  const results: string[] = []
  const resolvedStart = path.resolve(rootDir, startPath)
  if (!existsSync(resolvedStart)) return results

  const visit = (current: string) => {
    if (results.length >= maxFiles) return
    let stat
    try {
      stat = lstatSync(current)
    } catch {
      return
    }
    if (stat.isSymbolicLink()) return
    if (stat.isFile()) {
      const ext = path.extname(current).toLowerCase()
      if (!SKIP_BINARY_MEDIA_EXTENSIONS.has(ext) && stat.size <= 4 * 1024 * 1024) {
        results.push(current)
      }
      return
    }
    if (!stat.isDirectory()) return
    let entries: string[] = []
    try {
      entries = readdirSync(current)
    } catch {
      return
    }
    for (const entry of entries) {
      if (results.length >= maxFiles) break
      if (SKIP_DIRS.has(entry)) continue
      visit(path.join(current, entry))
    }
  }

  visit(resolvedStart)
  return results
}

function extractLinkedScriptUrls(html: string, pageUrl: string, maxScripts: number): string[] {
  const urls: string[] = []
  const seen = new Set<string>()
  const baseOrigin = new URL(pageUrl).origin
  const scriptRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi
  let m: RegExpExecArray | null
  while ((m = scriptRe.exec(html)) !== null && urls.length < maxScripts) {
    const rawSrc = m[1]?.trim()
    if (!rawSrc || rawSrc.startsWith("data:") || rawSrc.startsWith("javascript:")) continue
    try {
      const resolved = new URL(rawSrc, pageUrl)
      if (resolved.origin !== baseOrigin) continue
      const href = resolved.toString()
      if (!seen.has(href)) {
        seen.add(href)
        urls.push(href)
      }
    } catch {
      // Ignore malformed script src
    }
  }
  return urls
}

export class KeyHunterExecutor implements CyberLabExecutor {
  readonly id = "key-hunter-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string }> {
    return { available: true, version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(KeyHunterInputSchema)(input)
      const hasSource = Boolean(
        decoded.subpath?.trim() ||
          decoded.targetUrl?.trim() ||
          decoded.rawText?.trim() ||
          decoded.githubRepoOrOrg?.trim(),
      )
      if (!hasSource) {
        return {
          valid: false,
          errors: [
            "Provide at least one hunting target: subpath (workspace), targetUrl (web/JS), rawText (buffer), or githubRepoOrOrg.",
          ],
        }
      }
      if (decoded.targetUrl?.trim()) {
        const parsed = new URL(decoded.targetUrl.trim())
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          return { valid: false, errors: ["targetUrl must use http:// or https://"] }
        }
      }
      if (decoded.githubRepoOrOrg?.trim() && !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?$/.test(decoded.githubRepoOrOrg.trim())) {
        return {
          valid: false,
          errors: ["githubRepoOrOrg must be an explicit 'owner/repo' or 'org-name' identifier"],
        }
      }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, context: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(KeyHunterInputSchema)(execInput.input)
    const skipPlaceholders = params.skipPlaceholders ?? true
    const carveCryptoMaterial = params.carveCryptoMaterial ?? true
    const verifyActive = params.verifyActive ?? false
    const maxFiles = params.maxFiles ?? 250
    const maxRemoteScripts = params.maxRemoteScripts ?? 10

    const seenFingerprints = new Set<string>()
    const rawSecretsByFingerprint = new Map<string, string>()
    const allMatches: KeyHunterMatch[] = []
    let suppressedPlaceholders = 0
    let scannedWorkspaceFiles = 0
    let scannedWebAssets = 0
    let scannedGithubItems = 0
    const notes: string[] = []

    // 1. Local Workspace Files & Binary Strings
    if (params.subpath?.trim()) {
      const sub = params.subpath.trim()
      if (!isPathInsideRoot(sub, context.workspaceRoot)) {
        return {
          status: "failed",
          evidenceIds: [],
          summary: `subpath "${sub}" escapes workspaceRoot`,
          exitCode: 2,
        }
      }
      const files = collectWorkspaceCandidateFiles(context.workspaceRoot, sub, maxFiles)
      for (const fullFile of files) {
        if (context.signal.aborted) break
        let buf: Buffer
        try {
          buf = readFileSync(fullFile)
        } catch {
          continue
        }
        scannedWorkspaceFiles++
        const rel = path.relative(context.workspaceRoot, fullFile).replace(/\\/g, "/") || path.basename(fullFile)
        const ext = path.extname(fullFile).toLowerCase()
        const looksBinary = BINARY_EXTENSIONS.has(ext) || buf.subarray(0, 512).includes(0)
        const text = looksBinary ? extractPrintableStringsFromBinary(buf) : buf.toString("utf8")
        const scanned = scanTextWithKeyHunter({
          text,
          location: rel,
          sourceKind: looksBinary ? "binary_strings" : "workspace_file",
          ...(params.providerFilter !== undefined ? { providerFilter: params.providerFilter } : {}),
          skipPlaceholders,
          carveCryptoMaterial,
          seenFingerprints,
          rawSecretsByFingerprint,
        })
        allMatches.push(...scanned.matches)
        suppressedPlaceholders += scanned.suppressedPlaceholders
      }
    }

    // 2. Raw Pasted Text / Buffer / HTTP Dump
    if (params.rawText && params.rawText.trim().length > 0) {
      const scanned = scanTextWithKeyHunter({
        text: params.rawText,
        location: "inline-buffer",
        sourceKind: "raw_buffer",
        ...(params.providerFilter !== undefined ? { providerFilter: params.providerFilter } : {}),
        skipPlaceholders,
        carveCryptoMaterial,
        seenFingerprints,
        rawSecretsByFingerprint,
      })
      allMatches.push(...scanned.matches)
      suppressedPlaceholders += scanned.suppressedPlaceholders
    }

    // 3. In-Scope Webpage & Linked JS Bundles / Sourcemaps
    if (params.targetUrl?.trim()) {
      const pageUrl = params.targetUrl.trim()
      try {
        await EngagementRuntime.acquireRateSlot(context.projectId)
        const pageHeaders = EngagementRuntime.applyHeaders(context.projectId, {
          "User-Agent": "CyberLab-OS-KeyHunter/4.0",
        })
        const t0 = Date.now()
        const res = await fetch(pageUrl, {
          headers: pageHeaders,
          signal: AbortSignal.any([context.signal, AbortSignal.timeout(12000)]),
        })
        const html = await res.text()
        EngagementRuntime.recordTraffic({
          projectId: context.projectId,
          sourceTool: "key-hunter",
          method: "GET",
          url: pageUrl,
          host: new URL(pageUrl).host,
          statusCode: res.status,
          elapsedMs: Date.now() - t0,
          responseBytes: Buffer.byteLength(html, "utf8"),
        })
        scannedWebAssets++
        const htmlScan = scanTextWithKeyHunter({
          text: html,
          location: pageUrl,
          sourceKind: "web_html",
          ...(params.providerFilter !== undefined ? { providerFilter: params.providerFilter } : {}),
          skipPlaceholders,
          carveCryptoMaterial,
          seenFingerprints,
          rawSecretsByFingerprint,
        })
        allMatches.push(...htmlScan.matches)
        suppressedPlaceholders += htmlScan.suppressedPlaceholders

        const scriptUrls = extractLinkedScriptUrls(html, pageUrl, maxRemoteScripts)
        for (const scriptUrl of scriptUrls) {
          if (context.signal.aborted) break
          try {
            await EngagementRuntime.acquireRateSlot(context.projectId)
            const scriptHeaders = EngagementRuntime.applyHeaders(context.projectId, {
              "User-Agent": "CyberLab-OS-KeyHunter/4.0",
            })
            const ts0 = Date.now()
            const sRes = await fetch(scriptUrl, {
              headers: scriptHeaders,
              signal: AbortSignal.any([context.signal, AbortSignal.timeout(10000)]),
            })
            if (!sRes.ok) continue
            const jsBody = (await sRes.text()).slice(0, 2 * 1024 * 1024)
            EngagementRuntime.recordTraffic({
              projectId: context.projectId,
              sourceTool: "key-hunter",
              method: "GET",
              url: scriptUrl,
              host: new URL(scriptUrl).host,
              statusCode: sRes.status,
              elapsedMs: Date.now() - ts0,
              responseBytes: Buffer.byteLength(jsBody, "utf8"),
            })
            scannedWebAssets++
            const jsScan = scanTextWithKeyHunter({
              text: jsBody,
              location: scriptUrl,
              sourceKind: "web_js_bundle",
              ...(params.providerFilter !== undefined ? { providerFilter: params.providerFilter } : {}),
              skipPlaceholders,
              carveCryptoMaterial,
              seenFingerprints,
              rawSecretsByFingerprint,
            })
            allMatches.push(...jsScan.matches)
            suppressedPlaceholders += jsScan.suppressedPlaceholders
          } catch {
            // Skip unreachable individual bundle
          }
        }
      } catch (err) {
        notes.push(`Web fetch error for ${pageUrl}: ${err instanceof Error ? err.message : String(err)}`)
      }
    }

    // 4. Authorized Scoped GitHub Code Search (fadidevv/keyhunter mode)
    if (params.githubRepoOrOrg?.trim()) {
      const targetScope = params.githubRepoOrOrg.trim()
      const scopeQualifier = targetScope.includes("/") ? `repo:${targetScope}` : `org:${targetScope}`
      const queryPart = params.githubQuery?.trim() || '(T3BlbkFJ OR sk-ant-api03 OR sk_live_ OR AKIA OR ghp_)'
      const ghToken = process.env.KEYHUNTER_GITHUB_TOKEN || process.env.GITHUB_TOKEN
      if (!ghToken) {
        notes.push(
          "GitHub Code Search skipped: set KEYHUNTER_GITHUB_TOKEN or GITHUB_TOKEN with read access to query GitHub Code Search API.",
        )
      } else {
        try {
          const fullQ = `${queryPart} ${scopeQualifier}`
          const searchUrl = `https://api.github.com/search/code?q=${encodeURIComponent(fullQ)}&per_page=15`
          const ghRes = await fetch(searchUrl, {
            headers: {
              Accept: "application/vnd.github.text-match+json",
              Authorization: `Bearer ${ghToken}`,
              "User-Agent": "CyberLab-OS-KeyHunter/1.0",
            },
            signal: AbortSignal.any([context.signal, AbortSignal.timeout(8000)]),
          })
          if (!ghRes.ok) {
            notes.push(`GitHub Code Search returned HTTP ${ghRes.status} for "${fullQ}"`)
          } else {
            const payload = (await ghRes.json()) as {
              items?: Array<{
                path?: string
                html_url?: string
                repository?: { full_name?: string }
                text_matches?: Array<{ fragment?: string }>
              }>
            }
            for (const item of payload.items ?? []) {
              scannedGithubItems++
              const repoName = item.repository?.full_name ?? targetScope
              const loc = `${repoName}:${item.path ?? "unknown"}`
              const fragments = (item.text_matches ?? []).map((tm) => tm.fragment ?? "").join("\n")
              if (!fragments) continue
              const ghScan = scanTextWithKeyHunter({
                text: fragments,
                location: loc,
                sourceKind: "github_code",
                ...(params.providerFilter !== undefined ? { providerFilter: params.providerFilter } : {}),
                skipPlaceholders,
                carveCryptoMaterial,
                seenFingerprints,
                rawSecretsByFingerprint,
              })
              allMatches.push(...ghScan.matches)
              suppressedPlaceholders += ghScan.suppressedPlaceholders
            }
          }
        } catch (err) {
          notes.push(`GitHub search error: ${err instanceof Error ? err.message : String(err)}`)
        }
      }
    }

    // 5. Optional Safe Read-Only Liveness Verification (capped at first 15 high-confidence candidates)
    let verifiedActiveCount = 0
    if (verifyActive) {
      let checksRun = 0
      for (const match of allMatches) {
        if (context.signal.aborted || checksRun >= 15) break
        const patternDef = KEY_HUNTER_PATTERNS.find((p) => p.id === match.patternId)
        if (!patternDef?.supportsLiveVerify) continue
        const rawSecret = rawSecretsByFingerprint.get(match.fingerprintSha256)
        if (!rawSecret) continue
        checksRun++
        const result = await verifySecretReadOnly(match.patternId, rawSecret, context.signal)
        match.verificationStatus = result.status
        match.verificationNote = result.note
        if (result.status === "active_confirmed") {
          verifiedActiveCount++
        }
      }
    }

    rawSecretsByFingerprint.clear()

    const bySeverity = {
      critical: allMatches.filter((m) => m.severity === "critical").length,
      high: allMatches.filter((m) => m.severity === "high").length,
      medium: allMatches.filter((m) => m.severity === "medium").length,
    }

    const byCategory = allMatches.reduce<Record<string, number>>((acc, m) => {
      acc[m.category] = (acc[m.category] ?? 0) + 1
      return acc
    }, {})

    const reportPayload = {
      tool: "CyberLab Key Hunter",
      version: this.version,
      supportedPatternCount: KEY_HUNTER_PATTERNS.length,
      stats: {
        scannedWorkspaceFiles,
        scannedWebAssets,
        scannedGithubItems,
        totalFindings: allMatches.length,
        suppressedPlaceholders,
        verifiedActiveCount,
        bySeverity,
        byCategory,
      },
      notes,
      matches: allMatches,
    }

    const evidenceId = await context.emitEvidence(
      normalizeRawOutputDraft({
        kind: "json",
        title: `Key Hunter Report (${allMatches.length} secrets detected, ${suppressedPlaceholders} placeholders filtered)`,
        rawText: JSON.stringify(reportPayload, null, 2),
        mediaType: "application/json",
        toolId: KeyHunterCapability.id,
        toolVersion: this.version,
        executorId: this.id,
        executionId: context.executionId,
        maxOutputBytes: 768 * 1024,
        labels: ["key-hunter", "secrets", "api-keys", "crypto"],
      }),
    )

    const summaryParts = [
      `Key Hunter scanned ${scannedWorkspaceFiles} workspace file(s)${scannedWebAssets ? `, ${scannedWebAssets} web/JS asset(s)` : ""}${scannedGithubItems ? `, ${scannedGithubItems} GitHub match(es)` : ""}`,
      `found ${allMatches.length} secret(s) (critical=${bySeverity.critical}, high=${bySeverity.high}, medium=${bySeverity.medium})`,
      `filtered ${suppressedPlaceholders} false-positive placeholder(s)`,
    ]
    if (verifyActive) {
      summaryParts.push(`confirmed ${verifiedActiveCount} active key(s)`)
    }

    return {
      status: "succeeded",
      evidenceIds: [evidenceId],
      summary: `${summaryParts.join("; ")}.`,
      exitCode: 0,
    }
  }
}
