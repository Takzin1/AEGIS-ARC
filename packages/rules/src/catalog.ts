import { RuleCatalog, type RuleMeta } from "@whiteknight/core";

/**
 * MVP で扱うルールの一覧（機械向けの定義）。
 * 人向けの文章は ./ja/ にあり、全ルールに日本語テンプレートがあることをテストで保証する。
 * チェッカー（@whiteknight/scanner, M2 以降）はここにある ID だけを使う。
 */
export const RULES: readonly RuleMeta[] = [
  // ── リポジトリ：秘密情報 ─────────────────────────
  { id: "secret.aws-access-key", category: "secret", targetKind: "repo", defaultSeverity: "critical" },
  { id: "secret.github-token", category: "secret", targetKind: "repo", defaultSeverity: "critical" },
  { id: "secret.slack-token", category: "secret", targetKind: "repo", defaultSeverity: "critical" },
  { id: "secret.stripe-secret-key", category: "secret", targetKind: "repo", defaultSeverity: "critical" },
  { id: "secret.private-key", category: "secret", targetKind: "repo", defaultSeverity: "critical" },
  { id: "secret.google-api-key", category: "secret", targetKind: "repo", defaultSeverity: "high" },
  { id: "secret.db-connection-password", category: "secret", targetKind: "repo", defaultSeverity: "high" },
  { id: "secret.generic-high-entropy", category: "secret", targetKind: "repo", defaultSeverity: "medium" },

  // ── リポジトリ：依存パッケージ ───────────────────
  { id: "dep.vulnerable-package", category: "dependency", targetKind: "repo", defaultSeverity: "high" },

  // ── リポジトリ：危険なファイル ───────────────────
  { id: "file.dotenv-committed", category: "file", targetKind: "repo", defaultSeverity: "high" },
  { id: "file.sensitive-file-committed", category: "file", targetKind: "repo", defaultSeverity: "high" },

  // ── リポジトリ：危険な設定 ───────────────────────
  { id: "config.gitignore-missing-dotenv", category: "config", targetKind: "repo", defaultSeverity: "low" },
  { id: "config.terraform-s3-public", category: "config", targetKind: "repo", defaultSeverity: "high" },
  { id: "config.firebase-rules-open", category: "config", targetKind: "repo", defaultSeverity: "critical" },
  { id: "config.gha-pull-request-target-checkout", category: "config", targetKind: "repo", defaultSeverity: "high" },
  { id: "config.gha-write-all-permissions", category: "config", targetKind: "repo", defaultSeverity: "medium" },
  { id: "config.docker-compose-default-password", category: "config", targetKind: "repo", defaultSeverity: "medium" },

  // ── Web：通信・ヘッダ・Cookie ────────────────────
  { id: "web.https-redirect-missing", category: "web-header", targetKind: "domain", defaultSeverity: "medium" },
  { id: "web.hsts-missing", category: "web-header", targetKind: "domain", defaultSeverity: "medium" },
  { id: "web.csp-missing", category: "web-header", targetKind: "domain", defaultSeverity: "medium" },
  { id: "web.csp-unsafe", category: "web-header", targetKind: "domain", defaultSeverity: "low" },
  { id: "web.clickjacking-protection-missing", category: "web-header", targetKind: "domain", defaultSeverity: "medium" },
  { id: "web.x-content-type-options-missing", category: "web-header", targetKind: "domain", defaultSeverity: "low" },
  { id: "web.referrer-policy-missing", category: "web-header", targetKind: "domain", defaultSeverity: "low" },
  { id: "web.permissions-policy-missing", category: "web-header", targetKind: "domain", defaultSeverity: "info" },
  { id: "web.version-disclosure", category: "web-header", targetKind: "domain", defaultSeverity: "low" },
  { id: "web.cookie-insecure-flags", category: "web-header", targetKind: "domain", defaultSeverity: "medium" },
  { id: "web.security-txt-missing", category: "web-header", targetKind: "domain", defaultSeverity: "info" },

  // ── Web：証明書・TLS ─────────────────────────────
  { id: "tls.certificate-expired", category: "tls", targetKind: "domain", defaultSeverity: "high" },
  { id: "tls.certificate-expiring-soon", category: "tls", targetKind: "domain", defaultSeverity: "medium" },
  { id: "tls.hostname-mismatch", category: "tls", targetKind: "domain", defaultSeverity: "high" },
  { id: "tls.legacy-protocol", category: "tls", targetKind: "domain", defaultSeverity: "medium" },

  // ── Web：公開されてはいけないファイル ────────────
  { id: "exposure.git-directory", category: "exposure", targetKind: "domain", defaultSeverity: "critical" },
  { id: "exposure.dotenv", category: "exposure", targetKind: "domain", defaultSeverity: "critical" },
  { id: "exposure.backup-file", category: "exposure", targetKind: "domain", defaultSeverity: "high" },
  { id: "exposure.debug-endpoint", category: "exposure", targetKind: "domain", defaultSeverity: "high" },
  { id: "exposure.directory-listing", category: "exposure", targetKind: "domain", defaultSeverity: "medium" },
];

export const catalog = new RuleCatalog(RULES);
