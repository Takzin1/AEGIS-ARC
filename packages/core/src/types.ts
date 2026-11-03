import type { Severity } from "./severity";

export type TargetKind = "repo" | "domain";

export type RuleCategory =
  | "secret" // 秘密情報の混入
  | "dependency" // 脆弱な依存パッケージ
  | "file" // 危険なファイルのコミット
  | "config" // 危険な設定
  | "web-header" // Web のセキュリティヘッダ・Cookie
  | "tls" // 証明書・暗号化通信
  | "exposure"; // 公開されてはいけないファイル

/** ルールの機械的な定義。人向けの文章は @whiteknight/rules の言語別テンプレートに置く。 */
export interface RuleMeta {
  id: string;
  category: RuleCategory;
  targetKind: TargetKind;
  defaultSeverity: Severity;
}

/** 指摘の場所。行番号は変わりやすいので fingerprint には使わない。 */
export type Location =
  | { type: "file"; path: string; line?: number }
  | { type: "url"; url: string }
  | { type: "header"; url: string; header: string }
  | { type: "cookie"; url: string; cookieName: string }
  | { type: "package"; ecosystem: string; name: string; version: string; manifestPath: string }
  | { type: "tls"; host: string; port: number }
  | { type: "repo-setting"; setting: string };

export type DetailValue = string | number | boolean | string[];

/**
 * チェッカーが返す「生の」指摘。
 * secret に入れた値はエンジンが直ちにマスク・ハッシュ化し、Finding には残さない。
 */
export interface RawFinding {
  ruleId: string;
  location: Location;
  /** ルール既定の危険度を上書きしたい場合（例：CVSS に応じた依存脆弱性） */
  severity?: Severity;
  /** 検出した秘密情報の生の値。エンジン内でのみ使用し、保存・送信しない。 */
  secret?: string;
  /** 同じ場所に複数ある指摘を区別するキー（例：脆弱性ID）。fingerprint に使う。 */
  discriminator?: string;
  /** 画面表示用の補足情報。秘密情報を入れてはいけない。 */
  details?: Record<string, DetailValue>;
}

/** 正規化済みの指摘。DB 保存・画面表示・通知・（許可された場合のみ）AI 入力に使う。 */
export interface Finding {
  ruleId: string;
  category: RuleCategory;
  severity: Severity;
  location: Location;
  fingerprint: string;
  /** マスク済みの証拠（例："AKIA****…（sha256:1a2b3c4d）"） */
  evidenceMasked?: string;
  details: Record<string, DetailValue>;
}
