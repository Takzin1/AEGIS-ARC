import type { DetailValue, Location, Severity } from "@whiteknight/core";

/** 色だけに頼らないよう、記号＋文字で表す */
export const SEVERITY_LABELS_JA: Record<Severity, { icon: string; label: string; short: string }> = {
  critical: { icon: "🔴", label: "今すぐ対応", short: "緊急" },
  high: { icon: "🟠", label: "今週中に対応", short: "高" },
  medium: { icon: "🟡", label: "計画的に対応", short: "中" },
  low: { icon: "🔵", label: "余裕があれば対応", short: "低" },
  info: { icon: "⚪", label: "参考情報", short: "情報" },
};

export function describeLocationJa(loc: Location): string {
  switch (loc.type) {
    case "file":
      return loc.line !== undefined ? `ファイル ${loc.path}（${loc.line}行目）` : `ファイル ${loc.path}`;
    case "url":
      return `URL ${loc.url}`;
    case "header":
      return `${loc.url} の応答ヘッダ「${loc.header}」`;
    case "cookie":
      return `${loc.url} が発行する Cookie「${loc.cookieName}」`;
    case "package":
      return `部品 ${loc.name}@${loc.version}（${loc.ecosystem}／${loc.manifestPath}）`;
    case "tls":
      return `サーバー証明書 ${loc.host}:${loc.port}`;
    case "repo-setting":
      return `リポジトリの設定「${loc.setting}」`;
  }
}

const DETAIL_LABELS_JA: Record<string, string> = {
  fixedVersion: "直ったバージョン",
  vulnIds: "脆弱性の番号",
  summary: "概要（英語）",
  cvss: "深刻度スコア（CVSS）",
  knownExploited: "実際の攻撃が確認済み",
  daysRemaining: "残り日数",
  expiresAt: "有効期限",
  observed: "現在の値",
  protocol: "受け付けている方式",
  missingFlags: "足りない印",
  matchedPattern: "該当した指定",
};

export function describeDetailJa(key: string, value: DetailValue): { label: string; value: string } {
  const label = DETAIL_LABELS_JA[key] ?? key;
  let text: string;
  if (Array.isArray(value)) text = value.join("、");
  else if (typeof value === "boolean") text = value ? "はい" : "いいえ";
  else text = String(value);
  return { label, value: text };
}
