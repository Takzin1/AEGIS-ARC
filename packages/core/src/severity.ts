/**
 * 危険度。並び順は「危ない順」。
 * critical = 今すぐ対応 / high = 今週中に / medium = 計画的に / low = 余裕があれば / info = 参考
 */
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export type Severity = (typeof SEVERITIES)[number];

const RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}

/** a の方が危険なら負の値。Array.prototype.sort にそのまま渡せる。 */
export function compareSeverity(a: Severity, b: Severity): number {
  return RANK[a] - RANK[b];
}

/** severity が threshold と同じかそれより危険なら true。通知のしきい値判定に使う。 */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return RANK[severity] <= RANK[threshold];
}

/**
 * CVSS v3 基本スコアから危険度を決める。
 * known_exploited（CISA KEV 掲載など、実際に悪用が確認済み）なら常に critical。
 */
export function severityFromCvss(score: number | undefined, knownExploited = false): Severity {
  if (knownExploited) return "critical";
  if (score === undefined || Number.isNaN(score)) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}
