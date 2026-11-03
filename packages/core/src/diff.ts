import { meetsThreshold, type Severity } from "./severity";
import type { Finding } from "./types";

/**
 * 問題（issue）の状態。
 * - open: 未対応
 * - fixed: 前回の診断で見つからなくなった
 * - accepted_risk: 理由を書いたうえで「このままにする」と判断した
 * - false_positive: 誤検知と判断した
 */
export type IssueState = "open" | "fixed" | "accepted_risk" | "false_positive";

export interface KnownIssue {
  fingerprint: string;
  state: IssueState;
}

export interface ScanDiff {
  /** 初めて見つかった問題 */
  added: Finding[];
  /** 一度直ったのに、また見つかった問題（通知対象） */
  reopened: Finding[];
  /** 前回も今回も未対応のまま残っている問題 */
  persisting: Finding[];
  /** リスク受容・誤検知と判断済みの問題（通知しない） */
  suppressed: Finding[];
  /** 前回は open だったが今回見つからなかった問題 */
  resolved: KnownIssue[];
}

export function diffScan(known: readonly KnownIssue[], current: readonly Finding[]): ScanDiff {
  const knownByFp = new Map(known.map((k) => [k.fingerprint, k]));
  const currentFps = new Set(current.map((f) => f.fingerprint));
  const diff: ScanDiff = { added: [], reopened: [], persisting: [], suppressed: [], resolved: [] };

  for (const f of current) {
    const k = knownByFp.get(f.fingerprint);
    if (!k) diff.added.push(f);
    else if (k.state === "fixed") diff.reopened.push(f);
    else if (k.state === "open") diff.persisting.push(f);
    else diff.suppressed.push(f);
  }
  for (const k of known) {
    if (k.state === "open" && !currentFps.has(k.fingerprint)) diff.resolved.push(k);
  }
  return diff;
}

/** 通知すべき指摘：新規または再発で、しきい値以上の危険度のもの。毎回同じ問題を通知しない。 */
export function notifiableFindings(diff: ScanDiff, threshold: Severity): Finding[] {
  return [...diff.added, ...diff.reopened].filter((f) => meetsThreshold(f.severity, threshold));
}
