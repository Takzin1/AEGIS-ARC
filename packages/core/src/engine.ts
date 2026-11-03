import type { RuleCatalog } from "./catalog";
import { computeFingerprint } from "./fingerprint";
import { maskSecret, secretHash } from "./mask";
import { compareSeverity } from "./severity";
import type { Finding, RawFinding, TargetKind } from "./types";

export interface CheckContext {
  targetId: string;
  targetKind: TargetKind;
  /** 中断用。タイムアウトや利用者のキャンセルで abort される。 */
  signal: AbortSignal;
}

/** 診断の 1 単位（例：秘密情報検出、セキュリティヘッダ確認）。I は対象の入力（ファイル一覧、URL など）。 */
export interface Checker<I> {
  id: string;
  targetKind: TargetKind;
  run(input: I, ctx: CheckContext): Promise<RawFinding[]>;
}

export interface CheckerError {
  checkerId: string;
  message: string;
}

export interface EngineResult {
  findings: Finding[];
  /** 失敗したチェッカー。1 つ失敗しても他の結果は返す（「一部診断できませんでした」と表示する）。 */
  errors: CheckerError[];
}

export interface RunOptions<I> {
  targetId: string;
  targetKind: TargetKind;
  catalog: RuleCatalog;
  checkers: readonly Checker<I>[];
  input: I;
  signal?: AbortSignal;
}

export async function runCheckers<I>(opts: RunOptions<I>): Promise<EngineResult> {
  const signal = opts.signal ?? new AbortController().signal;
  const ctx: CheckContext = { targetId: opts.targetId, targetKind: opts.targetKind, signal };
  const errors: CheckerError[] = [];
  const byFingerprint = new Map<string, Finding>();

  for (const checker of opts.checkers) {
    if (checker.targetKind !== opts.targetKind) {
      errors.push({ checkerId: checker.id, message: `対象の種類が違います（${checker.targetKind} 用）` });
      continue;
    }
    if (signal.aborted) {
      errors.push({ checkerId: checker.id, message: "中断されました" });
      continue;
    }
    let raws: RawFinding[];
    try {
      raws = await checker.run(opts.input, ctx);
    } catch (err) {
      errors.push({ checkerId: checker.id, message: errorMessage(err) });
      continue;
    }
    for (const raw of raws) {
      try {
        const finding = normalize(raw, opts.targetId, opts.targetKind, opts.catalog);
        // 同一 fingerprint は 1 件にまとめる（同じ鍵が同じファイルに 2 回書かれている等）
        if (!byFingerprint.has(finding.fingerprint)) byFingerprint.set(finding.fingerprint, finding);
      } catch (err) {
        errors.push({ checkerId: checker.id, message: errorMessage(err) });
      }
    }
  }

  const findings = [...byFingerprint.values()].sort(
    (a, b) => compareSeverity(a.severity, b.severity) || a.ruleId.localeCompare(b.ruleId) || a.fingerprint.localeCompare(b.fingerprint),
  );
  return { findings, errors };
}

/**
 * RawFinding → Finding。
 * ここで秘密情報の生の値を捨てる。Finding 型には生の値を入れるフィールドが存在しない。
 */
export function normalize(raw: RawFinding, targetId: string, targetKind: TargetKind, catalog: RuleCatalog): Finding {
  const rule = catalog.require(raw.ruleId);
  if (rule.targetKind !== targetKind) {
    throw new Error(`ルール ${rule.id} は ${rule.targetKind} 用です`);
  }
  const hash = raw.secret !== undefined ? secretHash(raw.secret) : undefined;
  const finding: Finding = {
    ruleId: rule.id,
    category: rule.category,
    severity: raw.severity ?? rule.defaultSeverity,
    location: raw.location,
    fingerprint: computeFingerprint({
      targetId,
      ruleId: rule.id,
      location: raw.location,
      discriminator: raw.discriminator,
      secretHash: hash,
    }),
    details: { ...(raw.details ?? {}) },
  };
  if (raw.secret !== undefined) finding.evidenceMasked = maskSecret(raw.secret);
  return finding;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
