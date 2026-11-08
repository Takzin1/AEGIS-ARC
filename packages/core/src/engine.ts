import { performance } from "node:perf_hooks";
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

/** 診断の 1 単位。checker は共有 input を変更せず、signal に従って中断すること。 */
export interface Checker<I> {
  id: string;
  targetKind: TargetKind;
  run(input: I, ctx: CheckContext): Promise<RawFinding[]>;
}

export interface CheckerError {
  checkerId: string;
  message: string;
}

export type CheckerStatus = "ok" | "error" | "skipped" | "aborted";

export interface CheckerMetric {
  checkerId: string;
  status: CheckerStatus;
  /** 診断・正規化の実行時間。外部AIやネットワークのタイムアウトはチェッカー側で管理する。 */
  durationMs: number;
  findingCount: number;
  errorCount: number;
}

export interface EngineResult {
  findings: Finding[];
  /** 失敗したチェッカー。1つ失敗しても他の結果は返す。 */
  errors: CheckerError[];
  /** 入力順に並んだ各チェッカーのメトリクス。秘密情報は含まない。 */
  metrics: CheckerMetric[];
  totalDurationMs: number;
}

export interface RunOptions<I> {
  targetId: string;
  targetKind: TargetKind;
  catalog: RuleCatalog;
  checkers: readonly Checker<I>[];
  input: I;
  signal?: AbortSignal;
  /** 既定 1（既存の逐次動作を維持）。設定可能な範囲は 1〜8。 */
  maxConcurrency?: number;
}

interface Outcome {
  findings: Finding[];
  errors: CheckerError[];
  metric: CheckerMetric;
}

/**
 * 並列チェッカー実行。小さなワーカープールで同時実行数を制限する。
 * 完了順ではなく入力順に結果をマージし、重複指摘の採用順・エラー順を安定化する。
 * タイムアウトや I/O 上限は個別チェッカーの責任。abort 後に戻った結果は採用しない。
 */
export async function runCheckers<I>(opts: RunOptions<I>): Promise<EngineResult> {
  const maxConcurrency = opts.maxConcurrency ?? 1;
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1 || maxConcurrency > 8) {
    throw new RangeError("maxConcurrency は 1〜8 の整数にしてください");
  }

  const started = performance.now();
  const signal = opts.signal ?? new AbortController().signal;
  const ctx: CheckContext = { targetId: opts.targetId, targetKind: opts.targetKind, signal };
  const outcomes: Outcome[] = new Array(opts.checkers.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < opts.checkers.length) {
      // JS の単一スレッド上で await より前に確保するので同じ index を処理しない。
      const index = nextIndex++;
      const checker = opts.checkers[index]!;
      outcomes[index] = await execute(checker);
    }
  }

  async function execute(checker: Checker<I>): Promise<Outcome> {
    const began = performance.now();
    const findings: Finding[] = [];
    const errors: CheckerError[] = [];
    let status: CheckerStatus = "ok";

    if (checker.targetKind !== opts.targetKind) {
      status = "skipped";
      errors.push({ checkerId: checker.id, message: "対象の種類が違います（" + checker.targetKind + " 用）" });
    } else if (signal.aborted) {
      status = "aborted";
      errors.push({ checkerId: checker.id, message: "中断されました" });
    } else {
      try {
        const raws = await checker.run(opts.input, ctx);
        if (signal.aborted) {
          // キャンセルされた診断の結果を保存・通知に流さない。
          status = "aborted";
          errors.push({ checkerId: checker.id, message: "中断されました" });
        } else {
          for (const raw of raws) {
            if (signal.aborted) {
              status = "aborted";
              findings.length = 0;
              errors.push({ checkerId: checker.id, message: "中断されました" });
              break;
            }
            try {
              findings.push(normalize(raw, opts.targetId, opts.targetKind, opts.catalog));
            } catch (err) {
              errors.push({ checkerId: checker.id, message: errorMessage(err) });
            }
          }
          if (status === "ok" && errors.length > 0) status = "error";
        }
      } catch (err) {
        status = signal.aborted ? "aborted" : "error";
        errors.push({ checkerId: checker.id, message: signal.aborted ? "中断されました" : errorMessage(err) });
      }
    }

    return {
      findings,
      errors,
      metric: {
        checkerId: checker.id,
        status,
        durationMs: Math.max(0, performance.now() - began),
        findingCount: findings.length,
        errorCount: errors.length,
      },
    };
  }

  await Promise.all(
    Array.from({ length: Math.min(maxConcurrency, opts.checkers.length) }, () => worker()),
  );

  const errors: CheckerError[] = [];
  const metrics: CheckerMetric[] = [];
  const byFingerprint = new Map<string, Finding>();
  // 安定した入力順で統合。同じ指摘は先に登録したチェッカーの結果を採用。
  for (const outcome of outcomes) {
    errors.push(...outcome.errors);
    metrics.push(outcome.metric);
    for (const finding of outcome.findings) {
      if (!byFingerprint.has(finding.fingerprint)) byFingerprint.set(finding.fingerprint, finding);
    }
  }

  const findings = [...byFingerprint.values()].sort(
    (a, b) => compareSeverity(a.severity, b.severity) || a.ruleId.localeCompare(b.ruleId) || a.fingerprint.localeCompare(b.fingerprint),
  );
  return { findings, errors, metrics, totalDurationMs: Math.max(0, performance.now() - started) };
}

/** RawFinding → Finding。ここで生の秘密値を捨てる。 */
export function normalize(raw: RawFinding, targetId: string, targetKind: TargetKind, catalog: RuleCatalog): Finding {
  const rule = catalog.require(raw.ruleId);
  if (rule.targetKind !== targetKind) {
    throw new Error("ルール " + rule.id + " は " + rule.targetKind + " 用です");
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
