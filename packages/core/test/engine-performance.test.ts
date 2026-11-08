import { describe, expect, it } from "vitest";
import { RuleCatalog, runCheckers, type Checker, type RuleMeta } from "../src";

const catalog = new RuleCatalog([
  { id: "file.test-file", category: "file", targetKind: "repo", defaultSeverity: "high" },
] satisfies RuleMeta[]);

function finding(source: string) {
  return { ruleId: "file.test-file", location: { type: "file" as const, path: ".env" }, details: { source } };
}

describe("AEGIS-ARC bounded execution", () => {
  it("never runs more than the configured number of checkers", async () => {
    let active = 0;
    let peak = 0;
    let started = 0;
    let openGate!: () => void;
    let bothStarted!: () => void;
    const gate = new Promise<void>((resolve) => { openGate = resolve; });
    const twoStarted = new Promise<void>((resolve) => { bothStarted = resolve; });
    const checkers: Checker<null>[] = Array.from({ length: 5 }, (_, i) => ({
      id: "checker-" + i,
      targetKind: "repo" as const,
      async run() {
        active++;
        peak = Math.max(peak, active);
        started++;
        if (started === 2) bothStarted();
        await gate;
        active--;
        return [finding(String(i))];
      },
    }));
    const execution = runCheckers({
      targetId: "repo-1", targetKind: "repo", catalog, checkers, input: null, maxConcurrency: 2,
    });
    await twoStarted;
    expect(active).toBe(2);
    expect(started).toBe(2);
    openGate();
    const result = await execution;
    expect(peak).toBe(2);
    expect(started).toBe(5);
    expect(result.errors).toEqual([]);
    expect(result.metrics).toHaveLength(5);
    expect(result.metrics.map((m) => m.status)).toEqual(Array(5).fill("ok"));
    expect(result.metrics.every((m) => m.durationMs >= 0)).toBe(true);
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });

  it("preserves deterministic first-wins deduplication despite out-of-order completion", async () => {
    let unblock!: () => void;
    const gate = new Promise<void>((resolve) => { unblock = resolve; });
    const slow: Checker<null> = {
      id: "slow", targetKind: "repo",
      async run() { await gate; return [finding("slow")]; },
    };
    const fast: Checker<null> = {
      id: "fast", targetKind: "repo",
      async run() { return [finding("fast")]; },
    };
    const execution = runCheckers({
      targetId: "repo-1", targetKind: "repo", catalog,
      checkers: [slow, fast], input: null, maxConcurrency: 2,
    });
    await Promise.resolve();
    unblock();
    const result = await execution;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.details.source).toBe("slow");
    expect(result.metrics.map((m) => m.checkerId)).toEqual(["slow", "fast"]);
  });

  it("discards results returned after cancellation", async () => {
    const ac = new AbortController();
    let unblock!: () => void;
    let running!: () => void;
    const gate = new Promise<void>((resolve) => { unblock = resolve; });
    const began = new Promise<void>((resolve) => { running = resolve; });
    const checker: Checker<null> = {
      id: "late", targetKind: "repo",
      async run() { running(); await gate; return [finding("late")]; },
    };
    const execution = runCheckers({
      targetId: "repo-1", targetKind: "repo", catalog,
      checkers: [checker], input: null, signal: ac.signal, maxConcurrency: 2,
    });
    await began;
    ac.abort();
    unblock();
    const result = await execution;
    expect(result.findings).toEqual([]);
    expect(result.metrics[0]!.status).toBe("aborted");
    expect(result.errors).toEqual([{ checkerId: "late", message: "中断されました" }]);
  });

  it("validates concurrency limits", async () => {
    for (const n of [0, -1, 1.5, 9, Number.NaN, Number.POSITIVE_INFINITY]) {
      await expect(runCheckers({
        targetId: "repo-1", targetKind: "repo", catalog, checkers: [], input: null, maxConcurrency: n,
      })).rejects.toThrow(/maxConcurrency/);
    }
  });

  it("keeps errors and metrics in checker order", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const checkers: Checker<null>[] = [
      { id: "first", targetKind: "repo", async run() { await gate; throw new Error("first error"); } },
      { id: "second", targetKind: "repo", async run() { throw new Error("second error"); } },
    ];
    const execution = runCheckers({
      targetId: "repo-1", targetKind: "repo", catalog, checkers, input: null, maxConcurrency: 2,
    });
    await Promise.resolve();
    release();
    const result = await execution;
    expect(result.errors.map((e) => e.checkerId)).toEqual(["first", "second"]);
    expect(result.metrics.map((m) => m.status)).toEqual(["error", "error"]);
  });
});
