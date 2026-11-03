import { describe, expect, it } from "vitest";
import { compareSeverity, isSeverity, meetsThreshold, severityFromCvss, SEVERITIES } from "../src";

describe("severity", () => {
  it("危ない順に並ぶ", () => {
    const shuffled = ["low", "critical", "info", "medium", "high"] as const;
    expect([...shuffled].sort(compareSeverity)).toEqual([...SEVERITIES]);
  });

  it("しきい値以上を判定する", () => {
    expect(meetsThreshold("critical", "high")).toBe(true);
    expect(meetsThreshold("high", "high")).toBe(true);
    expect(meetsThreshold("medium", "high")).toBe(false);
  });

  it("不正な値を弾く", () => {
    expect(isSeverity("high")).toBe(true);
    expect(isSeverity("severe")).toBe(false);
    expect(isSeverity(undefined)).toBe(false);
  });

  it.each([
    [9.8, false, "critical"],
    [7.5, false, "high"],
    [5.0, false, "medium"],
    [2.1, false, "low"],
    [0, false, "info"],
    [undefined, false, "medium"],
    [3.0, true, "critical"],
  ] as const)("CVSS %s (悪用確認=%s) → %s", (score, kev, expected) => {
    expect(severityFromCvss(score, kev)).toBe(expected);
  });
});
