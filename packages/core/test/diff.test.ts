import { describe, expect, it } from "vitest";
import { diffScan, notifiableFindings, type Finding, type Severity } from "../src";

function finding(fp: string, severity: Severity = "high"): Finding {
  return { ruleId: "file.test", category: "file", severity, location: { type: "file", path: fp }, fingerprint: fp, details: {} };
}

describe("diffScan", () => {
  it("新規・再発・継続・抑止・解決を分類する", () => {
    const known = [
      { fingerprint: "persist", state: "open" as const },
      { fingerprint: "gone", state: "open" as const },
      { fingerprint: "back", state: "fixed" as const },
      { fingerprint: "accepted", state: "accepted_risk" as const },
      { fingerprint: "fp", state: "false_positive" as const },
      { fingerprint: "old-fixed", state: "fixed" as const },
    ];
    const current = ["persist", "back", "accepted", "fp", "brand-new"].map((x) => finding(x));
    const d = diffScan(known, current);
    expect(d.added.map((f) => f.fingerprint)).toEqual(["brand-new"]);
    expect(d.reopened.map((f) => f.fingerprint)).toEqual(["back"]);
    expect(d.persisting.map((f) => f.fingerprint)).toEqual(["persist"]);
    expect(d.suppressed.map((f) => f.fingerprint)).toEqual(["accepted", "fp"]);
    expect(d.resolved.map((k) => k.fingerprint)).toEqual(["gone"]);
  });
});

describe("notifiableFindings", () => {
  it("新規と再発のうち、しきい値以上だけを通知する（継続中の問題は毎回通知しない）", () => {
    const d = diffScan(
      [{ fingerprint: "persist", state: "open" }, { fingerprint: "back", state: "fixed" }],
      [finding("persist", "critical"), finding("back", "high"), finding("new-low", "low"), finding("new-crit", "critical")],
    );
    expect(notifiableFindings(d, "high").map((f) => f.fingerprint)).toEqual(["new-crit", "back"]);
  });
});
