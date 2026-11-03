import { describe, expect, it } from "vitest";
import { RuleCatalog, runCheckers, type Checker, type RuleMeta } from "../src";

const rules: RuleMeta[] = [
  { id: "secret.test-key", category: "secret", targetKind: "repo", defaultSeverity: "critical" },
  { id: "file.test-file", category: "file", targetKind: "repo", defaultSeverity: "high" },
  { id: "dep.test-vuln", category: "dependency", targetKind: "repo", defaultSeverity: "high" },
  { id: "web.test-header", category: "web-header", targetKind: "domain", defaultSeverity: "medium" },
];
const catalog = new RuleCatalog(rules);
const secretValue = ["sk", "test", "ZZZZ", "1234567890abcdef"].join("_");

describe("RuleCatalog", () => {
  it("ID の重複を拒否する", () => {
    expect(() => new RuleCatalog([rules[0]!, rules[0]!])).toThrow(/重複/);
  });
  it("ID の書式を検査する", () => {
    expect(() => new RuleCatalog([{ ...rules[0]!, id: "Bad ID" }])).toThrow(/書式/);
  });
});

describe("runCheckers", () => {
  it("危険度順に並べ、秘密情報の生の値を結果に残さない", async () => {
    const checker: Checker<null> = {
      id: "test",
      targetKind: "repo",
      run: async () => [
        { ruleId: "dep.test-vuln", location: { type: "package", ecosystem: "npm", name: "x", version: "1.0.0", manifestPath: "package-lock.json" }, severity: "low", discriminator: "GHSA-1" },
        { ruleId: "secret.test-key", location: { type: "file", path: "config.js", line: 2 }, secret: secretValue },
        { ruleId: "file.test-file", location: { type: "file", path: ".env" } },
      ],
    };
    const { findings, errors } = await runCheckers({ targetId: "t", targetKind: "repo", catalog, checkers: [checker], input: null });
    expect(errors).toEqual([]);
    expect(findings.map((f) => f.ruleId)).toEqual(["secret.test-key", "file.test-file", "dep.test-vuln"]);
    expect(findings[2]!.severity).toBe("low"); // チェッカーによる上書き
    expect(findings[0]!.evidenceMasked).toMatch(/^sk_t\*+/);
    expect(JSON.stringify(findings)).not.toContain(secretValue);
    expect(Object.keys(findings[0]!)).not.toContain("secret");
  });

  it("同じ fingerprint の指摘は1件にまとめる", async () => {
    const checker: Checker<null> = {
      id: "dup",
      targetKind: "repo",
      run: async () => [
        { ruleId: "secret.test-key", location: { type: "file", path: "a.js", line: 1 }, secret: secretValue },
        { ruleId: "secret.test-key", location: { type: "file", path: "a.js", line: 9 }, secret: secretValue },
      ],
    };
    const { findings } = await runCheckers({ targetId: "t", targetKind: "repo", catalog, checkers: [checker], input: null });
    expect(findings).toHaveLength(1);
  });

  it("1つのチェッカーが失敗しても他の結果は返す", async () => {
    const broken: Checker<null> = { id: "broken", targetKind: "repo", run: async () => { throw new Error("boom"); } };
    const ok: Checker<null> = { id: "ok", targetKind: "repo", run: async () => [{ ruleId: "file.test-file", location: { type: "file", path: ".env" } }] };
    const { findings, errors } = await runCheckers({ targetId: "t", targetKind: "repo", catalog, checkers: [broken, ok], input: null });
    expect(findings).toHaveLength(1);
    expect(errors).toEqual([{ checkerId: "broken", message: "boom" }]);
  });

  it("未登録ルールや対象違いのルールはエラーとして記録する", async () => {
    const checker: Checker<null> = {
      id: "bad",
      targetKind: "repo",
      run: async () => [
        { ruleId: "unknown.rule", location: { type: "file", path: "x" } },
        { ruleId: "web.test-header", location: { type: "header", url: "https://a.jp/", header: "x" } },
      ],
    };
    const { findings, errors } = await runCheckers({ targetId: "t", targetKind: "repo", catalog, checkers: [checker], input: null });
    expect(findings).toEqual([]);
    expect(errors).toHaveLength(2);
  });

  it("対象の種類が違うチェッカーは実行しない", async () => {
    let called = false;
    const web: Checker<null> = { id: "web", targetKind: "domain", run: async () => { called = true; return []; } };
    const { errors } = await runCheckers({ targetId: "t", targetKind: "repo", catalog, checkers: [web], input: null });
    expect(called).toBe(false);
    expect(errors).toHaveLength(1);
  });

  it("中断されたら残りのチェッカーを実行しない", async () => {
    const ac = new AbortController();
    ac.abort();
    let called = false;
    const c: Checker<null> = { id: "c", targetKind: "repo", run: async () => { called = true; return []; } };
    await runCheckers({ targetId: "t", targetKind: "repo", catalog, checkers: [c], input: null, signal: ac.signal });
    expect(called).toBe(false);
  });
});
