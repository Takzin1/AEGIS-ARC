import { describe, expect, it } from "vitest";
import { catalog, RULE_TEXTS_JA, RULES } from "../src";

describe("ルール一覧と日本語テンプレート", () => {
  it("すべてのルールに日本語テンプレートがある", () => {
    const missing = RULES.map((r) => r.id).filter((id) => !RULE_TEXTS_JA[id]);
    expect(missing).toEqual([]);
  });

  it("ルールに存在しないテンプレートがない（消し忘れ・打ち間違い防止）", () => {
    const orphan = Object.keys(RULE_TEXTS_JA).filter((id) => !catalog.get(id));
    expect(orphan).toEqual([]);
  });

  it.each(RULES.map((r) => r.id))("%s のテンプレートが必要な項目を満たす", (id) => {
    const t = RULE_TEXTS_JA[id]!;
    expect(t.title.length).toBeGreaterThan(5);
    expect(t.title.length).toBeLessThanOrEqual(60);
    expect(t.what.length).toBeGreaterThan(10);
    expect(t.why.length).toBeGreaterThan(10);
    expect(t.how.length).toBeGreaterThan(0);
    for (const step of t.how) expect(step.trim().length).toBeGreaterThan(5);
    for (const ref of t.references ?? []) expect(ref.url).toMatch(/^https:\/\//);
  });

  it("秘密情報のルールは、最初の手順で鍵の無効化・作り直しを求める（消すだけでは不十分なため）", () => {
    for (const r of RULES.filter((r) => r.category === "secret")) {
      const first = RULE_TEXTS_JA[r.id]!.how[0]!;
      expect(first, r.id).toMatch(/無効|作り直|再発行|再生成|削除|ロール|変更|確認/);
    }
  });

  it("リポジトリ用・Web用の両方のルールがある", () => {
    expect(RULES.some((r) => r.targetKind === "repo")).toBe(true);
    expect(RULES.some((r) => r.targetKind === "domain")).toBe(true);
  });
});
