import { describe, expect, it } from "vitest";
import { computeFingerprint, maskSecret, redactSecrets, secretHash, stableLocationKey } from "../src";

// テスト用のダミー値は実行時に組み立てる（本物そっくりの鍵をリポジトリに置かない）
const dummyKey = ["AKIA", "TESTONLY", "0000", "DUMMY"].join("");

describe("maskSecret", () => {
  it("先頭4文字だけ残し、元の値を含まない", () => {
    const masked = maskSecret(dummyKey);
    expect(masked.startsWith("AKIA****")).toBe(true);
    expect(masked).not.toContain(dummyKey.slice(4));
    expect(masked).toContain(`sha256:${secretHash(dummyKey).slice(0, 8)}`);
  });

  it("短い値は1文字も残さない", () => {
    expect(maskSecret("hunter2").startsWith("*******")).toBe(true);
    expect(maskSecret("hunter2")).not.toContain("hunt");
  });
});

describe("redactSecrets", () => {
  it("テキスト中の秘密情報をすべて伏せる", () => {
    const text = `aws_key = "${dummyKey}"\nother = "${dummyKey}"`;
    const out = redactSecrets(text, [dummyKey]);
    expect(out).not.toContain(dummyKey);
    expect(out.match(/AKIA\*{4}/g)).toHaveLength(2);
  });

  it("空文字は無視する", () => {
    expect(redactSecrets("abc", [""])).toBe("abc");
  });
});

describe("fingerprint", () => {
  const base = { targetId: "t1", ruleId: "secret.aws-access-key" };

  it("行番号が変わっても同じ値になる", () => {
    const a = computeFingerprint({ ...base, location: { type: "file", path: "src/a.ts", line: 3 } });
    const b = computeFingerprint({ ...base, location: { type: "file", path: "./src/a.ts", line: 40 } });
    expect(a).toBe(b);
  });

  it("対象・ルール・場所・秘密値が違えば別の値になる", () => {
    const loc = { type: "file", path: "src/a.ts" } as const;
    const fp = computeFingerprint({ ...base, location: loc });
    expect(computeFingerprint({ ...base, targetId: "t2", location: loc })).not.toBe(fp);
    expect(computeFingerprint({ ...base, ruleId: "secret.github-token", location: loc })).not.toBe(fp);
    expect(computeFingerprint({ ...base, location: { type: "file", path: "src/b.ts" } })).not.toBe(fp);
    expect(computeFingerprint({ ...base, location: loc, secretHash: "x" })).not.toBe(fp);
  });

  it("URL のクエリとホストの大文字小文字を無視する", () => {
    expect(stableLocationKey({ type: "url", url: "https://Example.JP/.git/HEAD?x=1" })).toBe(
      "url:https://example.jp/.git/HEAD",
    );
  });

  it("依存パッケージはバージョンを含めない（上げても直っていなければ同じ問題）", () => {
    const k1 = stableLocationKey({ type: "package", ecosystem: "npm", name: "lodash", version: "4.17.15", manifestPath: "package-lock.json" });
    const k2 = stableLocationKey({ type: "package", ecosystem: "npm", name: "lodash", version: "4.17.19", manifestPath: "package-lock.json" });
    expect(k1).toBe(k2);
  });
});
