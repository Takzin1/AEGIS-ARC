import { normalize, resolveAiPolicy, type Finding } from "@whiteknight/core";
import { describe, expect, it } from "vitest";
import { catalog, renderMarkdownReport } from "../src";

const secret = ["AKIA", "TESTONLY", "0000", "DUMMY"].join("");
const scannedAt = new Date("2026-11-03T03:00:00Z");
const offPolicy = resolveAiPolicy(undefined, {});

function f(raw: Parameters<typeof normalize>[0]): Finding {
  const kind = catalog.require(raw.ruleId).targetKind;
  return normalize(raw, "target-1", kind, catalog);
}

const repoFindings = [
  f({ ruleId: "secret.aws-access-key", location: { type: "file", path: "src/config.js", line: 3 }, secret }),
  f({
    ruleId: "dep.vulnerable-package",
    location: { type: "package", ecosystem: "npm", name: "lodash", version: "4.17.15", manifestPath: "package-lock.json" },
    discriminator: "GHSA-p6mc-m468-83gw",
    details: { fixedVersion: "4.17.19", vulnIds: ["GHSA-p6mc-m468-83gw", "CVE-2020-8203"] },
  }),
];

describe("renderMarkdownReport（AIなしモード）", () => {
  const md = renderMarkdownReport({ targetLabel: "github.com/example/site", scannedAt, findings: repoFindings, aiPolicy: offPolicy });

  it("ルールのテンプレートだけでレポートが完成する", () => {
    expect(md).toContain("# セキュリティ診断レポート：github.com/example/site");
    expect(md).toContain("診断日時：2026/11/03 12:00（日本時間）");
    expect(md).toContain("🔴 今すぐ対応｜AWS（アマゾンのクラウド）の鍵がプログラムに書かれています");
    expect(md).toContain("**何が問題？**");
    expect(md).toContain("**どう直す？**");
    expect(md).toContain("直ったバージョン**：4.17.19");
    expect(md).toContain("脆弱性の番号**：GHSA-p6mc-m468-83gw、CVE-2020-8203");
  });

  it("外部AIを使っていないことを明記する", () => {
    expect(md).toContain("外部のAIサービスには、コードも診断結果も送っていません");
  });

  it("秘密情報の生の値を含まない", () => {
    expect(md).not.toContain(secret);
    expect(md).toContain("AKIA****");
  });

  it("危険度順に並ぶ", () => {
    expect(md.indexOf("AWS（アマゾン")).toBeLessThan(md.indexOf("弱点が知られている部品"));
  });
});

describe("renderMarkdownReport（その他）", () => {
  it("問題がないときも、保証ではないことを書く", () => {
    const md = renderMarkdownReport({ targetLabel: "www.example.lg.jp", scannedAt, findings: [], aiPolicy: offPolicy });
    expect(md).toContain("問題は見つかりませんでした");
    expect(md).toContain("保証するものではありません");
  });

  it("新規の指摘に印を付け、件数を書く", () => {
    const fp = repoFindings[1]!.fingerprint;
    const md = renderMarkdownReport({ targetLabel: "x", scannedAt, findings: repoFindings, newFingerprints: new Set([fp]), aiPolicy: offPolicy });
    expect(md).toContain("**1 件** は今回新しく見つかったもの");
    expect(md.match(/🆕新規/g)).toHaveLength(1);
  });

  it("診断できなかった項目を伝える", () => {
    const md = renderMarkdownReport({ targetLabel: "x", scannedAt, findings: [], errors: [{ checkerId: "tls", message: "接続できませんでした" }], aiPolicy: offPolicy });
    expect(md).toContain("一部の項目は診断できませんでした");
    expect(md).toContain("`tls`：接続できませんでした");
  });

  it("リポジトリ由来のファイル名で Markdown を崩されない", () => {
    const evil = f({ ruleId: "file.dotenv-committed", location: { type: "file", path: "a`](https://evil.example)`\n# x/.env" } });
    const md = renderMarkdownReport({ targetLabel: "[click](https://evil.example)", scannedAt, findings: [evil], aiPolicy: offPolicy });
    expect(md).not.toContain("[click](https://evil.example)");
    expect(md).not.toMatch(/\n# x/);
    expect(md).toContain("``ファイル a`](https://evil.example)` # x/.env``");
  });

  it("設置環境でAIが制限されている場合はそのことも書く", () => {
    const capped = resolveAiPolicy("with_code", { WHITEKNIGHT_AI_MAX_MODE: "metadata_only" });
    const md = renderMarkdownReport({ targetLabel: "x", scannedAt, findings: [], aiPolicy: capped });
    expect(md).toContain("コードは送らない");
    expect(md).toContain("この設置環境の設定により");
  });
});
