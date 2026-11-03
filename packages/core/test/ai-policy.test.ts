import { describe, expect, it } from "vitest";
import {
  allowsCodeExcerpts,
  allowsExternalAi,
  buildAiPayload,
  redactSecrets,
  resolveAiPolicy,
  type Finding,
  type ResolvedAiPolicy,
} from "../src";

const secret = ["xoxb", "000000000000", "TESTONLYDUMMY"].join("-");
const code = `const client = new WebClient("${secret}");\nexport default client;`;
const redact = (t: string) => redactSecrets(t, [secret]);

const headerFinding: Finding = {
  ruleId: "web.hsts-missing",
  category: "web-header",
  severity: "medium",
  location: { type: "header", url: "https://www.example.lg.jp/", header: "strict-transport-security" },
  fingerprint: "f1",
  details: { observed: "なし", longText: "x".repeat(500), multi: "a\nb" },
};
const configFinding: Finding = {
  ruleId: "config.gha-write-all-permissions",
  category: "config",
  severity: "medium",
  location: { type: "file", path: ".github/workflows/ci.yml", line: 12 },
  fingerprint: "f2",
  details: {},
};
const secretFinding: Finding = {
  ruleId: "secret.slack-token",
  category: "secret",
  severity: "critical",
  location: { type: "file", path: "src/slack.ts", line: 1 },
  fingerprint: "f3",
  evidenceMasked: "xoxb****",
  details: { kind: "bot" },
};

const policy = (mode: ResolvedAiPolicy["mode"]): ResolvedAiPolicy => ({ mode, requested: mode, cappedByInstance: false });

describe("resolveAiPolicy", () => {
  it("組織が未設定なら off（既定はAIを使わない）", () => {
    expect(resolveAiPolicy(undefined, {}).mode).toBe("off");
    expect(resolveAiPolicy("garbage", {}).mode).toBe("off");
  });

  it("組織が選んだモードを使う", () => {
    expect(resolveAiPolicy("metadata_only", {}).mode).toBe("metadata_only");
    expect(resolveAiPolicy("with_code", {}).mode).toBe("with_code");
  });

  it("設置環境の強制オフは組織設定より優先する", () => {
    const p = resolveAiPolicy("with_code", { WHITEKNIGHT_AI_HARD_DISABLE: "true" });
    expect(p).toEqual({ mode: "off", requested: "with_code", cappedByInstance: true });
    expect(allowsExternalAi(p)).toBe(false);
  });

  it("設置環境の上限で切り下げる（「外部AIへコードを送らない」を環境側で強制）", () => {
    const p = resolveAiPolicy("with_code", { WHITEKNIGHT_AI_MAX_MODE: "metadata_only" });
    expect(p.mode).toBe("metadata_only");
    expect(p.cappedByInstance).toBe(true);
    expect(allowsCodeExcerpts(p)).toBe(false);
  });

  it("上限の値が不正なら安全側（off）に倒す", () => {
    expect(resolveAiPolicy("with_code", { WHITEKNIGHT_AI_MAX_MODE: "everything" }).mode).toBe("off");
  });

  it("上限より弱いモードはそのまま", () => {
    expect(resolveAiPolicy("metadata_only", { WHITEKNIGHT_AI_MAX_MODE: "with_code" }).mode).toBe("metadata_only");
  });
});

describe("buildAiPayload", () => {
  it("off なら何も作らない", () => {
    const d = buildAiPayload(policy("off"), { finding: configFinding, codeExcerpt: { path: "a", text: code } }, redact);
    expect(d.allowed).toBe(false);
  });

  it("metadata_only ではコードを渡されても送らない", () => {
    const d = buildAiPayload(policy("metadata_only"), { finding: configFinding, techStack: ["Next.js"], codeExcerpt: { path: "a", text: code } }, redact);
    expect(d.allowed).toBe(true);
    if (!d.allowed) return;
    expect(d.payload.codeExcerpt).toBeUndefined();
    expect(JSON.stringify(d.payload)).not.toContain("WebClient");
    expect(d.payload.location).toEqual({ type: "file", path: ".github/workflows/ci.yml" });
    expect(d.payload.techStack).toEqual(["Next.js"]);
  });

  it("metadata_only では長い文字列・複数行の details を落とす（コード片の混入対策）", () => {
    const d = buildAiPayload(policy("metadata_only"), { finding: headerFinding }, redact);
    if (!d.allowed) throw new Error("allowed のはず");
    expect(d.payload.details).toEqual({ observed: "なし" });
  });

  it("with_code ではコード抜粋を伏せ字にして送る", () => {
    const d = buildAiPayload(policy("with_code"), { finding: configFinding, codeExcerpt: { path: "src/slack.ts", text: code } }, redact);
    if (!d.allowed) throw new Error("allowed のはず");
    expect(d.payload.codeExcerpt?.text).toContain("WebClient");
    expect(JSON.stringify(d.payload)).not.toContain(secret);
  });

  it("秘密情報の指摘では with_code でもコード・証拠・details を送らない", () => {
    const d = buildAiPayload(policy("with_code"), { finding: secretFinding, codeExcerpt: { path: "src/slack.ts", text: code } }, redact);
    if (!d.allowed) throw new Error("allowed のはず");
    const json = JSON.stringify(d.payload);
    expect(d.payload.codeExcerpt).toBeUndefined();
    expect(json).not.toContain("xoxb");
    expect(d.payload.details).toEqual({});
  });
});
