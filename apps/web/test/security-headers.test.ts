import { describe, expect, it } from "vitest";
import { buildCsp, generateNonce, STATIC_SECURITY_HEADERS } from "../lib/security-headers";

function header(name: string) {
  return STATIC_SECURITY_HEADERS.find((h) => h.key.toLowerCase() === name.toLowerCase())?.value;
}

describe("このツール自身のセキュリティヘッダ", () => {
  it("自分が勧めるヘッダをすべて付けている", () => {
    expect(header("Strict-Transport-Security")).toMatch(/max-age=(\d+)/);
    const maxAge = Number(/max-age=(\d+)/.exec(header("Strict-Transport-Security")!)![1]);
    expect(maxAge).toBeGreaterThanOrEqual(31536000);
    expect(header("X-Content-Type-Options")).toBe("nosniff");
    expect(header("Referrer-Policy")).toBeDefined();
    expect(header("Permissions-Policy")).toContain("camera=()");
    expect(header("X-Frame-Options")).toBe("DENY");
  });

  it("本番の CSP に unsafe-inline / unsafe-eval / ワイルドカードを含まない", () => {
    const csp = buildCsp(generateNonce(), { dev: false });
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toMatch(/\s\*(\s|;|$)/);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("upgrade-insecure-requests");
  });

  it("開発時だけ unsafe-eval を許可する", () => {
    expect(buildCsp(generateNonce(), { dev: true })).toContain("'unsafe-eval'");
  });

  it("nonce は毎回違い、CSP に埋め込まれる", () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).not.toBe(b);
    expect(buildCsp(a, { dev: false })).toContain(`'nonce-${a}'`);
  });

  it("不正な nonce で CSP を組み立てない（ヘッダ注入対策）", () => {
    expect(() => buildCsp("abc'; script-src *", { dev: false })).toThrow();
  });
});
