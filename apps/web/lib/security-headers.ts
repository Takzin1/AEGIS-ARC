/**
 * このツール自身に適用するセキュリティヘッダ。
 * 「人に勧めるヘッダは自分で全部守る」ため、@whiteknight/rules の web.* ルールが指摘する項目をすべて満たす。
 */

export interface HeaderEntry {
  key: string;
  value: string;
}

/** すべての応答に付ける固定のヘッダ（CSP はリクエストごとの nonce が必要なので proxy.ts で付ける） */
export const STATIC_SECURITY_HEADERS: readonly HeaderEntry[] = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
];

/** 推測できない nonce（その場限りの合言葉）を作る。リクエストごとに必ず新しくする。 */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * nonce 方式の厳しい CSP。'unsafe-inline' は使わない。
 * 開発時だけ React のデバッグ機能のために 'unsafe-eval' を許可する（本番では付けない）。
 */
export function buildCsp(nonce: string, opts: { dev: boolean }): string {
  if (!/^[A-Za-z0-9+/=]{16,}$/.test(nonce)) {
    throw new Error("nonce の形式が不正です");
  }
  const directives: Record<string, string[]> = {
    "default-src": ["'self'"],
    "script-src": ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", ...(opts.dev ? ["'unsafe-eval'"] : [])],
    "style-src": ["'self'", `'nonce-${nonce}'`],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
  };
  const parts = Object.entries(directives).map(([k, v]) => `${k} ${v.join(" ")}`);
  if (!opts.dev) parts.push("upgrade-insecure-requests");
  return parts.join("; ");
}
