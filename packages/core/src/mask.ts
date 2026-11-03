import { createHash } from "node:crypto";

/** 秘密情報のハッシュ（先頭 16 桁）。同一の値かどうかの判定にだけ使う。 */
export function secretHash(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex").slice(0, 16);
}

/**
 * 秘密情報を画面に出せる形にマスクする。
 * 種類の見分けに必要な先頭だけ残す（短い値はまったく残さない）。
 *   "AKIAIOSFODNN7EXAMPLE" → "AKIA****************（sha256:…）"
 */
export function maskSecret(secret: string): string {
  const visible = secret.length >= 16 ? 4 : 0;
  const hidden = Math.min(secret.length - visible, 16);
  return `${secret.slice(0, visible)}${"*".repeat(Math.max(hidden, 4))}（sha256:${secretHash(secret).slice(0, 8)}）`;
}

/**
 * テキスト中に含まれる既知の秘密情報をすべてマスクに置き換える。
 * 通知・AI 入力・ログに出す直前の最終防衛線として使う。
 */
export function redactSecrets(text: string, secrets: readonly string[]): string {
  let out = text;
  // 長いものから置換（部分一致による取りこぼし防止）
  const sorted = [...new Set(secrets)].filter((s) => s.length > 0).sort((a, b) => b.length - a.length);
  for (const s of sorted) {
    out = out.split(s).join(maskSecret(s));
  }
  return out;
}
