import { createHash } from "node:crypto";
import type { Location } from "./types";

/**
 * 場所から「変わりにくい部分」だけを取り出す。
 * - 行番号は含めない（上に1行足しただけで別の問題扱いになるのを防ぐ）
 * - URL はクエリ・フラグメントを除き、ホスト名は小文字化
 */
export function stableLocationKey(location: Location): string {
  switch (location.type) {
    case "file":
      return `file:${normalizePath(location.path)}`;
    case "url":
      return `url:${normalizeUrl(location.url)}`;
    case "header":
      return `header:${normalizeUrl(location.url)}#${location.header.toLowerCase()}`;
    case "cookie":
      return `cookie:${normalizeUrl(location.url)}#${location.cookieName}`;
    case "package":
      // バージョンは含めない：上げても直っていなければ同じ問題として追跡したい
      return `package:${location.ecosystem.toLowerCase()}:${location.name}:${normalizePath(location.manifestPath)}`;
    case "tls":
      return `tls:${location.host.toLowerCase()}:${location.port}`;
    case "repo-setting":
      return `repo-setting:${location.setting}`;
  }
}

export interface FingerprintInput {
  targetId: string;
  ruleId: string;
  location: Location;
  discriminator?: string;
  secretHash?: string;
}

/** 同じ対象・同じルール・同じ場所（・同じ秘密値）なら毎回同じ値になる識別子。 */
export function computeFingerprint(input: FingerprintInput): string {
  const parts = [
    input.targetId,
    input.ruleId,
    stableLocationKey(input.location),
    input.discriminator ?? "",
    input.secretHash ?? "",
  ];
  return createHash("sha256").update(JSON.stringify(parts), "utf8").digest("hex");
}

function normalizePath(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/{2,}/g, "/");
}

function normalizeUrl(raw: string): string {
  try {
    const u = new URL(raw);
    return `${u.protocol}//${u.host.toLowerCase()}${u.pathname}`;
  } catch {
    return raw;
  }
}
