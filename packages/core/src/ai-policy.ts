import type { Severity } from "./severity";
import type { DetailValue, Finding, Location, RuleCategory } from "./types";

/**
 * 外部 AI の利用方針。**既定は "off"**（ルールベースの診断だけで完結し、外部 AI へは何も送らない）。
 *
 * - off           : 外部 AI を一切呼ばない。レポートはルールの日本語テンプレートだけで作る。
 * - metadata_only : 「外部AIへコードを送らない」。送るのは問題の種類・危険度・ファイル名/URL・
 *                   利用技術名だけ。ソースコード・秘密情報（マスク済みも含む）は送らない。
 * - with_code     : 上記に加え、関連するコードの抜粋を送る。秘密情報は伏せ字にしてから送る。
 */
export const AI_MODES = ["off", "metadata_only", "with_code"] as const;
export type AiMode = (typeof AI_MODES)[number];

const MODE_RANK: Record<AiMode, number> = { off: 0, metadata_only: 1, with_code: 2 };

export const DEFAULT_AI_MODE: AiMode = "off";

export function isAiMode(value: unknown): value is AiMode {
  return typeof value === "string" && (AI_MODES as readonly string[]).includes(value);
}

/** 画面・レポートに表示する説明文。 */
export const AI_MODE_LABELS_JA: Record<AiMode, { title: string; description: string }> = {
  off: {
    title: "AIを使わない（既定）",
    description:
      "外部のAIサービスには何も送りません。診断も説明文もすべてこのシステムの中で作ります。",
  },
  metadata_only: {
    title: "AIで説明を補足する（コードは送らない）",
    description:
      "問題の種類・危険度・ファイル名やURL・使っている技術の名前だけを外部AIに送ります。ソースコードと秘密情報は送りません。",
  },
  with_code: {
    title: "AIで説明を補足する（関連コードの抜粋も送る）",
    description:
      "上に加えて、問題のある箇所の前後のコードを外部AIに送ります。パスワードやAPIキーなどの秘密情報は伏せ字にしてから送ります。",
  },
};

export interface AiPolicyEnv {
  /** "true" ならこの設置環境では外部 AI を絶対に呼ばない（自治体のオンプレ・閉域向け）。組織設定より優先。 */
  WHITEKNIGHT_AI_HARD_DISABLE?: string | undefined;
  /** この設置環境で許可する最大のモード。組織設定がこれを超える場合は切り下げる。 */
  WHITEKNIGHT_AI_MAX_MODE?: string | undefined;
}

export interface ResolvedAiPolicy {
  mode: AiMode;
  /** 組織が選んだモード（未設定なら off） */
  requested: AiMode;
  /** 設置環境の上限で切り下げられたか */
  cappedByInstance: boolean;
}

/** 組織の設定と設置環境の上限から、実際に適用するモードを決める。厳しい方が必ず勝つ。 */
export function resolveAiPolicy(orgMode: unknown, env: AiPolicyEnv): ResolvedAiPolicy {
  const requested: AiMode = isAiMode(orgMode) ? orgMode : DEFAULT_AI_MODE;
  let cap: AiMode = "with_code";
  if (env.WHITEKNIGHT_AI_HARD_DISABLE?.toLowerCase() === "true") {
    cap = "off";
  } else if (env.WHITEKNIGHT_AI_MAX_MODE !== undefined && env.WHITEKNIGHT_AI_MAX_MODE !== "") {
    // 不正な値は安全側（off）に倒す
    cap = isAiMode(env.WHITEKNIGHT_AI_MAX_MODE) ? env.WHITEKNIGHT_AI_MAX_MODE : "off";
  }
  const mode = MODE_RANK[requested] <= MODE_RANK[cap] ? requested : cap;
  return { mode, requested, cappedByInstance: mode !== requested };
}

export function allowsExternalAi(policy: ResolvedAiPolicy): boolean {
  return policy.mode !== "off";
}

export function allowsCodeExcerpts(policy: ResolvedAiPolicy): boolean {
  return policy.mode === "with_code";
}

declare const aiPayloadBrand: unique symbol;

/**
 * 外部 AI に送ってよいことを確認済みのデータ。
 * buildAiPayload() 以外では作れないため、AI クライアントの引数をこの型にすれば
 * 方針チェックを経ないデータが外部に出ることはない。
 */
export interface AiPayload {
  readonly [aiPayloadBrand]: true;
  readonly mode: Exclude<AiMode, "off">;
  readonly ruleId: string;
  readonly category: RuleCategory;
  readonly severity: Severity;
  readonly location: Location;
  readonly details: Readonly<Record<string, DetailValue>>;
  readonly techStack: readonly string[];
  readonly codeExcerpt?: { readonly path: string; readonly text: string };
}

export interface AiFindingContext {
  finding: Finding;
  /** 例：["Next.js", "Vercel"]。リポジトリの設定ファイルから推定した技術名 */
  techStack?: readonly string[];
  /** 問題箇所の前後のコード。with_code のときだけ送られる */
  codeExcerpt?: { path: string; text: string };
}

export type AiPayloadDecision =
  | { allowed: false; reason: string }
  | { allowed: true; payload: AiPayload };

/** metadata_only で details の文字列がこれより長ければ、コード片の混入とみなして落とす */
export const METADATA_MAX_STRING_LENGTH = 200;
/** with_code で送るコード抜粋の上限（文字数） */
export const CODE_EXCERPT_MAX_LENGTH = 4000;

/**
 * 方針に従って外部 AI に送るデータを組み立てる。
 * @param redact 秘密情報を伏せ字にする関数（with_code のコード抜粋に必ず適用する）
 */
export function buildAiPayload(
  policy: ResolvedAiPolicy,
  ctx: AiFindingContext,
  redact: (text: string) => string,
): AiPayloadDecision {
  if (policy.mode === "off") {
    return { allowed: false, reason: "外部AIの利用がオフになっています" };
  }
  const f = ctx.finding;
  // 秘密情報のカテゴリは、マスク済みでも証拠を送らない。details も送らない。
  const details = f.category === "secret" ? {} : sanitizeDetails(f.details);
  const base = {
    mode: policy.mode,
    ruleId: f.ruleId,
    category: f.category,
    severity: f.severity,
    location: stripLineIfMetadataOnly(f.location, policy.mode),
    details,
    techStack: [...(ctx.techStack ?? [])].slice(0, 20),
  };
  // 秘密情報の指摘では、伏せ字にしてもコード抜粋は送らない（取りこぼしのリスクを取らない）
  if (policy.mode === "with_code" && ctx.codeExcerpt && f.category !== "secret") {
    const text = redact(ctx.codeExcerpt.text).slice(0, CODE_EXCERPT_MAX_LENGTH);
    return {
      allowed: true,
      payload: { ...base, codeExcerpt: { path: ctx.codeExcerpt.path, text } } as unknown as AiPayload,
    };
  }
  return { allowed: true, payload: base as unknown as AiPayload };
}

function sanitizeDetails(details: Record<string, DetailValue>): Record<string, DetailValue> {
  const out: Record<string, DetailValue> = {};
  for (const [k, v] of Object.entries(details)) {
    if (typeof v === "string") {
      if (v.length <= METADATA_MAX_STRING_LENGTH && !v.includes("\n")) out[k] = v;
    } else if (Array.isArray(v)) {
      out[k] = v.filter((s) => s.length <= METADATA_MAX_STRING_LENGTH && !s.includes("\n")).slice(0, 20);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function stripLineIfMetadataOnly(loc: Location, mode: AiMode): Location {
  // 行番号自体は機密ではないが、metadata_only では「どのファイルか」までに留める
  if (mode === "metadata_only" && loc.type === "file") return { type: "file", path: loc.path };
  return loc;
}
