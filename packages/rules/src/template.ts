/**
 * 1 ルール分の「やさしい日本語」の説明。
 * 方針：専門用語は使わない。使う場合は「用語（＝言い換え）」の形で併記する。
 */
export interface RuleText {
  /** 一言で。レポートの見出しになる。「〜状態です」「〜があります」で終える */
  title: string;
  /** 何が問題？（事実） */
  what: string;
  /** 何が起きうる？（影響。脅しすぎない） */
  why: string;
  /** どう直す？（順番どおりに実行できる手順） */
  how: readonly string[];
  /** 身近なたとえ（任意） */
  analogy?: string;
  /** 詳しい人向けの参考情報（任意） */
  references?: readonly { label: string; url: string }[];
}

export type RuleTextMap = Readonly<Record<string, RuleText>>;
