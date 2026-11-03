import type { RuleText, RuleTextMap } from "../template";
import { repoTextsJa } from "./repo";
import { webTextsJa } from "./web";

export const RULE_TEXTS_JA: RuleTextMap = { ...repoTextsJa, ...webTextsJa };

export function ruleTextJa(ruleId: string): RuleText {
  const text = RULE_TEXTS_JA[ruleId];
  if (!text) throw new Error(`日本語テンプレートがありません: ${ruleId}`);
  return text;
}

export { SEVERITY_LABELS_JA, describeLocationJa, describeDetailJa } from "./labels";
