import { isSeverity } from "./severity";
import type { RuleMeta } from "./types";

const RULE_ID_PATTERN = /^[a-z]+(\.[a-z0-9]+(-[a-z0-9]+)*)+$/;

/** ルール定義の一覧。ID の重複や書式の誤りは作成時に例外にする（起動時に気付けるように）。 */
export class RuleCatalog {
  private readonly rules = new Map<string, RuleMeta>();

  constructor(rules: readonly RuleMeta[]) {
    for (const rule of rules) {
      if (!RULE_ID_PATTERN.test(rule.id)) {
        throw new Error(`ルールIDの書式が不正です: "${rule.id}"（例: secret.aws-access-key）`);
      }
      if (!isSeverity(rule.defaultSeverity)) {
        throw new Error(`ルール ${rule.id} の危険度が不正です: ${String(rule.defaultSeverity)}`);
      }
      if (this.rules.has(rule.id)) {
        throw new Error(`ルールIDが重複しています: ${rule.id}`);
      }
      this.rules.set(rule.id, rule);
    }
  }

  get(id: string): RuleMeta | undefined {
    return this.rules.get(id);
  }

  require(id: string): RuleMeta {
    const rule = this.rules.get(id);
    if (!rule) throw new Error(`未登録のルールIDです: ${id}`);
    return rule;
  }

  ids(): string[] {
    return [...this.rules.keys()];
  }

  all(): RuleMeta[] {
    return [...this.rules.values()];
  }
}
