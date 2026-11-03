import {
  AI_MODE_LABELS_JA,
  SEVERITIES,
  type CheckerError,
  type Finding,
  type ResolvedAiPolicy,
} from "@whiteknight/core";
import { describeDetailJa, describeLocationJa, ruleTextJa, SEVERITY_LABELS_JA } from "./ja";

export interface ReportInput {
  /** 例："github.com/example/site" や "www.example.lg.jp" */
  targetLabel: string;
  scannedAt: Date;
  findings: readonly Finding[];
  errors?: readonly CheckerError[];
  /** 今回初めて（または再発で）見つかった指摘の fingerprint */
  newFingerprints?: ReadonlySet<string>;
  aiPolicy: ResolvedAiPolicy;
}

/**
 * ルールの日本語テンプレートだけで、完結したレポート（Markdown）を作る。
 * 外部 AI を一切使わない。AI を使う場合も、このレポートが土台になる。
 */
export function renderMarkdownReport(input: ReportInput): string {
  const out: string[] = [];
  out.push(`# セキュリティ診断レポート：${escapeText(input.targetLabel)}`, "");
  out.push(`診断日時：${formatJst(input.scannedAt)}（日本時間）`, "");

  // ── まとめ ──
  out.push("## まとめ", "");
  if (input.findings.length === 0) {
    out.push(
      "今回の診断では、問題は見つかりませんでした。",
      "",
      "※ この診断で調べられる範囲には限りがあり、「問題がまったくない」ことを保証するものではありません。",
      "",
    );
  } else {
    out.push("| 危険度 | 件数 |", "| --- | ---: |");
    for (const sev of SEVERITIES) {
      const n = input.findings.filter((f) => f.severity === sev).length;
      if (n > 0) out.push(`| ${SEVERITY_LABELS_JA[sev].icon} ${SEVERITY_LABELS_JA[sev].label} | ${n} |`);
    }
    out.push("");
    const newCount = input.findings.filter((f) => input.newFingerprints?.has(f.fingerprint)).length;
    if (input.newFingerprints && newCount > 0) out.push(`このうち **${newCount} 件** は今回新しく見つかったものです。`, "");
    out.push("上から順に（危ないものから）対応してください。", "");
  }

  if (input.errors && input.errors.length > 0) {
    out.push("## 一部の項目は診断できませんでした", "");
    out.push("次の項目は、通信の失敗などで診断を完了できませんでした。時間をおいてもう一度診断してください。", "");
    for (const e of input.errors) out.push(`- ${inlineCode(e.checkerId)}：${escapeText(e.message)}`);
    out.push("");
  }

  // ── 指摘 ──
  if (input.findings.length > 0) {
    out.push("## 指摘の一覧", "");
    input.findings.forEach((f, i) => {
      const text = ruleTextJa(f.ruleId);
      const sev = SEVERITY_LABELS_JA[f.severity];
      const badge = input.newFingerprints?.has(f.fingerprint) ? " 🆕新規" : "";
      out.push(`### ${i + 1}. ${sev.icon} ${sev.label}｜${escapeText(text.title)}${badge}`, "");
      out.push(`- **場所**：${inlineCode(describeLocationJa(f.location))}`);
      if (f.evidenceMasked) out.push(`- **見つかった値（一部を伏せ字にしています）**：${inlineCode(f.evidenceMasked)}`);
      for (const [k, v] of Object.entries(f.details)) {
        const d = describeDetailJa(k, v);
        out.push(`- **${escapeText(d.label)}**：${escapeText(d.value)}`);
      }
      out.push("", `**何が問題？**\u3000${text.what}`, "", `**何が起きうる？**\u3000${text.why}`, "");
      if (text.analogy) out.push(`> たとえるなら：${text.analogy}`, "");
      out.push("**どう直す？**", "");
      text.how.forEach((step, n) => out.push(`${n + 1}. ${step}`));
      out.push("");
      if (text.references && text.references.length > 0) {
        out.push(`詳しい情報：${text.references.map((r) => `[${escapeText(r.label)}](${r.url})`).join("、")}`, "");
      }
    });
  }

  // ── このレポートについて ──
  out.push("---", "", "## このレポートについて", "");
  out.push(`- **外部AIの利用**：${aiUsageStatement(input.aiPolicy)}`);
  out.push(
    "- **診断の方法**：設定の読み取り、応答ヘッダの確認、部品のバージョン照合など、相手に負担をかけない方法だけを使っています。攻撃を試すような操作は一切していません。",
    "- **秘密情報の扱い**：見つかったパスワードや鍵は、伏せ字にした形でだけ保存・表示しています。",
    "",
  );
  return out.join("\n");
}

export function aiUsageStatement(policy: ResolvedAiPolicy): string {
  const capped = policy.cappedByInstance ? "（この設置環境の設定により、外部AIの利用は制限されています）" : "";
  switch (policy.mode) {
    case "off":
      return `使っていません。このレポートはルールに基づく診断結果だけで作成しました。外部のAIサービスには、コードも診断結果も送っていません。${capped}`;
    case "metadata_only":
    case "with_code":
      return `${AI_MODE_LABELS_JA[policy.mode].title}。${AI_MODE_LABELS_JA[policy.mode].description}${capped}`;
  }
}

function formatJst(d: Date): string {
  return new Intl.DateTimeFormat("ja-JP", {
    timeZone: "Asia/Tokyo",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(d);
}

/** 利用者のリポジトリ由来の文字列（パス名など）で Markdown が崩れたり、リンクを埋め込まれたりしないようにする */
function escapeText(s: string): string {
  return s.replace(/[\\`*_[\]<>|#]/g, (c) => `\\${c}`).replace(/\r?\n/g, " ");
}

function inlineCode(s: string): string {
  const oneLine = s.replace(/\r?\n/g, " ");
  const longestRun = Math.max(0, ...(oneLine.match(/`+/g) ?? []).map((m) => m.length));
  const fence = "`".repeat(longestRun + 1);
  const pad = oneLine.startsWith("`") || oneLine.endsWith("`") ? " " : "";
  return `${fence}${pad}${oneLine}${pad}${fence}`;
}
