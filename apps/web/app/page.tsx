import { AI_MODE_LABELS_JA, AI_MODES, type RuleCategory } from "@whiteknight/core";
import { RULES } from "@whiteknight/rules";
import { connection } from "next/server";

const CATEGORY_LABELS: Record<RuleCategory, string> = {
  secret: "パスワードや鍵の書き込み",
  dependency: "弱点が知られている部品",
  file: "入れてはいけないファイル",
  config: "危険な設定",
  "web-header": "Webサイトの守りの設定",
  tls: "証明書と暗号化通信",
  exposure: "公開されてはいけないファイル",
};

export default async function Home() {
  // nonce 付き CSP のため、リクエストごとに描画する
  await connection();

  const counts = new Map<RuleCategory, number>();
  for (const r of RULES) counts.set(r.category, (counts.get(r.category) ?? 0) + 1);

  return (
    <main className="page">
      <header className="hero">
        <p className="eyebrow">WhiteKnight（開発中）</p>
        <h1>自分たちのWebサイトとGitHubの弱点を、専門家がいなくても見つけて直せる。</h1>
        <p className="lead">
          中小企業・自治体・大学研究室のための、やさしい日本語のセキュリティ診断です。
          「何が問題か」「どう直すか」を、専門用語を使わずにお伝えします。
        </p>
      </header>

      <section aria-labelledby="can">
        <h2 id="can">できること</h2>
        <ul className="cards">
          <li>
            <h3>GitHubリポジトリの診断</h3>
            <p>パスワードや鍵の書き込み、弱点のある部品、危険な設定を見つけます。</p>
          </li>
          <li>
            <h3>Webサイトの診断</h3>
            <p>守りの設定（セキュリティヘッダ）、証明書、公開されてはいけないファイルを確認します。</p>
          </li>
          <li>
            <h3>定期診断とお知らせ</h3>
            <p>決まった間隔で自動的に診断し、新しい問題が見つかったときだけメールやチャットでお知らせします。</p>
          </li>
        </ul>
      </section>

      <section aria-labelledby="cannot">
        <h2 id="cannot">やらないこと</h2>
        <ul className="plain">
          <li>
            <strong>他人のサイトやリポジトリは診断しません。</strong>
            ドメインはDNSかファイル設置で、リポジトリはGitHubの権限で、あなたが管理していることを確認してから診断します。
          </li>
          <li>
            <strong>攻撃を試すことはしません。</strong>
            設定の読み取りやバージョンの照合など、相手に負担をかけない方法だけを使います。
          </li>
          <li>
            <strong>見つけたパスワードや鍵をそのまま保存しません。</strong>伏せ字にした形でだけ記録します。
          </li>
        </ul>
      </section>

      <section aria-labelledby="ai">
        <h2 id="ai">AIの使い方は選べます（最初は「使わない」）</h2>
        <ol className="modes">
          {AI_MODES.map((mode) => (
            <li key={mode} data-default={mode === "off" ? "true" : undefined}>
              <h3>{AI_MODE_LABELS_JA[mode].title}</h3>
              <p>{AI_MODE_LABELS_JA[mode].description}</p>
            </li>
          ))}
        </ol>
        <p className="note">
          AIを使わない設定でも、診断と「どう直すか」の説明はすべて表示されます。
          自治体向けの設置では、外部AIへコードを送らない設定をシステム全体で強制できます。
        </p>
      </section>

      <section aria-labelledby="rules">
        <h2 id="rules">調べる項目（{RULES.length}項目）</h2>
        <ul className="rule-counts">
          {[...counts.entries()].map(([cat, n]) => (
            <li key={cat}>
              <span>{CATEGORY_LABELS[cat]}</span>
              <span className="count">{n}</span>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
