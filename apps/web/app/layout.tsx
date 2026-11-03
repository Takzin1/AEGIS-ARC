import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "WhiteKnight｜自分たちのWebとGitHubを守るセキュリティ診断",
  description:
    "中小企業・自治体・大学研究室が、自分で管理するWebサイトとGitHubリポジトリの弱点を、専門家がいなくても見つけて直せる診断ツール。",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="ja">
      <body>{children}</body>
    </html>
  );
}
