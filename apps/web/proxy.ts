import { NextResponse, type NextRequest } from "next/server";
import { buildCsp, generateNonce } from "./lib/security-headers";

/** ページごとに新しい nonce を作り、CSP を付ける（Next.js が自動でスクリプトに nonce を付与する） */
export function proxy(request: NextRequest) {
  const nonce = generateNonce();
  const csp = buildCsp(nonce, { dev: process.env.NODE_ENV === "development" });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
