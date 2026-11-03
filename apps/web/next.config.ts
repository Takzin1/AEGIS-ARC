import type { NextConfig } from "next";
import { STATIC_SECURITY_HEADERS } from "./lib/security-headers";

const nextConfig: NextConfig = {
  // 「X-Powered-By: Next.js」を出さない（web.version-disclosure を自分で満たす）
  poweredByHeader: false,
  reactStrictMode: true,
  transpilePackages: ["@whiteknight/core", "@whiteknight/rules"],
  async headers() {
    return [{ source: "/:path*", headers: [...STATIC_SECURITY_HEADERS] }];
  },
};

export default nextConfig;
