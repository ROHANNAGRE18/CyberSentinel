/** @type {import('next').NextConfig} */
const nextConfig = {
  // Strict mode helps catch issues early in development
  reactStrictMode: true,

  // Proxy /api/* requests to the FastAPI backend during development.
  // In production, configure your reverse proxy (nginx / Caddy) instead.
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000"}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
