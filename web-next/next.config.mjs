/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static HTML for FastAPI/aio hosting on :8080 (no Node process at runtime).
  output: "export",
  async rewrites() {
    // Applied by `next dev` only; ignored for `output: "export"` production builds.
    const target = process.env.API_PROXY_TARGET || "http://127.0.0.1:8080";
    return [
      {
        source: "/api/:path*",
        destination: `${target}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
