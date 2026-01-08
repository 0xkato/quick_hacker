/** @type {import('next').NextConfig} */
const nextConfig = {
  // Disable StrictMode in dev - causes WebSocket double-connect issues
  // Re-enable for production testing
  reactStrictMode: false,
  // For Monaco Editor
  webpack: (config) => {
    config.resolve.fallback = { fs: false, path: false };
    return config;
  },
};

module.exports = nextConfig;
