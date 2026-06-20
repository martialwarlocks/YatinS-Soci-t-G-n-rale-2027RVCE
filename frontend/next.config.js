/** @type {import('next').NextConfig} */
const nextConfig = {
  // Standalone only for Docker builds; breaks `next start` locally otherwise
  ...(process.env.DOCKER_BUILD === "true" ? { output: "standalone" } : {}),
};

module.exports = nextConfig;
