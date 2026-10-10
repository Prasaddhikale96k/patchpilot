/** @type {import('next').NextConfig} */
const nextConfig = {
  // NOTE: NEXT_PUBLIC_* values are inlined into client JS at BUILD time.
  // Rebuild (`npm run build`) after changing them; a stale build silently
  // keeps calling the old backend. See frontend/.env.example.
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
    NEXT_PUBLIC_WS_URL:  process.env.NEXT_PUBLIC_WS_URL  || "ws://localhost:8000",
  },
  transpilePackages: ["@vladmandic/face-api", "@tensorflow-models/coco-ssd"],
  webpack: (config, { isServer }) => {
    // Required for MediaPipe WASM modules
    config.experiments = { ...config.experiments, asyncWebAssembly: true }

    config.ignoreWarnings = [
      { module: /@vladmandic\/face-api/ },
      { module: /@tensorflow/ },
      { module: /@mediapipe/ },
    ]

    if (!isServer) {
      config.resolve.alias = {
        ...config.resolve.alias,
        "@tensorflow/tfjs-backend-wasm": false,
        "@tensorflow/tfjs-node": false,
        "@tensorflow/tfjs-node-gpu": false,
      }
    }
    return config
  },
}

module.exports = nextConfig
