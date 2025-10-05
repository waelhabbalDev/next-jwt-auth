import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/index.client.tsx"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  external: ["react"],

  // Pass esbuild-specific options here
  esbuildOptions(options) {
    // This is the correct way to configure JSX in modern tsup
    options.jsx = "automatic";
    return options;
  },
});
