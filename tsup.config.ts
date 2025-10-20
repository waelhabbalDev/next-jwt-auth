import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/server/index.ts",
    client: "src/client/index.tsx",
  },
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  external: ["react"],

  esbuildOptions(options) {
    options.jsx = "automatic";
    return options;
  },
});
