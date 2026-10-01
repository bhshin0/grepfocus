import { defineConfig } from "vitest/config";

// Unit tests over the pure modules in src/logic (no DOM, no Tauri), so the
// node environment is enough. `pnpm build` (tsc -noEmit, include: src) type
// checks the test files too.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
