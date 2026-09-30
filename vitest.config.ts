import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["scripts/tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["scripts/*.ts"],
      reporter: ["text", "lcov"],
    },
  },
});
