import { defineConfig } from "vitest/config";

// Unit and property suites: pure functions, Node environment, no bindings.
export default defineConfig({
  test: {
    name: "unit",
    environment: "node",
    include: ["test/unit/**/*.test.ts", "test/property/**/*.test.ts"],
  },
});
