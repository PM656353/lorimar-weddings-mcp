import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:workers": fileURLToPath(
        new URL("./fake-workers.ts", import.meta.url)
      )
    }
  },
  test: {
    server: { deps: { inline: ["@cloudflare/workers-oauth-provider"] } },
    include: ["tests/security.test.ts"],
    environment: "node"
  }
});
