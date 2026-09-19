import type { D1Migration } from "cloudflare:test";
import type { Env } from "../../src/env.ts";

// `cloudflare:workers` types `env` as `Cloudflare.Env` and `exports` from
// `Cloudflare.GlobalProps`. The single declaration of the bindings lives in
// src/env.ts (TIO-CFG-005); this augmentation adds the test-only migrations
// binding injected by vitest.workers.config.ts and points `exports` at the
// Worker's main module.
type TioEnv = Env;

declare global {
  namespace Cloudflare {
    interface Env extends TioEnv {
      TEST_MIGRATIONS: D1Migration[];
    }
    interface GlobalProps {
      mainModule: typeof import("../../src/index.ts");
      durableNamespaces: "UserDO" | "InteractionDO";
    }
  }
}
