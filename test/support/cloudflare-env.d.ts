import type { D1Migration } from "cloudflare:test";
import type { Env } from "../../src/env.ts";

// `cloudflare:test` types `env` as `Cloudflare.Env`. The single declaration of
// the bindings lives in src/env.ts (TIO-CFG-005); this augmentation only adds
// the test-only migrations binding injected by vitest.workers.config.ts.
type TioEnv = Env;

declare global {
  namespace Cloudflare {
    interface Env extends TioEnv {
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}
