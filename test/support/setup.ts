import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";

// Runs once per workers test file (storage is isolated per file): apply the
// D1 migrations so every suite starts from the real schema.
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
