import { applyD1Migrations, env } from "cloudflare:test";

// Runs once per workers test file (storage is isolated per file): apply the
// D1 migrations so every suite starts from the real schema.
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
