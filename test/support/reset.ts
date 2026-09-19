import { applyD1Migrations, reset } from "cloudflare:test";
import { env } from "cloudflare:workers";

/**
 * Per-file storage isolation is the default (TIO-TEST-004); files that need a
 * clean store between tests call this from `beforeEach`. `reset()` wipes every
 * binding (D1 rows, Durable Objects and their storage, Queues, R2); the D1
 * migrations are then re-applied so the schema is present again. Stubs
 * obtained before the reset are invalid afterwards.
 */
export async function resetStorage(): Promise<void> {
  await reset();
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
}
