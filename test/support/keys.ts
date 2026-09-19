import { DerivedKeys, parseMasterKeys } from "../../src/crypto/master-keys.ts";
import testEnv from "./test-env.json" with { type: "json" };

// Deterministic master-key material for tests, shared with vitest.workers.config.ts
// through test-env.json. Never used outside the test suite.

export const TEST_ENV = testEnv;
export const TEST_MASTER_KEYS = testEnv.MASTER_KEYS;

export function testKeys(active = "1", masterKeys = TEST_MASTER_KEYS): DerivedKeys {
  const parsed = parseMasterKeys(masterKeys, active);
  if (!parsed.ok) throw new Error(parsed.error);
  return new DerivedKeys(parsed.keys);
}

/** A key set that knows only version 1, to simulate a retired version 2 (TIO-ARCH-008). */
export function keysWithoutVersion2(): DerivedKeys {
  const only1 = JSON.stringify({
    "1": (JSON.parse(TEST_MASTER_KEYS) as Record<string, string>)["1"],
  });
  return testKeys("1", only1);
}
