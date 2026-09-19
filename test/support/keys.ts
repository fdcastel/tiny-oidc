import { DerivedKeys, parseMasterKeys } from "../../src/crypto/master-keys.ts";

// Deterministic master-key material for tests. Never used outside the test suite.

const BASE64_ONE = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="; // 32 × 0x01
const BASE64_TWO = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="; // 32 × 0x02

export const TEST_MASTER_KEYS = JSON.stringify({ "1": BASE64_ONE, "2": BASE64_TWO });

export function testKeys(active = "1", masterKeys = TEST_MASTER_KEYS): DerivedKeys {
  const parsed = parseMasterKeys(masterKeys, active);
  if (!parsed.ok) throw new Error(parsed.error);
  return new DerivedKeys(parsed.keys);
}

/** A key set that knows only version 1, to simulate a retired version 2 (TIO-ARCH-008). */
export function keysWithoutVersion2(): DerivedKeys {
  return testKeys("1", JSON.stringify({ "1": BASE64_ONE }));
}
