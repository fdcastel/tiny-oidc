import { describe, expect, it } from "vitest";
import { HeaderTooLargeError, MAX_HEADER_BYTES, signJwt } from "../../src/crypto/jwt.ts";
import { deriveRoles, roleOf } from "../../src/crypto/keystore.ts";
import type { SigningKeyRow } from "../../src/db/keys.ts";

const row = (
  kid: string,
  activates_at: number,
  created_at = activates_at,
  retired_at: number | null = null,
): SigningKeyRow => ({
  kid,
  alg: "ES256",
  public_jwk: "{}",
  private_jwk_enc: retired_at === null ? new Uint8Array(1) : null,
  created_at,
  activates_at,
  retired_at,
});

describe("key roles (§10.3)", () => {
  it("[TIO-KEYS-012] derives signing, next, verifying and retired from the timestamps, with deterministic tie-breaks", () => {
    const now = 1_000;
    const rows = [row("a", 100), row("b", 500), row("c", 2_000), row("d", 50, 50, 900)];
    const roles = deriveRoles(rows, now);
    expect(roles.signing?.kid).toBe("b");
    expect(roles.verifying.map((r) => r.kid)).toEqual(["a"]);
    expect(roles.next.map((r) => r.kid)).toEqual(["c"]);
    expect(roles.retired.map((r) => r.kid)).toEqual(["d"]);
    expect(roleOf(rows[0] as SigningKeyRow, now, 500)).toBe("verifying");
    expect(roleOf(rows[1] as SigningKeyRow, now, 500)).toBe("signing");
    expect(roleOf(rows[2] as SigningKeyRow, now, 500)).toBe("next");
    expect(roleOf(rows[3] as SigningKeyRow, now, 500)).toBe("retired");
    // Equal activation instants: the newer row signs; equal creation instants: the greater kid.
    expect(deriveRoles([row("x", 500, 400), row("y", 500, 450)], now).signing?.kid).toBe("y");
    expect(deriveRoles([row("y", 500, 450), row("x", 500, 400)], now).signing?.kid).toBe("y");
    expect(deriveRoles([row("m", 500, 400), row("n", 500, 400)], now).signing?.kid).toBe("n");
    expect(deriveRoles([row("n", 500, 400), row("m", 500, 400)], now).signing?.kid).toBe("n");
    expect(deriveRoles([row("p", 500, 400), row("q", 500, 399)], now).signing?.kid).toBe("p");
    expect(deriveRoles([], now).signing).toBeNull();
    expect(deriveRoles([row("z", 5_000)], now)).toEqual({
      signing: null,
      next: [rows[0] && row("z", 5_000)],
      verifying: [],
      retired: [],
    });
  });
});

describe("JOSE header bound", () => {
  it("[TIO-KEYS-015] signing refuses a header over 512 bytes", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const loaded = {
      signing: { kid: "k".repeat(600), privateKey: pair.privateKey },
      jwks: { keys: [] },
      rows: [],
    };
    await expect(signJwt(loaded, "JWT", { sub: "u" })).rejects.toBeInstanceOf(HeaderTooLargeError);
    expect(MAX_HEADER_BYTES).toBe(512);
  });
});
