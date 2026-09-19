import { describe, expect, it } from "vitest";
import { handleType } from "../../src/crypto/envelope.ts";
import { sha256 } from "../../src/crypto/hash.ts";
import { newInteractionId, newSecret } from "../../src/crypto/random.ts";
import {
  openBindingHandle,
  openCodeHandle,
  openSessionHandle,
  sealBindingHandle,
  sealCodeHandle,
  sealSessionHandle,
} from "../../src/oidc/handles.ts";
import { testKeys } from "../support/keys.ts";

const keys = testKeys();
const UID = "0192abcd-1234-7000-8000-000000000001";
const SID = "0192abcd-1234-7000-8000-000000000002";

describe("protocol handles", () => {
  it("[TIO-ARCH-007] session, code and binding handles open to their ids and the SHA-256 of the secret, never the secret", async () => {
    const secret = newSecret();
    const hash = await sha256(secret);
    const session = await sealSessionHandle(keys, UID, SID, secret);
    expect(handleType(session)).toBe("session");
    expect(await openSessionHandle(keys, session)).toEqual({
      uid: UID,
      sid: SID,
      secret_hash: hash,
    });
    const code = await sealCodeHandle(keys, UID, secret);
    expect(handleType(code)).toBe("code");
    expect(await openCodeHandle(keys, code)).toEqual({ uid: UID, secret_hash: hash });
    const id = newInteractionId();
    const binding = await sealBindingHandle(keys, id, secret);
    expect(handleType(binding)).toBe("interaction");
    expect(await openBindingHandle(keys, binding)).toEqual({
      interaction_id: id,
      secret_hash: hash,
    });
    // A handle of one type never opens as another, and garbage opens as nothing.
    expect(await openSessionHandle(keys, code)).toBeNull();
    expect(await openCodeHandle(keys, session)).toBeNull();
    expect(await openBindingHandle(keys, session)).toBeNull();
    expect(await openSessionHandle(keys, "tio_ss_nope")).toBeNull();
    expect(await openCodeHandle(keys, "")).toBeNull();
    expect(await openBindingHandle(keys, "tio_ix_")).toBeNull();
  });

  it("refuses to seal ids that are not UUIDs or interaction ids", async () => {
    const secret = newSecret();
    await expect(sealSessionHandle(keys, "user-1", SID, secret)).rejects.toThrow("not a UUID");
    await expect(sealSessionHandle(keys, UID, "sid-1", secret)).rejects.toThrow("not a UUID");
    await expect(sealCodeHandle(keys, "nope", secret)).rejects.toThrow("not a UUID");
    await expect(sealBindingHandle(keys, "short", secret)).rejects.toThrow("not an interaction id");
    await expect(sealBindingHandle(keys, "!".repeat(43), secret)).rejects.toThrow(
      "not an interaction id",
    );
  });
});
