import { describe, expect, it } from "vitest";
import { newInteractionId } from "../../src/crypto/random.ts";
import { interactionStub, startInteraction } from "../../src/oidc/interactions.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";

describe("startInteraction", () => {
  it("creates the document with the binding hash and refuses to overwrite an existing id", async () => {
    const id = newInteractionId();
    const input = {
      kind: "authorize" as const,
      status: "login_required" as const,
      client_id: "web",
    };
    const started = await startInteraction(env, testKeys(), id, input, 1_800_000_000, 600);
    expect(started.id).toBe(id);
    expect(started.cookie).toMatch(/^__Host-tio_ix_.{16}=tio_ix_/);
    const doc = await interactionStub(env, id).get(1_800_000_000);
    expect(doc.ok && doc.doc.binding_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(startInteraction(env, testKeys(), id, input, 1_800_000_000, 600)).rejects.toThrow(
      "interaction interaction_exists",
    );
  });
});
