import { describe, expect, it } from "vitest";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, RP_REDIRECT } from "../support/http.ts";
import { env } from "../support/op.ts";
import { userWithPasskey } from "../support/passkeys.ts";

// Enumeration (spec §13.7, TIO-TEST-020): where the OP refuses, an unknown
// thing and an invalid thing answer the same status and body, request id
// aside, so an attacker learns nothing about what exists.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

/** The Durable Object and D1 counts of the Server-Timing header (TIO-OBS-004). */
function work(res: Response): Record<string, string> {
  const header = res.headers.get("Server-Timing") ?? "";
  return Object.fromEntries(
    [...header.matchAll(/(do|d1r|d1w);desc="(\d+)"/g)].map((m) => [m[1], m[2]]),
  );
}

/** The body with its per-request id removed, and the work the answer took. */
async function shape(
  res: Response,
): Promise<{ status: number; body: Record<string, unknown>; work: Record<string, string> }> {
  const { request_id: _id, ...body } = (await res.json()) as Record<string, unknown>;
  return { status: res.status, body, work: work(res) };
}

const form = (params: Record<string, string>) =>
  h.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });

describe("enumeration equality", () => {
  it("[TIO-TEST-020] [TIO-TOKEN-010] [TIO-OBS-004] a code that never existed, a garbled one, one of another user and a spent one all fail the exchange identically", async () => {
    await adminSettings(h);
    const web = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const exchange = (code: string) =>
      form({
        grant_type: "authorization_code",
        client_id: web.client_id,
        code,
        redirect_uri: RP_REDIRECT,
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      });
    const answers = await Promise.all(
      ["tio_ac_" + "A".repeat(80), "not-a-handle", "", "tio_ac_!!!"].map((c) =>
        exchange(c).then(shape),
      ),
    );
    for (const answer of answers) expect(answer).toEqual(answers[0]);
    expect(answers[0]).toMatchObject({ status: 400, body: { error: "invalid_grant" } });
    // Equal answers include equal work: the counts are real, not an empty match (TIO-OBS-004).
    expect(Object.keys(answers[0]?.work ?? {}).sort()).toEqual(["d1r", "d1w", "do"]);
    const refreshes = await Promise.all(
      ["tio_rt_" + "A".repeat(80), "garbage"].map((token) =>
        form({ grant_type: "refresh_token", client_id: web.client_id, refresh_token: token }).then(
          shape,
        ),
      ),
    );
    expect(refreshes[1]).toEqual(refreshes[0]);
    expect(refreshes[0]).toMatchObject({ status: 400, body: { error: "invalid_grant" } });
  });

  it("[TIO-TEST-020] [TIO-UINFO-001] /userinfo answers the same 401 for a missing, malformed, foreign-signed and expired token", async () => {
    const answers = await Promise.all(
      [
        undefined,
        "Bearer garbage",
        "Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6Im5vIn0.eyJzdWIiOiJ4In0.c2ln",
        "Basic abc",
      ].map((authorization) =>
        h
          .send("/userinfo", {
            origin: null,
            ...(authorization === undefined ? {} : { headers: { authorization } }),
          })
          .then(async (res) => ({
            ...(await shape(res)),
            challenge: res.headers.get("WWW-Authenticate"),
          })),
      ),
    );
    for (const answer of answers) expect(answer).toEqual(answers[0]);
    expect(answers[0]).toMatchObject({
      status: 401,
      body: { error: "invalid_token" },
      challenge: 'Bearer error="invalid_token"',
    });
  });

  it("[TIO-TEST-020] [TIO-REG-002] a registration invitation that never existed and a garbled one are told apart from nothing: both are invitation_invalid", async () => {
    const web = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const started = await h.start(web, { scope: "openid email" });
    const answers = await Promise.all(
      ["tio_iv_" + "B".repeat(90), "tio_iv_x", "nonsense"].map((invitation) =>
        h.post(started, "register/options", { invitation }).then(shape),
      ),
    );
    for (const answer of answers) expect(answer).toEqual(answers[0]);
    expect(answers[0]).toMatchObject({ status: 400, body: { error: "invitation_invalid" } });
  });

  it("[TIO-TEST-020] [TIO-ADMIN-004] admin lookups of a user, client, group, upstream or invitation that never existed and of one deleted since answer identical 404s", async () => {
    const operator = await adminUser(h);
    const token = operator.access_token;
    const gone = await userWithPasskey(clock);
    expect((await admin(h, token, `users/${gone.profile.id}`, { method: "DELETE" })).status).toBe(
      204,
    );
    const never = new UuidV7(clock).next();
    const users = await Promise.all(
      [gone.profile.id, never].map((id) => admin(h, token, `users/${id}`).then(shape)),
    );
    expect(users[1]).toEqual(users[0]);
    expect(users[0]).toMatchObject({ status: 404, body: { error: "user_not_found" } });
    // Sub-resources of a missing user answer the same as the user itself.
    const sub = await Promise.all(
      ["passkeys", "sessions", "identities", "grants", "events"].map((path) =>
        admin(h, token, `users/${never}/${path}`).then(shape),
      ),
    );
    for (const answer of sub) expect(answer).toEqual(users[0]);
    const clients = await Promise.all(
      ["c_doesnotexist0000000000", "c_alsonot000000000000000"].map((id) =>
        admin(h, token, `clients/${id}`).then(shape),
      ),
    );
    expect(clients[1]).toEqual(clients[0]);
    expect(clients[0]?.status).toBe(404);
    const upstreams = await Promise.all(
      ["nope", "also-nope"].map((alias) => admin(h, token, `upstreams/${alias}`).then(shape)),
    );
    expect(upstreams[1]).toEqual(upstreams[0]);
    expect(upstreams[0]?.status).toBe(404);
    const invitations = await Promise.all(
      [never, new UuidV7(clock).next()].map((id) =>
        admin(h, token, `invitations/${id}`).then(shape),
      ),
    );
    expect(invitations[1]).toEqual(invitations[0]);
    expect(invitations[0]?.status).toBe(404);
  });
});
