import { describe, expect, it } from "vitest";
import { KeyStore } from "../../src/crypto/keystore.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { listSigningKeys } from "../../src/db/keys.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { harness, LOGIN_ORIGIN } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";

// Exactly-once for the steps that create something singular (TIO-TEST-010):
// the first signing key on an empty store, the bootstrap, a user behind a
// verified email, and the holder of an upstream identity pair. 20 racing
// attempts, one winner, the specified answer for the rest.

const PARALLEL = 20;
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

describe("exactly-once creation", () => {
  it("[TIO-TEST-010] [TIO-KEYS-014] 20 isolates loading keys from an empty store create exactly one signing key and all sign with it", async () => {
    expect(await listSigningKeys(db)).toEqual([]);
    // One KeyStore per isolate: nothing but D1 coordinates them.
    const stores = Array.from({ length: PARALLEL }, () => new KeyStore(clock));
    const loaded = await Promise.all(stores.map((store) => store.get(db, testKeys())));
    const rows = await listSigningKeys(db);
    expect(rows).toHaveLength(1);
    const kid = rows[0]?.kid;
    for (const keys of loaded) {
      expect(keys.signing.kid).toBe(kid);
      expect(keys.jwks.keys.map((k) => k.kid)).toEqual([kid]);
    }
  });

  it("[TIO-TEST-010] [TIO-ADMIN-010] 20 parallel bootstraps with the right token: one 201 with an invitation, the rest 410, and exactly one admin invitation exists", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    const attempt = () =>
      h.send("/api/v1/admin/bootstrap", {
        method: "POST",
        origin: null,
        headers: { authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN as string}` },
        body: { email: "root@example.com" },
      });
    const answers = await Promise.all(Array.from({ length: PARALLEL }, attempt));
    const statuses = answers.map((r) => r.status).sort();
    expect(statuses).toEqual([201, ...Array<number>(PARALLEL - 1).fill(410)]);
    const winner = answers.find((r) => r.status === 201) as Response;
    const body = (await winner.json()) as { invitation: string };
    expect(body.invitation).toMatch(/^tio_iv_/);
    for (const loser of answers.filter((r) => r.status === 410)) {
      expect(await loser.json()).toMatchObject({ error: "bootstrap_completed" });
    }
    const invitations = await db
      .prepare("SELECT COUNT(*) AS n FROM invitations WHERE created_by = 'bootstrap'")
      .first<{ n: number }>();
    expect(invitations?.n).toBe(1);
    // Nothing else raced: one admin-cli client, and a later call is 410 without side effects.
    const clients = await db
      .prepare("SELECT COUNT(*) AS n FROM clients WHERE client_id = 'admin-cli'")
      .first<{ n: number }>();
    expect(clients?.n).toBe(1);
    expect((await attempt()).status).toBe(410);
  });

  it("[TIO-TEST-010] [TIO-DATA-008] 20 parallel creations of a user with the same verified email: one 201, the rest 409 email_taken, one row", async () => {
    await adminSettings(h);
    const operator = await adminUser(h);
    const email = "shared@example.com";
    const answers = await Promise.all(
      Array.from({ length: PARALLEL }, () =>
        admin(h, operator.access_token, "users", {
          method: "POST",
          body: { email, email_verified: true, display_name: "Shared" },
        }),
      ),
    );
    expect(answers.map((r) => r.status).sort()).toEqual([
      201,
      ...Array<number>(PARALLEL - 1).fill(409),
    ]);
    for (const loser of answers.filter((r) => r.status === 409)) {
      expect(await loser.json()).toMatchObject({ error: "email_taken" });
    }
    const rows = await db
      .prepare("SELECT COUNT(*) AS n FROM users WHERE email_norm = ?")
      .bind(email)
      .first<{ n: number }>();
    expect(rows?.n).toBe(1);
  });

  it("[TIO-TEST-010] [TIO-FED-041] 20 parallel creations of users each linking the same (issuer, subject): one 201, the rest 409 identity_already_linked, one index row", async () => {
    const operator = await adminUser(h);
    const uuids = new UuidV7(clock);
    const identity = { issuer: "https://idp.example.com", subject: `sub-${uuids.next()}` };
    const answers = await Promise.all(
      Array.from({ length: PARALLEL }, (_, i) =>
        admin(h, operator.access_token, "users", {
          method: "POST",
          body: {
            email: `person-${i}@example.com`,
            email_verified: true,
            identities: [identity],
          },
        }),
      ),
    );
    expect(answers.map((r) => r.status).sort()).toEqual([
      201,
      ...Array<number>(PARALLEL - 1).fill(409),
    ]);
    for (const loser of answers.filter((r) => r.status === 409)) {
      expect(await loser.json()).toMatchObject({ error: "identity_already_linked" });
    }
    const index = await db
      .prepare("SELECT user_id FROM identity_index WHERE issuer = ? AND subject = ?")
      .bind(identity.issuer, identity.subject)
      .all<{ user_id: string }>();
    expect(index.results).toHaveLength(1);
    const winner = (await (answers.find((r) => r.status === 201) as Response).json()) as {
      id: string;
    };
    expect(index.results[0]?.user_id).toBe(winner.id);
    // The losers left no half-created account behind: their rows never became visible.
    const visible = await db
      .prepare(
        "SELECT COUNT(*) AS n FROM users WHERE email_norm LIKE 'person-%' AND status = 'active'",
      )
      .first<{ n: number }>();
    expect(visible?.n).toBe(1);
  });
});
