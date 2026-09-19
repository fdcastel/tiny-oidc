import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { createTestClient } from "../support/factories.ts";
import { FakeUpstream } from "../support/fake-upstream/index.ts";
import {
  IDP,
  IDP_CLIENT_ID,
  IDP_CLIENT_SECRET,
  mountFakeUpstream,
  registerUpstream,
} from "../support/federation.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT, type Started } from "../support/http.ts";
import { TEST_ENV } from "../support/keys.ts";
import { env } from "../support/op.ts";

// Exactly-once through the federation callback (TIO-TEST-010): one `state`
// presented 20 times, and 20 first logins of the same upstream person that
// all try to create the account behind one (issuer, subject).

const PARALLEL = 20;
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

let fake: FakeUpstream;
let web: Client;

interface Leg {
  started: Started;
  /** The OP's callback as the provider redirects to it (path and query). */
  callback: string;
}

/** Walks a federated login up to the provider's redirect back, without following it. */
async function prepareLeg(sub: string): Promise<Leg> {
  const started = await h.start(web, { scope: "openid email profile" });
  const begun = await h.post(started, "upstream/idp", {});
  if (begun.status !== 200) throw new Error(`upstream: ${begun.status}`);
  const authorizeUrl = new URL(((await begun.json()) as { redirect_to: string }).redirect_to);
  authorizeUrl.searchParams.set("x_sub", sub);
  const atProvider = await fake.handle(new Request(authorizeUrl.href));
  const back = new URL(atProvider.headers.get("location") as string);
  return { started, callback: `${back.pathname}${back.search}` };
}

const present = (leg: Leg) => h.send(leg.callback, { origin: null, cookie: leg.started.cookie });
const location = (res: Response) => res.headers.get("location") ?? "";

async function docOf(started: Started) {
  const got = await interactionStub(env, started.id).get(clock.now());
  if (!got.ok) throw new Error(got.error);
  return got.doc;
}

describe("exactly-once over the federation callback", () => {
  it("[TIO-TEST-010] [TIO-FED-020] 20 parallel callbacks with one state: one processed (the interaction authenticates once), the rest invalid_state", async () => {
    await writeSettings(
      db,
      {
        login_url: `${LOGIN_ORIGIN}/`,
        login_origins: [LOGIN_ORIGIN],
        "federation.auto_create": true,
      },
      "test",
      clock.now(),
    );
    fake = await FakeUpstream.create({
      issuer: IDP,
      client_id: IDP_CLIENT_ID,
      client_secret: IDP_CLIENT_SECRET,
      redirect_uris: [`${TEST_ENV.ISSUER}/federation/callback`],
      now: () => clock.now(),
    });
    mountFakeUpstream(fake);
    await registerUpstream(clock);
    web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true }))
      .client;
    const leg = await prepareLeg("alice");
    const answers = await Promise.all(Array.from({ length: PARALLEL }, () => present(leg)));
    for (const res of answers) expect(res.status).toBe(303);
    const targets = answers.map(location);
    const processed = targets.filter(
      (t) => t === `${TEST_ENV.ISSUER}/interactions/${leg.started.id}/complete`,
    );
    const refused = targets.filter((t) => t === `${LOGIN_ORIGIN}/?error=invalid_state`);
    expect(processed).toHaveLength(1);
    expect(refused).toHaveLength(PARALLEL - 1);
    const doc = await docOf(leg.started);
    expect(doc.status).toBe("ready");
    expect(doc.federation).toBeNull();
    const index = await db
      .prepare("SELECT COUNT(*) AS n FROM identity_index WHERE issuer = ? AND subject = ?")
      .bind(IDP, "alice")
      .first<{ n: number }>();
    expect(index?.n).toBe(1);
  });

  it("[TIO-TEST-010] [TIO-FED-041] 20 parallel first logins of one upstream person: one account created and linked (one index row); every other leg either fails with identity_already_linked or signs in as that account", async () => {
    // A person without an email, so the identity pair is the only thing the losers collide on
    // (with a verified email the users index fires first and reports account_exists).
    fake.person({ sub: "twin", name: "Twin" });
    const legs: Leg[] = [];
    for (let i = 0; i < PARALLEL; i++) legs.push(await prepareLeg("twin"));
    const answers = await Promise.all(legs.map(present));
    for (const res of answers) expect(res.status).toBe(303);
    // A leg that reaches the account lookup after the winner's creation signs in as that
    // account; one that races the creation itself loses on the index and fails.
    const signedIn: string[] = [];
    let refused = 0;
    for (const [i, leg] of legs.entries()) {
      const target = location(answers[i] as Response);
      const doc = await docOf(leg.started);
      if (target === `${TEST_ENV.ISSUER}/interactions/${leg.started.id}/complete`) {
        expect(doc.status).toBe("ready");
        signedIn.push((doc.auth as { uid: string }).uid);
      } else {
        expect(target).toBe(`${LOGIN_ORIGIN}/?interaction=${leg.started.id}`);
        expect(doc.status).toBe("failed");
        expect(doc.error).toMatchObject({ error: "identity_already_linked" });
        refused++;
      }
    }
    expect(signedIn.length).toBeGreaterThanOrEqual(1);
    expect(signedIn.length + refused).toBe(PARALLEL);
    expect(new Set(signedIn).size).toBe(1);
    const index = await db
      .prepare("SELECT user_id FROM identity_index WHERE issuer = ? AND subject = ?")
      .bind(IDP, "twin")
      .all<{ user_id: string }>();
    expect(index.results).toHaveLength(1);
    expect(index.results[0]?.user_id).toBe(signedIn[0]);
    // The losers' creations were rolled back with the index conflict: one account, fully visible.
    const holders = await db
      .prepare("SELECT status FROM users WHERE id = ?")
      .bind(index.results[0]?.user_id)
      .all<{ status: string }>();
    expect(holders.results).toEqual([{ status: "active" }]);
    const creating = await db
      .prepare("SELECT COUNT(*) AS n FROM users WHERE status = 'creating'")
      .first<{ n: number }>();
    expect(creating?.n).toBe(0);
  });
});
