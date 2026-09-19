import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/server";
import { describe, expect, it } from "vitest";
import { bytesToUuid } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { getUser } from "../../src/db/users.ts";
import { REQUEST_URI_PREFIX } from "../../src/oidc/authorize-endpoint.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { SESSION_COOKIE } from "../../src/router/cookies.ts";
import { createInvitation } from "../../src/users/invitations.ts";
import { decodeBase64Url } from "../../src/util/base64url.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT, type Started } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import { VirtualAuthenticator } from "../support/virtual-authenticator.ts";

// Exactly-once through the HTTP surface (TIO-TEST-010): 20 racing requests,
// one winner, the specified outcome for the rest.

const PARALLEL = 20;
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();

let web: Client;

const form = (params: Record<string, string>) =>
  h.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });

interface Tokens {
  access_token: string;
  refresh_token: string;
}

async function assertion(started: Started, user: PasskeyUser) {
  const options = await h.post(started, "passkey/options", {});
  const { publicKey } = (await options.json()) as {
    publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
  };
  return user.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
}

async function readyInteraction(user: PasskeyUser): Promise<Started> {
  const started = await h.start(web);
  const response = await assertion(started, user);
  expect((await h.post(started, "passkey/verify", { response })).status).toBe(200);
  return started;
}

async function codeFor(user: PasskeyUser): Promise<string> {
  const started = await readyInteraction(user);
  const complete = await h.send(`/interactions/${started.id}/complete`, {
    origin: null,
    cookie: started.cookie,
  });
  return new URL(complete.headers.get("location") as string).searchParams.get("code") as string;
}

describe("exactly-once over HTTP", () => {
  it("[TIO-TEST-010] [TIO-TOKEN-012] 20 parallel exchanges of one code: one token response, the rest invalid_grant, and the winner's refresh token is revoked", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true }))
      .client;
    const user = await userWithPasskey(clock);
    const code = await codeFor(user);
    const results = await Promise.all(
      Array.from({ length: PARALLEL }, () =>
        form({
          grant_type: "authorization_code",
          client_id: web.client_id,
          code,
          redirect_uri: RP_REDIRECT,
          code_verifier: VERIFIER,
        }),
      ),
    );
    const winners = results.filter((r) => r.status === 200);
    expect(winners).toHaveLength(1);
    for (const loser of results.filter((r) => r.status !== 200)) {
      expect(loser.status).toBe(400);
      expect(await loser.json()).toMatchObject({ error: "invalid_grant" });
    }
    const tokens = (await (winners[0] as Response).json()) as Tokens;
    const rotate = await form({
      grant_type: "refresh_token",
      client_id: web.client_id,
      refresh_token: tokens.refresh_token,
    });
    expect(await rotate.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("[TIO-TEST-010] [TIO-RT-003] 20 parallel rotations of one refresh token: exactly one success; the family and its session end", async () => {
    const user = await userWithPasskey(clock);
    const code = await codeFor(user);
    const first = (await (
      await form({
        grant_type: "authorization_code",
        client_id: web.client_id,
        code,
        redirect_uri: RP_REDIRECT,
        code_verifier: VERIFIER,
      })
    ).json()) as Tokens;
    const results = await Promise.all(
      Array.from({ length: PARALLEL }, () =>
        form({
          grant_type: "refresh_token",
          client_id: web.client_id,
          refresh_token: first.refresh_token,
        }),
      ),
    );
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 400)).toHaveLength(PARALLEL - 1);
    expect(h.lines.filter((l) => l["msg"] === "refresh token reuse detected")).toHaveLength(1);
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions).toEqual([]);
  });

  it("[TIO-TEST-010] [TIO-IX-030] 20 parallel verifications of one passkey challenge: one authentication, the rest refused, the counter moved once", async () => {
    const user = await userWithPasskey(clock);
    const started = await h.start(web);
    const response = await assertion(started, user);
    const results = await Promise.all(
      Array.from({ length: PARALLEL }, () => h.post(started, "passkey/verify", { response })),
    );
    const statuses = results.map((r) => r.status);
    // Exactly one assertion verified (the counter moved once); the rest found the challenge
    // spent (401), the state moved on (409) or the attempt limit of 10 tripped (403). Twenty
    // attempts exceed that limit, so the interaction itself may end as failed.
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    for (const status of statuses.filter((s) => s !== 200)) {
      expect([401, 403, 409]).toContain(status);
    }
    const passkeys = await user.stub.listPasskeys();
    expect(passkeys.ok && passkeys.passkeys[0]?.counter).toBe(1);
    const doc = await interactionStub(env, started.id).get(clock.now());
    expect(doc.ok && ["ready", "failed"]).toContain(doc.ok ? doc.doc.status : "");
    const winner = (await (results.find((r) => r.status === 200) as Response).json()) as {
      status: string;
    };
    expect(["ready", "failed"]).toContain(winner.status);
  });

  it("[TIO-TEST-010] [TIO-REG-002] 20 parallel registrations with one invitation: one user created, the others see invitation_used", async () => {
    const invitation = await createInvitation(
      db,
      keys,
      {
        kind: "register",
        user_id: null,
        email: "race@example.com",
        email_verified: true,
        display_name: null,
        groups: [],
        expires_in: null,
        created_by: "test",
      },
      clock,
    );
    if (!invitation.ok) throw new Error(invitation.error);
    const prepared = await Promise.all(
      Array.from({ length: PARALLEL }, async () => {
        const started = await h.start(web);
        const options = await h.post(started, "register/options", { invitation: invitation.token });
        const { publicKey } = (await options.json()) as {
          publicKey: PublicKeyCredentialCreationOptionsJSON;
        };
        const response = await new VirtualAuthenticator().register(publicKey, LOGIN_ORIGIN);
        return { started, publicKey, response };
      }),
    );
    const results = await Promise.all(
      prepared.map((p) => h.post(p.started, "register/verify", { response: p.response })),
    );
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    const losers = results.filter((r) => r.status !== 200);
    expect(losers).toHaveLength(PARALLEL - 1);
    for (const loser of losers) {
      expect(await loser.json()).toMatchObject({ error: "invitation_used" });
    }
    const created = await Promise.all(
      prepared.map((p) =>
        getUser(db, bytesToUuid(decodeBase64Url(p.publicKey.user.id) as Uint8Array)),
      ),
    );
    expect(created.filter((u) => u !== null)).toHaveLength(1);
  });

  it("[TIO-TEST-010] [TIO-PAR-003] 20 parallel uses of one request_uri: one interaction, the rest invalid_request", async () => {
    const pushed = await h.send("/par", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: web.client_id,
        redirect_uri: RP_REDIRECT,
        response_type: "code",
        scope: "openid",
        state: "s",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
      }).toString(),
    });
    const { request_uri: requestUri } = (await pushed.json()) as { request_uri: string };
    const results = await Promise.all(
      Array.from({ length: PARALLEL }, () =>
        h.send(
          `/authorize?${new URLSearchParams({ client_id: web.client_id, request_uri: requestUri })}`,
          {
            origin: null,
          },
        ),
      ),
    );
    const outcomes = results.map((r) => new URL(r.headers.get("location") as string));
    const winners = outcomes.filter((u) => u.searchParams.has("interaction"));
    expect(winners).toHaveLength(1);
    expect((winners[0] as URL).searchParams.get("interaction")).toBe(
      requestUri.slice(REQUEST_URI_PREFIX.length),
    );
    for (const loser of outcomes.filter((u) => !u.searchParams.has("interaction"))) {
      expect(loser.searchParams.get("error")).toBe("invalid_request");
    }
  });

  it("[TIO-TEST-010] [TIO-IX-061] 20 parallel completions of one ready interaction: one code, the others interaction_already_completed", async () => {
    const user = await userWithPasskey(clock);
    const started = await readyInteraction(user);
    const results = await Promise.all(
      Array.from({ length: PARALLEL }, () =>
        h.send(`/interactions/${started.id}/complete`, { origin: null, cookie: started.cookie }),
      ),
    );
    const targets = results.map((r) => new URL(r.headers.get("location") as string));
    const codes = targets.filter((u) => u.searchParams.has("code"));
    expect(codes).toHaveLength(1);
    for (const other of targets.filter((u) => !u.searchParams.has("code"))) {
      expect(other.searchParams.get("error")).toBe("interaction_already_completed");
    }
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions).toHaveLength(1);
    expect(
      results.filter((r) => r.headers.getSetCookie().some((c) => c.startsWith(SESSION_COOKIE))),
    ).toHaveLength(1);
  });
});
