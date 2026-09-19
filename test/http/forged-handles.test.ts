import { describe, expect, it } from "vitest";
import { newSecret } from "../../src/crypto/random.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Client } from "../../src/oidc/clients.ts";
import {
  openCodeHandle,
  openRefreshHandle,
  openSessionHandle,
  sealBindingHandle,
  sealCodeHandle,
  sealInvitationHandle,
  sealRefreshHandle,
  sealSessionHandle,
} from "../../src/oidc/handles.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { bindingCookieName, SESSION_COOKIE } from "../../src/router/cookies.ts";
import { createInvitation } from "../../src/users/invitations.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { loggedIn } from "../support/sessions.ts";

// A handle whose envelope verifies (real keys, well-formed fields) but whose
// secret matches no server-side record is worth nothing (TIO-ARCH-009): every
// handle is checked against its record for existence, expiry, consumption and
// revocation, so a forged secret is refused exactly like an unknown handle.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();
const uuids = new UuidV7(clock);

let web: Client;

const form = (params: Record<string, string>) =>
  h.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });

describe("forged handles (TIO-ARCH-009)", () => {
  it("[TIO-ARCH-009] a code, refresh token and session cookie with a valid envelope for a real user but a random secret are refused; the envelopes themselves open", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    const user = await loggedIn(clock);
    const uid = user.profile.id;

    const code = await sealCodeHandle(keys, uid, newSecret());
    expect(await openCodeHandle(keys, code)).toMatchObject({ uid });
    const exchanged = await form({
      grant_type: "authorization_code",
      client_id: web.client_id,
      code,
      redirect_uri: RP_REDIRECT,
      code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    });
    expect(exchanged.status).toBe(400);
    expect(await exchanged.json()).toMatchObject({ error: "invalid_grant" });

    const refresh = await sealRefreshHandle(keys, uid, uuids.next(), newSecret());
    expect(await openRefreshHandle(keys, refresh)).not.toBeNull();
    const rotated = await form({
      grant_type: "refresh_token",
      client_id: web.client_id,
      refresh_token: refresh,
    });
    expect(rotated.status).toBe(400);
    expect(await rotated.json()).toMatchObject({ error: "invalid_grant" });

    // The forged session names the user's live session id; only the secret is wrong.
    const session = await sealSessionHandle(keys, uid, user.sid, newSecret());
    expect(await openSessionHandle(keys, session)).toMatchObject({ uid, sid: user.sid });
    const started = await h.start(web, {}, `${SESSION_COOKIE}=${session}`);
    const doc = await interactionStub(env, started.id).get(clock.now());
    expect(doc.ok && doc.doc.status).toBe("login_required");
    expect(doc.ok && doc.doc.existing_session).toBeNull();
    // The genuine cookie for the same session is a hit.
    const genuine = await h.send(
      `/authorize?${new URLSearchParams({
        client_id: web.client_id,
        redirect_uri: RP_REDIRECT,
        response_type: "code",
        scope: "openid",
        state: "s",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
      })}`,
      { origin: null, cookie: user.cookie },
    );
    const location = new URL(genuine.headers.get("location") as string);
    expect(location.searchParams.has("interaction")).toBe(true);
    const hit = await interactionStub(env, location.searchParams.get("interaction") as string).get(
      clock.now(),
    );
    expect(hit.ok && hit.doc.status).toBe("consent_required");
  });

  it("[TIO-ARCH-009] a binding cookie and an invitation with a valid envelope but a random secret are refused", async () => {
    const started = await h.start(web);
    const forged = await sealBindingHandle(keys, started.id, newSecret());
    const refused = await h.get(started, { cookie: `${bindingCookieName(started.id)}=${forged}` });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: "interaction_binding_failed" });
    expect((await h.get(started)).status).toBe(200);

    const invitation = await createInvitation(
      db,
      keys,
      {
        kind: "register",
        user_id: null,
        email: "forged@example.com",
        email_verified: true,
        display_name: null,
        groups: [],
        expires_in: null,
        created_by: "test",
      },
      clock,
    );
    if (!invitation.ok) throw new Error(invitation.error);
    const forgedInvitation = await sealInvitationHandle(
      keys,
      invitation.invitation.id,
      newSecret(),
    );
    const options = await h.post(started, "register/options", { invitation: forgedInvitation });
    expect(options.status).toBe(400);
    expect(await options.json()).toMatchObject({ error: "invitation_invalid" });
    expect(
      (await h.post(started, "register/options", { invitation: invitation.token })).status,
    ).toBe(200);
  });
});
