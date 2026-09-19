import { decodeProtectedHeader, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { openHandle } from "../../src/crypto/envelope.ts";
import { retireSigningKeyNow, rotateSigningKey } from "../../src/crypto/keystore.ts";
import { Db } from "../../src/db/db.ts";
import { CODE_TTL_SECONDS } from "../../src/do/UserDO.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { sealCodeHandle } from "../../src/oidc/handles.ts";
import { decodeBase64Url, encodeBase64Url } from "../../src/util/base64url.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, RP_REDIRECT } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { loggedIn } from "../support/sessions.ts";

// Codes and tokens (spec §13.7, TIO-TEST-020): an authorization code past its
// lifetime, a code envelope that names another user with a real secret, and
// access tokens the OP would not have signed as presented (retired key,
// unknown kid, tampered payload) at every bearer-accepting surface.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

async function codeFor(client: Client, cookie: string): Promise<string> {
  const params = new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: RP_REDIRECT,
    response_type: "code",
    scope: "openid",
    state: "st-1",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
  });
  const res = await h.send(`/authorize?${params}`, { origin: null, cookie });
  expect(res.status).toBe(303);
  const code = new URL(res.headers.get("location") as string).searchParams.get("code");
  if (code === null) throw new Error("no code");
  return code;
}

const exchange = (client: Client, code: string) =>
  h.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: client.client_id,
      code,
      redirect_uri: RP_REDIRECT,
      code_verifier: VERIFIER,
    }).toString(),
  });

/** The three bearer surfaces, each answering with its status and WWW-Authenticate. */
async function presentEverywhere(
  token: string,
): Promise<{ status: number; challenge: string | null }[]> {
  const headers = { authorization: `Bearer ${token}` };
  const answers = await Promise.all([
    h.send("/userinfo", { origin: null, headers }),
    h.send("/api/v1/me", { origin: null, headers }),
    admin(h, token, "stats"),
  ]);
  return answers.map((res) => ({
    status: res.status,
    challenge: res.headers.get("WWW-Authenticate"),
  }));
}

describe("codes and tokens", () => {
  it("[TIO-TEST-020] [TIO-TOKEN-011] [TIO-ARCH-009] a code past its lifetime, and a code envelope naming another user with a real code's secret, are invalid_grant; the real code stays redeemable by its owner", async () => {
    await adminSettings(h);
    const web = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const alice = await loggedIn(clock);
    const bob = await loggedIn(clock);
    // Expired.
    const stale = await codeFor(web, alice.cookie);
    clock.advance(CODE_TTL_SECONDS + 1);
    const expired = await exchange(web, stale);
    expect(expired.status).toBe(400);
    expect(await expired.json()).toMatchObject({ error: "invalid_grant" });
    // Cross-user: alice's secret inside an envelope for bob.
    const real = await codeFor(web, alice.cookie);
    const fields = await openHandle(keys, "code", real);
    if (!fields) throw new Error("the code does not open");
    const crossed = await sealCodeHandle(keys, bob.profile.id, fields.secret);
    expect(crossed).not.toBe(real);
    const refused = await exchange(web, crossed);
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ error: "invalid_grant" });
    // Bob's object saw an unknown code, not a replay: alice's code is intact.
    const own = await exchange(web, real);
    expect(own.status).toBe(200);
  });

  it("[TIO-TEST-020] [TIO-TOKEN-034] [TIO-UINFO-001] [TIO-ME-001] [TIO-ADMIN-001] an access token with a tampered payload, under an unknown kid, or under a key retired since is 401 invalid_token at /userinfo, /me and /admin alike", async () => {
    const operator = await adminUser(h, { scope: "openid account admin" });
    const good = operator.access_token;
    expect((await presentEverywhere(good)).map((a) => a.status)).toEqual([200, 200, 200]);
    const [header, payload, signature] = good.split(".") as [string, string, string];
    const expectRefused = async (token: string, label: string) => {
      const answers = await presentEverywhere(token);
      for (const answer of answers) {
        expect(answer.status, label).toBe(401);
        expect(answer.challenge, label).toContain('error="invalid_token"');
      }
    };
    // Tampered payload: the same claims with the subject changed by one character.
    const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload) as Uint8Array)) as {
      sub: string;
    };
    const flipped = {
      ...claims,
      sub: `${claims.sub.slice(0, -1)}${claims.sub.endsWith("0") ? "1" : "0"}`,
    };
    const tamperedPayload = encodeBase64Url(new TextEncoder().encode(JSON.stringify(flipped)));
    await expectRefused(`${header}.${tamperedPayload}.${signature}`, "tampered payload");
    // Tampered signature and a shortened token.
    await expectRefused(`${header}.${payload}.${signature.slice(0, -2)}AA`, "tampered signature");
    await expectRefused(`${header}.${payload}`, "two segments");
    // Unknown kid: a well-formed token signed by a key the OP never published.
    const foreign = await generateKeyPair("ES256");
    const unknownKid = await new SignJWT(claims as Record<string, unknown>)
      .setProtectedHeader({ alg: "ES256", typ: "at+jwt", kid: "unknown-kid" })
      .sign(foreign.privateKey);
    await expectRefused(unknownKid, "unknown kid");
    expect((await exportJWK(foreign.publicKey)).kty).toBe("EC");
    // Retired key: rotate immediately and retire the key that signed the token.
    const signingKid = decodeProtectedHeader(good).kid as string;
    await rotateSigningKey(db, keys, clock.now(), 0, true);
    expect(await retireSigningKeyNow(db, signingKid, clock.now())).toBe("retired");
    clock.advance(61);
    await expectRefused(good, "retired key");
    // The OP itself still works: a fresh token under the new key is accepted everywhere.
    const fresh = await adminUser(h, { scope: "openid account admin" });
    expect(decodeProtectedHeader(fresh.access_token).kid).not.toBe(signingKid);
    expect((await presentEverywhere(fresh.access_token)).map((a) => a.status)).toEqual([
      200, 200, 200,
    ]);
  });
});
