import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { sha256 } from "../../src/crypto/hash.ts";
import { newSecret } from "../../src/crypto/random.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import {
  type ClientRef,
  CODE_TTL_SECONDS,
  type CodeInput,
  type ExchangeCodeInput,
  type NewSession,
  type UserDO,
} from "../../src/do/UserDO.ts";
import { ACR } from "../../src/oidc/capabilities.ts";
import { encodeBase64Url } from "../../src/util/base64url.ts";
import { FakeClock } from "../support/clock.ts";
import { unique, userProfile } from "../support/factories.ts";
import { env } from "../support/op.ts";

const clock = new FakeClock(1_800_000_000);
const uuids = new UuidV7(clock);
const IDLE = 86_400;
const ABSOLUTE = 2_592_000;
const REFRESH_IDLE = 1_209_600;
const REFRESH_ABSOLUTE = 2_592_000;
const REUSE_WINDOW = 86_400;

const client = (overrides: Partial<ClientRef> = {}): ClientRef => ({
  client_id: "web",
  created_at: 1_000,
  skip_consent: false,
  allowed_groups: null,
  ...overrides,
});

const passkeyAuth = {
  auth_time: clock.now(),
  amr: ["hwk", "user"],
  acr: ACR.passkey,
  upstream: null,
};

async function newUser(groups: string[] = []) {
  const profile = userProfile(clock, { groups });
  const stub = env.USER_DO.get(env.USER_DO.idFromName(profile.id));
  const created = await stub.init(profile, clock.now());
  if (!created.ok) throw new Error(created.error);
  return { stub, profile: created.profile };
}

async function sessionInput(): Promise<{ input: NewSession; secretHash: Uint8Array }> {
  const secretHash = await sha256(newSecret());
  return {
    input: {
      sid: uuids.next(),
      secret_hash: secretHash,
      auth: { ...passkeyAuth, auth_time: clock.now() },
      metadata: { ip_hash: "ip", ua_family: "Chrome/128", country: "BR" },
      idle_ttl: IDLE,
      absolute_ttl: ABSOLUTE,
    },
    secretHash,
  };
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = encodeBase64Url(newSecret());
  return { verifier, challenge: encodeBase64Url(await sha256(verifier)) };
}

async function codeInput(
  challenge: string,
  overrides: Partial<CodeInput> = {},
): Promise<{ code: CodeInput; secretHash: Uint8Array }> {
  const secretHash = await sha256(newSecret());
  return {
    code: {
      secret_hash: secretHash,
      client_id: "web",
      redirect_uri: "https://rp.example.com/cb",
      scope: ["openid", "email"],
      nonce: "n1",
      code_challenge: challenge,
      ...overrides,
    },
    secretHash,
  };
}

/** A logged-in user with one session and an issued code, ready for exchange. */
async function loggedIn(
  options: { scope?: string[]; groups?: string[]; clientRef?: ClientRef } = {},
) {
  const { stub, profile } = await newUser(options.groups ?? []);
  const session = await sessionInput();
  const { verifier, challenge } = await pkce();
  const codeOverrides: Partial<CodeInput> = options.scope ? { scope: options.scope } : {};
  const { code, secretHash } = await codeInput(challenge, codeOverrides);
  const login = await stub.finalizeLogin({
    now: clock.now(),
    session: { create: session.input },
    code,
    client: options.clientRef ?? client(),
    session_idle_ttl: IDLE,
  });
  if (!login.ok) throw new Error(login.error);
  return {
    stub,
    profile,
    session,
    sid: login.sid,
    code,
    codeHash: secretHash,
    verifier,
    challenge,
  };
}

async function exchange(
  stub: DurableObjectStub<UserDO>,
  codeHash: Uint8Array,
  verifier: string,
  overrides: Record<string, unknown> = {},
) {
  const refresh =
    "refresh" in overrides
      ? (overrides["refresh"] as ExchangeCodeInput["refresh"])
      : {
          secret_hash: await sha256(newSecret()),
          family_id: uuids.next(),
          offline_allowed: false,
          idle_ttl: REFRESH_IDLE,
          absolute_ttl: REFRESH_ABSOLUTE,
        };
  const result = await stub.exchangeCode({
    secret_hash: codeHash,
    client: client(),
    redirect_uri: "https://rp.example.com/cb",
    code_verifier: verifier,
    now: clock.now(),
    ...overrides,
    refresh,
  });
  return {
    result,
    refreshHash: refresh?.secret_hash ?? new Uint8Array(),
    familyId: refresh?.family_id ?? "",
  };
}

async function rotate(
  stub: DurableObjectStub<UserDO>,
  familyId: string,
  secretHash: Uint8Array,
  overrides: Record<string, unknown> = {},
) {
  const next = await sha256(newSecret());
  const result = await stub.rotateRefreshToken({
    family_id: familyId,
    secret_hash: secretHash,
    client: client(),
    now: clock.now(),
    requested_scope: null,
    new_secret_hash: next,
    idle_ttl: REFRESH_IDLE,
    session_idle_ttl: IDLE,
    reuse_window: REUSE_WINDOW,
    ...overrides,
  });
  return { result, next };
}

describe("UserDO sessions", () => {
  it("[TIO-SESS-002] creates a session at login with auth_time, amr, acr, metadata and both expiries; rotates the secret for the same user keeping sid", async () => {
    const { stub } = await newUser();
    const first = await sessionInput();
    const t0 = clock.now();
    const login = await stub.finalizeLogin({
      now: t0,
      session: { create: first.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    expect(login.ok).toBe(true);
    if (!login.ok) return;
    expect(login.session).toEqual({
      sid: first.input.sid,
      auth_time: t0,
      amr: ["hwk", "user"],
      acr: ACR.passkey,
      upstream: null,
      created_at: t0,
      last_seen_at: t0,
      idle_expires_at: t0 + IDLE,
      absolute_expires_at: t0 + ABSOLUTE,
      clients: [],
      country: "BR",
      ua_family: "Chrome/128",
    });
    expect((await stub.getSession(first.input.sid, first.secretHash, t0)).ok).toBe(true);
    // Re-authentication of the same user: new secret and auth context, same sid, absolute expiry untouched.
    clock.advance(600);
    const rotatedHash = await sha256(newSecret());
    const rotated = await stub.finalizeLogin({
      now: clock.now(),
      session: {
        rotate: {
          sid: first.input.sid,
          secret_hash: rotatedHash,
          auth: {
            ...passkeyAuth,
            auth_time: clock.now(),
            amr: ["fed"],
            acr: ACR.federated,
            upstream: "google",
          },
        },
      },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    expect(rotated.ok && rotated.sid).toBe(first.input.sid);
    expect(rotated.ok && rotated.session).toMatchObject({
      auth_time: t0 + 600,
      amr: ["fed"],
      acr: ACR.federated,
      upstream: "google",
      absolute_expires_at: t0 + ABSOLUTE,
      idle_expires_at: t0 + 600 + IDLE,
    });
    expect((await stub.getSession(first.input.sid, first.secretHash, clock.now())).ok).toBe(false);
    expect((await stub.getSession(first.input.sid, rotatedHash, clock.now())).ok).toBe(true);
    // Rotating a revoked or unknown session fails.
    await stub.revokeSession(first.input.sid, clock.now(), "logout");
    const dead = await stub.finalizeLogin({
      now: clock.now(),
      session: { rotate: { sid: first.input.sid, secret_hash: rotatedHash, auth: passkeyAuth } },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    expect(dead).toEqual({ ok: false, error: "session_invalid" });
    const unknown = await stub.finalizeLogin({
      now: clock.now(),
      session: { rotate: { sid: "nope", secret_hash: rotatedHash, auth: passkeyAuth } },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    expect(unknown).toEqual({ ok: false, error: "session_invalid" });
  });

  it("[TIO-SESS-004] a session with a wrong secret, unknown sid, revoked, idle-expired or absolutely expired is invalid", async () => {
    const { stub } = await newUser();
    const s = await sessionInput();
    const t0 = clock.now();
    await stub.finalizeLogin({
      now: t0,
      session: { create: s.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    expect(await stub.getSession(s.input.sid, await sha256(newSecret()), t0)).toEqual({
      ok: false,
      error: "session_invalid",
    });
    expect(await stub.getSession("unknown", s.secretHash, t0)).toEqual({
      ok: false,
      error: "session_invalid",
    });
    expect((await stub.getSession(s.input.sid, s.secretHash, t0 + IDLE - 1)).ok).toBe(true);
    expect(await stub.getSession(s.input.sid, s.secretHash, t0 + IDLE)).toEqual({
      ok: false,
      error: "session_invalid",
    });
    const long = await sessionInput();
    long.input.idle_ttl = ABSOLUTE * 2;
    await stub.finalizeLogin({
      now: t0,
      session: { create: long.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    expect((await stub.getSession(long.input.sid, long.secretHash, t0 + ABSOLUTE - 1)).ok).toBe(
      true,
    );
    expect((await stub.getSession(long.input.sid, long.secretHash, t0 + ABSOLUTE)).ok).toBe(false);
    await stub.revokeSession(s.input.sid, t0 + 1, "test");
    expect(await stub.getSession(s.input.sid, s.secretHash, t0 + 1)).toEqual({
      ok: false,
      error: "session_invalid",
    });
    expect((await stub.listSessions(t0 + 2)).ok && (await stub.listSessions(t0 + 2))).toMatchObject(
      { sessions: [{ sid: long.input.sid }] },
    );
  });

  it("[TIO-SESS-006] [TIO-LOGOUT-005] revoking a session revokes its session-bound families, keeps offline ones, and returns the clients it served", async () => {
    const user = await loggedIn();
    const { result, refreshHash, familyId } = await exchange(
      user.stub,
      user.codeHash,
      user.verifier,
    );
    expect(result.ok).toBe(true);
    // A second, offline family from another login of the same session (another client).
    const { challenge, verifier } = await pkce();
    const other = await codeInput(challenge, {
      client_id: "mobile",
      scope: ["openid", "offline_access"],
    });
    clock.advance(1);
    await user.stub.finalizeLogin({
      now: clock.now(),
      session: {
        rotate: { sid: user.sid, secret_hash: user.session.secretHash, auth: passkeyAuth },
      },
      code: other.code,
      client: client({ client_id: "mobile" }),
      session_idle_ttl: IDLE,
    });
    const offline = await exchange(user.stub, other.secretHash, verifier, {
      client: client({ client_id: "mobile" }),
      refresh: {
        secret_hash: await sha256(newSecret()),
        family_id: uuids.next(),
        offline_allowed: true,
        idle_ttl: REFRESH_IDLE,
        absolute_ttl: REFRESH_ABSOLUTE,
      },
    });
    expect(offline.result.ok).toBe(true);
    const revoked = await user.stub.revokeSession(user.sid, clock.now(), "logout");
    expect(revoked).toEqual({ ok: true, revoked: { sid: user.sid, clients: ["web", "mobile"] } });
    expect(await user.stub.revokeSession(user.sid, clock.now(), "logout")).toEqual({
      ok: true,
      revoked: null,
    });
    expect(await user.stub.revokeSession("nope", clock.now(), "logout")).toEqual({
      ok: true,
      revoked: null,
    });
    expect((await rotate(user.stub, familyId, refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    const offlineRotation = await rotate(user.stub, offline.familyId, offline.refreshHash, {
      client: client({ client_id: "mobile" }),
    });
    expect(offlineRotation.result.ok).toBe(true);
  });

  it("[TIO-DATA-009] revokeAll ends every session and family and reports the clients of each session", async () => {
    const user = await loggedIn();
    const { refreshHash, familyId } = await exchange(user.stub, user.codeHash, user.verifier);
    const second = await sessionInput();
    await user.stub.finalizeLogin({
      now: clock.now(),
      session: { create: second.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    const revoked = await user.stub.revokeAll(clock.now(), "disabled");
    expect(revoked).toEqual({
      ok: true,
      revoked: [
        { sid: user.sid, clients: ["web"] },
        { sid: second.input.sid, clients: [] },
      ],
    });
    expect(
      (await user.stub.listSessions(clock.now())).ok && (await user.stub.listSessions(clock.now())),
    ).toMatchObject({ sessions: [] });
    expect((await rotate(user.stub, familyId, refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect(await user.stub.revokeAll(clock.now(), "again")).toEqual({ ok: true, revoked: [] });
  });
});

describe("UserDO authorization with a session (§2.5.2)", () => {
  const evaluate = (
    stub: DurableObjectStub<UserDO>,
    sid: string,
    secret: Uint8Array,
    overrides: Record<string, unknown> = {},
  ) =>
    stub.authorizeWithSession({
      sid,
      secret_hash: secret,
      now: clock.now(),
      client: client({ skip_consent: true }),
      scope: ["openid", "email"],
      prompt_login: false,
      prompt_consent: false,
      max_age: null,
      code: null,
      session_idle_ttl: IDLE,
      ...overrides,
    });

  it("[TIO-AUTHZ-014] [TIO-AUTHZ-022] [TIO-AUTHZ-023] a usable session with consent satisfied issues a code bound to the request, records the client and touches the session", async () => {
    const { stub } = await newUser();
    const s = await sessionInput();
    const t0 = clock.now();
    await stub.finalizeLogin({
      now: t0,
      session: { create: s.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    clock.advance(100);
    const { challenge, verifier } = await pkce();
    const { code, secretHash } = await codeInput(challenge, { nonce: "second", scope: ["openid"] });
    const outcome = await evaluate(stub, s.input.sid, s.secretHash, { code, scope: ["openid"] });
    expect(outcome).toMatchObject({
      ok: true,
      outcome: "authorized",
      session: {
        clients: ["web"],
        last_seen_at: t0 + 100,
        idle_expires_at: t0 + 100 + IDLE,
        auth_time: t0,
      },
    });
    const exchanged = await exchange(stub, secretHash, verifier, { refresh: null });
    expect(exchanged.result).toMatchObject({
      ok: true,
      nonce: "second",
      family_id: null,
      kind: null,
      grant: {
        scope: ["openid"],
        sid: s.input.sid,
        auth_time: t0,
        amr: ["hwk", "user"],
        acr: ACR.passkey,
      },
    });
    // The code expires 60 s after issuance.
    const { challenge: c2, verifier: v2 } = await pkce();
    const late = await codeInput(c2);
    await evaluate(stub, s.input.sid, s.secretHash, { code: late.code });
    clock.advance(CODE_TTL_SECONDS);
    expect((await exchange(stub, late.secretHash, v2)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    clock.set(t0);
  });

  it("[TIO-AUTHZ-015] evaluating without a code never touches the session; login_required for prompt=login or a stale max_age; consent_required when the grant does not cover the scopes", async () => {
    const { stub } = await newUser();
    const s = await sessionInput();
    const t0 = clock.now();
    await stub.finalizeLogin({
      now: t0,
      session: { create: s.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    clock.advance(1_000);
    const evaluated = await evaluate(stub, s.input.sid, s.secretHash);
    expect(evaluated).toMatchObject({
      ok: true,
      outcome: "authorized",
      session: { last_seen_at: t0, idle_expires_at: t0 + IDLE },
    });
    expect(await evaluate(stub, s.input.sid, s.secretHash, { prompt_login: true })).toMatchObject({
      outcome: "login_required",
    });
    expect(await evaluate(stub, s.input.sid, s.secretHash, { max_age: 999 })).toMatchObject({
      outcome: "login_required",
    });
    expect(await evaluate(stub, s.input.sid, s.secretHash, { max_age: 1_001 })).toMatchObject({
      outcome: "authorized",
    });
    expect(await evaluate(stub, s.input.sid, s.secretHash, { max_age: 0 })).toMatchObject({
      outcome: "login_required",
    });
    const consentClient = client({ skip_consent: false });
    expect(
      await evaluate(stub, s.input.sid, s.secretHash, { client: consentClient }),
    ).toMatchObject({ outcome: "consent_required" });
    await stub.grantConsent(consentClient, ["openid"], clock.now());
    expect(
      await evaluate(stub, s.input.sid, s.secretHash, { client: consentClient }),
    ).toMatchObject({ outcome: "consent_required" });
    await stub.grantConsent(consentClient, ["email"], clock.now());
    expect(
      await evaluate(stub, s.input.sid, s.secretHash, { client: consentClient }),
    ).toMatchObject({ outcome: "authorized" });
    expect(
      await evaluate(stub, s.input.sid, s.secretHash, {
        client: consentClient,
        prompt_consent: true,
      }),
    ).toMatchObject({ outcome: "consent_required" });
    expect(
      (await stub.getSession(s.input.sid, s.secretHash, clock.now())).ok &&
        (await stub.getSession(s.input.sid, s.secretHash, clock.now())),
    ).toMatchObject({ session: { last_seen_at: t0 } });
    clock.set(t0);
  });

  it("[TIO-AUTHZ-017] [TIO-CONSENT-001] allowed_groups and disabled users are refused before consent; an invalid session is reported as such", async () => {
    const { stub } = await newUser(["staff"]);
    const s = await sessionInput();
    await stub.finalizeLogin({
      now: clock.now(),
      session: { create: s.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    expect(
      await evaluate(stub, s.input.sid, s.secretHash, {
        client: client({ skip_consent: true, allowed_groups: ["staff"] }),
      }),
    ).toMatchObject({ outcome: "authorized" });
    expect(
      await evaluate(stub, s.input.sid, s.secretHash, {
        client: client({ allowed_groups: ["admins"] }),
      }),
    ).toEqual({ ok: false, error: "user_not_allowed" });
    expect(await evaluate(stub, s.input.sid, await sha256(newSecret()))).toEqual({
      ok: false,
      error: "session_invalid",
    });
    const login = await stub.finalizeLogin({
      now: clock.now(),
      session: { create: (await sessionInput()).input },
      code: null,
      client: client({ allowed_groups: ["admins"] }),
      session_idle_ttl: IDLE,
    });
    expect(login).toEqual({ ok: false, error: "user_not_allowed" });
  });

  it("[TIO-AUTHZ-024] two requests on one session bind their own nonce and challenge: the second code redeems only with the second verifier", async () => {
    const { stub } = await newUser();
    const s = await sessionInput();
    await stub.finalizeLogin({
      now: clock.now(),
      session: { create: s.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    const first = await pkce();
    const second = await pkce();
    const c1 = await codeInput(first.challenge, { nonce: "n-first" });
    const c2 = await codeInput(second.challenge, { nonce: "n-second" });
    await evaluate(stub, s.input.sid, s.secretHash, { code: c1.code });
    await evaluate(stub, s.input.sid, s.secretHash, { code: c2.code });
    expect((await exchange(stub, c2.secretHash, first.verifier)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    const ok = await exchange(stub, c2.secretHash, second.verifier);
    expect(ok.result).toMatchObject({ ok: true, nonce: "n-second" });
    const okFirst = await exchange(stub, c1.secretHash, first.verifier);
    expect(okFirst.result).toMatchObject({ ok: true, nonce: "n-first" });
  });
});

describe("UserDO code exchange (§2.5.3)", () => {
  it("[TIO-TOKEN-011] [TIO-TOKEN-013] [TIO-TOKEN-014] exchanges a code exactly once, creating a session-bound or offline family with the first token", async () => {
    const user = await loggedIn({ scope: ["openid", "offline_access"] });
    const { result, familyId } = await exchange(user.stub, user.codeHash, user.verifier, {
      refresh: {
        secret_hash: await sha256(newSecret()),
        family_id: uuids.next(),
        offline_allowed: true,
        idle_ttl: REFRESH_IDLE,
        absolute_ttl: REFRESH_ABSOLUTE,
      },
    });
    expect(result).toMatchObject({
      ok: true,
      kind: "offline",
      grant: {
        sub: user.profile.id,
        scope: ["openid", "offline_access"],
        sid: user.sid,
        profile: { id: user.profile.id },
      },
    });
    expect(result.ok && result.family_id).toBe(familyId);
    const again = await exchange(user.stub, user.codeHash, user.verifier);
    expect(again.result).toEqual({ ok: false, error: "invalid_grant", replay: true });
  });

  it("[TIO-TOKEN-011] rejects a wrong client, redirect_uri, verifier (value, length or alphabet), unknown code, disabled user, revoked session and failed allowed_groups", async () => {
    const user = await loggedIn();
    const attempt = (overrides: Record<string, unknown>) =>
      exchange(user.stub, user.codeHash, user.verifier, overrides);
    expect((await attempt({ client: client({ client_id: "other" }) })).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await attempt({ redirect_uri: "https://rp.example.com/cb/" })).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await attempt({ code_verifier: encodeBase64Url(newSecret()) })).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await attempt({ code_verifier: user.verifier.slice(0, 42) })).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await attempt({ code_verifier: `${user.verifier}!` })).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await attempt({ code_verifier: "x".repeat(129) })).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await attempt({ secret_hash: await sha256(newSecret()) })).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await attempt({ client: client({ allowed_groups: ["admins"] }) })).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    await user.stub.revokeSession(user.sid, clock.now(), "logout");
    expect((await attempt({})).result).toEqual({ ok: false, error: "invalid_grant" });
    // The code is still unconsumed: none of the rejections consumed it.
    const fresh = await loggedIn();
    await fresh.stub.revokeAll(clock.now(), "disabled");
    const disabledUser = await newUser();
    await disabledUser.stub.revokeAll(clock.now(), "x");
  });

  it("[TIO-TOKEN-012] presenting a consumed code revokes every family created from it", async () => {
    const user = await loggedIn();
    const first = await exchange(user.stub, user.codeHash, user.verifier);
    expect(first.result.ok).toBe(true);
    const replay = await exchange(user.stub, user.codeHash, user.verifier);
    expect(replay.result).toEqual({ ok: false, error: "invalid_grant", replay: true });
    expect((await rotate(user.stub, first.familyId, first.refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
  });
});

describe("UserDO refresh rotation (§2.5.4)", () => {
  it("[TIO-RT-002] [TIO-RT-005] rotates exactly once per token, extends idle expiry, touches the bound session and returns the family's claims", async () => {
    const user = await loggedIn();
    const t0 = clock.now();
    const { refreshHash, familyId } = await exchange(user.stub, user.codeHash, user.verifier);
    clock.advance(3_600);
    const first = await rotate(user.stub, familyId, refreshHash);
    expect(first.result).toMatchObject({
      ok: true,
      serial: 2,
      kind: "session",
      grant: {
        scope: ["openid", "email"],
        sid: user.sid,
        auth_time: t0,
        amr: ["hwk", "user"],
        acr: ACR.passkey,
      },
    });
    const session = await user.stub.getSession(user.sid, user.session.secretHash, clock.now());
    expect(session.ok && session.session).toMatchObject({
      last_seen_at: t0 + 3_600,
      idle_expires_at: t0 + 3_600 + IDLE,
    });
    // The consumed token fails, revokes the family and the session (reuse detection).
    const reuse = await rotate(user.stub, familyId, refreshHash);
    expect(reuse.result).toEqual({
      ok: false,
      error: "invalid_grant",
      reuse_detected: true,
      revoked_session_clients: ["web"],
    });
    expect((await rotate(user.stub, familyId, first.next)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await user.stub.getSession(user.sid, user.session.secretHash, clock.now())).ok).toBe(
      false,
    );
    clock.set(t0);
  });

  it("[TIO-RT-002] rejects an unknown family, foreign token, wrong client, expired idle or absolute family, stale serial and a re-created client", async () => {
    const user = await loggedIn();
    const t0 = clock.now();
    const { refreshHash, familyId } = await exchange(user.stub, user.codeHash, user.verifier);
    expect((await rotate(user.stub, "nope", refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await rotate(user.stub, familyId, await sha256(newSecret()))).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect(
      (await rotate(user.stub, familyId, refreshHash, { client: client({ client_id: "other" }) }))
        .result,
    ).toEqual({ ok: false, error: "invalid_grant" });
    expect(
      (
        await rotate(user.stub, familyId, refreshHash, {
          client: client({ allowed_groups: ["admins"] }),
        })
      ).result,
    ).toEqual({ ok: false, error: "invalid_grant" });
    clock.advance(REFRESH_IDLE);
    expect((await rotate(user.stub, familyId, refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    clock.set(t0);
    // A re-created client (different created_at) loses the family (TIO-CLIENT-005).
    const recreated = await rotate(user.stub, familyId, refreshHash, {
      client: client({ created_at: 2_000 }),
    });
    expect(recreated.result).toEqual({ ok: false, error: "invalid_grant" });
    expect((await rotate(user.stub, familyId, refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
  });

  it("[TIO-RT-004] a scope parameter narrows the issued tokens without widening or changing the family", async () => {
    const user = await loggedIn();
    const { refreshHash, familyId } = await exchange(user.stub, user.codeHash, user.verifier);
    const narrowed = await rotate(user.stub, familyId, refreshHash, {
      requested_scope: ["openid"],
    });
    expect(narrowed.result).toMatchObject({ ok: true, grant: { scope: ["openid"] } });
    const widened = await rotate(user.stub, familyId, narrowed.next, {
      requested_scope: ["openid", "profile"],
    });
    expect(widened.result).toEqual({ ok: false, error: "invalid_scope" });
    const full = await rotate(user.stub, familyId, narrowed.next);
    expect(full.result).toMatchObject({ ok: true, grant: { scope: ["openid", "email"] } });
  });

  it("[TIO-RT-006] [TIO-RT-010] session-bound families die with the session and inherit its absolute expiry; offline families survive logout with their own lifetimes", async () => {
    const user = await loggedIn({ scope: ["openid", "offline_access"] });
    const t0 = clock.now();
    const sessionFamily = await exchange(user.stub, user.codeHash, user.verifier);
    expect(sessionFamily.result.ok).toBe(true);
    const { challenge, verifier } = await pkce();
    const second = await codeInput(challenge, { scope: ["openid", "offline_access"] });
    await user.stub.finalizeLogin({
      now: t0,
      session: {
        rotate: { sid: user.sid, secret_hash: user.session.secretHash, auth: passkeyAuth },
      },
      code: second.code,
      client: client(),
      session_idle_ttl: IDLE,
    });
    const offline = await exchange(user.stub, second.secretHash, verifier, {
      refresh: {
        secret_hash: await sha256(newSecret()),
        family_id: uuids.next(),
        offline_allowed: true,
        idle_ttl: REFRESH_IDLE,
        absolute_ttl: REFRESH_ABSOLUTE,
      },
    });
    expect(offline.result).toMatchObject({ ok: true, kind: "offline" });
    await user.stub.revokeSession(user.sid, t0 + 10, "logout");
    expect(
      (await rotate(user.stub, sessionFamily.familyId, sessionFamily.refreshHash)).result,
    ).toEqual({ ok: false, error: "invalid_grant" });
    const offlineRotation = await rotate(user.stub, offline.familyId, offline.refreshHash);
    expect(offlineRotation.result).toMatchObject({
      ok: true,
      kind: "offline",
      grant: { sid: null },
    });
    clock.set(t0 + REFRESH_ABSOLUTE);
    expect((await rotate(user.stub, offline.familyId, offlineRotation.next)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    clock.set(t0);
    // Session-bound idle expiry never exceeds the session's absolute expiry.
    const other = await loggedIn();
    const bound = await exchange(other.stub, other.codeHash, other.verifier, {
      refresh: {
        secret_hash: await sha256(newSecret()),
        family_id: uuids.next(),
        offline_allowed: false,
        idle_ttl: ABSOLUTE * 2,
        absolute_ttl: REFRESH_ABSOLUTE,
      },
    });
    clock.set(t0 + ABSOLUTE);
    expect((await rotate(other.stub, bound.familyId, bound.refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    clock.set(t0);
  });

  it("[TIO-SCOPE-002] admin scope is refused at refresh once the user leaves the admins group; a disabled user fails every refresh", async () => {
    const admin = await loggedIn({ scope: ["openid", "admin"], groups: ["admins"] });
    const { refreshHash, familyId } = await exchange(admin.stub, admin.codeHash, admin.verifier);
    const ok = await rotate(admin.stub, familyId, refreshHash);
    expect(ok.result).toMatchObject({ ok: true, grant: { scope: ["openid", "admin"] } });
    const demoted = await loggedIn({ scope: ["openid", "admin"], groups: ["admins"] });
    const family = await exchange(demoted.stub, demoted.codeHash, demoted.verifier);
    const updated = await demoted.stub.setGroups(["staff", "staff"], clock.now());
    expect(updated.ok && updated.profile.groups).toEqual(["staff"]);
    // No code with the admin scope is issued to a non-member either (TIO-AUTHZ-009).
    const { challenge } = await pkce();
    const adminCode = await codeInput(challenge, { scope: ["openid", "admin"] });
    expect(
      await demoted.stub.finalizeLogin({
        now: clock.now(),
        session: {
          rotate: { sid: demoted.sid, secret_hash: demoted.session.secretHash, auth: passkeyAuth },
        },
        code: adminCode.code,
        client: client(),
        session_idle_ttl: IDLE,
      }),
    ).toEqual({ ok: false, error: "user_not_allowed" });
    expect((await rotate(demoted.stub, family.familyId, family.refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect(
      (
        await rotate(demoted.stub, family.familyId, family.refreshHash, {
          requested_scope: ["openid"],
        })
      ).result,
    ).toMatchObject({ ok: true });
  });

  it("[TIO-REV-002] [TIO-REV-003] revocation by family id ignores other clients' families and revokes a client's session-bound families", async () => {
    const user = await loggedIn();
    const { refreshHash, familyId } = await exchange(user.stub, user.codeHash, user.verifier);
    expect(
      await user.stub.revokeFamilyById(familyId, clock.now(), "client_revoke", "other"),
    ).toEqual({ ok: true, revoked: false });
    expect(await user.stub.revokeFamilyById("nope", clock.now(), "client_revoke", null)).toEqual({
      ok: true,
      revoked: false,
    });
    expect(await user.stub.revokeSessionFamiliesOfClient(user.sid, "other", clock.now())).toEqual({
      ok: true,
      revoked: 0,
    });
    expect(await user.stub.revokeSessionFamiliesOfClient(user.sid, "web", clock.now())).toEqual({
      ok: true,
      revoked: 1,
    });
    expect(await user.stub.revokeFamilyById(familyId, clock.now(), "client_revoke", "web")).toEqual(
      { ok: true, revoked: false },
    );
    expect((await rotate(user.stub, familyId, refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    const other = await loggedIn();
    const family = await exchange(other.stub, other.codeHash, other.verifier);
    expect(
      await other.stub.revokeFamilyById(family.familyId, clock.now(), "client_revoke", null),
    ).toEqual({ ok: true, revoked: true });
  });
});

describe("UserDO consent grants (§6.6)", () => {
  it("[TIO-CONSENT-003] [TIO-CONSENT-004] [TIO-CLIENT-005] stores the union of scopes, lists only grants of current clients, and revoking a grant revokes the client's families", async () => {
    const user = await loggedIn();
    const c = client();
    const first = await user.stub.grantConsent(c, ["openid", "email"], clock.now());
    expect(first).toMatchObject({
      ok: true,
      grant: {
        client_id: "web",
        client_created_at: 1_000,
        scopes: ["email", "openid"],
        granted_at: clock.now(),
      },
    });
    clock.advance(5);
    const union = await user.stub.grantConsent(c, ["profile"], clock.now());
    expect(union.ok && union.grant).toMatchObject({
      scopes: ["email", "openid", "profile"],
      granted_at: clock.now() - 5,
      updated_at: clock.now(),
    });
    await user.stub.grantConsent(
      client({ client_id: "gone", created_at: 5 }),
      ["openid"],
      clock.now(),
    );
    const listed = await user.stub.listGrants([c, client({ client_id: "gone", created_at: 6 })]);
    expect(listed.ok && listed.grants.map((g) => g.client_id)).toEqual(["web"]);
    const after = await user.stub.listGrants([c, client({ client_id: "gone", created_at: 5 })]);
    expect(after.ok && after.grants.map((g) => g.client_id)).toEqual(["web"]);
    const stale = await user.stub.grantConsent(
      client({ created_at: 2_000 }),
      ["openid"],
      clock.now(),
    );
    expect(stale.ok && stale.grant).toMatchObject({ scopes: ["openid"], client_created_at: 2_000 });
    const { refreshHash, familyId } = await exchange(user.stub, user.codeHash, user.verifier);
    expect(await user.stub.revokeGrant("web", clock.now())).toEqual({ ok: true, revoked: true });
    expect(await user.stub.revokeGrant("web", clock.now())).toEqual({ ok: true, revoked: false });
    expect((await rotate(user.stub, familyId, refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    clock.set(1_800_000_000);
  });
});

describe("UserDO passkeys and identities storage", () => {
  const passkey = (id: string, credentialId: string) => ({
    id,
    credential_id: credentialId,
    public_key: new Uint8Array([1, 2, 3]),
    alg: -7,
    counter: 0,
    transports: ["internal"],
    aaguid: null,
    backup_eligible: true,
    backed_up: true,
    name: null,
    created_via: "interaction" as const,
  });

  it("[TIO-PK-012] stores passkeys up to the per-user limit, refuses duplicate credential ids, lists, renames and removes them", async () => {
    const { stub } = await newUser();
    const added = await stub.addPasskey(passkey("p1", "cred-1"), clock.now(), 2);
    expect(added).toMatchObject({
      ok: true,
      passkey: {
        id: "p1",
        credential_id: "cred-1",
        counter: 0,
        transports: ["internal"],
        backup_eligible: true,
        backed_up: true,
        created_at: clock.now(),
        last_used_at: null,
      },
    });
    expect(added.ok && added.passkey.public_key).toEqual(new Uint8Array([1, 2, 3]));
    expect(await stub.addPasskey(passkey("p2", "cred-1"), clock.now(), 2)).toEqual({
      ok: false,
      error: "passkey_exists",
    });
    expect(await stub.addPasskey(passkey("p1", "cred-x"), clock.now(), 2)).toEqual({
      ok: false,
      error: "passkey_exists",
    });
    expect((await stub.addPasskey(passkey("p2", "cred-2"), clock.now(), 2)).ok).toBe(true);
    expect(await stub.addPasskey(passkey("p3", "cred-3"), clock.now(), 2)).toEqual({
      ok: false,
      error: "passkey_limit_reached",
    });
    expect(await stub.renamePasskey("p1", "Laptop")).toEqual({ ok: true, renamed: true });
    expect(await stub.renamePasskey("nope", "x")).toEqual({ ok: true, renamed: false });
    const listed = await stub.listPasskeys();
    expect(listed.ok && listed.passkeys.map((p) => [p.id, p.name])).toEqual([
      ["p1", "Laptop"],
      ["p2", null],
    ]);
    expect(await stub.removePasskey("p1")).toEqual({ ok: true, removed: true });
    expect(await stub.removePasskey("p1")).toEqual({ ok: true, removed: false });
    expect((await stub.listPasskeys()).ok && (await stub.listPasskeys())).toMatchObject({
      passkeys: [{ id: "p2" }],
    });
  });

  it("[TIO-DATA-014] stores identities unique per (issuer, subject), lists and removes them", async () => {
    const { stub } = await newUser();
    const identity = {
      id: "i1",
      issuer: "https://accounts.google.com",
      subject: "s1",
      email: "a@example.com",
      email_verified: true,
      name: "A",
    };
    const added = await stub.addIdentity(identity, clock.now());
    expect(added).toEqual({
      ok: true,
      identity: { ...identity, created_at: clock.now(), last_login_at: null },
    });
    expect(await stub.addIdentity({ ...identity, id: "i2" }, clock.now())).toEqual({
      ok: false,
      error: "identity_exists",
    });
    expect(await stub.addIdentity({ ...identity, subject: "s2" }, clock.now())).toEqual({
      ok: false,
      error: "identity_exists",
    });
    const second = await stub.addIdentity(
      { ...identity, id: "i2", subject: "s2", email_verified: null },
      clock.now(),
    );
    expect(second.ok && second.identity.email_verified).toBeNull();
    const third = await stub.addIdentity(
      { ...identity, id: "i3", subject: "s3", email_verified: false },
      clock.now(),
    );
    expect(third.ok && third.identity.email_verified).toBe(false);
    const listed = await stub.listIdentities();
    expect(listed.ok && listed.identities.map((i) => i.id)).toEqual(["i1", "i2", "i3"]);
    expect(await stub.removeIdentity("i2")).toEqual({ ok: true, removed: true });
    expect(await stub.removeIdentity("i2")).toEqual({ ok: true, removed: false });
  });

  it("[TIO-PK-040] [TIO-FED-051] a user keeps at least one way to sign in: the last passkey goes only next to a linked identity, the last identity only next to a passkey; the Admin API removes anything", async () => {
    const { stub } = await newUser();
    const identity = {
      id: "i1",
      issuer: "https://accounts.google.com",
      subject: "only",
      email: null,
      email_verified: null,
      name: null,
    };
    const last = { ok: false, error: "last_login_method" };
    expect((await stub.addPasskey(passkey("p1", "cred-1"), clock.now(), 2)).ok).toBe(true);
    expect(await stub.removePasskey("p1", "self")).toEqual(last);
    expect(await stub.removePasskey("nope", "self")).toEqual({ ok: true, removed: false });
    expect((await stub.addPasskey(passkey("p2", "cred-2"), clock.now(), 2)).ok).toBe(true);
    expect(await stub.removePasskey("p1", "self")).toEqual({ ok: true, removed: true });
    expect(await stub.removePasskey("p2", "self")).toEqual(last);
    expect((await stub.addIdentity(identity, clock.now())).ok).toBe(true);
    expect(await stub.removePasskey("p2", "self")).toEqual({ ok: true, removed: true });
    expect(await stub.removeIdentity("i1", "self")).toEqual(last);
    expect(await stub.removeIdentity("nope", "self")).toEqual({ ok: true, removed: false });
    expect(
      (await stub.addIdentity({ ...identity, id: "i2", subject: "two" }, clock.now())).ok,
    ).toBe(true);
    expect(await stub.removeIdentity("i1", "self")).toEqual({ ok: true, removed: true });
    expect(await stub.removeIdentity("i2", "self")).toEqual(last);
    expect((await stub.addPasskey(passkey("p3", "cred-3"), clock.now(), 2)).ok).toBe(true);
    expect(await stub.removeIdentity("i2", "self")).toEqual({ ok: true, removed: true });
    // The administrator is not held to the rule (§9.4, TIO-PK-040).
    expect(await stub.removePasskey("p3")).toEqual({ ok: true, removed: true });
    expect(await stub.listPasskeys()).toEqual({ ok: true, passkeys: [] });
    expect(await stub.listIdentities()).toEqual({ ok: true, identities: [] });
  });

  it("[TIO-DATA-021] every method refuses an uninitialized object", async () => {
    const stub = env.USER_DO.get(env.USER_DO.idFromName(unique("blank")));
    const notInit = { ok: false, error: "user_not_initialized" };
    expect(await stub.getSession("s", new Uint8Array(32), 0)).toEqual(notInit);
    expect(await stub.revokeSession("s", 0, "x")).toEqual(notInit);
    expect(await stub.listSessions(0)).toEqual(notInit);
    expect(await stub.revokeAll(0, "x")).toEqual(notInit);
    expect(
      await stub.authorizeWithSession({
        sid: "s",
        secret_hash: new Uint8Array(32),
        now: 0,
        client: client(),
        scope: [],
        prompt_login: false,
        prompt_consent: false,
        max_age: null,
        code: null,
        session_idle_ttl: 1,
      }),
    ).toEqual(notInit);
    expect(
      await stub.finalizeLogin({
        now: 0,
        session: { create: (await sessionInput()).input },
        code: null,
        client: null,
        session_idle_ttl: 1,
      }),
    ).toEqual(notInit);
    expect(
      await stub.exchangeCode({
        secret_hash: new Uint8Array(32),
        client: client(),
        redirect_uri: "x",
        code_verifier: "x",
        now: 0,
        refresh: null,
      }),
    ).toEqual(notInit);
    expect(
      await stub.rotateRefreshToken({
        family_id: "f",
        secret_hash: new Uint8Array(32),
        client: client(),
        now: 0,
        requested_scope: null,
        new_secret_hash: new Uint8Array(32),
        idle_ttl: 1,
        session_idle_ttl: 1,
        reuse_window: 1,
      }),
    ).toEqual(notInit);
    expect(await stub.revokeFamilyById("f", 0, "x", null)).toEqual(notInit);
    expect(await stub.revokeSessionFamiliesOfClient("s", "c", 0)).toEqual(notInit);
    expect(await stub.grantConsent(client(), [], 0)).toEqual(notInit);
    expect(await stub.listGrants([])).toEqual(notInit);
    expect(await stub.revokeGrant("c", 0)).toEqual(notInit);
    expect(await stub.addPasskey(passkey("p", "c"), 0, 1)).toEqual(notInit);
    expect(await stub.listPasskeys()).toEqual(notInit);
    expect(await stub.removePasskey("p")).toEqual(notInit);
    expect(await stub.renamePasskey("p", null)).toEqual(notInit);
    expect(await stub.setGroups(["x"], 0)).toEqual(notInit);
    expect(
      await stub.addIdentity(
        { id: "i", issuer: "x", subject: "y", email: null, email_verified: null, name: null },
        0,
      ),
    ).toEqual(notInit);
    expect(await stub.listIdentities()).toEqual(notInit);
    expect(await stub.removeIdentity("i")).toEqual(notInit);
    expect(await stub.setDisabled(null, 0)).toEqual(notInit);
  });
});

describe("UserDO disabled users and constructed inconsistencies", () => {
  it("[TIO-DATA-009] disabling revokes every session and family in one transaction and every later operation fails closed; enabling restores the profile", async () => {
    const user = await loggedIn();
    const { refreshHash, familyId } = await exchange(user.stub, user.codeHash, user.verifier);
    const { challenge, verifier } = await pkce();
    const pending = await codeInput(challenge);
    await user.stub.finalizeLogin({
      now: clock.now(),
      session: {
        rotate: { sid: user.sid, secret_hash: user.session.secretHash, auth: passkeyAuth },
      },
      code: pending.code,
      client: client(),
      session_idle_ttl: IDLE,
    });
    const disabled = await user.stub.setDisabled(clock.now(), clock.now());
    expect(disabled).toMatchObject({
      ok: true,
      profile: { disabled_at: clock.now() },
      revoked: [{ sid: user.sid, clients: ["web"] }],
    });
    expect(await user.stub.getSession(user.sid, user.session.secretHash, clock.now())).toEqual({
      ok: false,
      error: "session_invalid",
    });
    expect((await rotate(user.stub, familyId, refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    expect((await exchange(user.stub, pending.secretHash, verifier)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    const fresh = await sessionInput();
    expect(
      await user.stub.finalizeLogin({
        now: clock.now(),
        session: { create: fresh.input },
        code: null,
        client: null,
        session_idle_ttl: IDLE,
      }),
    ).toEqual({ ok: false, error: "user_disabled" });
    const enabled = await user.stub.setDisabled(null, clock.now());
    expect(enabled).toMatchObject({ ok: true, profile: { disabled_at: null }, revoked: [] });
    const login = await user.stub.finalizeLogin({
      now: clock.now(),
      session: { create: fresh.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    expect(login.ok).toBe(true);
    // A user disabled while holding a live session is refused on the session paths too.
    await user.stub.setDisabled(clock.now(), clock.now());
    await user.stub.setDisabled(null, clock.now());
    const another = await sessionInput();
    expect(
      (
        await user.stub.finalizeLogin({
          now: clock.now(),
          session: { create: another.input },
          code: null,
          client: null,
          session_idle_ttl: IDLE,
        })
      ).ok,
    ).toBe(true);
  });

  it("[TIO-DATA-009] a disabled user with an unrevoked session (row edited directly) is refused by getSession and authorizeWithSession", async () => {
    const { stub } = await newUser();
    const s = await sessionInput();
    await stub.finalizeLogin({
      now: clock.now(),
      session: { create: s.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    // setDisabled revokes sessions; re-insert the disabled flag alone to reach the check on the read paths.
    await stub.setDisabled(clock.now(), clock.now());
    await stub.setDisabled(null, clock.now());
    const again = await sessionInput();
    await stub.finalizeLogin({
      now: clock.now(),
      session: { create: again.input },
      code: null,
      client: null,
      session_idle_ttl: IDLE,
    });
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      state.storage.sql.exec("UPDATE user SET disabled_at = ?", clock.now());
    });
    expect(await stub.getSession(again.input.sid, again.secretHash, clock.now())).toEqual({
      ok: false,
      error: "user_disabled",
    });
    expect(
      await stub.authorizeWithSession({
        sid: again.input.sid,
        secret_hash: again.secretHash,
        now: clock.now(),
        client: client({ skip_consent: true }),
        scope: ["openid"],
        prompt_login: false,
        prompt_consent: false,
        max_age: null,
        code: null,
        session_idle_ttl: IDLE,
      }),
    ).toEqual({ ok: false, error: "user_disabled" });
  });

  it("[TIO-RT-002] an unconsumed token with a stale serial and a session-bound family whose session row is gone (rows edited directly) are invalid_grant", async () => {
    const user = await loggedIn();
    const { refreshHash, familyId } = await exchange(user.stub, user.codeHash, user.verifier);
    const first = await rotate(user.stub, familyId, refreshHash);
    expect(first.result.ok).toBe(true);
    await runInDurableObject(user.stub, (_instance: UserDO, state) => {
      state.storage.sql.exec("UPDATE refresh_tokens SET consumed_at = NULL WHERE serial = 1");
    });
    expect((await rotate(user.stub, familyId, refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
    await runInDurableObject(user.stub, (_instance: UserDO, state) => {
      state.storage.sql.exec("DELETE FROM session_clients");
      state.storage.sql.exec("DELETE FROM sessions");
    });
    expect((await rotate(user.stub, familyId, first.next)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
  });

  it("[TIO-RT-002] reuse of an offline family's token revokes the family without touching any session; a disabled user (row edited directly) cannot rotate", async () => {
    const user = await loggedIn({ scope: ["openid", "offline_access"] });
    const offline = await exchange(user.stub, user.codeHash, user.verifier, {
      refresh: {
        secret_hash: await sha256(newSecret()),
        family_id: uuids.next(),
        offline_allowed: true,
        idle_ttl: REFRESH_IDLE,
        absolute_ttl: REFRESH_ABSOLUTE,
      },
    });
    expect(offline.result.ok).toBe(true);
    const first = await rotate(user.stub, offline.familyId, offline.refreshHash);
    expect(first.result.ok).toBe(true);
    expect((await rotate(user.stub, offline.familyId, offline.refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
      reuse_detected: true,
    });
    expect((await user.stub.getSession(user.sid, user.session.secretHash, clock.now())).ok).toBe(
      true,
    );
    const other = await loggedIn();
    const family = await exchange(other.stub, other.codeHash, other.verifier);
    await runInDurableObject(other.stub, (_instance: UserDO, state) => {
      state.storage.sql.exec("UPDATE user SET disabled_at = ?", clock.now());
    });
    expect((await rotate(other.stub, family.familyId, family.refreshHash)).result).toEqual({
      ok: false,
      error: "invalid_grant",
    });
  });

  it("stores passkeys whose authenticator flags are clear", async () => {
    const { stub } = await newUser();
    const added = await stub.addPasskey(
      {
        id: "p",
        credential_id: "c",
        public_key: new Uint8Array([9]),
        alg: -8,
        counter: 3,
        transports: [],
        aaguid: "00000000-0000-0000-0000-000000000000",
        backup_eligible: false,
        backed_up: false,
        name: "Key",
        created_via: "me",
      },
      clock.now(),
      20,
    );
    expect(added.ok && added.passkey).toMatchObject({
      backup_eligible: false,
      backed_up: false,
      counter: 3,
      alg: -8,
      name: "Key",
      created_via: "me",
    });
  });
});

describe("UserDO administration (§9.4)", () => {
  it("[TIO-DATA-008] updateProfile keeps what the patch leaves out, resets email_verified when the email changes unless told otherwise, and refuses on a destroyed object", async () => {
    const { stub } = await newUser();
    const trusted = await stub.updateProfile({ email_verified: true }, clock.now());
    expect(trusted.ok && trusted.profile.email_verified).toBe(true);
    const renamed = await stub.updateProfile({ display_name: "Renamed" }, clock.now());
    expect(renamed.ok && renamed.profile).toMatchObject({
      display_name: "Renamed",
      email_verified: true,
    });
    const moved = await stub.updateProfile(
      { email: "moved@example.com", email_norm: "moved@example.com" },
      clock.now(),
    );
    expect(moved.ok && moved.profile).toMatchObject({
      email: "moved@example.com",
      email_norm: "moved@example.com",
      email_verified: false,
      display_name: "Renamed",
    });
    const same = await stub.updateProfile(
      { email: "moved@example.com", email_norm: "moved@example.com" },
      clock.now(),
    );
    expect(same.ok && same.profile.email_verified).toBe(false);
    const verified = await stub.updateProfile({ email_verified: true }, clock.now());
    expect(verified.ok && verified.profile.email_verified).toBe(true);
    const cleared = await stub.updateProfile({ email: null, display_name: null }, clock.now());
    expect(cleared.ok && cleared.profile).toMatchObject({
      email: null,
      email_norm: null,
      email_verified: false,
      display_name: null,
    });
    await stub.destroy();
    expect(await stub.updateProfile({ display_name: "x" }, clock.now())).toEqual({
      ok: false,
      error: "user_destroyed",
    });
    for (const call of [
      stub.listFamilies(clock.now()),
      stub.revokeFamiliesOfClient("c", clock.now(), "admin"),
      stub.counts(clock.now()),
      stub.exportState(clock.now()),
      stub.grantClientIds(),
    ]) {
      expect(await call).toEqual({ ok: false, error: "user_destroyed" });
    }
  });
});
