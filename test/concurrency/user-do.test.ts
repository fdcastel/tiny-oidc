import { describe, expect, it } from "vitest";
import { sha256 } from "../../src/crypto/hash.ts";
import { newSecret } from "../../src/crypto/random.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import type { ClientRef, ExchangeOutcome, RotateOutcome } from "../../src/do/UserDO.ts";
import { ACR } from "../../src/oidc/capabilities.ts";
import { encodeBase64Url } from "../../src/util/base64url.ts";
import { FakeClock } from "../support/clock.ts";
import { userProfile } from "../support/factories.ts";
import { env } from "../support/op.ts";

// Exactly-once semantics under parallelism (TIO-TEST-010, TIO-DATA-020): the
// Durable Object serializes the transactions, so 20 racing callers see one
// winner and the specified side effect.

const clock = new FakeClock(1_800_000_000);
const uuids = new UuidV7(clock);
const client: ClientRef = {
  client_id: "web",
  created_at: 1,
  skip_consent: true,
  allowed_groups: null,
};
const PARALLEL = 20;

async function loggedInWithCode() {
  const profile = userProfile(clock);
  const stub = env.USER_DO.get(env.USER_DO.idFromName(profile.id));
  await stub.init(profile, clock.now());
  const sessionSecret = await sha256(newSecret());
  const verifier = encodeBase64Url(newSecret());
  const codeHash = await sha256(newSecret());
  const login = await stub.finalizeLogin({
    now: clock.now(),
    session: {
      create: {
        sid: uuids.next(),
        secret_hash: sessionSecret,
        auth: { auth_time: clock.now(), amr: ["hwk", "user"], acr: ACR.passkey, upstream: null },
        metadata: { ip_hash: null, ua_family: null, country: null },
        idle_ttl: 86_400,
        absolute_ttl: 2_592_000,
      },
    },
    code: {
      secret_hash: codeHash,
      client_id: "web",
      redirect_uri: "https://rp.example.com/cb",
      scope: ["openid"],
      nonce: null,
      code_challenge: encodeBase64Url(await sha256(verifier)),
    },
    client,
    session_idle_ttl: 86_400,
  });
  if (!login.ok) throw new Error(login.error);
  return { stub, codeHash, verifier, sid: login.sid };
}

describe("UserDO exactly-once", () => {
  it("[TIO-TEST-010] [TIO-DATA-020] [TIO-TOKEN-012] 20 parallel exchanges of one code: one success, the rest invalid_grant, and the winner's family revoked by the replay", async () => {
    const { stub, codeHash, verifier } = await loggedInWithCode();
    const attempts = await Promise.all(
      Array.from({ length: PARALLEL }, async () => {
        const family = {
          secret_hash: await sha256(newSecret()),
          family_id: uuids.next(),
          kind: "session" as const,
          idle_ttl: 1_209_600,
          absolute_ttl: 2_592_000,
        };
        const result = await stub.exchangeCode({
          secret_hash: codeHash,
          client,
          redirect_uri: "https://rp.example.com/cb",
          code_verifier: verifier,
          now: clock.now(),
          refresh: family,
        });
        return { result, family };
      }),
    );
    const winners = attempts.filter((a) => a.result.ok);
    const losers = attempts.filter((a) => !a.result.ok);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(PARALLEL - 1);
    for (const loser of losers) {
      expect(loser.result).toEqual({ ok: false, error: "invalid_grant", replay: true });
    }
    const winner = winners[0] as {
      result: ExchangeOutcome;
      family: { secret_hash: Uint8Array; family_id: string };
    };
    const rotation = await stub.rotateRefreshToken({
      family_id: winner.family.family_id,
      secret_hash: winner.family.secret_hash,
      client,
      now: clock.now(),
      requested_scope: null,
      new_secret_hash: await sha256(newSecret()),
      idle_ttl: 1_209_600,
      session_idle_ttl: 86_400,
      reuse_window: 86_400,
    });
    expect(rotation).toEqual({ ok: false, error: "invalid_grant" });
  });

  it("[TIO-TEST-010] [TIO-RT-003] 20 parallel rotations of one refresh token: exactly one success; one loser detects the reuse and revokes the family and its session", async () => {
    const { stub, codeHash, verifier, sid } = await loggedInWithCode();
    const first = {
      secret_hash: await sha256(newSecret()),
      family_id: uuids.next(),
      kind: "session" as const,
      idle_ttl: 1_209_600,
      absolute_ttl: 2_592_000,
    };
    const exchanged = await stub.exchangeCode({
      secret_hash: codeHash,
      client,
      redirect_uri: "https://rp.example.com/cb",
      code_verifier: verifier,
      now: clock.now(),
      refresh: first,
    });
    expect(exchanged.ok).toBe(true);
    const results: RotateOutcome[] = await Promise.all(
      Array.from({ length: PARALLEL }, async () =>
        stub.rotateRefreshToken({
          family_id: first.family_id,
          secret_hash: first.secret_hash,
          client,
          now: clock.now(),
          requested_scope: null,
          new_secret_hash: await sha256(newSecret()),
          idle_ttl: 1_209_600,
          session_idle_ttl: 86_400,
          reuse_window: 86_400,
        }),
      ),
    );
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    const reuse = results.filter((r) => !r.ok && r.reuse_detected);
    expect(reuse).toHaveLength(1);
    expect(reuse[0]).toEqual({
      ok: false,
      error: "invalid_grant",
      reuse_detected: true,
      revoked_session_clients: ["web"],
    });
    expect(results.filter((r) => !r.ok && !r.reuse_detected)).toHaveLength(PARALLEL - 2);
    const sessions = await stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions.map((s) => s.sid)).not.toContain(sid);
  });
});
