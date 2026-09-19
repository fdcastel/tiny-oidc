import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { Auditor } from "../../src/audit/events.ts";
import { signJwt } from "../../src/crypto/jwt.ts";
import { KeyStore } from "../../src/crypto/keystore.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import type { Env } from "../../src/env.ts";
import {
  BACKCHANNEL_TIMEOUT_MS,
  deliverLogoutToken,
  enqueueRetry,
  notifyClients,
  retryBackchannel,
} from "../../src/logout/backchannel.ts";
import { Logger, type LogLine } from "../../src/obs/log.ts";
import { ClientCache } from "../../src/oidc/client-cache.ts";
import { FakeClock } from "../support/clock.ts";
import { createTestClient } from "../support/factories.ts";
import { mountOrigin } from "../support/fetch-allowlist.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";

// The back-channel pieces on their own (spec §5.10.2): delivery through the
// real outbound path with its defaults, the transport failures, the queue
// hand-off, and the guards of the consumer.

const clock = new FakeClock(1_800_000_000);
const db = Db.from(env.DB);
const RP = "https://rp.example.com";
const lines: LogLine[] = [];
const logger = new Logger((line) => lines.push(line), "debug");
const auditor = () =>
  new Auditor(
    { request_id: "r", ip_hash: null, country: null, ua_family: null },
    new UuidV7(clock),
    clock,
  );

const received: string[] = [];
let status = 200;
mountOrigin(RP, async (request) => {
  received.push(new URLSearchParams(await request.text()).get("logout_token") ?? "");
  return new Response(null, { status });
});

const tasksEnv = (send: (body: unknown, options?: unknown) => Promise<void>): Env =>
  ({ ...env, TASKS: { send } }) as unknown as Env;

describe("back-channel delivery", () => {
  it("[TIO-LOGOUT-011] posts the token as a form through the outbound path with a 5 s default, and tells timeouts, unreachable endpoints and error statuses apart", async () => {
    expect(BACKCHANNEL_TIMEOUT_MS).toBe(5_000);
    expect(await deliverLogoutToken(`${RP}/bc`, "tok")).toEqual({ ok: true });
    expect(received).toEqual(["tok"]);
    status = 503;
    expect(await deliverLogoutToken(`${RP}/bc`, "tok")).toEqual({
      ok: false,
      reason: "status_503",
    });
    status = 200;
    const hanging: typeof fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      });
    expect(await deliverLogoutToken(`${RP}/bc`, "tok", { fetch: hanging, timeoutMs: 20 })).toEqual({
      ok: false,
      reason: "timeout",
    });
    const refusing: typeof fetch = async () => {
      throw new Error("refused");
    };
    expect(await deliverLogoutToken(`${RP}/bc`, "tok", { fetch: refusing })).toEqual({
      ok: false,
      reason: "unreachable",
    });
    // An origin nobody mounted is unreachable under the interceptor too (TIO-ARCH-016).
    expect(await deliverLogoutToken("https://nowhere.example.net/bc", "tok")).toEqual({
      ok: false,
      reason: "unreachable",
    });
  });

  it("[TIO-LOGOUT-011] [TIO-LOGOUT-012] a queue that refuses the retry is logged whatever it throws; the consumer drops a token without jti; notifyClients honours an injected fetch", async () => {
    const task = {
      kind: "backchannel_logout" as const,
      client_id: "c",
      uri: `${RP}/bc`,
      token: "t",
      attempt: 1,
      sid: "s",
      uid: "u",
    };
    await enqueueRetry(
      tasksEnv(async () => {
        throw "plain string";
      }),
      logger,
      task,
      30,
    );
    expect(lines.at(-1)).toMatchObject({
      msg: "backchannel retry could not be queued",
      reason: "plain string",
    });
    const keys = await new KeyStore(clock).get(db, testKeys());
    const noJti = await signJwt(keys, "logout+jwt", {
      iss: "https://auth.example.com",
      sub: "u",
      aud: "c",
      iat: clock.now(),
      exp: clock.now() + 120,
    });
    received.length = 0;
    await retryBackchannel(
      { env, keys, issuer: "https://auth.example.com", clock, audit: auditor(), logger },
      { ...task, token: noJti },
    );
    expect(lines.at(-1)).toMatchObject({ msg: "malformed backchannel task dropped" });
    expect(received).toEqual([]);
    // notifyClients with a fetch of its own: the token goes through it, not the network.
    const { client } = await createTestClient(db, clock, {
      redirect_uris: ["https://rp.example.com/cb"],
      backchannel_logout_uri: `${RP}/injected`,
    });
    const seen: string[] = [];
    const capture: typeof fetch = async (url, init) => {
      seen.push(`${String(url)} ${new URLSearchParams(String(init?.body)).get("logout_token")}`);
      return new Response(null, { status: 200 });
    };
    const pending: Promise<unknown>[] = [];
    const audit = auditor();
    await notifyClients(
      {
        env,
        db,
        keys,
        issuer: "https://auth.example.com",
        clients: new ClientCache(clock),
        clock,
        audit,
        logger,
        waitUntil: (p) => {
          pending.push(p);
        },
        fetch: capture,
      },
      { uid: "u", sid: "s", clients: [client.client_id, "missing-client"] },
    );
    await Promise.all(pending);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toContain(`${RP}/injected `);
    expect(decodeJwt(seen[0]?.split(" ")[1] as string)).toMatchObject({
      sub: "u",
      sid: "s",
      aud: client.client_id,
    });
    expect(received).toEqual([]);
    expect(audit.events.map((e) => e.type)).toEqual(["logout.backchannel_sent"]);
  });
});
