import { decodeJwt } from "jose";
import { z } from "zod";
import type { Auditor } from "../audit/events.ts";
import { signJwt } from "../crypto/jwt.ts";
import type { LoadedKeys } from "../crypto/keystore.ts";
import { UuidV7 } from "../crypto/uuid.ts";
import type { Db } from "../db/db.ts";
import type { Clock, Env } from "../env.ts";
import type { Logger } from "../obs/log.ts";
import type { ClientCache } from "../oidc/client-cache.ts";
import { logoutTokenClaims } from "../oidc/tokens.ts";

// Back-channel logout (spec §5.10.2): one logout token per client of an ended
// session, delivered right away in `waitUntil` (TIO-LOGOUT-011) and, when
// that fails, handed to the TASKS queue whose consumer retries on the
// schedule of TIO-LOGOUT-012 with the same `jti`. Every revocation path ends
// here (TIO-LOGOUT-013): RP-initiated logout, the logout interaction, the
// Self-service and Admin APIs, disable and delete.

export const BACKCHANNEL_TIMEOUT_MS = 5_000;
/** Seconds before each retry: the first retry after 30 s, the fifth after 2 h (TIO-LOGOUT-012). */
export const RETRY_DELAYS_SECONDS = [30, 120, 600, 1_800, 7_200] as const;
export const MAX_ATTEMPTS = RETRY_DELAYS_SECONDS.length;

/** The queue message of §4.5. `attempt` counts retries already made when the consumer reads it. */
export const BackchannelTaskSchema = z.object({
  kind: z.literal("backchannel_logout"),
  client_id: z.string().min(1),
  uri: z.string().min(1),
  token: z.string().min(1),
  attempt: z.int().min(1),
  sid: z.string().min(1),
  uid: z.string().min(1),
});

export type BackchannelTask = z.infer<typeof BackchannelTaskSchema>;

export interface EndedSession {
  uid: string;
  sid: string;
  /** The clients that took part in the session (`session_clients`). */
  clients: string[];
}

export interface BackchannelDeps {
  env: Env;
  db: Db;
  keys: LoadedKeys;
  issuer: string;
  clients: ClientCache;
  clock: Clock;
  audit: Auditor;
  logger: Logger;
  waitUntil: (promise: Promise<unknown>) => void;
  fetch?: typeof fetch;
}

export type DeliveryResult = { ok: true } | { ok: false; reason: string };

/** POSTs the token as a form with a bounded wait; anything but 2xx is a failure. */
export async function deliverLogoutToken(
  uri: string,
  token: string,
  options: { fetch?: typeof fetch; timeoutMs?: number } = {},
): Promise<DeliveryResult> {
  const doFetch = options.fetch ?? fetch;
  try {
    const response = await doFetch(uri, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ logout_token: token }).toString(),
      signal: AbortSignal.timeout(options.timeoutMs ?? BACKCHANNEL_TIMEOUT_MS),
    });
    return response.ok ? { ok: true } : { ok: false, reason: `status_${response.status}` };
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    return { ok: false, reason: timedOut ? "timeout" : "unreachable" };
  }
}

/** A logout token for one client, minted under the signing key; `jti` is kept across retries. */
export async function mintLogoutToken(
  keys: LoadedKeys,
  input: { issuer: string; clientId: string; sub: string; sid: string; jti: string; now: number },
): Promise<string> {
  return signJwt(keys, "logout+jwt", logoutTokenClaims(input));
}

/** Enqueues a retry; a queue failure is logged and never fails the caller (TIO-AUDIT-012). */
export async function enqueueRetry(
  env: Env,
  logger: Logger,
  task: BackchannelTask,
  delaySeconds: number,
): Promise<void> {
  try {
    await env.TASKS.send(task, { delaySeconds });
  } catch (error) {
    logger.log("error", "backchannel retry could not be queued", {
      client_id: task.client_id,
      attempt: task.attempt,
      reason: String(error),
    });
  }
}

/**
 * Notifies every client of an ended session that registered a
 * `backchannel_logout_uri` (TIO-LOGOUT-005, TIO-LOGOUT-011). The deliveries
 * run after the response, in `waitUntil`; the events are emitted now.
 */
export async function notifyClients(deps: BackchannelDeps, ended: EndedSession): Promise<void> {
  const now = deps.clock.now();
  const uuids = new UuidV7(deps.clock);
  for (const clientId of ended.clients) {
    let uri: string | null;
    try {
      uri = (await deps.clients.get(deps.db, clientId))?.backchannel_logout_uri ?? null;
    } catch {
      uri = null;
    }
    if (uri === null) continue;
    const jti = uuids.next();
    const token = await mintLogoutToken(deps.keys, {
      issuer: deps.issuer,
      clientId,
      sub: ended.uid,
      sid: ended.sid,
      jti,
      now,
    });
    deps.audit.emit({
      type: "logout.backchannel_sent",
      outcome: "success",
      actor: { kind: "system", id: null },
      user_id: ended.uid,
      client_id: clientId,
      sid: ended.sid,
      data: { jti },
    });
    const task: BackchannelTask = {
      kind: "backchannel_logout",
      client_id: clientId,
      uri,
      token,
      attempt: 1,
      sid: ended.sid,
      uid: ended.uid,
    };
    deps.waitUntil(
      deliverLogoutToken(uri, token, deps.fetch === undefined ? {} : { fetch: deps.fetch }).then(
        async (delivered) => {
          if (delivered.ok) return;
          deps.logger.log("warn", "backchannel logout failed, queued for retry", {
            client_id: clientId,
            reason: delivered.reason,
          });
          await enqueueRetry(deps.env, deps.logger, task, RETRY_DELAYS_SECONDS[0]);
        },
      ),
    );
  }
}

export interface ConsumerDeps {
  env: Env;
  keys: LoadedKeys;
  issuer: string;
  clock: Clock;
  audit: Auditor;
  logger: Logger;
  fetch?: typeof fetch;
}

/**
 * One retry from the queue (TIO-LOGOUT-012): the token is re-minted with the
 * original `jti` (the first one has long expired by the last retry), delivered,
 * and either done, queued again with the next delay, or given up with
 * `logout.backchannel_failed` after the fifth attempt.
 */
export async function retryBackchannel(deps: ConsumerDeps, body: unknown): Promise<void> {
  const parsed = BackchannelTaskSchema.safeParse(body);
  const jti = parsed.success ? decodeJwtId(parsed.data.token) : null;
  if (!parsed.success || jti === null) {
    deps.logger.log("warn", "malformed backchannel task dropped", {});
    return;
  }
  const task = parsed.data;
  const token = await mintLogoutToken(deps.keys, {
    issuer: deps.issuer,
    clientId: task.client_id,
    sub: task.uid,
    sid: task.sid,
    jti,
    now: deps.clock.now(),
  });
  const delivered = await deliverLogoutToken(
    task.uri,
    token,
    deps.fetch === undefined ? {} : { fetch: deps.fetch },
  );
  if (delivered.ok) return;
  if (task.attempt >= MAX_ATTEMPTS) {
    deps.audit.emit({
      type: "logout.backchannel_failed",
      outcome: "failure",
      actor: { kind: "system", id: null },
      user_id: task.uid,
      client_id: task.client_id,
      sid: task.sid,
      reason: delivered.reason,
      data: { jti, attempts: task.attempt },
    });
    return;
  }
  await enqueueRetry(
    deps.env,
    deps.logger,
    { ...task, token, attempt: task.attempt + 1 },
    RETRY_DELAYS_SECONDS[task.attempt] as number,
  );
}

/** The `jti` of a token the OP minted; null for anything unreadable. */
function decodeJwtId(token: string): string | null {
  try {
    const jti = decodeJwt(token).jti;
    return typeof jti === "string" ? jti : null;
  } catch {
    return null;
  }
}
