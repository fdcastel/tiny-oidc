// The load-test population and its tokens (spec §13.10, TIO-TEST-050,
// TIO-ADMIN-021), driven over HTTPS with no browser:
//
//   node perf/seed.ts generate --users 1000 [--seed 1 --groups staff --identities 2 --upstream-issuer URL]
//       NDJSON for `POST /api/v1/admin/import/users` on stdout.
//   node perf/seed.ts prepare  --issuer OP --client-id ID --client-secret S --login-url URL
//                              --fake-issuer URL --fake-client-id ID --fake-client-secret S [--rps 3]
//       Settings, the groups, the fake upstream and the relying parties; idempotent.
//   node perf/seed.ts import   --issuer OP --client-id ID --client-secret S --users 1000000
//                              [--from 0 --batch 1000 --clients 8 --sample 100 --report FILE --skip-if-seeded]
//       The import benchmark: batches through parallel clients, then the count and a sampled
//       deep comparison; the report is JSON. `--skip-if-seeded` does nothing when the
//       population's first and last users are already in the directory.
//   node perf/seed.ts harvest  --issuer OP --client-id ID --client-secret S --login-url URL
//                              --count 100000 [--from 0 --rate 50 --concurrency 20 --out FILE]
//       Federated logins through the fake upstream, one per user, each leaving a session cookie
//       and a refresh token in the NDJSON the k6 scenarios read.
//   node perf/seed.ts delete   --issuer OP --client-id ID --client-secret S --users 1000 [--from 0 --concurrency 20]
//       Deletes the population's users (their objects with them), so that the next import
//       places them again: a Durable Object lives where its first request entered, and the
//       nightly's measurements only mean something when the runner of the night created them.
//
// The values above are also read from TIO_PERF_ISSUER, TIO_PERF_CLIENT_ID,
// TIO_PERF_CLIENT_SECRET, TIO_PERF_LOGIN_URL, TIO_PERF_SEED, TIO_FAKE_ISSUER,
// TIO_FAKE_CLIENT_ID and TIO_FAKE_CLIENT_SECRET (the nightly job's secrets).

import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { parseArgs } from "node:util";
import {
  chunks,
  codeOf,
  cookieNamed,
  FailFast,
  interactionOf,
  percentiles,
  pkce,
  pool,
  RateLimiter,
} from "./lib/flow.ts";
import { DEFAULT_POPULATION, emailOf, type Population, seedBatch, subjectOf } from "./lib/lines.ts";

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    issuer: { type: "string", default: process.env["TIO_PERF_ISSUER"] },
    "client-id": { type: "string", default: process.env["TIO_PERF_CLIENT_ID"] },
    "client-secret": { type: "string", default: process.env["TIO_PERF_CLIENT_SECRET"] },
    "login-url": { type: "string", default: process.env["TIO_PERF_LOGIN_URL"] },
    "fake-issuer": { type: "string", default: process.env["TIO_FAKE_ISSUER"] },
    "fake-client-id": { type: "string", default: process.env["TIO_FAKE_CLIENT_ID"] },
    "fake-client-secret": { type: "string", default: process.env["TIO_FAKE_CLIENT_SECRET"] },
    alias: { type: "string", default: "fake" },
    rps: { type: "string", default: "3" },
    users: { type: "string", default: "1000" },
    from: { type: "string", default: "0" },
    count: { type: "string", default: "1000" },
    batch: { type: "string", default: "1000" },
    clients: { type: "string", default: "8" },
    sample: { type: "string", default: "100" },
    rate: { type: "string", default: "50" },
    concurrency: { type: "string", default: "20" },
    seed: { type: "string", default: process.env["TIO_PERF_SEED"] ?? DEFAULT_POPULATION.seed },
    groups: { type: "string", default: "" },
    identities: { type: "string", default: String(DEFAULT_POPULATION.identities) },
    "upstream-issuer": { type: "string" },
    report: { type: "string" },
    out: { type: "string", default: "perf/data/tokens.ndjson" },
    "skip-if-seeded": { type: "boolean", default: false },
  },
});

const command = positionals[0] ?? "generate";
const population: Population = {
  seed: values.seed as string,
  groups: values.groups === "" ? [] : (values.groups as string).split(","),
  identities: Number(values.identities),
  issuer: values["upstream-issuer"] ?? values["fake-issuer"] ?? DEFAULT_POPULATION.issuer,
};
const int = (name: keyof typeof values): number => {
  const n = Number(values[name]);
  if (!Number.isInteger(n) || n < 0) throw new Error(`--${name} must be a non-negative integer`);
  return n;
};
const need = (name: keyof typeof values): string => {
  const v = values[name];
  if (typeof v !== "string" || v === "") throw new Error(`--${name} is required`);
  return v;
};
const log = (message: string) => console.error(`seed: ${message}`);

// --- the admin session ------------------------------------------------------------------

/** A `client_credentials` administrator whose token is renewed before it expires. */
class Admin {
  readonly issuer: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private token: { value: string; at: number } | null = null;

  constructor(issuer: string, clientId: string, clientSecret: string) {
    this.issuer = issuer;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
  }

  async bearer(): Promise<string> {
    if (this.token && Date.now() - this.token.at < 8 * 60_000) return this.token.value;
    const res = await fetch(`${this.issuer}/token`, {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_type: "client_credentials", scope: "admin" }),
    });
    if (!res.ok) throw new Error(`admin token: ${res.status} ${await res.text()}`);
    const body = (await res.json()) as { access_token: string };
    this.token = { value: body.access_token, at: Date.now() };
    return body.access_token;
  }

  async call(
    method: string,
    path: string,
    body?: unknown,
    contentType = "application/json",
  ): Promise<Response> {
    const init: RequestInit = {
      method,
      headers: {
        authorization: `Bearer ${await this.bearer()}`,
        ...(body === undefined ? {} : { "content-type": contentType }),
      },
    };
    if (body !== undefined) init.body = typeof body === "string" ? body : JSON.stringify(body);
    // A connection reset under a thousand parallel calls is transport, not an answer: an
    // idempotent call is repeated; a POST is not (an import line must not run twice).
    const retries = method === "GET" || method === "DELETE" ? TRANSPORT_RETRIES : 0;
    for (let attempt = 0; ; attempt++) {
      try {
        return await fetch(`${this.issuer}/api/v1/admin/${path}`, init);
      } catch (error) {
        if (attempt >= retries) throw error;
        await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
      }
    }
  }

  async json<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: T }> {
    const res = await this.call(method, path, body);
    return { status: res.status, body: (await res.json()) as T };
  }
}

const admin = () => new Admin(need("issuer"), need("client-id"), need("client-secret"));
const rpIds = (count: number) => Array.from({ length: count }, (_, i) => `perf-rp-${i + 1}`);
const RP_REDIRECT = "https://perf-rp.invalid/callback";
/** How often an idempotent admin call is repeated after a transport error (a reset connection). */
const TRANSPORT_RETRIES = 2;
/** How often a delete retries a 503 (an object restarting under a deploy). */
const DELETE_RETRIES = 3;
/** A harvest whose first logins all fail stops here instead of running to its count. */
const HARVEST_FAIL_FAST = 100;

// --- generate ---------------------------------------------------------------------------

function generate(): void {
  const users = int("users");
  for (const c of chunks(int("from"), users, 1_000))
    process.stdout.write(seedBatch(population, c.from, c.count));
}

// --- prepare ----------------------------------------------------------------------------

async function prepare(): Promise<void> {
  const a = admin();
  const loginUrl = need("login-url");
  const settings = await a.json<{ error?: string }>("PATCH", "settings", {
    login_url: loginUrl,
    login_origins: [new URL(loginUrl).origin],
  });
  if (settings.status !== 200)
    throw new Error(`settings: ${settings.status} ${JSON.stringify(settings.body)}`);
  log("settings: login_url and login_origins set");
  for (const name of population.groups) {
    const created = await a.json<{ error?: string }>("POST", "groups", { name });
    if (created.status !== 201 && created.body.error !== "group_exists")
      throw new Error(`group ${name}: ${created.status} ${JSON.stringify(created.body)}`);
    log(`group ${name}: ${created.status === 201 ? "created" : "exists"}`);
  }
  const alias = values.alias as string;
  const upstream = await a.call("GET", `upstreams/${alias}`);
  if (upstream.status === 404) {
    const created = await a.json<{ error?: string; error_description?: string }>(
      "POST",
      "upstreams",
      {
        alias,
        issuer: need("fake-issuer"),
        display_name: "Fake upstream (staging)",
        client_id: need("fake-client-id"),
        token_endpoint_auth_method: "client_secret_basic",
        client_secret: need("fake-client-secret"),
      },
    );
    if (created.status !== 201)
      throw new Error(`upstream: ${created.status} ${JSON.stringify(created.body)}`);
    log(`upstream ${alias}: created`);
  } else if (upstream.status === 200) log(`upstream ${alias}: exists`);
  else throw new Error(`upstream: ${upstream.status} ${await upstream.text()}`);
  for (const rp of rpIds(int("rps"))) {
    const existing = await a.call("GET", `clients/${rp}`);
    if (existing.status === 200) {
      log(`client ${rp}: exists`);
      continue;
    }
    const created = await a.json<{ error?: string }>("POST", "clients", {
      client_id: rp,
      client_name: `Performance relying party ${rp}`,
      redirect_uris: [RP_REDIRECT],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      scopes_allowed: ["openid", "email", "profile", "offline_access"],
      skip_consent: true,
      offline_access: true,
    });
    if (created.status !== 201)
      throw new Error(`client ${rp}: ${created.status} ${JSON.stringify(created.body)}`);
    log(`client ${rp}: created`);
  }
}

// --- import -----------------------------------------------------------------------------

interface ImportLine {
  line: number;
  status: string;
  id?: string;
  error?: string;
}

async function importUsers(): Promise<void> {
  const a = admin();
  const users = int("users");
  const from = int("from");
  if (values["skip-if-seeded"]) {
    // The population's first and last users exist: this seed was imported already.
    const present = async (n: number) => {
      const found = await a.json<{ items: unknown[] }>(
        "GET",
        `users?email=${encodeURIComponent(emailOf(population, n))}`,
      );
      return (found.body.items?.length ?? 0) > 0;
    };
    if ((await present(from)) && (await present(from + users - 1))) {
      log(
        `import: population "${population.seed}" (${from}..${from + users - 1}) already there; skipped`,
      );
      return;
    }
  }
  const batches = chunks(from, users, int("batch"));
  const statuses: Record<string, number> = {};
  const errors: string[] = [];
  const durations: number[] = [];
  let done = 0;
  const startedAt = Date.now();
  log(
    `import: ${users} users from ${from} in ${batches.length} batches through ${int("clients")} clients`,
  );
  await pool(batches, int("clients"), async (batch) => {
    const t0 = Date.now();
    const res = await a.call(
      "POST",
      "import/users",
      seedBatch(population, batch.from, batch.count),
      "application/x-ndjson",
    );
    const text = await res.text();
    durations.push(Date.now() - t0);
    if (res.status !== 200) {
      errors.push(`batch ${batch.from}: ${res.status} ${text.slice(0, 200)}`);
      statuses["http_error"] = (statuses["http_error"] ?? 0) + batch.count;
    } else {
      for (const raw of text.trimEnd().split("\n")) {
        const line = JSON.parse(raw) as ImportLine;
        statuses[line.status] = (statuses[line.status] ?? 0) + 1;
        if (line.status === "error" && errors.length < 20)
          errors.push(`line ${batch.from + line.line - 1}: ${line.error}`);
      }
    }
    done += batch.count;
    if (done % 50_000 < batch.count || done === users) {
      const s = (Date.now() - startedAt) / 1000;
      log(`import: ${done}/${users} (${(done / s).toFixed(0)} users/s)`);
    }
  });
  const durationS = (Date.now() - startedAt) / 1000;
  // Verification (TIO-ADMIN-021): the count, then a sampled deep comparison.
  const stats = await a.json<{ users: Record<string, number> }>("GET", "stats");
  const sample = int("sample");
  const mismatches: string[] = [];
  const picked = Array.from(
    { length: Math.min(sample, users) },
    (_, i) => from + Math.floor(((i + 0.5) / sample) * users),
  );
  await pool(picked, 8, async (n) => {
    const email = emailOf(population, n);
    const listed = await a.json<{
      items: {
        id: string;
        email: string;
        email_verified: boolean;
        display_name: string;
        groups?: string[];
      }[];
    }>("GET", `users?email=${encodeURIComponent(email)}`);
    const user = listed.body.items?.[0];
    if (!user) {
      mismatches.push(`${n}: not found by email`);
      return;
    }
    const detail = await a.json<{
      display_name: string;
      email_verified: boolean;
      groups: string[];
    }>("GET", `users/${user.id}`);
    if (
      detail.body.display_name !== `User ${population.seed}-${n}` ||
      detail.body.email_verified !== true
    )
      mismatches.push(`${n}: profile differs (${JSON.stringify(detail.body)})`);
    if (
      JSON.stringify([...detail.body.groups].sort()) !==
      JSON.stringify([...population.groups].sort())
    )
      mismatches.push(`${n}: groups ${JSON.stringify(detail.body.groups)}`);
    const identities = await a.json<{ items: { issuer: string; subject: string }[] }>(
      "GET",
      `users/${user.id}/identities`,
    );
    const expected = Array.from(
      { length: population.identities },
      (_, i) =>
        `${i === 0 ? population.issuer : `${population.issuer}/${i}`}|${subjectOf(population, n)}`,
    ).sort();
    const got = identities.body.items.map((i) => `${i.issuer}|${i.subject}`).sort();
    if (JSON.stringify(got) !== JSON.stringify(expected))
      mismatches.push(`${n}: identities ${JSON.stringify(got)}`);
  });
  const report = {
    kind: "import_benchmark",
    issuer: a.issuer,
    users,
    from,
    batch: int("batch"),
    clients: int("clients"),
    started_at: new Date(startedAt).toISOString(),
    duration_s: Math.round(durationS * 10) / 10,
    users_per_s: Math.round(users / durationS),
    statuses,
    batch_ms: percentiles(durations),
    errors,
    verification: {
      active_users: stats.body.users?.["active"] ?? null,
      sampled: picked.length,
      mismatches,
    },
    within_target: durationS < 3_600 || users < 1_000_000,
  };
  const path =
    values.report ??
    `perf/data/import-${new Date(startedAt).toISOString().replaceAll(":", "-")}.json`;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
  log(
    `import: done in ${report.duration_s}s (${report.users_per_s} users/s), statuses ${JSON.stringify(statuses)}, ${mismatches.length} mismatches in ${picked.length} sampled; report ${path}`,
  );
  if (mismatches.length > 0 || (statuses["error"] ?? 0) > 0 || (statuses["http_error"] ?? 0) > 0)
    process.exitCode = 1;
}

// --- delete -----------------------------------------------------------------------------

async function deleteUsers(): Promise<void> {
  const a = admin();
  const users = int("users");
  const from = int("from");
  const counts = { deleted: 0, absent: 0, failed: 0 };
  const errors: string[] = [];
  const startedAt = Date.now();
  log(`delete: population "${population.seed}" (${from}..${from + users - 1})`);
  await pool(
    Array.from({ length: users }, (_, i) => from + i),
    int("concurrency"),
    async (n) => {
      const email = emailOf(population, n);
      let found: { body: { items?: { id: string }[] } };
      try {
        found = await a.json<{ items?: { id: string }[] }>(
          "GET",
          `users?email=${encodeURIComponent(email)}`,
        );
      } catch (error) {
        counts.failed += 1;
        if (errors.length < 20) errors.push(`${email}: ${String(error)}`);
        return;
      }
      const id = found.body.items?.[0]?.id;
      if (id === undefined) {
        counts.absent += 1;
        return;
      }
      // A 503 here is the user's object restarting (a deploy or a migration of the object):
      // retry a few times before counting a failure.
      let res = await a.call("DELETE", `users/${id}`);
      for (let attempt = 1; res.status === 503 && attempt <= DELETE_RETRIES; attempt++) {
        await res.text();
        await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
        res = await a.call("DELETE", `users/${id}`);
      }
      if (res.status === 204 || res.status === 404) counts.deleted += 1;
      else {
        counts.failed += 1;
        if (errors.length < 20)
          errors.push(`${email}: ${res.status} ${(await res.text()).slice(0, 120)}`);
      }
    },
  );
  const s = ((Date.now() - startedAt) / 1000).toFixed(1);
  log(
    `delete: ${counts.deleted} deleted, ${counts.absent} absent, ${counts.failed} failed in ${s}s`,
  );
  for (const e of errors) log(`delete: ${e}`);
  if (counts.failed > 0) process.exitCode = 1;
}

// --- harvest ----------------------------------------------------------------------------

interface Harvested {
  n: number;
  sub: string;
  client_id: string;
  session: string;
  refresh_token: string;
}

/** One federated login over HTTP: authorize, upstream leg, callback, complete, exchange. */
async function login(
  issuer: string,
  loginOrigin: string,
  alias: string,
  rp: string,
  n: number,
): Promise<Harvested> {
  const { verifier, challenge } = pkce();
  const authorize = new URL(`${issuer}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: rp,
    redirect_uri: RP_REDIRECT,
    scope: "openid email offline_access",
    state: `s${n}`,
    nonce: `n${n}`,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  const started = await fetch(authorize, { redirect: "manual" });
  const id = interactionOf(started.headers.get("location"));
  const binding = cookieNamed(started.headers.getSetCookie(), "__Host-tio_ix_");
  if (started.status !== 303 || id === null || binding === null)
    throw new Error(`authorize: ${started.status} ${started.headers.get("location") ?? ""}`);
  const leg = await fetch(`${issuer}/api/v1/interactions/${id}/upstream/${alias}`, {
    method: "POST",
    headers: { origin: loginOrigin, cookie: binding, "content-type": "application/json" },
    body: "{}",
  });
  if (leg.status !== 200) throw new Error(`upstream leg: ${leg.status} ${await leg.text()}`);
  const toUpstream = new URL(((await leg.json()) as { redirect_to: string }).redirect_to);
  toUpstream.searchParams.set("x_sub", subjectOf(population, n));
  const atUpstream = await fetch(toUpstream, { redirect: "manual" });
  const back = atUpstream.headers.get("location");
  if (atUpstream.status !== 302 || back === null)
    throw new Error(`fake upstream: ${atUpstream.status}`);
  const callback = await fetch(back, { redirect: "manual", headers: { cookie: binding } });
  const complete = callback.headers.get("location") ?? "";
  if (callback.status !== 303 || !complete.endsWith(`/interactions/${id}/complete`))
    throw new Error(`callback: ${callback.status} ${complete}`);
  const finished = await fetch(complete, { redirect: "manual", headers: { cookie: binding } });
  const outcome = codeOf(finished.headers.get("location"));
  const session = cookieNamed(finished.headers.getSetCookie(), "__Host-tio_session=");
  if (finished.status !== 303 || outcome === null || !("code" in outcome) || session === null)
    throw new Error(`complete: ${finished.status} ${JSON.stringify(outcome)}`);
  const exchanged = await fetch(`${issuer}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: rp,
      code: outcome.code,
      redirect_uri: RP_REDIRECT,
      code_verifier: verifier,
    }),
  });
  if (exchanged.status !== 200)
    throw new Error(`token: ${exchanged.status} ${await exchanged.text()}`);
  const tokens = (await exchanged.json()) as { refresh_token?: string };
  if (!tokens.refresh_token) throw new Error("token: no refresh_token");
  return {
    n,
    sub: subjectOf(population, n),
    client_id: rp,
    session,
    refresh_token: tokens.refresh_token,
  };
}

async function harvest(): Promise<void> {
  const issuer = need("issuer");
  const loginOrigin = new URL(need("login-url")).origin;
  const alias = values.alias as string;
  const rps = rpIds(int("rps"));
  const from = int("from");
  const count = int("count");
  const out = values.out as string;
  mkdirSync(dirname(out), { recursive: true });
  const limiter = new RateLimiter(int("rate"));
  const durations: number[] = [];
  const failures: string[] = [];
  const failFast = new FailFast(HARVEST_FAIL_FAST);
  let ok = 0;
  let failed = 0;
  const startedAt = Date.now();
  log(
    `harvest: ${count} logins from ${from} at ${int("rate")}/s through ${rps.length} relying parties into ${out}`,
  );
  await pool(
    Array.from({ length: count }, (_, i) => from + i),
    int("concurrency"),
    async (n) => {
      if (failFast.tripped) return;
      await limiter.acquire();
      const t0 = Date.now();
      try {
        const line = await login(issuer, loginOrigin, alias, rps[n % rps.length] as string, n);
        appendFileSync(out, `${JSON.stringify(line)}\n`);
        ok++;
        failFast.record(true);
      } catch (error) {
        failed++;
        failFast.record(false);
        if (failures.length < 50) failures.push(`${n}: ${String(error)}`);
      }
      durations.push(Date.now() - t0);
      if ((ok + failed) % 5_000 === 0)
        log(
          `harvest: ${ok} ok, ${failed} failed, ${((Date.now() - startedAt) / 1000).toFixed(0)}s`,
        );
    },
  );
  const total = durations.length;
  if (failFast.tripped)
    log(`harvest: the first ${HARVEST_FAIL_FAST} logins all failed; stopping (${failures[0]})`);
  const report = {
    kind: "seed_harvest",
    issuer,
    count,
    from,
    rate: int("rate"),
    duration_s: Math.round((Date.now() - startedAt) / 100) / 10,
    aborted: failFast.tripped,
    ok,
    failed,
    login_ms: percentiles(durations),
    failures,
  };
  const path =
    values.report ??
    `perf/data/harvest-${new Date(startedAt).toISOString().replaceAll(":", "-")}.json`;
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
  log(
    `harvest: ${ok} ok, ${failed} failed in ${report.duration_s}s (p99 ${report.login_ms.p99} ms); report ${path}`,
  );
  if (failFast.tripped || failed > total * 0.01) process.exitCode = 1;
}

// --- entry ------------------------------------------------------------------------------

const commands: Record<string, () => Promise<void> | void> = {
  generate,
  prepare,
  import: importUsers,
  harvest,
  delete: deleteUsers,
};
const run = commands[command];
if (run === undefined) {
  console.error(
    `seed: unknown command "${command}" (generate | prepare | import | harvest | delete)`,
  );
  process.exit(2);
}
await run();
