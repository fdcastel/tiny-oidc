// Shared pieces of the k6 scenarios (spec §13.10): the environment, the
// harvested population, the Server-Timing measurements every scenario records
// and the thresholds built from perf/scenarios/budgets.js. k6 runs this file;
// nothing here is Node.

import { check } from "k6";
import crypto from "k6/crypto";
import { SharedArray } from "k6/data";
import encoding from "k6/encoding";
import exec from "k6/execution";
import http from "k6/http";
import { Counter, Rate, Trend } from "k6/metrics";
import { BUDGETS, MAX_D1_WRITE_RATE, MAX_FAILED_RATE, TAIL_FACTOR } from "./budgets.js";

export const ISSUER = __ENV.TIO_PERF_ISSUER;
/** The origin of a URL without the URL class (k6 has none): scheme, host and port. */
export function originOf(url) {
  const m = /^(https?:\/\/[^/?#]+)/.exec(url || "");
  return m ? m[1] : "";
}
export const LOGIN_ORIGIN = originOf(__ENV.TIO_PERF_LOGIN_URL);
export const DURATION = __ENV.TIO_PERF_DURATION || "5m";
export const TOKENS_FILE = __ENV.TIO_PERF_TOKENS || "../data/tokens.ndjson";
export const RP_REDIRECT = "https://perf-rp.invalid/callback";

/** The measurements of TIO-OBS-004, one custom metric each, tagged by scenario. */
export const serverMs = new Trend("server_ms", true);
/** The same duration split by whether the request read D1 (§2.7: the budget is on the warm ones). */
export const serverMsWarm = new Trend("server_ms_warm", true);
export const serverMsD1 = new Trend("server_ms_d1", true);
export const doCalls = new Counter("do_calls");
export const d1Reads = new Counter("d1_reads");
export const d1Writes = new Counter("d1_writes");
export const withinBudget = new Rate("within_budget");

/** Parses `app;dur=12, do;desc="1", d1r;desc="0", d1w;desc="0"`. */
export function serverTiming(header) {
  const out = { app: null, do: 0, d1r: 0, d1w: 0 };
  if (!header) return out;
  const dur = /app;dur=([0-9.]+)/.exec(header);
  if (dur) out.app = Number(dur[1]);
  const counts = /(do|d1r|d1w);desc="(\d+)"/g;
  let m = counts.exec(header);
  while (m !== null) {
    out[m[1]] = Number(m[2]);
    m = counts.exec(header);
  }
  return out;
}

/** Records the response's server-side measurements under the current scenario. */
export function record(res, scenario = exec.scenario.name) {
  const timing = serverTiming(res.headers["Server-Timing"]);
  const tags = { scenario };
  // A burst or a step shares the budget of the scenario it belongs to.
  const budget = BUDGETS[scenario] || BUDGETS[scenario.replace(/_(burst|steps)$/, "")];
  if (timing.app !== null) {
    serverMs.add(timing.app, tags);
    (timing.d1r > 0 ? serverMsD1 : serverMsWarm).add(timing.app, tags);
    if (budget) withinBudget.add(timing.app <= budget.p99, tags);
  }
  doCalls.add(timing.do, tags);
  d1Reads.add(timing.d1r, tags);
  d1Writes.add(timing.d1w, tags);
  return timing;
}

/**
 * The thresholds of one scenario (`tagged` when a burst or a step of it carries
 * its own tag): the §2.7 p99 on the requests that read no D1, and TAIL_FACTOR
 * times it on the p99 over every request, the D1-touching ones included — or
 * the budget itself over every request for a row that reads D1 by design —,
 * the failure rate, the D1 write rate. (The D1-touching requests alone are a
 * few per cent of a run; their own p99 is a handful of samples that swings
 * twofold between identical runs, so the tail is bounded over everything.)
 */
export function thresholds(scenario, tagged = scenario) {
  const budget = BUDGETS[scenario];
  const timing = budget.d1
    ? { [`server_ms{scenario:${tagged}}`]: [`p(99)<=${budget.p99}`] }
    : {
        [`server_ms_warm{scenario:${tagged}}`]: [`p(99)<=${budget.p99}`],
        [`server_ms{scenario:${tagged}}`]: [`p(99)<=${budget.p99 * TAIL_FACTOR}`],
      };
  return {
    ...timing,
    [`http_req_failed{scenario:${tagged}}`]: [`rate<${MAX_FAILED_RATE}`],
    [`d1_writes{scenario:${tagged}}`]: [`rate<${MAX_D1_WRITE_RATE}`],
    [`checks{scenario:${tagged}}`]: ["rate>0.999"],
  };
}

/** The trend statistics every summary carries: the thresholds are on p(99), which k6 omits by default. */
export const SUMMARY_TREND_STATS = ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"];

/** A constant-arrival-rate scenario with enough VUs for the rate at the p99 budget's latency. */
export function arrival(exec_, rate, duration = DURATION, extra = {}) {
  return {
    executor: "constant-arrival-rate",
    exec: exec_,
    rate,
    timeUnit: "1s",
    duration,
    preAllocatedVUs: Math.max(10, Math.ceil(rate / 4)),
    maxVUs: Math.max(50, rate * 3),
    ...extra,
  };
}

/**
 * The harvested population: `{ n, sub, client_id, session, refresh_token }`
 * per line, restricted to the users `TIO_PERF_SLICE=from:to` names when set.
 * Scenarios that rotate refresh tokens (token_refresh, soak_refresh, the
 * userinfo setup) get disjoint slices from the nightly job, because a rotated
 * token is gone from the file and presenting the old one again would revoke
 * the family (TIO-RT-003).
 */
export const tokens = new SharedArray("tokens", () => {
  const [from, to] = (__ENV.TIO_PERF_SLICE || "0:0").split(":").map(Number);
  return open(TOKENS_FILE)
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line))
    .filter((entry) => to <= from || (entry.n >= from && entry.n < to));
});

/** The VUs a run can have at most: the stride that partitions the population between them. */
export function maxVusOf(options) {
  return Object.values(options.scenarios).reduce((sum, s) => sum + (s.maxVUs || s.vus || 1), 0);
}

/**
 * A slice of the population owned by this VU alone, so single-use tokens are
 * never shared. `stride` is the run's maximum VU count (maxVusOf): VU ids
 * are unique across scenarios, and a fixed stride keeps slices disjoint even
 * when VUs are initialized late.
 */
export function ownedByThisVu(stride) {
  const mine = [];
  for (let i = exec.vu.idInInstance - 1; i < tokens.length; i += stride)
    mine.push({ ...tokens[i] });
  if (mine.length === 0) mine.push({ ...tokens[exec.vu.idInInstance % tokens.length] });
  return mine;
}

/** An access token with the `admin` scope for the automation client of the run. */
export function adminToken() {
  const res = http.post(
    `${ISSUER}/token`,
    { grant_type: "client_credentials", scope: "admin" },
    {
      headers: {
        Authorization: `Basic ${encoding.b64encode(`${__ENV.TIO_PERF_CLIENT_ID}:${__ENV.TIO_PERF_CLIENT_SECRET}`)}`,
      },
      tags: { scenario: "setup" },
    },
  );
  check(res, { "admin token issued": (r) => r.status === 200 });
  return res.json("access_token");
}

/** `GET /authorize` for a session holder: a code straight back to the relying party (§2.5). */
export function sessionHit(entry, pkce, tags) {
  const params = {
    response_type: "code",
    client_id: entry.client_id,
    redirect_uri: RP_REDIRECT,
    scope: "openid email offline_access",
    state: "s",
    nonce: "n",
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
  };
  const query = Object.entries(params)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("&");
  return http.get(`${ISSUER}/authorize?${query}`, {
    redirects: 0,
    headers: { Cookie: entry.session },
    tags,
  });
}

/** The code of a redirect to the relying party, or null. */
export function codeOf(location) {
  const m = /[?&]code=([^&]+)/.exec(location || "");
  return m ? decodeURIComponent(m[1]) : null;
}

/** A PKCE pair; k6 has crypto.sha256 and base64url via encoding. */
export function pkce() {
  const verifier = encoding.b64encode(crypto.randomBytes(32), "rawurl");
  const challenge = encoding.b64encode(crypto.sha256(verifier, "binary"), "rawurl");
  return { verifier, challenge };
}

export function exchange(entry, code, verifier, tags) {
  return http.post(
    `${ISSUER}/token`,
    {
      grant_type: "authorization_code",
      client_id: entry.client_id,
      code,
      redirect_uri: RP_REDIRECT,
      code_verifier: verifier,
    },
    { tags },
  );
}

export function refresh(entry, tags) {
  return http.post(
    `${ISSUER}/token`,
    { grant_type: "refresh_token", client_id: entry.client_id, refresh_token: entry.refresh_token },
    { tags },
  );
}

/**
 * The end-of-test summary: the full k6 data as JSON at `TIO_PERF_SUMMARY`
 * (scripts/load-summary.ts turns the files into the job summary), and one
 * line per threshold on stdout. Every scenario exports `handleSummary` through
 * this function.
 */
export function summary(data) {
  const lines = [];
  for (const [name, metric] of Object.entries(data.metrics)) {
    for (const [expr, result] of Object.entries(metric.thresholds || {})) {
      lines.push(`${result.ok ? "ok  " : "FAIL"} ${name} ${expr}`);
    }
  }
  const out = { stdout: `${lines.sort().join("\n")}\n` };
  if (__ENV.TIO_PERF_SUMMARY) out[__ENV.TIO_PERF_SUMMARY] = JSON.stringify(data, null, 2);
  return out;
}
