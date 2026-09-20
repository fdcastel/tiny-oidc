// login_federated (spec §2.7 "GET /federation/callback", TIO-TEST-051): the
// whole federated login over HTTP at 50 per second, no browser: authorize,
// the upstream leg, the fake upstream's redirect, the callback (the budgeted
// request), complete, and the code exchange. Every seeded user already holds
// the (issuer, subject) pair, so the callback signs in rather than creates.
import { check } from "k6";
import http from "k6/http";
import {
  arrival,
  codeOf,
  exchange,
  ISSUER,
  LOGIN_ORIGIN,
  pkce,
  RP_REDIRECT,
  record,
  summary,
  thresholds,
  tokens,, SUMMARY_TREND_STATS } from "./lib.js";

const RATE = Number(__ENV.TIO_PERF_RATE || 50);
const ALIAS = __ENV.TIO_PERF_UPSTREAM_ALIAS || "fake";

export const options = {
  summaryTrendStats: SUMMARY_TREND_STATS,
  scenarios: { login_federated: arrival("loginFederated", RATE) },
  thresholds: thresholds("login_federated"),
};

const tags = { scenario: "login_federated" };
const other = { scenario: "login_federated_steps" };

function cookieNamed(res, prefix) {
  for (const [name, values] of Object.entries(res.cookies || {})) {
    if (name.startsWith(prefix) && values.length > 0) return `${name}=${values[0].value}`;
  }
  return null;
}

export function loginFederated() {
  const entry = tokens[(__VU * 7919 + __ITER) % tokens.length];
  const { verifier, challenge } = pkce();
  const params = {
    response_type: "code",
    client_id: entry.client_id,
    redirect_uri: RP_REDIRECT,
    scope: "openid email offline_access",
    state: "s",
    nonce: "n",
    code_challenge: challenge,
    code_challenge_method: "S256",
  };
  const query = Object.entries(params)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("&");
  // Every step runs with its own cookie jar: k6's per-VU jar would carry sessions across users.
  const jar = http.cookieJar();
  jar.clear(ISSUER);
  const started = http.get(`${ISSUER}/authorize?${query}`, { redirects: 0, tags: other });
  const location = started.headers.Location || "";
  const id = (/[?&]interaction=([^&]+)/.exec(location) || [])[1];
  const binding = cookieNamed(started, "__Host-tio_ix_");
  if (
    !check(started, {
      "authorize starts an interaction": () => started.status === 303 && !!id && !!binding,
    })
  )
    return;
  const leg = http.post(`${ISSUER}/api/v1/interactions/${id}/upstream/${ALIAS}`, "{}", {
    headers: { Origin: LOGIN_ORIGIN, Cookie: binding, "Content-Type": "application/json" },
    tags: other,
  });
  if (!check(leg, { "upstream leg answers": (r) => r.status === 200 })) return;
  const toUpstream = `${leg.json("redirect_to")}&x_sub=${encodeURIComponent(entry.sub)}`;
  const atUpstream = http.get(toUpstream, { redirects: 0, tags: other });
  const back = atUpstream.headers.Location;
  if (!check(atUpstream, { "fake upstream redirects back": (r) => r.status === 302 && !!back }))
    return;
  const callback = http.get(back, { redirects: 0, headers: { Cookie: binding }, tags });
  const complete = callback.headers.Location || "";
  check(callback, {
    "callback signs in": (r) =>
      r.status === 303 && complete.endsWith(`/interactions/${id}/complete`),
  });
  const timing = record(callback);
  check(timing, {
    "callback reads the index once, writes nothing": (t) => t.d1r <= 1 && t.d1w === 0,
  });
  const finished = http.get(complete, { redirects: 0, headers: { Cookie: binding }, tags: other });
  const code = codeOf(finished.headers.Location);
  if (
    !check(finished, { "complete issues a code": () => finished.status === 303 && code !== null })
  )
    return;
  const exchanged = exchange(entry, code, verifier, other);
  check(exchanged, { "exchange succeeds": (r) => r.status === 200 });
}

export function handleSummary(data) {
  return summary(data);
}
