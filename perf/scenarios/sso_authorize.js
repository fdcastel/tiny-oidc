// sso_authorize (spec §2.7 "GET /authorize (session hit)", TIO-TEST-051): a
// browser that already holds a session asks for a code and gets one straight
// back, at 50 per second, using the session cookies the harvest left behind.
import { check } from "k6";
import {
  arrival,
  codeOf,
  maxVusOf,
  ownedByThisVu,
  pkce,
  record,
  sessionHit,
  summary,
  thresholds,, SUMMARY_TREND_STATS } from "./lib.js";

const RATE = Number(__ENV.TIO_PERF_RATE || 50);

export const options = {
  summaryTrendStats: SUMMARY_TREND_STATS,
  scenarios: { sso_authorize: arrival("ssoAuthorize", RATE) },
  thresholds: thresholds("sso_authorize"),
};

const STRIDE = maxVusOf(options);
let mine = null;

export function ssoAuthorize() {
  if (mine === null) mine = ownedByThisVu(STRIDE);
  const entry = mine[__ITER % mine.length];
  const res = sessionHit(entry, pkce(), { scenario: "sso_authorize" });
  check(res, {
    "session hit answers 303 with a code": (r) =>
      r.status === 303 && codeOf(r.headers.Location) !== null,
  });
  const timing = record(res);
  check(timing, { "session hit is one hop, no D1": (t) => t.do <= 1 && t.d1w === 0 });
}

export function handleSummary(data) {
  return summary(data);
}
