// token_code_exchange (spec §2.7 "POST /token code exchange", TIO-PERF-001):
// 200 exchanges per second. Each one needs a fresh code, which a session hit
// at /authorize provides (that request is tagged as a step, not budgeted here).
import { check } from "k6";
import {
  arrival,
  codeOf,
  exchange,
  maxVusOf,
  ownedByThisVu,
  pkce,
  record,
  sessionHit,
  summary,
  thresholds,, SUMMARY_TREND_STATS } from "./lib.js";

const RATE = Number(__ENV.TIO_PERF_RATE || 200);

export const options = {
  summaryTrendStats: SUMMARY_TREND_STATS,
  scenarios: { token_code_exchange: arrival("tokenCodeExchange", RATE) },
  thresholds: thresholds("token_code_exchange"),
};

const STRIDE = maxVusOf(options);
let mine = null;

export function tokenCodeExchange() {
  if (mine === null) mine = ownedByThisVu(STRIDE);
  const entry = mine[__ITER % mine.length];
  const { verifier, challenge } = pkce();
  const hit = sessionHit(entry, { challenge }, { scenario: "token_code_exchange_steps" });
  const code = codeOf(hit.headers.Location);
  if (!check(hit, { "a code to exchange": () => hit.status === 303 && code !== null })) return;
  const res = exchange(entry, code, verifier, { scenario: "token_code_exchange" });
  check(res, {
    "exchange 200 with tokens": (r) =>
      r.status === 200 && !!r.json("access_token") && !!r.json("refresh_token"),
  });
  const timing = record(res);
  check(timing, { "exchange is one hop, no D1 write": (t) => t.do <= 1 && t.d1w === 0 });
}

export function handleSummary(data) {
  return summary(data);
}
