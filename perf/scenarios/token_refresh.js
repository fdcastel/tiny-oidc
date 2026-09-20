// token_refresh (spec §2.7 "POST /token refresh", §13.10): 150 refreshes per
// second sustained, then a 500 per second burst for 60 s. Every VU owns a
// slice of the harvested tokens and keeps the rotated token of each family, so
// no refresh token is ever presented twice (that would revoke the family).
// The burst is spread over the relying parties the harvest used, which keeps
// each client under its own limit of §6.7.
import { check } from "k6";
import {
  arrival,
  maxVusOf,
  ownedByThisVu,
  record,
  refresh,
  SUMMARY_TREND_STATS,
  summary,
  thresholds,
} from "./lib.js";

const SUSTAINED = Number(__ENV.TIO_PERF_RATE || 150);
const BURST = Number(__ENV.TIO_PERF_BURST_RATE || 500);
const SUSTAIN_FOR = __ENV.TIO_PERF_DURATION || "4m";

export const options = {
  summaryTrendStats: SUMMARY_TREND_STATS,
  scenarios: {
    token_refresh: arrival("tokenRefresh", SUSTAINED, SUSTAIN_FOR),
    token_refresh_burst: arrival("tokenRefresh", BURST, "60s", { startTime: SUSTAIN_FOR }),
  },
  thresholds: {
    ...thresholds("token_refresh"),
    "server_ms{scenario:token_refresh_burst}": ["p(99)<=150"],
    "http_req_failed{scenario:token_refresh_burst}": ["rate<0.001"],
    "d1_writes{scenario:token_refresh_burst}": ["rate<5"],
    "checks{scenario:token_refresh_burst}": ["rate>0.999"],
  },
};

const STRIDE = maxVusOf(options);
let mine = null;
let cursor = 0;

export function tokenRefresh() {
  if (mine === null) mine = ownedByThisVu(STRIDE);
  const entry = mine[cursor % mine.length];
  cursor++;
  const res = refresh(entry);
  const ok = check(res, {
    "refresh 200 with a rotated token": (r) => r.status === 200 && !!r.json("refresh_token"),
  });
  if (ok) entry.refresh_token = res.json("refresh_token");
  const timing = record(res);
  check(timing, { "refresh is one hop, no D1 write": (t) => t.do <= 1 && t.d1w === 0 });
}

export function handleSummary(data) {
  return summary(data);
}
