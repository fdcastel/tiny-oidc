// soak_refresh (spec §13.10, TIO-TEST-052): the refresh scenario for two hours
// at 100 per second. Two things must not grow: the p99 (the last ten minutes
// against the first ten, both under the §2.7 budget) and the per-user object
// storage beyond its retention bounds (sampled through GET /admin/users/{id}/export
// before and after; refresh rows are kept for the reuse window, so a user
// refreshed every ~n seconds gains a bounded number of rows).
import { check } from "k6";
import http from "k6/http";
import { Trend } from "k6/metrics";
import { BUDGETS } from "./budgets.js";
import {
  adminToken,
  arrival,
  ISSUER,
  maxVusOf,
  ownedByThisVu,
  record,
  refresh,
  SUMMARY_TREND_STATS,
  summary,
  thresholds,
  tokens,
} from "./lib.js";

const RATE = Number(__ENV.TIO_PERF_RATE || 100);
const DURATION = __ENV.TIO_PERF_SOAK_DURATION || "2h";
const WINDOW = __ENV.TIO_PERF_SOAK_WINDOW || "10m";
const SAMPLE = Number(__ENV.TIO_PERF_SOAK_SAMPLE || 20);
/** How much a sampled export may grow over the run (bytes after / bytes before). */
const MAX_GROWTH = Number(__ENV.TIO_PERF_SOAK_MAX_GROWTH || 3);

const durationMs = (text) => {
  const m = /^(\d+)(s|m|h)$/.exec(text);
  return Number(m[1]) * { s: 1000, m: 60_000, h: 3_600_000 }[m[2]];
};
const total = durationMs(DURATION);
const window = durationMs(WINDOW);

export const options = {
  summaryTrendStats: SUMMARY_TREND_STATS,
  scenarios: { soak_refresh: arrival("soakRefresh", RATE, DURATION) },
  thresholds: {
    ...thresholds("soak_refresh"),
    // No growth in p99 (TIO-TEST-052): the first and the last ten minutes each meet the row's
    // warm budget, measured as the gate measures it (requests that read no D1, ADR 0016).
    "server_ms_windowed{window:first}": [`p(99)<=${BUDGETS.soak_refresh.p99}`],
    "server_ms_windowed{window:last}": [`p(99)<=${BUDGETS.soak_refresh.p99}`],
    "checks{phase:teardown}": ["rate==1"],
  },
};

const STRIDE = maxVusOf(options);
const windowed = new Trend("server_ms_windowed", true);
let mine = null;
let cursor = 0;
let startedAt = null;

function sampledIds() {
  const ids = [];
  const step = Math.max(1, Math.floor(tokens.length / SAMPLE));
  for (let i = 0; i < tokens.length && ids.length < SAMPLE; i += step) ids.push(tokens[i].sub);
  return ids;
}

/** Bytes of each sampled user's export, by upstream subject (the seed's email is derived from it). */
function exportSizes(token, subs) {
  const sizes = {};
  for (const sub of subs) {
    const email = `${sub.replace(/^sub-/, "user-")}@example.com`;
    const found = http.get(
      `${ISSUER}/api/v1/admin/users?limit=1&email=${encodeURIComponent(email)}`,
      {
        headers: { Authorization: `Bearer ${token}` },
        tags: { phase: "sample" },
      },
    );
    const id = found.status === 200 && found.json("items.0.id");
    if (!id) continue;
    const exported = http.get(`${ISSUER}/api/v1/admin/users/${id}/export`, {
      headers: { Authorization: `Bearer ${token}` },
      tags: { phase: "sample" },
    });
    if (exported.status === 200) sizes[sub] = exported.body.length;
  }
  return sizes;
}

export function setup() {
  const token = adminToken();
  return { token, before: exportSizes(token, sampledIds()), startedAt: Date.now() };
}

export function soakRefresh(data) {
  if (mine === null) {
    mine = ownedByThisVu(STRIDE);
    startedAt = data.startedAt;
  }
  const entry = mine[cursor % mine.length];
  cursor++;
  const res = refresh(entry);
  const ok = check(res, {
    "refresh 200 with a rotated token": (r) => r.status === 200 && !!r.json("refresh_token"),
  });
  if (ok) entry.refresh_token = res.json("refresh_token");
  const timing = record(res);
  const elapsed = Date.now() - startedAt;
  if (timing.app !== null && timing.d1r === 0) {
    if (elapsed < window) windowed.add(timing.app, { scenario: "soak_refresh", window: "first" });
    else if (elapsed > total - window)
      windowed.add(timing.app, { scenario: "soak_refresh", window: "last" });
  }
}

export function teardown(data) {
  const token = adminToken();
  const after = exportSizes(token, Object.keys(data.before));
  for (const [sub, before] of Object.entries(data.before)) {
    const now = after[sub];
    check(
      now,
      {
        [`export of ${sub} within retention bounds`]: (bytes) =>
          bytes !== undefined && bytes <= before * MAX_GROWTH,
      },
      { phase: "teardown" },
    );
  }
}

export function handleSummary(data) {
  return summary(data);
}
