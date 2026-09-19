// userinfo (spec §2.7 "GET /userinfo", TIO-TEST-051): 200 requests per second
// with access tokens minted in setup by refreshing a slice of the population
// (access tokens live 600 s; the run is shorter). The refresh tokens rotated
// in setup are not written back: the sustained scenarios own the families.
import { check } from "k6";
import http from "k6/http";
import { arrival, ISSUER, record, refresh, summary, thresholds, tokens } from "./lib.js";

const RATE = Number(__ENV.TIO_PERF_RATE || 200);
const HOLDERS = Number(__ENV.TIO_PERF_USERINFO_HOLDERS || 500);

export const options = {
  scenarios: { userinfo: arrival("userinfo", RATE) },
  thresholds: thresholds("userinfo"),
};

export function setup() {
  const access = [];
  const step = Math.max(1, Math.floor(tokens.length / HOLDERS));
  for (let i = tokens.length - 1; i >= 0 && access.length < HOLDERS; i -= step) {
    const res = refresh(tokens[i], { scenario: "setup" });
    if (res.status === 200) access.push(res.json("access_token"));
  }
  check(access, {
    "setup minted access tokens": (a) => a.length >= Math.min(HOLDERS, tokens.length) * 0.9,
  });
  return { access };
}

export function userinfo(data) {
  const token = data.access[(__VU * 31 + __ITER) % data.access.length];
  const res = http.get(`${ISSUER}/userinfo`, { headers: { Authorization: `Bearer ${token}` } });
  check(res, { "userinfo 200 with sub": (r) => r.status === 200 && !!r.json("sub") });
  const timing = record(res);
  check(timing, { "userinfo is one hop, no D1 write": (t) => t.do <= 1 && t.d1w === 0 });
}

export function handleSummary(data) {
  return summary(data);
}
