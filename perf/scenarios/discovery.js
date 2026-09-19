// discovery (spec §2.7 row 1, TIO-TEST-051): the metadata and JWKS documents,
// served from cache, at 100 requests per second.
import { check } from "k6";
import http from "k6/http";
import { arrival, ISSUER, record, summary, thresholds } from "./lib.js";

const RATE = Number(__ENV.TIO_PERF_RATE || 100);

export const options = {
  scenarios: { discovery: arrival("discovery", RATE) },
  thresholds: thresholds("discovery"),
};

export function discovery() {
  const path = __ITER % 2 === 0 ? "/.well-known/openid-configuration" : "/.well-known/jwks.json";
  const res = http.get(`${ISSUER}${path}`);
  check(res, { "discovery 200": (r) => r.status === 200 });
  const timing = record(res);
  check(timing, { "discovery touches no store": (t) => t.do === 0 && t.d1w === 0 });
}

export function handleSummary(data) {
  return summary(data);
}
