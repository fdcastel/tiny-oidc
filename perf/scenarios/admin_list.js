// admin_list (spec §2.7 "Admin list endpoints", TIO-TEST-051): keyset pages of
// the user directory and the smaller listings at 20 requests per second, with
// the automation client's token (renewed by setup once; the run is shorter
// than the token's life).
import { check } from "k6";
import http from "k6/http";
import { adminToken, arrival, ISSUER, record, summary, thresholds } from "./lib.js";

const RATE = Number(__ENV.TIO_PERF_RATE || 20);

export const options = {
  scenarios: { admin_list: arrival("adminList", RATE) },
  thresholds: thresholds("admin_list"),
};

const PATHS = [
  "users?limit=100",
  "users?status=active&limit=100",
  "clients",
  "groups",
  "invitations?limit=100",
  "keys",
];

export function setup() {
  return { token: adminToken() };
}

export function adminList(data) {
  const path = PATHS[__ITER % PATHS.length];
  const res = http.get(`${ISSUER}/api/v1/admin/${path}`, {
    headers: { Authorization: `Bearer ${data.token}` },
  });
  check(res, { "admin list 200": (r) => r.status === 200 });
  const timing = record(res);
  check(timing, {
    "admin list touches no object, writes nothing": (t) => t.do === 0 && t.d1w === 0,
  });
}

export function handleSummary(data) {
  return summary(data);
}
