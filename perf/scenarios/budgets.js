// The §2.7 budgets each k6 scenario enforces (spec §13.10, TIO-PERF-001,
// TIO-TEST-051). Plain data, imported by the scenarios (k6) and by the test
// that checks these numbers against the specification's table (Node).
//
// `endpoint` is the row of the §2.7 table; `p99` its server-side budget in
// milliseconds, read from the `Server-Timing` header (TIO-OBS-004); `d1w` the
// D1 writes the row allows on the request path (the §13.10 write-rate
// assertion is on the same counter).

export const BUDGETS = {
  discovery: { endpoint: "GET /.well-known/*", p50: 5, p99: 20, d1w: 0 },
  sso_authorize: { endpoint: "GET /authorize (session hit)", p50: 30, p99: 150, d1w: 0 },
  login_federated: { endpoint: "GET /federation/callback", p50: 200, p99: 800, d1w: 0 },
  token_code_exchange: { endpoint: "POST /token code exchange", p50: 40, p99: 200, d1w: 0 },
  token_refresh: { endpoint: "POST /token refresh", p50: 30, p99: 150, d1w: 0 },
  userinfo: { endpoint: "GET /userinfo", p50: 20, p99: 100, d1w: 0 },
  admin_list: { endpoint: "Admin list endpoints", p50: 50, p99: 300, d1w: 0 },
  soak_refresh: { endpoint: "POST /token refresh", p50: 30, p99: 150, d1w: 0 },
};

/** `http_req_failed` for every scenario (§13.10: below 0.1%). */
export const MAX_FAILED_RATE = 0.001;

/** D1 writes per second on the request path during token scenarios (§13.10). */
export const MAX_D1_WRITE_RATE = 5;
