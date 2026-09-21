// The §2.7 budgets each k6 scenario enforces (spec §13.10, TIO-PERF-001,
// TIO-TEST-051). Plain data, imported by the scenarios (k6) and by the test
// that checks these numbers against the specification's table (Node).
//
// `endpoint` is the row of the §2.7 table; `p99` its server-side budget in
// milliseconds, read from the `Server-Timing` header (TIO-OBS-004); `d1w` the
// D1 writes the row allows on the request path (the §13.10 write-rate
// assertion is on the same counter); `d1` marks the rows whose path reads
// D1 by design — their budget covers every request, the others' the requests
// that read no D1, with the p99 over every request bounded at TAIL_FACTOR
// times the budget (§2.7, ADR 0016).

export const BUDGETS = {
  discovery: { endpoint: "GET /.well-known/*", p50: 5, p99: 20, d1w: 0, d1: false },
  sso_authorize: { endpoint: "GET /authorize (session hit)", p50: 30, p99: 200, d1w: 0, d1: false },
  login_federated: { endpoint: "GET /federation/callback", p50: 600, p99: 1200, d1w: 0, d1: true },
  token_code_exchange: {
    endpoint: "POST /token code exchange",
    p50: 40,
    p99: 200,
    d1w: 0,
    d1: false,
  },
  token_refresh: { endpoint: "POST /token refresh", p50: 30, p99: 200, d1w: 0, d1: false },
  userinfo: { endpoint: "GET /userinfo", p50: 20, p99: 100, d1w: 0, d1: false },
  admin_list: { endpoint: "Admin list endpoints", p50: 300, p99: 1000, d1w: 0, d1: true },
  soak_refresh: { endpoint: "POST /token refresh", p50: 30, p99: 200, d1w: 0, d1: false },
};

/** The bound on the p99 over every request, the D1-touching ones included, as a multiple of the row's p99 (§2.7). */
export const TAIL_FACTOR = 4;

/** The refresh burst's allowance (TIO-TEST-051): a spike of over three times the steady rate onto the same objects. */
export const BURST_FACTOR = 1.5;

/** `http_req_failed` for every scenario (§13.10: below 0.1%). */
export const MAX_FAILED_RATE = 0.001;

/** D1 writes per second on the request path during token scenarios (§13.10). */
export const MAX_D1_WRITE_RATE = 5;
