# Load and capacity (spec §13.10)

Everything here runs against **staging** over HTTPS with no browser and no
Cloudflare credential. The nightly job (`.github/workflows/nightly.yml`, job
`load`) runs it end to end; the weekly `soak` job runs the two-hour scenario.

| Piece | What it does | Requirement |
|---|---|---|
| `seed.ts generate` | The synthetic population as NDJSON for `POST /api/v1/admin/import/users`: deterministic emails, subjects and identities for a seed | TIO-TEST-050 |
| `seed.ts prepare` | Settings (`login_url`, `login_origins`), the `staff` group, the fake upstream as an upstream, the relying parties `perf-rp-1..3`; idempotent | — |
| `seed.ts import` | The import benchmark: 1,000-line batches through 8 parallel clients, then the active-user count and a sampled deep comparison; JSON report | TIO-ADMIN-021 |
| `seed.ts harvest` | One federated login per user through the fake upstream (authorize → upstream leg → callback → complete → exchange), leaving a session cookie and a refresh token per line in `data/tokens.ndjson` | TIO-TEST-050 |
| `scenarios/*.js` | The k6 scenarios, one per §2.7 row, with the budgets of `scenarios/budgets.js` as thresholds on the `Server-Timing` header the OP sends (TIO-OBS-004) | TIO-PERF-001, TIO-TEST-051 |
| `scenarios/soak_refresh.js` | Two hours of refreshes at 100/s: p99 of the last ten minutes against the first, per-user export size before and after | TIO-TEST-052 |

The budgets are checked against the specification's table by
`test/scripts/perf-budgets.test.ts`; the pure helpers of `seed.ts` by
`test/scripts/perf.test.ts`. `data/` is ignored by git: it holds the tokens
(credentials of synthetic users, never archived) and the reports.

## Running by hand

```sh
export TIO_PERF_ISSUER=https://auth.staging.example.com
export TIO_PERF_LOGIN_URL=https://login.staging.example.com/
export TIO_PERF_CLIENT_ID=… TIO_PERF_CLIENT_SECRET=…        # a client_credentials client with the admin scope
export TIO_FAKE_ISSUER=https://idp.staging.example.com TIO_FAKE_CLIENT_ID=… TIO_FAKE_CLIENT_SECRET=…
node perf/seed.ts prepare --groups staff
node perf/seed.ts import --users 10000 --groups staff --skip-if-seeded
node perf/seed.ts harvest --count 2000 --rate 20
TIO_PERF_DURATION=1m TIO_PERF_SUMMARY=perf/data/discovery.summary.json k6 run perf/scenarios/discovery.js
node scripts/load-summary.ts perf/data
```

Every scenario reads `TIO_PERF_RATE` and `TIO_PERF_DURATION`; the ones that
rotate refresh tokens (`token_refresh`, `soak_refresh`, the `userinfo` setup)
take `TIO_PERF_SLICE=from:to` so that two runs never present the same token
(a reuse revokes the family, TIO-RT-003). The nightly job assigns disjoint
slices.

## What the thresholds measure

The OP measures every request inside the Worker (`duration_ms` of the log
line, TIO-OBS-001) and exposes it with its Durable Object and D1 counts as
`Server-Timing: app;dur=<ms>, do;desc="<n>", d1r;desc="<n>", d1w;desc="<n>"`.
k6 records `app` as `server_ms` (the §2.7 p99 thresholds), the counts as
counters (`d1_writes` rate below 5/s during token scenarios, §13.10), and
each scenario checks the hop and write counts its row allows. `http_req_failed`
must stay below 0.1% everywhere.
