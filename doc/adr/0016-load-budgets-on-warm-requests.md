# 0016 — Load budgets on warm requests; the D1-touching tail bounded

Date: 2026-09-21 · Status: Accepted (owner's decision) · Task: P7-04

## Context

Seven nightly load runs against staging (1,000 users, 5-minute scenarios,
runner in the United States, D1 in ENAM) told one consistent story. The
requests whose path read no D1 met every §2.7 p99 budget:

| Scenario | budget p99 | p99 over every request | p99, no D1 on the path | p99, D1 on the path | share reading D1 |
|---|---|---|---|---|---|
| discovery | 20 ms | 22 | 22 | 97 | ~0% |
| `/authorize` session hit | 150 ms | 211 | 116 | 359 | ~7% |
| token refresh | 150 ms | 240 (burst 291) | 81 | 685 | ~7% |
| code exchange | 200 ms | 261 | 79 | 1124 | ~3% |
| userinfo | 100 ms | 31 | 24 | 1167 | ~2% |
| admin list | 300 ms | 930 | — | 930 | 100% |
| federation callback | 800 ms | 889 | — | 889 | 100% |

The p99 over every request was set by the 2–8 % of requests that read D1
synchronously: cold isolates — Workers spawn and evict them under load, and
each one loaded settings, keys and the client record in three sequential
round trips of 100–300 ms to the single D1 region — and, for the admin lists
and the federation callback, the D1 round trip itself. Night-to-night
variance of these tails was about 1.5×, with the runner's network path.

Four resolutions were put to the owner: budgets on warm requests with the
tail bounded (this record); every budget relaxed to measured values; a
colo-shared second cache tier in the Cache API before touching the budgets;
the load gate report-only until production.

## Decision

A row's p99 budget applies to the requests whose path read no D1
(`Server-Timing` `d1r` = 0, TIO-OBS-004), the work the Worker's code controls.
The p99 over every request, the D1-touching ones included, is bounded at
four times the row's p99, so a regression in the tail still fails the gate.
(The D1-touching requests alone are 2–8 % of a run; their own p99 is a
handful of samples that swung twofold between two runs of identical code,
and a gate that flaps on identical code is no gate.) The two rows whose path reads D1 by
design — the federation callback (600/1200 ms) and the admin lists
(300/1000 ms) — are budgeted over every request, at values set from the
measurements above. TIO-PERF-001 and §2.7 say so; `perf/scenarios/budgets.js`
carries the `d1` flag and `TAIL_FACTOR`, and `test/scripts/perf-budgets.test.ts`
checks them against the table.

Alongside, the cold isolate got cheaper: the request middleware starts the
settings and key loads together and keeps them alive past the response, both
caches share one blocking load among concurrent requests, and the client
lookup that follows the body parse overlaps them — one parallel round trip
where there were three in sequence. Upstream records are cached per isolate
like clients (§2.8), which brought the federation callback down to its one
D1 read.

## Consequences

- The gate distinguishes "our code got slower" from "the platform placed us
  farther from D1 tonight": the first fails the warm budget, the second the
  tail bound only when the p99 of everything is four times the budget.
- `sso_authorize` runs over a slice of 200 sessions, as `token_refresh` and
  `userinfo` run over slices of theirs: spread over all 1,000 sessions at
  50/s, each user's object was hit once every 20 s and evicted in between,
  and the scenario measured Durable Object cold starts (warm p99 383 ms
  against a p95 of 97) rather than the session hit. A cold object costs
  200–400 ms and is a platform property the callback row already carries.
- The rows whose one object call writes — the session hit (session touch and
  code mint) and the refresh (family rotation) — are budgeted at 200 ms, the
  value the code exchange (code consumption, family creation) already
  carried: on the sliced, correctly accounted runs their warm p99 was
  135–156 and 140–147 ms, the durable-write tail of an object, two to ten
  per cent under 150, and a gate with that margin flaps.
- The refresh burst (500/s for 60 s, §13.10) is budgeted at one and a half
  times the row's p99 (TIO-TEST-051): a spike of more than three times the
  steady rate onto the same 600 objects measured a warm p99 of 165 ms against
  147 sustained, and a bound that flaps on ten per cent of noise is no bound.
- The public documents (discovery, JWKS, WebAuthn origins) are held in
  isolate memory for 60 s in front of the Worker cache: the cache match alone
  had a tail past the discovery row's whole 20 ms budget.
- The `d1_reads` counter and the split trends (`server_ms_warm`,
  `server_ms_d1`) stay in every summary, so the share of cold requests is
  visible night to night.
- The 1,000,000-user run (TIO-PERF-001 as written) and the production
  measurements can revisit both the factor and the two measured rows.

## Requirements and tests

TIO-PERF-001, TIO-TEST-051, TIO-ARCH-011 — `test/scripts/perf-budgets.test.ts`,
`test/http/router.test.ts` (the cold isolate's one round trip), the nightly
`load` job.
