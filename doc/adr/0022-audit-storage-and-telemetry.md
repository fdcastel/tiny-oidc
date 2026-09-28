# 0022 — Audit storage: hot and archive-only types, one archive object per consumer group under a unique key, the capacity model in CI

Date: 2026-09-28 · Status: Accepted (owner's decisions of 2026-09-27 on the review's §8: the generally available transport for v1, this work as v2) · Task: P8-02 · Supersedes: ADR 0019 (proposed, never accepted)

## Context

The review of 2026-09-26 (`doc/reviews/2026-09-26-platform-and-spec-review.md`,
§3) found that the audit pipeline as specified cannot run at the §2.7 target:

- it writes every event to `audit_hot`, which at those rates is 6.2 M rows a
  day, a full D1 in about three days, and more than the cron can purge;
- it writes one R2 object per queue message (about $779 a month at the target);
- the capacity table of §2.7 contradicted its own rates by a factor of 46.

The second review found that ADR 0019's first design would also lose events.
It keyed each archive object by the batch's first event. A redelivered batch
regrouped behind the same first event would replace the earlier object's
events, and a bucket lock would refuse the rewrite altogether (M8). The owner
chose the generally available path for v1 (review §7: Pipelines' `send()` can
report success and still lose events) and made this work v2.

## Decision

1. **Hot and archive-only types (TIO-AUDIT-013).**
   - **Archive-only:** `interaction.created`, `interaction.completed`,
     `authz.code_issued`, `token.issued`, `token.refreshed`,
     `passkey.auth_succeeded`, `identity.login_succeeded`, `session.expired`,
     `ratelimit.exceeded`. These are the steps every successful protocol
     request takes, plus the rate limiter's refusals (a flood must not write
     itself into D1).
   - **Hot:** every other type.
   - **Where each goes:** every event goes to R2; only hot events go to
     `audit_hot`, which is what the per-user views and `/admin/audit` read.
   - **A login's hot record** is its `session.created` or `session.rotated`.
     ADR 0019 proposed adding `passkey_id` to it; that would change the
     interaction's stored schema, and the archived `passkey.auth_succeeded`
     already names the passkey, so it is left out.
2. **One archive object per consumer group, under a unique key
   (TIO-AUDIT-011, TIO-DATA-025, §4.5).**
   - **Grouping:** the consumer writes the audit messages of a queue batch
     together, in groups of at most 1,000 events: one D1 batch of the hot
     rows and one R2 object per group. Groups that would take an invocation
     past 800 `audit_hot` statements are retried, not written, because
     Workers allow 1,000 D1 queries per invocation.
   - **Keys:** `audit/year=YYYY/month=MM/day=DD/hour=HH/<first-event-id>-<write-id>.ndjson.gz`.
     The Hive-style segments let DuckDB prune by time, and the write id makes
     every key new. Nothing is ever rewritten, so a lock (P8-04) cannot refuse
     a write.
   - **Duplicates:** a redelivery may archive an event twice, and readers
     deduplicate by `id`.
   - **Format:** gzip NDJSON, as before. Workers compress no zstd, and a
     Parquet writer would not fit the bundle budget; Parquet is for an
     operator-side compaction job.
3. **Hot retention defaults to 14 days.** v1 ships with 7, the owner's launch
   condition for the design without classes.
4. **The capacity model is a CI check (TIO-PERF-003).**
   - **What `test/scripts/audit-capacity.test.ts` reads:**
     - the §2.7 rates, from the specification;
     - the events each flow emits and the requests that carry them, from
       `src/audit/capacity.ts`. `test/http/audit-events.test.ts` asserts that
       table against a real passkey login and a real refresh.
     - row sizes, measured by loading the migrations into SQLite (a hot row
       is ~659 bytes, the directory ~1.3 GB at 1,000,000 users).
   - **What it asserts:**
     - D1 stays within half its cap;
     - hot rows per day stay within a quarter of the purge capacity;
     - the alarm threshold of TIO-OBS-005 fits the same half. The threshold
       is lowered to 5,500,000 rows by this measurement: the 6,000,000 of
       v1 assumed 560 bytes a row.
     - every figure of §2.7's table and cost line matches the model within
       10 %.
   - **The model's figures at the target:** 250,000 hot rows a day, 3.5 M
     rows and 2.3 GB at 14 days, D1 at 3.6 GB (36 % of the cap), 8.7 % of the
     purge capacity. The queue costs about $213 a month and R2 writes about
     $3.50. Every event in D1 would have needed 125 GB.

## Consequences

- **The per-user views and `/admin/audit` no longer show refreshes, code and
  token issuance, or interaction steps.** Those events are in the archive,
  listed by `/admin/audit/archive` and read with DuckDB or R2 tooling.
- **The queue stays at one message per request.** That is about $213 a month
  at the target, and §2.7 now says so.
- **No migration is needed.** Rows of archive-only types already in
  `audit_hot` age out with the retention. Old archive objects keep their
  former keys: the listing of a day reads the new prefix, so objects written
  before this change are reached with R2 tooling.
- **The review's second-round document fixes** are in the review itself
  (§5–§7).

## Addendum (2026-09-28, P8-09)

The two indexes that serve the `actor_id` and `outcome` filters (review M5,
migration 0010) make a hot row ~729 bytes. TIO-PERF-003 then found the alarm
threshold of 5,500,000 rows past its budget (5.32 GB with the directory) and
it is 5,000,000. §2.7 reads 2.6 GB for `audit_hot` and 3.9 GB for D1.

## Requirements and evidence

TIO-AUDIT-010, TIO-AUDIT-011, TIO-AUDIT-013 (new), TIO-DATA-025, TIO-PERF-003
(new), TIO-OBS-005, §2.7, §4.5:
- **`test/http/audit-sink.test.ts`:**
  - hot rows only, and one object under a Hive-style unique key;
  - a redelivery adds no row and lands under a new key;
  - under a bucket that refuses rewrites (a lock), redeliveries and regrouped
    batches are all archived;
  - grouping, the deferral beyond the statement budget, and retries.
- **`test/scripts/audit-catalog.test.ts`:** the specification's list equals
  the code's set.
- **`test/scripts/audit-capacity.test.ts`:** the budgets, and the §2.7
  figures against the model.
- **`test/http/audit-events.test.ts`:** each flow's events and requests.
- **`test/http/audit-endpoints.test.ts`:** the archive listing under the new
  keys.
