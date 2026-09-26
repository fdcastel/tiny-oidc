# 0019 — The audit hot table keeps a bounded subset of events; the archive is written per consumer batch

Date: 2026-09-26 · Status: **Proposed — awaiting the owner's sign-off** · Task: P7-09

## Context

After a week of load runs on a 7,000-user population, the staging D1 database
held **3.26 GB**, almost all of it `audit_hot`: 5.84 M rows, 3.1 M of them
written on 2026-09-22 alone. The rows by type:

| Type | Rows | Share |
|---|---|---|
| `token.refreshed` | 3,376,258 | 58 % |
| `authz.code_issued` | 946,717 | 16 % |
| `token.issued` | 791,240 | 14 % |
| `interaction.created`, `identity.login_succeeded`, `interaction.completed`, `session.created` | 674,547 | 12 % |
| the other 26 types | 46,734 | 0.8 % |

The volume follows **traffic, not users**. The specification sends every
event of the §11.2 catalog to `audit_hot` (TIO-AUDIT-011), and §2.7 budgets
the table at "~4,000,000 rows, ~2 GB" for 30 days at 100,000 daily active
users. The same section puts the traffic at ~200,000 interactive logins and
~5,000,000 refreshes a day, and `test/http/audit-events.test.ts` fixes what
each flow emits: a login emits six events (`interaction.created`,
`passkey.auth_succeeded` or `identity.login_succeeded`, `session.created`,
`authz.code_issued`, `interaction.completed`, `token.issued`) and a refresh
one. The budget and the rates contradict each other by a factor of 46.

### Measurements

- **Bytes per row: 533** on average and **608** for `session.created`. They
  were measured by loading 24,565 staging rows (every 250th) into SQLite with
  the schema of migrations 0001 and 0007, copied to about 200,000 rows and
  vacuumed. Without the four secondary indexes the average is 381. Staging
  itself reads 558 per row (database size over row count).
- **Archive bytes per event (gzip NDJSON): 345** when an object holds one
  request's events, as today, and **71** when it holds 100 messages.
- **Platform limits**, read on 2026-09-26 from Cloudflare's pages:
  - **D1:** 10 GB per database on Workers Paid, which "cannot be further
    increased". 50 M rows written a month are included, then $1.00 per
    million, and "indexes will add an additional written row" (the pages
    say "at least one", so the model below takes 2 to 6 rows per insert).
  - **Queues:** 3 operations per delivered message, 1 M operations included,
    then $0.40 per million.
  - **R2:** Class A $4.50 per million after 1 M; storage $0.015 per
    GB-month.

### What the current design does at the §2.7 rates

The sessions an SSO hit reuses are not in §2.7's rates and are left out, so
every figure below is a lower bound.

| | Value | Specification says |
|---|---|---|
| Audit rows per day (1.2 M from logins, 5 M from refreshes) | **6.2 M** | — |
| `audit_hot` growth | **3.3 GB/day** | ~2 GB for 30 days |
| 30 days at the default retention | **186 M rows, ~99 GB** | ~4 M rows |
| Time until D1 is full (10 GB less the 0.9 GB directory) | **≈ 2.8 days** | 3× headroom |
| Purge capacity (TIO-CFG-010: 10 × 1,000 rows every 5 minutes) | 2.88 M rows/day, so the table grows by ≥ 3.3 M rows/day whatever the retention | — |
| D1 rows written for inserts (deletes as much again) | $322–$1,066/month, $694–$2,182 with the purge | D1 < $10/month |
| Queue messages (one per request that emits events: 5 M refreshes, 4 per login) | 5.8 M/day: 522 M operations, ~$208/month | 1–3 M/day, ~$40 |
| R2 objects (one per message, TIO-AUDIT-011) | 174 M Class A per month, ~$779 | — |

When D1 is full, every write to it fails: directory writes, key rotation,
settings and invitations. The specification's §2.3 moved refresh rotation out
of D1 for exactly this kind of volume (Appendix B #2). The audit pipeline
brings that volume back into D1 through the queue.

## Options

- **A. A hot subset, and the archive written per consumer batch
  (proposed).** Only events worth reading back soon go to `audit_hot`;
  every event still reaches R2. The consumer writes one R2 object and one D1
  batch per queue batch instead of per message. Details below.
- **B. Per-user events in `UserDO`, no audit in D1.** Scales with users
  (object storage is unbounded in total), but it reverses Appendix B #31,
  adds an object write per event to the queue consumer, and cross-user admin
  queries (`GET /admin/audit`) would have to read R2. It is the right design
  if A's budget is ever exceeded; not needed for v1.
- **C. A separate D1 database for audit, rotated monthly.** Moves the ceiling
  and adds a binding and operational steps per rotation, but leaves the
  write cost and the purge rate as they are.
- **Retention alone.** 3.3 GB/day leaves under three days of retention and
  does not fix the purge rate. **Dropping the secondary indexes** saves 29 %
  and breaks the `/admin/audit` filters. Neither is enough.

## Proposed decision (option A)

1. **Every catalog type carries a class, `hot` or `archive`** (§11.2 gains a
   column; `src/audit/catalog.ts` gains the field; the existing spec-to-catalog
   test is extended to it). `archive` types go to the R2 archive and to Analytics
   Engine counts (TIO-OBS-002) only. `hot` types also go to `audit_hot`. The
   class is per type, not per outcome: `ratelimit.exceeded` is a failure but
   is emitted once per refused request, so a flood would write itself into
   D1.

   | Class | Types |
   |---|---|
   | `archive` | `interaction.created`, `interaction.completed`, `authz.code_issued`, `token.issued`, `token.refreshed`, `passkey.auth_succeeded`, `identity.login_succeeded`, `session.expired`, `ratelimit.exceeded` |
   | `hot` | every other type: users, groups, passkey and identity changes, invitations, consent, `session.created`, `session.rotated`, `session.revoked`, every failure type (`passkey.auth_failed`, `passkey.clone_suspected`, `identity.login_failed`, `interaction.failed`, `authz.denied`, `token.refresh_reuse`, `token.code_replay`, `token.client_auth_failed`, `token.revoke_foreign`), `token.revoked`, logout, clients, upstreams, keys, settings, administration, system |

2. **A login is one hot row.** `session.created` (or `session.rotated` on a
   re-authentication) is the login record, and gains the `passkey_id` data
   key, so the per-user view still says which passkey signed in. The
   upstream is already in the row's `upstream` column.

3. **The consumer writes per queue batch.** One R2 object holds all the
   batch's events, keyed by the first event (`archiveKey`), and one
   `db.batch()` holds the batch's hot rows. Every message is acknowledged
   only after both succeed. A retried batch can regroup its messages
   differently, so an event may appear twice in the archive under another
   key. `audit_hot` stays unique through `INSERT OR IGNORE`. Archive readers
   deduplicate by event `id`, and TIO-DATA-025 is amended to say so.

4. **`audit.hot_retention_days` defaults to 14** (range unchanged, 1–365).
   The R2 archive keeps everything; the runbook recommends 365 days.

5. **The capacity model becomes a CI check (TIO-PERF-003).**
   - **`test/scripts/audit-capacity.test.ts`** reads §2.7's daily rates from
     the specification, as `test/scripts/perf-budgets.test.ts` already does.
     It multiplies them by the hot events each flow emits and adds an
     allowance of 25 % of logins for failures, logouts and administration.
     It takes the measured row size (610 bytes, the largest measured type),
     the default retention and the directory estimate. It asserts two
     bounds: D1's audit plus directory stays within **50 % of the 10 GB
     cap**, and the hot rows per day stay within **25 % of the cron's purge
     capacity**.
   - **`test/http/audit-events.test.ts`** asserts that each flow emits
     exactly the events the capacity table lists for it (a passkey login, a
     federated login, a session hit with its code exchange, a refresh, an RP
     logout). The table cannot drift from the code.
   - **A new event type without a class fails the catalog test.**

### The same rates under option A

| | 14 days (proposed) | 30 days |
|---|---|---|
| Hot rows per day (200,000 logins × 1, + 25 %) | 250,000 | 250,000 |
| Rows in `audit_hot` | 3.5 M | 7.5 M |
| `audit_hot` size | 2.13 GB | 4.56 GB |
| D1 total with the directory | **3.03 GB (30 % of the cap)** | 5.46 GB (55 %, over the budget) |
| Purge capacity used | 8.7 % | 8.7 % |
| D1 rows written, purge included | $0–$40/month | $0–$40/month |
| R2 Class A (one object per consumer batch of ≤ 100 messages) | 1.74 M/month, ~$4.50 | same |
| R2 archive after 365 days (71 B/event) | 161 GB, ~$2.40/month | same |
| Queue operations (unchanged: one message per request) | ~$208/month | same |

Refreshes and SSO hits no longer touch D1 at all. The hot table grows with
logins, failures and administration only.

### Draft specification text

These changes go into `doc/TINY_OIDC_SPEC.md` in the implementing commit:

- **§0 item 4, §2.2 and §2.3 "Audit events" row:** "`TASKS` queue → R2
  archive (every event) + D1 `audit_hot` (hot types, 14 days)".
- **§2.7 capacity table:**
  - The `audit_hot` row becomes "~3.5 M rows, ~2.1 GB (hot types, 14 days)".
  - The queue row becomes "~6 M messages/day (one per request that emits
    events), ~$210/month".
  - The D1 total becomes "~3 GB".
  - The cost line is corrected to the figures above.
  - New sentence: "The hot table grows with interactive logins, failures and
    administration, not with refreshes or session hits (§11.2 classes)."
- **§11.2:** a "Class" column; the classes of the table above.
- **New [TIO-AUDIT-013]:** "Every catalog type SHALL have the class `hot` or
  `archive`. Events of every class SHALL be archived to R2; only `hot` events
  SHALL be written to `audit_hot`. A type that successful protocol requests
  emit as a matter of course (interaction steps, code and token issuance,
  refresh) or that the rate limiter emits per refused request SHALL be
  `archive`; authentication and client-authentication failures SHALL be
  `hot` (§6.7 bounds them per address)."
- **TIO-AUDIT-010:** "Per-user views read the hot events of `audit_hot` by
  `user_id`…"; `/me/events` shows sign-ins (`session.created`,
  `session.rotated`), credential and identity changes, consent and failures.
- **TIO-AUDIT-011:** "The queue consumer SHALL write the hot events of a
  queue batch to `audit_hot` (…) and all of its events to R2 as one gzip
  NDJSON object per queue batch, and SHALL acknowledge the batch's messages
  only after both succeed."
- **TIO-DATA-025:** "…an archived event may repeat under another key after a
  retry; the archive is unique by event `id`, and readers deduplicate by it."
- **§9 `/audit` row:** "from `audit_hot` (hot types); the full stream is in
  the archive (`/audit/archive`)".
- **§12 `audit.hot_retention_days`:** default 14.
- **New [TIO-PERF-003] (V: ci):** "At the §2.7 rates, the hot rows kept for
  the default retention at the measured row size, plus the directory
  estimate, SHALL stay within 50 % of the D1 database cap, and the hot rows
  per day within 25 % of the purge capacity of TIO-CFG-010; a CI test
  computes both from the catalog classes and the events each flow emits."
- **Appendix B #38:** "Every audit event in `audit_hot` → a hot subset by
  type (ADR 0019). *Why:* at the §2.7 rates every event means 6.2 M rows a
  day and a full D1 in three days."

## Consequences

- **The per-user and admin views lose the routine success steps**:
  refreshes, code issuance, token issuance and interaction bookkeeping.
  Those remain in R2, listed by `/audit/archive` and read with R2 tooling.
  An investigation of "which refresh token was used when" becomes an
  archive query instead of an API filter.
- **Failure events a caller can trigger stay hot.** Each class is bounded
  per address by §6.7; a distributed flood still grows the table. The
  backstop is operational: `/admin/stats` already reports `audit_hot` rows,
  and the runbook gains a threshold, the budget row count (≈ 6.7 M rows: 5 GB less the
  0.9 GB directory, at 610 bytes a row), to alert on.
- **The queue stays at one message per request** (~$208/month at the §2.7
  rates). Cutting it means batching across requests, which a Worker cannot
  do without losing events. It is recorded here, not changed.
- **No migration is needed.** Rows of `archive` types already in `audit_hot`
  age out with the retention. On staging they are gone 14 days after
  deployment.
- **The 1,000,000-user benchmark (OP-07) is unaffected**: the import emits
  `user.created` per user (1 M hot rows, ~0.6 GB, once).

## Requirements and evidence (on implementation)

TIO-AUDIT-010, TIO-AUDIT-011, TIO-AUDIT-013 (new), TIO-DATA-025, TIO-PERF-003
(new), TIO-CFG-010, §2.7, §11.2:
- `test/scripts/audit-capacity.test.ts`: the two bounds.
- `test/scripts/audit-catalog.test.ts`: every type has a class, and the
  spec's column matches the catalog.
- `test/http/audit-events.test.ts`: each flow's events match the capacity
  table.
- `test/http/audit-sink.test.ts`: `archive` events reach R2 and not
  `audit_hot`; one object and one D1 batch per queue batch; a retried batch
  is idempotent in `audit_hot`, and archive duplicates carry equal ids.
- `test/http/audit-endpoints.test.ts`: the per-user views show the login as
  `session.created` with `passkey_id`.

## Sign-off

| Role | Name | Date | Decision |
|---|---|---|---|
| Owner | | | |
