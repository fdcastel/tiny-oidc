 ✅ DONE | 00c3f7f | ✅ DONE | 00c3f7f | ✅ DONE | c88b17e | ✅ DONE | 6422772 | ✅ DONE | 993c69b | ✅ DONE | 993c69b | ✅ DONE | 75ff0c2 | ✅ DONE | 75ff0c2 | ✅ DONE | 6601661 | ✅ DONE | 6601661 | ✅ DONE | 75ff0c2 | ✅ DONE | 9acb15c | ✅ DONE | 9acb15c |#undefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefined 🔧 IN PROGRESS | pending | 🔧. `fetchMock` no longer exists in `@cloudflare/vitest-plugin` 1.x: `fetch-allowlist.ts` is built on `@msw/cloudflare` (spec TIO-ARCH-016 and TIO-TEST-031 reworded, §13.1 row added); the authenticator interface arrives with its implementation in P2-06 instead of as an unused stub; tests reach the Worker through `test/support/op.ts` (`cloudflare:workers` `exports.default.fetch`, since `SELF` is deprecated) |IN PROGRESS | pending | 🔧. Production path parses `Worker Version ID:` and `Version Preview URL:` from `wrangler versions upload` (verified against wrangler 4.135), so the production Worker must keep preview URLs enabled; generated config is `wrangler.generated.jsonc` (gitignored) |IN PROGRESS | pending | 🔧. Schemas moved to `src/config/schema.ts` and OpenAPI route definitions to `src/api/definitions.ts` (no Workers types) so Node generators can import them; `gen:openapi` added; `pnpm gen:secrets --dev-vars` writes `.dev.vars` for local runs |IN PROGRESS | pending | 🔧. `createApp({ clock, sink })` so tests inject the clock and capture log lines; one route table (`src/router/routes.ts`) drives CORS, 405 `Allow`, body limits and the header matrix; `OpenAPIHono` from Phase 0 so the OpenAPI drift check exists early; Host compared through the request URL (workerd does not expose the header); `minify: true` added to `wrangler.jsonc` because unminified zod alone is 787 KB |IN PROGRESS | pending | 🔧. DO methods return `{ ok, error }` results rather than throwing so codes survive RPC; every mutating method takes `now` from the caller's Clock; state machine is a pure table in `src/interaction/state-machine.ts` |IN PROGRESS | pending | 🔧. Repositories land with the phase that first needs them (settings in Phase 0); `Db` wrapper counts reads and writes for the log line |IN PROGRESS | pending | 🔧. `secretsEqual` uses `crypto.subtle.timingSafeEqual` (workerd-only), so its test lives in `test/component`; envelope property tests run in Node with fast-check |IN PROGRESS | pending | 🔧. `http` ISSUER accepted only on loopback hosts (no environment flag, TIO-GEN-004); registrable domains approximated without a PSL (`src/util/domain.ts`); `SettingsLoader` 60 s TTL, 1 h stale-if-error |IN PROGRESS | pending | Tiny. Written; runs on the first push after P0-14. Nightly cannot run `deploy.ts` (no Cloudflare token in GitHub, TIO-DEPLOY-006): the real runs happen in Workers Builds on every push to `main`; nightly reaches staging over HTTPS only |OIDC — Implementation Plan (living document)

| | |
|---|---|
| **Source of truth for behavior** | [TINY_OIDC_SPEC.md](TINY_OIDC_SPEC.md) (283 requirement ids). This plan says *when* and *in what order*; the spec says *what*. |
| **Last updated** | 2026-09-19 |
| **Current focus** | Phase 0 complete. Next: `P1-01` (key store). |
| **Branch model** | Direct commits to `main`; every push runs the full gate set. `production` branch is fast-forwarded for releases (spec §12.3). |

## How to keep this plan updated

These rules bind whoever works on the repository, human or agent. The plan is only useful while it is true.

1. **Before starting a task**, set its Status to `🔧 IN PROGRESS` and update *Current focus* above. Work on at most two tasks at once.
2. **A task is `✅ DONE` only when** its code is merged on `main`, every test named in the task passes in CI, coverage is still 100%, and `pnpm trace` shows the task's spec ids as covered (spec §13.12). "Implemented but untested" is `🔧 IN PROGRESS`, never done.
3. **Fill the Commit column** with the short hash (7 characters) of the commit that completed the task. When the task and this plan change in the same commit, the hash is not known yet: write `pending` and replace it in the next commit that touches this file (`git log --oneline -- <path>` finds it).
4. **Never delete or renumber a row.** A task that becomes unnecessary gets `⏯️ DEFERRED` with the reason in Notes, or is superseded by a new row that says "supersedes Pn-mm".
5. **Add tasks with the next free id in their phase** (`P3-12` after `P3-11`). Cross-phase or operator work goes in the *Operator tasks* or *Backlog* tables.
6. **`⏯️ DEFERRED` rows must name the task or decision they wait for** in Notes, so the blocker is visible.
7. **When a spec change alters a task**, update the task text and its Spec column in the same commit as the spec change, and record it in the *Plan change log* at the end of this file.
8. **Update *Last updated*** and the change log on every edit. Keep phases in order; do not start Phase n+1 tasks that depend on an unmet exit criterion of Phase n (independent tasks may run early and say so in Notes).
9. **Operator tasks** (rows `OP-nn`) are for the repository owner. Set them `🔧 IN PROGRESS` when the request has been sent to the owner and `✅ DONE` when confirmed.

### Status legend

| Status | Meaning |
|---|---|
| ✅ DONE | Fix implemented and tested |
| 🔧 IN PROGRESS | Partially implemented or underway |
| ❌ OPEN | Not yet addressed |
| ⏯️ DEFERRED | Delayed or put on hold until another task is finished |

### Column meanings

| Column | Meaning |
|---|---|
| **ID** | `Pn-mm` for phase *n* task *mm*; `S-mm` specification work; `OP-mm` operator tasks; `B-mm` backlog. |
| **Task** | What to build, in actionable terms. Paths are repository-relative. |
| **Spec** | Requirement ids or sections in TINY_OIDC_SPEC.md that the task implements. `pnpm trace` will show them covered when the task is done. |
| **Status** | One of the four values above. |
| **Commit** | Short git hash that completed the task, `pending`, or `—` when not applicable. |
| **Notes** | Blockers, decisions, deviations. |

---

## Phase S — Specification (complete)

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| S-01 | Write the v1 specification from the initial draft; verify Cloudflare limits and tooling facts | all | ✅ DONE | 79fc01c | 268 ids at that point |
| S-02 | Deployment model (Workers Builds, host-neutral repo, Deploy button, bundled reference login app), README, MIT license | §12, §7.9 | ✅ DONE | 17d7620 | |
| S-03 | Reference review against tinyauth and authenti-kate: 12 improvements, 8 simplifications, decision log 28–36 | Appendix B | ✅ DONE | becd7c5 | 283 ids, 6 withdrawn |
| S-04 | This implementation plan | §14.2 | ✅ DONE | 058caee | |

---

## Phase 0 — Foundation (complete)

**Goal:** every CI gate exists and is green on a nearly empty `src/`, so the gates tighten as phases complete instead of being bolted on at the end.

**Exit criteria:** `pnpm lint`, `pnpm typecheck`, `pnpm test` (unit + workers), `pnpm test:e2e` (one smoke test), `pnpm trace` (with the phase allow-list), bundle, config, neutrality and drift checks all pass in `pr.yml`; `wrangler dev` serves `/api/v1/health`.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P0-01 | Repository scaffold: `package.json` (scripts `dev`, `build`=typecheck, `test`, `test:unit`, `test:workers`, `test:e2e`, `deploy`, `trace`, `lint`, `gen:openapi`, `gen:config`), `.nvmrc` (24), `pnpm-lock.yaml`, `tsconfig.json` (`strict`, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`, `noImplicitOverride`), `biome.json`, host-neutral `wrangler.jsonc` with top-level profile and `env.staging`/`env.production` | §12.1, §14.1, TIO-CFG-001, TIO-GEN-003 | ✅ DONE | 9acb15c | Runtime deps limited to hono, @hono/zod-openapi, zod, jose, @simplewebauthn/server, uuidv7; `jose` and `@simplewebauthn/server` are added when first used (Phase 1, Phase 2) because `knip` fails on unused dependencies. Scripts run on Node 24 type stripping (no `tsx`), so imports carry `.ts` extensions everywhere |
| P0-02 | Test toolchain: Vitest 4 with `vitest.unit.config.ts` (Node) and `vitest.workers.config.ts` (`@cloudflare/vitest-plugin`, Istanbul coverage, thresholds 100/100/100/100 on `src/**`, `src/generated/**` excluded); `playwright.config.ts` with Chromium, Firefox, WebKit projects; `test/support/reset.ts` for per-file storage isolation | TIO-TEST-002, TIO-TEST-003, TIO-TEST-004 | ✅ DONE | 9acb15c | Per-file isolation only; `resetStorage()` in `beforeEach` where needed. Root `vitest.config.ts` runs both configs as projects so coverage is one report; Vitest pinned to 4.1 because `@cloudflare/vitest-plugin` 1.1 requires `^4.1` |
| P0-03 | CI: `.github/workflows/pr.yml` running lint, typecheck, knip, unit, workers with coverage, e2e Chromium, trace, bundle size, config check, OpenAPI drift, config-docs drift, neutrality check; `.github/workflows/nightly.yml` skeleton with conformance, load and mutation jobs (skipped until Phase 7) | TIO-TEST-001, TIO-TEST-008, TIO-DEPLOY-011 | ✅ DONE | 75ff0c2 | No Cloudflare token in GitHub, ever. Nightly cannot run `deploy.ts` (no Cloudflare token in GitHub, TIO-DEPLOY-006): the real runs happen in Workers Builds on every push to `main`; nightly reaches staging over HTTPS only |
| P0-04 | `scripts/trace.ts` + `scripts/trace.config.json`: parse spec ids and verification tags, parse test titles, fail on uncovered default-tag ids not allow-listed for the current phase, fail on unknown or withdrawn ids in tests, emit `doc/TRACEABILITY.md`; drift check for the generated file | TIO-TEST-006, TIO-TEST-007 | ✅ DONE | 6601661 | Allow-list shrinks as phases complete. Mapping is section → phase (`phases`) with per-id `overrides`; `describe` titles do not count, only `it`/`test` titles (incl. `.each`/`.for`) |
| P0-05 | `scripts/lint-rules.ts` (every rule in TIO-TEST-060), `scripts/check-ignores.ts` (≤ 15 justified istanbul ignores), `scripts/config-check.ts` (bindings equal §2.2, runtime deps equal the list, `nodejs_compat` absent, button profile has default ids), `scripts/neutrality-check.ts` (no 32-hex ids, no non-placeholder `database_id`), `scripts/bundle-check.ts` (≤ 1.5 MB) | TIO-TEST-060, TIO-TEST-003, TIO-ARCH-003, TIO-GEN-002, TIO-GEN-003, TIO-CFG-001, TIO-DEPLOY-005, TIO-PERF-002 | ✅ DONE | 6601661 | Runtime-dependency check is a subset check (fails on additions, does not require listed deps to be installed) because `knip` fails on unused dependencies; deps are added when first used |
| P0-06 | `src/env.ts`: `Env` bindings type, injected `Clock`, zod schema for env vars, secrets and settings with descriptions, defaults and bounds; settings loader with 60 s isolate cache and 1 h stale-if-error; cross-field validation; `MASTER_KEYS` validation at first request | TIO-CFG-002, TIO-CFG-003, TIO-CFG-005, TIO-ARCH-011, TIO-ARCH-012, TIO-ARCH-013, TIO-CRYPTO-010 | ✅ DONE | 75ff0c2 | Only place `Date.now()` is allowed. `http` ISSUER accepted only on loopback hosts (no environment flag, TIO-GEN-004); registrable domains approximated without a PSL (`src/util/domain.ts`); `SettingsLoader` 60 s TTL, 1 h stale-if-error; schemas live in `src/config/schema.ts` (no Workers types) and are re-exported by `src/env.ts` |
| P0-07 | `src/crypto/`: `random.ts`, `hash.ts` (SHA-256, constant-time compare), `master-keys.ts` (HKDF-derived keys per version), `envelope.ts` (AES-GCM handle codec for all six types), `uuid.ts` (v7 monotonic); property tests with fast-check for round-trip and single-bit tamper rejection | TIO-ARCH-006..009, TIO-CRYPTO-001..004, TIO-CRYPTO-020, TIO-DATA-001, TIO-DATA-002 | ✅ DONE | 75ff0c2 | |. `secretsEqual` uses `crypto.subtle.timingSafeEqual` (workerd-only), so its test lives in `test/component`; envelope property tests run in Node with fast-check |
| P0-08 | D1: `migrations/0001_init.sql` exactly as §4.1; `src/db/` repositories with typed parameters, `db.batch()` helper, Sessions API `withSession("first-primary")` helper; lint forbids `prepare(` elsewhere | §4.1, TIO-DATA-015, TIO-DATA-016, TIO-DATA-017 | ✅ DONE | 993c69b | |. Repositories land with the phase that first needs them (settings in Phase 0); `Db` wrapper counts reads and writes for the log line |
| P0-09 | Durable Objects: `src/do/UserDO.ts` with SQLite schema (§4.2 as amended), lazy `migrate()`, `init()`/`destroy()` guards, on-write purge; `src/do/InteractionDO.ts` with JSON document, alarm `deleteAll`, transition validator stub | §4.2, §4.3, TIO-DATA-019..023 | ✅ DONE | 993c69b | Two classes only. DO methods return `{ ok, error }` results rather than throwing so codes survive RPC; every mutating method takes `now` from the caller's Clock; state machine is a pure table in `src/interaction/state-machine.ts` |
| P0-10 | Router skeleton (`src/router/`): Hono app, security headers, CORS matrix, body and query limits, request id, `Host` check with health exception, 404/405 handling, JSON error model, uniform-error helper, structured log line, optional metrics, `GET /api/v1/health` | TIO-HTTP-001..006, TIO-ERR-001, TIO-ERR-002, TIO-OBS-001..003 | ✅ DONE | 6422772 | Header matrix test per route. `createApp({ clock, sink })` so tests inject the clock and capture log lines; one route table (`src/router/routes.ts`) drives CORS, 405 `Allow`, body limits and the header matrix; `OpenAPIHono` from Phase 0 so the OpenAPI drift check exists early; Host compared through the request URL (workerd does not expose the header); `minify: true` added to `wrangler.jsonc` because unminified zod alone is 787 KB |
| P0-11 | `scripts/gen-config-docs.ts` generating `doc/CONFIG.md` and `.dev.vars.example` from the schema in `src/env.ts`, with CI drift check; `scripts/gen-secrets.ts` printing `MASTER_KEYS` and `ADMIN_BOOTSTRAP_TOKEN` values for the README steps | TIO-CFG-005, TIO-DEPLOY-008 | ✅ DONE | c88b17e | |. OpenAPI route definitions live in `src/api/definitions.ts` (no Workers types) so Node generators can import them; `gen:openapi` added; `pnpm gen:secrets --dev-vars` writes `.dev.vars` for local runs |
| P0-12 | `scripts/deploy.ts` (profile selection, D1 migrations, D1 id resolution by name, `--var` injection, versions upload + smoke + deploy for production) and `scripts/smoke.ts`; unit tests with a fake `wrangler`; README deploy steps finalized | TIO-DEPLOY-007, TIO-DEPLOY-008 | ✅ DONE | 00c3f7f | Real run happens in nightly from Phase 2. Production path parses `Worker Version ID:` and `Version Preview URL:` from `wrangler versions upload` (verified against wrangler 4.135), so the production Worker must keep preview URLs enabled; generated config is `wrangler.generated.jsonc` (gitignored) |
| P0-13 | `test/support/`: `clock.ts`, `factories.ts` skeleton, `fetch-allowlist.ts` (fetchMock with network disabled and an allow-list), `virtual-authenticator.ts` stub interface | TIO-TEST-032, TIO-ARCH-016 | ✅ DONE | 00c3f7f | Authenticator implemented in P2-06. `fetchMock` no longer exists in `@cloudflare/vitest-plugin` 1.x: `fetch-allowlist.ts` is built on `@msw/cloudflare` (spec TIO-ARCH-016 and TIO-TEST-031 reworded, §13.1 row added); the authenticator interface arrives with its implementation in P2-06 instead of as an unused stub; tests reach the Worker through `test/support/op.ts` (`cloudflare:workers` `exports.default.fetch`, since `SELF` is deprecated) |
| P0-14 | Phase 0 exit: all gates green on `main`; `wrangler dev` answers `/api/v1/health`; trace allow-list configured for Phases 1–7 | §14.2 | ✅ DONE | 73a803a | Gates green locally and on the first push; `wrangler dev` answers `/api/v1/health`; Playwright smoke (health, JSON 404) on Chromium; `trace.config.json` `phase` stays 0 until Phase 1 exits (it names the last completed phase) |

---

## Phase 1 — Keys and discovery

**Goal:** the OP can publish JWKS and discovery and can sign and verify its own tokens.

**Exit criteria:** §5.2, §5.3 and §10 identifiers covered; `GET /.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/.well-known/jwks.json`, `/.well-known/webauthn` served with correct caching.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P1-01 | Key store: `src/crypto/keystore.ts` generating ES256 keys, exporting the JWK once, encrypting `private_jwk_enc` under the keystore key, importing non-extractable at runtime; `kid` = RFC 7638 thumbprint; first-key bootstrap guarded by `INSERT ... WHERE NOT EXISTS` | TIO-KEYS-010, TIO-KEYS-011, TIO-KEYS-014 | ❌ OPEN | — | |
| P1-02 | Key roles derived from `activates_at`/`retired_at`; rotation creates (with `immediate`), cron retires superseded keys after `retire_after_seconds`, deletes retired rows after 90 days; fail closed when no active key; three-key lifetime test with the injected clock | TIO-KEYS-012, TIO-KEYS-013, TIO-CFG-010 (key steps) | ❌ OPEN | — | Admin endpoints for keys arrive in P3-07 |
| P1-03 | JWKS endpoint publishing every unretired key, no `d` member under any state, `Cache-Control: public, max-age=300`, served through `caches.default` | TIO-KEYS-001, TIO-KEYS-002 | ❌ OPEN | — | |
| P1-04 | `src/oidc/capabilities.ts` constant; discovery documents for both well-known paths; deep-equality test against the constant; route-table comparison test; `/.well-known/webauthn` from `webauthn_origins` with the 5-label validation | TIO-DISC-001..004, TIO-PK-001 | ❌ OPEN | — | Validators import the same constant in Phase 2 |
| P1-05 | JWT service (`src/crypto/jwt.ts` over jose): sign with header `alg`/`typ`/`kid` only and a 512-byte header test; verify own tokens against unretired keys with `iss`, `exp` (0 s leeway), `typ`; ID token builder (claims table, null omission, `at_hash`); `at+jwt` builder with `aud` from `audiences`; logout token builder | TIO-KEYS-015, TIO-TOKEN-030..034, TIO-LOGOUT-010 | ❌ OPEN | — | |
| P1-06 | Master-key rotation: re-encrypt keystore rows under the active version in cron chunks; handles under retired versions rejected; three-phase test | TIO-CRYPTO-011, TIO-ARCH-008 | ❌ OPEN | — | `POST /maintenance/rekey` endpoint in P3-07 |
| P1-07 | Phase 1 exit: trace shows §5.2, §5.3, §10 covered | §14.2 | ❌ OPEN | — | |

---

## Phase 2 — Core flow with passkeys

**Goal:** a standard OIDC client signs a user in with a passkey through the reference login app, end to end, on local `wrangler dev`.

**Exit criteria:** §5.4–§5.9, §6.1–§6.3, §6.6, §7 identifiers covered; `oauth4webapi` interop green; concurrency suite green for code, refresh, challenge, invitation, PAR and complete; Playwright passkey sign-up and sign-in green on Chromium.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P2-01 | Clients: repository, validation rules (redirect URI rules incl. loopback exception, grant/auth-method combinations, `audiences`, TTL bounds), secret generation and hashing, isolate cache with stale-if-error, disable semantics | TIO-CLIENT-001..004, TIO-CLIENT-010, TIO-CLIENT-011, TIO-ARCH-011 | ❌ OPEN | — | |
| P2-02 | Client authentication for `/token`, `/par`, `/revoke`: `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt` (jose against `jwks`/`jwks_uri`, 60-second assertion window with mandatory `iat`); strict method enforcement; failed-auth rate-limit keys | TIO-TOKEN-002, TIO-TOKEN-003, TIO-TOKEN-004 | ❌ OPEN | — | No replay cache by decision (Appendix B #28) |
| P2-03 | `/authorize` validation pipeline in spec order, non-redirectable errors to `login_url`, redirectable errors with `iss`, `prompt`/`max_age`/`login_hint` handling, session evaluation, stale-parameter rule, `prompt=none` never touching the session, `allowed_groups` outcome | TIO-AUTHZ-001..024 (013 withdrawn) | ❌ OPEN | — | Depends on P2-08 for `authorizeWithSession` |
| P2-04 | PAR endpoint: client auth, validation reuse, `request_uri` single use and 60 s expiry stored in `InteractionDO`, `require_par` enforcement | TIO-PAR-001..004 | ❌ OPEN | — | |
| P2-05 | Interaction API: origin and binding-cookie checks, `GET` document (masking, field allow-list test), state machine table test, attempt counter, `abort`, consent endpoint and grant storage, logout interaction confirm | TIO-IX-001..003, TIO-IX-010, TIO-IX-011, TIO-IX-020, TIO-IX-021, TIO-IX-040, TIO-IX-041, TIO-IX-050, TIO-IX-070, TIO-CONSENT-001..004, TIO-RL-002 | ❌ OPEN | — | Federation endpoint arrives in P4-02 |
| P2-06 | Passkeys: registration and authentication options, verification via `@simplewebauthn/server` inside `UserDO.verifyAssertion` (atomic counter), counter policy, `credProps.rk` rule, `userHandle` routing with `passkey_index` fallback, limits and naming; `test/support/virtual-authenticator.ts` with fault injection, itself verified with the library | TIO-PK-002, TIO-PK-010..014, TIO-PK-020..023, TIO-PK-030, TIO-PK-040, TIO-PK-041, TIO-IX-030, TIO-TEST-030 | ❌ OPEN | — | |
| P2-07 | Registration policy and invitations: `register`/`recover` invitations as `tio_iv` handles, atomic consumption, pre-filled fields, `email_in_use` hint, recovery always revoking sessions and families; Interaction API register endpoints | TIO-REG-001..005, TIO-IX-032, TIO-REC-001 | ❌ OPEN | — | |
| P2-08 | `UserDO` core: sessions (create, rotate, touch, expire, revoke with family cascade), `authorizeWithSession`, `issueCode`, `exchangeCode` (atomic, PKCE, replay revokes families), refresh families and `rotateRefreshToken` (reuse detection, serial check, idle/absolute, session binding), grants with `client_created_at`, purge | TIO-SESS-001..006, TIO-TOKEN-010..014, TIO-RT-001..010, TIO-CLIENT-005, TIO-AUTHZ-022, TIO-AUTHZ-023 | ❌ OPEN | — | Largest task; split into sub-commits by table |
| P2-09 | `/interactions/{id}/complete`: binding check, session creation or rotation, code issuance, cookie handling, error redirect, resume and already-completed cases, revoked-session case | TIO-IX-033, TIO-IX-060..062 | ❌ OPEN | — | |
| P2-10 | `/token` endpoint: form parsing and limits, grants `authorization_code`, `refresh_token`, `client_credentials`, response shape, storage error mapping, scope rules including `admin` membership check | TIO-TOKEN-001, TIO-TOKEN-005, TIO-TOKEN-020, TIO-TOKEN-021, TIO-SCOPE-001, TIO-SCOPE-002, TIO-ARCH-014, TIO-ARCH-015 | ❌ OPEN | — | |
| P2-11 | `/userinfo` (GET and POST, fresh profile from `UserDO`, scope-gated claims) and `/revoke` (family revocation, foreign-token no-op, access-token session-family case) | TIO-UINFO-001..003, TIO-REV-001..003 | ❌ OPEN | — | |
| P2-12 | Groups: `groups` claim from `UserDO`, `allowed_groups` enforcement at authorization and refresh, `admins` system group bootstrap | TIO-DATA-011..013, TIO-AUTHZ-017, TIO-SCOPE-002 | ❌ OPEN | — | Group CRUD endpoints in P3-03 |
| P2-13 | Admin bootstrap endpoint (single use, constant-time token compare, `admin-cli` client, first admin invitation) so tests and dev can create the first client and user without backdoors | TIO-ADMIN-010, TIO-ADMIN-011, TIO-GEN-004 | ❌ OPEN | — | Full Admin API is Phase 3 |
| P2-14 | Reference login app `examples/login-app/` (static, dependency-free, every interaction state) served through the `ASSETS` binding under `/login/` when `BUNDLED_LOGIN_APP=true`, with default `login_url`/`login_origins`; `not_configured` behavior | TIO-IX-080, TIO-IX-081, TIO-CFG-004, TIO-GEN-001 | ❌ OPEN | — | |
| P2-15 | Interop and e2e: `oauth4webapi` code flow, refresh, PAR, `private_key_jwt`, revocation, userinfo inside workerd; `examples/rp-node` with `openid-client` v6; Playwright passkey sign-up and sign-in on Chromium, Firefox, WebKit via `browserContext.credentials`; RP never touches OP storage | TIO-TEST-033, §13.5 interop and e2e rows | ❌ OPEN | — | CDP virtual authenticator for negative UV cases |
| P2-16 | Concurrency suite for this phase: parallel code exchange, refresh rotation, passkey challenge, invitation, PAR `request_uri`, `/complete` | TIO-TEST-010 (rows 1–5, 7), TIO-RT-003 | ❌ OPEN | — | |
| P2-17 | Phase 2 exit: trace shows §5.4–§5.9, §6.1–§6.3, §6.6, §7 covered; staging deploy exercised for real by nightly | §14.2 | ❌ OPEN | — | Needs OP-01 |

---

## Phase 3 — Admin API

**Goal:** everything an operator needs is an authenticated JSON call, documented by a generated OpenAPI 3.1 file.

**Exit criteria:** §9 identifiers covered; `doc/openapi.json` committed and drift-checked; import benchmark measured on staging.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P3-01 | Admin authorization model (scope `admin`, `aud ∋ ISSUER`, live `admins` membership, service clients), audit of every mutation, secret-free responses, keyset pagination with signed cursors, conflict codes | TIO-ADMIN-001..004 | ❌ OPEN | — | |
| P3-02 | Users endpoints: list/filter, create (D1 claim → DO init → activate), get, patch, disable/enable, delete, passkeys, identities, sessions, refresh families, grants, events (from `audit_hot`, view lands in P6-03), invitations, reindex, export, restore from DO bookmark | §9.4 Users, TIO-DATA-009, TIO-DATA-010, TIO-DATA-026, TIO-DATA-027, TIO-DEPLOY-003, TIO-PRIV-002 | ❌ OPEN | — | `events` row returns 501 until P6-03 |
| P3-03 | Groups endpoints and membership with dual-write reporting (`partial_failure`) | §9.4 Groups, TIO-DATA-011..013 | ❌ OPEN | — | |
| P3-04 | Clients endpoints: CRUD, rotate-secret (immediate), disable/enable, deletion with lazy cleanup test (delete, re-create same id) | §9.4 Clients, TIO-CLIENT-003..005 | ❌ OPEN | — | |
| P3-05 | Upstreams endpoints: CRUD with discovery fetch and validation on create/update, secrets encrypted, `test` endpoint | §9.4 Upstreams, TIO-FED-001, TIO-FED-002 | ❌ OPEN | — | Login flow is Phase 4 |
| P3-06 | Invitations endpoints (create with one-time token and URL, list, get, revoke) | §9.4 Invitations, TIO-REG-002 | ❌ OPEN | — | |
| P3-07 | Keys endpoints (`GET /keys` with derived role, `POST /keys/rotate` with `immediate`, `DELETE /keys/{kid}` with `last_active_key` refusal), settings endpoints, `/stats`, maintenance (`reindex`, `purge`, `rekey`) | §9.4 Keys/Settings/Maintenance, TIO-KEYS-012, TIO-KEYS-013, TIO-CFG-003, TIO-CRYPTO-011 | ❌ OPEN | — | |
| P3-08 | Bulk import `POST /import/users` (NDJSON, idempotent per line, 50 concurrent creations) and `perf/seed.ts`; measure on staging | TIO-ADMIN-020, TIO-ADMIN-021 | ❌ OPEN | — | Target time verified in P7-04 |
| P3-09 | OpenAPI 3.1 generation with `@hono/zod-openapi` (`doc31`), served at `/api/v1/openapi.json`, committed snapshot `doc/openapi.json`, drift check | §5.1, §14.1 | ❌ OPEN | — | |
| P3-10 | `scheduled()` handler: audit purge placeholder, invitation cleanup, `creating` repair, `deleting` completion, key rotation and retirement, rekey chunk, retired-key deletion, `system.cron_run`; tests with `createScheduledController` | TIO-CFG-010, §4.6 | ❌ OPEN | — | |
| P3-11 | Phase 3 exit: trace shows §9 covered | §14.2 | ❌ OPEN | — | |

---

## Phase 4 — Federation

**Goal:** users sign in through Google, Microsoft or any compliant upstream, with the account-resolution policy enforced.

**Exit criteria:** §6.4 identifiers covered; security-suite federation cases green; outbound allow-list test green; Google and Microsoft verified manually and recorded.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P4-01 | Upstream metadata and JWKS caching (1 h, stale-if-error 24 h, single refetch on unknown `kid` per 5 min) | TIO-FED-001, §2.8 | ❌ OPEN | — | |
| P4-02 | Outbound authorization request builder with PKCE, nonce, `tio_fs` state, `extra_authorize_params`, `forward_login_hint`; Interaction API `POST …/upstream/{alias}`; federation leg expiry | TIO-FED-010, TIO-FED-011, TIO-IX-040 | ❌ OPEN | — | |
| P4-03 | `/federation/callback` (GET and POST): state decryption and single-use consumption, binding cookie, upstream `error` handling, code exchange with `client_secret_basic`/`client_secret_post`/`private_key_jwt`, timeouts | TIO-FED-020..022 | ❌ OPEN | — | |
| P4-04 | ID-token validation (jose, every condition a negative test), optional userinfo with `sub` equality, `required_claims`, `claims_map`, `trust_email_verified` boolean rule | TIO-FED-030..033 | ❌ OPEN | — | |
| P4-05 | Account resolution: identity lookup, verified-email `link_required` path with passkey re-authentication by the candidate, auto-create and registration policy, `amr`/`acr`, disabled user; finalization from the callback when ready | TIO-FED-040..043, TIO-IX-031 | ❌ OPEN | — | |
| P4-06 | Unlinking rule in Self-service and Admin (`last_login_method`) | TIO-FED-051, TIO-PK-040 | ❌ OPEN | — | Self-service endpoint lands in P5-03 |
| P4-07 | Fake upstream: `test/support/fake-upstream/` pure module with fault injection, mounted via the outbound interceptor (`@msw/cloudflare`); standalone Worker entry for staging with deploy refusal outside staging; outbound allow-list test across all flows | TIO-TEST-031, TIO-ARCH-016 | ❌ OPEN | — | Deployed to staging by me from this workstation |
| P4-08 | Google and Microsoft (single tenant) verification on staging, recorded in `doc/adr/0001-upstream-verification.md` | §6.4 | ❌ OPEN | — | Needs OP-04 |
| P4-09 | Phase 4 exit: trace shows §6.4 covered | §14.2 | ❌ OPEN | — | |

---

## Phase 5 — Logout and self-service

**Goal:** sessions end everywhere they should, and first-party apps can build security settings screens.

**Exit criteria:** §5.10 and §8 identifiers covered; e2e logout cases green.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P5-01 | RP-initiated logout: hint verification (expiry ignored, retired key fails), `post_logout_redirect_uri` matching, hinted-session revocation, no-hint confirmation interaction, landing URL | TIO-LOGOUT-001..005, TIO-IX-050 | ❌ OPEN | — | |
| P5-02 | Back-channel logout: token delivery in `waitUntil`, queue-based retries with the delay schedule, `logout.backchannel_failed`, triggers from every revocation path (self-service, admin, disable, delete) | TIO-LOGOUT-011..013, TIO-DATA-009 | ❌ OPEN | — | Queue consumer skeleton shared with P6-02 |
| P5-03 | Self-service API `/api/v1/me`: profile, passkeys (with reauthentication rule), sessions, identities, grants; audit actor rules | TIO-ME-001..003, TIO-CONSENT-004, TIO-PK-040, TIO-PK-041 | ❌ OPEN | — | `/me/events` completes in P6-03 |
| P5-04 | E2E: logout with hint, logout confirmation without hint, self-service passkey add with `max_age=0` re-authorization | §13.5 e2e row | ❌ OPEN | — | |
| P5-05 | Phase 5 exit: trace shows §5.10, §8 covered | §14.2 | ❌ OPEN | — | |

---

## Phase 6 — Audit, observability, rate limits, cron

**Goal:** every security-relevant event is durable and queryable; abuse is bounded; the system cleans up after itself.

**Exit criteria:** §6.7, §11, §12.4 identifiers covered; soak test green.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P6-01 | Event catalog (`src/audit/catalog.ts`) with per-type data allow-lists, emitter, redaction; one test per event type; canary-string redaction test across every sink | TIO-AUDIT-001, TIO-AUDIT-002 | ❌ OPEN | — | |
| P6-02 | Queue producer batching in `waitUntil` and consumer writing `audit_hot` (`INSERT OR IGNORE`, batched) and gzip NDJSON to R2 with idempotent keys; ack only after both succeed; send failures never fail requests | TIO-AUDIT-010..012, TIO-DATA-025 | ❌ OPEN | — | |
| P6-03 | Audit query endpoints (`/admin/audit`, `/admin/audit/archive`) and per-user views (`/me/events`, `/admin/users/{id}/events`) from `audit_hot` | §9.4 Audit, TIO-AUDIT-010 | ❌ OPEN | — | Replaces the 501 placeholders from P3-02 and P5-03 |
| P6-04 | Retention: hot-table purge in cron (bounded iterations), invitation and retired-key cleanup already wired, `UserDO` purge windows verified | §4.7, TIO-CFG-010 | ❌ OPEN | — | |
| P6-05 | Rate limiting: `RL_IP` and `RL_CLIENT` bindings with the key table in §6.7, 429 handling, IPv6 /64 keys, fake binding in tests | TIO-RL-001, TIO-RL-003 | ❌ OPEN | — | Per-interaction and per-user limits already in P2-05 and P5-03 |
| P6-06 | Metrics data points (requests and events) when `METRICS` is bound; health `degraded` on D1 failure | TIO-OBS-002, TIO-OBS-003 | ❌ OPEN | — | |
| P6-07 | Soak scenario: 2 h refresh at 100/s on staging, p99 and per-user storage flat | TIO-TEST-052 | ❌ OPEN | — | Needs P7-04 seed |
| P6-08 | Phase 6 exit: trace shows §6.7, §11, §12.4 covered | §14.2 | ❌ OPEN | — | |

---

## Phase 7 — Hardening and release

**Goal:** every identifier covered, conformance and load gates green, `v1.0.0` in production.

**Exit criteria:** trace reports zero uncovered ids; conformance results archived; load thresholds green; runbook and guide written; `v1.0.0` tagged and deployed.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P7-01 | Complete the security suite (every bullet in §13.7), including header and CORS matrices, enumeration equality, size limits, injection spies | TIO-TEST-020 | ❌ OPEN | — | Many cases land earlier; this closes the list |
| P7-02 | Complete the concurrency suite (remaining rows: federation state, verified-email user creation, identity link, bootstrap, first key) | TIO-TEST-010 | ❌ OPEN | — | |
| P7-03 | Conformance: `conformance/` docker compose, plan configs (config, basic with three client-auth variants, RP-initiated logout, back-channel logout), `waivers.json`, browser automation through the reference login app and the staging fake upstream; nightly job and archived results | TIO-TEST-040, TIO-TEST-041 | ❌ OPEN | — | Needs OP-01, OP-03 |
| P7-04 | Load: seed 1,000,000 users on staging via import (benchmark), harvest 100,000 refresh tokens over HTTP, k6 scenarios with §2.7 thresholds, D1 write-rate assertion | TIO-TEST-050, TIO-TEST-051, TIO-PERF-001, TIO-PERF-002, TIO-ADMIN-021 | ❌ OPEN | — | |
| P7-05 | Documents: `doc/RUNBOOK.md` (bootstrap, key rotation, master-key rotation, emergency retirement, secret rotation, recovery, D1 restore, reindex, lost `MASTER_KEYS`), `doc/LOGIN_APP_GUIDE.md`, `doc/adr/` for decisions made during the build, threat-model review sign-off | TIO-DEPLOY-004, TIO-SEC-001, TIO-GEN-005 | ❌ OPEN | — | |
| P7-06 | Release: create the `production` branch, Workers Builds production Worker (OP-02), `deploy.ts` versions upload + smoke + deploy exercised, `v1.0.0` tag, README status updated | TIO-DEPLOY-006, TIO-DEPLOY-010 | ❌ OPEN | — | |
| P7-07 | Mutation-testing baseline in nightly (report only) | §13.1 | ❌ OPEN | — | Non-blocking by decision |
| P7-08 | Phase 7 exit: zero uncovered ids, all nightly gates green, production live | §14.2 | ❌ OPEN | — | |

---

## Operator tasks (repository owner)

| ID | Task | When | Status | Commit | Notes |
|---|---|---|---|---|---|
| OP-01 | Connect the repository to Cloudflare Workers Builds for staging: Worker `tiny-oidc-staging`, branch `main`, build `pnpm run build`, deploy `pnpm run deploy`, build variables `TIO_ENV`, `TIO_ISSUER`, `TIO_RP_ID`, `TIO_RP_NAME` | After P0-14 | ❌ OPEN | — | Values are in the private notes, never in this repo |
| OP-02 | Connect Workers Builds for production: Worker `tiny-oidc`, branch `production`, same commands, production build variables | Before P7-06 | ❌ OPEN | — | |
| OP-03 | Review and merge the infrastructure-repository change attaching the five custom hostnames to the staging and production Workers | After OP-01 and the staging fixtures exist (P4-07) | ❌ OPEN | — | PR opened by the implementing agent in the private infra repo |
| OP-04 | Create a Google OAuth client and a Microsoft Entra app registration for staging with the staging callback URL; hand over ids and secrets outside the repo | Before P4-08 | ❌ OPEN | — | |
| OP-05 | Confirm or change the assumed defaults: no DO jurisdiction, `registration.mode` `open` on staging and `invite` on production, metrics enabled, no R2 lifecycle rule | Any time before P7-06 | ❌ OPEN | — | Defaults are applied until changed |

---

## Backlog (deferred beyond v1)

| ID | Item | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| B-01 | DPoP sender-constrained tokens (RFC 9449) | Appendix B | ⏯️ DEFERRED | — | Re-evaluate when a resource server requires sender constraining |
| B-02 | Apple Sign-in upstream (JWT client secret, cross-site `form_post` callback) | Appendix B | ⏯️ DEFERRED | — | Blocked by the `SameSite=Lax` binding cookie model |
| B-03 | RFC 8707 resource indicators (per-request audience) | Appendix B #29 | ⏯️ DEFERRED | — | Static `audiences` covers v1 |
| B-04 | Self-service identity linking (`link` interaction, `/me/identities/link`) | Appendix B #30 | ⏯️ DEFERRED | — | Login-time linking covers v1 |
| B-05 | Configuration as code (`PUT /admin/config`) | Appendix B #33 | ⏯️ DEFERRED | — | CRUD + `client_credentials` covers automation |
| B-06 | `jti` replay cache for `private_key_jwt` | Appendix B #28 | ⏯️ DEFERRED | — | Only if a profile such as FAPI is targeted |
| B-07 | EdDSA as a signing option; pairwise subject identifiers; device authorization grant; token exchange; outbound webhooks; SCIM server; D1 directory sharding beyond ~5,000,000 users | §1.5 | ⏯️ DEFERRED | — | Post-1.0 candidates |

---

## Plan change log

| Date | Change |
|---|---|
| 2026-09-19 | Plan created from spec §14.2 after the reference review; Phase S recorded as done; all implementation tasks `❌ OPEN`. |
| 2026-09-19 | Recorded the plan's own commit hash in S-04. |
| 2026-09-19 | P0-01 and P0-02 implemented (scaffold, toolchain, migration 0001, `resetStorage`); marked in progress until CI (P0-03) runs them. |
| 2026-09-19 | P0-04 (trace tool, phase allow-list, `doc/TRACEABILITY.md`) and P0-05 (lint rules, ignore count, config, neutrality and bundle checks) implemented with unit tests; in progress until CI runs them. |
| 2026-09-19 | P0-03 (workflows), P0-06 (env, config, settings loader), P0-07 (crypto: random, hash, master keys, envelope, uuid) implemented with tests; `test/support/clock.ts` and `keys.ts` from P0-13. |
| 2026-09-19 | P0-08 (D1 wrapper, settings repository) and P0-09 (UserDO schema, guards, purge; InteractionDO document, alarm, transitions) implemented with tests. |
| 2026-09-19 | P0-10 (router skeleton: request id, startup config, host check, limits, security headers, CORS, JSON errors, log line, metrics, health, OpenAPI) implemented with tests. |
| 2026-09-19 | P0-11 (generated `doc/CONFIG.md`, `.dev.vars.example`, `doc/openapi.json`, `gen-secrets`) implemented with tests. |
| 2026-09-19 | P0-12 (deploy and smoke scripts with a fake wrangler) and P0-13 (clock, keys, factories, outbound guard) implemented. Spec draft.2: `fetchMock` replaced by `@msw/cloudflare` in TIO-ARCH-016, TIO-TEST-031 and §13.1; dev dependency list in §14.1 extended. |
| 2026-09-19 | Phase 0 complete: P0-01..P0-14 done; e2e smoke suite with Playwright `webServer` starting `wrangler dev`; README status updated. Chromium for Playwright had to be installed by hand on the workstation (Node's downloader times out against the CDN; curl works). |
