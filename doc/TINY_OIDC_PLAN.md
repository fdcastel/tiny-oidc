# Tiny OIDC — Implementation Plan (living document)

| | |
|---|---|
| **Source of truth for behavior** | [TINY_OIDC_SPEC.md](TINY_OIDC_SPEC.md) (283 requirement ids). This plan says *when* and *in what order*; the spec says *what*. |
| **Last updated** | 2026-09-19 |
| **Current focus** | `P3-05` (upstreams endpoints); `P2-17` waits on OP-01. |
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

## Phase 1 — Keys and discovery (complete)

**Goal:** the OP can publish JWKS and discovery and can sign and verify its own tokens.

**Exit criteria:** §5.2, §5.3 and §10 identifiers covered; `GET /.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/.well-known/jwks.json`, `/.well-known/webauthn` served with correct caching.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P1-01 | Key store: `src/crypto/keystore.ts` generating ES256 keys, exporting the JWK once, encrypting `private_jwk_enc` under the keystore key, importing non-extractable at runtime; `kid` = RFC 7638 thumbprint; first-key bootstrap guarded by `INSERT ... WHERE NOT EXISTS` | TIO-KEYS-010, TIO-KEYS-011, TIO-KEYS-014 | ✅ DONE | add37f6 | |. `src/crypto/secretbox.ts` seals private JWKs (and, later, upstream secrets) under the keystore key with the master-key version in the blob |
| P1-02 | Key roles derived from `activates_at`/`retired_at`; rotation creates (with `immediate`), cron retires superseded keys after `retire_after_seconds`, deletes retired rows after 90 days; fail closed when no active key; three-key lifetime test with the injected clock | TIO-KEYS-012, TIO-KEYS-013, TIO-CFG-010 (key steps) | ✅ DONE | add37f6 | Admin endpoints for keys arrive in P3-07. `maintainSigningKeys()` is the cron body; `scheduled()` wires it in P3-10. Key cache TTL is 60 s (spec §2.8 said 5 min; TIO-ARCH-011 wins and §2.8 was aligned). Same-second ties between active keys resolve to the newest row, then the greater kid |
| P1-03 | JWKS endpoint publishing every unretired key, no `d` member under any state, `Cache-Control: public, max-age=300`, served through `caches.default` | TIO-KEYS-001, TIO-KEYS-002 | ✅ DONE | add37f6 | |. Served through `caches.default`; cache hits are copied so the header middleware can decorate them |
| P1-04 | `src/oidc/capabilities.ts` constant; discovery documents for both well-known paths; deep-equality test against the constant; route-table comparison test; `/.well-known/webauthn` from `webauthn_origins` with the 5-label validation | TIO-DISC-001..004, TIO-PK-001 | ✅ DONE | add37f6 | Validators import the same constant in Phase 2. The protocol endpoints (`/authorize`, `/par`, `/token`, `/userinfo`, `/revoke`, `/logout`, `/federation/callback`, `/interactions/{id}/complete`) are in the route table now with a 501 `not_implemented` handler until Phase 2, so the discovery-vs-route-table test holds |
| P1-05 | JWT service (`src/crypto/jwt.ts` over jose): sign with header `alg`/`typ`/`kid` only and a 512-byte header test; verify own tokens against unretired keys with `iss`, `exp` (0 s leeway), `typ`; ID token builder (claims table, null omission, `at_hash`); `at+jwt` builder with `aud` from `audiences`; logout token builder | TIO-KEYS-015, TIO-TOKEN-030..034, TIO-LOGOUT-010 | ✅ DONE | add37f6 | |. Header sizes pinned at 106/110/115 bytes for JWT, at+jwt and logout+jwt; `ignoreExpiry` re-verifies an expired hint with the clock set to its `iat` |
| P1-06 | Master-key rotation: re-encrypt keystore rows under the active version in cron chunks; handles under retired versions rejected; three-phase test | TIO-CRYPTO-011, TIO-ARCH-008 | ✅ DONE | add37f6 | `POST /maintenance/rekey` endpoint in P3-07. `rekeySigningKeys(db, keys, limit)`; rows sealed under a version no longer in the secret are reported as unrecoverable, never modified |
| P1-07 | Phase 1 exit: trace shows §5.2, §5.3, §10 covered | §14.2 | ✅ DONE | 353b088 | |. `trace.config.json` phase = 1; 59 identifiers covered |

---

## Phase 2 — Core flow with passkeys

**Goal:** a standard OIDC client signs a user in with a passkey through the reference login app, end to end, on local `wrangler dev`.

**Exit criteria:** §5.4–§5.9, §6.1–§6.3, §6.6, §7 identifiers covered; `oauth4webapi` interop green; concurrency suite green for code, refresh, challenge, invitation, PAR and complete; Playwright passkey sign-up and sign-in green on Chromium.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P2-01 | Clients: repository, validation rules (redirect URI rules incl. loopback exception, grant/auth-method combinations, `audiences`, TTL bounds), secret generation and hashing, isolate cache with stale-if-error, disable semantics | TIO-CLIENT-001..004, TIO-CLIENT-010, TIO-CLIENT-011, TIO-ARCH-011 | ✅ DONE | 9526bdb | Phase 2 factories create clients through the OP's service layer (`src/oidc/clients.ts` + repository), the same functions the Admin API calls in P3-04, never raw SQL; TIO-TEST-032 is read that way until the Admin API exists. Validation, repository, cache and `createClient` done with tests; the disable semantics at `/token`, `/par` and refresh land with those endpoints. Spec TIO-DATA-003 reworded: generated ids use `[a-z0-9]` because base64url violates the lowercase pattern. Disable semantics at `/par`, `/token` (every grant) and refresh done at the Phase 2 exit (P2-17): the refresh grant of a disabled client revokes the family it presents (`client_disabled`) and answers `invalid_grant`, so the family stays dead after re-enabling; the rest is `invalid_client` |
| P2-02 | Client authentication for `/token`, `/par`, `/revoke`: `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt` (jose against `jwks`/`jwks_uri`, 60-second assertion window with mandatory `iat`); strict method enforcement; failed-auth rate-limit keys | TIO-TOKEN-002, TIO-TOKEN-003, TIO-TOKEN-004 | ✅ DONE | 83ffbb1 | No replay cache by decision (Appendix B #28). `src/oidc/client-auth.ts` (`authenticateClient`, pure over a parsed form and the `Authorization` header), `src/oidc/jwks-cache.ts` (jose remote sets, LRU 100, unknown-`kid` refetches spaced by a 30 s cooldown) and `src/router/form.ts` (TIO-TOKEN-001 content type and duplicates). The failure result carries the client id for the TIO-TOKEN-004 limiter key; the limiter call and `WWW-Authenticate` are wired at the endpoints (P2-10, P2-04, P2-11) with the binding of P6-05 |
| P2-03 | `/authorize` validation pipeline in spec order, non-redirectable errors to `login_url`, redirectable errors with `iss`, `prompt`/`max_age`/`login_hint` handling, session evaluation, stale-parameter rule, `prompt=none` never touching the session, `allowed_groups` outcome | TIO-AUTHZ-001..024 (013 withdrawn) | ✅ DONE | 1a0ee7b | Depends on P2-08 for `authorizeWithSession`. `src/oidc/authorize.ts` (steps 5–12, shared with `/par`), `src/oidc/authorize-endpoint.ts` (steps 1–4 and 14), `src/oidc/handles.ts` (session, code and binding handles), `src/router/cookies.ts`, `src/oidc/interactions.ts`. A pushed request is taken with `InteractionDO.claimPushed` (exactly one taker, client-bound, fresh binding and TTL) before the session is evaluated, so two `/authorize` calls on one `request_uri` cannot both issue a code. The second TIO-AUTHZ-024 test (`prompt=login` interaction, then a bare `/authorize` on the new session is a hit) lands with `/complete` in P2-09. 19 HTTP tests |
| P2-04 | PAR endpoint: client auth, validation reuse, `request_uri` single use and 60 s expiry stored in `InteractionDO`, `require_par` enforcement | TIO-PAR-001..004 | ✅ DONE | 9f6f437 | `src/oidc/par-endpoint.ts` and `src/oidc/token-common.ts` (form + client authentication shared with `/token` and `/revoke`). `src/router/rate-limit.ts` started here for TIO-PAR-004/TIO-TOKEN-004: the §6.7 key table over the two bindings. Spec conflict for P6-05: §6.7 lists different limits per key class (20/60 s failed auth, 60/60 s navigation, 600/60 s admin) but §12.1 declares only two `simple` bindings, which carry one limit each; until the bindings are split, every class on a binding shares its limit |
| P2-05 | Interaction API: origin and binding-cookie checks, `GET` document (masking, field allow-list test), state machine table test, attempt counter, `abort`, consent endpoint and grant storage, logout interaction confirm | TIO-IX-001..003, TIO-IX-010, TIO-IX-011, TIO-IX-020, TIO-IX-021, TIO-IX-040, TIO-IX-041, TIO-IX-050, TIO-IX-070, TIO-CONSENT-001..004, TIO-RL-002 | ✅ DONE | b7a0ff9 | Federation endpoint arrives in P4-02. `src/interaction/api.ts`: guard (id shape, origin or same-site GET, binding cookie, pushed and terminal rules), GET document, `consent`, `abort`; `InteractionDO.patch` and `attempt` (the call past the limit fails the interaction, TIO-RL-002); `interactions` CORS class in `headers.ts`; OpenAPI definitions for the JSON API routes (`registerPath`, plain handlers, JSON bodies through `readJsonBody`). Error statuses: 403 origin/binding/too_many_attempts, 404 not found, 409 invalid state, 401 passkey codes. TIO-IX-011 and TIO-IX-070 covered by the `passkey/verify` tests of P2-06; `logout` confirm is Phase 5 (TIO-IX-050, P5-01). TIO-ARCH-010 (API surface enumeration) and TIO-IX-010 citations added at the Phase 2 exit |
| P2-06 | Passkeys: registration and authentication options, verification via `@simplewebauthn/server` inside `UserDO.verifyAssertion` (atomic counter), counter policy, `credProps.rk` rule, `userHandle` routing with `passkey_index` fallback, limits and naming; `test/support/virtual-authenticator.ts` with fault injection, itself verified with the library | TIO-PK-002, TIO-PK-010..014, TIO-PK-020..023, TIO-PK-030, TIO-PK-040, TIO-PK-041, TIO-IX-030, TIO-TEST-030 | ✅ DONE | b37af2f | Options, registration and assertion verification (`src/auth/passkey.ts`), `UserDO.verifyAssertion` and the virtual authenticator (ES256, EdDSA, RS256, packed self-attestation, fault injection) done with 12 unit and 3 component tests; `@simplewebauthn/server` runs in workerd without `nodejs_compat`. Attestation statements of other formats are stripped to `none` before verification (TIO-PK-012, `attestation_policy = ignore`). Only §7.8 error codes are used: an unsupported algorithm or a bad credential id length is `passkey_verification_failed` with a log-only `reason`. `userHandle` routing with the `passkey_index` fallback (orphan rows deleted on discovery, TIO-DATA-026), `passkey/options` and `passkey/verify` on the Interaction API (`src/interaction/passkey.ts`), `src/users/create.ts` (§4.6 creation order), `src/users/passkeys.ts` (DO then index, rollback), `src/db/users.ts`, `src/db/groups.ts` and `test/support/{http,passkeys,sessions}.ts` done. TIO-PK-040 (last passkey) is Phase 5 (self-service); TIO-PK-041 (names) done in P2-07 |
| P2-07 | Registration policy and invitations: `register`/`recover` invitations as `tio_iv` handles, atomic consumption, pre-filled fields, `email_in_use` hint, recovery always revoking sessions and families; Interaction API register endpoints | TIO-REG-001..005, TIO-IX-032, TIO-REC-001 | ✅ DONE | cafb69c | `src/db/invitations.ts`, `src/users/invitations.ts` (`createInvitation` mints the `tio_iv` handle; `openInvitation` tells invalid, used and expired apart), `src/interaction/register.ts`. The interaction document gained a `registration` section (the draft account: email, verified flag, display name, groups) alongside `passkey_challenge.pending_uid`/`invitation_id`, since the verify body carries only the WebAuthn response and a name. A credential already indexed is refused before the invitation is consumed; an invitation consumed for a ceremony that then fails to create the account stays consumed (TIO-IX-032, by design). Admin creation of invitations is P3-04; the bootstrap invitation is P2-13 |
| P2-08 | `UserDO` core: sessions (create, rotate, touch, expire, revoke with family cascade), `authorizeWithSession`, `issueCode`, `exchangeCode` (atomic, PKCE, replay revokes families), refresh families and `rotateRefreshToken` (reuse detection, serial check, idle/absolute, session binding), grants with `client_created_at`, purge | TIO-SESS-001..006, TIO-TOKEN-010..014, TIO-RT-001..010, TIO-CLIENT-005, TIO-AUTHZ-022, TIO-AUTHZ-023 | ✅ DONE | deefbb9 | Largest task; split into sub-commits by table. Core done with 25 component and 2 concurrency tests. `refresh_families.code_secret_hash` added to §4.2 so TIO-TOKEN-012 can revoke the families a replayed code created; `setDisabled()` added early because the disabled-user checks needed it; session ids are generated by the caller (UUID v7 from the Clock). Completed by the endpoints of P2-09..P2-11 and the concurrency suite of P2-16 |
| P2-09 | `/interactions/{id}/complete`: binding check, session creation or rotation, code issuance, cookie handling, error redirect, resume and already-completed cases, revoked-session case | TIO-IX-033, TIO-IX-060..062 | ✅ DONE | 0447b9a | `src/interaction/complete.ts`; `src/obs/request-meta.ts` (ip hash under `tio/v1/iphash`, `Family/major` user agent, `cf.country`). Consent-only interactions issue the code on the session whose cookie the browser still presents (re-verified at `/complete`, as TIO-IX-050 does for logout); a missing or revoked session restarts the interaction as `login_required` (TIO-IX-062). Same-user re-authentication rotates the session; a rotation target that vanished is replaced. The code binds the consented scopes. Second TIO-AUTHZ-024 test lives here |
| P2-10 | `/token` endpoint: form parsing and limits, grants `authorization_code`, `refresh_token`, `client_credentials`, response shape, storage error mapping, scope rules including `admin` membership check | TIO-TOKEN-001, TIO-TOKEN-005, TIO-TOKEN-020, TIO-TOKEN-021, TIO-SCOPE-001, TIO-SCOPE-002, TIO-ARCH-014, TIO-ARCH-015 | ✅ DONE | 7d9779f | `src/oidc/token-endpoint.ts`. The family kind is decided inside `UserDO.exchangeCode` from the code's scope and the client's `offline_access` flag (TIO-TOKEN-014), so the endpoint passes `offline_allowed`; `/authorize` refuses `offline_access` for clients without the flag. `UserContext.sid` is nullable: offline families carry no `sid` in either token. TIO-SCOPE-002 enforced at passkey verification, session hit, code issuance, exchange and refresh (`UserDO.adminAllowed`); `UserDO.setGroups` added. 9 HTTP tests through the full login flow |
| P2-11 | `/userinfo` (GET and POST, fresh profile from `UserDO`, scope-gated claims) and `/revoke` (family revocation, foreign-token no-op, access-token session-family case) | TIO-UINFO-001..003, TIO-REV-001..003 | ✅ DONE | b2bd4f8 | `src/oidc/bearer.ts` (bearer extraction and `verifyAccessToken`, reused by the Self-service and Admin APIs with `acceptClient = false`), `userinfo-endpoint.ts`, `revoke-endpoint.ts`. A token whose `aud` is only the client's `audiences` is refused at `/userinfo` (TIO-TOKEN-033/034); the `account` scope adds the issuer. Client tokens (no `auth_time`) are 401. `token.revoke` / `token.revoke_foreign` are log lines until the audit pipeline (P6) |
| P2-12 | Groups: `groups` claim from `UserDO`, `allowed_groups` enforcement at authorization and refresh, `admins` system group bootstrap | TIO-DATA-011..013, TIO-AUTHZ-017, TIO-SCOPE-002 | ✅ DONE | f2ff0e9 | Group CRUD endpoints in P3-03. `src/db/groups.ts` (system groups refuse rename and delete), `src/users/groups.ts` (`ensureAdminsGroup`, `setUserGroups`: DO first, then the mirror; `partial_failure` on a failed mirror write), `UserDO.setGroups`. `allowed_groups` and admin-membership enforcement landed with P2-03, P2-06 and P2-10 |
| P2-13 | Admin bootstrap endpoint (single use, constant-time token compare, `admin-cli` client, first admin invitation) so tests and dev can create the first client and user without backdoors | TIO-ADMIN-010, TIO-ADMIN-011, TIO-GEN-004 | ✅ DONE | f2ff0e9 | `src/admin/bootstrap.ts`; the response carries the raw invitation token besides `invitation_url` (null without `login_url`) so a deployment can be bootstrapped before the login app is configured; an `admin-cli` client left by an interrupted attempt is reused. The bootstrap→register→admin-scope flow is tested end to end. Full Admin API is Phase 3 |
| P2-14 | Reference login app `examples/login-app/` (static, dependency-free, every interaction state) served through the `ASSETS` binding under `/login/` when `BUNDLED_LOGIN_APP=true`, with default `login_url`/`login_origins`; `not_configured` behavior | TIO-IX-080, TIO-IX-081, TIO-CFG-004, TIO-GEN-001 | ✅ DONE | 9147917 | `examples/login-app/{index.html,app.js,style.css}` (every state: sign-in, sign-up with invitation, consent, link, logout, ready/failed/completed, non-redirectable errors; WebAuthn JSON fallbacks for browsers without the `*FromJSON` statics; a bootstrap invitation link parks the token in `sessionStorage` until an interaction arrives). `src/router/login-app.ts` serves the binding under `/login/*` (path rewritten to the assets root) with a same-origin CSP and no WebAuthn denial; `doc/LOGIN_APP_GUIDE.md` written. Browser-driven coverage of the app comes with the P2-15 e2e suite |
| P2-15 | Interop and e2e: `oauth4webapi` code flow, refresh, PAR, `private_key_jwt`, revocation, userinfo inside workerd; `examples/rp-node` with `openid-client` v6; Playwright passkey sign-up and sign-in on Chromium, Firefox, WebKit via `browserContext.credentials`; RP never touches OP storage | TIO-TEST-033, §13.5 interop and e2e rows | ✅ DONE | 861de99 | CDP virtual authenticator for negative UV cases. `test/interop/oauth4webapi.test.ts` (discovery, PKCE code flow with JWKS signature validation, userinfo, refresh, revocation, PAR with `private_key_jwt`, `client_credentials` with `client_secret_basic`) runs on the real clock because the library stamps assertions itself. `examples/rp-node/server.ts` (openid-client v6, JSON responses) is Playwright's second web server; `scripts/e2e-server.ts` starts `wrangler dev` on `http://localhost:8787` with a fresh `--persist-to` directory, migrations and `registration.mode = open` written by `wrangler d1 execute` (an operator action, no test-only OP code), and overrides `ISSUER`/`RP_ID` with `--var` because browsers do not accept an IP literal as RP ID. Playwright has no `browserContext.credentials` API: Chromium uses the real WebAuthn stack through the CDP virtual authenticator (credentials exported and re-added across contexts); Firefox and WebKit get a page-side shim (`test/e2e/support/webauthn-shim.ts`) that hands ceremonies to the software authenticator over `exposeFunction`, so the OP still verifies real signatures. Bootstrap runs once per run in a Playwright global setup; 7 e2e tests green on Chromium and Firefox locally (Firefox unpacked by hand like Chromium); WebKit not installed on this workstation |
| P2-16 | Concurrency suite for this phase: parallel code exchange, refresh rotation, passkey challenge, invitation, PAR `request_uri`, `/complete` | TIO-TEST-010 (rows 1–5, 7), TIO-RT-003 | ✅ DONE | effe958 | `test/concurrency/http.test.ts`. Spec conflict: TIO-TEST-010 row 3 races 20 passkey verifications while §7.4 caps attempts at 10, so the losers see 401/403/409 and the interaction may end `failed`; the test asserts one winner and one counter move. Finding: `InteractionDO` read-check-writes (`claimPushed`, `claimCompletion`, `apply`, `attempt`) were not exactly-once without input gates (the vitest runtime); every write now runs under `blockConcurrencyWhile`. `/complete` gained a `completing` claim (TIO-IX-061). |
| P2-17 | Phase 2 exit: trace shows §5.4–§5.9, §6.1–§6.3, §6.6, §7 covered; staging deploy exercised for real by nightly | §14.2 | 🔧 IN PROGRESS | 68e6e86 | `scripts/trace.config.json` phase = 2 (0 errors). Exit criteria met locally and in CI: trace, oauth4webapi interop, concurrency suite, Playwright on Chromium. Seven Phase 2 identifiers had no citing test and got one here: TIO-ARCH-002 (lint rule `do-addressed-by-entity-id` + real-tree test; `userStub` is now the only user addressing), TIO-ARCH-009 (`test/http/forged-handles.test.ts`), TIO-ARCH-010 (surface enumeration + claim probe), TIO-CLIENT-002, TIO-PK-011, TIO-IX-010 (citations), TIO-TEST-032 (lint rule `factories-through-public-apis`). TIO-CLIENT-004 gained its HTTP test and the lazy family revocation. Remaining: the staging nightly needs OP-01 (owner) |

---

## Phase 3 — Admin API

**Goal:** everything an operator needs is an authenticated JSON call, documented by a generated OpenAPI 3.1 file.

**Exit criteria:** §9 identifiers covered; `doc/openapi.json` committed and drift-checked; import benchmark measured on staging.

| ID | Task | Spec | Status | Commit | Notes |
|---|---|---|---|---|---|
| P3-01 | Admin authorization model (scope `admin`, `aud ∋ ISSUER`, live `admins` membership, service clients), audit of every mutation, secret-free responses, keyset pagination with signed cursors, conflict codes | TIO-ADMIN-001..004 | ✅ DONE | 3b8aac4 | `src/admin/auth.ts` `requireAdmin` (401 `invalid_token` / 403 `insufficient_scope` with `WWW-Authenticate`, 429 per token jti, 503 on storage failure; a user's membership read from `UserDO.getProfile` every request, a service client's record from the cache); `src/audit/events.ts` `Auditor` (per-request §11.1 events, flushed to the log at request end; queue producer is P6-02) and `src/audit/diff.ts` `boundedDiff` (secret fields as `{changed: true}`); `src/admin/pagination.ts` (HMAC cursors under `tio/v1/cursor`, listing-bound, 1 h); `GET /admin/users` built here as the vehicle (`src/db/users.ts` `listUsersStatement`, row-value keyset on `users_created`; 10,000-row test asserts the plan and `rows_read ≤ limit + 1`). Conflict codes land with their endpoints. `test/support/admin.ts` obtains admin tokens through real logins |
| P3-02 | Users endpoints: list/filter, create (D1 claim → DO init → activate), get, patch, disable/enable, delete, passkeys, identities, sessions, refresh families, grants, events (from `audit_hot`, view lands in P6-03), invitations, reindex, export, restore from DO bookmark | §9.4 Users, TIO-DATA-009, TIO-DATA-010, TIO-DATA-026, TIO-DATA-027, TIO-DEPLOY-003, TIO-PRIV-002 | ✅ DONE | 4204c13 | `GET /users` (filters, paging) done in P3-01; `events` answers 501 until P6-03. 24 routes in `src/admin/users.ts` over `src/users/admin.ts` (profile update, disable/enable, delete, reindex) and new `UserDO` methods (`updateProfile`, `listFamilies`, `revokeFamiliesOfClient`, `counts`, `exportState`, `restore`, `grantClientIds`); `createUser` links identities at creation (`identity_index` claims). `partial_failure` is a boolean on the 200 body and the audit event's `reason`. Restore: the local Durable Object backend has no point-in-time recovery, so the success path (bookmark applied, object aborted in `waitUntil`) carries the first two istanbul ignores (2/15); the 503 `restore_unavailable` path is tested. Back-channel logout on disable/delete is Phase 5. Recovery invitations done here (P3-06 keeps the register ones) |
| P3-03 | Groups endpoints and membership with dual-write reporting (`partial_failure`) | §9.4 Groups, TIO-DATA-011..013 | ✅ DONE | 135ecc5 | `src/admin/groups.ts`, `src/users/groups.ts` (`addMembership`, `removeMembership`, `propagateToMembers`), migration `0002_groups_created.sql` (keyset index). Decisions: a rename or deletion first rewrites the group list in every member's object (concurrency 20, at most 1,000 members per call, else 409 `group_too_large`; `propagation.failed` lists members to retry) because the objects are authoritative for the `groups` claim; a rename pre-checks the new name and reverts the propagation on a late collision. Spec gap: §11.2 has no `group.*` events, so `group.created`, `group.updated` and `group.deleted` are emitted and must join the P6-01 catalog. The admin rate limit is keyed by the whole `jti` (a UUID v7 prefix is its timestamp, shared by tokens minted in the same millisecond) — §6.7 says "jti prefix". Fault injection for the admin suites is `test/http/faults.ts` (`brokenD1`, `failingD1`, `brokenDoFor`, `sabotageDo`) |
| P3-04 | Clients endpoints: CRUD, rotate-secret (immediate), disable/enable, deletion with lazy cleanup test (delete, re-create same id) | §9.4 Clients, TIO-CLIENT-003..005 | ✅ DONE | 3a693ff | `src/admin/clients.ts`; `updateClientRecord` in `src/oidc/clients.ts` lays the patch over the stored record and validates the whole (schema defaults never replace stored values); a switch to a secret method mints a secret returned once, a switch away drops the hash; `rotate-secret` on a secretless client is 409 `no_secret`. Listing walks `clients_created` (migration `0003_clients_created.sql`); a row that no longer decodes still counts for paging but is not shown. `publicClient` moved to `src/oidc/clients.ts`. The lazy-cleanup test (`test/http/admin-clients.test.ts`, TIO-CLIENT-005) deletes and re-creates a client under the same id and asserts the old family is `invalid_grant` and a session hit asks for consent again |
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
| OP-01 | Connect the repository to Cloudflare Workers Builds for staging: Worker `tiny-oidc-staging`, branch `main`, build `pnpm run build`, deploy `pnpm run deploy`, build variables `TIO_ENV`, `TIO_ISSUER`, `TIO_RP_ID`, `TIO_RP_NAME` | After P0-14 | 🔧 IN PROGRESS | — | Values are in the private notes, never in this repo. Requested from the owner on 2026-09-19 (mobile notification) after Phase 0 went green; not blocking Phase 1 |
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
| 2026-09-19 | First CI run green on `main` (e561660). OP-01 requested from the owner. |
| 2026-09-19 | Phase 1 complete (P1-01..P1-07): key store, roles, rotation, JWKS, discovery, capabilities, JWT service, token builders, master-key rotation. Spec §2.8 key cache aligned to 60 s per TIO-ARCH-011. Smoke test now checks discovery, JWKS and health. |
| 2026-09-19 | P2-01 client model: TIO-DATA-003 reworded (generated client ids `c_` + 22 chars of `[a-z0-9]`, since base64url contradicts the lowercase pattern). |
| 2026-09-19 | P2-08 UserDO core: sessions, codes, refresh families with reuse detection, grants, passkey and identity storage. Spec §4.2 amended with `refresh_families.code_secret_hash` (TIO-TOKEN-012). |
| 2026-09-19 | P2-06 passkey ceremonies, virtual authenticator and `UserDO.verifyAssertion`; P2-01 and P2-08 commit hashes recorded. Plan title line restored (a scripted edit had mangled it since 75ff0c2; rows were intact). |
| 2026-09-19 | P2-02 client authentication (four methods, `private_key_jwt` against `jwks`/`jwks_uri`) with 11 component tests. |
| 2026-09-19 | P2-03 `/authorize`: validation pipeline, session evaluation, interaction start, PAR consumption. `InteractionDO` sections typed concretely (§4.3) so documents cross the RPC boundary; `par_consumed` flag and `claimPushed` added for single-use `request_uri`. |
| 2026-09-19 | P2-04 `/par` with the shared form/client-auth helpers and the first rate-limit keys; §6.7 vs §12.1 rate-limit binding conflict recorded for P6-05. |
| 2026-09-19 | P2-05 Interaction API guard, document, consent and abort (14 HTTP tests); `test/support/sessions.ts` shared session fixture. |
| 2026-09-19 | P2-06 passkey sign-in on the Interaction API (options, verify, routing, attempts, access_denied outcomes) with the user-creation and passkey-registration services (§4.6) and the `users`, `passkey_index` and `groups` repositories. TIO-IX-011 and TIO-IX-070 of P2-05 covered. |
| 2026-09-19 | P2-09 `/interactions/{id}/complete` with 9 HTTP tests; full passkey login flow now runs end to end through HTTP (authorize → interaction → passkey → complete → code exchange in the DO). |
| 2026-09-19 | P2-10 `/token` (three grants, tokens verified against the served JWKS in tests); admin-scope membership enforced at every point of TIO-SCOPE-002. |
| 2026-09-19 | P2-11 `/userinfo` and `/revoke` with 5 HTTP tests. |
| 2026-09-19 | P2-07 registration policy, invitations and the `register/options` + `register/verify` endpoints (9 HTTP tests incl. the invitation race). P2-06 TIO-PK-041 (names) done here. |
| 2026-09-19 | P2-12 groups service and repository rules; P2-13 bootstrap endpoint (6 HTTP tests incl. the full bootstrap→registration→admin token flow). Workers test timeout raised to 30 s because rate-limit tests exhaust a binding under parallel load. |
| 2026-09-19 | P2-14 reference login app, `/login/*` serving and `doc/LOGIN_APP_GUIDE.md`. |
| 2026-09-19 | P2-15 interop (oauth4webapi) and e2e (Playwright, openid-client RP, real browsers with passkeys) suites; `test/support/virtual-authenticator.ts` types made portable to the Node type set so the e2e suite can reuse it. |
| 2026-09-19 | P2-16 concurrency suite over HTTP (6 races). `InteractionDO` writes serialized with `blockConcurrencyWhile`; `/complete` claims the interaction before minting the code. Conflict recorded on the row: 20 parallel passkey verifications vs the 10-attempt limit. |
| 2026-09-19 | Phase 2 exit (P2-17): trace phase 2, seven uncited identifiers given tests, TIO-CLIENT-004 lazy family revocation, P2-01/P2-05/P2-06/P2-08 closed. Phase 3 starts while the staging nightly waits on OP-01 (independent of it). |
| 2026-09-19 | P3-01 admin authorization, audit emitter and diff, keyset cursors, `GET /admin/users`; the Admin API guard runs for every path under the prefix except bootstrap. |
| 2026-09-19 | P3-02 users endpoints (create, get, patch, disable/enable, delete, passkeys, identities, sessions, refresh families, grants, recovery invitations, reindex, export, restore). Vanishing-object tests use a per-user sabotaging `USER_DO` proxy (`test/http/admin-users.test.ts`). |
| 2026-09-19 | P3-03 groups endpoints with propagated renames/deletions and dual-write membership; admin rate-limit key changed to the full `jti`; `group.*` audit events added ahead of the P6-01 catalog. |
| 2026-09-19 | P3-04 clients endpoints (CRUD, rotate-secret, disable/enable, lazy cleanup on delete). |
