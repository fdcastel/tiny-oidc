# Tiny OIDC — Product and Engineering Specification

| | |
|---|---|
| **Version** | 1.0.0-draft.2 |
| **Date** | 2026-09-21 |
| **Status** | Authoritative for the v1 build. Supersedes `tmp/INITIAL_TINY_OIDC_SPEC.md`. |
| **Runtime** | TypeScript on Cloudflare Workers (workerd) |
| **Storage** | Durable Objects (SQLite) for per-entity state, D1 for the directory, R2 for the audit archive |
| **Protocol** | OpenID Connect Core 1.0, OAuth 2.0 Authorization Code + PKCE (S256), PAR, JWT access tokens, refresh-token rotation, RP-initiated and back-channel logout, token revocation, client credentials |
| **Authentication** | Passkeys (WebAuthn, discoverable credentials, user verification required) and upstream OIDC federation |
| **Shape** | Headless. API-first. No HTML. The login UI is a separate app that talks to the Interaction API. |
| **Scale target** | 1,000,000 users, 100,000 daily active users, 200 token requests per second at peak, one deployment |
| **Quality bar** | Every normative statement has an identifier and at least one automated test. 100% code coverage on `src/`. |

---

## 0. How to read this document

### 0.1 Normative language

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY are to be interpreted as described in RFC 2119 and RFC 8174.

"The OP" means the Tiny OIDC deployment. "The login app" means the operator-provided browser application that renders authentication and consent screens. "RP" means a relying party (an OIDC client). "Upstream" means an external OIDC provider the OP federates to.

### 0.2 Requirement identifiers and traceability

Every normative statement carries an identifier of the form `[TIO-<AREA>-<NNN>]`. Identifiers are stable: a requirement that is removed keeps its number and is marked `(withdrawn)`; it is never reused.

Each requirement is verified by exactly one of the following, stated after the identifier when it is not an automated test:

| Tag | Meaning |
|---|---|
| (default) | An automated test whose title contains the identifier. Runs on every pull request. |
| `(V: conformance)` | Verified by the OpenID Foundation conformance suite run (§13.9). |
| `(V: load)` | Verified by the k6 load-test thresholds (§13.10). |
| `(V: ci)` | Verified by a CI check that is not a test (bundle size, lint, drift, trace). |
| `(V: review)` | Verified by code review or an operational procedure. Used sparingly and only where automation is impossible. |

The `pnpm trace` command (§13.4) parses this document and the test suite. CI fails when any identifier with the default tag has no test whose title contains it, or when a test references an identifier that does not exist. This is how "not tested means not working" becomes enforceable rather than aspirational.

### 0.3 What changed from the initial draft

The initial draft (`tmp/INITIAL_TINY_OIDC_SPEC.md`) was a good statement of values. This document keeps those values and changes the architecture where the draft would not have reached 1,000,000 users or would have violated "no UI". Appendix B lists every change with its reason. The largest ones:

1. The OP is headless. There is no login page, consent page, or template engine in the OP. The login app is a separate application, and the OP exposes an Interaction API for it (§7).
2. Hot-path state (sessions, authorization codes, refresh-token families, passkeys, consent grants) lives in one Durable Object per user, not in D1. D1 holds the directory and global configuration. Login and refresh do zero D1 writes (§2.3).
3. Signing keys live in an encrypted key store in D1 and rotate through the admin API, not through a Worker secret and a redeploy (§10).
4. Audit events flow through a Queue to an R2 archive and a 30-day hot table. At 1,000,000 users an unbounded audit table in D1 would exceed the 10 GB database limit within a year (§11).
5. Modern extensions are in: PAR, `iss` in the authorization response, RFC 9068 JWT access tokens, resource indicators, back-channel logout, revocation, `client_credentials` with `private_key_jwt`, groups, a self-service API, bulk import. DPoP and Apple Sign-in are deferred by decision (§1.5).

### 0.4 Document map

§1 defines the product. §2 is the architecture. §3–§4 are the data model and storage. §5 is the OIDC/OAuth protocol surface. §6 is authentication (passkeys, sessions, federation). §7–§9 are the three JSON APIs (Interaction, Self-service, Admin). §10–§12 are cryptography, audit/observability, and configuration/deployment. §13 is the testing strategy. §14 is the repository layout and implementation plan. §15 is the threat model. Appendices hold the authentik comparison, the decision log, and the glossary.

---

## 1. Product definition

### 1.1 What Tiny OIDC is

Tiny OIDC is a headless, passkey-first OpenID Provider that runs entirely on Cloudflare. It gives one organization a single authoritative identity service for its own applications. Relying parties integrate through standard OpenID Connect. The organization's login screens are built by the organization, in any framework, on top of a small JSON Interaction API. Administration is a JSON API. End users manage their own passkeys, sessions and linked identities through a JSON API. The OP never serves HTML.

It is "tiny" in surface, not in capacity. The design target is one million users on one deployment with no servers, containers, or external databases.

**[TIO-GEN-001]** (V: review) OP code SHALL NOT generate or template HTML, CSS or client-side JavaScript on any endpoint. Every response the OP produces is `application/json`, a redirect, or empty. The single exception is the optional bundled reference login app (§7.9): a set of static files served unmodified by the Workers Assets binding under `/login/` when `BUNDLED_LOGIN_APP` is `true`. OP code never renders, templates or injects anything into those files.

**[TIO-GEN-002]** (V: ci) The Worker script bundle SHALL contain no template engine, no HTML sanitizer, and no UI framework. The reference login app is dependency-free static files outside the script bundle. The CI bundle-content check fails on any of them.

### 1.2 Personas

| Persona | Interacts through | Needs |
|---|---|---|
| **Operator / administrator** | Admin API (§9), `wrangler`, CI | Register clients and upstreams, manage users and groups, rotate keys, read audit, migrate users in bulk. |
| **Login-app developer** | Interaction API (§7) | Render sign-in, sign-up, account-linking, consent and logout confirmation screens with their own design system; run the WebAuthn ceremonies in the browser. |
| **Relying-party developer** | OIDC discovery, `/authorize`, `/par`, `/token`, `/userinfo`, `/revoke`, `/logout` (§5) | Standard OIDC with a standard client library. Nothing proprietary. |
| **Resource-server developer** | JWKS, JWT access tokens (§5.6) | Validate `at+jwt` locally; read `scope`, `aud`, `groups`. |
| **End user** | The login app, and any first-party app that calls the Self-service API (§8) | Sign in with a passkey or a federated account; see and revoke sessions; manage passkeys. |
| **Automation** | `client_credentials` + Admin API | Terraform-style provisioning of clients, upstreams, groups. |

### 1.3 Scale and performance targets (summary)

| Dimension | Target | Where verified |
|---|---|---|
| Registered users | 1,000,000 | §2.7 capacity model, §13.10 seeded load test |
| Daily active users | 100,000 | §13.10 |
| Peak token endpoint rate | 200 req/s sustained, 500 req/s burst | §13.10 |
| Peak interactive logins | 50 /s | §13.10 |
| D1 writes on login and refresh paths | 0 | §2.3, component tests |
| p99 server-side latency, `/token` | ≤ 200 ms | §2.7, §13.10 |
| Availability posture | Fail closed; no single hot object; stale-if-error caches for config | §2.9 |

### 1.4 Principles

Each principle is a decision filter. When a proposal conflicts with one, the proposal loses.

1. **Modern-only.** One protocol (OIDC over OAuth 2.0 code flow with PKCE), one credential type (passkeys), one federation type (OIDC). No passwords, no SAML, no LDAP, no SMS, no magic links, no implicit or password grants, no `plain` PKCE, no front-channel logout, no session iframes. The OP signs with ES256 only. The OP *verifies* whatever standard algorithms upstreams and clients use, including RS256, because interoperability with Google and Microsoft is not optional.
2. **Headless.** The OP owns the protocol and every security decision. The login app owns pixels. No security decision is delegated to the login app.
3. **Per-user isolation for scale.** Everything about a user that changes at login time lives in that user's Durable Object. Global tables hold only what must be global: uniqueness indexes, configuration, keys.
4. **Fail closed.** Any inability to verify state is a rejection. Stale configuration is tolerated only within explicit, short, documented windows.
5. **Tested is the only definition of working.** Every requirement has a test. Coverage is 100%. Concurrency, security and conformance are test suites, not checklists.
6. **Small surface.** A feature enters only if it improves a passkey-first OIDC provider for first-party applications and can be built without enlarging the security-critical core disproportionately.
7. **Cloudflare-native.** Workers, Durable Objects, D1, Queues, R2, the Rate Limiting binding and Cron Triggers. Nothing else at runtime.

### 1.5 Scope

**In v1**

- OIDC Core (code flow), discovery (OIDC and RFC 8414), JWKS, UserInfo.
- PKCE S256 required for every authorization request by default; a confidential client may be registered with `require_pkce = 0` (relying parties that cannot send one, including the OpenID Foundation conformance suite, §13.9), and a `code_challenge` it does send is still verified. Public clients always require it. Exact redirect URI matching (loopback port exception for native apps).
- Pushed Authorization Requests (RFC 9126), `iss` authorization response parameter (RFC 9207), JWT access tokens (RFC 9068) with a static per-client audience list, token revocation (RFC 7009).
- Grants: `authorization_code`, `refresh_token` (rotating, family-tracked, reuse-detected), `client_credentials`.
- Client authentication: `none` (public clients), `client_secret_basic`, `client_secret_post`, `private_key_jwt`.
- Passkeys: registration, authentication, discoverable credentials, user verification required, counter policy, up to 20 per user. Related Origin Requests for first-party apps on other domains.
- Upstream OIDC federation with automatic discovery, PKCE, nonce, full ID-token validation, and an explicit account-resolution policy (login-time linking by verified email). Verified against Google and Microsoft (single tenant).
- Browser sessions with SSO across clients, `prompt`, `max_age`, `login_hint`, `ui_locales`.
- RP-initiated logout with `id_token_hint`, logout confirmation through the login app when no hint is present, back-channel logout to registered clients.
- Groups (flat), per-client `allowed_groups`, `groups` claim and scope.
- Consent with per-client persistent grants; first-party clients may skip consent.
- Registration policy (`closed`, `invite`, `open`), invitations, admin-driven recovery.
- Interaction API for the login app; Self-service API for end users; Admin API with bootstrap, bulk NDJSON import, settings, key rotation, audit query.
- Audit pipeline (30-day hot table, R2 archive, per-user views of the hot table), structured logs, optional metrics.
- Rate limiting, cron maintenance, D1 and Durable Object schema migrations, OpenAPI 3.1 document.
- Deploy-to-Cloudflare button for one-click evaluation, with an optional bundled reference login app served as static assets on the OP origin (§7.9, §12.3).

**Explicitly excluded (will not be added)**

Passwords and password reset; SAML; LDAP; RADIUS; SCIM in the OP core; SMS, TOTP and email one-time codes; magic links; implicit, hybrid and password grants; `plain` PKCE; front-channel logout; OIDC Session Management (`check_session_iframe`); JAR request objects and JARM; token introspection (RFC 7662), unnecessary because access tokens are `at+jwt` validated locally against JWKS; dynamic client registration open to the public; wildcard or prefix redirect URIs; HTML of any kind; multi-tenancy inside one deployment; an authorization policy language; email sending; telemetry of any kind.

**Deferred (post-1.0 candidates, tracked in Appendix B)**

DPoP (RFC 9449); Apple Sign-in upstream; EdDSA as a signing option; pairwise subject identifiers; device authorization grant; token exchange; outbound webhooks; SCIM server; sharding the D1 directory beyond ~5,000,000 users; RFC 8707 resource indicators; self-service identity linking; configuration as code (`PUT /admin/config`); a `jti` replay cache for `private_key_jwt`.

### 1.6 Benchmark

authentik is the feature reference. Appendix A maps every authentik capability to a Tiny OIDC decision (kept, replaced, dropped) with the reason. The short version: Tiny OIDC keeps authentik's OIDC provider, OIDC sources, users, groups, application access control, sessions, events and API; it replaces flows and stages with the login app; it drops every non-OIDC protocol and every legacy factor.

---

## 2. Architecture

### 2.1 Component overview

```text
                                   Internet
                                       │
          RP browser redirects         │        Login app (operator-owned, same-site)
          RP backend / SPA calls       │        first-party apps, admin tooling
                                       ▼
                    ┌──────────────────────────────────────┐
                    │  Cloudflare Worker  (auth.example.com)│
                    │                                       │
                    │  Router (Hono)                        │
                    │   ├─ OIDC/OAuth endpoints      §5     │
                    │   ├─ Interaction API           §7     │
                    │   ├─ Self-service API          §8     │
                    │   ├─ Admin API                 §9     │
                    │   ├─ Queue consumer            §11    │
                    │   └─ Cron handler              §12    │
                    │                                       │
                    │  Isolate caches: clients, settings,   │
                    │  signing keys, upstream metadata      │
                    └───┬──────────┬──────────┬───────┬─────┘
                        │          │          │       │
          ┌─────────────┘          │          │       └──────────────┐
          ▼                        ▼          ▼                      ▼
 ┌─────────────────┐   ┌──────────────────┐  ┌────────────┐  ┌────────────────┐
 │ Durable Objects │   │ D1 "directory"   │  │ Queue      │  │ Rate Limiting  │
 │                 │   │                  │  │ TASKS      │  │ bindings       │
 │ UserDO ×1/user  │   │ users (index)    │  │            │  │ per IP, client,│
 │ InteractionDO   │   │ groups, members  │  │ audit      │  │ (per-colo)     │
 │   ×1/login      │   │ passkey_index    │  │ batches,   │  └────────────────┘
 │                 │   │ identity_index   │  │ logout     │
 │                 │   │ clients          │  │ retries    │  ┌────────────────┐
 │                 │   │ upstreams        │  └─────┬──────┘  │ Cron Trigger   │
 │ SQLite each     │   │ signing_keys     │        │         │ every 5 min    │
 │                 │   │ invitations      │        ▼         └────────────────┘
 │                 │   │ settings         │  ┌────────────┐
 │                 │   │ audit_hot (30 d) │  │ R2 archive │
 └─────────────────┘   └──────────────────┘  │ audit/…    │
                                             └────────────┘
                        ▲
                        │ HTTPS (server-to-server)
                        ▼
              ┌────────────────────┐
              │ Upstream OIDC OPs  │  Google, Microsoft, any compliant issuer
              └────────────────────┘
```

**[TIO-ARCH-001]** (V: review) The deployable unit SHALL be a single Worker script exporting `fetch`, `queue` and `scheduled` handlers and the two Durable Object classes `UserDO` and `InteractionDO`.

**[TIO-ARCH-002]** No request path SHALL depend on a Durable Object that is shared by all users or all clients. Per-deployment state (clients, upstreams, keys, settings) is read from D1 through isolate caches. Tests assert that the Durable Object namespaces are only addressed by user id, interaction id or client id.

### 2.2 Cloudflare resources

| Binding | Type | Purpose | Notes |
|---|---|---|---|
| `DB` | D1 | Directory, configuration, key store, hot audit | One database. 10 GB hard cap. Capacity model §2.7. |
| `USER_DO` | Durable Object namespace (SQLite) | One object per user | `idFromName(user_id)`. 10 GB per object cap, never approached. |
| `INTERACTION_DO` | Durable Object namespace (SQLite) | One object per authorization/logout/link interaction and per PAR request | `idFromName(interaction_id)`. Self-deletes on alarm. |
| `TASKS` | Queue (producer and consumer) | Audit event batches, back-channel logout retries | 5,000 msg/s per queue; we need < 500. |
| `AUDIT_BUCKET` | R2 | Audit archive, D1 exports | NDJSON, gzip. |
| `RL_IP`, `RL_CLIENT` | Rate Limiting | Per-colo permissive limits | GA since 2025-09. Periods 10 s or 60 s only. Exact per-interaction and per-user limits live in Durable Object state (§6.7). |
| `METRICS` | Analytics Engine (optional) | Request and event counters | Absent binding disables metrics. |
| `ASSETS` | Workers Assets | Static files of the reference login app, served under `/login/` only when `BUNDLED_LOGIN_APP=true` | Bundled in every environment; inert unless enabled. |
| Cron `*/5 * * * *` | Cron Trigger | Maintenance | One trigger. |
| Secrets | Worker secrets | `MASTER_KEYS`, `ADMIN_BOOTSTRAP_TOKEN` | §12.2 |

**[TIO-ARCH-003]** (V: ci) `wrangler.jsonc` SHALL declare exactly the bindings above. The CI config check fails on additions without a spec change.

### 2.3 Data placement

The rule: **a user's Durable Object is the source of truth for everything about that user; D1 is the source of truth for existence, uniqueness and global configuration.**

| Data | Lives in | Why |
|---|---|---|
| User profile (email, verified flag, display name, groups, disabled) | `UserDO` (truth) + `users` row in D1 (mirror for listing and search) | Profile is read on every token issuance; must be one DO hop. Listing needs a global table. |
| Passkeys (public key, counter, flags) | `UserDO` (truth) + `passkey_index` in D1 (credential id → user id) | Counter update must be atomic with verification. Index exists for uniqueness, admin lookup, and the rare assertion without `userHandle`. |
| Federated identities | `UserDO` (truth) + `identity_index` in D1 ((issuer, subject) → user id) | Login must resolve (issuer, subject) globally. |
| Browser sessions | `UserDO` | Session cookie routes to the user; revocation is per user. |
| Authorization codes | `UserDO` | Issued after authentication when the user is known; consumed exactly once inside the DO. |
| Refresh-token families and tokens | `UserDO` | Rotation is the highest-frequency write in the system. Per-user isolation makes it linear. |
| Consent grants | `UserDO` | Read at authorization time with the session. |
| Interaction state (authorize params, challenge, upstream state, link candidate) | `InteractionDO` | Exists before the user is known; ten-minute lifetime; self-deletes. |
| PAR request | `InteractionDO` (same object becomes the interaction) | One-minute lifetime. |
| Clients, upstreams, groups, settings, invitations | D1 | Global configuration. Low write rate. Isolate-cached reads. |
| Signing keys (public + encrypted private) | D1 | Global. Cached in isolates for 60 seconds. |
| Audit events | `TASKS` queue → D1 `audit_hot` (30 days) + R2 archive (indefinite) | Volume is unbounded; D1 cannot hold it. |

**[TIO-ARCH-004]** The authorization-code exchange, refresh-token rotation, passkey assertion verification and session validation paths SHALL perform no D1 write. Component tests wrap the D1 binding in a spy and assert zero write statements.

**[TIO-ARCH-005]** Each of those paths SHALL perform at most one Durable Object round trip to `UserDO` (plus one to `InteractionDO` during an interaction). Tests count stub invocations.

### 2.4 Opaque handles

Every secret handle the OP hands out (session cookie value, authorization code, refresh token, upstream `state`, interaction binding cookie, invitation token) is a fixed-format encrypted envelope. Encryption gives three things: the handle is opaque to everyone but the OP, garbage is rejected before any storage lookup, and the OP can route the handle to the right Durable Object without a global index.

```text
handle      = prefix "_" base64url( version(1) || keyver(1) || type(1) || nonce(12) || ciphertext || tag(16) )
ciphertext  = AES-256-GCM( key = HKDF-SHA256(MASTER_KEYS[keyver], salt="", info="tio/v1/envelope"),
                           aad = version || keyver || type,
                           plaintext = fields )
```

| Prefix | Type byte | Plaintext fields | Stored server-side |
|---|---|---|---|
| `tio_ss` | `0x01` session | `uid(16) sid(16) secret(32)` | SHA-256(secret) in `UserDO.sessions` |
| `tio_ac` | `0x02` authorization code | `uid(16) secret(32)` | SHA-256(secret) in `UserDO.auth_codes` |
| `tio_rt` | `0x03` refresh token | `uid(16) family(16) secret(32)` | SHA-256(secret) in `UserDO.refresh_tokens` |
| `tio_ix` | `0x04` interaction binding | `ixid(32) secret(32)` | SHA-256(secret) in `InteractionDO` |
| `tio_fs` | `0x05` federation state | `ixid(32) secret(32)` | SHA-256(secret) in `InteractionDO` |
| `tio_iv` | `0x06` invitation | `invid(16) secret(32)` | SHA-256(secret) in D1 `invitations` |

`uid`, `sid`, `family`, `invid` are UUIDs as 16 raw bytes. `ixid` is 32 random bytes. `secret` is 32 random bytes from `crypto.getRandomValues`.

**[TIO-ARCH-006]** All handles listed above SHALL use the envelope format. Property-based tests round-trip random field values and assert that any single-bit flip in the handle is rejected without a storage access.

**[TIO-ARCH-007]** The OP SHALL store only the SHA-256 of a handle's `secret`, never the secret or the handle. Tests inspect Durable Object and D1 storage after issuance.

**[TIO-ARCH-008]** Envelope decryption SHALL try only the key version named in the handle. Handles encrypted under a retired key version SHALL be rejected. Tests cover key-version rollover (§10.4).

**[TIO-ARCH-009]** The presence of a valid envelope SHALL never be sufficient on its own; every handle is additionally validated against its server-side record (existence, expiry, consumption, revocation). Tests forge a structurally valid envelope with a random secret and assert rejection.

### 2.5 Request flows

The flows below are normative for hop counts and ordering. Endpoint details are in §5–§7.

#### 2.5.1 Interactive login with a passkey (no existing session)

```text
RP browser                 OP Worker                 InteractionDO        UserDO           Login app
   │  GET /authorize?…        │                           │                  │                │
   │─────────────────────────▶│ validate client, redirect_uri, PKCE, scope   │                │
   │                          │ no session cookie → create interaction       │                │
   │                          │──────────────────────────▶│ create(params)   │                │
   │  303 LOGIN_URL?interaction=ix   Set-Cookie: __Host-tio_ix_<p>=tio_ix_…  │                │
   │◀─────────────────────────│                           │                  │                │
   │  GET LOGIN_URL?interaction=ix ───────────────────────────────────────────────────────────▶│
   │                          │  GET  /api/v1/interactions/ix (credentials: include)          │
   │                          │◀───────────────────────────────────────────────────────────────│
   │                          │──────────────────────────▶│ get()            │                │
   │                          │  { status: "login_required", client, methods, … }             │
   │                          │──────────────────────────────────────────────────────────────▶│
   │                          │  POST /api/v1/interactions/ix/passkey/options                 │
   │                          │◀───────────────────────────────────────────────────────────────│
   │                          │──────────────────────────▶│ setChallenge()   │                │
   │                          │  { publicKey: {challenge, rpId, userVerification:"required"} } │
   │                          │──────────────────────────────────────────────────────────────▶│
   │                          │            navigator.credentials.get() runs in the login app  │
   │                          │  POST /api/v1/interactions/ix/passkey/verify {assertion}      │
   │                          │◀───────────────────────────────────────────────────────────────│
   │                          │──────────────────────────▶│ consumeChallenge()                │
   │                          │ uid ← userHandle          │                  │                │
   │                          │────────────────────────────────────────────▶│ verifyAssertion │
   │                          │ (signature, origin, rpId, UV, counter) atomically             │
   │                          │ allowed_groups, disabled, consent check      │                │
   │                          │──────────────────────────▶│ setAuthenticated(), status ready  │
   │                          │  { status: "ready", redirect_to: ISSUER/interactions/ix/complete }
   │                          │──────────────────────────────────────────────────────────────▶│
   │  GET /interactions/ix/complete  (top-level navigation, cookie __Host-tio_ix_<p> present) │
   │◀─────────────────────────────────────────────────────────────────────────────────────────│
   │─────────────────────────▶│──────────────────────────▶│ complete()       │                │
   │                          │────────────────────────────────────────────▶│ createSession + issueCode
   │  303 redirect_uri?code=tio_ac_…&state=…&iss=ISSUER   Set-Cookie: __Host-tio_session=tio_ss_…
   │◀─────────────────────────│                           │                  │                │
```

DO hops: two to `InteractionDO` and one to `UserDO` on verify; one each on complete.

#### 2.5.2 Single sign-on (existing session, consent already granted)

```text
GET /authorize → decrypt session cookie → UserDO.authorizeWithSession(params)
  → session valid, not disabled, allowed_groups ok, grant covers scopes, prompt/max_age satisfied
  → issue code, record session_clients, touch session
→ 303 redirect_uri?code&state&iss
```

One `UserDO` hop, no `InteractionDO`. If the session is valid but consent is missing or `prompt` demands interaction, the OP creates an interaction with `existing_session` set and the login app sees `status: "consent_required"` (or `login_required` for `prompt=login` / stale `max_age`).

#### 2.5.3 Token endpoint: code exchange

```text
POST /token grant_type=authorization_code
  → authenticate client (none / secret / private_key_jwt)
  → decrypt code envelope → uid
  → UserDO.exchangeCode({secret_hash, client_id, client_created_at, redirect_uri, code_verifier})
      atomically: exists, not expired, not consumed, client & redirect match, PKCE ok
      → mark consumed; create refresh family (kind session|offline) and first token secret
      → return grant (sub, scope, nonce, sid, auth_time, amr, acr, claims, family, rt_secret)
  → sign ID token + access token (keys from isolate cache)
  → 200 { access_token, id_token, refresh_token, token_type, expires_in, scope }
```

One `UserDO` hop. Two signatures.

#### 2.5.4 Token endpoint: refresh

```text
POST /token grant_type=refresh_token
  → authenticate client
  → decrypt rt envelope → uid, family
  → UserDO.rotateRefreshToken({family, secret_hash, client_id, client_created_at, scope?})
      atomically: family active and unexpired; token is current and unconsumed
        → consumed → reuse detected → revoke family (+ session if session-bound) → error
        → current  → mark consumed, insert next token, extend idle, return claims + new secret
      re-check user not disabled, allowed_groups, session alive (session-bound families)
  → sign tokens → 200
```

One `UserDO` hop.

#### 2.5.5 Federated login

```text
Login app: POST /api/v1/interactions/ix/upstream/google
  → OP: InteractionDO.setFederation({issuer, state_secret_hash, nonce, code_verifier})
  → { redirect_to: https://accounts.google.com/o/oauth2/v2/auth?…state=tio_fs_…&nonce=…&code_challenge=… }
Browser navigates to upstream, authenticates, returns:
GET /federation/callback?code=…&state=tio_fs_…   (cookie __Host-tio_ix_<p> present)
  → decrypt state → ixid; InteractionDO.consumeFederation(secret_hash) (single use)
  → verify binding cookie
  → POST upstream token endpoint (client auth, code_verifier) [server-to-server]
  → validate ID token (jose, remote JWKS cached): iss, aud/azp, exp, iat, nonce, alg, sub
  → optional userinfo fetch; required_claims check
  → resolve account: identity_index (D1 read) → existing user
                     | verified-email match → link_required
                     | auto_create/invitation → create user (D1 claim + UserDO.init)
                     | else registration_closed
  → InteractionDO.setAuthenticated() → status ready | link_required | failed
  → if ready: same finalization as /complete (session, code, 303 to RP)
    else:     303 LOGIN_URL?interaction=ix (login app renders link or error)
```

#### 2.5.6 Logout

```text
GET /logout?id_token_hint=…&post_logout_redirect_uri=…&state=…
  → verify hint signature (expiry ignored), iss, aud → client; validate post_logout_redirect_uri exact
  → sid from hint; if session cookie present and sid matches → UserDO.revokeSession(sid)
     else → UserDO(hint.sub).revokeSession(hint.sid)   (revokes that session wherever it is)
  → revokeSession: session-bound refresh families revoked; back-channel logout tokens sent to
    every client in session_clients with a backchannel_logout_uri (waitUntil; retries via TASKS)
  → clear cookie → 303 post_logout_redirect_uri?state=…
GET /logout (no hint, session present)
  → create logout interaction → 303 LOGIN_URL?interaction=ix  (login app asks "Sign out?")
  → POST /api/v1/interactions/ix/logout {confirm:true} → { redirect_to: ISSUER/interactions/ix/complete }
```

### 2.6 Trust boundaries

| Boundary | Trust assumption | Enforcement |
|---|---|---|
| RP browser → OP | Untrusted. Every parameter is validated; redirects only to registered URIs. | §5.3 validation order, exact matching, `state`, `iss`, PKCE. |
| Login app → OP | Trusted to render, never trusted to decide. It cannot assert an identity; it can only drive ceremonies whose proofs the OP verifies (WebAuthn signatures, upstream ID tokens). | Interaction API accepts proofs, not claims. Origin allow-list, binding cookie, single-use challenges. |
| RP backend → OP | Authenticated per client type. Public clients are identified, not authenticated; PKCE binds the code to the requester. | §5.6 client authentication; `private_key_jwt` assertions live 60 seconds (TIO-TOKEN-003). |
| OP → upstream | Trusted only for what its signed ID token proves after full validation against the configured issuer. Email is an attribute, never an identifier. | §6.4. |
| OP → storage | D1 and DO are trusted for integrity but treated as leakable: no plaintext secrets, private keys encrypted under `MASTER_KEYS`. | §2.4, §10. |
| Admin token → OP | Trusted per scope and audience; every action is audited with the actor. | §9.1. |
| Resource server → OP | Validates `at+jwt` locally with JWKS; trusts `aud`, `scope`, `groups`. | §5.6. |

**[TIO-ARCH-010]** The Interaction API SHALL NOT expose any operation that marks an interaction as authenticated without a proof verified by the OP (a WebAuthn assertion or an upstream ID token). Tests enumerate the API surface and assert no such operation exists.

### 2.7 Performance budgets and capacity model

Budgets are server-side, measured inside the Worker from request receipt to response send, at the load in §1.3, over a five-minute window.

| Endpoint | p50 | p99 | DO hops | D1 | Signatures |
|---|---|---|---|---|---|
| `GET /.well-known/*`, `GET /.well-known/jwks.json` | 5 ms | 20 ms | 0 | 0 (cached) | 0 |
| `GET /authorize` (session hit) | 30 ms | 150 ms | 1 | 0 | 0 |
| `GET /authorize` (new interaction) | 30 ms | 150 ms | 1 | 0 | 0 |
| `POST /par` | 30 ms | 150 ms | 1 | 0 | 0 |
| `POST /token` code exchange | 40 ms | 200 ms | 1 | 0 | 2 |
| `POST /token` refresh | 30 ms | 150 ms | 1 | 0 | 2 |
| `POST /token` client credentials | 30 ms | 150 ms | 0–1 | 0 | 1 |
| `GET /userinfo` | 20 ms | 100 ms | 1 | 0 | 0 |
| `POST …/passkey/verify` | 40 ms | 250 ms | 2 | 0 | 0 |
| `GET /interactions/{id}/complete` | 40 ms | 200 ms | 2 | 0 | 0 |
| `GET /federation/callback` | 200 ms | 800 ms | 2 | 1 read | 0 |
| Admin list endpoints | 50 ms | 300 ms | 0 | 1–2 reads | 0 |

**[TIO-PERF-001]** (V: load) The k6 suite SHALL enforce the p99 budgets above as thresholds at 200 token requests per second with 1,000,000 seeded users.

**[TIO-PERF-002]** (V: ci) Worker CPU time per request SHALL stay below 30 ms at p99 in the load test; the uncompressed bundle SHALL stay below 1.5 MB. CI fails on bundle growth beyond the budget.

**Capacity model at 1,000,000 users (100,000 DAU)**

| Store | Rows / objects | Size estimate | Limit | Headroom |
|---|---|---|---|---|
| `UserDO` objects | 1,000,000 | ≤ 40 KB each typical (profile 1 KB, 2 passkeys 1.2 KB, sessions 2 KB, refresh rows ≤ 30 KB at 24 h retention) → ≤ 40 GB total | 10 GB per object; unlimited total | Enormous |
| `InteractionDO` objects | ~300,000 created per day, deleted after ≤ 15 min | negligible | — | — |
| D1 `users` | 1,000,000 | ~200 MB | | |
| D1 `passkey_index` | 2,000,000 | ~300 MB | | |
| D1 `identity_index` | 1,000,000 | ~200 MB | | |
| D1 `group_members` | 2,000,000 | ~200 MB | | |
| D1 `audit_hot` (30 days) | ~4,000,000 | ~2 GB | | |
| D1 total | | **~3 GB** | 10 GB | 3× |
| Queue | ~1–3 M messages/day (35/s avg, 300/s peak) | | 5,000/s | 15× |

Request rates at 100,000 DAU: ~200,000 interactive logins/day (peak 50/s), ~5,000,000 refreshes/day (peak 150/s), ~10,000,000 Worker requests/day. Per-user DO load is ~50 requests/day, far below the 1,000 req/s per-object soft limit. Order-of-magnitude monthly cost at published 2026 prices: DO requests ~$25, DO storage ~$20, Worker requests ~$90, Queues ~$40, D1 < $10. Verify against current pricing before budgeting.

The D1 directory is the first ceiling. Its size is dominated by `audit_hot` retention, which is a setting. Beyond roughly 5,000,000 users the directory would need sharding by user-id prefix; the design permits it (all D1 access goes through repositories keyed by user id) but v1 does not implement it.

### 2.8 Caching and staleness

| Cached item | Cache | TTL | Stale-if-error | Invalidation |
|---|---|---|---|---|
| Discovery document, JWKS | Cloudflare edge cache via `Cache-Control: public, max-age=300` + Worker `caches.default` | 5 min | — | Time |
| Client record | Isolate memory (LRU 1,000) | 60 s | up to 1 h | Time |
| Settings | Isolate memory | 60 s | up to 1 h | Time |
| Signing keys (public and decrypted private) | Isolate memory | 60 s (so that retirement meets TIO-ARCH-011) | up to 1 h | Time |
| Upstream discovery metadata | Isolate memory | 1 h | up to 24 h | Time |
| Upstream JWKS | `jose` remote JWK set (isolate) | 1 h; refetch on unknown `kid` at most once per 5 min | up to 24 h | `kid` miss |

**[TIO-ARCH-011]** Disabling a client, retiring a key or changing a setting SHALL take effect on every isolate within 60 seconds under normal D1 availability. Tests advance a fake clock and assert refresh. From three quarters of the TTL a read SHALL serve the cached value and refresh it in the background (one refresh in flight per cache, kept alive past the request), so that under steady traffic no request waits for D1 on a cache expiry; a value past the TTL is refreshed before it is served.

**[TIO-ARCH-012]** When D1 is unavailable, the OP SHALL serve client, settings and key reads from stale cache for at most one hour, then fail closed. Tests simulate D1 errors.

**[TIO-ARCH-013]** Administrative reads (`GET /api/v1/admin/...`) SHALL bypass isolate caches and read D1 directly.

### 2.9 Availability and failure behavior

| Failure | Behavior |
|---|---|
| D1 unavailable | Login of federated users fails (identity lookup). Passkey login, code exchange, refresh, userinfo continue on stale caches for ≤ 1 h. User creation, admin API, invitations fail. Health endpoint reports `degraded`. |
| A `UserDO` unavailable | That user's operations fail with `temporarily_unavailable` / HTTP 503. Other users unaffected. |
| Queue unavailable | Audit events are still written to structured logs; the hot table, the archive and the per-user views lag; back-channel logout retries are lost after the first synchronous attempt. |
| Upstream unavailable | Federated login fails with `upstream_unavailable`; passkey login unaffected. |
| `MASTER_KEYS` missing or malformed | The Worker refuses to start handling requests (fails every request with 500 `server_error` and logs a fatal). |

**[TIO-ARCH-014]** Every security-relevant failure SHALL fail closed: unknown key, unknown client, unverifiable handle, storage error during verification, clock outside tolerance. Tests inject each failure and assert rejection with a generic error and no token issuance.

**[TIO-ARCH-015]** Storage errors SHALL map to HTTP 503 with `error: "temporarily_unavailable"` on the token endpoint and Interaction API, never to a 200 or to an OAuth `invalid_grant`. Tests assert the status and that no state transition was partially applied (the DO transaction rolled back).

**[TIO-ARCH-016]** The OP SHALL make outbound HTTP requests only to: the configured upstreams' discovery, authorization, token, JWKS and userinfo endpoints; registered clients' `jwks_uri`; registered clients' `backchannel_logout_uri`. It SHALL send no telemetry, heartbeat, version check or crash report anywhere. A test runs every flow with outbound requests intercepted (`@msw/cloudflare`, unhandled requests rejected) and an allow-list of exactly those hosts, and fails on any other outbound request.

---
## 3. Identity model

### 3.1 Entities

```text
User (canonical, immutable id)
 ├── Passkey ×0..20         WebAuthn credentials; the only local authenticator type
 ├── Identity ×0..n         (issuer, subject) pairs from upstream OIDC providers
 ├── Session ×0..n          browser sessions at the OP; carry sid, auth_time, amr, acr
 │    └── session_clients   clients that received tokens under this session (for logout)
 ├── RefreshFamily ×0..n    one per (client, login); kind = session | offline
 │    └── RefreshToken ×1..n  rotation chain; only the newest is valid
 ├── Grant ×0..n            consent: per client, the union of scopes the user granted
 └── AuthorizationCode ×0..n  60-second, single-use

Group (flat)  ◀──▶  User   many-to-many; the `admins` group is system-defined
Client        registered relying party or service client
Upstream      configured external OIDC provider
Invitation    single-use registration or recovery token
SigningKey    ES256 key with lifecycle next → active → retiring → retired
```

### 3.2 Identifiers

**[TIO-DATA-001]** User identifiers SHALL be UUID version 7, generated by the OP at creation, never derived from email, upstream subject, credential id or any other attribute. The `sub` claim is the user id as a lowercase 36-character UUID string.

**[TIO-DATA-002]** Session ids (`sid`), refresh-family ids, invitation ids, event ids and audit ids SHALL be UUID version 7. Interaction ids SHALL be 32 random bytes, base64url-encoded (43 characters).

**[TIO-DATA-003]** Client ids SHALL match `^[a-z0-9][a-z0-9._-]{2,63}$`. When not supplied by the administrator, the OP generates `c_` followed by 22 characters of `[a-z0-9]` (base64url would violate the pattern's lowercase rule). Group names SHALL match `^[a-z0-9][a-z0-9._-]{0,63}$`. Upstream aliases SHALL match `^[a-z0-9][a-z0-9_-]{0,31}$`.

**[TIO-DATA-004]** Timestamps SHALL be integers, seconds since the Unix epoch, in storage and in every API. Durations in APIs are seconds.

### 3.3 Email semantics

Email is an attribute, not an identifier. At consumer scale an unverified email must not be able to block or hijack anyone.

**[TIO-DATA-005]** A user MAY have at most one email. It is stored as given, compared case-insensitively after Unicode NFC normalization and trimming, and SHALL be at most 254 characters and syntactically valid per the WHATWG HTML `email` input rules.

**[TIO-DATA-006]** Uniqueness SHALL be enforced only among verified emails: at most one user with `email_verified = true` per normalized email. Any number of users may hold the same unverified email.

**[TIO-DATA-007]** Account resolution (federation linking, admin lookup by email) SHALL consider only verified emails. Unverified emails are never used to find an account.

**[TIO-DATA-008]** `email_verified` SHALL become `true` only through (a) an upstream identity whose issuer is configured with `trust_email_verified` and whose ID token or userinfo asserts `email_verified: true` for the same email, (b) an invitation created with `email_verified: true`, (c) the Admin API, or (d) bulk import. The OP never sends email. Any change to the email address resets `email_verified` to `false` unless made through (b), (c) or (d).

### 3.4 User status

| Status | Meaning | Effect |
|---|---|---|
| `creating` | D1 row claimed, `UserDO` not yet initialized | Invisible to every lookup. Repaired or deleted by cron after 1 h. |
| `active` | Normal | — |
| `disabled` | Administratively disabled | Every session and refresh family revoked at disable time; every subsequent operation on the user fails closed (`access_denied` / `invalid_grant`); back-channel logout sent. |
| `deleting` | Deletion in progress | As disabled; row removed when `UserDO.destroy()` completes. |

**[TIO-DATA-009]** Disabling a user SHALL, in one `UserDO` transaction, set `disabled_at`, revoke all sessions and refresh families, and enqueue back-channel logout for every client in every session. Tests assert that a token refresh, a code exchange, a session-hit `/authorize`, `/userinfo` and every Self-service call fail after disable.

**[TIO-DATA-010]** Deleting a user SHALL revoke as in disable, delete every D1 row referencing the user (index rows, group memberships, invitations bound to the user), call `UserDO.destroy()` (`deleteAll`), and emit `user.deleted`. Audit records already archived retain the user id, which is a random UUID and identifies no person by itself.

### 3.5 Groups

**[TIO-DATA-011]** Groups SHALL be flat. There is no nesting, no inheritance and no group-of-groups.

**[TIO-DATA-012]** The group `admins` SHALL exist in every deployment, be marked `system = 1`, and SHALL NOT be deletable or renamable.

**[TIO-DATA-013]** A user's group list SHALL be stored in `UserDO` (authoritative for claims) and mirrored in D1 `group_members` (authoritative for "list members of group"). Membership changes write both in the same admin operation; a failed second write is retried and reported as `partial_failure` so the operator can reconcile with the reindex endpoint (§9.10).

### 3.6 Passkey record

| Field | Type | Notes |
|---|---|---|
| `id` | UUID v7 | Internal id used by APIs |
| `credential_id` | base64url | Globally unique |
| `public_key` | bytes (COSE) | As returned by the authenticator |
| `alg` | int | COSE algorithm: -8 (EdDSA), -7 (ES256), -257 (RS256) |
| `counter` | int | Signature counter; policy in §6.1.5 |
| `transports` | string[] | Hint for clients |
| `aaguid` | UUID | For display; not trusted for policy |
| `backup_eligible`, `backed_up` | bool | From authenticator data flags |
| `name` | string ≤ 64 | User-assigned label; optional |
| `created_via` | `interaction` \| `me` \| `recovery` | Provenance |
| `created_at`, `last_used_at` | int | |

### 3.7 Federated identity record

| Field | Notes |
|---|---|
| `id` | UUID v7 |
| `issuer` | Exact issuer URL of the upstream |
| `subject` | Upstream `sub`, ≤ 255 chars |
| `email`, `email_verified`, `name` | Latest attributes observed from the upstream; informational |
| `created_at`, `last_login_at` | |

**[TIO-DATA-014]** `(issuer, subject)` SHALL be globally unique across all users. An attempt to link a pair already linked to another user SHALL fail with `identity_already_linked`.

---

## 4. Storage

### 4.1 D1 directory schema

D1 migrations live in `migrations/` and are applied with `wrangler d1 migrations apply` before deployment. The schema below is migration `0001`.

```sql
-- users: registry of existence. UserDO is the source of truth for content.
CREATE TABLE users (
  id              TEXT PRIMARY KEY,                 -- UUID v7
  email           TEXT,                             -- mirror, as given
  email_norm      TEXT,                             -- mirror, normalized (lowercase NFC trim)
  email_verified  INTEGER NOT NULL DEFAULT 0,
  display_name    TEXT,
  status          TEXT NOT NULL CHECK (status IN ('creating','active','disabled','deleting')),
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX users_verified_email ON users(email_norm) WHERE email_verified = 1 AND email_norm IS NOT NULL;
CREATE INDEX users_email_norm ON users(email_norm);
CREATE INDEX users_created   ON users(created_at, id);
CREATE INDEX users_status    ON users(status, updated_at);

CREATE TABLE groups (
  id          TEXT PRIMARY KEY,                     -- UUID v7
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  system      INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE group_members (
  group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id   TEXT NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
  added_at  INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members(user_id);

CREATE TABLE passkey_index (
  credential_id TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    INTEGER NOT NULL
);
CREATE INDEX passkey_index_user ON passkey_index(user_id);

CREATE TABLE identity_index (
  issuer     TEXT NOT NULL,
  subject    TEXT NOT NULL,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (issuer, subject)
);
CREATE INDEX identity_index_user ON identity_index(user_id);

CREATE TABLE clients (
  client_id                   TEXT PRIMARY KEY,
  client_name                 TEXT NOT NULL,
  client_uri                  TEXT,
  logo_uri                    TEXT,
  redirect_uris               TEXT NOT NULL,        -- JSON array
  post_logout_redirect_uris   TEXT NOT NULL DEFAULT '[]',
  backchannel_logout_uri      TEXT,
  grant_types                 TEXT NOT NULL,        -- JSON array ⊆ ["authorization_code","refresh_token","client_credentials"]
  token_endpoint_auth_method  TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('none','client_secret_basic','client_secret_post','private_key_jwt')),
  client_secret_hash          BLOB,                 -- SHA-256 of the secret; NULL unless method is client_secret_basic or client_secret_post
  jwks                        TEXT,                 -- JSON JWK Set for private_key_jwt (either jwks or jwks_uri)
  jwks_uri                    TEXT,
  scopes_allowed              TEXT NOT NULL,        -- JSON array
  audiences                   TEXT NOT NULL DEFAULT '[]',   -- JSON array of resource identifiers placed in aud (TIO-TOKEN-033)
  allowed_groups              TEXT,                 -- NULL = everyone; JSON array of group names otherwise
  skip_consent                INTEGER NOT NULL DEFAULT 0,
  require_par                 INTEGER NOT NULL DEFAULT 0,
  require_pkce                INTEGER NOT NULL DEFAULT 1,   -- 0 only for confidential clients (TIO-AUTHZ-008)
  offline_access              INTEGER NOT NULL DEFAULT 0,
  access_token_ttl            INTEGER,              -- seconds; NULL = setting default
  id_token_ttl                INTEGER,
  refresh_token_ttl           INTEGER,              -- absolute, offline families
  refresh_idle_ttl            INTEGER,
  disabled_at                 INTEGER,
  created_at                  INTEGER NOT NULL,
  updated_at                  INTEGER NOT NULL
);

CREATE TABLE upstreams (
  alias                       TEXT PRIMARY KEY,
  issuer                      TEXT NOT NULL UNIQUE,
  display_name                TEXT NOT NULL,
  client_id                   TEXT NOT NULL,
  token_endpoint_auth_method  TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('client_secret_basic','client_secret_post','private_key_jwt')),
  client_secret_enc           BLOB,                 -- AES-GCM under MASTER_KEYS (keystore info)
  client_jwk_enc              BLOB,                 -- private JWK for private_key_jwt, encrypted
  scopes                      TEXT NOT NULL DEFAULT 'openid email profile',
  discovery                   TEXT NOT NULL,        -- JSON: {"mode":"auto"} | {"mode":"manual", authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint?}
  use_userinfo                INTEGER NOT NULL DEFAULT 0,
  trust_email_verified        INTEGER NOT NULL DEFAULT 0,
  claims_map                  TEXT NOT NULL DEFAULT '{}',   -- {"email":"email","email_verified":"email_verified","name":"name"}
  required_claims             TEXT NOT NULL DEFAULT '{}',   -- {"hd":"example.com"} equality checks
  extra_authorize_params      TEXT NOT NULL DEFAULT '{}',
  enabled                     INTEGER NOT NULL DEFAULT 1,
  created_at                  INTEGER NOT NULL,
  updated_at                  INTEGER NOT NULL
);

CREATE TABLE signing_keys (
  kid             TEXT PRIMARY KEY,                 -- RFC 7638 JWK thumbprint (TIO-KEYS-014)
  alg             TEXT NOT NULL CHECK (alg = 'ES256'),
  public_jwk      TEXT NOT NULL,
  private_jwk_enc BLOB,                             -- NULL once retired
  created_at      INTEGER NOT NULL,
  activates_at    INTEGER NOT NULL,                 -- signs from this instant; role is derived (§10.3)
  retired_at      INTEGER
);
CREATE INDEX signing_keys_active ON signing_keys(retired_at, activates_at);

CREATE TABLE invitations (
  id               TEXT PRIMARY KEY,                -- UUID v7
  token_hash       BLOB NOT NULL UNIQUE,
  kind             TEXT NOT NULL CHECK (kind IN ('register','recover')),
  user_id          TEXT REFERENCES users(id) ON DELETE CASCADE,  -- recover: target user
  email            TEXT,
  email_verified   INTEGER NOT NULL DEFAULT 0,
  display_name     TEXT,
  groups           TEXT NOT NULL DEFAULT '[]',
  expires_at       INTEGER NOT NULL,
  used_at          INTEGER,
  used_by_user_id  TEXT,
  created_by       TEXT NOT NULL,                   -- actor id
  created_at       INTEGER NOT NULL
);
CREATE INDEX invitations_expires ON invitations(expires_at);
CREATE INDEX invitations_user    ON invitations(user_id);

CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,                         -- JSON
  updated_at INTEGER NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE audit_hot (
  id          TEXT PRIMARY KEY,                     -- UUID v7 (time-ordered)
  ts          INTEGER NOT NULL,
  type        TEXT NOT NULL,
  outcome     TEXT NOT NULL CHECK (outcome IN ('success','failure')),
  actor_kind  TEXT NOT NULL,
  actor_id    TEXT,
  user_id     TEXT,
  client_id   TEXT,
  upstream    TEXT,
  ip_hash     TEXT,
  data        TEXT NOT NULL                         -- JSON, bounded 4 KB
);
CREATE INDEX audit_hot_ts     ON audit_hot(ts, id);
CREATE INDEX audit_hot_user   ON audit_hot(user_id, ts);
CREATE INDEX audit_hot_client ON audit_hot(client_id, ts);
CREATE INDEX audit_hot_type   ON audit_hot(type, ts);
```

**[TIO-DATA-015]** Every D1 access SHALL go through a repository module under `src/db/` with typed parameters. No SQL string is built by concatenation with request data. Tests grep for `prepare(` outside `src/db/` and fail on any hit (also enforced by a lint rule).

**[TIO-DATA-016]** Every D1 write that must be atomic with another D1 write SHALL use `db.batch()` (which runs as one transaction). Tests cover user creation, group membership change and invitation consumption with injected failures between statements.

**[TIO-DATA-017]** Reads that follow a write in the same request SHALL use the D1 Sessions API (`withSession("first-primary")`) so read-your-writes holds when read replication is enabled. (D1 read replication is in public beta as of this writing; the code path is exercised in tests either way.)

### 4.2 `UserDO` schema

Each user's Durable Object owns one SQLite database. Schema versioning is lazy: on first access after a deploy, `migrate()` runs idempotent steps up to the current version.

```sql
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);                                                  -- schema_version, user_id

CREATE TABLE user (
  id             TEXT PRIMARY KEY,
  email          TEXT,
  email_norm     TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  display_name   TEXT,
  groups         TEXT NOT NULL DEFAULT '[]',        -- JSON array of group names, sorted
  disabled_at    INTEGER,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE TABLE passkeys (
  id              TEXT PRIMARY KEY,
  credential_id   TEXT NOT NULL UNIQUE,
  public_key      BLOB NOT NULL,
  alg             INTEGER NOT NULL,
  counter         INTEGER NOT NULL DEFAULT 0,
  transports      TEXT NOT NULL DEFAULT '[]',
  aaguid          TEXT,
  backup_eligible INTEGER NOT NULL,
  backed_up       INTEGER NOT NULL,
  name            TEXT,
  created_via     TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER
);

CREATE TABLE identities (
  id             TEXT PRIMARY KEY,
  issuer         TEXT NOT NULL,
  subject        TEXT NOT NULL,
  email          TEXT,
  email_verified INTEGER,
  name           TEXT,
  created_at     INTEGER NOT NULL,
  last_login_at  INTEGER,
  UNIQUE (issuer, subject)
);

CREATE TABLE sessions (
  sid                 TEXT PRIMARY KEY,
  secret_hash         BLOB NOT NULL UNIQUE,
  created_at          INTEGER NOT NULL,
  last_seen_at        INTEGER NOT NULL,
  idle_expires_at     INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  auth_time           INTEGER NOT NULL,
  amr                 TEXT NOT NULL,                -- JSON array
  acr                 TEXT NOT NULL,
  upstream            TEXT,                         -- upstream alias when federated
  ip_hash             TEXT,
  ua_family           TEXT,                         -- minimized UA: family/major only
  country             TEXT,
  revoked_at          INTEGER,
  revoke_reason       TEXT
);

CREATE TABLE session_clients (
  sid       TEXT NOT NULL REFERENCES sessions(sid) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  first_at  INTEGER NOT NULL,
  PRIMARY KEY (sid, client_id)
);

CREATE TABLE auth_codes (
  secret_hash     BLOB PRIMARY KEY,
  client_id       TEXT NOT NULL,
  redirect_uri    TEXT NOT NULL,
  scope           TEXT NOT NULL,                    -- space-delimited, validated
  nonce           TEXT,
  code_challenge  TEXT,                             -- NULL when a require_pkce = 0 client sent none
  sid             TEXT NOT NULL,
  auth_time       INTEGER NOT NULL,
  amr             TEXT NOT NULL,
  acr             TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  consumed_at     INTEGER
);
CREATE INDEX auth_codes_expires ON auth_codes(expires_at);

CREATE TABLE refresh_families (
  id                  TEXT PRIMARY KEY,
  client_id           TEXT NOT NULL,
  client_created_at   INTEGER NOT NULL,             -- the client's created_at when the family was created (TIO-CLIENT-005)
  code_secret_hash    BLOB,                         -- the authorization code that created the family, for replay revocation (TIO-TOKEN-012)
  kind                TEXT NOT NULL CHECK (kind IN ('session','offline')),
  sid                 TEXT,                         -- session-bound families
  scope               TEXT NOT NULL,
  auth_time           INTEGER NOT NULL,
  amr                 TEXT NOT NULL,
  acr                 TEXT NOT NULL,
  created_at          INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  idle_expires_at     INTEGER NOT NULL,
  current_serial      INTEGER NOT NULL DEFAULT 1,
  revoked_at          INTEGER,
  revoke_reason       TEXT
);
CREATE INDEX refresh_families_client ON refresh_families(client_id);
CREATE INDEX refresh_families_sid    ON refresh_families(sid);
CREATE INDEX refresh_families_code   ON refresh_families(code_secret_hash);

CREATE TABLE refresh_tokens (
  secret_hash  BLOB PRIMARY KEY,
  family_id    TEXT NOT NULL REFERENCES refresh_families(id) ON DELETE CASCADE,
  serial       INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  consumed_at  INTEGER
);
CREATE INDEX refresh_tokens_family ON refresh_tokens(family_id, serial);

CREATE TABLE grants (
  client_id         TEXT PRIMARY KEY,
  client_created_at INTEGER NOT NULL,               -- the client's created_at when consent was given (TIO-CLIENT-005)
  scopes            TEXT NOT NULL,                  -- JSON array
  granted_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
);
```

**[TIO-DATA-018]** (withdrawn) The per-user `events` ring was removed on 2026-09-19 (Appendix B #31); per-user activity is read from `audit_hot` (TIO-AUDIT-010).

**[TIO-DATA-019]** `UserDO` SHALL purge, on any write and at most once per 60 seconds: expired `auth_codes`; `refresh_tokens` rows consumed more than `refresh_reuse_window` (default 24 h) ago; families expired or revoked more than 24 h ago; sessions expired or revoked more than 24 h ago. Purge never runs on dormant objects (no alarms); logical expiry is always checked on read.

**[TIO-DATA-020]** Every `UserDO` method that changes state SHALL run inside one `transactionSync` (or a single synchronous `sql.exec` sequence with no `await` between statements) so that partial application is impossible. Concurrency tests (§13.6) issue parallel calls and assert exactly-once semantics.

**[TIO-DATA-021]** `UserDO` SHALL refuse every method except `init()` and `destroy()` until `init()` has run, returning `user_not_initialized`; and SHALL refuse every method except `destroy()` after `destroy()`.

### 4.3 `InteractionDO` state

A single JSON document in the SQLite-backed key-value storage, plus an alarm set to `expires_at` that calls `deleteAll()`.

```jsonc
{
  "id": "…",                              // 43-char interaction id
  "kind": "authorize" | "logout" | "par",
  "status": "pushed" | "login_required" | "link_required" | "consent_required" | "ready" | "completed" | "failed",
  "created_at": 0, "expires_at": 0,
  "binding_hash": "<base64 sha256>",      // secret from the __Host-tio_ix_<p> cookie
  "client_id": "…",
  "request": {                            // validated /authorize or /par parameters
    "redirect_uri": "…", "scope": ["openid","email"], "state": "…", "nonce": "…",
    "code_challenge": "…" | null, "prompt": ["login"], "max_age": 3600, "login_hint": "…",
    "ui_locales": "…", "acr_values": []
  },
  "existing_session": { "uid": "…", "sid": "…", "auth_time": 0 } | null,
  "passkey_challenge": { "value": "…", "expires_at": 0, "pending_uid": "…" | null, "invitation_id": "…" | null } | null,
  "federation": { "alias": "…", "state_hash": "…", "nonce": "…", "code_verifier": "…", "expires_at": 0 } | null,
  "link": { "candidate_uid": "…", "alias": "…", "subject": "…", "claims": { "email": "…", "name": "…", "email_verified": true } } | null,
  "auth": { "uid": "…", "method": "passkey" | "federated", "amr": ["…"], "acr": "…", "upstream": "…" | null, "auth_time": 0, "new_session": true } | null,
  "consent": { "scopes": ["…"] } | null,
  "logout": { "sid": "…", "uid": "…", "post_logout_redirect_uri": "…", "state": "…" } | null,
  "error": { "error": "…", "error_description": "…" } | null
}
```

**[TIO-DATA-022]** An interaction SHALL expire 600 seconds after creation (`interaction_ttl`, maximum 900). The alarm SHALL delete all storage at expiry; `completed` and `failed` interactions are deleted 60 seconds after reaching that state. Tests use `runDurableObjectAlarm`.

**[TIO-DATA-023]** Every state transition SHALL be validated against the state machine in §7.2; an invalid transition SHALL fail with `interaction_invalid_state` and leave the document unchanged.

### 4.4 (removed) `ClientDO`

**[TIO-DATA-024]** (withdrawn) The per-client Durable Object holding a `jti` replay cache for `private_key_jwt` was removed on 2026-09-19 (Appendix B #28). Assertions are short-lived instead (TIO-TOKEN-003).

### 4.5 Queue messages and the R2 archive

```jsonc
// TASKS queue message (JSON, ≤ 128 KB)
{ "kind": "audit", "events": [ { …AuditEvent } ] }                   // producer batches up to 50 events per message
{ "kind": "backchannel_logout", "client_id": "…", "uri": "…", "token": "…", "attempt": 1, "sid": "…", "uid": "…" }
```

R2 object key: `audit/<yyyy>/<mm>/<dd>/<hh>/<first_event_id>.ndjson.gz`, one JSON object per line, gzip-compressed, immutable.

**[TIO-DATA-025]** The queue consumer SHALL be idempotent: `audit_hot` inserts use `INSERT OR IGNORE` on the event id, and the R2 key is derived from the batch's first event id so a redelivered batch overwrites an identical object.

### 4.6 Consistency between D1 and Durable Objects

| Operation | Order | On failure of step 2 | Repair |
|---|---|---|---|
| Create user | 1. D1 batch: insert `users` (status `creating`), `identity_index` and/or `group_members` claims. 2. `UserDO.init(profile)`. 3. D1 update status `active`. | Row stays `creating`; invisible. Cron retries `init` for rows older than 60 s and deletes rows older than 1 h. | Cron |
| Add passkey | 1. `UserDO.addPasskey`. 2. D1 insert `passkey_index`. | Retry once; then `UserDO.removePasskey` and fail the request. | Reindex |
| Link identity | 1. D1 insert `identity_index` (claims uniqueness). 2. `UserDO.addIdentity`. | D1 row deleted; request fails. | Reindex |
| Unlink identity / remove passkey | 1. `UserDO` remove. 2. D1 delete. | Retry; orphan index row is harmless (lookup hits DO, DO says unknown → treated as not found and deleted lazily). | Lazy + reindex |
| Update profile / groups / disable | 1. `UserDO` write. 2. D1 mirror write. | Reported as `partial_failure`; audit records both outcomes. | Reindex |
| Delete user | 1. D1 status `deleting`. 2. `UserDO.destroy()`. 3. D1 delete rows. | Cron finishes deletion. | Cron |

**[TIO-DATA-026]** A D1 index row whose `UserDO` does not confirm the referenced record SHALL be treated as absent and deleted lazily by the code path that discovered it. Tests create the inconsistency directly and assert both the outcome and the cleanup.

**[TIO-DATA-027]** `POST /api/v1/admin/users/{id}/reindex` SHALL rebuild that user's `users` mirror, `passkey_index`, `identity_index` and `group_members` rows from `UserDO` state. `POST /api/v1/admin/maintenance/reindex` SHALL walk `users` in id order in batches of 100 and do the same, resumable by cursor.

### 4.7 Retention

| Data | Retention | Mechanism |
|---|---|---|
| Interactions | ≤ 15 min | DO alarm `deleteAll` |
| Authorization codes | 60 s + lazy purge | `UserDO` purge |
| Consumed refresh tokens | `refresh_reuse_window` (24 h) | `UserDO` purge |
| Expired/revoked families and sessions | 24 h after expiry | `UserDO` purge |
| `audit_hot` | `audit.hot_retention_days` (30) | Cron, 1,000 rows per run per iteration, bounded to 10 iterations |
| R2 archive | Indefinite (bucket lifecycle rule is the operator's choice) | — |
| Invitations | Deleted 30 days after expiry or use | Cron |
| Retired signing keys | Row kept 90 days with `private_jwk_enc = NULL`, then deleted | Cron |
| `users` rows in `creating` | 1 h | Cron |

---
## 5. Protocol surface: OIDC and OAuth 2.0

### 5.1 Endpoint map

| Method | Path | Purpose | Auth | CORS |
|---|---|---|---|---|
| GET | `/.well-known/openid-configuration` | OIDC discovery | none | `*` |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 metadata (same document) | none | `*` |
| GET | `/.well-known/jwks.json` | Public signing keys | none | `*` |
| GET | `/.well-known/webauthn` | WebAuthn Related Origins | none | `*` |
| GET, POST | `/authorize` | Authorization endpoint | browser | — |
| POST | `/par` | Pushed authorization request | client | `*` |
| POST | `/token` | Token endpoint | client | `*` |
| GET, POST | `/userinfo` | UserInfo | bearer | `*` |
| POST | `/revoke` | Token revocation | client | `*` |
| GET, POST | `/logout` | RP-initiated logout | browser | — |
| GET, POST | `/federation/callback` | Upstream callback | browser | — |
| GET | `/interactions/{id}/complete` | Finalize an interaction (top-level navigation) | browser | — |
| GET | `/api/v1/openapi.json` | OpenAPI 3.1 for the JSON APIs | none | `*` |
| GET | `/api/v1/health` | Health | none | `*` |
| * | `/api/v1/interactions/...` | Interaction API (§7) | login-app origin + binding cookie | login origins |
| * | `/api/v1/me/...` | Self-service API (§8) | bearer, scope `account` | `*` |
| * | `/api/v1/admin/...` | Admin API (§9) | bearer, scope `admin` | `*` |

**[TIO-HTTP-001]** Every path not listed SHALL return 404 with `{"error":"not_found"}`. Every listed path with an unlisted method SHALL return 405 with an `Allow` header.

### 5.2 Discovery

**[TIO-DISC-001]** `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` SHALL return the same JSON document, built from `ISSUER` and the effective settings, with `Cache-Control: public, max-age=300`.

**[TIO-DISC-002]** The document SHALL advertise only features the OP implements. Every advertised list (`scopes_supported`, `response_types_supported`, `response_modes_supported`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `token_endpoint_auth_signing_alg_values_supported`, `code_challenge_methods_supported`, `claims_supported`, `acr_values_supported`, and the accepted `prompt` values) SHALL be generated from one constant in `src/oidc/capabilities.ts`, which the validators in §5.4 and §5.6 also import. The conformance run (§13.9) and a test comparing the document against the router's route table both enforce this.

**[TIO-DISC-004]** A test SHALL deep-equal every array in the discovery document to the `capabilities.ts` constant, and the lint rules (TIO-TEST-060) SHALL forbid literal arrays of scopes, grant types, response types, client authentication methods, algorithms or `prompt` values anywhere else in `src/`.

Reference document:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "pushed_authorization_request_endpoint": "https://auth.example.com/par",
  "require_pushed_authorization_requests": false,
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "revocation_endpoint": "https://auth.example.com/revoke",
  "end_session_endpoint": "https://auth.example.com/logout",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email", "groups", "offline_access", "account", "admin"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported": ["ES256", "ES384", "EdDSA", "PS256", "RS256"],
  "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid", "at_hash",
                       "name", "updated_at", "email", "email_verified", "groups"],
  "claims_parameter_supported": false,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "authorization_response_iss_parameter_supported": true,
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true,
  "frontchannel_logout_supported": false,
  "acr_values_supported": ["urn:tinyoidc:acr:passkey", "urn:tinyoidc:acr:federated"],
  "ui_locales_supported": [],
  "service_documentation": "https://github.com/…/tiny-oidc/blob/main/doc/TINY_OIDC_SPEC.md"
}
```

**[TIO-DISC-003]** `request_uri_parameter_supported` SHALL be `false` (JAR request URIs are not accepted). PAR-issued `request_uri` values are accepted regardless, per RFC 9126 §5.

### 5.3 JWKS

**[TIO-KEYS-001]** `/.well-known/jwks.json` SHALL publish the public JWK of every unretired key (`retired_at IS NULL`, that is the signing key, keys not yet active, and superseded keys still verifying), each with `kid`, `kty: "EC"`, `crv: "P-256"`, `alg: "ES256"`, `use: "sig"`, and nothing else. Private parameters (`d`) SHALL never appear. A test asserts the response contains no `d` member under any key-rotation state.

**[TIO-KEYS-002]** The JWKS response SHALL carry `Cache-Control: public, max-age=300` and be served from the Worker cache when present.

### 5.4 Authorization endpoint

```text
GET /authorize?client_id&redirect_uri&response_type=code&scope&state&code_challenge&code_challenge_method=S256
              [&nonce&prompt&max_age&login_hint&ui_locales&acr_values]
GET /authorize?client_id&request_uri=urn:ietf:params:oauth:request_uri:…
POST /authorize  (application/x-www-form-urlencoded, the same parameters in the body)
```

**Validation order.** The order matters because it determines whether an error may be redirected to the client.

1. **[TIO-AUTHZ-001]** Method SHALL be GET or POST (OIDC Core §3.1.2.1). Query string SHALL be ≤ 8 KB. A POST SHALL carry `application/x-www-form-urlencoded` (anything else is non-redirectable `invalid_request`) and its parameters are read from the body, as `/logout` does. Duplicate parameters SHALL be rejected (`invalid_request`).
2. **[TIO-AUTHZ-002]** `client_id` SHALL be present and refer to an enabled client with `authorization_code` in `grant_types`. Otherwise the error is non-redirectable.
3. **[TIO-AUTHZ-003]** If `request_uri` is present, it SHALL be a PAR reference issued to this `client_id`, unexpired and unconsumed; all other query parameters except `client_id` SHALL be absent. The stored parameters replace the query. A consumed or unknown `request_uri` is non-redirectable `invalid_request`.
4. **[TIO-AUTHZ-004]** If the client has `require_par = 1` and no `request_uri` is present, the error SHALL be non-redirectable `invalid_request`.
5. **[TIO-AUTHZ-005]** `redirect_uri` SHALL be present and SHALL match one registered URI by the rules in §5.11.3. Otherwise non-redirectable `invalid_request`. From here on errors are redirected to `redirect_uri`.
6. **[TIO-AUTHZ-006]** `response_type` SHALL equal `code`; else `unsupported_response_type`.
7. **[TIO-AUTHZ-007]** `state` SHALL be present, 1–2048 characters, printable ASCII; else `invalid_request`.
8. **[TIO-AUTHZ-008]** `code_challenge` SHALL be present when the client has `require_pkce = 1` (every public client; the default). When present, it SHALL be 43–128 characters of `[A-Za-z0-9._~-]` and `code_challenge_method` SHALL equal `S256`; a missing method, `plain`, or a method without a challenge is `invalid_request`. A `require_pkce = 0` client may omit both, and the code is then issued without a challenge (§5.6.2). The exemption exists because the OpenID Foundation conformance suite sends no PKCE in its certification plans (§13.9); it is a registered, audited client property, never a test-only path.
9. **[TIO-AUTHZ-009]** `scope` SHALL be present, contain `openid`, contain only scopes in `scopes_supported` and in the client's `scopes_allowed`, with no duplicates; else `invalid_scope`. `admin` SHALL additionally require the user to be in `admins` at authentication time (checked in step 14).
10. **[TIO-AUTHZ-010]** `nonce`, if present, SHALL be 1–512 characters. `login_hint` ≤ 256, `ui_locales` ≤ 64, `acr_values` ≤ 256 characters; each is passed to the login app verbatim and never interpreted by the OP except that `acr_values` is echoed.
11. **[TIO-AUTHZ-011]** `prompt`, if present, SHALL be a space-separated subset of `none`, `login`, `consent`, `select_account`; `none` SHALL NOT be combined with others; else `invalid_request`. `select_account` is treated as `login`.
12. **[TIO-AUTHZ-012]** `max_age`, if present, SHALL be a non-negative integer; else `invalid_request`.
13. **[TIO-AUTHZ-013]** (withdrawn) RFC 8707 resource indicators were deferred on 2026-09-19 (Appendix B #29). A `resource` parameter is ignored like any other unrecognized parameter (RFC 6749 §3.1); the audience comes from the client record (TIO-TOKEN-033).
14. **Session evaluation.** Decrypt `__Host-tio_session` if present; call `UserDO.authorizeWithSession`. The session is usable when it exists, is not revoked or expired, the user is not disabled, the user satisfies `allowed_groups`, and (`max_age` absent or `auth_time + max_age > now`), and `prompt` does not contain `login`. Consent is satisfied when `skip_consent = 1` or the stored grant covers the requested scopes and `prompt` does not contain `consent`.
    - **[TIO-AUTHZ-014]** Usable session and consent satisfied → issue code and redirect (§5.4.2). No interaction is created.
    - **[TIO-AUTHZ-015]** `prompt=none` and anything is missing → redirect with `login_required` (no or unusable session), `consent_required` (consent missing) or `interaction_required` (other), never an interaction. The existing session, if any, SHALL remain untouched: an RP cannot end or shorten a session by probing with `prompt=none`.
    - **[TIO-AUTHZ-016]** Otherwise create an interaction (§7) with `existing_session` set when the session is usable, and respond `303` to `login_url` with `?interaction=<id>`, setting the binding cookie.
    - **[TIO-AUTHZ-017]** A user who fails `allowed_groups` with a usable session → redirect with `access_denied` and `error_description=user_not_allowed`; without a session the check happens after authentication and produces the same redirect through `/complete`.

**Non-redirectable errors.** **[TIO-AUTHZ-018]** When the client or redirect URI cannot be trusted, the OP SHALL respond `303` to `login_url` with `error` and `error_description` query parameters and no interaction id, so the login app can render the failure. It SHALL NOT redirect to the supplied `redirect_uri`, SHALL NOT return HTML, and SHALL NOT echo the untrusted `redirect_uri` anywhere in the response.

**Redirectable errors.** **[TIO-AUTHZ-019]** The OP SHALL redirect with `error`, optional `error_description` (ASCII, no secrets), `state` and `iss`. Status `303`.

#### 5.4.1 `login_url` handoff

**[TIO-AUTHZ-020]** The redirect to the login app SHALL be `303 See Other` to `login_url` with exactly one added query parameter `interaction`, plus `Set-Cookie: __Host-tio_ix_<p>=<tio_ix handle>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<interaction_ttl>` where `<p>` is the first 16 characters of the interaction id. The response SHALL carry `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

#### 5.4.2 Successful response

**[TIO-AUTHZ-021]** The OP SHALL redirect `303` to `redirect_uri` with `code`, `state` and `iss` (RFC 9207), appended to the existing query string without altering registered components. No other parameters. `Cache-Control: no-store`.

**[TIO-AUTHZ-022]** The authorization code SHALL be a `tio_ac` handle with `expires_at = now + 60`, bound to `client_id`, `redirect_uri`, `scope`, `nonce`, `code_challenge`, `sid`, `auth_time`, `amr`, `acr`.

**[TIO-AUTHZ-023]** Issuing a code SHALL record `(sid, client_id)` in `session_clients` and touch `last_seen_at` and `idle_expires_at` of the session.

**[TIO-AUTHZ-024]** A code SHALL bind exactly the `scope`, `nonce`, `redirect_uri`, `code_challenge` and `state` of the request that produced it. A session hit SHALL never reuse any parameter from an earlier request or from the interaction that created the session, and `prompt` and `max_age` SHALL never be persisted anywhere except inside the interaction that carried them. Two tests name this bug class: two `/authorize` requests on one session with different `nonce` and `code_challenge` produce a second code that redeems only with the second verifier and an ID token carrying the second `nonce`; an interaction started with `prompt=login` followed by a bare `/authorize` on the resulting session is a session hit, never a login loop.

### 5.5 Pushed Authorization Requests (RFC 9126)

**[TIO-PAR-001]** `POST /par` SHALL accept `application/x-www-form-urlencoded` with the same parameters as `/authorize` (except `request_uri`, which is `invalid_request`), authenticate the client as the token endpoint does (§5.6.1; public clients send `client_id` only), run validation steps 1–13, and respond `201` with `{"request_uri":"urn:ietf:params:oauth:request_uri:<id>","expires_in":60}`.

**[TIO-PAR-002]** Errors SHALL be returned as JSON with the same error codes as `/authorize` and status 400 (401 for failed client authentication). Nothing is ever redirected from `/par`.

**[TIO-PAR-003]** A `request_uri` SHALL be single-use and expire after 60 seconds. The stored request is an `InteractionDO` document with `status: "pushed"`; `/authorize` transitions it.

**[TIO-PAR-004]** `/par` SHALL be rate-limited per client id (§6.7).

### 5.6 Token endpoint

#### 5.6.1 Common rules

**[TIO-TOKEN-001]** `POST /token` SHALL accept only `application/x-www-form-urlencoded` bodies ≤ 16 KB. Any other content type is `invalid_request`. Duplicate parameters are `invalid_request`.

**[TIO-TOKEN-002]** Client authentication SHALL be determined by the registered `token_endpoint_auth_method` and SHALL be enforced strictly: a `none` client SHALL send `client_id` in the body and no credentials; a `client_secret_basic` client SHALL send an HTTP Basic header (secret compared by SHA-256 in constant time) and SHALL NOT be accepted with `client_secret` in the body; a `client_secret_post` client SHALL send `client_id` and `client_secret` in the body and SHALL NOT be accepted with an `Authorization` header; a `private_key_jwt` client SHALL send `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`. Mixed or mismatched methods are `invalid_client` (401 with `WWW-Authenticate: Basic realm="tiny-oidc"` for basic).

**[TIO-TOKEN-003]** A `private_key_jwt` assertion SHALL be verified with the client's registered `jwks` or `jwks_uri` (fetched with a 5 s timeout, cached 1 h, refetched once on unknown `kid`), and SHALL satisfy: `alg` ∈ {ES256, ES384, EdDSA, PS256, RS256} and not `none`; `iss = sub = client_id`; `aud` equals `ISSUER` or the token endpoint URL; `iat` present, no more than 60 s in the past and no more than 60 s in the future; `exp` present and no more than 60 s after `now`; `jti` present and ≤ 255 chars. Assertions are not stored: a replay inside the 60-second window is accepted by design (Appendix B #28), which is why the window is short and `iat` is mandatory. Each failing condition is a separate test.

**[TIO-TOKEN-004]** Client credentials SHALL never be logged, and a failed client authentication SHALL be rate-limited per client id and per IP.

**[TIO-TOKEN-005]** Successful responses SHALL be `200` JSON with `Cache-Control: no-store` and `Pragma: no-cache`. Error responses SHALL follow RFC 6749 §5.2 with status 400, except `invalid_client` (401) and storage failures (503 `temporarily_unavailable`).

**[TIO-TOKEN-006]** (withdrawn) Resource indicators on the token endpoint were deferred with TIO-AUTHZ-013; a `resource` parameter is ignored.

#### 5.6.2 `grant_type=authorization_code`

Parameters: `code`, `redirect_uri`, `code_verifier`, `client_id` (public clients).

**[TIO-TOKEN-010]** The OP SHALL decrypt `code` as a `tio_ac` handle; any malformed code is `invalid_grant` with no storage access.

**[TIO-TOKEN-011]** `UserDO.exchangeCode` SHALL, atomically: find the code by secret hash; reject if absent, expired or consumed; reject if `client_id` differs; reject if `redirect_uri` differs byte-for-byte from the bound value; when the code binds a `code_challenge`, reject if `code_verifier` is absent or `BASE64URL(SHA-256(code_verifier)) ≠ code_challenge` (`code_verifier` 43–128 chars of the PKCE alphabet); when it binds none (a `require_pkce = 0` client that sent no challenge), reject if a `code_verifier` is present at all; reject if the user is disabled, the session is revoked, or `allowed_groups` no longer holds; then mark the code consumed. Every rejection is `invalid_grant`.

**[TIO-TOKEN-012]** Presenting an already-consumed code SHALL, in addition to `invalid_grant`, revoke every refresh family created from that code (RFC 6749 §4.1.2 replay handling) and emit `token.code_replay`.

**[TIO-TOKEN-013]** On success the OP SHALL issue an ID token (§5.7.1), an access token (§5.7.2), and, when the client has `refresh_token` in `grant_types`, a refresh token (§5.7.3). Response: `access_token`, `token_type: "Bearer"`, `expires_in`, `id_token`, `refresh_token` (if issued), `scope` (always, space-delimited).

**[TIO-TOKEN-014]** A refresh family created from a code SHALL be `kind = "offline"` when `offline_access` was granted and the client has `offline_access = 1`; otherwise `kind = "session"` bound to `sid`. `offline_access` requested by a client without `offline_access = 1` is `invalid_scope` at `/authorize`.

#### 5.6.3 `grant_type=refresh_token`

Parameters: `refresh_token`, `client_id` (public), optional `scope` (subset).

**[TIO-RT-001]** The OP SHALL decrypt `refresh_token` as a `tio_rt` handle; malformed tokens are `invalid_grant` with no storage access.

**[TIO-RT-002]** `UserDO.rotateRefreshToken` SHALL, atomically: load the family; reject if absent, revoked, past `absolute_expires_at` or past `idle_expires_at`; reject if `client_id` differs; find the token by secret hash within the family; if the token is **consumed**: revoke the family (`reason = "reuse"`), revoke the bound session if `kind = "session"`, emit `token.refresh_reuse`, and reject; if the token's `serial ≠ current_serial`: reject; reject if the user is disabled, `allowed_groups` fails, or (`kind = "session"` and the session is revoked or expired); then mark the token consumed, increment `current_serial`, insert the next token, set `idle_expires_at = now + refresh_idle_ttl` (capped by `absolute_expires_at`), touch the bound session, and return the new secret with the family's claims. All rejections are `invalid_grant`.

**[TIO-RT-003]** Two concurrent presentations of the same valid refresh token SHALL result in exactly one success; the other SHALL observe the consumed state and trigger family revocation. This is the canonical concurrency test.

**[TIO-RT-004]** A `scope` parameter SHALL narrow the family scope for the issued tokens only; it SHALL NOT widen it (`invalid_scope`), and the family keeps its original scope.

**[TIO-RT-005]** The refresh response SHALL contain a new `id_token` only when the family scope includes `openid` (always true for families created from a code) and SHALL carry the original `auth_time`, `amr`, `acr` and `sid`; `nonce` is omitted.

**[TIO-RT-006]** Session-bound families SHALL be revoked whenever their session ends (logout, revocation, idle or absolute expiry). Offline families survive logout and end only by expiry, revocation, reuse detection, user disable, or client disable.

#### 5.6.4 `grant_type=client_credentials`

**[TIO-TOKEN-020]** `client_credentials` SHALL be accepted only from clients with `client_credentials` in `grant_types` and `token_endpoint_auth_method ≠ none`. Requested `scope` SHALL be a subset of `scopes_allowed` excluding `openid`, `profile`, `email`, `groups`, `offline_access`, `account`; `admin` is allowed only when the client has it in `scopes_allowed`.

**[TIO-TOKEN-021]** The response SHALL contain an access token with `sub = client_id`, no ID token and no refresh token. `aud` follows [TIO-TOKEN-033]; `admin` scope forces `aud` to include `ISSUER`.

### 5.7 Tokens

#### 5.7.1 ID token

**[TIO-TOKEN-030]** ID tokens SHALL be JWS-signed JWTs with header `{"alg":"ES256","typ":"JWT","kid":"<active kid>"}` and claims:

| Claim | Value |
|---|---|
| `iss` | `ISSUER` |
| `sub` | user id |
| `aud` | `client_id` (string) |
| `exp` | `iat + id_token_ttl` (default 600 s) |
| `iat` | now |
| `auth_time` | session authentication time |
| `nonce` | echoed when the request had one |
| `acr` | `urn:tinyoidc:acr:passkey` or `urn:tinyoidc:acr:federated` |
| `amr` | passkey: `["hwk","user"]` when `backup_eligible = 0`, else `["swk","user"]`; federated: `["fed"]` (RFC 8176 values; `fed` is a documented local value) |
| `sid` | session id |
| `at_hash` | left-most 128 bits of SHA-256 of the access token, base64url |
| `name`, `updated_at` | with scope `profile`, when present |
| `email`, `email_verified` | with scope `email`, when email present |
| `groups` | with scope `groups`: sorted group names |

**[TIO-TOKEN-031]** Claims with null values SHALL be omitted, never emitted as `null`. `email_verified` is emitted only alongside `email`.

#### 5.7.2 Access token (RFC 9068)

**[TIO-TOKEN-032]** Access tokens SHALL be JWTs with header `{"alg":"ES256","typ":"at+jwt","kid":…}` and claims `iss`, `sub`, `aud`, `exp` (`iat + access_token_ttl`, default 600 s, client override 60–3600 s), `iat`, `jti` (UUID v7), `client_id`, `scope` (space-delimited), and, for user tokens, `sid` (session families only), `auth_time`, `acr`, `amr`, plus `groups` when the `groups` scope is present.

**[TIO-TOKEN-033]** `aud` SHALL be the client's `audiences` list when it is non-empty, else `[client_id]`. When the scope includes `account` or `admin`, `ISSUER` SHALL be added. `aud` is a string when it has one member and an array otherwise.

**[TIO-TOKEN-034]** The OP SHALL accept its own access tokens on `/userinfo`, `/api/v1/me/*` and `/api/v1/admin/*` only when `aud` contains `ISSUER` (for `/userinfo`, `aud` containing the client id is also sufficient per OIDC Core), the signature verifies against a key in `active` or `retiring` state, `iss` matches, `exp` is in the future with 0 s leeway, and `typ` is `at+jwt`.

#### 5.7.3 Refresh token

**[TIO-RT-010]** Refresh tokens SHALL be `tio_rt` handles. Family lifetimes: `session` kind → `absolute_expires_at = session.absolute_expires_at`, `idle_expires_at = min(now + refresh_idle_ttl, absolute)`; `offline` kind → `absolute = now + refresh_token_ttl` (default 30 d, max 90 d), `idle = now + refresh_idle_ttl` (default 14 d).

#### 5.7.4 Lifetimes

| Item | Default | Bounds | Configurable by |
|---|---|---|---|
| Authorization code | 60 s | fixed | — |
| PAR `request_uri` | 60 s | fixed | — |
| Interaction | 600 s | ≤ 900 s | setting |
| Passkey challenge | 300 s | fixed | — |
| Access token | 600 s | 60–3600 s | setting, client |
| ID token | 600 s | 60–3600 s | setting, client |
| Refresh idle | 14 d | 1 h–30 d | setting, client |
| Refresh absolute (offline) | 30 d | 1 d–90 d | setting, client |
| Session idle | 24 h | 15 min–30 d | setting |
| Session absolute | 30 d | 1 h–365 d | setting |
| Invitation | 7 d | 1 h–90 d | per invitation |
| Logout token | 120 s | fixed | — |
| Consumed refresh-token retention | 24 h | 1–72 h | setting |

#### 5.7.5 Logout token (back-channel)

**[TIO-LOGOUT-010]** Logout tokens SHALL be ES256 JWTs with header `typ: "logout+jwt"` and claims `iss`, `sub`, `aud` (client id), `iat`, `exp = iat + 120`, `jti`, `sid`, `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`, and SHALL NOT contain `nonce`.

### 5.8 UserInfo

**[TIO-UINFO-001]** `/userinfo` SHALL accept GET and POST with `Authorization: Bearer <at+jwt>` (form-body `access_token` on POST is also accepted; query-string tokens are rejected). The token is validated per [TIO-TOKEN-034]; failures return 401 with `WWW-Authenticate: Bearer error="invalid_token"` and no body details.

**[TIO-UINFO-002]** The response SHALL be built from the current `UserDO` profile (not from the token), include `sub`, and include only claims permitted by the token's `scope`. A disabled user yields 401 `invalid_token`.

**[TIO-UINFO-003]** `client_credentials` tokens (no user) SHALL be rejected with 401 `invalid_token`.

### 5.9 Revocation (RFC 7009)

**[TIO-REV-001]** `POST /revoke` SHALL authenticate the client as `/token` does, accept `token` and optional `token_type_hint`, and return `200` with an empty body for every syntactically acceptable request, including unknown or already-revoked tokens.

**[TIO-REV-002]** A `tio_rt` handle belonging to the authenticated client SHALL revoke its entire family (`reason = "client_revoke"`). A token belonging to a different client SHALL be ignored (200, no effect, `token.revoke_foreign` audit event).

**[TIO-REV-003]** An access token presented for revocation SHALL be accepted (200) and, if it carries `sid` and the client matches, SHALL revoke the session-bound family for that client; JWT access tokens cannot otherwise be revoked before expiry and the documentation says so.

### 5.10 Logout

#### 5.10.1 RP-initiated logout

```text
GET|POST /logout?[id_token_hint][&post_logout_redirect_uri][&state][&client_id][&ui_locales]
```

**[TIO-LOGOUT-001]** `id_token_hint`, when present, SHALL be verified for signature (any key in `active` or `retiring`; a `retired` key fails), `iss`, and `aud` naming a known client; `exp` is ignored. A hint that fails verification is `invalid_request` rendered through `login_url?error=…` (no redirect to any client).

**[TIO-LOGOUT-002]** `post_logout_redirect_uri`, when present, SHALL match exactly one of the client's `post_logout_redirect_uris` (client from the hint, or from `client_id` when both present and consistent). Otherwise it is ignored and the OP redirects to `logout_landing_url` (setting; defaults to `login_url?event=logged_out`).

**[TIO-LOGOUT-003]** With a valid hint: if a session cookie is present and its `sid` equals the hint's `sid`, the OP SHALL end that session; otherwise the OP SHALL end the hinted session in `UserDO(hint.sub)` if it still exists, and leave the current browser session untouched. Then clear the session cookie only when it referred to the ended session, and redirect `303` with `state` echoed.

**[TIO-LOGOUT-004]** Without a hint: if no session cookie is present, redirect to the landing URL immediately. If a session is present, create a `logout` interaction (§7.6) and redirect to `login_url?interaction=<id>` for confirmation. The session SHALL NOT be ended without a valid hint or an explicit confirmation.

**[TIO-LOGOUT-005]** Ending a session SHALL, in one `UserDO` transaction, set `revoked_at`, revoke all `session` families bound to it, and return the list of `session_clients`; the OP then sends back-channel logout to each client with a `backchannel_logout_uri`.

#### 5.10.2 Back-channel logout

**[TIO-LOGOUT-011]** For each client in the ended session with a `backchannel_logout_uri`, the OP SHALL POST `logout_token=<jwt>` as `application/x-www-form-urlencoded` with a 5 s timeout, using `ctx.waitUntil`. Non-2xx or timeout enqueues a `backchannel_logout` task with `attempt = 1`.

**[TIO-LOGOUT-012]** The queue consumer SHALL retry at most 5 times with delays 30 s, 2 min, 10 min, 30 min, 2 h, then emit `logout.backchannel_failed`. The same `jti` is reused across retries; clients MAY deduplicate on it.

**[TIO-LOGOUT-013]** Back-channel logout SHALL also be triggered by session revocation through the Self-service and Admin APIs and by user disable/delete.

### 5.11 Clients

#### 5.11.1 Fields and validation

**[TIO-CLIENT-001]** A client SHALL be created and updated only through the Admin API or bulk configuration (§9.4); there is no public dynamic registration.

**[TIO-CLIENT-002]** Validation rules (each a test):
- `redirect_uris`: 1–32 entries, each valid per §5.11.3, no duplicates; required when `authorization_code` ∈ `grant_types`; must be empty otherwise.
- `post_logout_redirect_uris`: 0–32 entries, same URI rules.
- `backchannel_logout_uri`: `https` absolute URL, no fragment.
- `grant_types`: non-empty subset of `authorization_code`, `refresh_token`, `client_credentials`; `refresh_token` requires `authorization_code`.
- `token_endpoint_auth_method`: `none` requires `grant_types = ["authorization_code"]` or `["authorization_code","refresh_token"]`; `client_credentials` requires `client_secret_basic`, `client_secret_post` or `private_key_jwt`.
- `require_pkce`: defaults to `1`; `0` requires `token_endpoint_auth_method ≠ none` (a public client's only binding is PKCE, TIO-AUTHZ-008).
- `client_secret_basic` and `client_secret_post` require a generated secret (§5.11.1 below); `private_key_jwt` requires exactly one of `jwks` (≤ 8 keys, each a public EC/RSA/OKP key with `kid`) or `jwks_uri` (`https`).
- `scopes_allowed`: non-empty subset of `scopes_supported`; `admin` may be granted only by an actor that itself holds `admin`.
- `audiences`: 0–16 entries, each an absolute `https` URI or URN without fragment, no duplicates, never equal to `ISSUER` (which is added by scope, not configured).
- `allowed_groups`: `null` or an array of existing group names.
- TTL overrides within the bounds of §5.7.4.

**[TIO-CLIENT-003]** A client secret SHALL be 32 random bytes, base64url, returned exactly once in the create or rotate response, and stored as SHA-256. Rotation replaces the secret immediately; clients that need zero-downtime rotation use `private_key_jwt` with several keys in `jwks`.

**[TIO-CLIENT-004]** Disabling a client SHALL cause every grant, PAR, token and refresh operation for it to fail within the cache window, and SHALL revoke all of its refresh families lazily on next use (a family whose client is disabled is `invalid_grant`). Deletion follows [TIO-CLIENT-005].

**[TIO-CLIENT-005]** Deleting a client SHALL write no `UserDO`. Consent grants and refresh families store the client's `created_at` (`client_created_at`) when they are created; every read that resolves one (`authorizeWithSession`, `exchangeCode`, `rotateRefreshToken`, `/me/grants`, `/admin/users/{id}/grants`, `/admin/users/{id}/refresh-families`) receives the current client record from the caller and SHALL treat a record whose client is unknown, or whose `client_created_at` differs from the client's `created_at` (the id was deleted and re-created), as absent and delete it on discovery, in the TIO-DATA-026 pattern. Tests delete a client, re-create it under the same id, and assert that the old consent does not apply and the old families are `invalid_grant`.

#### 5.11.2 Client types

| Type | `token_endpoint_auth_method` | Typical use | Notes |
|---|---|---|---|
| Public | `none` | SPAs, native and mobile apps, CLIs | PKCE is the only binding. Refresh tokens are session-bound unless `offline_access = 1`. |
| Confidential (secret) | `client_secret_basic` or `client_secret_post` | Server-side web apps that cannot hold a key | Secret hashed; rotate via API. `client_secret_post` exists for clients and conformance profiles that require it; `client_secret_basic` is preferred. |
| Confidential (key) | `private_key_jwt` | Server-side web apps, service clients, admin automation | Preferred. Assertions live 60 seconds; rotate keys by publishing several in `jwks`. |

#### 5.11.3 Redirect URI rules

**[TIO-CLIENT-010]** A registered redirect URI SHALL be an absolute URI with no fragment and one of: (a) scheme `https`, host non-empty, not an IP literal; (b) scheme `http`, host exactly `127.0.0.1` or `[::1]`, any port (loopback interface, RFC 8252 §7.3); (c) a private-use scheme containing at least one `.` in the scheme (reverse-DNS, RFC 8252 §7.1), for example `com.example.app:/oauth2/callback`. `http://localhost` is rejected. Wildcards are rejected.

**[TIO-CLIENT-011]** Matching at `/authorize` SHALL be exact, byte-for-byte on the normalized-once registered string, with a single exception: for loopback URIs the port in the request MAY differ from the registered port. No prefix, suffix, case-folding, trailing-slash or query-string tolerance. Tests cover each tolerance as a negative case.

### 5.12 Scopes and claims

| Scope | Claims in ID token and UserInfo | Effect on access token |
|---|---|---|
| `openid` | `sub` and the standard claims | required |
| `profile` | `name`, `updated_at` | — |
| `email` | `email`, `email_verified` | — |
| `groups` | `groups` | `groups` claim included |
| `offline_access` | — | family becomes `offline` (client must allow) |
| `account` | — | `aud` includes `ISSUER`; unlocks Self-service API |
| `admin` | — | `aud` includes `ISSUER`; unlocks Admin API; user must be in `admins` |

**[TIO-SCOPE-001]** Unknown scopes SHALL be rejected (`invalid_scope`), never silently dropped.

**[TIO-SCOPE-002]** The `admin` scope SHALL be granted to a user only if the user is a member of `admins` at authentication time and at each refresh; membership loss revokes admin families on next refresh (`invalid_grant`).

### 5.13 Error model

**[TIO-ERR-001]** Every JSON error SHALL have the shape `{"error": "<code>", "error_description": "<ascii, ≤ 256 chars>", "request_id": "<uuid>"}`. `error_description` SHALL never contain user data, secrets, SQL, stack traces or storage identifiers.

OAuth error codes used: `invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`, `unauthorized_client`, `unsupported_grant_type`, `unsupported_response_type`, `access_denied`, `login_required`, `consent_required`, `interaction_required`, `server_error`, `temporarily_unavailable`. Product API codes are listed in §7–§9.

**[TIO-ERR-002]** Responses to invalid credentials, unknown users, unknown codes and unknown tokens SHALL be indistinguishable in status, body and headers from each other within the same endpoint. Tests compare responses field by field.

### 5.14 HTTP conventions

**[TIO-HTTP-002]** Every response SHALL carry: `Cache-Control: no-store` (except discovery, JWKS, related origins and OpenAPI), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `Permissions-Policy: publickey-credentials-get=(), publickey-credentials-create=()` on non-API responses, `X-Request-Id`. A header matrix test asserts these per route.

**[TIO-HTTP-003]** CORS: `/token`, `/par`, `/revoke`, `/userinfo`, `/.well-known/*`, `/api/v1/openapi.json`, `/api/v1/health`, `/api/v1/me/*`, `/api/v1/admin/*` SHALL answer preflights with `Access-Control-Allow-Origin: *`, no credentials, allowed methods per route, allowed headers `Authorization, Content-Type`, `Access-Control-Max-Age: 600`. `/api/v1/interactions/*` SHALL reflect the request `Origin` only when it is in `login_origins`, with `Access-Control-Allow-Credentials: true`. Browser-navigation endpoints (`/authorize`, `/logout`, `/federation/callback`, `/interactions/{id}/complete`) SHALL have no CORS headers.

**[TIO-HTTP-004]** Request bodies SHALL be limited to 16 KB on protocol endpoints, 64 KB on JSON APIs, and 8 MB on `/api/v1/admin/import/*`; larger bodies are 413.

**[TIO-HTTP-005]** Every request SHALL be assigned a UUID v7 request id, returned in `X-Request-Id`, included in every log line and error body.

**[TIO-HTTP-006]** The OP SHALL reject any request whose `Host` does not match the `ISSUER` host with 421, and SHALL never build a URL from the request `Host` header. The only exception is `GET /api/v1/health`, which answers on any host and reports `"issuer_mismatch": "<observed host>"` when the host differs, so that a fresh deployment with a wrong `ISSUER` is diagnosable.

---
## 6. Authentication

### 6.1 Passkeys (WebAuthn)

Passkeys are the only local credential. A passkey with user verification is inherently two-factor (possession of the authenticator plus biometric or PIN), phishing-resistant, and has no shared secret to leak. The OP therefore has no second factor, no lockout table and no password reset.

#### 6.1.1 Relying-party configuration

| Setting | Meaning |
|---|---|
| `RP_ID` (env) | The WebAuthn RP ID, e.g. `example.com`. Must be a registrable domain that is equal to or a parent of every WebAuthn origin's host. |
| `RP_NAME` (env) | Human name shown by authenticators. |
| `webauthn_origins` (setting) | Origins allowed to run ceremonies: the login app origins plus any first-party app origins using the Self-service passkey endpoints. |
| `login_origins` (setting) | Origins allowed to call the Interaction API; MUST be same-site with `ISSUER`. |

**[TIO-PK-001]** The OP SHALL serve `GET /.well-known/webauthn` returning `{"origins": [...webauthn_origins]}` so that origins outside `RP_ID`'s registrable domain can use Related Origin Requests (Chrome 128+, Safari 18+, Firefox 152+). The settings validator SHALL reject more than 5 distinct registrable labels among the origins.

**[TIO-PK-002]** `expectedOrigin` for every verification SHALL be the full `webauthn_origins` list and `expectedRPID` SHALL be `RP_ID`. An assertion from any other origin SHALL fail.

#### 6.1.2 Registration options

**[TIO-PK-010]** Registration options SHALL be: `rp {id: RP_ID, name: RP_NAME}`; `user {id: <16 raw bytes of the user UUID>, name: <email or "user-" + first 8 hex of id>, displayName: <display_name or name>}`; a 32-byte random `challenge`; `pubKeyCredParams` `[{alg:-8},{alg:-7},{alg:-257}]` in that order; `timeout: 300000`; `attestation: "none"`; `authenticatorSelection {residentKey: "required", requireResidentKey: true, userVerification: "required"}`; `excludeCredentials` listing the user's existing credential ids; `extensions {credProps: true}`.

**[TIO-PK-011]** The challenge SHALL be stored server-side (in the interaction or, for the Self-service API, in `UserDO` with the requesting `sid`), be single-use, and expire after 300 s.

#### 6.1.3 Registration verification

**[TIO-PK-012]** Verification SHALL check: the client data `type` is `webauthn.create`; the challenge equals the stored challenge (single use, consumed before verification); the origin is in `webauthn_origins`; the RP ID hash matches `RP_ID`; the user-present and user-verified flags are both set; the attestation format is `none` (or, if another format is presented, the attestation is ignored and the key is accepted only when `attestation_policy = "ignore"`, the default); the COSE algorithm is one of -8, -7, -257; the credential id is 16–1023 bytes and not already registered anywhere (`passkey_index`); the user has fewer than `passkeys.max_per_user` (default 20) credentials.

**[TIO-PK-013]** If the `credProps.rk` extension output is present and `false`, registration SHALL fail with `passkey_not_discoverable`. If absent, the credential is accepted (many platform authenticators omit it).

**[TIO-PK-014]** On success the OP SHALL store the record of §3.6 with `backup_eligible` and `backed_up` from the authenticator-data flags (BE, BS) and emit `passkey.registered`.

#### 6.1.4 Authentication options and verification

**[TIO-PK-020]** Authentication options SHALL be: a 32-byte random `challenge`; `rpId: RP_ID`; `timeout: 300000`; `userVerification: "required"`; `allowCredentials: []` (discoverable only). Clients MAY use conditional mediation; the options are identical.

**[TIO-PK-021]** The assertion's `userHandle` SHALL be used to route to `UserDO`. If absent, the OP SHALL look up `passkey_index` by credential id (one D1 read). If both fail, the response is `passkey_unknown` (indistinguishable from a signature failure in status and shape).

**[TIO-PK-022]** `UserDO.verifyAssertion` SHALL, atomically: load the passkey by credential id; verify `type = webauthn.get`, challenge, origin, RP ID hash, UP and UV flags, and the signature over `authenticatorData || SHA-256(clientDataJSON)` with the stored public key; apply the counter policy (§6.1.5); update `counter` and `last_used_at`; return the user's profile snapshot (`disabled_at`, groups). The challenge is consumed by the caller before this call so that a failed verification still burns it.

**[TIO-PK-023]** A disabled user SHALL fail with `access_denied` after the assertion verifies (so that the failure is not distinguishable from an invalid signature by timing of storage access is not a goal; the response shape is identical).

#### 6.1.5 Signature-counter policy

**[TIO-PK-030]** If the stored counter is 0 and the new counter is 0, accept (synced passkeys never increment). If the new counter is greater than the stored counter, accept and store it. Otherwise reject with `passkey_counter_regression`, emit `passkey.clone_suspected`, and do not update the stored counter. The passkey is not disabled automatically; the event is surfaced in the user's events and the audit stream.

#### 6.1.6 Limits and management

**[TIO-PK-040]** A user SHALL NOT delete their last passkey unless they have at least one linked federated identity. The Admin API MAY delete any passkey (then the user recovers by invitation or federation).

**[TIO-PK-041]** Passkey names SHALL be 1–64 Unicode characters after trimming, stored as given, and returned verbatim only in JSON (never interpolated anywhere).

### 6.2 Browser sessions

**[TIO-SESS-001]** The session cookie SHALL be `__Host-tio_session=<tio_ss handle>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<session_absolute_ttl>`. No `Domain` attribute. No other cookies are set by the OP except interaction binding cookies.

**[TIO-SESS-002]** A session SHALL be created only at `/interactions/{id}/complete` (or the equivalent finalization in `/federation/callback`) after a successful authentication, with `auth_time = now`, `amr`, `acr`, `upstream`, `ip_hash`, `ua_family`, `country`, `idle_expires_at = now + session_idle_ttl`, `absolute_expires_at = now + session_absolute_ttl`. A re-authentication in a browser that already has a valid session for the **same** user SHALL rotate the secret and update `auth_time`, `amr`, `acr`, keeping `sid`. A re-authentication as a **different** user SHALL revoke the old session and create a new one.

**[TIO-SESS-003]** Every use of a session (`/authorize` hit, code issuance, refresh of a session-bound family) SHALL extend `idle_expires_at` to `now + session_idle_ttl`, never beyond `absolute_expires_at`. Expiry checks use both fields on every read.

**[TIO-SESS-004]** A session cookie that fails decryption, refers to an unknown, revoked or expired session, or to a disabled user SHALL be treated as absent and cleared (`Max-Age=0`) on browser-navigation responses.

**[TIO-SESS-005]** Session records SHALL never contain the IP address or full user agent; `ip_hash` is HMAC-SHA256 under the `tio/v1/iphash` derived key, truncated to 16 bytes; `ua_family` is browser family and major version only.

**[TIO-SESS-006]** Revoking a session (any path) SHALL revoke its session-bound families and trigger back-channel logout for its clients.

### 6.3 Registration policy and invitations

Setting `registration.mode`:

| Mode | Who can create an account |
|---|---|
| `closed` | Nobody except through the Admin API and bulk import. Federated first-time logins fail with `registration_closed`. |
| `invite` | Holders of a valid `register` invitation (passkey registration), and federated first-time logins only when `federation.auto_create = true`. |
| `open` | Anyone reaching the login app: passkey registration without invitation, federated auto-create if enabled. |

**[TIO-REG-001]** Passkey self-registration SHALL be allowed only when `registration.mode = "open"` or a valid `register` invitation is presented; otherwise `registration_closed`.

**[TIO-REG-002]** An invitation SHALL be a `tio_iv` handle; the OP stores SHA-256 of its secret. Consumption SHALL be atomic in D1: `UPDATE invitations SET used_at = ?, used_by_user_id = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?` with `meta.changes = 1` required. Two concurrent registrations with the same invitation SHALL yield exactly one account.

**[TIO-REG-003]** A `register` invitation SHALL pre-fill `email`, `email_verified`, `display_name` and `groups` on the created user; a login app MAY override `display_name` and MAY supply `email` only when the invitation has none (then unverified).

**[TIO-REG-004]** A `recover` invitation SHALL bind to an existing user; using it registers a new passkey on that user and always revokes all of that user's sessions and refresh families first (back-channel logout follows). Other passkeys are never deleted by recovery; an administrator removes a lost or suspect passkey explicitly. The interaction becomes authenticated as that user with `amr = ["hwk"|"swk","user"]`.

**[TIO-REG-005]** Registration in `open` mode with an email that is already verified on another account SHALL still succeed (the new account's email is unverified and non-unique); the login app is told `email_in_use: true` in the response so it can suggest signing in instead.

### 6.4 Upstream OIDC federation

#### 6.4.1 Configuration and discovery

**[TIO-FED-001]** An upstream SHALL be identified by `alias` in APIs and by `issuer` in identity records. Creating or updating an upstream with `discovery.mode = "auto"` SHALL fetch `<issuer>/.well-known/openid-configuration` (5 s timeout), require `issuer` in the document to equal the configured issuer exactly, and require `authorization_endpoint`, `token_endpoint`, `jwks_uri` to be `https` URLs. Metadata is cached per §2.8; the Admin API `POST /api/v1/admin/upstreams/{alias}/test` refetches and reports.

**[TIO-FED-002]** The upstream redirect URI SHALL always be `${ISSUER}/federation/callback`; it is reported in the upstream record so operators can register it.

#### 6.4.2 Outbound authorization request

**[TIO-FED-010]** The OP SHALL redirect to `authorization_endpoint` with `response_type=code`, `client_id`, `redirect_uri`, `scope` (configured, always containing `openid`), `state` (a `tio_fs` handle; its secret hash is stored in the interaction), `nonce` (32 random bytes, base64url, stored), `code_challenge` (S256 of a stored 43-char verifier), `code_challenge_method=S256`, plus `extra_authorize_params`. `login_hint` from the local request is forwarded when `forward_login_hint` is set on the upstream.

**[TIO-FED-011]** The federation leg SHALL expire 300 s after it starts, independently of the interaction expiry.

#### 6.4.3 Callback

**[TIO-FED-020]** `/federation/callback` SHALL accept GET query parameters and POST form bodies. It SHALL decrypt `state` (malformed → `login_url?error=invalid_state`), load the interaction, verify the binding cookie, and consume the federation leg atomically (a second callback with the same state fails with `invalid_state`).

**[TIO-FED-021]** An `error` parameter from the upstream SHALL mark the interaction `failed` with `error = "upstream_error"` and a sanitized `error_description` limited to the upstream's `error` code (never its free-text description), then redirect to the login app.

**[TIO-FED-022]** The code exchange SHALL POST to `token_endpoint` with `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`, and client authentication per `token_endpoint_auth_method` (`client_secret_basic`, `client_secret_post`, or `private_key_jwt` signed with the upstream-specific private JWK, `aud = token_endpoint`, 60 s expiry, fresh `jti`), with a 10 s timeout. Non-JSON or non-200 responses are `upstream_error`.

#### 6.4.4 ID-token validation

**[TIO-FED-030]** The upstream ID token SHALL be validated with `jose.jwtVerify` against the upstream JWKS (remote set, cached; one refetch on unknown `kid`, rate-limited to once per 5 min per upstream) and SHALL satisfy all of: `alg` ∈ {RS256, PS256, ES256, ES384, EdDSA}; `iss` equals the configured issuer exactly; `aud` contains the upstream `client_id` and, if `aud` has multiple values, `azp` equals `client_id`; `exp` in the future (60 s leeway); `iat` no more than 600 s in the past and 60 s in the future; `nonce` equals the stored nonce; `sub` present, 1–255 characters. Each condition is a separate negative test using the fake upstream.

**[TIO-FED-031]** When `use_userinfo = 1`, the OP SHALL GET `userinfo_endpoint` with the upstream access token (5 s timeout) and SHALL require its `sub` to equal the ID token `sub`; claims from userinfo override ID-token claims for `email`, `email_verified`, `name`.

**[TIO-FED-032]** `required_claims` SHALL be checked by strict equality on the merged claims; any mismatch fails with `upstream_claims_rejected`.

**[TIO-FED-033]** Claim extraction SHALL use `claims_map` (`email`, `email_verified`, `name` source claim names; defaults to the same names) and SHALL treat `email_verified` as `true` only when the upstream has `trust_email_verified = 1` and the claim is boolean `true`. A string `"true"` is not `true`.

#### 6.4.5 Account resolution

**[TIO-FED-040]** Resolution SHALL proceed in this order and stop at the first match:
1. `identity_index(issuer, subject)` → user exists (and `UserDO` confirms) → authenticated; update the identity's `email`, `email_verified`, `name`, `last_login_at`.
2. The upstream email is verified (per [TIO-FED-033]) and a user with that verified email exists → policy `federation.link_by_verified_email`: `never` → fail `account_exists`; `reauth` → interaction `link_required` with the candidate user, awaiting a passkey assertion by that same user (§7.4).
3. `federation.auto_create = true`, or the interaction carries a `register` invitation, and `registration.mode ≠ closed` → create the user (`email`, `email_verified`, `display_name = name`, invitation groups) with the identity, then authenticated.
4. Otherwise fail `registration_closed`.

**[TIO-FED-041]** A user created or linked through federation SHALL have the identity written to `identity_index` before `UserDO` (uniqueness claim first) per §4.6.

**[TIO-FED-042]** Federated authentication SHALL set `amr = ["fed"]`, `acr = urn:tinyoidc:acr:federated`, `upstream = alias`.

**[TIO-FED-043]** A disabled user resolved through federation SHALL fail `access_denied` with no upstream information leaked.

#### 6.4.6 Unlinking

**[TIO-FED-050]** (withdrawn) Self-service linking through a `link` interaction was deferred on 2026-09-19 (Appendix B #30). Identities are linked at login time by verified email ([TIO-FED-040] step 2, [TIO-IX-031]) or by import.

**[TIO-FED-051]** Unlinking the last identity of a user with no passkeys SHALL fail with `last_login_method`.

### 6.5 Account recovery

There is no password fallback and no email-only recovery.

**[TIO-REC-001]** Recovery paths SHALL be limited to: another registered passkey; a linked federated identity; a `recover` invitation issued by an administrator. Tests assert that no other endpoint can add a credential to an existing user without an authenticated session or an admin actor.

### 6.6 Consent

**[TIO-CONSENT-001]** Consent SHALL be required when the client has `skip_consent = 0` and (the user has no grant for the client, or the grant does not include every requested scope, or `prompt` contains `consent`).

**[TIO-CONSENT-002]** The login app SHALL receive, for a `consent_required` interaction, the client's `client_name`, `client_uri`, `logo_uri` and the list of requested scopes with `granted: true|false` and a fixed English description per scope (the login app localizes).

**[TIO-CONSENT-003]** A consent decision SHALL name the granted scopes; `openid` is always granted; the OP SHALL reject any scope not in the request. Denying SHALL mark the interaction `failed` with `access_denied`. Granting SHALL store the union with the existing grant in `UserDO.grants` and continue to `ready`.

**[TIO-CONSENT-004]** Revoking a grant (Self-service or Admin) SHALL delete it and revoke every refresh family for that client and user.

### 6.7 Rate limits

Limits use the Rate Limiting binding (per-colo, permissive) for coarse protection, and `UserDO`/`InteractionDO` state for exact per-entity limits.

| Key | Scope | Limit | Binding / store |
|---|---|---|---|
| IP | `/authorize`, `/par`, `/logout`, `/federation/callback` | 60 per 60 s | `RL_IP` |
| IP | `/token`, `/par`, `/revoke` (failed client auth) | 120 per 60 s | `RL_IP` |
| IP | `/api/v1/interactions/*` | 120 per 60 s | `RL_IP` |
| IP | `/api/v1/me/*` | 120 per 60 s | `RL_IP` |
| client id | `/token`, `/par`, `/revoke` (failed client auth) | 20 per 60 s | `RL_CLIENT` |
| client id | `/token` successful | 2,000 per 10 s | `RL_CLIENT` |
| interaction id | passkey and registration attempts | 10 per interaction | `InteractionDO` |
| user id | Self-service passkey registration attempts | 10 per 10 min | `UserDO` |
| admin token | `/api/v1/admin/*` | 600 per 60 s | `RL_CLIENT` keyed by `jti` prefix |

**[TIO-RL-001]** Exceeding a binding limit SHALL return 429 with `Retry-After: 10` and `{"error":"rate_limited"}`; on protocol endpoints where a redirect is expected, the error is rendered through `login_url`. Tests use a fake binding.

**[TIO-RL-002]** Exceeding a per-interaction limit SHALL mark the interaction `failed` with `too_many_attempts`.

**[TIO-RL-003]** The IP key SHALL be `CF-Connecting-IP`; IPv6 addresses are keyed by their /64 prefix.

---

## 7. Interaction API (for the login app)

### 7.1 Model

An interaction is the OP-side record of one authorization, logout or linking attempt. The login app reads it, drives ceremonies against it, and finally navigates the browser to the OP to finish. Everything the login app sends is either a proof (WebAuthn response) or a choice (which upstream, which scopes); the OP verifies proofs and validates choices.

Base path: `/api/v1/interactions/{id}`. Requests are JSON; responses are JSON.

**[TIO-IX-001]** Every Interaction API request SHALL be accepted only when (a) the `Origin` header is present and in `login_origins`, or the request is a GET with no `Origin` and `Sec-Fetch-Site` is `same-origin` or `same-site`; and (b) the request carries the interaction's binding cookie `__Host-tio_ix_<p>` whose secret hash matches the stored `binding_hash`. Failure of (a) is 403 `origin_not_allowed`; failure of (b) is 403 `interaction_binding_failed`. Neither reveals whether the interaction exists.

**[TIO-IX-002]** Interaction ids SHALL be looked up only by the exact 43-character id; malformed ids are 404 `interaction_not_found` without a Durable Object access.

**[TIO-IX-003]** Expired, completed or unknown interactions SHALL return 404 `interaction_not_found` for every endpoint except `GET`, which returns the `failed`/`completed` document for 60 s after that state is reached.

### 7.2 State machine

```text
                     ┌──────────┐  /authorize consumes PAR
     POST /par ─────▶│  pushed  │────────────────────────────┐
                     └──────────┘                            │
                                                             ▼
 /authorize (no usable session, or prompt/max_age)   ┌────────────────┐
 ───────────────────────────────────────────────────▶│ login_required │
                                                     └───────┬────────┘
              passkey/verify ok │ register/verify ok │ upstream callback ok
                                ▼                    ▼
                      ┌─────────────────┐   email matches existing verified user
                      │ (authenticated) │◀───────────────── ┌───────────────┐
                      └────────┬────────┘  passkey/verify   │ link_required │
                               │           by candidate ─── └───────────────┘
        allowed_groups fail ───┼──▶ failed(access_denied)
                               │
              consent needed?  ├── yes ──▶ ┌──────────────────┐ consent ok ┐
                               │           │ consent_required │────────────┤
                               │           └──────────────────┘  deny ──▶ failed
                               └── no ─────────────────────────────────────┤
                                                                           ▼
 /authorize (usable session, consent missing) ──▶ consent_required     ┌───────┐
                                                                       │ ready │
                                                                       └───┬───┘
                                   GET /interactions/{id}/complete         │
                                   (binding cookie verified)               ▼
                                                                    ┌───────────┐
                                                                    │ completed │  303 to RP with code
                                                                    └───────────┘
 any state ── abort / expiry / too_many_attempts / upstream_error ──▶ failed ── /complete ──▶ 303 to RP with error
```

**[TIO-IX-010]** The transitions above SHALL be the only ones permitted. A table-driven test exercises every (state, operation) pair and asserts the allowed outcome or `interaction_invalid_state`.

**[TIO-IX-011]** The user id established by authentication SHALL be immutable for the rest of the interaction; a second successful authentication as a different user SHALL fail with `interaction_invalid_state`.

### 7.3 `GET /api/v1/interactions/{id}`

Response (fields are `null` when not applicable):

```json
{
  "id": "…",
  "kind": "authorize",
  "status": "login_required",
  "expires_at": 1790000600,
  "client": { "client_id": "web", "client_name": "Example Web", "client_uri": "https://app.example.com", "logo_uri": null },
  "request": { "scopes": ["openid", "email", "profile"], "prompt": [], "max_age": null,
               "login_hint": "alice@example.com", "ui_locales": "pt-BR", "acr_values": [] },
  "methods": { "passkey": true, "registration": "invite", "upstreams": [ { "alias": "google", "display_name": "Google" } ] },
  "session_user": null,
  "consent": null,
  "link": null,
  "logout": null,
  "error": null,
  "attempts_remaining": 10
}
```

`session_user` (present when `existing_session` is set and the status is `consent_required`): `{ "display_name": "Alice", "email_masked": "a***@example.com" }`.
`consent` (status `consent_required`): `{ "scopes": [ { "name": "email", "description": "Your email address and whether it is verified", "granted": false } ] }`.
`link` (status `link_required`): `{ "upstream": "google", "email_masked": "a***@example.com", "display_name_hint": "Alice" }`.
`logout` (kind `logout`): `{ "client": {...} | null, "post_logout_redirect_uri_registered": true }`.
`error` (status `failed`): `{ "error": "access_denied", "error_description": "…" }`.

**[TIO-IX-020]** The interaction document SHALL never include the user id, email (unmasked), redirect URI, `state`, `nonce`, `code_challenge`, challenge values, or any handle. A test serializes every state and asserts the absence of these fields.

**[TIO-IX-021]** Email masking SHALL keep the first character of the local part and the full domain, replacing the rest of the local part with `***`.

### 7.4 Passkey and registration endpoints

| Endpoint | Allowed in status | Body | Response |
|---|---|---|---|
| `POST …/passkey/options` | `login_required`, `link_required` | `{}` | `{ "publicKey": PublicKeyCredentialRequestOptionsJSON }` |
| `POST …/passkey/verify` | `login_required`, `link_required` | `{ "response": AuthenticationResponseJSON }` | `{ "status": "ready"\|"consent_required", "redirect_to": "…" \| null }` |
| `POST …/register/options` | `login_required` | `{ "invitation": "tio_iv_…"?, "email"?: "…", "display_name"?: "…" }` | `{ "publicKey": PublicKeyCredentialCreationOptionsJSON, "email_in_use": false }` |
| `POST …/register/verify` | `login_required` | `{ "response": RegistrationResponseJSON, "name"?: "…" }` | as verify |

**[TIO-IX-030]** `passkey/options` SHALL replace any previous challenge in the interaction; only the most recent challenge is valid; `verify` consumes it before verification. Each `options` or `verify` call counts as one attempt against the per-interaction limit.

**[TIO-IX-031]** In `link_required`, `passkey/verify` SHALL succeed only if the asserting user equals `link.candidate_uid`; then the identity is linked (D1 claim, `UserDO.addIdentity`) and the interaction proceeds as authenticated by that user with `amr` from the passkey. Any other user's assertion fails with `link_wrong_user` and counts as an attempt.

**[TIO-IX-032]** `register/options` SHALL allocate a fresh pending user id on every call; `register/verify` SHALL create the user (§4.6 order) only after the WebAuthn verification succeeds, consuming the invitation atomically first when present. If invitation consumption fails, no user is created.

**[TIO-IX-033]** The `redirect_to` value SHALL always be `${ISSUER}/interactions/{id}/complete`; it is returned when the status becomes `ready` or `failed`, and `null` when the next step is consent.

### 7.5 Federation, consent, abort

| Endpoint | Allowed in status | Body | Response |
|---|---|---|---|
| `POST …/upstream/{alias}` | `login_required` | `{}` | `{ "redirect_to": "<upstream authorization URL>" }` |
| `POST …/consent` | `consent_required` | `{ "decision": "grant", "scopes": ["openid","email"] }` or `{ "decision": "deny" }` | `{ "status": "ready"\|"failed", "redirect_to": "…" }` |
| `POST …/abort` | any non-terminal | `{}` | `{ "status": "failed", "redirect_to": "…" }` |

**[TIO-IX-040]** `upstream/{alias}` SHALL fail with `upstream_not_found` for unknown or disabled aliases and SHALL invalidate any previous federation leg on the interaction.

**[TIO-IX-041]** `abort` SHALL set `failed` with `access_denied`; `/complete` then redirects to the RP with `error=access_denied`.

### 7.6 Logout interactions

| Endpoint | Allowed in status | Body | Response |
|---|---|---|---|
| `POST …/logout` | `login_required` (kind `logout`) | `{ "confirm": true }` or `{ "confirm": false }` | `{ "redirect_to": "…/complete" }` |

**[TIO-IX-050]** Confirming SHALL end the session bound to the interaction (the session cookie present at `/logout` time, re-verified at `/complete`); declining SHALL leave it intact. Both redirect to the resolved post-logout URL.

### 7.7 `GET /interactions/{id}/complete`

**[TIO-IX-060]** `/complete` SHALL be a top-level navigation endpoint that: verifies the binding cookie; requires status `ready` or `failed`; for `authorize` kind and `ready`: creates or rotates the session (§6.2), issues the code via `UserDO.issueCode`, marks the interaction `completed`, clears the binding cookie, sets the session cookie and redirects `303` to the RP with `code`, `state`, `iss`; for `failed`: clears the binding cookie and redirects with `error`, `error_description`, `state`, `iss`. For `logout` kind: ends the session when confirmed and redirects to the post-logout URL.

**[TIO-IX-061]** `/complete` on an interaction that is not `ready` or `failed` SHALL redirect to `login_url?interaction=<id>` so the login app resumes. `/complete` on `completed` SHALL redirect to `login_url?error=interaction_already_completed` (a code is never issued twice).

**[TIO-IX-062]** If the interaction's `existing_session` refers to a session that has since been revoked, `/complete` SHALL fail the interaction with `login_required` semantics (redirect to the RP with `error=login_required` only if `prompt=none`; otherwise restart the interaction as `login_required`).

### 7.8 Error codes

`interaction_not_found`, `interaction_binding_failed`, `origin_not_allowed`, `interaction_invalid_state`, `interaction_expired`, `too_many_attempts`, `passkey_unknown`, `passkey_verification_failed`, `passkey_counter_regression`, `passkey_not_discoverable`, `passkey_limit_reached`, `registration_closed`, `invitation_invalid`, `invitation_expired`, `invitation_used`, `email_invalid`, `link_wrong_user`, `identity_already_linked`, `account_exists`, `upstream_not_found`, `upstream_error`, `upstream_unavailable`, `upstream_claims_rejected`, `invalid_state`, `access_denied`, `rate_limited`, `temporarily_unavailable`.

**[TIO-IX-070]** `passkey_unknown` and `passkey_verification_failed` SHALL produce byte-identical response bodies except for `request_id`, and the same status (401).

### 7.9 Reference login app

**[TIO-IX-080]** (V: ci) The repository SHALL contain `examples/login-app/`, a static HTML+JS application with no build step and no dependencies that implements every interaction state (sign-in, sign-up, account linking, consent, logout confirmation, errors). It is used by the end-to-end suite and is the reference for `doc/LOGIN_APP_GUIDE.md`. It is never part of the Worker script bundle. Because the conformance suite drives it with HtmlUnit (TIO-TEST-041), whose Rhino engine has no `async`/`await`, `fetch` or spread syntax, the app SHALL use Promise chains, `XMLHttpRequest` where `fetch` is absent and no spread or rest syntax; `test/scripts/login-app.test.ts` enforces this (ADR 0014).

**[TIO-IX-081]** The same files SHALL be published through the `ASSETS` binding under `/login/` when the var `BUNDLED_LOGIN_APP` is `true`. When enabled and no `login_url` setting is stored, the effective `login_url` is `${ISSUER}/login/` and `login_origins` is `[origin of ISSUER]`, so a fresh deployment can complete a passkey login with no further configuration. When disabled, requests under `/login/` return 404 and the assets are never served. Tests cover both states, and a header test asserts the served files carry the same security headers as every other response except that `Content-Security-Policy` permits same-origin scripts and styles.

---
## 8. Self-service API (`/api/v1/me`)

For first-party apps building "security settings" screens. Authorization: a user access token with scope `account` and `aud ∋ ISSUER`. WebAuthn ceremonies from these apps require their origin in `webauthn_origins`.

**[TIO-ME-001]** Every `/api/v1/me/*` request SHALL require a valid `at+jwt` with scope `account`, a user subject (not a client), and a non-disabled user; otherwise 401 `invalid_token` or 403 `insufficient_scope` with `WWW-Authenticate: Bearer error="…"`.

| Method | Path | Effect |
|---|---|---|
| GET | `/me` | Profile: `id`, `email`, `email_verified`, `display_name`, `groups`, `created_at`, `updated_at` |
| PATCH | `/me` | Update `display_name` (1–128 chars). `email` change allowed only when `me.allow_email_change` setting is true; sets `email_verified = false`. |
| GET | `/me/passkeys` | List (§3.6 fields minus `public_key`) |
| POST | `/me/passkeys/options` | Registration options for the current user (challenge stored in `UserDO` keyed by `sid` from the token or, for offline tokens, by `jti`) |
| POST | `/me/passkeys` | `{ response, name? }` → registers; enforces max and uniqueness |
| PATCH | `/me/passkeys/{id}` | Rename |
| DELETE | `/me/passkeys/{id}` | Delete; last-method rule (§6.1.6) |
| GET | `/me/sessions` | List sessions: `sid`, `created_at`, `last_seen_at`, `auth_time`, `amr`, `upstream`, `country`, `ua_family`, `current` (equals the token's `sid`), `clients` |
| DELETE | `/me/sessions/{sid}` | Revoke one (back-channel logout) |
| DELETE | `/me/sessions` | Revoke all except current (`?include_current=true` to revoke all) |
| GET | `/me/identities` | Linked identities: `id`, `upstream` alias, `issuer`, `email`, `name`, `created_at`, `last_login_at` (never `subject`) |
| DELETE | `/me/identities/{id}` | Unlink; last-method rule |
| GET | `/me/grants` | Per-client consent grants with scopes and `granted_at` |
| DELETE | `/me/grants/{client_id}` | Revoke grant and refresh families for that client |
| GET | `/me/events` | The user's events from `audit_hot` (`type`, `ts`, `client_id`, `country`, `ua_family`, `outcome`), keyset-paginated, limited to the hot retention window |

**[TIO-ME-002]** Self-service mutations SHALL be audited with `actor = {kind: "user", id: sub}` and the token's `client_id`.

**[TIO-ME-003]** `POST /me/passkeys` SHALL require that the access token was issued from a session authenticated within `me.passkey_add_max_auth_age` (default 900 s), checked via `auth_time`; otherwise 403 `reauthentication_required`. A client handles this by re-authorizing with `max_age=0`.

---

## 9. Admin API (`/api/v1/admin`)

### 9.1 Authorization model

**[TIO-ADMIN-001]** Every `/api/v1/admin/*` request SHALL require a valid `at+jwt` with scope `admin` and `aud ∋ ISSUER`. For user subjects the user SHALL currently be a member of `admins` (checked in `UserDO` on each request, not only from the token). For client subjects the client SHALL have `admin` in `scopes_allowed` and not be disabled.

**[TIO-ADMIN-002]** Every admin mutation SHALL emit an audit event with `actor = {kind: "admin", id: sub}` (user id or client id), the target, and a bounded diff of changed fields (no secrets).

**[TIO-ADMIN-003]** The Admin API SHALL never return client secrets after creation or rotation responses, never return `private_jwk`, never return upstream secrets, and never return passkey public keys or refresh-token hashes.

### 9.2 Conventions

- Pagination: `?limit=1..200` (default 50) and opaque `cursor`; responses `{ "items": [...], "next_cursor": "…" | null }`. Cursors are keyset (`(created_at, id)`), signed with the envelope key so they cannot be forged, and expire after 1 h.
- Filtering is exact-match on indexed columns only (`email` normalized-verified, `status`, `group`, `type`, `client_id`, `user_id`, time ranges).
- `PATCH` bodies are partial; unknown fields are 400 `invalid_request`.
- Conflicts (unique violations) are 409 with codes `email_taken`, `identity_already_linked`, `client_exists`, `group_exists`, `upstream_exists`.

**[TIO-ADMIN-004]** Listing endpoints SHALL be keyset-paginated and SHALL NOT support offsets; a test with 10,000 seeded rows asserts constant-time paging (query plan uses the index).

### 9.3 Bootstrap

**[TIO-ADMIN-010]** `POST /api/v1/admin/bootstrap` with `Authorization: Bearer <ADMIN_BOOTSTRAP_TOKEN>` SHALL, only while `admins` has no members and `settings.bootstrapped_at` is unset: ensure the `admins` group; create a public client `admin-cli` (`grant_types` code+refresh, redirect `http://127.0.0.1:0/callback` loopback, `scopes_allowed` all, `skip_consent`); create one `register` invitation with `groups = ["admins"]`, `email`, `email_verified: true`, `display_name` from the body; set `bootstrapped_at`; and return the invitation URL (`login_url?invitation=<token>`) and the client record. Any later call SHALL return 410 `bootstrap_completed`. A wrong token is 401 and rate-limited by IP.

**[TIO-ADMIN-011]** The bootstrap token SHALL be compared in constant time and SHALL never be accepted on any other endpoint.

### 9.4 Endpoints

**Users**

| Method | Path | Notes |
|---|---|---|
| GET | `/users` | filters: `email`, `status`, `group`, `created_after`, `created_before` |
| POST | `/users` | `{ email?, email_verified?, display_name?, groups?, identities?: [{issuer, subject}] }` → creates (§4.6) |
| GET | `/users/{id}` | Full profile from `UserDO` + counts |
| PATCH | `/users/{id}` | `email`, `email_verified`, `display_name`, `groups` (replace) |
| DELETE | `/users/{id}` | §3.4 |
| POST | `/users/{id}/disable`, `/users/{id}/enable` | §3.4 |
| GET | `/users/{id}/passkeys` · DELETE `/users/{id}/passkeys/{pid}` | |
| GET | `/users/{id}/identities` · DELETE `/users/{id}/identities/{iid}` | Admin unlink has no last-method rule |
| GET | `/users/{id}/sessions` · DELETE `/users/{id}/sessions/{sid}` · DELETE `/users/{id}/sessions` | |
| GET | `/users/{id}/refresh-families` · DELETE `/users/{id}/refresh-families/{fid}` · DELETE `/users/{id}/refresh-families?client_id=` | |
| GET | `/users/{id}/grants` · DELETE `/users/{id}/grants/{client_id}` | |
| GET | `/users/{id}/events` | From `audit_hot` by `user_id` |
| POST | `/users/{id}/invitations` | `{ kind: "recover", expires_in? }` |
| POST | `/users/{id}/reindex` | §4.6 |
| GET | `/users/{id}/export` | Complete JSON export of the user's `UserDO` state minus secret hashes (data-portability) |

**Groups**

| Method | Path |
|---|---|
| GET | `/groups` · POST `/groups` · GET `/groups/{id}` · PATCH `/groups/{id}` · DELETE `/groups/{id}` |
| GET | `/groups/{id}/members` · PUT `/groups/{id}/members/{user_id}` · DELETE `/groups/{id}/members/{user_id}` |

**Clients**

| Method | Path |
|---|---|
| GET | `/clients` · POST `/clients` · GET `/clients/{id}` · PATCH `/clients/{id}` · DELETE `/clients/{id}` |
| POST | `/clients/{id}/rotate-secret` |
| POST | `/clients/{id}/disable` · `/clients/{id}/enable` |

**Upstreams**

| Method | Path |
|---|---|
| GET | `/upstreams` · POST `/upstreams` · GET `/upstreams/{alias}` · PATCH `/upstreams/{alias}` · DELETE `/upstreams/{alias}` |
| POST | `/upstreams/{alias}/test` — refetch discovery and JWKS, report |

**Invitations**

| Method | Path |
|---|---|
| GET | `/invitations` · POST `/invitations` `{ kind: "register", email?, email_verified?, display_name?, groups?, expires_in? }` · GET `/invitations/{id}` · DELETE `/invitations/{id}` |

The token is returned once at creation as `token` and `url` (`login_url?invitation=<token>`).

**Keys**

| Method | Path | Notes |
|---|---|---|
| GET | `/keys` | Every key with its derived `role` (`signing`, `next`, `verifying`, `retired`) and timestamps; public JWK only |
| POST | `/keys/rotate` | Creates a key (§10.3); body `{ "immediate": true }` makes it sign at once (emergency) |
| DELETE | `/keys/{kid}` | Retires a key immediately (emergency); refused with 409 `last_active_key` for the only active key; tokens signed with it become invalid |

**Settings**

| Method | Path |
|---|---|
| GET | `/settings` — effective settings with source (`default` \| `setting`) |
| PATCH | `/settings` — validated as a whole; invalid combinations rejected atomically |

**Audit**

| Method | Path | Notes |
|---|---|---|
| GET | `/audit` | filters: `type`, `user_id`, `client_id`, `actor_id`, `outcome`, `since`, `until`; from `audit_hot` |
| GET | `/audit/archive` | Lists R2 objects by day range (keys only); the operator downloads with R2 tooling |

**Import**

| Method | Path | Notes |
|---|---|---|
| POST | `/import/users` | NDJSON body, ≤ 1,000 lines, ≤ 8 MB. Each line: `{ id?, email?, email_verified?, display_name?, groups?, identities?: [{issuer, subject, email?, email_verified?}], disabled?, created_at?, create_invitation?: bool, invitation_expires_in? }` |

**[TIO-ADMIN-020]** Import SHALL be idempotent per line: a line with an `id` that exists is compared and reported `unchanged` or `conflict` (never modified); a line without `id` and with a verified email that exists is reported `conflict`; new lines create users. The response is NDJSON with one `{ line, status: "created"|"unchanged"|"conflict"|"error", id?, invitation_url?, error? }` per input line, in order. Processing is bounded to 50 concurrent user creations.

**[TIO-ADMIN-021]** (V: load) Importing 1,000,000 users with two identities and one group each SHALL complete in under 60 minutes using 8 parallel clients, with zero data loss verified by a count and a sampled deep comparison.

**Maintenance**

| Method | Path |
|---|---|
| POST | `/maintenance/reindex` `{ cursor? }` — §4.6 |
| POST | `/maintenance/purge` — runs the cron body once, synchronously bounded |
| GET | `/stats` — counts of users by status, clients, upstreams, keys by role, `audit_hot` rows, last cron run |

### 9.5 Configuration as code (deferred)

**[TIO-ADMIN-030]** (withdrawn) `PUT /api/v1/admin/config` was deferred on 2026-09-19 (Appendix B #33). Automation uses `client_credentials` with the idempotent CRUD endpoints above.

---

## 10. Cryptography and key management

### 10.1 Primitives

| Purpose | Algorithm | Implementation |
|---|---|---|
| Token signing | ES256 (ECDSA P-256, SHA-256) | `jose` over Web Crypto |
| Token and assertion verification | ES256, ES384, EdDSA, PS256, RS256 | `jose` |
| Handle and secret encryption | AES-256-GCM, 12-byte random nonce | Web Crypto |
| Key derivation | HKDF-SHA256 | Web Crypto |
| Hashing of secrets | SHA-256 | Web Crypto |
| IP pseudonymization | HMAC-SHA256, truncated 16 bytes | Web Crypto |
| Randomness | `crypto.getRandomValues` | Runtime |
| Comparisons of secrets | `crypto.subtle.timingSafeEqual` | Runtime |

**[TIO-CRYPTO-001]** (V: ci) No cryptographic primitive SHALL be implemented in project code; a lint rule forbids importing any non-allow-listed crypto package and any hand-written hash, cipher or signature code. The allow-list is `jose`, `@simplewebauthn/server` and the Web Crypto API.

**[TIO-CRYPTO-002]** Every random value (challenges, secrets, ids, nonces, verifiers) SHALL come from `crypto.getRandomValues` or `crypto.randomUUID`; `Math.random` is forbidden by lint.

**[TIO-CRYPTO-003]** Every comparison involving a secret, hash, or MAC SHALL use `timingSafeEqual` on equal-length inputs; a length mismatch returns false after hashing both inputs to fixed length.

**[TIO-CRYPTO-004]** SHA-256 without salt or stretching is the storage form for client secrets, handle secrets and invitation secrets because each has ≥ 256 bits of entropy from the OP's CSPRNG; the OP never stores a hash of a human-chosen secret. A test asserts every hashed secret's generator produces 32 random bytes.

### 10.2 Master keys

`MASTER_KEYS` is a Worker secret: JSON `{ "<version>": "<base64 32 bytes>", ... }`. `MASTER_KEY_ACTIVE` is the version used for new encryptions.

Derived keys (HKDF-SHA256, empty salt, `info` strings):

| `info` | Use |
|---|---|
| `tio/v1/envelope` | Handles (§2.4) |
| `tio/v1/keystore` | Private signing JWKs, upstream secrets and JWKs in D1 |
| `tio/v1/iphash` | IP pseudonymization |
| `tio/v1/cursor` | Admin pagination cursors |

**[TIO-CRYPTO-010]** The Worker SHALL validate `MASTER_KEYS` at first request (each value decodes to 32 bytes; the active version exists) and fail every request with 500 `server_error` otherwise.

**[TIO-CRYPTO-011]** Master-key rotation SHALL be: add the new version, set it active, deploy; the cron job then re-encrypts every keystore row under the active version (`POST /admin/maintenance/rekey` does the same on demand); outstanding handles under the old version stay valid until the operator removes the old version from the secret, at which point they are rejected ([TIO-ARCH-008]). Tests cover all three phases.

### 10.3 Signing key lifecycle

Keys carry no status column. A key's role is derived from two timestamps and the clock, so there is no transition to forget and nothing to get out of sync:

| Role | Definition |
|---|---|
| `signing` | The unretired key with the greatest `activates_at ≤ now`. Exactly one after bootstrap. |
| `next` | Unretired keys with `activates_at > now`. Published in JWKS so caches warm up; they never sign. |
| `verifying` | Unretired keys with `activates_at` below the signing key's. Published; verify only. |
| `retired` | `retired_at IS NOT NULL`. Not published; private material deleted; row removed 90 days after `retired_at`. |

**[TIO-KEYS-010]** The first request on an empty key store SHALL create one key with `activates_at = now` (guarded by a D1 `INSERT ... WHERE NOT EXISTS` so concurrent isolates create at most one). If no unretired key has `activates_at ≤ now`, the OP SHALL fail closed (500 `server_error`) rather than sign with a `next` key.

**[TIO-KEYS-011]** Private keys SHALL be generated with `crypto.subtle.generateKey` as extractable only for the export step, exported as JWK, encrypted under the keystore key, and stored; at runtime they are imported non-extractable. A test asserts the imported key's `extractable` is `false`.

**[TIO-KEYS-012]** Rotation SHALL be a single action that only creates. `POST /api/v1/admin/keys/rotate` inserts a key with `activates_at = now + keys.prepublish_seconds` (default 24 h), or `activates_at = now` when the body carries `immediate: true` (emergency). Because a key is published before it signs, clients that cache JWKS see it in time. Automatic rotation runs from cron when the signing key's `activates_at` is older than `keys.rotation_days` (default 90, `0` disables) and no `next` key exists. Cron SHALL retire every key whose `activates_at` is below the signing key's once the signing key has been signing for `keys.retire_after_seconds` (default 7 days; must exceed the maximum ID, access and logout token lifetime plus 1 h), setting `retired_at = now`, deleting `private_jwk_enc` and emitting `key.retired`; retired rows are deleted 90 days later. Tests drive the whole life of three keys with the injected clock.

**[TIO-KEYS-013]** Verification of the OP's own tokens SHALL accept any unretired key; a token whose `kid` names a retired or unknown key SHALL fail. `DELETE /api/v1/admin/keys/{kid}` retires a key immediately and SHALL be refused with 409 `last_active_key` when the key is the only unretired key with `activates_at ≤ now`; the runbook says to rotate with `immediate: true` first.

**[TIO-KEYS-014]** `kid` SHALL be the RFC 7638 JWK Thumbprint of the public key (base64url of SHA-256 over the canonical `{"crv","kty","x","y"}` member set), so any JWKS consumer can recompute it from the key itself; the table enforces uniqueness.

**[TIO-KEYS-015]** Every JWT the OP signs SHALL carry a JOSE header containing only `alg`, `typ` and `kid`, whose encoded form is at most 512 bytes; a test pins the header size for ID, access and logout tokens.

### 10.4 Envelope key versions

**[TIO-CRYPTO-020]** The envelope key SHALL be derived per master-key version and cached in the isolate; encryption always uses the active version; decryption uses the version byte in the handle. Property tests round-trip across versions.

---

## 11. Audit, observability and privacy

### 11.1 Audit event schema

```jsonc
{
  "id": "0192…",                       // UUID v7
  "ts": 1790000000,
  "type": "token.refresh_reuse",
  "outcome": "failure",                // success | failure
  "actor": { "kind": "user" | "client" | "admin" | "system" | "anonymous", "id": "…" | null },
  "user_id": "…" | null,
  "client_id": "…" | null,
  "upstream": "google" | null,
  "sid": "…" | null,
  "interaction_id": "…" | null,
  "ip_hash": "…" | null,
  "country": "BR" | null,
  "ua_family": "Chrome/128" | null,
  "request_id": "…",
  "reason": "consumed_token" | null,   // machine-readable
  "data": { }                          // ≤ 4 KB, allow-listed keys per event type
}
```

### 11.2 Event catalog

| Type | Emitted when |
|---|---|
| `user.created`, `user.updated`, `user.disabled`, `user.enabled`, `user.deleted`, `user.reindexed`, `user.exported` | Admin, import, registration, federation; `user.exported` is the one audited read: `GET /admin/users/{id}/export` hands over a person's whole record (threat-model review, ADR 0011) |
| `user.group_added`, `user.group_removed` | Membership change |
| `passkey.registered`, `passkey.renamed`, `passkey.deleted`, `passkey.auth_succeeded`, `passkey.auth_failed`, `passkey.clone_suspected` | §6.1 |
| `identity.linked`, `identity.unlinked`, `identity.login_succeeded`, `identity.login_failed` | §6.4 |
| `invitation.created`, `invitation.used`, `invitation.revoked` | §6.3 |
| `interaction.created`, `interaction.failed`, `interaction.completed` | §7 |
| `authz.code_issued`, `authz.denied` | §5.4 |
| `consent.granted`, `consent.denied`, `consent.revoked` | §6.6 |
| `token.issued`, `token.refreshed`, `token.refresh_reuse`, `token.code_replay`, `token.client_auth_failed`, `token.revoked`, `token.revoke_foreign` | §5.6, §5.9 |
| `session.created`, `session.rotated`, `session.revoked`, `session.expired` | §6.2 |
| `logout.rp_initiated`, `logout.confirmed`, `logout.backchannel_sent`, `logout.backchannel_failed` | §5.10 |
| `client.created`, `client.updated`, `client.secret_rotated`, `client.disabled`, `client.enabled`, `client.deleted` | §9 |
| `upstream.created`, `upstream.updated`, `upstream.deleted`, `upstream.discovery_failed` | §9, §6.4 |
| `key.created`, `key.retired`, `key.deleted`, `masterkey.rekeyed` | §10 |
| `settings.updated`, `admin.bootstrap`, `admin.import_batch` | §9 |
| `ratelimit.exceeded` | §6.7 |
| `system.cron_run`, `system.repair` | §12 |

**[TIO-AUDIT-001]** Every event type above SHALL have at least one test that triggers it and asserts the emitted event's `type`, `outcome`, `actor`, and that `data` contains only allow-listed keys for that type.

**[TIO-AUDIT-002]** Audit events SHALL never contain: tokens, codes, handles, secrets, hashes of secrets, challenges, WebAuthn responses, upstream tokens, raw IP addresses, full user agents, unmasked emails of users other than the subject, or `error_description` from upstreams. A redaction test feeds every event emitter a payload seeded with canary strings and asserts none reach any sink.

### 11.3 Sinks

**[TIO-AUDIT-010]** Every event SHALL be delivered to: (1) the `TASKS` queue (batched per request, sent in `waitUntil`); (2) a structured log line at level `info`. Per-user views (`GET /api/v1/me/events`, `GET /api/v1/admin/users/{id}/events`) read `audit_hot` by `user_id` and are therefore eventually consistent (seconds) and bounded by `audit.hot_retention_days`.

**[TIO-AUDIT-011]** The queue consumer SHALL write each batch to `audit_hot` (`INSERT OR IGNORE`, ≤ 9 rows per statement, `db.batch()`) and to R2 as one gzip NDJSON object, and SHALL acknowledge the batch only after both succeed; a failure retries the whole batch (idempotent by design).

**[TIO-AUDIT-012]** Queue send failures SHALL be logged and SHALL NOT fail the user-facing request.

### 11.4 Logs and metrics

**[TIO-OBS-001]** Every request SHALL produce exactly one structured JSON log line with `request_id`, `route` (template, not raw path), `method`, `status`, `duration_ms`, `cpu_ms` if available, `do_calls`, `d1_reads`, `d1_writes`, `client_id` if known, `error` code if any. No query strings, no bodies, no headers except `content-length`.

**[TIO-OBS-002]** When the `METRICS` binding exists, the OP SHALL write one Analytics Engine data point per request (`blobs: [route, status, error]`, `doubles: [duration_ms]`) and one per audit event type and outcome the request emitted (`blobs: [type, outcome]`, `doubles: [count]`), so that a request emitting thousands of events (a bulk import) stays within the binding's per-invocation write limit. A refused write SHALL be logged and SHALL never fail the request.

**[TIO-OBS-003]** `GET /api/v1/health` SHALL return `{ "status": "ok" | "degraded", "version": "<git sha>", "active_kid": "…", "d1": "ok" | "error", "time": <now> }` with status 200 for `ok` and 503 for `degraded`; it SHALL touch no Durable Object.

**[TIO-OBS-004]** Every response SHALL carry a `Server-Timing` header with the request's server-side measurements: `app;dur=<duration_ms>` and the counts `do`, `d1r` and `d1w` (as `desc` values) of the log line, so the k6 suite can enforce the budgets of §2.7 and the D1-write assertion of §13.10 from the responses themselves rather than from logs. The counts reveal nothing a response time does not: enumeration-sensitive endpoints do the same work for unknown and invalid input (§13.7), and the security suite asserts equal counts there.

### 11.5 Privacy

**[TIO-PRIV-001]** The OP SHALL store about a user only: id, email, verified flag, display name, groups, passkey public material and metadata, federated identifiers and the attributes the upstream provided, sessions with pseudonymized network metadata, and consent grants. No profile pictures, no addresses, no phone numbers, no free-form attributes.

**[TIO-PRIV-002]** `GET /api/v1/admin/users/{id}/export` and `DELETE /api/v1/admin/users/{id}` SHALL satisfy data-portability and erasure requests; archived audit lines reference the random user id only.

---

## 12. Configuration and deployment

### 12.1 `wrangler.jsonc`

The configuration is host-neutral: it names no hostname, zone or account. The top-level profile is what the Deploy-to-Cloudflare button and local development use; `env.staging` and `env.production` are used by the operator's own deployments and receive their deployment-specific values (`ISSUER`, `RP_ID`, `RP_NAME`) from the deploy environment, never from the repository.

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "tiny-oidc",
  "main": "src/index.ts",
  "compatibility_date": "2026-09-01",
  "compatibility_flags": [],
  "keep_vars": true,
  "observability": { "enabled": true, "logs": { "invocation_logs": false } },
  "limits": { "cpu_ms": 30000 },
  "assets": { "directory": "examples/login-app", "binding": "ASSETS", "run_worker_first": true },
  "vars": {
    "ISSUER": "https://tiny-oidc.example.workers.dev",   // button and dev: set to your Worker URL
    "RP_ID": "tiny-oidc.example.workers.dev",
    "RP_NAME": "Tiny OIDC",
    "BUNDLED_LOGIN_APP": "true",
    "LOG_LEVEL": "info",
    "DO_JURISDICTION": ""
  },
  "d1_databases": [{ "binding": "DB", "database_name": "tiny-oidc", "database_id": "00000000-0000-4000-8000-000000000000", "migrations_dir": "migrations" }],
  "durable_objects": { "bindings": [
    { "name": "USER_DO", "class_name": "UserDO" },
    { "name": "INTERACTION_DO", "class_name": "InteractionDO" } ] },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["UserDO", "InteractionDO"] }],
  "queues": {
    "producers": [{ "binding": "TASKS", "queue": "tiny-oidc-tasks" }],
    "consumers": [{ "queue": "tiny-oidc-tasks", "max_batch_size": 100, "max_batch_timeout": 5, "max_retries": 5, "dead_letter_queue": "tiny-oidc-dlq" }] },
  "r2_buckets": [{ "binding": "AUDIT_BUCKET", "bucket_name": "tiny-oidc-audit" }],
  "ratelimits": [
    { "name": "RL_IP", "namespace_id": "1001", "simple": { "limit": 120, "period": 60 } },
    { "name": "RL_CLIENT", "namespace_id": "1002", "simple": { "limit": 2000, "period": 10 } } ],
  "analytics_engine_datasets": [{ "binding": "METRICS", "dataset": "tiny_oidc" }],
  "triggers": { "crons": ["*/5 * * * *"] },
  "env": {
    "staging":    { "name": "tiny-oidc-staging", "vars": { "BUNDLED_LOGIN_APP": "false", "LOG_LEVEL": "info", "DO_JURISDICTION": "" },
                    "d1_databases": [{ "binding": "DB", "database_name": "tiny-oidc-staging", "migrations_dir": "migrations" }],
                    "queues": { "producers": [{ "binding": "TASKS", "queue": "tiny-oidc-staging-tasks" }],
                                "consumers": [{ "queue": "tiny-oidc-staging-tasks", "max_batch_size": 100, "max_batch_timeout": 5, "max_retries": 5, "dead_letter_queue": "tiny-oidc-staging-dlq" }] },
                    "r2_buckets": [{ "binding": "AUDIT_BUCKET", "bucket_name": "tiny-oidc-staging-audit" }] },
    "production": { "name": "tiny-oidc", "vars": { "BUNDLED_LOGIN_APP": "false", "LOG_LEVEL": "info", "DO_JURISDICTION": "" },
                    "d1_databases": [{ "binding": "DB", "database_name": "tiny-oidc-production", "migrations_dir": "migrations" }],
                    "queues": { "producers": [{ "binding": "TASKS", "queue": "tiny-oidc-production-tasks" }],
                                "consumers": [{ "queue": "tiny-oidc-production-tasks", "max_batch_size": 100, "max_batch_timeout": 5, "max_retries": 5, "dead_letter_queue": "tiny-oidc-production-dlq" }] },
                    "r2_buckets": [{ "binding": "AUDIT_BUCKET", "bucket_name": "tiny-oidc-production-audit" }] }
  }
}
```

Durable Object bindings, the rate-limit bindings, the Analytics Engine dataset, the assets binding and the cron trigger are inherited by every environment. The environment sections omit `database_id`: the deploy script resolves it by `database_name` at deploy time (§12.3), so no account-specific identifier lives in the repository. `keep_vars` preserves vars set outside the repository across deploys.

**[TIO-CFG-001]** (V: ci) `compatibility_flags` SHALL be empty; `nodejs_compat` is not used. A dependency that requires it is rejected at review. CI fails if the flag appears.

**[TIO-CFG-002]** `ISSUER` SHALL be an `https` URL with no path, query or fragment (a path is permitted only when the deployment is under a sub-path, and then every endpoint is prefixed accordingly); the OP validates it at startup. In the `dev` environment only, `http://localhost:<port>` and `http://127.0.0.1:<port>` are also accepted, because browsers treat them as secure contexts for WebAuthn and `__Host-` cookies.

### 12.2 Secrets and settings

| Name | Kind | Purpose |
|---|---|---|
| `MASTER_KEYS` | secret | §10.2 |
| `MASTER_KEY_ACTIVE` | secret | Active version |
| `ADMIN_BOOTSTRAP_TOKEN` | secret | §9.3; may be deleted after bootstrap |
| `ISSUER`, `RP_ID`, `RP_NAME` | var | Deployment identity; supplied by the deploy environment for staging and production, by the form for button deployments |
| `BUNDLED_LOGIN_APP` | var | `true` serves the reference login app under `/login/` (§7.9); `false` in the operator's staging and production |

Runtime settings (D1 `settings`, editable via Admin API, cached 60 s):

| Key | Default | Notes |
|---|---|---|
| `login_url` | required, or `${ISSUER}/login/` when `BUNDLED_LOGIN_APP=true` | Absolute `https` URL, same-site with `ISSUER` |
| `login_origins` | required, or `[origin of ISSUER]` when `BUNDLED_LOGIN_APP=true` | Array of origins, same-site with `ISSUER` |
| `webauthn_origins` | `login_origins` | Array; ≤ 5 registrable labels |
| `logout_landing_url` | `login_url` | |
| `registration.mode` | `invite` | `closed` \| `invite` \| `open` |
| `federation.auto_create` | `false` | |
| `federation.link_by_verified_email` | `reauth` | `never` \| `reauth` |
| `passkeys.max_per_user` | `20` | 1–50 |
| `passkeys.attestation_policy` | `ignore` | `ignore` only in v1 |
| `interaction_ttl` | `600` | |
| `session.idle_ttl`, `session.absolute_ttl` | `86400`, `2592000` | |
| `tokens.access_ttl`, `tokens.id_ttl`, `tokens.refresh_idle_ttl`, `tokens.refresh_absolute_ttl`, `tokens.refresh_reuse_window` | `600`, `600`, `1209600`, `2592000`, `86400` | |
| `keys.rotation_days`, `keys.prepublish_seconds`, `keys.retire_after_seconds` | `90`, `86400`, `604800` | |
| `audit.hot_retention_days` | `30` | 1–365 |
| `me.allow_email_change` | `false` | |
| `me.passkey_add_max_auth_age` | `900` | |
| `bootstrapped_at` | unset | System-managed |

**[TIO-CFG-003]** Settings SHALL be validated as a whole on every `PATCH`; a violated cross-field rule (for example `retire_after_seconds` ≤ max token lifetime) rejects the entire patch with `invalid_settings` and a list of violations.

**[TIO-CFG-004]** The OP SHALL refuse to serve `/authorize` (503 `not_configured` rendered as JSON, since no `login_url` exists to redirect to) until `login_url` and `login_origins` are effective, either stored as settings or defaulted by `BUNDLED_LOGIN_APP=true`.

**[TIO-CFG-005]** (V: ci) Environment variables, secrets and settings SHALL be declared exactly once, as a zod schema in `src/env.ts` with a description, a default and bounds per entry. `scripts/gen-config-docs.ts` SHALL generate `doc/CONFIG.md` and `.dev.vars.example` from that schema, and CI SHALL fail when either committed file differs from the generated output, exactly as `doc/TRACEABILITY.md` is drift-checked. The tables in this section are snapshots of `doc/CONFIG.md`.

### 12.3 Environments, deployment and releases

**[TIO-DEPLOY-001]** (V: review) Four deployment profiles SHALL exist: `dev` (local `wrangler dev` with local D1, Durable Objects, Queues and R2), `button` (the top-level configuration profile used by the Deploy-to-Cloudflare button: workers.dev hostname, bundled login app on), `staging` (the operator's Cloudflare account, seeded with synthetic users, target of conformance and load tests, with a staging-only auto-approving fake upstream deployed as a separate Worker), and `production`. No credential, key, database, queue or bucket is shared between profiles.

**[TIO-DEPLOY-005]** (V: ci) The public repository SHALL be host- and account-neutral: no hostname of any real deployment, no zone name, no Cloudflare account id, no D1 database id of a real database, and no credential may appear in any committed file, including this document, workflows and examples. Deployment-specific values live in the operator's private infrastructure repository and in the Cloudflare dashboard. A CI grep with an operator-maintained deny-list (kept outside the public repo and run only in the operator's environment) plus a public generic check (no 32-hex account ids, no `database_id` other than the placeholder) enforce this.

**[TIO-DEPLOY-006]** (V: review) Staging and production SHALL be deployed by Cloudflare Workers Builds connected to the GitHub repository, not by GitHub Actions: one connected Worker per environment, `staging` building the default branch `main` and `production` building the protected `production` branch. Build variables set in the Cloudflare dashboard per Worker supply `TIO_ENV`, `TIO_ISSUER`, `TIO_RP_ID` and `TIO_RP_NAME`. No Cloudflare API token is stored in GitHub. GitHub Actions runs tests and gates only.

**[TIO-DEPLOY-007]** The deploy command for every profile SHALL be `pnpm run deploy`, which runs `scripts/deploy.ts`: read `TIO_ENV` (default: top-level profile); apply D1 migrations with `wrangler d1 migrations apply DB --remote [--env]`; for `staging` and `production`, resolve the D1 `database_id` by `database_name` through `wrangler d1 list --json` and write a generated configuration file (never committed) that adds it; pass `--var ISSUER:$TIO_ISSUER --var RP_ID:$TIO_RP_ID --var RP_NAME:$TIO_RP_NAME`; for `production`, `wrangler versions upload`, run the smoke test (`scripts/smoke.ts`: discovery, JWKS, health) against the version's preview URL, then `wrangler versions deploy` to 100%; for other profiles, `wrangler deploy`. Any failing step aborts before traffic changes. The script is unit-tested with a fake `wrangler` and run for real in the nightly job against staging.

**[TIO-DEPLOY-008]** (V: ci) `README.md` SHALL carry the Deploy-to-Cloudflare button (`https://deploy.workers.cloudflare.com/?url=<repository URL>`) near the top, followed by numbered steps: click, set `ISSUER` and `RP_ID` to the Worker's URL and host in the form, fill `ADMIN_BOOTSTRAP_TOKEN` and `MASTER_KEYS` from the generator command shown in the README, create and deploy, then call bootstrap. `.dev.vars.example` (generated, TIO-CFG-005) SHALL list every secret with a one-line description so the form renders the fields, and `package.json` SHALL declare `build` (typecheck) and `deploy` scripts because the button pre-fills its commands from them. A CI check validates that `wrangler.jsonc` top-level profile carries default names and ids for every provisionable resource (D1, Queues, R2, Durable Objects) as the button requires.

**[TIO-DEPLOY-009]** (V: review) Custom hostnames for staging and production SHALL be attached outside this repository, in the operator's infrastructure-as-code (Cloudflare Workers custom domains), after the Worker exists. Workers custom domains provision their certificates automatically, including multi-level names, and cannot coexist with an existing DNS record on the same name. The repository's `wrangler.jsonc` SHALL contain no `routes`.

**[TIO-DEPLOY-010]** (V: review) Promotion to production SHALL be a fast-forward push of the `production` branch to a `main` commit whose nightly conformance and load gates passed; rollback is a revert on `production`. Both branches are protected against force-push and history rewriting.

**[TIO-DEPLOY-011]** (V: ci) Changes reach `main` by direct commits from the implementing agent; the full gate set (§13.1) runs on every push, and a red `main` blocks the staging deploy until it is fixed forward. Pull requests are used only when the repository owner asks for a review point.

**[TIO-DEPLOY-003]** (V: review) D1 SHALL be backed up weekly by `wrangler d1 export` to `AUDIT_BUCKET/backups/`, and D1 Time Travel (30 days) is the point-in-time recovery mechanism. Durable Object point-in-time recovery is per object via the bookmark API and is exposed through `POST /api/v1/admin/users/{id}/restore` `{ "bookmark_time": … }` for individual-user recovery.

**[TIO-DEPLOY-004]** (V: review) A `doc/RUNBOOK.md` SHALL document: bootstrap, key rotation, master-key rotation, emergency key retirement, client-secret rotation, user recovery, D1 restore, reindex, and what to do when `MASTER_KEYS` is lost (re-key everything; all sessions and refresh tokens invalid; upstream secrets and signing keys must be regenerated).

### 12.4 Cron maintenance

**[TIO-CFG-010]** The `scheduled()` handler SHALL, every 5 minutes and bounded to 20 s of wall time: purge `audit_hot` beyond retention (≤ 10 × 1,000 rows); delete expired invitations beyond 30 days; repair or delete `creating` users; finish `deleting` users; create the next signing key when rotation is due and retire superseded keys (§10.3); run one re-encryption chunk when a master-key rotation is pending; delete retired keys beyond 90 days; emit `system.cron_run` with counts. Each step is idempotent and individually tested with `createScheduledController`.

---
## 13. Testing strategy

"Not tested = not proven = not working." This section turns that into mechanisms: a coverage gate, a traceability gate, and eleven suites with distinct purposes. A requirement without a test is a CI failure. A line of `src/` without coverage is a CI failure.

### 13.1 Toolchain

| Concern | Tool | Notes |
|---|---|---|
| Test runner | Vitest 4.1+ | Two configs: `vitest.unit.config.ts` (Node environment, pure functions) and `vitest.workers.config.ts` (workerd via `@cloudflare/vitest-plugin`). |
| Workers runtime in tests | `@cloudflare/vitest-plugin` 1.x (formerly `@cloudflare/vitest-pool-workers`) | Runs tests inside workerd with real D1, Durable Objects, Queues, R2 and cron bindings. Storage is isolated **per test file**, not per test; suites are written accordingly (§13.3). |
| Coverage | `@vitest/coverage-istanbul` | V8 coverage is unsupported in workerd; Istanbul instrumentation is required. |
| Outbound request mocking | `@msw/cloudflare` + `msw` 2.14+ | `fetchMock` was removed from `@cloudflare/vitest-plugin` 1.x; MSW's `onUnhandledFrame: "error"` gives the disable-network behavior. |
| Browser end-to-end | Playwright 1.61+ (Chromium, Firefox, WebKit) | First-party `browserContext.credentials` for discoverable passkeys on all engines; CDP `WebAuthn.*` on Chromium for negative user-verification cases. |
| Property-based tests | `fast-check` | Codecs, envelopes, parsers, redirect-URI matcher. |
| Load | k6 via `grafana/setup-k6-action` | Against staging. |
| Conformance | OpenID Foundation conformance suite (Docker) | Against staging, nightly and before release. |
| Interop RP libraries | `oauth4webapi` (in workerd tests), `openid-client` v6 (Node, in e2e) | Both maintained by the same author as `jose`; cover browser-style and server-style clients. |
| Lint and format | Biome | Includes custom rules (§13.11). |
| Types | TypeScript 5.9, `strict`, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`, `noImplicitOverride` | `tsc --noEmit` in CI. |
| Dead code and deps | `knip`, `pnpm audit` | CI. |
| Mutation testing | Stryker (evaluation) | Nightly, non-blocking until it proves stable with the Workers plugin. |

**[TIO-TEST-001]** (V: ci) CI SHALL run, on every pull request: Biome, `tsc`, `knip`, unit suite, workers suites (component, http, security, concurrency, property) with coverage, e2e suite on Chromium, the trace check, the bundle-size check, the config check, and the OpenAPI drift check. A failure in any blocks merge.

### 13.2 Coverage gate

**[TIO-TEST-002]** (V: ci) Coverage thresholds SHALL be 100% statements, branches, functions and lines for `src/**`, measured by the union of the unit and workers suites, excluding only generated files (`src/generated/**`). Thresholds live in the Vitest config and CI fails below them.

**[TIO-TEST-003]** (V: ci) `/* istanbul ignore next -- reason: … */` SHALL be the only permitted form of exclusion, SHALL carry a reason, and SHALL be limited to 15 occurrences across `src/`; `scripts/check-ignores.ts` enforces the count and prints every occurrence in the CI log. Acceptable reasons are limited to platform-unreachable branches (for example a `default` in an exhaustive `switch` over a closed union).

### 13.3 Isolation discipline

**[TIO-TEST-004]** (V: review) Because storage isolation is per file, every workers test file SHALL either (a) create its own users, clients and interactions with unique ids and never assume an empty store, or (b) call `resetStorage()` from `test/support/reset.ts` in `beforeEach`, which truncates D1 tables, deletes every Durable Object it created (`listDurableObjectIds` + `runInDurableObject(deleteAll)`), and drains the queue. Files that test cross-user isolation use (a) deliberately.

**[TIO-TEST-005]** Every test SHALL control time through the injected `Clock`; tests that depend on expiry use `vi.setSystemTime` and never sleep. A lint rule forbids `setTimeout` in tests except inside `test/support/`, and `Date.now()` / `new Date()` anywhere in `src/` outside the `Clock` implementation in `src/env.ts`, so that every time comparison in the OP flows through one choke point.

### 13.4 Traceability gate

**[TIO-TEST-006]** (V: ci) `scripts/trace.ts` SHALL: parse every `[TIO-…]` identifier and verification tag in `doc/TINY_OIDC_SPEC.md`; parse every test title in `test/**` (including `test.each` templates) for identifiers; fail when a default-tag identifier has zero tests, when a test cites an unknown or withdrawn identifier, or when an identifier appears twice in the spec; and write `doc/TRACEABILITY.md` with one row per requirement (identifier, section, verification, test files). The generated file is committed and its drift is a CI failure.

**[TIO-TEST-007]** (V: ci) Identifiers tagged `(V: load)` and `(V: conformance)` SHALL be mapped to k6 threshold names and conformance plan names in `scripts/trace.config.json`; the nightly job fails when a mapped threshold or plan is missing from the results.

### 13.5 Suites

| Suite | Environment | What it proves | Examples |
|---|---|---|---|
| **Unit** (`test/unit`) | Node | Pure logic without bindings | base64url, UUID v7 monotonicity, envelope codec, PKCE, redirect-URI matcher, scope parser, claims mapper, cookie parser, settings validator, error mapper, email normalizer, masking |
| **Property** (`test/property`) | Node | Invariants over random inputs | envelope round-trip and tamper rejection; redirect matcher never matches a non-registered URI; scope parser idempotence; form parser handles arbitrary bytes; JWT claims builder never emits `null` |
| **Component** (`test/component`) | workerd | Each Durable Object and repository against real storage | `UserDO` every method incl. purge and migration; `InteractionDO` state machine and alarm; D1 repositories against real migrations; key store lifecycle; queue consumer; cron steps |
| **HTTP** (`test/http`) | workerd, `SELF.fetch` | Full flows through the router with real bindings | discovery, JWKS, PAR, authorize (all branches), interaction API, passkey ceremonies with the software authenticator, federation with the fake upstream, token (all grants), userinfo, revoke, logout, back-channel, self-service, admin, bootstrap, import |
| **Security** (`test/security`) | workerd | Negative and adversarial behavior | §13.7 list |
| **Concurrency** (`test/concurrency`) | workerd | Exactly-once under parallelism | §13.6 list |
| **Interop** (`test/interop`) | workerd | Real client libraries complete flows | `oauth4webapi` code flow, refresh, PAR, `private_key_jwt`, revocation, userinfo |
| **E2E** (`test/e2e`) | Playwright + `wrangler dev` | Real browsers, real WebAuthn, the reference login app, a Node RP (`openid-client`) | passkey sign-up and sign-in on Chromium/Firefox/WebKit; federation via the fake upstream; consent; logout with and without hint; self-service passkey add with reauthentication |
| **Conformance** (`conformance/`) | Docker suite vs staging | Standards compliance | §13.9 |
| **Load** (`perf/`) | k6 vs staging | Budgets at scale | §13.10 |
| **Mutation** (nightly) | Stryker | Test strength | Report only |

**[TIO-TEST-008]** (V: ci) Each suite SHALL run in CI in the environment named above; the HTTP and security suites SHALL exercise every route in the router table (a route-coverage assertion at the end of the http suite fails on any route without at least one request).

### 13.6 Concurrency suite (exactly-once)

**[TIO-TEST-010]** The following operations SHALL each have a test that fires 20 parallel attempts and asserts exactly one success and the specified side effect on the others:

| Operation | Others observe | Side effect |
|---|---|---|
| Exchange the same authorization code | `invalid_grant` | Families created by the winner are revoked ([TIO-TOKEN-012]) |
| Rotate the same refresh token | `invalid_grant` | Family revoked, `token.refresh_reuse` emitted once |
| Verify the same passkey challenge | `interaction_invalid_state` or challenge failure | Counter updated once |
| Consume the same invitation | `invitation_used` | One user created |
| Consume the same PAR `request_uri` | `invalid_request` | One interaction |
| Consume the same federation `state` | `invalid_state` | One callback processed |
| `/complete` on the same interaction | Second redirects with `interaction_already_completed` | One code issued |
| Create a user with the same verified email | 409 `email_taken` | One user row |
| Link the same `(issuer, subject)` | `identity_already_linked` | One index row |
| Bootstrap | 410 | One admin invitation |
| First key creation on an empty store | — | One signing key |

### 13.7 Security suite

**[TIO-TEST-020]** The security suite SHALL contain at least the following, each as a named test citing the requirement it protects:

- Redirect URI: prefix, suffix, case, trailing slash, query addition, fragment, userinfo (`user@host`), IP-literal `https`, `localhost`, scheme downgrade, loopback port change (must pass), open-redirect via `login_url` parameter injection.
- PKCE: missing, `plain`, wrong verifier, verifier of wrong length or alphabet, challenge reuse across clients.
- Code: reuse, expired, wrong client, wrong redirect_uri, forged envelope, cross-user envelope (valid structure, other user's id).
- Refresh: reuse, cross-client, expired idle, expired absolute, after session logout (session-bound), after user disable, after group removal for `admin` scope, scope widening.
- Client auth: secret in body for a basic client, basic header for a `none` client, `private_key_jwt` with each failing claim, `alg: none`, missing `iat`, `iat` too old, `exp` too far, wrong `aud`, key not in JWKS, JWKS URI unreachable.
- Tokens: signature by a retired key, by an unknown `kid`, wrong `typ`, `aud` without `ISSUER` on `/me` and `/admin`, `client_credentials` token on `/userinfo`, tampered payload, JOSE header over 512 bytes rejected by the builder.
- Interaction: missing binding cookie, wrong binding cookie, cross-interaction cookie, wrong `Origin`, no `Origin` on POST, request after expiry, every invalid state transition, second authentication as another user, `link_wrong_user`, attempt exhaustion.
- WebAuthn: wrong origin, wrong RP ID, UV flag clear, UP flag clear, wrong challenge, reused challenge, wrong signature, unknown credential, counter regression, non-discoverable (`rk:false`), duplicate credential id across users, 21st passkey, unsupported algorithm, oversized credential id.
- Federation: each ID-token validation failure, `state` reuse, `state` from another interaction, callback without binding cookie, upstream `error` handling, userinfo `sub` mismatch, `required_claims` mismatch, `email_verified` as string, disabled user, `account_exists` policy, `registration_closed`.
- Logout: hint signed by retired key, hint for another client, unregistered `post_logout_redirect_uri`, no-hint CSRF (session must survive), logout-token contents, back-channel retry.
- Headers and CORS: full matrix of routes × required headers; `Origin` reflection only for login origins; no CORS on navigation endpoints; `Host` mismatch → 421.
- Redaction: canary strings in every emitter never reach logs, audit, events, or error bodies.
- Enumeration: response equality across unknown/invalid for token, userinfo, passkey verify, invitations, admin lookups.
- Size limits: 413 on every body limit; 414 on long query; JSON depth bomb rejected.
- Injection: SQL metacharacters in every string parameter reach D1 only as bound parameters (asserted by the repository spy); no parameter is ever interpolated into a URL without validation.

### 13.8 Fixtures

**[TIO-TEST-030]** `test/support/virtual-authenticator.ts` SHALL implement a software WebAuthn authenticator on Web Crypto (ES256 by default; EdDSA and RS256 selectable) that produces registration responses (`fmt: "none"`) and assertions for arbitrary origins, RP IDs, flags, counters and challenges, with fault injection for every negative case in §13.7. It is itself unit-tested by verifying its output with `@simplewebauthn/server`.

**[TIO-TEST-031]** `test/support/fake-upstream/` SHALL implement a minimal OIDC OP (discovery, authorize with auto-approve, token, JWKS, userinfo) as a pure `handle(Request): Response` module with fault injection via a control header or query flags (bad `iss`, `aud`, `nonce`, `exp`, `iat`, unknown `kid`, key rotation, slow responses, malformed JSON, `error` responses, string `email_verified`). It is mounted in workers tests through the outbound interceptor (`test/support/fetch-allowlist.ts`, `@msw/cloudflare`) and deployed as a standalone Worker for staging (`conformance/` and `perf/` depend on it). It SHALL never be deployable to production (the deploy script refuses a `fake-upstream` name outside staging).

**[TIO-TEST-032]** `test/support/factories.ts` SHALL create users, passkeys, clients, upstreams, sessions and tokens through the public APIs and Durable Object methods only, never by writing storage directly, except in tests that deliberately construct inconsistent state (§4.6) and say so in their title.

**[TIO-TEST-033]** `examples/rp-node` and everything under `test/e2e` SHALL reach the OP over HTTP only: they never import `src/**` or `cloudflare:test`, never read or write D1 or Durable Object storage, and the relying party verifies ID tokens against the live JWKS like a real client. The lint rules enforce the import ban.

### 13.9 Conformance

**[TIO-TEST-040]** (V: conformance) Before every release and nightly, the OpenID Foundation conformance suite SHALL run against staging with these plans, and the results SHALL be archived in the release: `oidcc-config-certification-test-plan`, `oidcc-basic-certification-test-plan` (the plan itself exercises `client_secret_basic` and `client_secret_post` on static clients; the suite offers no plan that sends PKCE with `none`, so the public-client flow is verified by the `oauth4webapi` interop suite of §13.5), `oidcc-rp-initiated-logout-certification-test-plan`, `oidcc-backchannel-rp-initiated-logout-certification-test-plan`. The plans' own fixed variants are not repeated on the command line (the suite refuses them). The suite's relying parties are confidential clients registered with `require_pkce = 0` because its modules send no `code_challenge` (TIO-AUTHZ-008). Every test SHALL pass or be explicitly waived in `conformance/waivers.json` with a reason limited to "feature intentionally unsupported and advertised as such in discovery" (for example request objects).

**[TIO-TEST-041]** (V: conformance) The suite's browser automation SHALL complete login through the reference login app by selecting the staging-only fake upstream (auto-approving); no test-only code path exists in the OP. Logout confirmation is automated by clicking the reference login app's confirm control.

### 13.10 Load and capacity

**[TIO-TEST-050]** (V: load) `perf/seed.ts` SHALL create 1,000,000 synthetic users on staging through `/api/v1/admin/import/users` (8 parallel clients), then obtain 100,000 refresh tokens by driving the federated code flow against the fake upstream over HTTP only (no browser). Timings are recorded as the import benchmark ([TIO-ADMIN-021]).

**[TIO-TEST-051]** (V: load) `perf/scenarios/` SHALL contain k6 scenarios with thresholds equal to §2.7: `discovery`, `sso_authorize` (session cookies harvested at seed time), `login_federated` (50/s), `token_code_exchange`, `token_refresh` (150/s sustained, 500/s burst for 60 s), `userinfo`, `admin_list`. Each scenario also asserts `http_req_failed < 0.1%` and, through the health endpoint, that D1 write rate stays under 5/s during token scenarios (read from `/api/v1/admin/stats` deltas).

**[TIO-TEST-052]** (V: load) A soak scenario SHALL run the refresh scenario for 2 hours at 100/s and assert no growth in p99 and no growth in per-user Durable Object storage beyond the retention bounds (sampled via `GET /api/v1/admin/users/{id}/export` size).

### 13.11 Lint rules that encode requirements

**[TIO-TEST-060]** (V: ci) Custom Biome/ESLint-compatible rules (implemented as a small `scripts/lint-rules.ts` run in CI) SHALL forbid: `Math.random`; `Date.now()` and `new Date()` in `src/` outside `src/env.ts`; `prepare(` outside `src/db/` and `src/do/`; string concatenation into SQL; `console.log` outside `src/obs/`; `new Response(` with `text/html`; `nodejs_compat`; imports of non-allow-listed crypto packages; literal arrays of scopes, grant types, response types, client authentication methods, algorithms or `prompt` values outside `src/oidc/capabilities.ts`; imports of `src/**` or `cloudflare:test` from `examples/` and `test/e2e/`; `setTimeout` in tests outside `test/support/`; `any` in `src/`; `JSON.parse` without a schema in request handlers.

### 13.12 Definition of done for a requirement

A requirement is done when: the code exists; at least one test titled with its identifier passes in CI; coverage remains 100%; `doc/TRACEABILITY.md` shows it as covered; and, if it is tagged `load` or `conformance`, the mapped threshold or plan passed in the most recent nightly run.

---

## 14. Repository layout and implementation plan

### 14.1 Layout

```text
tiny-oidc/
├── doc/
│   ├── TINY_OIDC_SPEC.md            this document
│   ├── TRACEABILITY.md              generated by scripts/trace.ts
│   ├── LOGIN_APP_GUIDE.md           how to build a login app against §7
│   ├── RUNBOOK.md                   operations (§12.3)
│   ├── openapi.json                 committed snapshot, drift-checked
│   └── adr/                         one file per decision after v1
├── src/
│   ├── index.ts                     fetch / queue / scheduled entry; exports DO classes
│   ├── env.ts                       Env type, settings loader, clock, caches
│   ├── router/                      Hono app, middleware (headers, CORS, rate limit, request id, errors, body limits)
│   ├── oidc/                        discovery, authorize, par, token, userinfo, revoke, logout, backchannel, claims, scopes, client-auth
│   ├── interaction/                 Interaction API handlers, state machine, complete
│   ├── auth/                        passkey (options/verify), session, federation, consent, registration, invitations, recovery
│   ├── do/                          UserDO.ts, InteractionDO.ts, schema/*.sql, migrate.ts
│   ├── db/                          D1 repositories (users, groups, clients, upstreams, keys, invitations, settings, audit)
│   ├── crypto/                      envelope, master-keys, keystore, jwt, hash, random, uuid
│   ├── audit/                       event catalog, emitter, redaction, queue consumer, sinks
│   ├── admin/                       Admin API handlers, import, bootstrap
│   ├── me/                          Self-service API handlers
│   ├── obs/                         logging, metrics, health
│   └── generated/                   wrangler types
├── migrations/                      D1 migrations (0001_init.sql, …)
├── test/                            §13.5 suites and support/
├── examples/
│   ├── login-app/                   static reference login app (fixture)
│   └── rp-node/                     Node RP with openid-client (e2e fixture)
├── perf/                            k6 scenarios, seed script
├── conformance/                     docker compose, plan configs, waivers.json, runner
├── scripts/                         trace.ts, check-ignores.ts, lint-rules.ts, gen-openapi.ts, gen-config-docs.ts, bundle-check.ts, config-check.ts, deploy.ts, smoke.ts, neutrality-check.ts, gen-secrets.ts
├── README.md  LICENSE (MIT)  .dev.vars.example  .nvmrc
├── wrangler.jsonc  package.json  pnpm-lock.yaml  tsconfig.json  biome.json
├── vitest.unit.config.ts  vitest.workers.config.ts  playwright.config.ts
└── .github/workflows/               pr.yml (gates), nightly.yml (conformance, load, mutation); deploys are Workers Builds, not Actions
```

Dependencies (runtime): `hono`, `@hono/zod-openapi`, `zod`, `jose`, `@simplewebauthn/server`, `uuidv7`. Nothing else at runtime. Dev: `wrangler`, `vitest`, `@cloudflare/vitest-plugin`, `@vitest/coverage-istanbul`, `@playwright/test`, `fast-check`, `msw`, `@msw/cloudflare`, `oauth4webapi`, `openid-client`, `biome`, `knip`, `typescript`, `jsonc-parser`, `@types/node`.

**[TIO-GEN-003]** (V: ci) Adding a runtime dependency SHALL require a change to the list above in the same pull request; `scripts/config-check.ts` compares `package.json` against the list.

### 14.2 Phases

Each phase ends when its exit criteria are green in CI. Phases are sequential; within a phase, work is parallelizable by module.

| Phase | Scope | Exit criteria |
|---|---|---|
| **0. Foundation** | Repo, toolchain, CI with all gates wired (coverage, trace, lint rules, bundle, config), `Clock`, envelope, master keys, UUID v7, D1 migration 0001, DO skeletons with migrations, settings loader, error model, security headers, request ids, health. | All gates pass on a nearly empty `src/`; `pnpm trace` reports the spec's identifiers as uncovered (expected) and the CI trace job is configured to allow-list uncovered identifiers by phase (`scripts/trace.config.json` `phase` field) so the gate tightens as phases complete. |
| **1. Keys and discovery** | Key store and lifecycle, JWKS, discovery, JWT sign/verify, `at+jwt`, ID token builder. | §5.2, §5.3, §10 identifiers covered. |
| **2. Core flow with passkeys** | Clients (D1 + admin create for tests via bootstrap), `/authorize` validation, `/par`, `InteractionDO`, Interaction API for passkeys and registration (invite + open), `UserDO` sessions/codes/families, `/complete`, `/token` (code, refresh), `/userinfo`, `/revoke`, consent, groups enforcement, reference login app, software authenticator, e2e passkey sign-up and sign-in. | §5.4–§5.9, §6.1–§6.3, §6.6, §7 covered; `oauth4webapi` interop green; concurrency suite green for code, refresh, challenge, invitation, PAR, complete. |
| **3. Admin API** | Bootstrap, users, groups, clients, upstream CRUD (no login yet), invitations, settings, keys, stats, reindex, import, OpenAPI generation, generated configuration docs. | §9 covered; import benchmark measured on staging (may be below target until Phase 6 tuning). |
| **4. Federation** | Upstream discovery, outbound request, callback, ID-token validation, account resolution and login-time linking policy, fake upstream fixture, outbound allow-list test, Google and Microsoft manual verification recorded in `doc/adr/`. | §6.4 covered; security suite federation cases green. |
| **5. Logout and self-service** | RP-initiated logout, logout interaction, back-channel logout with retries, Self-service API, reauthentication rule. | §5.10, §8 covered; e2e logout cases green. |
| **6. Audit, observability, rate limits, cron** | Event catalog, sinks, queue consumer, R2 archive, hot purge, metrics, rate limiting, cron steps, redaction suite. | §6.7, §11, §12.4 covered; soak test green. |
| **7. Hardening and release** | Full security suite, conformance runs with waivers, load tests at 1,000,000 users, runbook, release pipeline with gradual rollout, mutation-test baseline, threat-model review sign-off. | Every identifier covered; conformance archived; load thresholds green; `v1.0.0` tagged. |

**[TIO-GEN-004]** (V: ci) No phase SHALL introduce a test-only code path in `src/` (no `if (env.TEST)`, no backdoor identities, no mock authenticator in production code). The lint rules forbid references to `NODE_ENV`, `VITEST` and `TEST` in `src/`.

### 14.3 Estimated size

For planning only: roughly 9,000–12,000 lines of `src/` TypeScript and 2–3× that in tests, judging by comparable headless providers. The number that matters is the identifier count in this document (see Appendix C), each of which is a unit of work.

---

### 14.4 Code conventions

**[TIO-GEN-005]** (V: review) Every branch that implements a protocol rule SHALL carry a comment citing the specification section it implements (for example `// RFC 6749 §4.1.3: redirect_uri must match the one bound to the code`), and every commit that changes protocol behavior SHALL cite the section in its message. Reviewers reject protocol changes without a citation.

---

## 15. Threat model

| # | Threat | Mitigation | Requirements |
|---|---|---|---|
| T1 | Authorization-code interception or injection | PKCE S256 mandatory; code bound to client, redirect URI, verifier; 60 s lifetime; single use with family revocation on replay; `iss` parameter defeats mix-up | AUTHZ-008, TOKEN-011, TOKEN-012, AUTHZ-021 |
| T2 | Open redirect through the OP | Exact redirect URI matching; non-redirectable errors go to `login_url` only; `post_logout_redirect_uri` registered | CLIENT-010, CLIENT-011, AUTHZ-018, LOGOUT-002 |
| T3 | Refresh-token theft | Rotation with family reuse detection; session-bound families die with the session; opaque encrypted handles; hashes only at rest; revocation endpoint | RT-002, RT-003, RT-006, ARCH-007, REV-002 |
| T4 | Session fixation / login CSRF (attacker completes their auth in the victim's interaction) | Interaction bound to the browser by a cookie verified on every Interaction API call and at `/complete`; `Origin` allow-list; new session secret at authentication; different-user re-auth revokes old session | IX-001, IX-060, SESS-002 |
| T5 | CSRF on logout | No session termination without a valid `id_token_hint` or explicit confirmation | LOGOUT-004 |
| T6 | Phishing | Passkeys are origin-bound; RP ID and origin allow-list verified on every ceremony | PK-002, PK-012, PK-022 |
| T7 | Authenticator cloning | Counter regression detection and event | PK-030 |
| T8 | Upstream compromise or misconfiguration | Full ID-token validation; `(issuer, subject)` identity key; email never an identifier; `required_claims`; `trust_email_verified` opt-in; disabled user check after upstream auth | FED-030–FED-043 |
| T9 | Account takeover via email collision | Uniqueness only among verified emails; linking requires re-authentication by the existing user or is disabled | DATA-006, DATA-007, FED-040 |
| T10 | Storage leak (D1 or DO dump) | No plaintext secrets or tokens; private keys and upstream secrets encrypted under `MASTER_KEYS`; handle secrets hashed | ARCH-007, KEYS-011, CRYPTO-004 |
| T11 | Master-key compromise | Handles become forgeable only in structure; every handle still requires a server-side record; documented re-key runbook | ARCH-009, CRYPTO-011, DEPLOY-004 |
| T12 | Signing-key compromise | Emergency retire endpoint; short token lifetimes; JWKS pre-publication makes rotation routine | KEYS-012, KEYS-013 |
| T13 | Client impersonation | Strict per-client auth method; secret hashed; `private_key_jwt` with a 60-second assertion lifetime and `aud` check; failed-auth rate limits | TOKEN-002, TOKEN-003, TOKEN-004 |
| T14 | Denial of service / brute force | Per-IP, per-client, per-interaction and per-user limits; body and query limits; no unbounded loops; per-user isolation stops one user from affecting others | RL-001–RL-003, HTTP-004, ARCH-002 |
| T15 | Enumeration of users, credentials, invitations | Uniform responses; masked emails; no existence disclosure in the Interaction API | ERR-002, IX-001, IX-070 |
| T16 | Log or audit leakage | Redaction canaries; allow-listed data keys; pseudonymized IP | AUDIT-002, OBS-001, SESS-005 |
| T17 | Privilege escalation to admin | `admin` scope requires live `admins` membership; only admins can grant `admin` to clients; bootstrap single-use | ADMIN-001, CLIENT-002, ADMIN-010 |
| T18 | Malicious or buggy login app | It cannot assert identity; it only relays proofs; origin-restricted | ARCH-010, IX-001 |
| T19 | Host-header attacks | Absolute `ISSUER` for every URL; 421 on mismatch | HTTP-006 |
| T20 | Clickjacking / framing of navigation endpoints | `frame-ancestors 'none'`; no HTML anyway | HTTP-002, GEN-001 |
| T21 | Partial-write inconsistencies between D1 and DO | Ordered writes, repair cron, lazy cleanup, reindex | DATA-026, DATA-027 |
| T22 | Time manipulation / clock skew | Fixed leeway per token type; injected clock tested at boundaries | TOKEN-003, FED-030, TOKEN-034 |
| T23 | Data exfiltration through outbound requests (telemetry, SSRF via configured URLs) | Outbound allow-list limited to configured upstream and client endpoints; no telemetry; `https` required for every configured URL | ARCH-016, FED-001, CLIENT-002 |
| T24 | Stale or confused authorization parameters (`nonce`/`code_challenge` from a previous request, `prompt` loops) | Codes bind exactly their request; session hits reuse nothing; `prompt`/`max_age` never persisted | AUTHZ-024 |
| T25 | Consent or tokens surviving client deletion and id reuse | `client_created_at` binding; lazy deletion on discovery | CLIENT-005 |

**[TIO-SEC-001]** (V: review) The threat model SHALL be reviewed at the end of Phase 7 and whenever a new endpoint or handle type is added; the review is recorded in `doc/adr/`.

---

## Appendix A. authentik feature mapping

| authentik | Tiny OIDC decision | Reason |
|---|---|---|
| OAuth2/OIDC provider | **Kept**, narrowed to code + PKCE, with PAR, JWT AT, resource indicators, back-channel logout | Modern subset; everything advertised is implemented |
| SAML provider | Dropped | Legacy protocol; XML signature surface |
| LDAP / RADIUS providers | Dropped | Legacy; require passwords |
| Proxy provider (forward auth) | Dropped | An API gateway concern; build it as a separate Worker consuming this OP |
| SCIM provider / source | Deferred | Provisioning is valuable but is a second product; the Admin API and import cover migration |
| RAC (remote access) | Dropped | Out of scope |
| OAuth/OIDC sources (social login) | **Kept** as generic OIDC federation with Google and Microsoft verified | Standards-based; provider-specific quirks refused (Apple deferred) |
| SAML / LDAP / Plex / Apple sources | Dropped or deferred | Non-OIDC or quirk-heavy |
| Flows and stages (customizable login flows) | **Replaced** by the login app and the Interaction API | The operator owns the UI completely; the OP owns the decisions |
| Prompt stages, captcha stage, email stage | Replaced (login app) / dropped (email) | No email sending in the OP |
| Password stage and policies | Dropped | No passwords |
| MFA: TOTP, static, SMS, Duo, WebAuthn | **Kept** WebAuthn only, as the primary factor | Passkeys with UV are two-factor by construction |
| Identification stage (username/email first) | Replaced by discoverable passkeys and `login_hint` passthrough | Usernameless |
| Enrollment and invitations | **Kept**: registration modes, invitations, recovery invitations | |
| Recovery flows (email link) | Replaced by admin-issued recovery invitations, second passkeys, federated identities | No email-only recovery |
| Users, groups, attributes | **Kept** users and flat groups; custom attributes dropped | Small surface |
| Application access control (policies bound to applications) | **Kept** as `allowed_groups` per client | The one authorization feature every IdP needs |
| Expression policies, policy engine | Dropped | Not a policy engine |
| Property mappings (custom claims) | Dropped; fixed claim set plus `groups` | Predictable tokens |
| Brands / tenants | Dropped; one issuer per deployment | Multi-tenancy is another deployment |
| Sessions and device management | **Kept** via Self-service and Admin APIs | |
| Events, notifications, transports | **Kept** audit pipeline; webhooks deferred | |
| Outposts | Dropped | No agents |
| Blueprints (config as code) | Deferred | Idempotent CRUD plus `client_credentials` covers automation in v1 |
| Admin UI, user UI | Dropped | API-first; UIs are the operator's |
| API (REST, OpenAPI) | **Kept**, OpenAPI 3.1 | |
| Certificates / key management | **Kept** as the key store with rotation | |
| Branding, custom CSS, footer links | Dropped | No UI |

## Appendix B. Decision log and changes from the initial draft

Each entry: what the draft said → what this spec does → why.

1. **Built-in HTML login/consent/registration pages** → headless OP with an Interaction API and an operator-owned login app. *Why:* the "no UI" requirement; removes CSP, XSS, templating and inline-script concerns from the security core; lets every organization use its own design system.
2. **All state in D1 (users, passkeys, codes, refresh tokens, audit)** → per-user Durable Objects for hot state; D1 as directory. *Why:* one D1 database is single-threaded and capped at 10 GB; refresh rotation alone is hundreds of writes per second at 1,000,000 users; single-use semantics are native in a DO transaction.
3. **Signing key as a Worker secret (`OIDC_SIGNING_KEY_JWK`)** → encrypted key store in D1 with timestamp-derived key roles and API-driven rotation (#32). *Why:* rotation must not require a deploy; overlapping keys need a store.
4. **Audit events in D1 indefinitely** → queue → 30-day hot table + R2 archive, per-user views of the hot table (#31). *Why:* capacity.
5. **Generic `AuthState` DO used as a key-value store** → two typed DO classes with SQLite schemas and RPC methods. *Why:* atomicity, clarity, testability.
6. **Cookie/session model unspecified** → encrypted opaque handles for every secret (§2.4), `__Host-` cookies, explicit binding cookie for interactions. *Why:* routing without global indexes; login-CSRF defense.
7. **`client_type` + `token_endpoint_auth_method`** → only `token_endpoint_auth_method`. *Why:* redundancy; `public` is exactly `none`.
8. **Access token `aud = client_id`** → a static per-client `audiences` list, `ISSUER` added for the OP's own APIs, RFC 9068 `at+jwt`. *Why:* resource servers need a real audience. RFC 8707 resource indicators were designed in and then deferred (#29).
9. **No `sid`, `amr`, `acr`, `at_hash`** → added. *Why:* back-channel logout needs `sid`; clients need authentication context.
10. **Logout "MAY support RP-initiated"** → RP-initiated with hint, confirmation interaction without hint, back-channel logout with retries; front-channel and session iframe rejected. *Why:* third-party cookies are gone; back-channel is the only reliable mechanism.
11. **No PAR / `iss` response parameter / revocation** → added. *Why:* cheap, modern, expected by current libraries and conformance profiles.
12. **No `client_credentials`** → added with `private_key_jwt` and `client_secret_basic`/`client_secret_post`. *Why:* API-first administration needs machine tokens. `client_secret_post` was added specifically because the OIDF basic certification plan exercises it.
13. **Consent as a UI concern** → persistent per-client grants in `UserDO`, `skip_consent` for first-party clients, consent decisions through the Interaction API. *Why:* headless.
14. **Email unique per user** → unique only among verified emails; unverified emails are never used for resolution. *Why:* prevents email squatting at consumer scale.
15. **Recovery "MAY include admin procedure"** → concrete `recover` invitations that always revoke sessions and refresh families and never delete passkeys (#34). *Why:* operators need a defined path with one behavior.
16. **Rate limiting "MAY use Cloudflare controls"** → Rate Limiting binding for coarse limits, DO state for exact per-entity limits, with a numeric table. *Why:* the binding is GA, per-colo and permissive by design, so exact limits live where the state is.
17. **Unit/protocol/browser test list** → eleven suites, 100% coverage gate, traceability gate, concurrency and security suites enumerated, conformance and load as release gates. *Why:* "not tested = not working" must be a CI failure, not a sentence.
18. **Project layout with `ui/`** → no `ui/`; `examples/login-app` as a test fixture. *Why:* no UI.
19. **Recommended tokens in `localStorage` prohibition** → out of scope for the OP (it cannot enforce client storage); moved to `LOGIN_APP_GUIDE.md` guidance.
20. **`ISSUER` and `RP_ID` equal** → `RP_ID` is the registrable domain shared by the OP and the login app; Related Origin Requests for other first-party origins. *Why:* the login app runs on a different origin than the OP.
21. **Groups, self-service API, bulk import** → added; configuration as code was added and later deferred (#33). *Why:* authentik benchmark; 1,000,000-user migration is impossible without import.
22. **Dynamic client registration "OPTIONAL, admin-protected"** → no RFC 7591 endpoint; Admin API only. *Why:* one fewer public surface.
23. **`nodejs_compat`** → forbidden. *Why:* every runtime dependency is Web-standard; keeping the flag off keeps the bundle small and the runtime surface known.

24. **Deployment pipeline unspecified** → Cloudflare Workers Builds per environment (`main` → staging, `production` branch → production), GitHub Actions for gates only, public repository host- and account-neutral, hostnames attached from the operator's infrastructure repository. *Why:* the operator's standing rule for public repositories is that no credential, hostname, zone or account id may land in them; Workers Builds needs no token in GitHub and is the same path the Deploy button exercises.
25. **Deploy-to-Cloudflare button on workers.dev** → optional bundled reference login app served as static assets on the OP origin. *Why:* `workers.dev` is on the Public Suffix List, so two workers.dev names are different sites and the interaction binding cookie would not flow; same-origin static files give a working one-click evaluation while OP code still never generates HTML.
26. **Staging isolation** → staging under its own subdomain with its own RP ID, so staging passkeys never appear in the production picker. *Why:* operator decision; Workers custom domains provision certificates for multi-level names automatically.
27. **License** → MIT. **Git flow** → direct commits to `main` by the implementing agent with the full gate set on every push (changed from pull requests on 2026-09-19 at the owner's request).

**Reference review (2026-09-19).** Before Phase 0 the spec was compared against two similar open-source providers: tinyauth (Go, OpenID Certified Basic OP, forward-auth and OIDC provider, ~22k LOC) and authenti-kate tiny-oidc (Flask, a toy OP with a strong test harness, ~4.7k LOC). Entries 28–36 record what changed as a result.

28. **`ClientDO` replay cache for `private_key_jwt`** → removed; assertions must carry `iat` and expire within 60 s (TIO-TOKEN-003). *Why:* RFC 7523 §3 makes replay rejection optional and neither reference implements `private_key_jwt` at all; the cache cost a DO class, a binding, a token-endpoint hop and a concurrency case for a threat (a captured assertion replayed within a minute) that already implies a compromised client host.
29. **RFC 8707 resource indicators** → deferred; clients get a static `audiences` list (TIO-TOKEN-033). *Why:* per-request audience narrowing is unused by first-party applications; the static list keeps the real-audience property with a fraction of the validation surface.
30. **Self-service identity linking (`link` interaction, `/me/identities/link`, `return_to`)** → deferred. *Why:* login-time linking by verified email covers the common case; the deferred path added a second interaction kind and an open-redirect surface (`return_to`) for a rare need.
31. **Per-user `events` ring in `UserDO`** → removed; per-user views read `audit_hot`. *Why:* the ring was 80% of the per-user storage estimate and an extra DO call per event, to answer a query the indexed hot table already answers.
32. **Four-state key lifecycle (`next`/`active`/`retiring`/`retired` with a two-step activation)** → roles derived from `activates_at` and `retired_at` (§10.3). *Why:* authenti-kate's per-client keys and tinyauth's single unrotated key both show what happens without a rotation story; ours now has no forgettable step and no state column to drift.
33. **`PUT /admin/config` (configuration as code)** → deferred. *Why:* plan/diff/prune semantics are a product of their own; `client_credentials` plus idempotent CRUD serves automation. tinyauth's configuration-first model is its core, not a layer over CRUD.
34. **Client-secret rotation grace period; `revoke_existing` on recovery invitations** → removed. *Why:* the grace period contradicted the single-hash schema, and `private_key_jwt` with several keys already gives zero-downtime rotation; recovery now has one behavior.
35. **Improvements adopted from the references:** `kid` as the RFC 7638 thumbprint with a 512-byte header test (authenti-kate `tests/test_key_id.py`, after a PEM-derived `kid` produced a 1,702-byte header); one `capabilities.ts` constant driving validators and discovery with an equality test (authenti-kate `app/prompts.py`, `tests/test_discovery_jwks.py`); the stale-parameter requirement TIO-AUTHZ-024 (authenti-kate `authorize.py:242-249` documents the exact bug); `prompt=none` never touching the session; lazy cleanup of grants and families when a client is deleted or re-created (tinyauth reconciles consents of vanished clients, `oidc_service.go:1051-1079`; a sweep over 1,000,000 Durable Objects is impossible, so ours is lazy); no `Date.now()` outside `Clock` (authenti-kate `app/times.py`); the e2e relying party never touches OP storage (authenti-kate `tests/e2e/rp_app.py`); generated `doc/CONFIG.md` and `.dev.vars.example` with a drift check (tinyauth `gen/docs/gen_env.go` and its `git diff --exit-code` CI step); an outbound-host allow-list with a no-network test (tinyauth's default-on heartbeat to its vendor); RFC citations as a code convention; introspection and telemetry named as exclusions; the unused `RL_INTERACTION` binding removed.
36. **Kept deliberately although a reference does it more simply:** immutable `sub` (TIO-DATA-001; tinyauth derives it from `username:client_id`); S256-only PKCE (TIO-AUTHZ-008; both accept `plain`); rolling keys with pre-publication (TIO-KEYS-012; neither rotates); Durable-Object-backed codes and state (TIO-ARCH-002; tinyauth uses in-memory caches); refresh families with reuse detection (TIO-RT-002); unknown scopes rejected (TIO-SCOPE-001; tinyauth filters silently); no request objects (TIO-DISC-003; tinyauth parses them unverified); claims gated by scope (TIO-TOKEN-030); `email_verified` only from trusted sources (TIO-DATA-008; tinyauth infers it from a non-empty email); `Secure` cookies always (TIO-SESS-001); one JWKS per issuer (TIO-KEYS-001; authenti-kate publishes a key per client); exact redirect matching (TIO-CLIENT-011; authenti-kate uses an unanchored regex); no plaintext secrets and no tokens in logs (TIO-ARCH-007, TIO-KEYS-011, TIO-TOKEN-004, TIO-AUDIT-002); remembered consent (TIO-CONSENT-001); no public dynamic registration (TIO-CLIENT-001); a blocking coverage gate (TIO-TEST-002; tinyauth's is informational); `client_secret_post` (conformance); the `account` and `admin` scopes; the bundled reference login app.
37. **PKCE mandatory for every client** → mandatory by default, with a per-client `require_pkce = 0` for confidential clients (2026-09-20, ADR 0013). *Why:* the OpenID Foundation conformance suite sends no `code_challenge` in any module of the certification plans except its one PKCE test (verified in the suite's source), so TIO-TEST-040 and the old TIO-AUTHZ-008 could not both hold; a waiver was not available because the reason is limited to unsupported features advertised in discovery. Public clients keep the requirement (PKCE is their only binding); a confidential client's code is bound by client authentication and `nonce`; a present `code_challenge` is verified regardless; the option is a registered, audited client property rather than a test-only path (TIO-TEST-041). `POST /authorize` was added at the same time (OIDC Core §3.1.2.1 requires both methods; the suite warns without it and warnings fail a plan).

**Declined or deferred with the user's decision (2026-09-19):** DPoP (deferred; re-evaluate when public-client sender-constraining is required by a resource server); Apple Sign-in (deferred; needs a JWT client secret rotated every six months and a cross-site `form_post` callback that `SameSite=Lax` binding cookies block). Also deferred by the author: EdDSA signing (client library support is still uneven), pairwise subjects, device grant, token exchange, webhooks, SCIM.

**Operator decisions still open (do not block Phase 0):** Durable Object jurisdiction (`eu` or none); `registration.mode` for the first deployment; whether `METRICS` is enabled; R2 lifecycle for the audit archive.

## Appendix C. Requirement index

Identifiers are numbered per area; gaps are intentional to leave room. The trace tool produces the complete list with test mappings in `doc/TRACEABILITY.md`.

| Area | Prefix | Section |
|---|---|---|
| General | `TIO-GEN` | §1, §14 |
| Architecture | `TIO-ARCH` | §2 |
| Performance | `TIO-PERF` | §2.7 |
| Data model and storage | `TIO-DATA` | §3, §4 |
| HTTP conventions | `TIO-HTTP` | §5.1, §5.14 |
| Discovery | `TIO-DISC` | §5.2 |
| Keys | `TIO-KEYS` | §5.3, §10.3 |
| Authorization endpoint | `TIO-AUTHZ` | §5.4 |
| PAR | `TIO-PAR` | §5.5 |
| Token endpoint and tokens | `TIO-TOKEN` | §5.6, §5.7 |
| Refresh tokens | `TIO-RT` | §5.6.3, §5.7.3 |
| UserInfo | `TIO-UINFO` | §5.8 |
| Revocation | `TIO-REV` | §5.9 |
| Logout | `TIO-LOGOUT` | §5.10 |
| Clients | `TIO-CLIENT` | §5.11 |
| Scopes | `TIO-SCOPE` | §5.12 |
| Errors | `TIO-ERR` | §5.13 |
| Passkeys | `TIO-PK` | §6.1 |
| Sessions | `TIO-SESS` | §6.2 |
| Registration and invitations | `TIO-REG` | §6.3 |
| Federation | `TIO-FED` | §6.4 |
| Recovery | `TIO-REC` | §6.5 |
| Consent | `TIO-CONSENT` | §6.6 |
| Rate limiting | `TIO-RL` | §6.7 |
| Interaction API | `TIO-IX` | §7 |
| Self-service API | `TIO-ME` | §8 |
| Admin API | `TIO-ADMIN` | §9 |
| Cryptography | `TIO-CRYPTO` | §10 |
| Audit | `TIO-AUDIT` | §11 |
| Observability | `TIO-OBS` | §11.4 |
| Privacy | `TIO-PRIV` | §11.5 |
| Configuration | `TIO-CFG` | §12 |
| Deployment | `TIO-DEPLOY` | §12.3 |
| Testing | `TIO-TEST` | §13 |
| Security review | `TIO-SEC` | §15 |

## Appendix D. Glossary

| Term | Meaning |
|---|---|
| **Handle** | An encrypted, prefixed, opaque string issued by the OP (code, refresh token, cookie value, state, invitation). §2.4 |
| **Interaction** | The OP-side record of one authorization, logout or link attempt, driven by the login app. §7 |
| **Login app** | The operator's browser application that renders screens and calls the Interaction API. |
| **Binding cookie** | `__Host-tio_ix_<p>`, ties an interaction to one browser. |
| **Session-bound family** | A refresh-token family that dies with the OP browser session. |
| **Offline family** | A refresh-token family independent of the browser session (`offline_access`). |
| **Directory** | The D1 database: existence, uniqueness, configuration. |
| **UserDO / InteractionDO** | The two Durable Object classes. |
| **Related Origin Requests** | WebAuthn mechanism letting origins outside the RP ID's domain use its passkeys via `/.well-known/webauthn`. |
| **Hot table** | `audit_hot`, the last 30 days of audit events in D1. |
| **Reindex** | Rebuilding a user's D1 mirror and index rows from `UserDO`. |

---

*End of specification.*
