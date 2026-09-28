# Tiny OIDC — Operations runbook

The procedures an operator runs against a deployment (spec §12.3, TIO-DEPLOY-004).
Every step is an Admin API call or a `wrangler` command; nothing here needs a
dashboard. Where a procedure has a test that proves it, the test is named, and
where it cannot be tested (Cloudflare-only mechanisms such as Time Travel) the
section says so.

## 0. Conventions

| Symbol | Meaning |
|---|---|
| `$ISSUER` | The deployment's issuer URL, for example `https://auth.example.com`. Every endpoint below is relative to it. |
| `$TOKEN` | An access token with the `admin` scope (§1). |
| `--env staging` / `--env production` | The `wrangler` environment. The Worker names are `tiny-oidc-staging` and `tiny-oidc` (`wrangler.jsonc`); the D1 databases `tiny-oidc-staging` and `tiny-oidc-production`; the R2 buckets `tiny-oidc-staging-audit` and `tiny-oidc-production-audit`. The `button` profile (top level, no `--env`) uses `tiny-oidc` and `tiny-oidc-audit`. |

Admin calls are JSON over `https` with `Authorization: Bearer $TOKEN`; errors are
`{ error, error_description, request_id }` (spec §5.13). Every mutation emits an
audit event that names the acting administrator (`GET /api/v1/admin/audit`).

Settings edited with `PATCH /api/v1/admin/settings` take effect within 60 s on
every isolate (TIO-ARCH-011); a deploy makes them immediate.

## 1. Getting an administrator token

There are two kinds of administrator: a person in the `admins` group, who signs
in with a passkey, and an automation client granted the `admin` scope.

### 1.1 A person, through the `admin-cli` client

The bootstrap (§2) registers a public client `admin-cli` with the loopback
redirect `http://127.0.0.1:0/callback` (RFC 8252; any port matches,
TIO-CLIENT-011) and every scope. Any OIDC command-line client works with it;
by hand:

1. Pick a port, say `9876`, and a PKCE verifier `V` (43–128 characters of
   `[A-Za-z0-9._~-]`); compute `C = base64url(sha256(V))`.
2. Open in a browser:

   ```text
   $ISSUER/authorize?response_type=code&client_id=admin-cli
     &redirect_uri=http%3A%2F%2F127.0.0.1%3A9876%2Fcallback
     &scope=openid%20admin&code_challenge=C&code_challenge_method=S256&state=x
   ```

3. Sign in with the passkey. The browser lands on
   `http://127.0.0.1:9876/callback?code=tio_ac_…&state=x&iss=…`; copy `code`
   from the address bar (the connection itself may fail, that is fine). The code
   is valid for 60 s and once.
4. Exchange it:

   ```sh
   curl -s $ISSUER/token -d grant_type=authorization_code -d client_id=admin-cli \
     -d code=tio_ac_… -d redirect_uri=http://127.0.0.1:9876/callback -d code_verifier=V
   ```

   The `access_token` lives `tokens.access_ttl` seconds (default 600). Add
   `offline_access` to the scope for a refresh token.

The `admin` scope is granted only while the user is a member of `admins`, at
sign-in and at every refresh (TIO-SCOPE-002).

### 1.2 An automation client

Create a confidential client with `grant_types: ["client_credentials"]` and
`scopes_allowed` containing `admin` (only an administrator may grant it,
TIO-CLIENT-002), then:

```sh
curl -s $ISSUER/token -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials -d scope=admin
```

`private_key_jwt` clients send a 60-second assertion instead (TIO-TOKEN-003).

## 2. Bootstrap

Runs once per deployment, while `admins` is empty and `bootstrapped_at` is
unset (TIO-ADMIN-010). It needs the `ADMIN_BOOTSTRAP_TOKEN` secret and a login
app: either `BUNDLED_LOGIN_APP=true` or the `login_url` and `login_origins`
settings (§12.2). No administrator exists yet to store those two through the
API, so a hosted login app is registered straight into D1 first:

```sh
wrangler d1 execute tiny-oidc-production --remote --command "INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('login_url', '\"https://login.example.com/\"', 0, 'operator'), ('login_origins', '[\"https://login.example.com\"]', 0, 'operator')"
```

`scripts/bootstrap-staging.ts` runs the whole of this section unattended for
staging (a bot administrator with a virtual passkey, the nightly automation
client, an invitation for the owner's own account).

**Choose the Durable Object jurisdiction before bootstrapping** (TIO-CFG-006).
`DO_JURISDICTION` in `wrangler.jsonc` (`""`, `"eu"` or `"fedramp"`) decides
where every account's object lives, and bootstrap records it: an object made
under one jurisdiction cannot be found from another, so after bootstrap the
OP refuses to run under a different value (health reports `settings:
"error"`, the deploy's smoke test refuses the version, and every login fails
closed until the value is put back). A residency guarantee also needs the D1
database and the R2 bucket created in the same jurisdiction
(`wrangler d1 create <name> --jurisdiction eu`,
`wrangler r2 bucket create <name> --jurisdiction eu`), which can only be
chosen at creation. Local `workerd` implements no jurisdictions: `wrangler
dev` and the test suites run with `""`. Moving an existing deployment to
another jurisdiction is an export of every user and an import into a fresh
deployment, not a setting.

```sh
curl -s -X POST $ISSUER/api/v1/admin/bootstrap \
  -H "Authorization: Bearer $ADMIN_BOOTSTRAP_TOKEN" -H "content-type: application/json" \
  -d '{"email":"root@example.com","display_name":"Root"}'
```

The 201 answer carries `invitation` (the token), `invitation_url`
(`login_url?invitation=…`) and the `admin-cli` client record. Open the URL in
the browser that holds the administrator's authenticator, choose *Create an
account* and register the passkey; the invitation puts the user in `admins`
with the email verified. The invitation expires after seven days (the default
invitation lifetime); if it lapses before it is used, the bootstrap cannot be repeated
(every later call is 410 `bootstrap_completed`): delete the row
`bootstrapped_at` from the D1 `settings` table (`wrangler d1 execute <db>
--remote --command "DELETE FROM settings WHERE key='bootstrapped_at'"`) and call
it again — that is only safe while `admins` is still empty, which the endpoint
also checks.

Afterwards delete the bootstrap secret: `wrangler secret delete
ADMIN_BOOTSTRAP_TOKEN --env production`. Twenty concurrent bootstraps produce
one invitation (`test/concurrency/creation.test.ts`); the wrong token is 401 and
rate-limited (`test/http/bootstrap.test.ts`).

## 3. Signing-key rotation (routine)

Keys have no status column; a key's role follows from `activates_at`,
`retired_at` and the clock (§10.3). `GET /api/v1/admin/keys` lists every key
with its role: `signing`, `next`, `verifying` or `retired`.

Rotation happens by itself: the cron creates a `next` key when the signing
key's `activates_at` is older than `keys.rotation_days` (default 90; `0`
disables), publishes it in the JWKS for `keys.prepublish_seconds` (default
24 h) before it signs, and retires superseded keys once the new key has been
signing for `keys.retire_after_seconds` (default 7 days). Retired rows are
deleted after 90 days (`test/component/keystore.test.ts`, `test/http/admin-system.test.ts`).

To rotate by hand, on the same schedule:

```sh
curl -s -X POST $ISSUER/api/v1/admin/keys/rotate -H "Authorization: Bearer $TOKEN" -d '{}'
```

The new key appears in `/.well-known/jwks.json` at once and starts signing after
`keys.prepublish_seconds`. Nothing else to do; relying parties that cache the
JWKS pick it up in time. `keys.retire_after_seconds` must exceed the longest
ID, access and logout token lifetime plus one hour (the settings validator
enforces it).

## 4. Emergency key retirement (signing-key compromise)

Two calls, in this order:

```sh
# 1. A key that signs immediately (published and signing at once).
curl -s -X POST $ISSUER/api/v1/admin/keys/rotate -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" -d '{"immediate":true}'
# 2. Retire the compromised key by its kid (from GET /api/v1/admin/keys).
curl -s -X DELETE $ISSUER/api/v1/admin/keys/$KID -H "Authorization: Bearer $TOKEN"
```

`DELETE` sets `retired_at`, deletes the private material and removes the key
from the JWKS; every token signed with it is invalid from that moment
(TIO-KEYS-013). Retiring the only active key is refused with 409
`last_active_key`, which is why step 1 comes first. Relying parties see
`invalid_token` on outstanding access tokens for at most `tokens.access_ttl`;
ID tokens already validated are unaffected; refresh tokens are opaque handles
and keep working. `test/http/admin-system.test.ts` and
`test/security/tokens.test.ts` cover retirement and the rejection of tokens
signed by a retired key.

## 5. Master-key rotation

`MASTER_KEYS` is `{"<version>":"<base64 of 32 bytes>", …}` and
`MASTER_KEY_ACTIVE` names the version used for new encryptions (§10.2). Every
handle (session, code, refresh token, interaction binding, federation state,
invitation) and every keystore row (private signing JWKs, upstream secrets)
carries the version it was sealed under. Rotation has three phases
(TIO-CRYPTO-011; `test/component/keystore.test.ts`, `test/http/admin-system.test.ts`):

1. **Add and activate.** Generate a new version (`pnpm gen:secrets` prints one),
   add it to the JSON *keeping the old versions*, set `MASTER_KEY_ACTIVE` to it:

   ```sh
   printf '%s' '{"1":"<old>","2":"<new>"}' | wrangler secret put MASTER_KEYS --env production
   printf '%s' '2' | wrangler secret put MASTER_KEY_ACTIVE --env production
   ```

   Secrets apply to the running Worker without a code deploy. From now on new
   handles and new keystore rows use version 2; old handles still open.
2. **Re-encrypt the keystore.** The cron re-encrypts 50 rows per run; to finish
   at once:

   ```sh
   curl -s -X POST $ISSUER/api/v1/admin/maintenance/rekey -H "Authorization: Bearer $TOKEN"
   ```

   Repeat while `remaining > 0`. The answer lists `signing_keys` and `upstreams`
   re-encrypted and `unrecoverable` rows (sealed under a version the secret no
   longer holds; see §6).
3. **Drop the old version** once every handle sealed under it has expired: the
   longest is `tokens.refresh_absolute_ttl` (default 30 days; sessions and
   invitations are shorter). Then:

   ```sh
   printf '%s' '{"2":"<new>"}' | wrangler secret put MASTER_KEYS --env production
   ```

   Any handle still under version 1 is rejected from then on (TIO-ARCH-008): the
   affected users sign in again, the affected refresh tokens are `invalid_grant`.

Dropping the old version *before* step 2 finished makes the rows sealed under
it unrecoverable; §6 applies to them.

## 6. Lost `MASTER_KEYS`

If the secret is lost (or a version was dropped before its rows were
re-encrypted), the keystore rows sealed under the missing version cannot be
opened: the OP cannot decrypt its signing key and every endpoint that needs one
answers 503 `temporarily_unavailable` ("keys unavailable"; the key store fails
closed rather than sign with anything else), and every handle under that
version is invalid. Public data (users, passkeys, identities, groups,
clients, audit) is intact: only sealed material and outstanding handles are
lost. Recovery:

1. **New secret.** `pnpm gen:secrets`, then `wrangler secret put MASTER_KEYS`
   and `MASTER_KEY_ACTIVE` as in §5 step 1 (keep any version you still have).
2. **Regenerate the signing keys.** The Admin API cannot mint a token while no
   signing key opens, so retire the unopenable keys directly in D1; the next
   request creates a fresh key (TIO-KEYS-010):

   ```sh
   wrangler d1 execute tiny-oidc-production --remote --command \
     "UPDATE signing_keys SET retired_at = unixepoch(), private_jwk_enc = NULL WHERE retired_at IS NULL"
   curl -s $ISSUER/.well-known/jwks.json   # one new key
   ```

   Every token signed by the old keys is now invalid; relying parties refresh
   their JWKS caches on the unknown `kid`.
3. **Sign in again.** Sessions and refresh tokens were handles under the lost
   version: everyone signs in again (passkeys are untouched). Get an
   administrator token (§1.1).
4. **Upstream secrets.** `POST /api/v1/admin/maintenance/rekey` reports the
   upstreams whose `client_secret` or private JWK is `unrecoverable`. Set each
   one again with `PATCH /api/v1/admin/upstreams/{alias}` (`client_secret` or
   `client_jwk`); federated logins through that upstream fail with
   `upstream_error` until then.
5. **Invitations** outstanding at the time were handles too: reissue them
   (`POST /api/v1/admin/invitations`, or `/users/{id}/invitations` for recovery
   ones).

There is nothing to do for relying-party client secrets: they are stored as
hashes, not sealed.

## 7. Client-secret rotation

```sh
curl -s -X POST $ISSUER/api/v1/admin/clients/$CLIENT_ID/rotate-secret -H "Authorization: Bearer $TOKEN"
```

The answer carries the new `client_secret` once; only its hash is stored. The
previous secret stops working immediately (there is no overlap period), so
hand the new secret to the relying party in the same change window; until it
is in place the client's `/token`, `/par` and `/revoke` calls fail with
`invalid_client`. The call is refused with 409 `no_secret` for `none` and
`private_key_jwt` clients; those rotate by `PATCH /clients/{id}` with a new
`jwks` or `jwks_uri`. `test/http/admin-clients.test.ts` covers the rotation and
the rejection of the old secret.

Upstream credentials rotate with `PATCH /api/v1/admin/upstreams/{alias}`
(`client_secret`, `client_jwk`), and `POST /upstreams/{alias}/test` refetches
discovery and JWKS to confirm the configuration. Worker secrets other than the
master keys: `ADMIN_BOOTSTRAP_TOKEN` is single-use and can be deleted after
bootstrap (§2).

## 8. User recovery

There is no password and no email-only recovery (TIO-REC-001). A user who lost
every passkey and has no linked upstream identity gets a **recovery
invitation** from an administrator:

```sh
curl -s -X POST $ISSUER/api/v1/admin/users/$USER_ID/invitations -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" -d '{"kind":"recover","expires_in":3600}'
```

The answer carries `url` (`login_url?invitation=…`). Hand it to the user over a
channel you trust (the OP sends no mail); they open it, choose *Create an
account* in the login app and register a new passkey, which is added to their
existing account. Only `active` users can be recovered (409 `user_not_active`);
a disabled user is enabled first with `POST /users/{id}/enable`.
`test/http/admin-users.test.ts` and `test/http/passkey-interaction.test.ts`
cover the invitation and its consumption.

Related calls: `GET /users/{id}/passkeys` and `DELETE …/passkeys/{pid}` to drop
a lost authenticator; `DELETE /users/{id}/sessions` and
`DELETE /users/{id}/refresh-families` to sign the user out everywhere (both run
back-channel logout); `POST /users/{id}/disable` to freeze an account under
investigation (revokes everything at once, TIO-DATA-009).

**Erasure** (TIO-PRIV-002, TIO-DATA-010): `DELETE /users/{id}` removes the
person's rows from D1 — the `users` row, the index rows, memberships and the
invitations made out to or redeemed by them — and destroys their object. Audit
events never carried their email or name (ADR 0020). Three recovery copies
still hold them until they age out: D1 Time Travel (30 days), the user's
Durable Object point-in-time recovery (30 days) and the `backups/` exports
(90 days, §9). A restore from any of them within those windows brings the
person back: **repeat the deletion right after a restore**, and tell the
requester the recovery copies are gone after 90 days.
`test/http/admin-users.test.ts` ("erasure") scans every D1 table and every log
line for the person's values after a deletion.

**No per-user point-in-time restore in v1** (TIO-DEPLOY-003, ADR 0021).
Rolling one user's object back to a bookmark would bring back everything
withdrawn since: revoked sessions and refresh tokens, consumed codes, removed
passkeys, unlinked identities, revoked consent and removed group memberships.
Recover a user with the tools above instead: a recovery invitation for lost
passkeys, `DELETE …/passkeys/{pid}` and `DELETE /users/{id}/sessions` for a
compromise, and the reindex (§10) when the directory disagrees with the object.
Cloudflare still keeps 30 days of the object's history (TIO-PRIV-002 counts it
as a recovery copy), but nothing in the OP applies it.

## 9. D1 backup and restore

D1 is the directory (users mirror, indexes, groups, clients, upstreams,
settings, keys, invitations, `audit_hot`); the Durable Objects are the source of
truth for every user's state (§4.6). Two mechanisms:

- **Time Travel** (30 days, Cloudflare-managed, no setup):

  ```sh
  wrangler d1 time-travel info tiny-oidc-production --timestamp=2026-09-19T03:00:00Z
  wrangler d1 time-travel restore tiny-oidc-production --timestamp=2026-09-19T03:00:00Z
  ```

- **Weekly export** to the audit bucket (TIO-DEPLOY-003), from an operator
  workstation or the private infrastructure repository (no Cloudflare token is
  stored in GitHub, TIO-DEPLOY-006):

  ```sh
  wrangler d1 export tiny-oidc-production --remote --output=tiny-oidc-$(date -u +%F).sql
  wrangler r2 object put tiny-oidc-production-audit/backups/tiny-oidc-$(date -u +%F).sql \
    --file=tiny-oidc-$(date -u +%F).sql --remote
  ```

  To restore from an export, create an empty database (`wrangler d1 create`),
  `wrangler d1 execute <db> --remote --file=<export>.sql`, and point the Worker
  at it (the deploy script resolves the database by name, TIO-DEPLOY-007).

After any restore the directory is older than the objects. Bring it back in
line, in this order:

1. **Reindex everything** (§10) so the mirror and index rows of every user the
   directory still knows match their objects.
2. **Re-adopt users created after the restore point.** Their objects exist but
   their rows are gone, so they cannot sign in (their passkeys are not in the
   index). Their ids are in the audit archive (`user.created` events, §12) and
   in the relying parties' `sub` claims. For each id, one import line with the
   id alone re-creates the row (the object keeps its state), then the user's
   reindex fills in the mirror and the indexes:

   ```sh
   printf '{"id":"%s"}\n' "$USER_ID" | curl -s -X POST $ISSUER/api/v1/admin/import/users \
     -H "Authorization: Bearer $TOKEN" -H "content-type: application/x-ndjson" --data-binary @-
   curl -s -X POST $ISSUER/api/v1/admin/users/$USER_ID/reindex -H "Authorization: Bearer $TOKEN"
   ```

   This drill is `test/http/admin-import.test.ts` ("the D1 restore drill of the
   runbook").
3. **Settings, clients, upstreams, groups** changed after the restore point are
   lost with the rows; replay them from the audit archive (`settings.updated`,
   `client.*`, `upstream.*`, `group.*` events carry the diffs).
4. **Signing keys** created after the restore point are gone from the table; the
   next request creates a key if none is active, and relying parties refresh the
   JWKS. Tokens signed by the vanished keys fail until then.

Users deleted after the restore point come back as rows without objects; the
Admin API reports them 404 and the lazy cleanup (TIO-DATA-026) drops their index
rows on discovery.

## 10. Reindex

Rebuilds a user's `users` mirror row, `passkey_index`, `identity_index` and
`group_members` from the object (TIO-DATA-027):

```sh
# One user.
curl -s -X POST $ISSUER/api/v1/admin/users/$USER_ID/reindex -H "Authorization: Bearer $TOKEN"
# The whole directory, 100 users per call, resumable.
curl -s -X POST $ISSUER/api/v1/admin/maintenance/reindex -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" -d '{}'
```

The directory-wide call answers `{ processed, failed, next_cursor }`; pass
`{"cursor": next_cursor}` until it is `null` (cursors expire after an hour).
`failed` lists users whose object was unreachable; run them again. A group name
held by an object that no longer exists in D1 is reported in `unknown_groups`
and left out of the mirror. Reindex is the answer to every `partial_failure`
reported by a group or profile update and to the drift a D1 restore leaves
(§9). `test/http/admin-users.test.ts` and `test/http/admin-system.test.ts`
cover both endpoints.

## 11. Health, maintenance and capacity

- `GET /api/v1/health` (no auth): `{ status, version, active_kid, d1, time }`,
  503 when D1 does not answer. Alert on it; it touches no Durable Object.
- `GET /api/v1/admin/stats`: users by status, clients, upstreams, keys by role,
  `audit_hot` rows and `last_cron_run`. A `creating` count that does not return
  to zero, or a `last_cron_run` older than 10 minutes, means the cron is not
  running (check the Worker's trigger and its logs for `system.cron_run`
  with `outcome: failure`).
- `POST /api/v1/admin/maintenance/purge` runs the cron body once, bounded to
  20 s, and returns its report (§12.4): audit purge, expired invitations,
  `creating` repairs and drops, `deleting` completions, key rotation and
  retirement, one re-encryption chunk.
- Queue: audit batches and back-channel logout deliveries go through
  `tiny-oidc-<env>-tasks`; after five failed attempts a message lands in
  `tiny-oidc-<env>-dlq`. A growing dead-letter queue means R2 or D1 refused
  writes (audit) or a relying party's `backchannel_logout_uri` is down.
- **Capacity alarm** (TIO-OBS-005). Every cron run estimates the hot audit
  table's rows (`audit_hot_rows` in the `cron` log line and in
  `system.cron_run`) and logs `audit_hot above its alarm threshold` at `error`
  above 5,000,000. The `watch` workflow checks every environment's stats every
  six hours and fails (you get GitHub's mail) above the same threshold or when
  the cron has not run for 30 minutes. It needs `TIO_<ENV>_ISSUER`,
  `_CLIENT_ID` and `_CLIENT_SECRET` secrets for each environment; production
  is skipped until they exist. **Remedy:** lower `audit.hot_retention_days`
  (`PATCH /admin/settings`, default 7). The cron then purges up to 10,000 rows
  every five minutes, 2.88 M a day. Run `POST /admin/maintenance/purge` for
  more.
- Rate limits are two Workers bindings (`RL_IP` 120/60 s per address,
  `RL_CLIENT` 2,000/10 s per client, §6.7); `ratelimit.exceeded` events name
  the class. Raise them in `wrangler.jsonc` and deploy.

## 12. Audit archive

`audit_hot` keeps `audit.hot_retention_days` (default 14) of the **hot**
event types for `GET /api/v1/admin/audit` and the per-user views
(TIO-AUDIT-013). The queue consumer writes **every** event to the R2 bucket,
one object per group of messages, under
`audit/year=<yyyy>/month=<mm>/day=<dd>/hour=<hh>/<first event id>-<write id>.ndjson.gz`
(§4.5, TIO-DATA-025). Every write takes a new key, so an event redelivered by
the queue may appear twice. Deduplicate by `id` when reading.
`GET /api/v1/admin/audit/archive?from=<date>&to=<date>` lists the object
keys; download with `wrangler r2 object get <bucket>/<key> --remote`.
Objects written before ADR 0022 sit under `audit/<yyyy>/<mm>/<dd>/<hh>/`.
Events never carry emails, names, tokens or addresses in clear (TIO-AUDIT-002,
ADR 0020).

**Investigations with DuckDB** (read-only R2 token; the path segments prune by
time):

```sql
CREATE SECRET (TYPE r2, KEY_ID '…', SECRET '…', ACCOUNT_ID '…');
SELECT DISTINCT ON (id) *
FROM read_json_auto('r2://<bucket>/audit/year=2026/month=10/day=*/hour=*/*.ndjson.gz', hive_partitioning = true)
WHERE user_id = '<user id>'
ORDER BY ts;
```

**Retention.** Without a lifecycle rule the bucket keeps everything forever,
including the weekly D1 exports under `backups/` (§9), which hold emails and
profiles. A deleted user's email would then outlive the deletion in every old
export. The recommended rules, set once per bucket:

```sh
wrangler r2 bucket lifecycle add <bucket> backups-90d "backups/" --expire-days 90
wrangler r2 bucket lifecycle add <bucket> audit-365d "audit/" --expire-days 365
wrangler r2 bucket lifecycle add <bucket> audit-ia-120d "audit/" --ia-transition-days 120
```

Use two rules: wrangler 4.135 given both flags in one rule recorded the
transition at the expiry age (365 days), as `lifecycle list` showed on
staging on 2026-09-28. Check with `wrangler r2 bucket lifecycle list <bucket>`.

- Ninety days of exports is well past the 30 days D1 Time Travel already
  covers, and 365 days of audit history is the usual baseline for security
  logs.
- Objects move to Infrequent Access at 120 days, after the lock's 90 days
  below. The docs do not say whether a locked object may change storage
  class.
- Raising a period later is safe: objects not yet expired are kept. Lowering
  it deletes what is older at the next lifecycle run.

**The lock** (P8-04, ADR 0022). A bucket lock keeps the archive write-once for
90 days:

```sh
wrangler r2 bucket lock add <bucket> audit-90d --prefix "audit/year=" --retention-days 90
```

What it does, as tested on a throw-away bucket on 2026-09-28:
- A **new** key under the locked prefix is accepted.
- **Rewriting** an existing key is refused with R2 error `10069` ("The object
  is locked by the bucket policy", HTTP 409). The consumer never rewrites: every
  write takes a new key.
- A **delete** is refused too, **but `wrangler r2 object delete` still prints
  "Delete complete."** Check with `wrangler r2 object get`.
- The rule guards against the Worker's own binding and mistakes, not against
  the account: anyone with bucket-configuration rights can lift it. That is
  also the way out of a leak.
- The prefix `audit/year=` leaves the objects written before ADR 0022
  unlocked.

**A leak into locked objects** (personal data archived by mistake, as before
ADR 0020):
1. `wrangler r2 bucket lock list <bucket>`, then
   `wrangler r2 bucket lock remove <bucket> --name audit-90d`.
2. Find the affected keys (DuckDB, filtering on the leaked value), delete them
   with `wrangler r2 object delete <bucket>/<key> --remote`, and confirm each
   is gone with `wrangler r2 object get` (it must fail).
3. Put the rule back with the `lock add` command above, the same day.
4. Record what was removed and why. The archive no longer shows it.

## 13. Deployment, release and rollback

Staging and production are deployed by Cloudflare Workers Builds
(TIO-DEPLOY-006): `main` builds `tiny-oidc-staging`, the protected
`production` branch builds `tiny-oidc`. Build variables `TIO_ENV`,
`TIO_ISSUER`, `TIO_RP_ID` and `TIO_RP_NAME` are set per Worker in the
dashboard; the build runs `pnpm run build` and `pnpm run deploy`
(`scripts/deploy.ts`, TIO-DEPLOY-007). Both environments deploy by **staged
rollout** ([ADR 0018](adr/0018-staged-rollout-through-version-overrides.md)):
the script reads the live version, applies D1 migrations, uploads the new
version, puts it in the deployment at 0%, smoke-tests it on the issuer's
hostname through the `Cloudflare-Workers-Version-Overrides` header (health
must report the new build), and only then gives it 100%. A failed smoke test
puts the live version back at 100% and fails the build; the previous version
keeps serving. Every push to `main` exercises this path on staging.

- **First deployment of a Worker** (production's first release, a rebuilt
  staging): there is no live version to stage against. Set the build variable
  `TIO_DIRECT_DEPLOY=true` for that one build, which deploys with a plain
  `wrangler deploy`; attach the hostname (TIO-DEPLOY-009), run
  `pnpm smoke <issuer>`, and delete the variable before the next build.
- **A release that adds, renames or deletes a Durable Object class** carries a
  class migration, which Cloudflare cannot upload as a version: the staged
  rollout fails at the upload. Deploy that one release with
  `TIO_DIRECT_DEPLOY=true` as above. SQLite schema changes inside `UserDO`
  are not class migrations and roll out staged as usual.
- **A deployment split between versions** (someone started a gradual rollout
  by hand) is refused by the script until one version is back at 100%:
  `wrangler versions deploy <version>@100% --yes --env <env>`.

- **Release:** fast-forward `production` to a `main` commit whose nightly gates
  passed: `git push origin <sha>:production` (TIO-DEPLOY-010). Tag releases
  `vX.Y.Z` on that commit.
- **Rollback:** `git revert` on `production` (never a force-push), or, for an
  immediate return while the revert builds, `wrangler deployments list --env
  production` to find the previous version and `wrangler versions deploy
  <previous>@100% --yes --env production` (or `wrangler rollback --env
  production`). The next build deploys the revert by staged rollout like any
  other release. D1 migrations are forward-only:
  a rollback of code must be compatible with the schema, which is why
  migrations only add.
- **Custom hostnames** are attached outside this repository (TIO-DEPLOY-009).
- **Secrets** (`MASTER_KEYS`, `MASTER_KEY_ACTIVE`, `ADMIN_BOOTSTRAP_TOKEN`) are
  set with `wrangler secret put … --env <env>`; `pnpm gen:secrets` prints
  fresh values. The staging fake upstream is a separate Worker deployed with
  `pnpm run deploy:fake-upstream` (README).
