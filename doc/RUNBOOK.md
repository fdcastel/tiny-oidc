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
settings (§12.2).

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

**Point-in-time recovery of one user's object** (TIO-DEPLOY-003): a user's
Durable Object can be rolled back to how it was at a past instant:

```sh
curl -s -X POST $ISSUER/api/v1/admin/users/$USER_ID/restore -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" -d '{"bookmark_time":1790000000}'
```

`202` with the bookmark applied; the object restarts from that state on its
next request. Then run the user's reindex (§10) so the directory matches the
restored object. Sessions and refresh tokens created after the bookmark are
gone (they were in the object). The local Durable Object backend has no
point-in-time recovery, so this call is tested only for its input validation
and its 503 `restore_unavailable` path; verify it on staging before relying on
it in production.

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
- Rate limits are two Workers bindings (`RL_IP` 120/60 s per address,
  `RL_CLIENT` 2,000/10 s per client, §6.7); `ratelimit.exceeded` events name
  the class. Raise them in `wrangler.jsonc` and deploy.

## 12. Audit archive

`audit_hot` keeps `audit.hot_retention_days` (default 30) of events for
`GET /api/v1/admin/audit` and `/users/{id}/events`; the queue consumer also
writes every batch to the R2 bucket under
`audit/<yyyy>/<mm>/<dd>/<hh>/<first event id>.ndjson.gz` (§4.5, TIO-DATA-025).
`GET /api/v1/admin/audit/archive?from=<date>&to=<date>` lists
the object keys; download with `wrangler r2 object get <bucket>/<key> --remote`.
Events never carry emails, tokens or addresses in clear (TIO-AUDIT-002).

## 13. Deployment, release and rollback

Staging and production are deployed by Cloudflare Workers Builds
(TIO-DEPLOY-006): `main` builds `tiny-oidc-staging`, the protected
`production` branch builds `tiny-oidc`. Build variables `TIO_ENV`,
`TIO_ISSUER`, `TIO_RP_ID` and `TIO_RP_NAME` are set per Worker in the
dashboard; the build runs `pnpm run build` and `pnpm run deploy`
(`scripts/deploy.ts`: migrations, database resolution, and for production a
versions upload, the smoke test against the preview URL, then the deploy,
TIO-DEPLOY-007).

- **Release:** fast-forward `production` to a `main` commit whose nightly gates
  passed: `git push origin <sha>:production` (TIO-DEPLOY-010). Tag releases
  `vX.Y.Z` on that commit.
- **Rollback:** `git revert` on `production` (never a force-push), or
  `wrangler rollback --env production` for an immediate return to the previous
  Worker version while the revert builds. D1 migrations are forward-only:
  a rollback of code must be compatible with the schema, which is why
  migrations only add.
- **Custom hostnames** are attached outside this repository (TIO-DEPLOY-009).
- **Secrets** (`MASTER_KEYS`, `MASTER_KEY_ACTIVE`, `ADMIN_BOOTSTRAP_TOKEN`) are
  set with `wrangler secret put … --env <env>`; `pnpm gen:secrets` prints
  fresh values. The staging fake upstream is a separate Worker deployed with
  `pnpm run deploy:fake-upstream` (README).
