# Connecting upstream identity providers

Tiny OIDC can hand authentication to any OpenID Connect provider: the user
clicks a button in your login app, signs in at Google, Microsoft Entra ID or
any compliant issuer, and comes back with an account here (spec §6.4). This
guide is the operator's side of that — what to register at the provider, what
to store here, and how to prove a real login works before you let anyone use
it.

It assumes a running deployment, an administrator token, and nothing else.
Everything below is an Admin API call; no dashboard of ours is involved,
because there is none.

## 0. Conventions

| Symbol | Meaning |
|---|---|
| `$ISSUER` | Your deployment's issuer URL, for example `https://auth.example.com`. |
| `$TOKEN` | An access token with the `admin` scope ([Runbook §1](RUNBOOK.md)). |
| `<alias>` | The short name you give an upstream: `[a-z0-9][a-z0-9_-]{0,31}`, for example `google`. |

Calls are JSON over HTTPS with `Authorization: Bearer $TOKEN`. Errors come
back as `{ error, error_description, request_id }`, and every mutation is an
audit event naming the administrator who made it.

**The redirect URI is always `$ISSUER/federation/callback`** — one URI for
every provider, fixed by the protocol surface (TIO-FED-002). It is also
reported in each upstream record, so you can read it back instead of
assembling it by hand. Providers match it exactly: scheme, host, path, no
trailing slash, no query.

## 1. The shape of the work

Whatever the provider, the steps are the same:

1. Register an application there, with `$ISSUER/federation/callback` as the
   redirect URI, and collect a **client id** and a **client secret**.
2. Create the upstream record here (`POST /api/v1/admin/upstreams`). With
   `discovery.mode = "auto"` — the default — the provider's
   `/.well-known/openid-configuration` is fetched and checked as part of the
   call, so a wrong issuer fails immediately (TIO-FED-001).
3. Decide who may arrive through it (§4 below): registration mode, automatic
   account creation, and what happens when a federated email matches an
   existing account.
4. Sign in once for real and read the result back through the Admin API (§5).

### The upstream record

`POST /api/v1/admin/upstreams` takes the whole record; `PATCH
/api/v1/admin/upstreams/<alias>` takes any subset of it except `alias`.

| Field | Default | What it does |
|---|---|---|
| `alias` | — | The name used in APIs and in the login app's button list. |
| `issuer` | — | The provider's issuer URL, `https` only. Must equal the `issuer` in its discovery document exactly. |
| `display_name` | — | What your login app shows on the button. |
| `client_id` | — | From the provider. |
| `client_secret` | — | From the provider. Write-only: stored sealed, never returned. |
| `token_endpoint_auth_method` | — | `client_secret_post`, `client_secret_basic` or `private_key_jwt`. |
| `scopes` | `openid email profile` | Space-separated, sent on every authorization request. |
| `discovery` | `{"mode":"auto"}` | `auto` fetches the metadata; `manual` takes `authorization_endpoint`, `token_endpoint`, `jwks_uri` and an optional `userinfo_endpoint` from you. |
| `use_userinfo` | `false` | Also call the provider's userinfo endpoint and let its claims override the ID token's. Needed only by providers that keep claims out of the ID token. |
| `trust_email_verified` | `false` | Whether to believe the provider's `email_verified`. Left false, every account arriving through this upstream has an **unverified** email. |
| `claims_map` | `{}` | Which upstream claims carry `email`, `email_verified` and `name` when they are not called that. |
| `required_claims` | `{}` | Equality checks the ID token must satisfy, for example `{"hd": "example.com"}`. A mismatch refuses the login. |
| `extra_authorize_params` | `{}` | Extra query parameters on the authorization request, for example `{"prompt": "select_account"}`. |
| `forward_login_hint` | `false` | Pass a `login_hint` from the relying party on to the provider. |
| `enabled` | `true` | A disabled upstream disappears from the login app and refuses new logins. |

After creating it, `POST /api/v1/admin/upstreams/<alias>/test` refetches the
discovery document and the JWKS and reports both:

```json
{
  "discovery": { "ok": true, "reason": null, "metadata": { "authorization_endpoint": "…", "token_endpoint": "…", "jwks_uri": "…", "userinfo_endpoint": "…" } },
  "jwks": { "ok": true, "reason": null, "keys": 2 }
}
```

Run it after every credential change; it is the cheapest proof that the
provider is reachable and that you typed the issuer correctly.

## 2. Google

### 2.1 In the Google Cloud console

1. Create or pick a project at <https://console.cloud.google.com>.
2. **APIs & Services → OAuth consent screen** (newer consoles: **Google Auth
   platform → Branding**). Choose **External** unless every user is in your
   Google Workspace organization, fill in the application name, support email
   and developer contact. The scopes to declare are the three default ones:
   `openid`, `email`, `profile`. Nothing else is needed — Tiny OIDC reads
   identity claims only, never Gmail, Drive or the rest.
3. While the consent screen is in **Testing**, only the accounts you list as
   test users can sign in, and refresh is capped. Publish it before real
   users arrive. With only the three basic scopes, publishing needs no
   verification review.
4. **Credentials → Create credentials → OAuth client ID → Web application**.
   Under *Authorized redirect URIs* add exactly:

   ```text
   https://auth.example.com/federation/callback
   ```

   Authorized JavaScript origins stay empty; the flow is server-side.
5. Copy the **Client ID** and **Client secret**.

### 2.2 The upstream record

```json
{
  "alias": "google",
  "issuer": "https://accounts.google.com",
  "display_name": "Google",
  "client_id": "…apps.googleusercontent.com",
  "client_secret": "…",
  "token_endpoint_auth_method": "client_secret_post",
  "scopes": "openid email profile",
  "discovery": { "mode": "auto" },
  "trust_email_verified": true
}
```

```sh
curl -sS -X POST "$ISSUER/api/v1/admin/upstreams" -H "authorization: Bearer $TOKEN" -H "content-type: application/json" -d @google.json
curl -sS -X POST "$ISSUER/api/v1/admin/upstreams/google/test" -H "authorization: Bearer $TOKEN"
```

### 2.3 Notes

- **`trust_email_verified: true` is safe here.** Google issues a boolean
  `email_verified` and means it. That is what lets a Google login link to an
  existing account by email instead of creating a second one (§4).
- **Restricting to one Workspace domain:** add
  `"required_claims": {"hd": "example.com"}`. The `hd` claim is present only
  for Workspace accounts, so this also excludes consumer `@gmail.com`
  accounts. Do not try to achieve the same by checking the email suffix —
  `hd` is the claim Google guarantees.
- **Account chooser:** `"extra_authorize_params": {"prompt": "select_account"}`
  makes Google ask which account to use instead of silently reusing the one
  already signed in to the browser. Useful on shared machines, and useful
  while testing.
- `use_userinfo` can stay `false`: Google puts `email`, `email_verified` and
  `name` in the ID token.

## 3. Microsoft Entra ID (single tenant)

A *single-tenant* registration accepts only accounts from your own directory.
That is the configuration described here; see §3.7 for why multi-tenant and
personal-account modes are not supported.

### 3.1 If you have no Microsoft tenant yet

You need a **work or school** tenant; a personal Microsoft account alone can
no longer create one. The two usual routes:

- **Azure free account** (<https://azure.microsoft.com/free>): sign in with a
  personal Microsoft account, pass the phone and card identity check — the
  card is verification only, with a small temporary authorization that is
  released — and a directory is created for you, with your account as its
  Global Administrator. You never need to create an Azure resource, and the
  Microsoft Entra ID **Free** tier includes application registrations at no
  cost.
- **A Microsoft 365 Business trial**, which also gives a tenant but turns
  into a paid subscription unless cancelled.

Nothing in this guide costs money on either route.

### 3.2 The app registration

At <https://entra.microsoft.com> → **Identity → Applications → App
registrations → New registration**:

| Field | Value |
|---|---|
| Name | anything, for example `tiny-oidc` |
| Supported account types | **Accounts in this organizational directory only (single tenant)** |
| Redirect URI | platform **Web**, `https://auth.example.com/federation/callback` |

From the registration's **Overview**, copy the **Application (client) ID** and
the **Directory (tenant) ID**.

### 3.3 A client secret

**Certificates & secrets → Client secrets → New client secret**. Copy the
**Value** immediately — it is displayed once, and the *Secret ID* beside it is
not the secret. Note the expiry date; Entra secrets always expire, so plan the
rotation (§6) into your calendar.

### 3.4 Claims

**Token configuration → Add optional claim → ID → `email`** (add
`given_name` and `family_name` if you want them). Accept the prompt offering
to turn on the Microsoft Graph `email` permission. The delegated permissions
`openid`, `profile` and `email` need no administrator consent.

Two things to know before the first login:

- **Entra never issues `email_verified`.** Leave `trust_email_verified` at
  `false`. Accounts arriving through Entra therefore hold an *unverified*
  email, which means they are never found by email when some other provider
  or an administrator looks for them (TIO-DATA-007), and they cannot be
  linked to an existing account by email (§4). Federated logins still resolve
  perfectly through the `(issuer, subject)` pair, which is the primary path.
- **The `email` claim can be absent.** It is populated from the user's mail
  attribute, which a cloud-only account without a mailbox may not have. If
  your first login arrives with no email, map the user principal name
  instead:

  ```json
  "claims_map": { "email": "preferred_username" }
  ```

  An account may also exist with no email at all; it simply cannot be found
  by one afterwards.

### 3.5 A user to test with

Create a normal member in the directory (**Identity → Users → New user →
Create new user**), sign in with it once at
<https://myaccount.microsoft.com> to replace the temporary password, and
complete whatever multi-factor registration the tenant requires. Use that
account for the verification login, not the administrator account that owns
the tenant.

### 3.6 The upstream record

```json
{
  "alias": "microsoft",
  "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "display_name": "Microsoft",
  "client_id": "<application (client) id>",
  "client_secret": "<the secret value>",
  "token_endpoint_auth_method": "client_secret_post",
  "scopes": "openid email profile",
  "discovery": { "mode": "auto" },
  "trust_email_verified": false
}
```

`<tenant-id>` is the Directory (tenant) ID — the GUID, or your
`example.onmicrosoft.com` domain, as long as it is the form that the
discovery document's own `issuer` uses.

### 3.7 Notes

- **Multi-tenant and personal-account registrations are not supported.**
  Their metadata is served from the `organizations`, `consumers` or `common`
  endpoints, whose `issuer` is the template
  `https://login.microsoftonline.com/{tenantid}/v2.0`. TIO-FED-001 requires
  the document's issuer to equal the configured issuer exactly, and an ID
  token from such an endpoint carries a per-tenant issuer that no fixed
  configuration can match. Register one upstream per tenant instead: the
  aliases are yours to name, and each gets its own button.
- **Guest (B2B) accounts** in your tenant can sign in through a single-tenant
  registration; they authenticate at their home tenant and return with your
  tenant's issuer and a subject scoped to it, which is exactly what
  federation here expects.
- `extra_authorize_params` accepts Entra's `prompt` (`select_account`,
  `login`) and `domain_hint` if you want to steer the sign-in page.

## 4. Who may arrive through an upstream

Three settings decide what a federated login does when it is not already
linked (`PATCH /api/v1/admin/settings`, effective within 60 s):

| Setting | Values | Effect on federation |
|---|---|---|
| `registration.mode` | `closed`, `invite`, `open` | `closed` refuses every account creation, including federated ones. |
| `federation.auto_create` | boolean, default `false` | Whether a first-time federated login may create an account. |
| `federation.link_by_verified_email` | `never`, `reauth` (default) | What happens when the upstream's **verified** email matches an existing account: refuse, or ask that user to prove the account is theirs with a passkey, then link. |

Resolution runs in this order and stops at the first match (TIO-FED-040):

1. The `(issuer, subject)` pair is already linked → that account signs in,
   and the identity's `email`, `name` and `last_login_at` are refreshed.
2. The upstream email is verified *and* belongs to an existing account →
   `never` refuses with `account_exists`; `reauth` starts a link interaction
   that the owner completes with a passkey.
3. `federation.auto_create` is on (or the interaction carries a register
   invitation) and registration is not closed → a new account, created with
   the upstream's email, its verification state and the profile name.
4. Otherwise the login is refused with `registration_closed`.

A practical consequence: to let people sign up with Google or Entra by
themselves, turn `federation.auto_create` on. To let only invited people in,
leave it off and send invitations. Either way, step 2 is what prevents a
second account for someone who already has one — and it needs a *verified*
email, which is why `trust_email_verified` matters so much per provider.

## 5. Verifying a real login

Registration is not proof. Sign in once, end to end, through a relying party
you control, and read the result back.

1. Set `federation.auto_create` to `true` if the test account does not exist
   yet, and remember to put it back afterwards if that is not your policy.
2. Start a login at a relying party, pick the provider's button in your login
   app, authenticate, and let the browser return.
3. Read the account back:

   ```sh
   curl -sS "$ISSUER/api/v1/admin/users?email=person@example.com" -H "authorization: Bearer $TOKEN"
   curl -sS "$ISSUER/api/v1/admin/users/<id>/identities" -H "authorization: Bearer $TOKEN"
   curl -sS "$ISSUER/api/v1/admin/users/<id>/sessions" -H "authorization: Bearer $TOKEN"
   curl -sS "$ISSUER/api/v1/admin/users/<id>/events" -H "authorization: Bearer $TOKEN"
   ```

What each answer should show on a first login:

- **the user**: the email and display name the provider sent, `status`
  `active`, one identity, one session;
- **the identity**: the provider's `issuer`, its opaque `subject`, and
  `last_login_at: null` — the column is written when the identity is linked
  and set only by a *later* login through it, so a null here means "this is
  the login that created it", not a fault;
- **the session**: `amr ["fed"]`, `acr urn:tinyoidc:acr:federated` and the
  upstream alias (TIO-FED-042);
- **the audit trail**, in order: `user.created`, `identity.linked`,
  `identity.login_succeeded`, `session.created`, `authz.code_issued`,
  `interaction.completed`, `token.issued`.

And in the ID token your relying party received: `sub` is the account id
here, never the provider's subject, which no relying party ever sees
(TIO-DATA-001).

**The second login is worth doing too**, and it needs a trick: with a usable
session, `/authorize` issues a code without going near the provider
(TIO-AUTHZ-014), so you would be testing single sign-on rather than
federation. Send `prompt=login` to force a fresh authentication. Then the
trail shows `identity.login_succeeded` with **no** `user.created` and **no**
`identity.linked` (step 1 of the resolution order), the identity's
`last_login_at` filled in, and `session.rotated` rather than
`session.created`: the same user re-authenticating in the same browser keeps
its `sid` and gets a new `auth_time` (TIO-SESS-002).

## 6. Rotating, disabling, removing

- **Rotate a secret:** `PATCH /api/v1/admin/upstreams/<alias>` with
  `{"client_secret": "…"}`, then `POST …/test`. Do it before the provider's
  expiry date; an expired secret fails every login with `upstream_error`.
- **Suspend a provider:** `PATCH` with `{"enabled": false}`. The button
  disappears from the login app and new logins are refused; existing sessions
  and accounts are untouched.
- **Remove it:** `DELETE /api/v1/admin/upstreams/<alias>`. Linked identities
  survive as records of how an account was created, but nobody can sign in
  through that provider any more — make sure those accounts have another way
  in (a passkey, or another upstream) first.
- After a master-key rotation, upstream secrets that could not be re-sealed
  are reported by `POST /api/v1/admin/maintenance/rekey` and must be set
  again ([Runbook §5–§6](RUNBOOK.md)).

## 7. When it does not work

| Symptom | Cause | Fix |
|---|---|---|
| `upstream_discovery_failed` when creating | The issuer is wrong, unreachable, or its document's `issuer` differs from what you sent | Fetch `<issuer>/.well-known/openid-configuration` yourself and copy its `issuer` verbatim |
| The provider shows "redirect URI mismatch" | The registered URI is not exactly `$ISSUER/federation/callback` | Compare character by character; a trailing slash or `http` is enough to break it |
| `upstream_error` right after the provider's consent | Bad or expired client secret, wrong auth method, or a signature that fails validation | `POST …/test`, then read the audit events: `upstream.*` entries carry the reason |
| `registration_closed` | No account exists and nothing allows creating one | Turn on `federation.auto_create`, or invite the person, or create the account first |
| `account_exists` | A verified email already belongs to another account and linking is `never` | Switch to `reauth` so the owner can link it with a passkey, or merge the accounts by hand |
| The account arrives with no email | The provider did not send one | Map another claim with `claims_map`, or request the scope that carries it |
| `email_verified` is false although the provider says it is true | `trust_email_verified` is off, or the claim is the string `"true"` rather than boolean `true` | Turn it on only for providers that mean it, and only when the claim is a real boolean (TIO-FED-033) |

Every failure above is an audit event (`upstream.discovery_failed`,
`identity.login_failed`, …) with a `reason`, so
`GET /api/v1/admin/audit?type=upstream.discovery_failed` is usually faster
than guessing.

## 8. Where the rules live

The behaviour described here is specified in [§6.4 of the
specification](TINY_OIDC_SPEC.md) — discovery (TIO-FED-001), the fixed
redirect URI (TIO-FED-002), ID-token validation (TIO-FED-030), claim
extraction (TIO-FED-033), account resolution (TIO-FED-040) and the
authentication context it produces (TIO-FED-042) — and every rule has a test
against a fake provider that can be made to misbehave on demand, listed in
[the traceability matrix](TRACEABILITY.md).
