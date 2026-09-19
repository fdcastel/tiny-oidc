# Writing a login app for Tiny OIDC

Tiny OIDC is headless: it never renders a page. When a relying party sends a
browser to `/authorize` and the OP needs the user, it redirects the browser to
your **login app** with one query parameter, `interaction`, and sets a
per-interaction binding cookie on its own origin. Your app then talks to the
**Interaction API** (`/api/v1/interactions/{id}`, spec §7) to find out what is
needed, runs the passkey ceremony in the browser, and finally sends the browser
to the completion URL the OP hands back. The OP makes every security decision;
the app owns pixels.

The reference implementation is [`examples/login-app/`](../examples/login-app/):
three static files, no build step, no dependencies. It is served by the OP
itself under `/login/` when the var `BUNDLED_LOGIN_APP` is `true`.

## Contract

1. **Origin.** Every Interaction API call must carry an `Origin` in the
   `login_origins` setting (bundled mode: the OP's own origin) and the binding
   cookie, so use `fetch(url, { credentials: "include" })`. A `GET` with no
   `Origin` is accepted only from a same-site navigation.
2. **Document.** `GET /api/v1/interactions/{id}` returns the state:
   `login_required`, `link_required`, `consent_required`, `ready`, `completed`
   or `failed`, plus `client`, `request` (scopes, prompt, hints), `methods`
   (passkey, registration mode, upstreams), `session_user`, `consent`, `link`,
   `logout`, `error` and `attempts_remaining`. It never contains the user id,
   an email in clear, the redirect URI, `state`, `nonce` or any handle.
3. **Passkey sign-in.** `POST …/passkey/options` → `navigator.credentials.get()`
   → `POST …/passkey/verify { response }`. Each call counts against the
   per-interaction attempt limit (10). Only the most recent challenge is
   valid, and `verify` consumes it whether or not it succeeds.
4. **Registration.** `POST …/register/options { invitation?, email?, display_name? }`
   → `navigator.credentials.create()` → `POST …/register/verify { response, name? }`.
   Without an invitation this works only when `registration.mode` is `open`;
   `email_in_use: true` in the options response means a verified account holds
   that email already (registration still proceeds with an unverified email).
5. **Consent.** In `consent_required`, show `consent.scopes` (name, English
   description, `granted`) and `POST …/consent { decision: "grant", scopes }`
   or `{ decision: "deny" }`. `openid` is always granted.
6. **Finishing.** Every step answers `{ status, redirect_to }`. When
   `redirect_to` is set (`ready` or `failed`), navigate there:
   `${ISSUER}/interactions/{id}/complete` creates the session, issues the code
   and redirects to the relying party. When it is `null`, reload the document:
   the next step is consent.
7. **Abort.** `POST …/abort` fails the interaction with `access_denied`; then
   navigate to the completion URL so the relying party learns the outcome.
8. **Errors.** JSON `{ error, error_description, request_id }`. Codes are
   listed in spec §7.8. `passkey_verification_failed` is the answer for an
   unknown credential too. `interaction_not_found` means the interaction
   expired (600 s) or was completed.
9. **Invitations.** The bootstrap endpoint and administrators hand out
   `login_url?invitation=<token>` links. The reference app stores the token in
   `sessionStorage` until an interaction arrives, then pre-fills the
   registration form with it.

## Hosting your own app

Serve the files from any `https` origin, set the `login_url` and
`login_origins` settings to it (they must be same-site with `ISSUER`), and add
the origin to `webauthn_origins` if it is outside the RP ID's registrable
domain. Set the `tio-issuer` meta tag (or replace the `issuer` constant) to the
OP's issuer URL when the app is not served by the OP itself.
