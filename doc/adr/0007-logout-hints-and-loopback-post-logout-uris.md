# 0007 — Logout hint decisions and loopback `post_logout_redirect_uri` ports

Date: 2026-09-19 · Status: Accepted · Task: P5-01

## Context

§5.10 leaves four cases open: an `id_token_hint` whose `client_id` parameter
disagrees with its audience, a hint with several audiences, a hint for an
unknown audience, and a hint without `sid` (an offline ID token). It also says
`post_logout_redirect_uri` matches "exactly" (TIO-LOGOUT-002) while
`/authorize` tolerates any port for loopback redirect URIs (TIO-CLIENT-011,
RFC 8252) — and the bootstrap's `admin-cli` client is a loopback client that
needs a post-logout return.

## Decision

- A hint whose `client_id` disagrees with its audience, a multi-audience hint
  and an unknown audience are `invalid_request`, rendered through `login_url`.
- A hint without `sid` ends nothing (there is no session to end) and the
  logout proceeds to the return URI.
- `post_logout_redirect_uri` matching reuses the `/authorize` matcher, so
  loopback clients may return on any port; every other URI matches exactly.
  The `admin-cli` client registers `http://127.0.0.1:0/loggedout`.
- `state` is echoed only to the client's registered URI, never to the landing
  URL.

## Consequences

- One matcher for both endpoints; the loopback tolerance is the single
  exception of TIO-CLIENT-011 applied consistently.
- TIO-LOGOUT-002's "exactly" is read with that exception; recorded in P5-01.

## Requirements and evidence

TIO-LOGOUT-001..005, TIO-CLIENT-011 — `test/http/logout.test.ts`,
`test/security/redirects.test.ts`.
