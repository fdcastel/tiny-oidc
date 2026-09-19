# Tiny OIDC

### A headless, passkey-first OpenID Provider that runs entirely on Cloudflare.

Tiny OIDC gives one organization a single, standards-compliant identity service for its own applications: OpenID Connect for relying parties, passkeys and upstream OIDC federation for users, JSON APIs for everything else. No servers, no containers, no external databases. Designed for one million users on one deployment.

> **Status: pre-alpha, under construction.** The [specification](doc/TINY_OIDC_SPEC.md) is the contract for the build and the [implementation plan](doc/TINY_OIDC_PLAN.md) tracks progress phase by phase. Phases 0–6 are done: the core OIDC flow works end to end (discovery, JWKS, `/authorize`, PAR, `/token` with the three grants, `/userinfo`, `/revoke`, the Interaction API, passkey registration and sign-in, invitations, the bootstrap endpoint and the reference login app) and the Admin API covers users, groups, clients, upstreams, invitations, keys, settings, stats, maintenance and bulk import, with a cron that keeps the store tidy, users can sign in through any OpenID Connect upstream (Google, Microsoft, …) with the account-resolution policy enforced, sessions end everywhere through RP-initiated and back-channel logout, first-party apps manage passkeys, sessions, identities and consents through the Self-service API, and every security-relevant action is an audit event that reaches the log, a 30-day hot table and an R2 archive through a queue, with redaction and per-type allow-lists; everything is verified by unit, component, HTTP, interop (`oauth4webapi`), concurrency and Playwright suites. Still to come: hardening and release (Phase 7). The Deploy button below provisions a Worker you can bootstrap and sign in to, but the service is not ready for anything beyond evaluation.

### Already on Cloudflare?

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/fdcastel/tiny-oidc)

## What it is

- **OpenID Connect, modern subset only.** Authorization Code with PKCE (S256), Pushed Authorization Requests, JWT access tokens (RFC 9068), rotating refresh tokens with reuse detection, RP-initiated and back-channel logout, token revocation, client credentials with `private_key_jwt`.
- **Passkeys as the only local credential.** WebAuthn discoverable credentials with user verification required. No passwords, no OTP, no magic links.
- **Federation** to any standards-compliant upstream OIDC provider, with strict ID-token validation and an explicit account-linking policy.
- **Headless.** Your login screens, in any framework, driven by a small JSON Interaction API. A dependency-free reference login app ships as static files for evaluation and tests.
- **API-first administration.** Admin API, self-service API, groups with per-client access control, invitations, bulk NDJSON import, configuration as code, OpenAPI 3.1.
- **Cloudflare-native.** Workers, one Durable Object per user, D1 for the directory, Queues and R2 for audit, rate limiting, cron.
- **Tested is the only definition of working.** Every requirement in the specification has an identifier and a test; 100% coverage and requirement traceability are CI gates.

## What it is not

Passwords, SAML, LDAP, SMS or TOTP factors, magic links, implicit or password grants, front-channel logout, session iframes, HTML rendering of any kind, multi-tenancy, a policy engine.

## Deploy to Cloudflare Workers

The fastest path to a live instance is the Deploy to Cloudflare button above.

1. **Click the button.** Cloudflare forks this repository into your GitHub account and opens the Workers Builds form pre-configured from [wrangler.jsonc](wrangler.jsonc).
2. **Set `ISSUER` and `RP_ID`** to the URL and host your Worker will have, for example `https://tiny-oidc.<your-subdomain>.workers.dev` and `tiny-oidc.<your-subdomain>.workers.dev`.
3. **Fill the secrets** `MASTER_KEYS`, `MASTER_KEY_ACTIVE` and `ADMIN_BOOTSTRAP_TOKEN`. Generate values with `pnpm gen:secrets` (or any tool that prints 32 random bytes as base64); every secret is described in [doc/CONFIG.md](doc/CONFIG.md).
4. Click **Create and deploy.** D1, Durable Objects, Queues and R2 are provisioned for you; migrations run as part of the deploy command.
5. **Bootstrap** your first administrator with one API call, then sign in with a passkey at `/login/` on your Worker.

Production deployments run with the bundled login app disabled and a custom domain attached; see the specification, §12.3.

## Documents

- [Specification](doc/TINY_OIDC_SPEC.md): architecture, protocol surface, APIs, storage, cryptography, testing strategy, implementation plan, threat model.
- [Implementation plan](doc/TINY_OIDC_PLAN.md): the living task list, phase by phase.
- [Configuration](doc/CONFIG.md): every variable, secret and setting (generated from the code).
- [Traceability](doc/TRACEABILITY.md): which test proves which requirement (generated).

## Developing

```sh
pnpm install
pnpm gen:secrets --dev-vars   # writes .dev.vars for wrangler dev
pnpm dev                      # http://localhost:8787/api/v1/health
pnpm test                     # unit + workers suites, 100% coverage gate
pnpm test:e2e                 # Playwright against wrangler dev
pnpm lint && pnpm build && pnpm check && pnpm trace
```

Requires Node 24 and pnpm 10. Every push to `main` runs the full gate set in GitHub Actions; deployments are made by Cloudflare Workers Builds, never by CI.

Staging also runs a fake upstream identity provider (`test/support/fake-upstream/`, the same module the tests mount) as its own Worker: `TIO_ENV=staging TIO_FAKE_ISSUER=… TIO_FAKE_CLIENT_ID=… TIO_FAKE_CLIENT_SECRET=… TIO_FAKE_REDIRECT_URIS=… pnpm run deploy:fake-upstream`. It refuses every other profile.

## License

[MIT](LICENSE).
