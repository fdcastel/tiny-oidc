# Tiny OIDC

### A headless, passkey-first OpenID Provider that runs entirely on Cloudflare.

Tiny OIDC gives one organization a single, standards-compliant identity service for its own applications: OpenID Connect for relying parties, passkeys and upstream OIDC federation for users, JSON APIs for everything else. No servers, no containers, no external databases. Designed for one million users on one deployment.

> **Status: pre-alpha.** The [specification](doc/TINY_OIDC_SPEC.md) is complete and is the contract for the build. Implementation has not started. The Deploy button below is wired for the day it does.

### Already on Cloudflare?

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/fdcastel/tiny-oidc)

## What it is

- **OpenID Connect, modern subset only.** Authorization Code with PKCE (S256), Pushed Authorization Requests, JWT access tokens (RFC 9068), resource indicators, rotating refresh tokens with reuse detection, RP-initiated and back-channel logout, token revocation, client credentials with `private_key_jwt`.
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
3. **Fill the secrets** `MASTER_KEYS` and `ADMIN_BOOTSTRAP_TOKEN`. The generator command is documented in the specification (§12.2).
4. Click **Create and deploy.** D1, Durable Objects, Queues and R2 are provisioned for you; migrations run as part of the deploy command.
5. **Bootstrap** your first administrator with one API call, then sign in with a passkey at `/login/` on your Worker.

Production deployments run with the bundled login app disabled and a custom domain attached; see the specification, §12.3.

## Documents

- [Specification](doc/TINY_OIDC_SPEC.md): architecture, protocol surface, APIs, storage, cryptography, testing strategy, implementation plan, threat model.

## License

[MIT](LICENSE).
