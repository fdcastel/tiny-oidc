# Architecture decision records

One file per decision taken **during the build** that the specification did
not settle, or that resolved a conflict inside it. Decisions taken while the
specification was written are in its Appendix B; the plan's Notes column
points here when a task produced one of these records.

Format: context (what forced the decision), decision, consequences, the
requirement ids it touches and the tests that prove it. A record is never
edited into a different decision: a reversal is a new record that supersedes
the old one.

| Id | Title | Status |
|---|---|---|
| [0001](0001-rate-limit-classes-share-two-bindings.md) | Rate-limit classes share the two declared bindings | Accepted |
| [0002](0002-interaction-writes-under-blockconcurrencywhile.md) | Every `InteractionDO` write runs under `blockConcurrencyWhile` | Accepted |
| [0003](0003-passkey-concurrency-row-versus-attempt-cap.md) | The passkey concurrency row is asserted on one winner and one counter move | Accepted |
| [0004](0004-group-changes-propagate-to-objects-first.md) | Group renames and deletions rewrite member objects first; `group.*` events | Accepted |
| [0005](0005-admin-rate-limit-keyed-by-whole-jti.md) | The admin rate limit is keyed by the whole `jti` | Accepted |
| [0006](0006-last-login-method-binds-the-user.md) | The last-login-method rule binds the user, not the administrator | Accepted |
| [0007](0007-logout-hints-and-loopback-post-logout-uris.md) | Logout hint decisions and loopback `post_logout_redirect_uri` ports | Accepted |
| [0008](0008-key-thumbprints-in-audit-data.md) | Key thumbprints travel as `kid:<thumbprint>` in audit data | Accepted |
| [0009](0009-in-flight-claims-are-not-stale-rows.md) | In-flight creation claims are not stale index rows; single-use steps claim in D1 | Accepted |
| [0010](0010-toolchain.md) | Toolchain: Node 24 native TypeScript, Vitest 4 with the Workers plugin, MSW for outbound traffic, Playwright against `wrangler dev` | Accepted |
| [0011](0011-threat-model-review-phase-7.md) | Threat-model review at the end of Phase 7 (TIO-SEC-001) | Proposed — awaiting the owner's sign-off |
| [0012](0012-no-per-address-limit-on-successful-token-traffic.md) | No per-address limit on successful `/token` traffic; the address class counts failed client authentication | Accepted |
| [0013](0013-per-client-pkce-requirement.md) | PKCE required by default, clearable per confidential client (the conformance suite sends none); `POST /authorize` | Accepted |
| [0014](0014-login-app-runs-under-the-suites-browser.md) | The reference login app runs under the conformance suite's browser (HtmlUnit: no async/await, fetch or spread) | Accepted |
| [0015](0015-warning-waivers-for-deliberate-behaviour.md) | A second waiver reason: suite warnings on behaviour the spec chooses deliberately (email in the ID token, no access-token revocation on code replay) | Accepted |
