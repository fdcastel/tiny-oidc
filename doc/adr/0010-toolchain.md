# 0010 — Toolchain: Node 24 native TypeScript, Vitest 4 with the Workers plugin, MSW for outbound traffic, Playwright against `wrangler dev`

Date: 2026-09-19 · Status: Accepted · Tasks: P0-01, P0-02, P2-15, P4-07

## Context

§13.1 names the runners (Vitest in workerd, Playwright) but not the versions or
the mechanisms for outbound mocking and script execution, and the tools moved
while Phase 0 was under way: `@cloudflare/vitest-plugin` 1.1 requires Vitest
`^4.1`, no longer ships `fetchMock`, and deprecates `SELF` and `env` from
`cloudflare:test`.

## Decision

- **Scripts run on Node 24 without a build**: every import carries its `.ts`
  extension and `erasableSyntaxOnly` is on (no parameter properties, no
  enums), so `node scripts/x.ts` and the Worker share one syntax. Generators
  that run in Node import only Workers-type-free modules.
- **Workers tests** use Vitest 4.1 with `@cloudflare/vitest-plugin` 1.1,
  storage isolation per test file, and `test/support/op.ts` on
  `cloudflare:workers` instead of the deprecated `SELF`/`env`.
- **Outbound traffic** in tests goes through `@msw/cloudflare` + `msw` with
  `onUnhandledFrame: "error"`; `test/support/fetch-allowlist.ts` records every
  request, which is how TIO-ARCH-016 is asserted.
- **End to end** runs Playwright against `wrangler dev` on `localhost:8787`
  (WebAuthn RP IDs cannot be IP literals) with the bundled login app, on
  Chromium in CI and Chromium plus Firefox locally.
- **Bundles** are minified (`minify: true`); unminified `zod` alone is 787 KB
  against the 1.5 MB budget.
- **Deployment** is Cloudflare Workers Builds from `main` (staging) and
  `production`; GitHub Actions runs gates only and holds no Cloudflare token
  (TIO-DEPLOY-006).

## Consequences

- One TypeScript dialect everywhere; no transpile step to drift.
- Test-time outbound mocking is explicit per suite; an unmocked request fails
  the test rather than reaching the network.
- Version pins are exact in `package.json`; upgrades are deliberate.

## Requirements and evidence

TIO-TEST-001..003, TIO-ARCH-016, TIO-PERF-002, TIO-DEPLOY-006 —
`vitest.config.ts`, `test/http/outbound.test.ts`, `scripts/bundle-check.ts`,
`.github/workflows/pr.yml`.
