# 0018 — Staged rollout through version overrides, on staging and production

Date: 2026-09-22 · Status: Accepted · Task: P7-06

## Context

TIO-DEPLOY-007 asked production deploys to upload a version, smoke-test it on
the version's **preview URL**, and only then send it traffic; staging deployed
with a plain `wrangler deploy`. A rehearsal of the production path against the
staging Worker on 2026-09-22 found that it could never have succeeded:

1. **No preview URL.** `wrangler versions upload` (4.135) printed a version id
   and no preview URL for this Worker. The script required one and would have
   aborted every production release with "could not find the preview URL".
   Its unit test passed because the fake wrangler's canned output contained a
   preview URL the real one never printed.
2. **The preview host answers 421.** Even with a preview URL, the OP refuses
   every request whose host is not the issuer's (TIO-HTTP-006), except health.
   Discovery and JWKS on a `*.workers.dev` preview host answer 421, so the
   smoke test would have failed on two of its three paths.
3. **Nothing had exercised it.** The requirement said the script runs for real
   in the nightly against staging, but staging used the other branch of the
   script. The production path had never run before the release it guards.

## Decision

Staging and production deploy the same way — a **staged rollout**:

1. Read the live version (`wrangler deployments status --json`) and require a
   commit sha, before anything on the account changes.
2. Apply D1 migrations, `wrangler versions upload`.
3. `wrangler versions deploy <new>@0% <live>@100%`: the new version is part of
   the deployment but receives no traffic.
4. Smoke-test on the **issuer's own hostname** with
   `Cloudflare-Workers-Version-Overrides: <worker>="<new>"`, which routes those
   requests, and only those, to the new version. Health must report the
   deploy's `VERSION`, which proves the override reached the new build rather
   than the live one; the smoke test waits up to 60 s for that before its
   checks, because the new deployment takes seconds to propagate.
5. Pass: `<new>@100%`. Fail: `<live>@100%` again, and the build fails.

A deployment already split without a version at 100% (a rollout someone else
started) is refused. One that this script left at `<new>@0% <live>@100%`
when interrupted is accepted: the live version is still at 100%.

`TIO_DIRECT_DEPLOY=true` deploys with a plain `wrangler deploy` for the two
cases the staged rollout cannot handle, set for that one build: the Worker's
**first deployment** (no live version exists) and a release that carries a
**Durable Object class migration** (Cloudflare refuses to upload those as
versions, because class migrations are atomic). It logs that no smoke test ran
before traffic moved.

## Evidence

Rehearsed against the staging Worker on 2026-09-22, live traffic untouched
throughout:

- A version uploaded beside the live one at 0%: the live hostname kept
  answering with the live build, the override header reached the new build on
  all three smoke paths (200, no 421), and restoring the live version at 100%
  worked.
- The rewritten `deploy()` run for real with a smoke test sabotaged to expect
  another build: the smoke test met the new version (its `VERSION` answered),
  failed, and the script restored the live version — 38 s, the live build
  never changed.
- The same run unsabotaged: six wrangler commands, 38 s, the new version
  smoke-tested at 0% and then serving 100%.

Then the same code in Workers Builds, on the push that introduced it:

- **First build (`83811b4`): refused, safely.** The new version joined the
  deployment at 0% and was out of it 4 s later: the smoke test, fired within
  a second of the 0% deployment, was answered by the live build, and the
  script restored the live version and failed the build. Staging kept
  serving. A new deployment takes seconds to reach every Cloudflare location,
  and until it reaches the one that answers, the override is ignored there;
  from the workstation it had arrived in time, from the build machine it had
  not.
- **Fix:** the smoke test first waits — up to 60 s, polling every 2 s — for
  health to report the new build through the override, then runs its checks;
  a build that never appears is reported with how long it was waited for.
- **Second build (`390979d`): rolled out.** 0% at 19:55:15.7 UTC, 100% at
  19:55:21.2, health reporting `390979d`.

`test/scripts/deploy.test.ts` uses the upload output wrangler actually
printed, and covers the restore, a failing restore, every refusal before
anything changes, and the settle wait (live build first, a failed poll, then
the new build).

## Consequences

- Every push to `main` runs the release path, so production's first release is
  its thousandth rehearsal rather than its first run. A staging build whose
  new version fails the smoke test leaves the previous version serving.
- A deploy costs four wrangler commands more than before; the rollout takes
  about 40 s from a workstation.
- Durable Object instances follow the deployment's percentages: at 0% every
  object stays on the live version, so the smoke test exercises the new
  version's stateless paths only (discovery, JWKS and health touch no object).
  That is what the smoke test is for; the gates behind promotion
  (TIO-DEPLOY-010) cover the rest.
- The first production deployment (P7-06) is a `TIO_DIRECT_DEPLOY=true` build,
  before the hostname is attached; every later one is staged. Runbook §13.

## Requirements

TIO-DEPLOY-007 amended; TIO-DEPLOY-006 and TIO-DEPLOY-010 unchanged.
