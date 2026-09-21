# Conformance (spec §13.9)

The OpenID Foundation conformance suite against **staging**, nightly and
before every release (TIO-TEST-040), with its browser automation signing in
through the reference login app and the staging-only fake upstream
(TIO-TEST-041). Nothing here runs on this machine: the nightly job
(`.github/workflows/nightly.yml`, job `conformance`) does, and the exported
results are its artifact.

| Piece | What it is |
|---|---|
| `docker-compose.yml` | The suite from its prebuilt images (`registry.gitlab.com/openid/conformance-suite` and `…/nginx`, plus MongoDB), dev profile (no API token), `BASE_URL` = the public URL the OP will see |
| `plans/*.json` | Templates of the plan configurations, host-neutral: `{ISSUER}`, `{LOGIN_URL}`, `{SUITE}`, the clients; `browser.json` is the automation block every plan gets |
| `waivers.json` | Conditions allowed to fail or warn and modules allowed to skip, each with the one permitted reason and the discovery field that advertises the absence; turned into the suite's expected-failures and expected-skips files |
| `lib.ts` | The pure parts (plans and variants, rendering, waivers, the runner's arguments); tested by `test/scripts/conformance.test.ts` |
| `run.ts` | The run: registers the suite's relying parties on staging with the run's public URL (secrets rotated, never stored), renders the plans, drives the suite's own `scripts/run-test-plan.py` |

## The four plans

`oidcc-config-certification-test-plan`; `oidcc-basic-certification-test-plan`
(the plan itself runs `client_secret_basic` throughout and one
`client_secret_post` module, read from the `client_secret_post` block of
the configuration); `oidcc-rp-initiated-logout-certification-test-plan`;
`oidcc-backchannel-rp-initiated-logout-certification-test-plan`. Each plan
is invoked with only the variants it leaves selectable, as the suite's own CI
does (`.gitlab-ci/run-tests.sh`): none for the config plan,
`[server_metadata=discovery][client_registration=static_client]` for the
basic plan, `[response_type=code][client_registration=static_client]` for the
logout plans. A variant the plan fixes itself is refused on the command line.

The suite offers no plan that sends PKCE with a public client, so the `none`
variant is covered by the `oauth4webapi` interop suite instead. Its modules
send no `code_challenge` at all (only `oidcc-ensure-request-with-valid-pkce-succeeds`
does), which is why the three relying parties are confidential clients
registered with `require_pkce: false` (spec TIO-AUTHZ-008, ADR 0013).

## The relying parties

`conformance-basic` (`client`), `conformance-basic2` (`client2`) and
`conformance-post` (`client_secret_post`), created on the first run and
re-pointed at the run's tunnel URL afterwards, their secrets rotated on every
run and never stored.

## How the browser automation works

The suite opens the OP's `/authorize` in its own browser. The OP sends it to
the login app; the automation waits for the app's heading, clicks
`#upstream-<alias>` (the fake upstream auto-approves and redirects back), and
waits until the browser is back at the suite's callback or at the login app's
error page. For `/logout` it clicks `#logout-confirm` when the OP asks for a
confirmation. Every control of the reference app carries a stable id for this
(`examples/login-app/app.js`). There is no test-only code path in the OP.

## Why the suite needs a public URL

The back-channel logout plan has the OP call the suite's
`backchannel_logout_uri`, so the suite running on the CI runner must be
reachable from Cloudflare: the job opens a `cloudflared` quick tunnel to the
suite's nginx and passes that URL as `BASE_URL` and as the relying parties'
redirect, post-logout and back-channel URIs. The runner talks to the suite
over `https://localhost:8443` with certificate verification off (the suite's
certificate is self-signed).

## Running by hand

```sh
export TIO_STAGING_ISSUER=https://auth.staging.example.com
export TIO_STAGING_LOGIN_URL=https://login.staging.example.com/
export TIO_STAGING_CLIENT_ID=… TIO_STAGING_CLIENT_SECRET=…    # a client_credentials client with the admin scope
git clone --depth 1 --filter=blob:none --sparse https://gitlab.com/openid/conformance-suite conformance/suite
git -C conformance/suite sparse-checkout set scripts
python3 -m pip install httpx pyparsing
cloudflared tunnel --url https://localhost:8443 --no-tls-verify   # note the https://….trycloudflare.com URL
BASE_URL=https://….trycloudflare.com docker compose -f conformance/docker-compose.yml up -d
node conformance/run.ts --suite-scripts conformance/suite/scripts --public-url https://….trycloudflare.com
```

`--dry-run` registers the clients and renders the configurations without
running the suite. Results land in `conformance/results/` (ignored by git):
the rendered configurations, the expected-failures and expected-skips files, the suite's
exported zips (a plan is exported only when it completes) and, under `logs/`,
the event log of every module the suite ran whatever its outcome, with a
`.browser.txt` next to it holding the browser automation's own trace: every
request the suite's browser made and every script error, since the plans set
`browser_verbose`. That trace is the only evidence when a login-dependent
module is `INTERRUPTED` (the automation timed out) rather than failed.

## Waivers

A waiver names a test (shell wildcards), a variant (`"*"` or the variant
object), the configuration file and the expected result, plus `reason` —
which must be the sentence `feature intentionally unsupported and advertised
as such in discovery` — and `advertised_by`, the discovery field that says
so. With `"expected-result": "failure"` or `"warning"` it also names the
failing condition class and the block, exactly as the suite's
expected-failures format; with `"skip"` it names neither and becomes an
entry of the suite's expected-skips file (the suite skips a module itself
when discovery says the feature is absent, and an unexpected skip fails the
plan like a failure). Anything else is rejected before the run starts, and
the suite fails a run whose waivers went unused.
