# 0014 — The reference login app runs under the conformance suite's browser

Date: 2026-09-21 · Status: Accepted · Task: P7-03

## Context

TIO-TEST-041 has the OpenID Foundation conformance suite complete login
through the reference login app by clicking its `upstream-<alias>` control.
The suite drives pages with HtmlUnit (its `BrowserControl` builds a Selenium
`HtmlUnitDriver`; the version comes from the Spring Boot 4.0.7 BOM the suite
inherits: HtmlUnit 4.17.0). HtmlUnit's JavaScript engine is a Rhino fork,
and three things the app relied on do not exist there:

- `async`/`await`: no Rhino release parses it (the Rhino compatibility table
  reports "missing ; before statement" on every version up to 1.9.0, and the
  HtmlUnit change log never mentions it). A parse error stops the whole
  script, so the app rendered nothing and the automation's first step,
  waiting for `#app h1`, timed out.
- `fetch`: HtmlUnit only offers an opt-in polyfill
  (`setFetchPolyfillEnabled`, 2.59.0) and the suite does not enable it.
- Spread in arrays and argument lists: added in HtmlUnit 4.19.0, after the
  suite's version. Rest parameters and object spread are recent additions
  too (Rhino 1.7.15, HtmlUnit 4.16.0).

The suite's own comment on the driver ("HtmlUnit's javascript engine barfs
at a lot of modern javascript") and `setThrowExceptionOnScriptError(false)`
mean a failure is silent: script errors go to the test's event log only.

Alternatives considered: a build step transpiling the app for the suite
(against TIO-IX-080, "no build step", and a generated artifact to keep in
sync); a navigational `GET` variant of the upstream-start endpoint so the
suite needs no script (a spec change to the Interaction API for one test
browser); a separate minimal page for the suite (TIO-TEST-041 says *the
reference login app*).

## Decision

The reference app is written for the engine the suite ships: Promise chains
instead of `async`/`await`, `XMLHttpRequest` where `fetch` is missing (the
`fetch` path stays for real browsers, behind `typeof fetch === "function"`),
arrays instead of variadic arguments, `Object.assign` instead of object
spread, `Array.from` instead of array spread, a bound `catch (_error)`, and
no trailing comma in argument lists (`biome.json` formats the app with
`trailingCommas: "es5"`). Optional chaining, nullish coalescing, template
literals, arrow functions, destructuring declarations, default parameters
and `for…of` are kept: HtmlUnit 4.5.0 and earlier releases added them.

`test/scripts/login-app.test.ts` parses the app with the TypeScript compiler
and fails on any of the forbidden constructs, so the constraint survives the
next edit. The e2e suite runs the app in Chromium and Firefox with `fetch`
deleted (`test/e2e/passkey.spec.ts`), which proves the XMLHttpRequest path in
a real browser; the nightly conformance run is the proof under HtmlUnit
itself, which nothing on a workstation without Java or Docker can replace.

## Consequences

- The app is a little longer and reads as Promise chains. The behaviour is
  unchanged: the same screens, control ids, messages and error handling
  (`busy()` still disables every button while an action runs and re-enables
  them with the message on a rejection or a synchronous throw).
- A stray `null` text node that `render(...children)` used to pass to
  `replaceChildren` (a screen without a hint rendered the word "null") is gone
  with the rewrite; the e2e suite asserts it.
- TIO-IX-080 names the constraint and its test.

## Requirements and tests

TIO-TEST-041, TIO-IX-080 — `test/scripts/login-app.test.ts`,
`test/e2e/passkey.spec.ts` (the no-fetch and no-WebAuthn cases), the nightly
`conformance` job.
