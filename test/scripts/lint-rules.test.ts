import { describe, expect, it } from "vitest";
import {
  findIstanbulIgnores,
  MAX_ISTANBUL_IGNORES,
  RULES,
  runRules,
  stripCommentsAndStrings,
} from "../../scripts/lib/lint-rules.ts";

const rulesHit = (files: Record<string, string>) =>
  runRules(files).map((v) => `${v.path}:${v.line}:${v.rule}`);

describe("stripCommentsAndStrings", () => {
  it("blanks comments and string contents while preserving line numbers", () => {
    const src = 'a // c1\n/* b\nb */ "s\\"x" `t\nt` \'u\' z';
    const out = stripCommentsAndStrings(src);
    expect(out.split("\n")).toHaveLength(src.split("\n").length);
    expect(out).not.toContain("c1");
    expect(out).not.toContain("b */");
    expect(out).toContain('"');
    expect(out).toContain(" z");
    expect(stripCommentsAndStrings("/* open")).toBe("       ");
    expect(stripCommentsAndStrings('"open')).toBe('"    ');
  });
});

describe("lint rules (TIO-TEST-060)", () => {
  it("every rule names the requirements it enforces", () => {
    for (const rule of RULES) expect(rule.spec.length, rule.id).toBeGreaterThan(0);
  });

  it("[TIO-CRYPTO-002] forbids Math.random in code but not in comments", () => {
    expect(rulesHit({ "src/a.ts": "const x = Math.random();" })).toEqual([
      "src/a.ts:1:no-math-random",
    ]);
    expect(rulesHit({ "src/a.ts": "// Math.random is banned\nconst x = 1;" })).toEqual([]);
    expect(rulesHit({ "test/a.ts": "Math.random()" })).toEqual(["test/a.ts:1:no-math-random"]);
  });

  it("[TIO-TEST-005] forbids Date.now() and new Date() in src/ except src/env.ts", () => {
    expect(rulesHit({ "src/a.ts": "const t = Date.now();\nconst d = new Date();" })).toEqual([
      "src/a.ts:1:no-date-outside-clock",
      "src/a.ts:2:no-date-outside-clock",
    ]);
    expect(rulesHit({ "src/env.ts": "const t = Date.now();" })).toEqual([]);
    expect(rulesHit({ "src/a.ts": "const s = 'Date.now()';" })).toEqual([]);
  });

  it("[TIO-DATA-015] forbids prepare( outside src/db/ and src/do/ and SQL interpolation anywhere in src/", () => {
    expect(rulesHit({ "src/router/x.ts": "db.prepare('SELECT 1')" })).toEqual([
      "src/router/x.ts:1:no-prepare-outside-db",
    ]);
    expect(rulesHit({ "src/db/x.ts": "db.prepare('SELECT 1')" })).toEqual([]);
    expect(rulesHit({ "src/do/x.ts": "db.prepare('SELECT 1')" })).toEqual([]);
    expect(rulesHit({ "src/db/x.ts": "db.prepare(`SELECT * FROM t WHERE id = ${id}`)" })).toEqual([
      "src/db/x.ts:1:no-sql-concatenation",
    ]);
    expect(
      rulesHit({ "src/db/x.ts": "db.prepare(`SELECT * FROM t WHERE id = ?`).bind(id)" }),
    ).toEqual([]);
  });

  it("forbids console output outside src/obs/", () => {
    expect(rulesHit({ "src/a.ts": "console.log('x')" })).toEqual([
      "src/a.ts:1:no-console-outside-obs",
    ]);
    expect(rulesHit({ "src/obs/log.ts": "console.log('x')" })).toEqual([]);
  });

  it("[TIO-GEN-001] forbids text/html responses in src/", () => {
    expect(
      rulesHit({ "src/a.ts": "new Response('x', { headers: { 'content-type': 'text/html' } })" }),
    ).toEqual(["src/a.ts:1:no-html-response"]);
  });

  it("[TIO-CFG-001] forbids nodejs_compat in wrangler.jsonc and src/", () => {
    expect(rulesHit({ "wrangler.jsonc": '{ "compatibility_flags": ["nodejs_compat"] }' })).toEqual([
      "wrangler.jsonc:1:no-nodejs-compat",
    ]);
    expect(rulesHit({ "wrangler.jsonc": '{ "compatibility_flags": [] }' })).toEqual([]);
  });

  it("[TIO-CRYPTO-001] allows only jose, @simplewebauthn/server and Web Crypto", () => {
    expect(
      rulesHit({
        "src/a.ts": [
          'import { createHash } from "node:crypto";',
          'import nacl from "tweetnacl";',
          'import * as jose from "jose";',
          'import { verifyRegistrationResponse } from "@simplewebauthn/server";',
          'const m = await import("crypto-js");',
        ].join("\n"),
      }),
    ).toEqual([
      "src/a.ts:1:crypto-allowlist",
      "src/a.ts:2:crypto-allowlist",
      "src/a.ts:5:crypto-allowlist",
    ]);
  });

  it("[TIO-DISC-004] forbids capability literal arrays outside src/oidc/capabilities.ts", () => {
    expect(
      rulesHit({ "src/oidc/token.ts": 'const g = ["authorization_code", "refresh_token"];' }),
    ).toEqual(["src/oidc/token.ts:1:capabilities-single-source"]);
    expect(rulesHit({ "src/oidc/token.ts": 'const r = [\n  "code",\n  "query",\n];' })).toEqual([
      "src/oidc/token.ts:1:capabilities-single-source",
    ]);
    expect(
      rulesHit({ "src/oidc/capabilities.ts": 'export const SCOPES = ["openid", "email"];' }),
    ).toEqual([]);
    expect(rulesHit({ "src/oidc/token.ts": 'const names = ["admins", "users"];' })).toEqual([]);
    // Mixed lists and lone ambiguous words are not capability lists.
    expect(rulesHit({ "src/x.ts": 'const ops = ["consent", "abort", "fail"];' })).toEqual([]);
    expect(rulesHit({ "src/x.ts": 'const one = ["login"];' })).toEqual([]);
    expect(rulesHit({ "src/x.ts": 'const p = ["login", "consent"];' })).toEqual([
      "src/x.ts:1:capabilities-single-source",
    ]);
    expect(rulesHit({ "src/x.ts": 'const a = ["S256"];' })).toEqual([
      "src/x.ts:1:capabilities-single-source",
    ]);
  });

  it("[TIO-TEST-033] forbids src/ and cloudflare:test imports from examples/ and test/e2e/", () => {
    expect(
      rulesHit({
        "test/e2e/login.spec.ts":
          'import { env } from "cloudflare:test";\nimport { x } from "../../src/env.ts";',
        "examples/rp-node/index.ts": 'import { app } from "../../src/index.ts";',
        "test/http/a.test.ts": 'import { env } from "cloudflare:test";',
      }),
    ).toEqual([
      "examples/rp-node/index.ts:1:no-op-internals-in-examples-and-e2e",
      "test/e2e/login.spec.ts:1:no-op-internals-in-examples-and-e2e",
      "test/e2e/login.spec.ts:2:no-op-internals-in-examples-and-e2e",
    ]);
  });

  it("[TIO-TEST-005] forbids setTimeout in tests outside test/support/", () => {
    expect(
      rulesHit({ "test/http/a.test.ts": "await new Promise((r) => setTimeout(r, 10));" }),
    ).toEqual(["test/http/a.test.ts:1:no-settimeout-in-tests"]);
    expect(rulesHit({ "test/support/wait.ts": "setTimeout(r, 10)" })).toEqual([]);
  });

  it("forbids the any type in src/", () => {
    expect(rulesHit({ "src/a.ts": "let x: any = 1; const y = z as any;" })).toEqual([
      "src/a.ts:1:no-any",
      "src/a.ts:1:no-any",
    ]);
    expect(rulesHit({ "src/a.ts": 'const many = "any"; // any' })).toEqual([]);
  });

  it("forbids JSON.parse and .json() outside src/util/json.ts", () => {
    expect(
      rulesHit({ "src/oidc/a.ts": "const b = JSON.parse(text); const c = await req.json();" }),
    ).toEqual(["src/oidc/a.ts:1:no-unvalidated-json", "src/oidc/a.ts:1:no-unvalidated-json"]);
    expect(rulesHit({ "src/util/json.ts": "JSON.parse(text)" })).toEqual([]);
    expect(rulesHit({ "src/oidc/a.ts": "return c.json({ ok: true });" })).toEqual([]);
  });

  it("[TIO-GEN-004] forbids NODE_ENV, VITEST and TEST references in src/", () => {
    expect(
      rulesHit({ "src/a.ts": "if (env.NODE_ENV) {}\nif (process.env.VITEST) {}\nconst TEST = 1;" }),
    ).toEqual([
      "src/a.ts:1:no-test-only-paths",
      "src/a.ts:2:no-test-only-paths",
      "src/a.ts:3:no-test-only-paths",
    ]);
    expect(rulesHit({ "src/a.ts": "// TIO-TEST-060 is the rule\nconst TIO_TEST = 1;" })).toEqual(
      [],
    );
  });
});

describe("istanbul ignores (TIO-TEST-003)", () => {
  it("accepts only the documented form and counts every occurrence", () => {
    const found = findIstanbulIgnores({
      "src/a.ts": [
        "/* istanbul ignore next -- reason: exhaustive switch default */",
        "/* istanbul ignore next */",
        "/* istanbul ignore if -- reason: x */",
        "/* istanbul ignore next -- reason:  */",
      ].join("\n"),
    });
    expect(found.map((f) => [f.line, f.valid])).toEqual([
      [1, true],
      [2, false],
      [3, false],
      [4, false],
    ]);
    expect(MAX_ISTANBUL_IGNORES).toBe(15);
  });
});
