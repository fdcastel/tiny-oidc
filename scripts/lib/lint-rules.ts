// Lint rules that encode requirements (TIO-TEST-060, TIO-TEST-005, TIO-GEN-004,
// TIO-TEST-033, TIO-DATA-015, TIO-CRYPTO-001, TIO-CRYPTO-002). Each rule is a
// small text check over repository files; scripts/lint-rules.ts runs them all.

export interface Violation {
  rule: string;
  path: string;
  line: number;
  message: string;
}

export interface Rule {
  id: string;
  /** Requirement identifiers the rule enforces. */
  spec: string[];
  appliesTo(path: string): boolean;
  check(path: string, source: string): Violation[];
}

const inSrc = (p: string) => p.startsWith("src/");
const inTest = (p: string) => p.startsWith("test/");
const isTs = (p: string) => p.endsWith(".ts") && !p.endsWith(".d.ts");

/** Replaces comments and string contents with spaces, preserving line numbers and offsets. */
export function stripCommentsAndStrings(source: string): string {
  let out = "";
  let i = 0;
  const n = source.length;
  while (i < n) {
    const ch = source[i] as string;
    const next = source[i + 1];
    if (ch === "/" && next === "/") {
      while (i < n && source[i] !== "\n") {
        out += " ";
        i++;
      }
    } else if (ch === "/" && next === "*") {
      out += "  ";
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) {
        out += source[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < n) {
        out += "  ";
        i += 2;
      }
    } else if (ch === '"' || ch === "'" || ch === "`") {
      out += ch;
      i++;
      while (i < n && source[i] !== ch) {
        if (source[i] === "\\") {
          out += "  ";
          i += 2;
          continue;
        }
        out += source[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < n) {
        out += ch;
        i++;
      }
    } else {
      out += ch;
      i++;
    }
  }
  return out;
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (source[i] === "\n") line++;
  return line;
}

/** Builds a rule from a regex applied to the comment- and string-stripped source. */
function patternRule(
  id: string,
  spec: string[],
  appliesTo: (path: string) => boolean,
  pattern: RegExp,
  message: string,
  options: { raw?: boolean } = {},
): Rule {
  return {
    id,
    spec,
    appliesTo,
    check(path, source) {
      const haystack = options.raw ? source : stripCommentsAndStrings(source);
      const violations: Violation[] = [];
      for (const match of haystack.matchAll(new RegExp(pattern.source, `${pattern.flags}g`))) {
        violations.push({ rule: id, path, line: lineOf(haystack, match.index), message });
      }
      return violations;
    },
  };
}

/** The only modules that turn an entity id into a Durable Object stub (TIO-ARCH-002). */
const DO_STUB_FILES = new Set(["src/users/create.ts", "src/oidc/interactions.ts"]);

/** Strings that only src/oidc/capabilities.ts may place in an array literal (TIO-DISC-004). */
const CAPABILITY_LITERALS = [
  "openid",
  "profile",
  "email",
  "groups",
  "offline_access",
  "account",
  "admin",
  "authorization_code",
  "refresh_token",
  "client_credentials",
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
  "ES256",
  "ES384",
  "EdDSA",
  "PS256",
  "RS256",
  "S256",
  "code",
  "query",
  "none",
  "login",
  "consent",
  "select_account",
];

/** Tokens that identify a capability list on their own, even as a one-element array. */
const UNAMBIGUOUS_LITERALS = new Set([
  "openid",
  "offline_access",
  "authorization_code",
  "refresh_token",
  "client_credentials",
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
  "ES256",
  "ES384",
  "EdDSA",
  "PS256",
  "RS256",
  "S256",
  "select_account",
]);

const CRYPTO_PACKAGE =
  /^(node:)?crypto$|crypto-js|@noble\/|tweetnacl|elliptic|bcrypt|argon2|scrypt|sha\.js|hash\.js|jsrsasign|node-forge|sjcl|aes-js|js-sha|md5|@peculiar\/webcrypto|@stablelib\//;
const CRYPTO_ALLOWLIST = new Set(["jose", "@simplewebauthn/server"]);

export const RULES: Rule[] = [
  patternRule(
    "no-math-random",
    ["TIO-CRYPTO-002", "TIO-TEST-060"],
    (p) => isTs(p) && !p.startsWith("tmp/"),
    /\bMath\.random\b/,
    "Math.random is forbidden; use crypto.getRandomValues or crypto.randomUUID",
  ),
  patternRule(
    "no-date-outside-clock",
    ["TIO-TEST-005", "TIO-TEST-060"],
    (p) => inSrc(p) && isTs(p) && p !== "src/env.ts",
    /\bDate\.now\s*\(|\bnew\s+Date\s*\(/,
    "Date.now() and new Date() are only allowed in src/env.ts; use the injected Clock",
  ),
  patternRule(
    "no-prepare-outside-db",
    ["TIO-DATA-015", "TIO-TEST-060"],
    (p) => inSrc(p) && isTs(p) && !p.startsWith("src/db/") && !p.startsWith("src/do/"),
    /\.prepare\s*\(/,
    "D1 statements are prepared only in src/db/ repositories",
  ),
  patternRule(
    "no-sql-concatenation",
    ["TIO-DATA-015", "TIO-TEST-060"],
    (p) => inSrc(p) && isTs(p),
    /`[^`]*\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b[^`]*\$\{/i,
    "SQL is never built by interpolation; bind parameters instead",
    { raw: true },
  ),
  patternRule(
    "no-console-outside-obs",
    ["TIO-TEST-060"],
    (p) => inSrc(p) && isTs(p) && !p.startsWith("src/obs/"),
    /\bconsole\.\w+\s*\(/,
    "console output is only allowed in src/obs/",
  ),
  patternRule(
    "no-html-response",
    ["TIO-GEN-001", "TIO-TEST-060"],
    (p) => inSrc(p) && isTs(p),
    /text\/html/,
    "the OP never produces HTML",
    { raw: true },
  ),
  patternRule(
    "no-nodejs-compat",
    ["TIO-CFG-001", "TIO-TEST-060"],
    (p) => p === "wrangler.jsonc" || (inSrc(p) && isTs(p)),
    /nodejs_compat/,
    "nodejs_compat is forbidden",
    { raw: true },
  ),
  {
    id: "crypto-allowlist",
    spec: ["TIO-CRYPTO-001", "TIO-TEST-060"],
    appliesTo: (p) => inSrc(p) && isTs(p),
    check(path, source) {
      const violations: Violation[] = [];
      const imports =
        /\b(?:import|export)\b[^;]*?\bfrom\s*["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']/g;
      for (const match of source.matchAll(imports)) {
        const specifier = (match[1] ?? match[2]) as string;
        if (CRYPTO_ALLOWLIST.has(specifier)) continue;
        if (CRYPTO_PACKAGE.test(specifier)) {
          violations.push({
            rule: "crypto-allowlist",
            path,
            line: lineOf(source, match.index),
            message: `crypto package "${specifier}" is not allow-listed (jose, @simplewebauthn/server, Web Crypto only)`,
          });
        }
      }
      return violations;
    },
  },
  {
    id: "capabilities-single-source",
    spec: ["TIO-DISC-004", "TIO-TEST-060"],
    appliesTo: (p) => inSrc(p) && isTs(p) && p !== "src/oidc/capabilities.ts",
    check(path, source) {
      const violations: Violation[] = [];
      const arrays = /\[\s*(?:"[^"\n]*"\s*,?\s*)+\]/g;
      for (const match of source.matchAll(arrays)) {
        const members = [...match[0].matchAll(/"([^"\n]*)"/g)].map((m) => m[1] as string);
        // A list of two or more members that are all capability tokens, or a
        // single unambiguous token, is a capability list living outside capabilities.ts.
        const allTokens = members.every((m) => CAPABILITY_LITERALS.includes(m));
        const hit =
          (members.length >= 2 && allTokens) ||
          (members.length === 1 && UNAMBIGUOUS_LITERALS.has(members[0] as string))
            ? members[0]
            : undefined;
        if (hit !== undefined) {
          violations.push({
            rule: "capabilities-single-source",
            path,
            line: lineOf(source, match.index),
            message: `array literal contains "${hit}"; scopes, grant types, response types, auth methods, algorithms and prompt values live only in src/oidc/capabilities.ts`,
          });
        }
      }
      return violations;
    },
  },
  {
    id: "no-op-internals-in-examples-and-e2e",
    spec: ["TIO-TEST-033", "TIO-TEST-060"],
    appliesTo: (p) => (p.startsWith("examples/") || p.startsWith("test/e2e/")) && isTs(p),
    check(path, source) {
      const violations: Violation[] = [];
      const imports =
        /\b(?:import|export)\b[^;]*?\bfrom\s*["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']/g;
      for (const match of source.matchAll(imports)) {
        const specifier = (match[1] ?? match[2]) as string;
        if (/(^|\/)src\//.test(specifier) || specifier.startsWith("cloudflare:")) {
          violations.push({
            rule: "no-op-internals-in-examples-and-e2e",
            path,
            line: lineOf(source, match.index),
            message: `"${specifier}": examples/ and test/e2e/ reach the OP over HTTP only`,
          });
        }
      }
      return violations;
    },
  },
  patternRule(
    "no-settimeout-in-tests",
    ["TIO-TEST-005", "TIO-TEST-060"],
    (p) => inTest(p) && isTs(p) && !p.startsWith("test/support/"),
    /\bsetTimeout\s*\(/,
    "tests never sleep; control time through the injected Clock",
  ),
  patternRule(
    "no-any",
    ["TIO-TEST-060"],
    (p) => inSrc(p) && isTs(p),
    /\bany\b/,
    "the any type is forbidden in src/",
  ),
  patternRule(
    "no-unvalidated-json",
    ["TIO-TEST-060"],
    (p) => inSrc(p) && isTs(p) && p !== "src/util/json.ts",
    /\bJSON\.parse\s*\(|\.json\s*\(\s*\)/,
    "parse JSON through src/util/json.ts with a zod schema",
  ),
  {
    // Durable Object namespaces are addressed only through the two stubs that take an
    // entity id (a user id, an interaction id); nothing shared by all users or clients.
    id: "do-addressed-by-entity-id",
    spec: ["TIO-ARCH-002", "TIO-TEST-060"],
    appliesTo: (p) => inSrc(p) && isTs(p) && !p.startsWith("src/generated/"),
    check(path, source) {
      const violations: Violation[] = [];
      const stripped = stripCommentsAndStrings(source);
      const addressing = /\.(?:idFromName|idFromString|newUniqueId|getByName)\s*\(/g;
      for (const match of stripped.matchAll(addressing)) {
        const line = lineOf(stripped, match.index);
        if (!DO_STUB_FILES.has(path)) {
          violations.push({
            rule: "do-addressed-by-entity-id",
            path,
            line,
            message: "address Durable Objects through userStub() or interactionStub() only",
          });
        } else if (/^\s*["'`]/.test(stripped.slice(match.index + match[0].length))) {
          violations.push({
            rule: "do-addressed-by-entity-id",
            path,
            line,
            message: "a Durable Object is never addressed by a constant name",
          });
        }
      }
      return violations;
    },
  },
  // The fake upstream is its own Worker with its own object storage (its
  // signing keys), not a fixture writing the OP's state.
  patternRule(
    "factories-through-public-apis",
    ["TIO-TEST-032", "TIO-TEST-060"],
    (p) => p.startsWith("test/support/") && !p.startsWith("test/support/fake-upstream/") && isTs(p),
    /\brunInDurableObject\b|\bstorage\s*\.\s*(?:put|delete|deleteAll|transaction|sql)\b|\.(?:prepare|exec|batch)\s*\(|\bINSERT\s+INTO\b|\bUPDATE\s+\w+\s+SET\b/,
    "test/support builds state through public APIs and Durable Object methods, never by writing storage",
  ),
  patternRule(
    "no-test-only-paths",
    ["TIO-GEN-004", "TIO-TEST-060"],
    (p) => inSrc(p) && isTs(p),
    /\bNODE_ENV\b|\bVITEST\b|(?<!TIO-)\bTEST\b/,
    "no test-only code paths in src/ (NODE_ENV, VITEST, TEST)",
  ),
];

export function runRules(files: Record<string, string>, rules: Rule[] = RULES): Violation[] {
  const violations: Violation[] = [];
  for (const [path, source] of Object.entries(files)) {
    for (const rule of rules) {
      if (rule.appliesTo(path)) violations.push(...rule.check(path, source));
    }
  }
  return violations.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
}

/** istanbul ignore accounting (TIO-TEST-003). */
export interface IgnoreOccurrence {
  path: string;
  line: number;
  text: string;
  valid: boolean;
}

const IGNORE_ANY = /istanbul\s+ignore[^*]*\*\//g;
const IGNORE_VALID = /^\/\*\s*istanbul ignore next -- reason: \S[^*]*\*\/$/;

export function findIstanbulIgnores(files: Record<string, string>): IgnoreOccurrence[] {
  const occurrences: IgnoreOccurrence[] = [];
  for (const [path, source] of Object.entries(files)) {
    for (const match of source.matchAll(IGNORE_ANY)) {
      const start = source.lastIndexOf("/*", match.index);
      const text = source.slice(start < 0 ? match.index : start, match.index + match[0].length);
      occurrences.push({
        path,
        line: lineOf(source, match.index),
        text,
        valid: IGNORE_VALID.test(text),
      });
    }
  }
  return occurrences;
}

export const MAX_ISTANBUL_IGNORES = 15;
