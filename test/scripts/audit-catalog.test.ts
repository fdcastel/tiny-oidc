import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AUDIT_CATALOG, AUDIT_TYPES } from "../../src/audit/catalog.ts";

// The catalog against the code and the tests (TIO-AUDIT-001): every type in
// the spec's table is in the catalog, every catalogued type has an emitter in
// src/ and a test that names it, and every emitter names a catalogued type.

function files(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry !== "generated") files(path, out);
    } else if (path.endsWith(".ts")) out.push(path);
  }
  return out;
}

const read = (paths: string[]) => paths.map((p) => readFileSync(p, "utf8")).join("\n");

/** The types of §11.2, read from the specification's table. */
function specTypes(): string[] {
  const spec = readFileSync("doc/TINY_OIDC_SPEC.md", "utf8");
  const start = spec.indexOf("### 11.2 Event catalog");
  const end = spec.indexOf("**[TIO-AUDIT-001]**", start);
  const table = spec.slice(start, end);
  return [...table.matchAll(/`([a-z]+\.[a-z_]+)`/g)].map((m) => m[1] as string);
}

describe("audit catalog", () => {
  const src = read(files("src"));
  const tests = read(files("test").filter((p) => !p.includes("test/scripts/audit-catalog")));

  it("[TIO-AUDIT-001] holds every type of §11.2 (plus the group events noted as a spec gap), each with an emitter in src/ and a test that names it", () => {
    const fromSpec = specTypes();
    expect(fromSpec.length).toBeGreaterThan(50);
    for (const type of fromSpec) expect(AUDIT_TYPES, type).toContain(type);
    const extra = AUDIT_TYPES.filter((t) => !fromSpec.includes(t));
    expect(extra.sort()).toEqual(["group.created", "group.deleted", "group.updated"]);
    for (const type of AUDIT_TYPES) {
      expect(src.includes(`"${type}"`), `${type} has an emitter`).toBe(true);
      expect(tests.includes(`"${type}"`), `${type} is asserted by a test`).toBe(true);
    }
  });

  it("[TIO-AUDIT-001] every type literal an emitter uses is in the catalog, and allow-lists carry no duplicates", () => {
    const emitted = new Set(
      [...src.matchAll(/type: "([a-z]+\.[a-z_]+)"/g)].map((m) => m[1] as string),
    );
    for (const type of emitted) expect(AUDIT_TYPES, type).toContain(type);
    for (const [type, keys] of Object.entries(AUDIT_CATALOG)) {
      expect(new Set(keys).size, type).toBe(keys.length);
    }
  });
});
