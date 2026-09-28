import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ARCHIVE_ONLY_TYPES,
  AUDIT_CATALOG,
  AUDIT_TYPES,
  isHotType,
} from "../../src/audit/catalog.ts";

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

  it("[TIO-AUDIT-013] the archive-only types are the ones TIO-AUDIT-013 lists, all catalogued; every other type is hot", () => {
    const spec = readFileSync("doc/TINY_OIDC_SPEC.md", "utf8");
    const start = spec.indexOf("**[TIO-AUDIT-013]**");
    const paragraph = spec.slice(start, spec.indexOf(String.fromCharCode(10), start));
    const listed = paragraph.slice(
      paragraph.indexOf("The archive-only types are"),
      paragraph.indexOf(": the steps"),
    );
    const fromSpec = [...listed.matchAll(/`([a-z]+\.[a-z_]+)`/g)].map((m) => m[1] as string);
    expect(fromSpec.sort()).toEqual([...ARCHIVE_ONLY_TYPES].sort());
    for (const type of ARCHIVE_ONLY_TYPES) expect(AUDIT_TYPES, type).toContain(type);
    expect(AUDIT_TYPES.filter((t) => isHotType(t))).toHaveLength(
      AUDIT_TYPES.length - ARCHIVE_ONLY_TYPES.size,
    );
    expect(isHotType("session.created")).toBe(true);
    expect(isHotType("token.refreshed")).toBe(false);
  });
});
