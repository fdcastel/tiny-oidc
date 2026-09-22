import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  REVIEW_NOTICE,
  SURFACE_PATH,
  type Surface,
  surfaceDiff,
  surfaceOf,
} from "../../scripts/lib/threat-surface.ts";
import { HANDLE_TYPES } from "../../src/crypto/handle-types.ts";
import { ROUTES } from "../../src/router/routes.ts";

// The drift test TIO-SEC-001 deserves: not the review record against the
// generated evidence — that moves whenever a test changes a citation — but the
// surface the review was made against. Routes, handle kinds and the
// requirements of each §15 row change rarely, and each change is exactly the
// trigger the requirement names.

const reviewed = (): Surface => JSON.parse(readFileSync(SURFACE_PATH, "utf8")) as Surface;
const current = (): Surface =>
  surfaceOf({
    routes: ROUTES,
    handles: HANDLE_TYPES,
    spec: readFileSync("doc/TINY_OIDC_SPEC.md", "utf8"),
  });

describe("the surface behind the threat model", () => {
  it("[TIO-SEC-001] the routes, handle kinds and threat-row requirements are the ones §15 was reviewed against", () => {
    const changes = surfaceDiff(reviewed(), current());
    expect(changes, [...changes, "", REVIEW_NOTICE].join("\n")).toEqual([]);
  });

  it("covers the whole protocol surface, not only the documented API", () => {
    const surface = current();
    expect(surface.routes).toContain("GET /authorize");
    expect(surface.routes).toContain("POST /authorize");
    expect(surface.routes).toContain("POST /token");
    expect(surface.handles).toContain("session tio_ss 0x01");
    expect(Object.keys(surface.threats).length).toBeGreaterThan(10);
  });
});

describe("surfaceOf", () => {
  const spec = [
    "## 15. Threat model",
    "",
    "| Id | Threat | Mitigation | Requirements |",
    "|---|---|---|---|",
    "| T1 | Stolen code | PKCE | AUTHZ-008, TOKEN-010–TOKEN-011 |",
    "| T2 | Replay | Nonce | SESS-002 |",
  ].join("\n");

  it("sorts and deduplicates the routes and names every handle kind with its prefix and type byte", () => {
    const surface = surfaceOf({
      routes: [
        { method: "POST", path: "/token" },
        { method: "GET", path: "/authorize" },
        { method: "GET", path: "/authorize" },
      ],
      handles: { code: { prefix: "tio_ac", type: 0x02 } },
      spec,
    });
    expect(surface.routes).toEqual(["GET /authorize", "POST /token"]);
    expect(surface.handles).toEqual(["code tio_ac 0x02"]);
  });

  it("expands the requirement ranges of every §15 row", () => {
    const surface = surfaceOf({ routes: [], handles: {}, spec });
    expect(surface.threats).toEqual({
      T1: ["TIO-AUTHZ-008", "TIO-TOKEN-010", "TIO-TOKEN-011"],
      T2: ["TIO-SESS-002"],
    });
  });
});

describe("surfaceDiff", () => {
  const base: Surface = {
    routes: ["GET /authorize"],
    handles: ["session tio_ss 0x01"],
    threats: { T1: ["TIO-AUTHZ-008"] },
  };

  it("is empty for an unchanged surface", () => {
    expect(surfaceDiff(base, structuredClone(base))).toEqual([]);
  });

  it("names an added route, a removed handle kind and a row whose evidence moved", () => {
    expect(
      surfaceDiff(base, {
        routes: ["GET /authorize", "POST /authorize"],
        handles: [],
        threats: { T1: ["TIO-CLIENT-002"] },
      }),
    ).toEqual([
      "route added: POST /authorize",
      "handle removed: session tio_ss 0x01",
      "threat T1 added: TIO-CLIENT-002",
      "threat T1 removed: TIO-AUTHZ-008",
    ]);
  });

  it("names a row that appeared or disappeared", () => {
    const withT2: Surface = { ...base, threats: { ...base.threats, T2: ["TIO-SESS-002"] } };
    expect(surfaceDiff(base, withT2)).toEqual(["threat T2 added"]);
    expect(surfaceDiff(withT2, base)).toEqual(["threat T2 removed"]);
  });
});
