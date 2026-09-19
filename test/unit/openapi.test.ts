import { describe, expect, it } from "vitest";
import snapshot from "../../doc/openapi.json" with { type: "json" };
import { API_ROUTES, openApiDocument } from "../../src/api/definitions.ts";

describe("OpenAPI definitions", () => {
  it("build the committed doc/openapi.json and cover every JSON API route (§5.1 drift check)", () => {
    const document = openApiDocument();
    expect(document).toEqual(snapshot);
    const paths = Object.keys(document["paths"] as Record<string, unknown>);
    expect(paths).toEqual([...new Set(API_ROUTES.map((r) => r.path))]);
  });
});
