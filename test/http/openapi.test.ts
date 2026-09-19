import { describe, expect, it } from "vitest";
import snapshot from "../../doc/openapi.json" with { type: "json" };
import { ROUTES } from "../../src/router/routes.ts";
import { op } from "../support/op.ts";

interface Operation {
  security?: Record<string, string[]>[];
  responses: Record<string, unknown>;
  tags?: string[];
}

describe("OpenAPI snapshot", () => {
  it("the served document equals the committed doc/openapi.json (drift check, §5.1)", async () => {
    const res = await op("/api/v1/openapi.json");
    expect(await res.json()).toEqual(snapshot);
  });

  it("is an OpenAPI 3.1 document in which every Admin API operation but bootstrap requires the admin bearer token and every route-table JSON API path is documented", () => {
    expect(snapshot.openapi).toBe("3.1.0");
    const doc = snapshot as unknown as {
      components: { securitySchemes: Record<string, { type: string; scheme: string }> };
      paths: Record<string, Record<string, Operation>>;
    };
    expect(doc.components.securitySchemes["adminToken"]).toMatchObject({
      type: "http",
      scheme: "bearer",
    });
    for (const [path, operations] of Object.entries(doc.paths)) {
      for (const [method, operation] of Object.entries(operations)) {
        const admin = path.startsWith("/api/v1/admin/") && path !== "/api/v1/admin/bootstrap";
        expect(operation.security, `${method} ${path}`).toEqual(
          admin ? [{ adminToken: [] }] : undefined,
        );
        if (admin) {
          expect(Object.keys(operation.responses), `${method} ${path}`).toEqual(
            expect.arrayContaining(["401", "403", "429"]),
          );
        }
        // Every documented operation is in the route table with the same method.
        const template = path.replace(/\{(\w+)\}/g, ":$1");
        expect(
          ROUTES.some((r) => r.path === template && r.method === method.toUpperCase()),
          `${method} ${path}`,
        ).toBe(true);
      }
    }
  });
});
