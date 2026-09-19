import { createRoute, OpenAPIHono, z } from "@hono/zod-openapi";

// OpenAPI route definitions of the JSON APIs (spec §5.1). Handlers live next
// to their features; this module has no Workers types so that
// scripts/gen-openapi.ts can build doc/openapi.json in Node.

export const API_INFO = {
  openapi: "3.1.0",
  info: {
    title: "Tiny OIDC JSON APIs",
    version: "1.0.0",
    description:
      "Interaction, Self-service and Admin APIs of Tiny OIDC. The OIDC protocol endpoints are described by the discovery document.",
  },
} as const;

export const OPENAPI_PATH = "/api/v1/openapi.json";

export const HealthSchema = z
  .object({
    status: z.enum(["ok", "degraded"]),
    version: z.string(),
    active_kid: z.string().nullable(),
    d1: z.enum(["ok", "error"]),
    time: z.int(),
    issuer_mismatch: z.string().optional(),
  })
  .openapi("Health");

export type Health = z.infer<typeof HealthSchema>;

export const healthRoute = createRoute({
  method: "get",
  path: "/api/v1/health",
  tags: ["system"],
  summary: "Liveness and configuration diagnostics",
  responses: {
    200: { description: "Healthy", content: { "application/json": { schema: HealthSchema } } },
    503: {
      description: "Degraded: D1 unavailable",
      content: { "application/json": { schema: HealthSchema } },
    },
  },
});

/** Every OpenAPI route, in document order. */
export const API_ROUTES = [healthRoute] as const;

/** The OpenAPI 3.1 document built from the definitions alone (no handlers, no bindings). */
export function openApiDocument(): Record<string, unknown> {
  const app = new OpenAPIHono();
  for (const route of API_ROUTES) app.openAPIRegistry.registerPath(route);
  return app.getOpenAPI31Document(API_INFO) as unknown as Record<string, unknown>;
}
