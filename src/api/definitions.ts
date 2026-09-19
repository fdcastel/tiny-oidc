import { createRoute, OpenAPIHono, z } from "@hono/zod-openapi";
import { CAPABILITIES } from "../oidc/capabilities.ts";

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

// --- Interaction API (§7) ---------------------------------------------------

export const ErrorSchema = z
  .object({
    error: z.string(),
    error_description: z.string(),
    request_id: z.string(),
  })
  .openapi("Error");

const errorResponse = (description: string) => ({
  description,
  content: { "application/json": { schema: ErrorSchema } },
});

const INTERACTION_ERRORS = {
  403: errorResponse("origin_not_allowed, interaction_binding_failed or too_many_attempts"),
  404: errorResponse("interaction_not_found"),
  409: errorResponse("interaction_invalid_state"),
  503: errorResponse("temporarily_unavailable"),
};

export const InteractionIdParams = z.object({
  id: z.string().length(43).openapi({ description: "Interaction id (43 base64url characters)" }),
});

export const ClientSummarySchema = z
  .object({
    client_id: z.string(),
    client_name: z.string(),
    client_uri: z.string().nullable(),
    logo_uri: z.string().nullable(),
  })
  .openapi("ClientSummary");

export const InteractionDocumentSchema = z
  .object({
    id: z.string(),
    kind: z.enum(["authorize", "logout"]),
    status: z.enum([
      "login_required",
      "link_required",
      "consent_required",
      "ready",
      "completed",
      "failed",
    ]),
    expires_at: z.int(),
    client: ClientSummarySchema.nullable(),
    request: z
      .object({
        scopes: z.array(z.string()),
        prompt: z.array(z.enum(CAPABILITIES.prompt_values_supported)),
        max_age: z.int().nullable(),
        login_hint: z.string().nullable(),
        ui_locales: z.string().nullable(),
        acr_values: z.array(z.string()),
      })
      .nullable(),
    methods: z.object({
      passkey: z.boolean(),
      registration: z.enum(["closed", "invite", "open"]),
      upstreams: z.array(z.object({ alias: z.string(), display_name: z.string() })),
    }),
    session_user: z
      .object({ display_name: z.string().nullable(), email_masked: z.string().nullable() })
      .nullable(),
    consent: z
      .object({
        scopes: z.array(
          z.object({ name: z.string(), description: z.string(), granted: z.boolean() }),
        ),
      })
      .nullable(),
    link: z
      .object({
        upstream: z.string(),
        email_masked: z.string(),
        display_name_hint: z.string().nullable(),
      })
      .nullable(),
    logout: z
      .object({
        client: ClientSummarySchema.nullable(),
        post_logout_redirect_uri_registered: z.boolean(),
      })
      .nullable(),
    error: z.object({ error: z.string(), error_description: z.string() }).nullable(),
    attempts_remaining: z.int(),
  })
  .openapi("InteractionDocument");

export type InteractionDocumentBody = z.infer<typeof InteractionDocumentSchema>;

export const InteractionStepSchema = z
  .object({
    status: z.enum(["ready", "consent_required", "failed"]),
    redirect_to: z.string().nullable(),
  })
  .openapi("InteractionStep");

export type InteractionStep = z.infer<typeof InteractionStepSchema>;

export const ConsentDecisionSchema = z
  .discriminatedUnion("decision", [
    z.object({ decision: z.literal("grant"), scopes: z.array(z.string()).max(16) }),
    z.object({ decision: z.literal("deny") }),
  ])
  .openapi("ConsentDecision");

const jsonBody = (schema: z.ZodType) => ({
  content: { "application/json": { schema } },
  required: true,
});

export const interactionGetRoute = createRoute({
  method: "get",
  path: "/api/v1/interactions/{id}",
  tags: ["interactions"],
  summary: "The interaction document for the login app (§7.3)",
  request: { params: InteractionIdParams },
  responses: {
    200: {
      description: "The document",
      content: { "application/json": { schema: InteractionDocumentSchema } },
    },
    ...INTERACTION_ERRORS,
  },
});

export const interactionConsentRoute = createRoute({
  method: "post",
  path: "/api/v1/interactions/{id}/consent",
  tags: ["interactions"],
  summary: "Grant or deny consent (§7.5)",
  request: { params: InteractionIdParams, body: jsonBody(ConsentDecisionSchema) },
  responses: {
    200: {
      description: "ready or failed",
      content: { "application/json": { schema: InteractionStepSchema } },
    },
    400: errorResponse("invalid_request"),
    ...INTERACTION_ERRORS,
  },
});

export const interactionAbortRoute = createRoute({
  method: "post",
  path: "/api/v1/interactions/{id}/abort",
  tags: ["interactions"],
  summary: "Abort the interaction with access_denied (§7.5)",
  request: { params: InteractionIdParams },
  responses: {
    200: {
      description: "failed",
      content: { "application/json": { schema: InteractionStepSchema } },
    },
    ...INTERACTION_ERRORS,
  },
});

export const PasskeyOptionsResponseSchema = z
  .object({
    publicKey: z.looseObject({}).openapi({
      description: "PublicKeyCredentialRequestOptionsJSON for navigator.credentials.get()",
    }),
  })
  .openapi("PasskeyOptions");

export const PasskeyVerifyBodySchema = z
  .object({
    response: z
      .looseObject({})
      .openapi({ description: "AuthenticationResponseJSON from the browser" }),
  })
  .openapi("PasskeyVerify");

export const interactionPasskeyOptionsRoute = createRoute({
  method: "post",
  path: "/api/v1/interactions/{id}/passkey/options",
  tags: ["interactions"],
  summary: "Authentication options with a fresh challenge (§7.4)",
  request: { params: InteractionIdParams },
  responses: {
    200: {
      description: "Options",
      content: { "application/json": { schema: PasskeyOptionsResponseSchema } },
    },
    ...INTERACTION_ERRORS,
  },
});

export const interactionPasskeyVerifyRoute = createRoute({
  method: "post",
  path: "/api/v1/interactions/{id}/passkey/verify",
  tags: ["interactions"],
  summary: "Verify an assertion and authenticate the interaction (§7.4)",
  request: { params: InteractionIdParams, body: jsonBody(PasskeyVerifyBodySchema) },
  responses: {
    200: {
      description: "ready, consent_required or failed",
      content: { "application/json": { schema: InteractionStepSchema } },
    },
    400: errorResponse("invalid_request"),
    401: errorResponse("passkey_verification_failed or passkey_counter_regression"),
    ...INTERACTION_ERRORS,
  },
});

/** Every OpenAPI route, in document order. */
export const API_ROUTES = [
  healthRoute,
  interactionGetRoute,
  interactionPasskeyOptionsRoute,
  interactionPasskeyVerifyRoute,
  interactionConsentRoute,
  interactionAbortRoute,
] as const;

/** The OpenAPI 3.1 document built from the definitions alone (no handlers, no bindings). */
export function openApiDocument(): Record<string, unknown> {
  const app = new OpenAPIHono();
  for (const route of API_ROUTES) app.openAPIRegistry.registerPath(route);
  return app.getOpenAPI31Document(API_INFO) as unknown as Record<string, unknown>;
}
