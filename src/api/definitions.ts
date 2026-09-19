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

export const RegisterOptionsBodySchema = z
  .object({
    invitation: z.string().optional().openapi({ description: "A tio_iv invitation token" }),
    email: z
      .string()
      .optional()
      .openapi({ description: "Only when the invitation has none, or in open mode" }),
    display_name: z.string().optional(),
  })
  .openapi("RegisterOptionsBody");

export const RegisterOptionsResponseSchema = z
  .object({
    publicKey: z.looseObject({}).openapi({
      description: "PublicKeyCredentialCreationOptionsJSON for navigator.credentials.create()",
    }),
    email_in_use: z.boolean(),
  })
  .openapi("RegisterOptions");

export const RegisterVerifyBodySchema = z
  .object({
    response: z
      .looseObject({})
      .openapi({ description: "RegistrationResponseJSON from the browser" }),
    name: z.string().optional().openapi({ description: "Passkey name, 1-64 characters" }),
  })
  .openapi("RegisterVerify");

export const interactionRegisterOptionsRoute = createRoute({
  method: "post",
  path: "/api/v1/interactions/{id}/register/options",
  tags: ["interactions"],
  summary: "Registration options under the registration policy (§7.4, §6.3)",
  request: { params: InteractionIdParams, body: jsonBody(RegisterOptionsBodySchema) },
  responses: {
    200: {
      description: "Options",
      content: { "application/json": { schema: RegisterOptionsResponseSchema } },
    },
    400: errorResponse(
      "invalid_request, invitation_invalid, invitation_expired, invitation_used, email_invalid",
    ),
    ...INTERACTION_ERRORS,
    409: errorResponse("account_exists or interaction_invalid_state"),
  },
});

export const interactionRegisterVerifyRoute = createRoute({
  method: "post",
  path: "/api/v1/interactions/{id}/register/verify",
  tags: ["interactions"],
  summary:
    "Verify the registration, create or recover the user and authenticate the interaction (§7.4)",
  request: { params: InteractionIdParams, body: jsonBody(RegisterVerifyBodySchema) },
  responses: {
    200: {
      description: "ready, consent_required or failed",
      content: { "application/json": { schema: InteractionStepSchema } },
    },
    400: errorResponse("invalid_request, passkey_not_discoverable, invitation_*"),
    401: errorResponse("passkey_verification_failed"),
    ...INTERACTION_ERRORS,
    409: errorResponse("account_exists or interaction_invalid_state"),
  },
});

// --- Admin API (§9) ----------------------------------------------------------

export const BootstrapBodySchema = z
  .object({
    email: z.string().openapi({ description: "Email of the first administrator" }),
    display_name: z.string().optional(),
  })
  .openapi("BootstrapBody");

export const BootstrapResponseSchema = z
  .object({
    invitation: z.string().openapi({ description: "The tio_iv register invitation token" }),
    invitation_url: z.string().nullable(),
    invitation_expires_at: z.int(),
    client: z.looseObject({}).openapi({ description: "The admin-cli client record" }),
  })
  .openapi("BootstrapResponse");

export const adminBootstrapRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/bootstrap",
  tags: ["admin"],
  summary:
    "One-time bootstrap: admins group, admin-cli client and the first admin invitation (§9.3)",
  request: { body: jsonBody(BootstrapBodySchema) },
  responses: {
    201: {
      description: "Bootstrapped",
      content: { "application/json": { schema: BootstrapResponseSchema } },
    },
    400: errorResponse("invalid_request or email_invalid"),
    401: errorResponse("unauthorized"),
    410: errorResponse("bootstrap_completed"),
    429: errorResponse("rate_limited"),
    503: errorResponse("temporarily_unavailable"),
  },
});

// --- Admin API (§9) ----------------------------------------------------------

export const USER_STATUSES = ["creating", "active", "disabled", "deleting"] as const;

export const AdminUserSchema = z
  .object({
    id: z.uuid(),
    email: z.string().nullable(),
    email_verified: z.boolean(),
    display_name: z.string().nullable(),
    status: z.enum(USER_STATUSES),
    created_at: z.int(),
    updated_at: z.int(),
  })
  .openapi("AdminUser");

export const AdminUserListQuerySchema = z
  .object({
    limit: z.string().optional().openapi({ description: "1..200, default 50" }),
    cursor: z.string().optional().openapi({ description: "Opaque; from next_cursor" }),
    email: z.string().optional().openapi({ description: "Exact match on the verified email" }),
    status: z.enum(USER_STATUSES).optional(),
    group: z.string().optional().openapi({ description: "Group name" }),
    created_after: z.string().optional().openapi({ description: "Unix seconds, inclusive" }),
    created_before: z.string().optional().openapi({ description: "Unix seconds, inclusive" }),
  })
  .strict();

const pageSchema = <T extends z.ZodType>(item: T, name: string) =>
  z.object({ items: z.array(item), next_cursor: z.string().nullable() }).openapi(name);

const adminSecurity = [{ adminToken: [] }];

export const adminUsersListRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/users",
  tags: ["admin"],
  summary: "List users (keyset-paginated, exact-match filters)",
  security: adminSecurity,
  request: { query: AdminUserListQuerySchema },
  responses: {
    200: {
      description: "A page of users",
      content: { "application/json": { schema: pageSchema(AdminUserSchema, "AdminUserPage") } },
    },
    400: errorResponse("invalid_request"),
    401: errorResponse("invalid_token"),
    403: errorResponse("insufficient_scope"),
    429: errorResponse("rate_limited"),
    503: errorResponse("temporarily_unavailable"),
  },
});

// Admin users (§9.4 Users)

const ADMIN_ERRORS = {
  401: errorResponse("invalid_token"),
  403: errorResponse("insufficient_scope"),
  429: errorResponse("rate_limited"),
  503: errorResponse("temporarily_unavailable"),
};

export const UserIdParams = z.object({
  id: z.uuid().openapi({ description: "User id (UUID v7)" }),
});

const GROUP_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export const AdminIdentityInputSchema = z
  .object({
    issuer: z.string().min(1).max(512),
    subject: z.string().min(1).max(512),
    email: z.string().max(254).nullable().optional(),
    email_verified: z.boolean().nullable().optional(),
    name: z.string().max(256).nullable().optional(),
  })
  .strict()
  .openapi("AdminIdentityInput");

export const AdminUserCreateSchema = z
  .object({
    email: z.string().max(254).nullable().optional(),
    email_verified: z.boolean().optional(),
    display_name: z.string().max(256).nullable().optional(),
    groups: z.array(z.string().regex(GROUP_NAME)).max(64).optional(),
    identities: z.array(AdminIdentityInputSchema).max(16).optional(),
  })
  .strict()
  .openapi("AdminUserCreate");

export const AdminUserPatchSchema = z
  .object({
    email: z.string().max(254).nullable().optional(),
    email_verified: z.boolean().optional(),
    display_name: z.string().max(256).nullable().optional(),
    groups: z.array(z.string().regex(GROUP_NAME)).max(64).optional(),
  })
  .strict()
  .openapi("AdminUserPatch");

export const UserCountsSchema = z
  .object({
    passkeys: z.int(),
    identities: z.int(),
    sessions: z.int(),
    refresh_families: z.int(),
    grants: z.int(),
  })
  .openapi("UserCounts");

export const AdminUserDetailSchema = AdminUserSchema.extend({
  groups: z.array(z.string()),
  disabled_at: z.int().nullable(),
  counts: UserCountsSchema,
}).openapi("AdminUserDetail");

export const AdminPasskeySchema = z
  .object({
    id: z.string(),
    credential_id: z.string(),
    alg: z.int(),
    counter: z.int(),
    transports: z.array(z.string()),
    aaguid: z.string().nullable(),
    backup_eligible: z.boolean(),
    backed_up: z.boolean(),
    name: z.string().nullable(),
    created_via: z.enum(["interaction", "me", "recovery"]),
    created_at: z.int(),
    last_used_at: z.int().nullable(),
  })
  .openapi("AdminPasskey");

export const AdminIdentitySchema = z
  .object({
    id: z.string(),
    issuer: z.string(),
    subject: z.string(),
    email: z.string().nullable(),
    email_verified: z.boolean().nullable(),
    name: z.string().nullable(),
    created_at: z.int(),
    last_login_at: z.int().nullable(),
  })
  .openapi("AdminIdentity");

export const AdminSessionSchema = z
  .object({
    sid: z.string(),
    auth_time: z.int(),
    amr: z.array(z.string()),
    acr: z.string(),
    upstream: z.string().nullable(),
    created_at: z.int(),
    last_seen_at: z.int(),
    idle_expires_at: z.int(),
    absolute_expires_at: z.int(),
    clients: z.array(z.string()),
  })
  .openapi("AdminSession");

export const AdminRefreshFamilySchema = z
  .object({
    id: z.string(),
    client_id: z.string(),
    kind: z.enum(["session", "offline"]),
    sid: z.string().nullable(),
    scope: z.array(z.string()),
    auth_time: z.int(),
    amr: z.array(z.string()),
    acr: z.string(),
    created_at: z.int(),
    absolute_expires_at: z.int(),
    idle_expires_at: z.int(),
    current_serial: z.int(),
  })
  .openapi("AdminRefreshFamily");

export const AdminGrantSchema = z
  .object({
    client_id: z.string(),
    scopes: z.array(z.string()),
    granted_at: z.int(),
    updated_at: z.int(),
  })
  .openapi("AdminGrant");

export const RecoverInvitationBodySchema = z
  .object({
    kind: z.literal("recover"),
    expires_in: z.int().optional(),
  })
  .strict()
  .openapi("RecoverInvitationBody");

export const InvitationCreatedSchema = z
  .object({
    id: z.string(),
    kind: z.enum(["register", "recover"]),
    user_id: z.string().nullable(),
    email: z.string().nullable(),
    email_verified: z.boolean(),
    display_name: z.string().nullable(),
    groups: z.array(z.string()),
    expires_at: z.int(),
    created_by: z.string(),
    created_at: z.int(),
    token: z.string().openapi({ description: "Returned once" }),
    url: z
      .string()
      .nullable()
      .openapi({ description: "login_url?invitation=<token>, when a login_url is configured" }),
  })
  .openapi("InvitationCreated");

export const ReindexReportSchema = z
  .object({
    passkeys: z.int(),
    identities: z.int(),
    groups: z.int(),
    unknown_groups: z.array(z.string()),
  })
  .openapi("ReindexReport");

export const RestoreBodySchema = z
  .object({ bookmark_time: z.int().openapi({ description: "Unix seconds" }) })
  .strict()
  .openapi("RestoreBody");

const listOf = (item: z.ZodType, name: string, description: string) => ({
  200: {
    description,
    content: { "application/json": { schema: z.object({ items: z.array(item) }).openapi(name) } },
  },
  404: errorResponse("user_not_found"),
  ...ADMIN_ERRORS,
});

const revokedResponse = (description: string) => ({
  200: {
    description,
    content: { "application/json": { schema: z.object({ revoked: z.boolean() }) } },
  },
  404: errorResponse("user_not_found or the record"),
  ...ADMIN_ERRORS,
});

const userDetailResponse = (description: string) => ({
  description,
  content: { "application/json": { schema: AdminUserDetailSchema } },
});

const USER_PATH = "/api/v1/admin/users/{id}";

export const adminUserCreateRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/users",
  tags: ["admin"],
  summary: "Create a user (§4.6 order); identities are linked at creation",
  security: adminSecurity,
  request: { body: jsonBody(AdminUserCreateSchema) },
  responses: {
    201: userDetailResponse("Created"),
    400: errorResponse("invalid_request, email_invalid or group_unknown"),
    409: errorResponse("email_taken or identity_already_linked"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserGetRoute = createRoute({
  method: "get",
  path: USER_PATH,
  tags: ["admin"],
  summary: "A user's profile from its Durable Object, with counts",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: {
    200: userDetailResponse("The user"),
    404: errorResponse("user_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserPatchRoute = createRoute({
  method: "patch",
  path: USER_PATH,
  tags: ["admin"],
  summary: "Update email, email_verified, display_name or groups (replace)",
  security: adminSecurity,
  request: { params: UserIdParams, body: jsonBody(AdminUserPatchSchema) },
  responses: {
    200: {
      description: "Updated; partial_failure when the D1 mirror write failed",
      content: {
        "application/json": {
          schema: AdminUserDetailSchema.extend({ partial_failure: z.boolean() }),
        },
      },
    },
    400: errorResponse("invalid_request, email_invalid or group_unknown"),
    404: errorResponse("user_not_found"),
    409: errorResponse("email_taken"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserDeleteRoute = createRoute({
  method: "delete",
  path: USER_PATH,
  tags: ["admin"],
  summary: "Delete a user and everything about them (TIO-DATA-010, TIO-PRIV-002)",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: {
    204: { description: "Deleted" },
    404: errorResponse("user_not_found"),
    ...ADMIN_ERRORS,
  },
});

const statusRoute = (op: "disable" | "enable") =>
  createRoute({
    method: "post",
    path: `${USER_PATH}/${op}`,
    tags: ["admin"],
    summary:
      op === "disable"
        ? "Disable a user: every session and refresh family is revoked (TIO-DATA-009)"
        : "Enable a disabled user",
    security: adminSecurity,
    request: { params: UserIdParams },
    responses: {
      200: {
        description: "The user",
        content: {
          "application/json": {
            schema: AdminUserDetailSchema.extend({ partial_failure: z.boolean() }),
          },
        },
      },
      404: errorResponse("user_not_found"),
      ...ADMIN_ERRORS,
    },
  });

export const adminUserDisableRoute = statusRoute("disable");
export const adminUserEnableRoute = statusRoute("enable");

export const adminUserPasskeysRoute = createRoute({
  method: "get",
  path: `${USER_PATH}/passkeys`,
  tags: ["admin"],
  summary: "The user's passkeys (metadata only, never public keys)",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: listOf(AdminPasskeySchema, "AdminPasskeyList", "Passkeys"),
});

export const adminUserPasskeyDeleteRoute = createRoute({
  method: "delete",
  path: `${USER_PATH}/passkeys/{pid}`,
  tags: ["admin"],
  summary: "Remove a passkey (the object first, then the index)",
  security: adminSecurity,
  request: { params: UserIdParams.extend({ pid: z.string() }) },
  responses: revokedResponse("Whether a passkey was removed"),
});

export const adminUserIdentitiesRoute = createRoute({
  method: "get",
  path: `${USER_PATH}/identities`,
  tags: ["admin"],
  summary: "The user's federated identities",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: listOf(AdminIdentitySchema, "AdminIdentityList", "Identities"),
});

export const adminUserIdentityDeleteRoute = createRoute({
  method: "delete",
  path: `${USER_PATH}/identities/{iid}`,
  tags: ["admin"],
  summary: "Unlink an identity (no last-method rule for administrators)",
  security: adminSecurity,
  request: { params: UserIdParams.extend({ iid: z.string() }) },
  responses: revokedResponse("Whether an identity was unlinked"),
});

export const adminUserSessionsRoute = createRoute({
  method: "get",
  path: `${USER_PATH}/sessions`,
  tags: ["admin"],
  summary: "The user's live sessions",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: listOf(AdminSessionSchema, "AdminSessionList", "Sessions"),
});

export const adminUserSessionDeleteRoute = createRoute({
  method: "delete",
  path: `${USER_PATH}/sessions/{sid}`,
  tags: ["admin"],
  summary: "Revoke one session and its session-bound families",
  security: adminSecurity,
  request: { params: UserIdParams.extend({ sid: z.string() }) },
  responses: revokedResponse("Whether a session was revoked"),
});

export const adminUserSessionsDeleteRoute = createRoute({
  method: "delete",
  path: `${USER_PATH}/sessions`,
  tags: ["admin"],
  summary: "Revoke every session and refresh family",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: {
    200: {
      description: "How many sessions were revoked",
      content: { "application/json": { schema: z.object({ revoked: z.int() }) } },
    },
    404: errorResponse("user_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserFamiliesRoute = createRoute({
  method: "get",
  path: `${USER_PATH}/refresh-families`,
  tags: ["admin"],
  summary: "The user's live refresh families (never token material)",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: listOf(AdminRefreshFamilySchema, "AdminRefreshFamilyList", "Refresh families"),
});

export const adminUserFamilyDeleteRoute = createRoute({
  method: "delete",
  path: `${USER_PATH}/refresh-families/{fid}`,
  tags: ["admin"],
  summary: "Revoke one refresh family",
  security: adminSecurity,
  request: { params: UserIdParams.extend({ fid: z.string() }) },
  responses: revokedResponse("Whether a family was revoked"),
});

export const adminUserFamiliesDeleteRoute = createRoute({
  method: "delete",
  path: `${USER_PATH}/refresh-families`,
  tags: ["admin"],
  summary: "Revoke every refresh family of a client",
  security: adminSecurity,
  request: { params: UserIdParams, query: z.object({ client_id: z.string() }).strict() },
  responses: {
    200: {
      description: "How many families were revoked",
      content: { "application/json": { schema: z.object({ revoked: z.int() }) } },
    },
    400: errorResponse("invalid_request"),
    404: errorResponse("user_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserGrantsRoute = createRoute({
  method: "get",
  path: `${USER_PATH}/grants`,
  tags: ["admin"],
  summary: "The user's consent grants for clients that still exist",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: listOf(AdminGrantSchema, "AdminGrantList", "Grants"),
});

export const adminUserGrantDeleteRoute = createRoute({
  method: "delete",
  path: `${USER_PATH}/grants/{client_id}`,
  tags: ["admin"],
  summary: "Revoke the consent grant of a client",
  security: adminSecurity,
  request: { params: UserIdParams.extend({ client_id: z.string() }) },
  responses: revokedResponse("Whether a grant was revoked"),
});

export const adminUserEventsRoute = createRoute({
  method: "get",
  path: `${USER_PATH}/events`,
  tags: ["admin"],
  summary: "The user's audit events from audit_hot (arrives with the audit endpoints)",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: {
    501: errorResponse("not_implemented"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserInvitationRoute = createRoute({
  method: "post",
  path: `${USER_PATH}/invitations`,
  tags: ["admin"],
  summary: "Create a recovery invitation for the user (TIO-REG-004)",
  security: adminSecurity,
  request: { params: UserIdParams, body: jsonBody(RecoverInvitationBodySchema) },
  responses: {
    201: {
      description: "The invitation with its one-time token",
      content: { "application/json": { schema: InvitationCreatedSchema } },
    },
    400: errorResponse("invalid_request or expires_in_out_of_bounds"),
    404: errorResponse("user_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserReindexRoute = createRoute({
  method: "post",
  path: `${USER_PATH}/reindex`,
  tags: ["admin"],
  summary: "Rebuild the user's D1 mirror and index rows from the object (TIO-DATA-027)",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: {
    200: {
      description: "What was rebuilt",
      content: { "application/json": { schema: ReindexReportSchema } },
    },
    404: errorResponse("user_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserExportRoute = createRoute({
  method: "get",
  path: `${USER_PATH}/export`,
  tags: ["admin"],
  summary: "Complete export of the user's state minus secrets (TIO-PRIV-002)",
  security: adminSecurity,
  request: { params: UserIdParams },
  responses: {
    200: {
      description: "The export",
      content: { "application/json": { schema: z.looseObject({}).openapi("UserExport") } },
    },
    404: errorResponse("user_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminUserRestoreRoute = createRoute({
  method: "post",
  path: `${USER_PATH}/restore`,
  tags: ["admin"],
  summary: "Point-in-time recovery of the user's object (TIO-DEPLOY-003)",
  security: adminSecurity,
  request: { params: UserIdParams, body: jsonBody(RestoreBodySchema) },
  responses: {
    202: {
      description: "The restore is scheduled; the object restarts from the bookmark",
      content: { "application/json": { schema: z.object({ bookmark: z.string() }) } },
    },
    400: errorResponse("invalid_request"),
    404: errorResponse("user_not_found"),
    503: errorResponse("restore_unavailable or temporarily_unavailable"),
    401: errorResponse("invalid_token"),
    403: errorResponse("insufficient_scope"),
    429: errorResponse("rate_limited"),
  },
});

export const ADMIN_USER_ROUTES = [
  adminUsersListRoute,
  adminUserCreateRoute,
  adminUserGetRoute,
  adminUserPatchRoute,
  adminUserDeleteRoute,
  adminUserDisableRoute,
  adminUserEnableRoute,
  adminUserPasskeysRoute,
  adminUserPasskeyDeleteRoute,
  adminUserIdentitiesRoute,
  adminUserIdentityDeleteRoute,
  adminUserSessionsRoute,
  adminUserSessionDeleteRoute,
  adminUserSessionsDeleteRoute,
  adminUserFamiliesRoute,
  adminUserFamilyDeleteRoute,
  adminUserFamiliesDeleteRoute,
  adminUserGrantsRoute,
  adminUserGrantDeleteRoute,
  adminUserEventsRoute,
  adminUserInvitationRoute,
  adminUserReindexRoute,
  adminUserExportRoute,
  adminUserRestoreRoute,
] as const;

/** Every OpenAPI route, in document order. */
export const API_ROUTES = [
  healthRoute,
  interactionGetRoute,
  interactionPasskeyOptionsRoute,
  interactionPasskeyVerifyRoute,
  interactionRegisterOptionsRoute,
  interactionRegisterVerifyRoute,
  interactionConsentRoute,
  interactionAbortRoute,
  adminBootstrapRoute,
  ...ADMIN_USER_ROUTES,
] as const;

/** Registers every route and the bearer scheme of the Admin API on an app's registry. */
export function registerApi(app: Pick<OpenAPIHono, "openAPIRegistry">): void {
  for (const route of API_ROUTES) app.openAPIRegistry.registerPath(route);
  app.openAPIRegistry.registerComponent("securitySchemes", "adminToken", {
    type: "http",
    scheme: "bearer",
    bearerFormat: "at+jwt",
    description: "An access token with scope admin and the issuer in aud (§9.1)",
  });
}

/** The OpenAPI 3.1 document built from the definitions alone (no handlers, no bindings). */
export function openApiDocument(): Record<string, unknown> {
  const app = new OpenAPIHono();
  registerApi(app);
  return app.getOpenAPI31Document(API_INFO) as unknown as Record<string, unknown>;
}
