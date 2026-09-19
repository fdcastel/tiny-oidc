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

export const UpstreamStartBodySchema = z
  .object({
    invitation: z.string().min(1).max(512).optional().openapi({
      description: "A register invitation token (tio_iv_…) to create the account with",
    }),
  })
  .openapi("UpstreamStart");

export const UpstreamStartResponseSchema = z
  .object({
    redirect_to: z
      .string()
      .openapi({ description: "The upstream's authorization URL the browser must visit" }),
  })
  .openapi("UpstreamStartResponse");

export const interactionUpstreamRoute = createRoute({
  method: "post",
  path: "/api/v1/interactions/{id}/upstream/{alias}",
  tags: ["interactions"],
  summary: "Start a federated login through an upstream (§7.5, TIO-IX-040)",
  request: {
    params: InteractionIdParams.extend({
      alias: z.string().min(1).max(64).openapi({ description: "The upstream alias" }),
    }),
    body: jsonBody(UpstreamStartBodySchema),
  },
  responses: {
    200: {
      description: "Where to send the browser",
      content: { "application/json": { schema: UpstreamStartResponseSchema } },
    },
    400: errorResponse(
      "invalid_request, invitation_invalid, invitation_expired or invitation_used",
    ),
    ...INTERACTION_ERRORS,
    404: errorResponse("interaction_not_found or upstream_not_found"),
    503: errorResponse("temporarily_unavailable or upstream_unavailable"),
  },
});

export const LogoutDecisionSchema = z
  .object({ confirm: z.boolean() })
  .strict()
  .openapi("LogoutDecision");

export const LogoutStepSchema = z.object({ redirect_to: z.string() }).openapi("LogoutStep");

export const interactionLogoutRoute = createRoute({
  method: "post",
  path: "/api/v1/interactions/{id}/logout",
  tags: ["interactions"],
  summary: "Confirm or decline signing out (§7.6)",
  request: { params: InteractionIdParams, body: jsonBody(LogoutDecisionSchema) },
  responses: {
    200: {
      description: "Where the browser finishes",
      content: { "application/json": { schema: LogoutStepSchema } },
    },
    400: errorResponse("invalid_request"),
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

export const PersonalEventSchema = z
  .object({
    id: z.string(),
    type: z.string(),
    ts: z.int(),
    outcome: z.enum(["success", "failure"]),
    client_id: z.string().nullable(),
    country: z.string().nullable(),
    ua_family: z.string().nullable(),
  })
  .openapi("PersonalEvent");

export const EventsQuerySchema = z
  .object({
    limit: z.string().optional().openapi({ description: "1..200, default 50" }),
    cursor: z.string().optional().openapi({ description: "Opaque; from next_cursor" }),
  })
  .strict();

export const adminUserEventsRoute = createRoute({
  method: "get",
  path: `${USER_PATH}/events`,
  tags: ["admin"],
  summary: "The user's events from audit_hot, newest first, within the hot retention window (§9.4)",
  security: adminSecurity,
  request: { params: UserIdParams, query: EventsQuerySchema },
  responses: {
    200: {
      description: "A page",
      content: {
        "application/json": { schema: pageSchema(PersonalEventSchema, "PersonalEventPage") },
      },
    },
    400: errorResponse("invalid_request"),
    404: errorResponse("user_not_found"),
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

// Admin groups (§9.4 Groups, §3.5)

export const GroupIdParams = z.object({
  id: z.uuid().openapi({ description: "Group id (UUID v7)" }),
});

export const AdminGroupSchema = z
  .object({
    id: z.uuid(),
    name: z.string(),
    description: z.string().nullable(),
    system: z.boolean(),
    created_at: z.int(),
    updated_at: z.int(),
  })
  .openapi("AdminGroup");

export const AdminGroupDetailSchema = AdminGroupSchema.extend({
  members: z.int().openapi({ description: "From the D1 mirror (TIO-DATA-013)" }),
}).openapi("AdminGroupDetail");

export const AdminGroupCreateSchema = z
  .object({
    name: z.string().regex(GROUP_NAME),
    description: z.string().max(512).nullable().optional(),
  })
  .strict()
  .openapi("AdminGroupCreate");

export const AdminGroupPatchSchema = z
  .object({
    name: z.string().regex(GROUP_NAME).optional(),
    description: z.string().max(512).nullable().optional(),
  })
  .strict()
  .openapi("AdminGroupPatch");

export const PropagationSchema = z
  .object({
    members: z.int(),
    failed: z.array(z.string()).openapi({ description: "Members whose object was not updated" }),
  })
  .openapi("Propagation");

export const AdminListQuerySchema = z
  .object({
    limit: z.string().optional().openapi({ description: "1..200, default 50" }),
    cursor: z.string().optional().openapi({ description: "Opaque; from next_cursor" }),
  })
  .strict();

export const MembershipResponseSchema = z
  .object({
    user_id: z.uuid(),
    groups: z.array(z.string()),
    changed: z.boolean(),
    partial_failure: z.boolean(),
  })
  .openapi("Membership");

const GROUP_PATH = "/api/v1/admin/groups/{id}";

export const adminGroupsListRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/groups",
  tags: ["admin"],
  summary: "List groups (keyset-paginated)",
  security: adminSecurity,
  request: { query: AdminListQuerySchema },
  responses: {
    200: {
      description: "A page of groups",
      content: { "application/json": { schema: pageSchema(AdminGroupSchema, "AdminGroupPage") } },
    },
    400: errorResponse("invalid_request"),
    ...ADMIN_ERRORS,
  },
});

export const adminGroupCreateRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/groups",
  tags: ["admin"],
  summary: "Create a group",
  security: adminSecurity,
  request: { body: jsonBody(AdminGroupCreateSchema) },
  responses: {
    201: {
      description: "Created",
      content: { "application/json": { schema: AdminGroupDetailSchema } },
    },
    400: errorResponse("invalid_request"),
    409: errorResponse("group_exists"),
    ...ADMIN_ERRORS,
  },
});

export const adminGroupGetRoute = createRoute({
  method: "get",
  path: GROUP_PATH,
  tags: ["admin"],
  summary: "A group with its member count",
  security: adminSecurity,
  request: { params: GroupIdParams },
  responses: {
    200: {
      description: "The group",
      content: { "application/json": { schema: AdminGroupDetailSchema } },
    },
    404: errorResponse("group_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminGroupPatchRoute = createRoute({
  method: "patch",
  path: GROUP_PATH,
  tags: ["admin"],
  summary:
    "Rename or describe a group; a rename is propagated to every member's object (at most 1,000 members per call)",
  security: adminSecurity,
  request: { params: GroupIdParams, body: jsonBody(AdminGroupPatchSchema) },
  responses: {
    200: {
      description: "Updated; `propagation.failed` lists members to retry",
      content: {
        "application/json": {
          schema: AdminGroupDetailSchema.extend({ propagation: PropagationSchema.nullable() }),
        },
      },
    },
    400: errorResponse("invalid_request"),
    404: errorResponse("group_not_found"),
    409: errorResponse("group_exists, system_group or group_too_large"),
    ...ADMIN_ERRORS,
  },
});

export const adminGroupDeleteRoute = createRoute({
  method: "delete",
  path: GROUP_PATH,
  tags: ["admin"],
  summary:
    "Delete a group; the name leaves every member's object first (at most 1,000 members per call)",
  security: adminSecurity,
  request: { params: GroupIdParams },
  responses: {
    200: {
      description: "Deleted; `propagation.failed` lists members whose object kept the name",
      content: { "application/json": { schema: z.object({ propagation: PropagationSchema }) } },
    },
    404: errorResponse("group_not_found"),
    409: errorResponse("system_group or group_too_large"),
    ...ADMIN_ERRORS,
  },
});

export const adminGroupMembersRoute = createRoute({
  method: "get",
  path: `${GROUP_PATH}/members`,
  tags: ["admin"],
  summary: "The group's members (users, keyset-paginated)",
  security: adminSecurity,
  request: { params: GroupIdParams, query: AdminListQuerySchema },
  responses: {
    200: {
      description: "A page of users",
      content: { "application/json": { schema: pageSchema(AdminUserSchema, "AdminMemberPage") } },
    },
    400: errorResponse("invalid_request"),
    404: errorResponse("group_not_found"),
    ...ADMIN_ERRORS,
  },
});

const membershipRoute = (method: "put" | "delete") =>
  createRoute({
    method,
    path: `${GROUP_PATH}/members/{user_id}`,
    tags: ["admin"],
    summary:
      method === "put"
        ? "Add a user to the group (object first, then the mirror)"
        : "Remove a user from the group (object first, then the mirror)",
    security: adminSecurity,
    request: { params: GroupIdParams.extend({ user_id: z.uuid() }) },
    responses: {
      200: {
        description: "The user's groups after the change",
        content: { "application/json": { schema: MembershipResponseSchema } },
      },
      404: errorResponse("group_not_found or user_not_found"),
      ...ADMIN_ERRORS,
    },
  });

export const adminGroupMemberAddRoute = membershipRoute("put");
export const adminGroupMemberRemoveRoute = membershipRoute("delete");

export const ADMIN_GROUP_ROUTES = [
  adminGroupsListRoute,
  adminGroupCreateRoute,
  adminGroupGetRoute,
  adminGroupPatchRoute,
  adminGroupDeleteRoute,
  adminGroupMembersRoute,
  adminGroupMemberAddRoute,
  adminGroupMemberRemoveRoute,
] as const;

// Admin clients (§9.4 Clients, §5.11)

export const ClientIdParams = z.object({
  id: z
    .string()
    .regex(/^[a-z0-9][a-z0-9._-]{2,63}$/)
    .openapi({ description: "Client id" }),
});

export const AdminClientSchema = z
  .looseObject({
    client_id: z.string(),
    client_name: z.string(),
    token_endpoint_auth_method: z.string(),
    grant_types: z.array(z.string()),
    scopes_allowed: z.array(z.string()),
    disabled_at: z.int().nullable(),
    created_at: z.int(),
    updated_at: z.int(),
  })
  .openapi("AdminClient", {
    description:
      "The client record without its secret hash (TIO-ADMIN-003); see §5.11 for every field",
  });

export const AdminClientCreatedSchema = AdminClientSchema.extend({
  client_secret: z
    .string()
    .nullable()
    .openapi({ description: "Returned exactly once, for client_secret_basic/post clients" }),
}).openapi("AdminClientCreated");

export const AdminClientInputSchema = z
  .looseObject({
    client_id: z.string().optional(),
    client_name: z.string(),
    grant_types: z.array(z.string()),
    token_endpoint_auth_method: z.string(),
    scopes_allowed: z.array(z.string()),
  })
  .openapi("AdminClientInput", {
    description: "The create body; every field of §5.11 is accepted",
  });

export const AdminClientPatchInputSchema = z
  .looseObject({})
  .openapi("AdminClientPatch", { description: "Any subset of the create body except client_id" });

export const RotatedSecretSchema = z
  .object({ client_id: z.string(), client_secret: z.string(), rotated_at: z.int() })
  .openapi("RotatedSecret");

const CLIENT_PATH = "/api/v1/admin/clients/{id}";

export const adminClientsListRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/clients",
  tags: ["admin"],
  summary: "List clients (keyset-paginated)",
  security: adminSecurity,
  request: { query: AdminListQuerySchema },
  responses: {
    200: {
      description: "A page of clients",
      content: { "application/json": { schema: pageSchema(AdminClientSchema, "AdminClientPage") } },
    },
    400: errorResponse("invalid_request"),
    ...ADMIN_ERRORS,
  },
});

export const adminClientCreateRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/clients",
  tags: ["admin"],
  summary:
    "Create a client; the secret, when the method uses one, is returned once (TIO-CLIENT-003)",
  security: adminSecurity,
  request: { body: jsonBody(AdminClientInputSchema) },
  responses: {
    201: {
      description: "Created",
      content: { "application/json": { schema: AdminClientCreatedSchema } },
    },
    400: errorResponse("invalid_client with the violations in error_description"),
    409: errorResponse("client_exists"),
    ...ADMIN_ERRORS,
  },
});

export const adminClientGetRoute = createRoute({
  method: "get",
  path: CLIENT_PATH,
  tags: ["admin"],
  summary: "A client record",
  security: adminSecurity,
  request: { params: ClientIdParams },
  responses: {
    200: {
      description: "The client",
      content: { "application/json": { schema: AdminClientSchema } },
    },
    404: errorResponse("client_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminClientPatchRoute = createRoute({
  method: "patch",
  path: CLIENT_PATH,
  tags: ["admin"],
  summary:
    "Update a client; the merged record is validated as a whole. A switch to a secret method returns a new secret once",
  security: adminSecurity,
  request: { params: ClientIdParams, body: jsonBody(AdminClientPatchInputSchema) },
  responses: {
    200: {
      description: "Updated",
      content: { "application/json": { schema: AdminClientCreatedSchema } },
    },
    400: errorResponse("invalid_request or invalid_client"),
    404: errorResponse("client_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminClientDeleteRoute = createRoute({
  method: "delete",
  path: CLIENT_PATH,
  tags: ["admin"],
  summary:
    "Delete a client; consent grants and refresh families are cleaned up lazily (TIO-CLIENT-005)",
  security: adminSecurity,
  request: { params: ClientIdParams },
  responses: {
    204: { description: "Deleted" },
    404: errorResponse("client_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminClientRotateRoute = createRoute({
  method: "post",
  path: `${CLIENT_PATH}/rotate-secret`,
  tags: ["admin"],
  summary: "Replace the secret immediately (TIO-CLIENT-003)",
  security: adminSecurity,
  request: { params: ClientIdParams },
  responses: {
    200: {
      description: "The new secret, returned once",
      content: { "application/json": { schema: RotatedSecretSchema } },
    },
    404: errorResponse("client_not_found"),
    409: errorResponse("no_secret: the client's method uses no shared secret"),
    ...ADMIN_ERRORS,
  },
});

const clientStatusRoute = (op: "disable" | "enable") =>
  createRoute({
    method: "post",
    path: `${CLIENT_PATH}/${op}`,
    tags: ["admin"],
    summary:
      op === "disable"
        ? "Disable a client: every grant, PAR, token and refresh operation fails within the cache window (TIO-CLIENT-004)"
        : "Enable a disabled client",
    security: adminSecurity,
    request: { params: ClientIdParams },
    responses: {
      200: {
        description: "The client",
        content: { "application/json": { schema: AdminClientSchema } },
      },
      404: errorResponse("client_not_found"),
      ...ADMIN_ERRORS,
    },
  });

export const adminClientDisableRoute = clientStatusRoute("disable");
export const adminClientEnableRoute = clientStatusRoute("enable");

export const ADMIN_CLIENT_ROUTES = [
  adminClientsListRoute,
  adminClientCreateRoute,
  adminClientGetRoute,
  adminClientPatchRoute,
  adminClientDeleteRoute,
  adminClientRotateRoute,
  adminClientDisableRoute,
  adminClientEnableRoute,
] as const;

// Admin upstreams (§9.4 Upstreams, §6.4.1)

export const UpstreamAliasParams = z.object({
  alias: z
    .string()
    .regex(/^[a-z0-9][a-z0-9_-]{0,31}$/)
    .openapi({ description: "Upstream alias" }),
});

export const AdminUpstreamSchema = z
  .looseObject({
    alias: z.string(),
    issuer: z.string(),
    display_name: z.string(),
    client_id: z.string(),
    token_endpoint_auth_method: z.string(),
    has_client_secret: z.boolean(),
    has_client_jwk: z.boolean(),
    redirect_uri: z
      .string()
      .openapi({ description: "The issuer URL followed by /federation/callback (TIO-FED-002)" }),
    enabled: z.boolean(),
    created_at: z.int(),
    updated_at: z.int(),
  })
  .openapi("AdminUpstream", {
    description: "The upstream record without its secret or private key (TIO-ADMIN-003)",
  });

export const AdminUpstreamInputSchema = z
  .looseObject({
    alias: z.string(),
    issuer: z.string(),
    display_name: z.string(),
    client_id: z.string(),
    token_endpoint_auth_method: z.string(),
    client_secret: z.string().optional().openapi({ description: "Write-only; stored encrypted" }),
    client_jwk: z
      .looseObject({})
      .optional()
      .openapi({ description: "Write-only private JWK for private_key_jwt" }),
  })
  .openapi("AdminUpstreamInput", {
    description: "The create body; every field of §4.1 upstreams is accepted",
  });

export const AdminUpstreamPatchInputSchema = z
  .looseObject({})
  .openapi("AdminUpstreamPatch", { description: "Any subset of the create body except alias" });

export const UpstreamTestReportSchema = z
  .object({
    discovery: z.object({
      ok: z.boolean(),
      reason: z.string().nullable(),
      metadata: z
        .object({
          authorization_endpoint: z.string(),
          token_endpoint: z.string(),
          jwks_uri: z.string(),
          userinfo_endpoint: z.string().nullable(),
        })
        .nullable(),
    }),
    jwks: z.object({ ok: z.boolean(), reason: z.string().nullable(), keys: z.int().nullable() }),
  })
  .openapi("UpstreamTestReport");

const UPSTREAM_PATH = "/api/v1/admin/upstreams/{alias}";

export const adminUpstreamsListRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/upstreams",
  tags: ["admin"],
  summary: "List upstreams (keyset-paginated)",
  security: adminSecurity,
  request: { query: AdminListQuerySchema },
  responses: {
    200: {
      description: "A page of upstreams",
      content: {
        "application/json": { schema: pageSchema(AdminUpstreamSchema, "AdminUpstreamPage") },
      },
    },
    400: errorResponse("invalid_request"),
    ...ADMIN_ERRORS,
  },
});

export const adminUpstreamCreateRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/upstreams",
  tags: ["admin"],
  summary:
    "Create an upstream; with discovery.mode auto the provider's document is fetched and checked (TIO-FED-001)",
  security: adminSecurity,
  request: { body: jsonBody(AdminUpstreamInputSchema) },
  responses: {
    201: {
      description: "Created",
      content: { "application/json": { schema: AdminUpstreamSchema } },
    },
    400: errorResponse(
      "invalid_upstream (violations in error_description) or upstream_discovery_failed",
    ),
    409: errorResponse("upstream_exists (alias or issuer)"),
    ...ADMIN_ERRORS,
  },
});

export const adminUpstreamGetRoute = createRoute({
  method: "get",
  path: UPSTREAM_PATH,
  tags: ["admin"],
  summary: "An upstream record",
  security: adminSecurity,
  request: { params: UpstreamAliasParams },
  responses: {
    200: {
      description: "The upstream",
      content: { "application/json": { schema: AdminUpstreamSchema } },
    },
    404: errorResponse("upstream_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminUpstreamPatchRoute = createRoute({
  method: "patch",
  path: UPSTREAM_PATH,
  tags: ["admin"],
  summary:
    "Update an upstream; the merged record is validated as a whole and auto discovery is fetched again",
  security: adminSecurity,
  request: { params: UpstreamAliasParams, body: jsonBody(AdminUpstreamPatchInputSchema) },
  responses: {
    200: {
      description: "Updated",
      content: { "application/json": { schema: AdminUpstreamSchema } },
    },
    400: errorResponse("invalid_request, invalid_upstream or upstream_discovery_failed"),
    404: errorResponse("upstream_not_found"),
    409: errorResponse("upstream_exists (issuer)"),
    ...ADMIN_ERRORS,
  },
});

export const adminUpstreamDeleteRoute = createRoute({
  method: "delete",
  path: UPSTREAM_PATH,
  tags: ["admin"],
  summary: "Delete an upstream; linked identities stay on their users",
  security: adminSecurity,
  request: { params: UpstreamAliasParams },
  responses: {
    204: { description: "Deleted" },
    404: errorResponse("upstream_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminUpstreamTestRoute = createRoute({
  method: "post",
  path: `${UPSTREAM_PATH}/test`,
  tags: ["admin"],
  summary: "Refetch the discovery document and the JWKS and report (TIO-FED-001)",
  security: adminSecurity,
  request: { params: UpstreamAliasParams },
  responses: {
    200: {
      description: "The report; each part says whether it succeeded",
      content: { "application/json": { schema: UpstreamTestReportSchema } },
    },
    404: errorResponse("upstream_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const ADMIN_UPSTREAM_ROUTES = [
  adminUpstreamsListRoute,
  adminUpstreamCreateRoute,
  adminUpstreamGetRoute,
  adminUpstreamPatchRoute,
  adminUpstreamDeleteRoute,
  adminUpstreamTestRoute,
] as const;

// Admin invitations (§9.4 Invitations, §6.3)

export const InvitationIdParams = z.object({
  id: z.uuid().openapi({ description: "Invitation id (UUID v7)" }),
});

export const AdminInvitationSchema = z
  .object({
    id: z.uuid(),
    kind: z.enum(["register", "recover"]),
    user_id: z.uuid().nullable(),
    email: z.string().nullable(),
    email_verified: z.boolean(),
    display_name: z.string().nullable(),
    groups: z.array(z.string()),
    expires_at: z.int(),
    used_at: z.int().nullable(),
    used_by_user_id: z.uuid().nullable(),
    created_by: z.string(),
    created_at: z.int(),
  })
  .openapi("AdminInvitation");

export const AdminInvitationCreateSchema = z
  .object({
    kind: z.literal("register"),
    email: z.string().max(254).nullable().optional(),
    email_verified: z.boolean().optional(),
    display_name: z.string().max(256).nullable().optional(),
    groups: z.array(z.string().regex(GROUP_NAME)).max(64).optional(),
    expires_in: z.int().optional().openapi({ description: "Seconds, 1 h – 90 d; default 7 d" }),
  })
  .strict()
  .openapi("AdminInvitationCreate");

export const AdminInvitationListQuerySchema = z
  .object({
    limit: z.string().optional(),
    cursor: z.string().optional(),
    kind: z.enum(["register", "recover"]).optional(),
    user_id: z.uuid().optional(),
  })
  .strict();

const INVITATION_PATH = "/api/v1/admin/invitations/{id}";

export const adminInvitationsListRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/invitations",
  tags: ["admin"],
  summary: "List invitations (keyset-paginated; filters kind, user_id)",
  security: adminSecurity,
  request: { query: AdminInvitationListQuerySchema },
  responses: {
    200: {
      description: "A page of invitations (never their tokens)",
      content: {
        "application/json": { schema: pageSchema(AdminInvitationSchema, "AdminInvitationPage") },
      },
    },
    400: errorResponse("invalid_request"),
    ...ADMIN_ERRORS,
  },
});

export const adminInvitationCreateRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/invitations",
  tags: ["admin"],
  summary: "Create a register invitation; the token and URL are returned once (TIO-REG-002)",
  security: adminSecurity,
  request: { body: jsonBody(AdminInvitationCreateSchema) },
  responses: {
    201: {
      description: "The invitation with its one-time token",
      content: { "application/json": { schema: InvitationCreatedSchema } },
    },
    400: errorResponse("invalid_request, email_invalid, group_unknown or expires_in_out_of_bounds"),
    ...ADMIN_ERRORS,
  },
});

export const adminInvitationGetRoute = createRoute({
  method: "get",
  path: INVITATION_PATH,
  tags: ["admin"],
  summary: "An invitation record (never its token)",
  security: adminSecurity,
  request: { params: InvitationIdParams },
  responses: {
    200: {
      description: "The invitation",
      content: { "application/json": { schema: AdminInvitationSchema } },
    },
    404: errorResponse("invitation_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const adminInvitationDeleteRoute = createRoute({
  method: "delete",
  path: INVITATION_PATH,
  tags: ["admin"],
  summary: "Revoke an invitation: its token stops working at once",
  security: adminSecurity,
  request: { params: InvitationIdParams },
  responses: {
    204: { description: "Revoked" },
    404: errorResponse("invitation_not_found"),
    ...ADMIN_ERRORS,
  },
});

export const ADMIN_INVITATION_ROUTES = [
  adminInvitationsListRoute,
  adminInvitationCreateRoute,
  adminInvitationGetRoute,
  adminInvitationDeleteRoute,
] as const;

// Admin keys, settings, stats and maintenance (§9.4, §10.3, §12.2, §12.4)

export const AdminKeySchema = z
  .object({
    kid: z.string(),
    alg: z.string(),
    role: z.enum(["signing", "next", "verifying", "retired"]),
    public_jwk: z.looseObject({}),
    created_at: z.int(),
    activates_at: z.int(),
    retired_at: z.int().nullable(),
  })
  .openapi("AdminKey");

export const RotateKeyBodySchema = z
  .object({
    immediate: z
      .boolean()
      .optional()
      .openapi({ description: "true makes the new key sign at once (emergency)" }),
  })
  .strict()
  .openapi("RotateKeyBody");

export const KidParams = z.object({ kid: z.string().min(1).max(128) });

export const adminKeysListRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/keys",
  tags: ["admin"],
  summary: "Every signing key with its derived role; public JWKs only (§10.3)",
  security: adminSecurity,
  responses: {
    200: {
      description: "The keys, oldest activation first",
      content: { "application/json": { schema: z.object({ items: z.array(AdminKeySchema) }) } },
    },
    ...ADMIN_ERRORS,
  },
});

export const adminKeysRotateRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/keys/rotate",
  tags: ["admin"],
  summary: "Create the next signing key, prepublished or immediate (TIO-KEYS-012)",
  security: adminSecurity,
  request: { body: jsonBody(RotateKeyBodySchema) },
  responses: {
    201: {
      description: "The new key",
      content: { "application/json": { schema: AdminKeySchema } },
    },
    400: errorResponse("invalid_request"),
    ...ADMIN_ERRORS,
  },
});

export const adminKeyDeleteRoute = createRoute({
  method: "delete",
  path: "/api/v1/admin/keys/{kid}",
  tags: ["admin"],
  summary: "Retire a key immediately; refused for the only active key (TIO-KEYS-013)",
  security: adminSecurity,
  request: { params: KidParams },
  responses: {
    200: {
      description: "The retired key",
      content: { "application/json": { schema: AdminKeySchema } },
    },
    404: errorResponse("key_not_found"),
    409: errorResponse("last_active_key"),
    ...ADMIN_ERRORS,
  },
});

export const EffectiveSettingSchema = z
  .object({ value: z.unknown(), source: z.enum(["default", "setting"]) })
  .openapi("EffectiveSetting");

export const adminSettingsGetRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/settings",
  tags: ["admin"],
  summary: "Effective settings, each with its source (§12.2)",
  security: adminSecurity,
  responses: {
    200: {
      description: "Setting name → { value, source }",
      content: { "application/json": { schema: z.record(z.string(), EffectiveSettingSchema) } },
    },
    ...ADMIN_ERRORS,
  },
});

export const adminSettingsPatchRoute = createRoute({
  method: "patch",
  path: "/api/v1/admin/settings",
  tags: ["admin"],
  summary:
    "Change settings; null returns a key to its default; the whole is validated (TIO-CFG-003)",
  security: adminSecurity,
  request: {
    body: jsonBody(
      z.record(z.string(), z.unknown()).openapi("SettingsPatch", {
        description: "Setting name → new value, or null for the default",
      }),
    ),
  },
  responses: {
    200: {
      description: "The effective settings after the change",
      content: { "application/json": { schema: z.record(z.string(), EffectiveSettingSchema) } },
    },
    400: errorResponse("invalid_request or invalid_settings with the violations"),
    ...ADMIN_ERRORS,
  },
});

export const StatsSchema = z
  .object({
    users: z.object({ creating: z.int(), active: z.int(), disabled: z.int(), deleting: z.int() }),
    clients: z.int(),
    upstreams: z.int(),
    keys: z.object({ signing: z.int(), next: z.int(), verifying: z.int(), retired: z.int() }),
    audit_hot_rows: z.int(),
    last_cron_run: z.int().nullable(),
  })
  .openapi("Stats");

export const adminStatsRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/stats",
  tags: ["admin"],
  summary:
    "Counts of users by status, clients, upstreams, keys by role, hot audit rows and the last cron run",
  security: adminSecurity,
  responses: {
    200: { description: "The counts", content: { "application/json": { schema: StatsSchema } } },
    ...ADMIN_ERRORS,
  },
});

export const MaintenanceReportSchema = z
  .object({
    audit_rows_purged: z.int(),
    invitations_deleted: z.int(),
    users_repaired: z.int(),
    users_dropped: z.int(),
    users_deleted: z.int(),
    keys: z.object({
      created: z.string().nullable(),
      retired: z.array(z.string()),
      deleted: z.int(),
    }),
    rekeyed: z.object({
      signing_keys: z.int(),
      upstreams: z.int(),
      unrecoverable: z.int(),
      remaining: z.int(),
    }),
    skipped: z.array(z.string()),
    duration_ms: z.int(),
  })
  .openapi("MaintenanceReport");

export const adminMaintenancePurgeRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/maintenance/purge",
  tags: ["admin"],
  summary: "Run the cron body once, bounded (§12.4)",
  security: adminSecurity,
  responses: {
    200: {
      description: "What the run did",
      content: { "application/json": { schema: MaintenanceReportSchema } },
    },
    ...ADMIN_ERRORS,
  },
});

export const RekeyReportSchema = z
  .object({
    signing_keys: z.array(z.string()),
    upstreams: z.int(),
    unrecoverable: z.int(),
    remaining: z.int(),
  })
  .openapi("RekeyReport");

export const adminMaintenanceRekeyRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/maintenance/rekey",
  tags: ["admin"],
  summary: "Re-encrypt one chunk of keystore rows under the active master key (TIO-CRYPTO-011)",
  security: adminSecurity,
  responses: {
    200: {
      description: "What was re-encrypted",
      content: { "application/json": { schema: RekeyReportSchema } },
    },
    ...ADMIN_ERRORS,
  },
});

export const ReindexBodySchema = z
  .object({ cursor: z.string().optional() })
  .strict()
  .openapi("ReindexBody");

export const ReindexBatchSchema = z
  .object({
    processed: z.int(),
    failed: z.array(z.string()),
    next_cursor: z.string().nullable(),
  })
  .openapi("ReindexBatch");

export const adminMaintenanceReindexRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/maintenance/reindex",
  tags: ["admin"],
  summary:
    "Rebuild the D1 mirror of 100 users per call, in id order, resumable by cursor (TIO-DATA-027)",
  security: adminSecurity,
  request: { body: jsonBody(ReindexBodySchema) },
  responses: {
    200: {
      description: "The batch",
      content: { "application/json": { schema: ReindexBatchSchema } },
    },
    400: errorResponse("invalid_request"),
    ...ADMIN_ERRORS,
  },
});

export const ADMIN_SYSTEM_ROUTES = [
  adminKeysListRoute,
  adminKeysRotateRoute,
  adminKeyDeleteRoute,
  adminSettingsGetRoute,
  adminSettingsPatchRoute,
  adminStatsRoute,
  adminMaintenancePurgeRoute,
  adminMaintenanceRekeyRoute,
  adminMaintenanceReindexRoute,
] as const;

// Bulk import (§9.4 Import, TIO-ADMIN-020)

export const ImportResultSchema = z
  .object({
    line: z.int(),
    status: z.enum(["created", "unchanged", "conflict", "error"]),
    id: z.uuid().optional(),
    invitation_url: z.string().nullable().optional(),
    error: z.string().optional(),
  })
  .openapi("ImportResult");

export const adminImportUsersRoute = createRoute({
  method: "post",
  path: "/api/v1/admin/import/users",
  tags: ["admin"],
  summary:
    "Import users from NDJSON (≤ 1,000 lines, ≤ 8 MB): one result line per input line, in order; idempotent per line, 50 creations in flight",
  security: adminSecurity,
  request: {
    body: {
      required: true,
      content: {
        "application/x-ndjson": {
          schema: z.string().openapi({
            description:
              "One JSON object per line: { id?, email?, email_verified?, display_name?, groups?, identities?: [{issuer, subject, email?, email_verified?}], disabled?, created_at?, create_invitation?, invitation_expires_in? }",
          }),
        },
      },
    },
  },
  responses: {
    200: {
      description: "One ImportResult per line, as NDJSON",
      content: { "application/x-ndjson": { schema: ImportResultSchema } },
    },
    400: errorResponse("invalid_request"),
    413: errorResponse("payload_too_large"),
    ...ADMIN_ERRORS,
  },
});

// Self-service API (§8)

const ME_ERRORS = {
  401: errorResponse("invalid_token"),
  403: errorResponse("insufficient_scope"),
  429: errorResponse("rate_limited"),
  503: errorResponse("temporarily_unavailable"),
};
const meSecurity = [{ accountToken: [] }];

export const MeProfileSchema = z
  .object({
    id: z.string(),
    email: z.string().nullable(),
    email_verified: z.boolean(),
    display_name: z.string().nullable(),
    groups: z.array(z.string()),
    created_at: z.int(),
    updated_at: z.int(),
  })
  .openapi("MeProfile");

export const MeProfilePatchSchema = z
  .object({
    display_name: z.string().min(1).max(128).optional(),
    email: z.string().min(3).max(254).optional().openapi({
      description: "Only under the me.allow_email_change setting; verification is reset",
    }),
  })
  .strict()
  .openapi("MeProfilePatch");

export const MePasskeySchema = AdminPasskeySchema.openapi("MePasskey");

export const MePasskeyRegisterSchema = z
  .object({
    response: z
      .looseObject({})
      .openapi({ description: "RegistrationResponseJSON from the browser" }),
    name: z.string().max(256).optional(),
  })
  .strict()
  .openapi("MePasskeyRegister");

export const MePasskeyRenameSchema = z
  .object({ name: z.string().max(256) })
  .strict()
  .openapi("MePasskeyRename");

export const MeSessionSchema = z
  .object({
    sid: z.string(),
    created_at: z.int(),
    last_seen_at: z.int(),
    auth_time: z.int(),
    amr: z.array(z.string()),
    upstream: z.string().nullable(),
    country: z.string().nullable(),
    ua_family: z.string().nullable(),
    current: z.boolean(),
    clients: z.array(z.string()),
  })
  .openapi("MeSession");

export const MeIdentitySchema = z
  .object({
    id: z.string(),
    upstream: z.string().nullable(),
    issuer: z.string(),
    email: z.string().nullable(),
    name: z.string().nullable(),
    created_at: z.int(),
    last_login_at: z.int().nullable(),
  })
  .openapi("MeIdentity");

export const MeGrantSchema = AdminGrantSchema.openapi("MeGrant");

const meList = (description: string, schema: z.ZodType) => ({
  200: {
    description,
    content: { "application/json": { schema: z.object({ items: z.array(schema) }) } },
  },
  ...ME_ERRORS,
});

export const meGetRoute = createRoute({
  method: "get",
  path: "/api/v1/me",
  tags: ["me"],
  summary: "The signed-in person's profile (§8)",
  security: meSecurity,
  responses: {
    200: { description: "Profile", content: { "application/json": { schema: MeProfileSchema } } },
    ...ME_ERRORS,
  },
});

export const mePatchRoute = createRoute({
  method: "patch",
  path: "/api/v1/me",
  tags: ["me"],
  summary: "Update display_name, and email when allowed (§8)",
  security: meSecurity,
  request: { body: jsonBody(MeProfilePatchSchema) },
  responses: {
    200: { description: "Profile", content: { "application/json": { schema: MeProfileSchema } } },
    400: errorResponse("invalid_request or email_invalid"),
    ...ME_ERRORS,
    403: errorResponse("insufficient_scope or email_change_not_allowed"),
  },
});

export const mePasskeysListRoute = createRoute({
  method: "get",
  path: "/api/v1/me/passkeys",
  tags: ["me"],
  summary: "The person's passkeys (§8)",
  security: meSecurity,
  responses: meList("Passkeys", MePasskeySchema),
});

export const mePasskeyOptionsRoute = createRoute({
  method: "post",
  path: "/api/v1/me/passkeys/options",
  tags: ["me"],
  summary: "Registration options for a new passkey (§8, TIO-ME-003)",
  security: meSecurity,
  responses: {
    200: {
      description: "Options",
      content: {
        "application/json": {
          schema: z.object({
            publicKey: z.looseObject({}).openapi({
              description:
                "PublicKeyCredentialCreationOptionsJSON for navigator.credentials.create()",
            }),
          }),
        },
      },
    },
    ...ME_ERRORS,
    403: errorResponse("insufficient_scope or reauthentication_required"),
  },
});

export const mePasskeyRegisterRoute = createRoute({
  method: "post",
  path: "/api/v1/me/passkeys",
  tags: ["me"],
  summary: "Register a passkey (§8, TIO-ME-003)",
  security: meSecurity,
  request: { body: jsonBody(MePasskeyRegisterSchema) },
  responses: {
    201: {
      description: "Registered",
      content: { "application/json": { schema: MePasskeySchema } },
    },
    400: errorResponse("invalid_request or passkey_not_discoverable"),
    ...ME_ERRORS,
    401: errorResponse("invalid_token or passkey_verification_failed"),
    403: errorResponse("insufficient_scope, reauthentication_required or passkey_limit_reached"),
  },
});

const PasskeyIdParams = z.object({ id: z.uuid().openapi({ description: "Passkey id" }) });

export const mePasskeyRenameRoute = createRoute({
  method: "patch",
  path: "/api/v1/me/passkeys/{id}",
  tags: ["me"],
  summary: "Rename a passkey (TIO-PK-041)",
  security: meSecurity,
  request: { params: PasskeyIdParams, body: jsonBody(MePasskeyRenameSchema) },
  responses: {
    204: { description: "Renamed" },
    400: errorResponse("invalid_request"),
    404: errorResponse("not_found"),
    ...ME_ERRORS,
  },
});

export const mePasskeyDeleteRoute = createRoute({
  method: "delete",
  path: "/api/v1/me/passkeys/{id}",
  tags: ["me"],
  summary: "Delete a passkey; the last way to sign in stays (TIO-PK-040)",
  security: meSecurity,
  request: { params: PasskeyIdParams },
  responses: {
    204: { description: "Deleted" },
    404: errorResponse("not_found"),
    409: errorResponse("last_login_method"),
    ...ME_ERRORS,
  },
});

export const meSessionsListRoute = createRoute({
  method: "get",
  path: "/api/v1/me/sessions",
  tags: ["me"],
  summary: "The person's live sessions, the token's own flagged current (§8)",
  security: meSecurity,
  responses: meList("Sessions", MeSessionSchema),
});

export const meSessionDeleteRoute = createRoute({
  method: "delete",
  path: "/api/v1/me/sessions/{sid}",
  tags: ["me"],
  summary: "End one session; its clients receive back-channel logout (TIO-LOGOUT-013)",
  security: meSecurity,
  request: { params: z.object({ sid: z.string().min(1) }) },
  responses: {
    204: { description: "Ended" },
    404: errorResponse("not_found"),
    ...ME_ERRORS,
  },
});

export const meSessionsDeleteRoute = createRoute({
  method: "delete",
  path: "/api/v1/me/sessions",
  tags: ["me"],
  summary: "End every other session (include_current=true ends this one too)",
  security: meSecurity,
  request: { query: z.object({ include_current: z.enum(["true", "false"]).optional() }) },
  responses: {
    200: {
      description: "How many ended",
      content: { "application/json": { schema: z.object({ revoked: z.int() }) } },
    },
    ...ME_ERRORS,
  },
});

export const meIdentitiesListRoute = createRoute({
  method: "get",
  path: "/api/v1/me/identities",
  tags: ["me"],
  summary: "Linked identities, never the upstream subject (§8)",
  security: meSecurity,
  responses: meList("Identities", MeIdentitySchema),
});

export const meIdentityDeleteRoute = createRoute({
  method: "delete",
  path: "/api/v1/me/identities/{id}",
  tags: ["me"],
  summary: "Unlink an identity; the last way to sign in stays (TIO-FED-051)",
  security: meSecurity,
  request: { params: z.object({ id: z.uuid() }) },
  responses: {
    204: { description: "Unlinked" },
    404: errorResponse("not_found"),
    409: errorResponse("last_login_method"),
    ...ME_ERRORS,
  },
});

export const meGrantsListRoute = createRoute({
  method: "get",
  path: "/api/v1/me/grants",
  tags: ["me"],
  summary: "Consent grants per client (§8)",
  security: meSecurity,
  responses: meList("Grants", MeGrantSchema),
});

export const meGrantDeleteRoute = createRoute({
  method: "delete",
  path: "/api/v1/me/grants/{client_id}",
  tags: ["me"],
  summary: "Revoke a grant and the client's refresh families (TIO-CONSENT-004)",
  security: meSecurity,
  request: { params: z.object({ client_id: z.string().min(1) }) },
  responses: {
    204: { description: "Revoked" },
    404: errorResponse("not_found"),
    ...ME_ERRORS,
  },
});

export const meEventsRoute = createRoute({
  method: "get",
  path: "/api/v1/me/events",
  tags: ["me"],
  summary:
    "The person's own events from audit_hot, newest first, within the hot retention window (§8)",
  security: meSecurity,
  request: { query: EventsQuerySchema },
  responses: {
    200: {
      description: "A page",
      content: {
        "application/json": { schema: pageSchema(PersonalEventSchema, "PersonalEventPage") },
      },
    },
    400: errorResponse("invalid_request"),
    ...ME_ERRORS,
  },
});

export const ME_ROUTES = [
  meGetRoute,
  mePatchRoute,
  mePasskeysListRoute,
  mePasskeyOptionsRoute,
  mePasskeyRegisterRoute,
  mePasskeyRenameRoute,
  mePasskeyDeleteRoute,
  meSessionsListRoute,
  meSessionDeleteRoute,
  meSessionsDeleteRoute,
  meIdentitiesListRoute,
  meIdentityDeleteRoute,
  meGrantsListRoute,
  meGrantDeleteRoute,
  meEventsRoute,
] as const;

// Admin audit (§9.4 Audit, §11.3)

export const AuditActorSchema = z
  .object({
    kind: z.enum(["user", "client", "admin", "system", "anonymous"]),
    id: z.string().nullable(),
  })
  .openapi("AuditActor");

export const AuditEventSchema = z
  .object({
    id: z.string(),
    ts: z.int(),
    type: z.string(),
    outcome: z.enum(["success", "failure"]),
    actor: AuditActorSchema,
    user_id: z.string().nullable(),
    client_id: z.string().nullable(),
    upstream: z.string().nullable(),
    sid: z.string().nullable(),
    interaction_id: z.string().nullable(),
    ip_hash: z.string().nullable(),
    country: z.string().nullable(),
    ua_family: z.string().nullable(),
    request_id: z.string(),
    reason: z.string().nullable(),
    data: z.record(z.string(), z.unknown()),
  })
  .openapi("AuditEvent");

export const AdminAuditQuerySchema = z
  .object({
    limit: z.string().optional().openapi({ description: "1..200, default 50" }),
    cursor: z.string().optional().openapi({ description: "Opaque; from next_cursor" }),
    type: z.string().optional(),
    user_id: z.string().optional(),
    client_id: z.string().optional(),
    actor_id: z.string().optional(),
    outcome: z.enum(["success", "failure"]).optional(),
    since: z.string().optional().openapi({ description: "Unix seconds, inclusive" }),
    until: z.string().optional().openapi({ description: "Unix seconds, inclusive" }),
  })
  .strict();

export const adminAuditListRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/audit",
  tags: ["admin"],
  summary: "Audit events from the hot table, newest first, under filters (§9.4)",
  security: adminSecurity,
  request: { query: AdminAuditQuerySchema },
  responses: {
    200: {
      description: "A page",
      content: { "application/json": { schema: pageSchema(AuditEventSchema, "AuditEventPage") } },
    },
    400: errorResponse("invalid_request"),
    ...ADMIN_ERRORS,
  },
});

export const ArchiveObjectSchema = z
  .object({ key: z.string(), size: z.int(), uploaded: z.int() })
  .openapi("ArchiveObject");

export const adminAuditArchiveRoute = createRoute({
  method: "get",
  path: "/api/v1/admin/audit/archive",
  tags: ["admin"],
  summary: "The R2 archive's object keys for a range of days, at most 31 (§9.4)",
  security: adminSecurity,
  request: {
    query: z
      .object({
        from: z.string().openapi({ description: "YYYY-MM-DD (UTC)" }),
        to: z.string().optional().openapi({ description: "YYYY-MM-DD (UTC), defaults to from" }),
      })
      .strict(),
  },
  responses: {
    200: {
      description: "Keys only; the operator downloads with R2 tooling",
      content: {
        "application/json": {
          schema: z
            .object({ items: z.array(ArchiveObjectSchema), from: z.string(), to: z.string() })
            .openapi("ArchiveListing"),
        },
      },
    },
    400: errorResponse("invalid_request"),
    ...ADMIN_ERRORS,
  },
});

export const ADMIN_AUDIT_ROUTES = [adminAuditListRoute, adminAuditArchiveRoute] as const;

/** Every OpenAPI route, in document order. */
export const API_ROUTES = [
  healthRoute,
  interactionGetRoute,
  interactionPasskeyOptionsRoute,
  interactionPasskeyVerifyRoute,
  interactionRegisterOptionsRoute,
  interactionRegisterVerifyRoute,
  interactionUpstreamRoute,
  interactionConsentRoute,
  interactionAbortRoute,
  interactionLogoutRoute,
  ...ME_ROUTES,
  adminBootstrapRoute,
  ...ADMIN_USER_ROUTES,
  ...ADMIN_GROUP_ROUTES,
  ...ADMIN_CLIENT_ROUTES,
  ...ADMIN_UPSTREAM_ROUTES,
  ...ADMIN_INVITATION_ROUTES,
  ...ADMIN_SYSTEM_ROUTES,
  adminImportUsersRoute,
  ...ADMIN_AUDIT_ROUTES,
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
  app.openAPIRegistry.registerComponent("securitySchemes", "accountToken", {
    type: "http",
    scheme: "bearer",
    bearerFormat: "at+jwt",
    description: "A user's access token with scope account and the issuer in aud (§8)",
  });
}

/** The OpenAPI 3.1 document built from the definitions alone (no handlers, no bindings). */
export function openApiDocument(): Record<string, unknown> {
  const app = new OpenAPIHono();
  registerApi(app);
  return app.getOpenAPI31Document(API_INFO) as unknown as Record<string, unknown>;
}
