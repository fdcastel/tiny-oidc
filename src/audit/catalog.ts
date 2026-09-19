// The audit event catalog (spec §11.2, TIO-AUDIT-001): every type the OP
// emits and the keys its `data` may carry. The emitter drops anything else
// (TIO-AUDIT-002), so a new field is a deliberate decision recorded here.
// `target` and `diff` are what the Admin API adds to every mutation
// (TIO-ADMIN-002); the rest is per type.

const ADMIN = ["target", "diff"] as const;

export const AUDIT_CATALOG = {
  // Users (§4.6, §9.4)
  "user.created": [...ADMIN, "via", "invitation", "identities", "import_line"],
  "user.updated": [...ADMIN, "fields", "bookmark_time"],
  "user.disabled": [...ADMIN, "sessions_revoked", "import_line"],
  "user.enabled": [...ADMIN, "sessions_revoked"],
  "user.deleted": [...ADMIN, "sessions_revoked"],
  "user.reindexed": [...ADMIN, "passkeys", "identities", "groups", "unknown_groups"],
  // The one audited read (ADR 0011): who took a person's whole record, and how much of it.
  "user.exported": [...ADMIN, "passkeys", "identities", "sessions", "refresh_families", "grants"],
  "user.group_added": [...ADMIN, "group"],
  "user.group_removed": [...ADMIN, "group"],
  // Groups (§9.4; not in §11.2, recorded as a spec gap at P3-03)
  "group.created": [...ADMIN],
  "group.updated": [...ADMIN, "propagation"],
  "group.deleted": [...ADMIN, "propagation"],
  // Passkeys (§6.1)
  "passkey.registered": [...ADMIN, "passkey_id", "via"],
  "passkey.renamed": [...ADMIN, "passkey_id"],
  "passkey.deleted": [...ADMIN, "passkey_id"],
  "passkey.auth_succeeded": ["passkey_id"],
  "passkey.auth_failed": ["step"],
  "passkey.clone_suspected": ["passkey_id", "stored", "observed"],
  // Identities (§6.4)
  "identity.linked": [...ADMIN, "issuer", "via"],
  "identity.unlinked": [...ADMIN, "issuer", "identity_id"],
  "identity.login_succeeded": [],
  "identity.login_failed": [],
  // Invitations (§6.3)
  "invitation.created": [...ADMIN, "kind", "groups", "expires_at", "import_line"],
  "invitation.used": ["kind", "via"],
  "invitation.revoked": [...ADMIN, "kind", "used"],
  // Interactions (§7)
  "interaction.created": ["kind", "status"],
  "interaction.failed": ["kind", "error"],
  "interaction.completed": ["kind"],
  // Authorization (§5.4)
  "authz.code_issued": ["scopes", "session_hit"],
  "authz.denied": ["error"],
  // Consent (§6.6)
  "consent.granted": ["scopes"],
  "consent.denied": [],
  "consent.revoked": [...ADMIN, "grant_client_id"],
  // Tokens (§5.6, §5.9)
  "token.issued": ["grant_type", "scopes", "kind"],
  "token.refreshed": ["scopes", "kind"],
  "token.refresh_reuse": ["revoked_session_clients"],
  "token.code_replay": [],
  "token.client_auth_failed": ["method"],
  "token.revoked": [...ADMIN, "family", "families", "hint"],
  "token.revoke_foreign": ["hint"],
  // Sessions (§6.2)
  "session.created": ["amr", "acr", "upstream"],
  "session.rotated": ["amr", "acr", "upstream"],
  "session.revoked": [...ADMIN, "clients"],
  "session.expired": [],
  // Logout (§5.10)
  "logout.rp_initiated": ["registered_redirect"],
  "logout.confirmed": [],
  "logout.backchannel_sent": ["jti"],
  "logout.backchannel_failed": ["jti", "attempts"],
  // Clients (§9)
  "client.created": [...ADMIN],
  "client.updated": [...ADMIN, "secret_issued"],
  "client.secret_rotated": [...ADMIN],
  "client.disabled": [...ADMIN],
  "client.enabled": [...ADMIN],
  "client.deleted": [...ADMIN],
  // Upstreams (§9, §6.4)
  "upstream.created": [...ADMIN],
  "upstream.updated": [...ADMIN, "secret_replaced", "jwk_replaced"],
  "upstream.deleted": [...ADMIN],
  "upstream.discovery_failed": [...ADMIN, "issuer", "step"],
  // Keys (§10)
  "key.created": [...ADMIN, "activates_at", "immediate", "via"],
  "key.retired": [...ADMIN, "emergency", "via"],
  "key.deleted": ["kid", "via"],
  "masterkey.rekeyed": [...ADMIN, "signing_keys", "upstreams", "unrecoverable"],
  // Administration (§9)
  "settings.updated": [...ADMIN, "keys"],
  "admin.bootstrap": ["client_id"],
  "admin.import_batch": [...ADMIN, "lines", "created", "unchanged", "conflict", "error"],
  // Abuse and operations (§6.7, §12)
  "ratelimit.exceeded": ["class"],
  "system.cron_run": [
    "audit_rows_purged",
    "invitations_deleted",
    "users_repaired",
    "users_dropped",
    "users_deleted",
    "keys",
    "rekeyed",
    "skipped",
    "duration_ms",
  ],
  "system.repair": [...ADMIN, "processed", "failed", "more"],
} as const satisfies Record<string, readonly string[]>;

export type AuditType = keyof typeof AUDIT_CATALOG;

export const AUDIT_TYPES = Object.keys(AUDIT_CATALOG) as AuditType[];

export function isAuditType(type: string): type is AuditType {
  return Object.hasOwn(AUDIT_CATALOG, type);
}

/** Keys `data` may carry for a type (none for an unknown type: everything is dropped). */
export function allowedDataKeys(type: string): ReadonlySet<string> {
  return new Set(isAuditType(type) ? AUDIT_CATALOG[type] : []);
}
