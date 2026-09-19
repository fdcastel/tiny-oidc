import { z } from "zod";
import { CAPABILITIES } from "../oidc/capabilities.ts";
import { type Client, JwksSchema } from "../oidc/clients.ts";
import { parseJson } from "../util/json.ts";
import type { Db } from "./db.ts";

// Repository for the D1 `clients` table (spec §4.1). JSON columns are decoded
// through schemas so a corrupt row reads as absent rather than crashing.

interface RawClientRow extends Record<string, unknown> {
  client_id: string;
  client_name: string;
  client_uri: string | null;
  logo_uri: string | null;
  redirect_uris: string;
  post_logout_redirect_uris: string;
  backchannel_logout_uri: string | null;
  grant_types: string;
  token_endpoint_auth_method: Client["token_endpoint_auth_method"];
  client_secret_hash: ArrayBuffer | null;
  jwks: string | null;
  jwks_uri: string | null;
  scopes_allowed: string;
  audiences: string;
  allowed_groups: string | null;
  skip_consent: number;
  require_par: number;
  offline_access: number;
  access_token_ttl: number | null;
  id_token_ttl: number | null;
  refresh_token_ttl: number | null;
  refresh_idle_ttl: number | null;
  disabled_at: number | null;
  created_at: number;
  updated_at: number;
}

const Strings = z.array(z.string());
const Grants = z.array(z.enum(CAPABILITIES.grant_types_supported));
const Scopes = z.array(z.enum(CAPABILITIES.scopes_supported));

/** Decodes a row; null when a JSON column is corrupt (treated as absent, TIO-DATA-026 style). */
export function decodeClientRow(raw: RawClientRow): Client | null {
  const redirect = parseJson(Strings, raw.redirect_uris);
  const postLogout = parseJson(Strings, raw.post_logout_redirect_uris);
  const grants = parseJson(Grants, raw.grant_types);
  const scopes = parseJson(Scopes, raw.scopes_allowed);
  const audiences = parseJson(Strings, raw.audiences);
  const groups = raw.allowed_groups === null ? null : parseJson(Strings, raw.allowed_groups);
  const jwks = raw.jwks === null ? null : parseJson(JwksSchema, raw.jwks);
  if (
    !redirect.ok ||
    !postLogout.ok ||
    !grants.ok ||
    !scopes.ok ||
    !audiences.ok ||
    (groups !== null && !groups.ok) ||
    (jwks !== null && !jwks.ok)
  ) {
    return null;
  }
  return {
    client_id: raw.client_id,
    client_name: raw.client_name,
    client_uri: raw.client_uri,
    logo_uri: raw.logo_uri,
    redirect_uris: redirect.value,
    post_logout_redirect_uris: postLogout.value,
    backchannel_logout_uri: raw.backchannel_logout_uri,
    grant_types: grants.value,
    token_endpoint_auth_method: raw.token_endpoint_auth_method,
    client_secret_hash:
      raw.client_secret_hash === null ? null : new Uint8Array(raw.client_secret_hash),
    jwks: jwks === null ? null : jwks.value,
    jwks_uri: raw.jwks_uri,
    scopes_allowed: scopes.value,
    audiences: audiences.value,
    allowed_groups: groups === null ? null : groups.value,
    skip_consent: raw.skip_consent === 1,
    require_par: raw.require_par === 1,
    offline_access: raw.offline_access === 1,
    access_token_ttl: raw.access_token_ttl,
    id_token_ttl: raw.id_token_ttl,
    refresh_token_ttl: raw.refresh_token_ttl,
    refresh_idle_ttl: raw.refresh_idle_ttl,
    disabled_at: raw.disabled_at,
    created_at: raw.created_at,
    updated_at: raw.updated_at,
  };
}

export async function getClient(db: Db, clientId: string): Promise<Client | null> {
  const raw = await db
    .prepare(
      "SELECT client_id, client_name, client_uri, logo_uri, redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, grant_types, token_endpoint_auth_method, client_secret_hash, jwks, jwks_uri, scopes_allowed, audiences, allowed_groups, skip_consent, require_par, offline_access, access_token_ttl, id_token_ttl, refresh_token_ttl, refresh_idle_ttl, disabled_at, created_at, updated_at FROM clients WHERE client_id = ?",
    )
    .bind(clientId)
    .first<RawClientRow>();
  return raw === null ? null : decodeClientRow(raw);
}

export type InsertClientResult = "created" | "client_exists";

export async function insertClient(db: Db, client: Client): Promise<InsertClientResult> {
  const existing = await db
    .prepare("SELECT 1 AS present FROM clients WHERE client_id = ?")
    .bind(client.client_id)
    .first();
  if (existing !== null) return "client_exists";
  await db
    .prepare(
      "INSERT INTO clients (client_id, client_name, client_uri, logo_uri, redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, grant_types, token_endpoint_auth_method, client_secret_hash, jwks, jwks_uri, scopes_allowed, audiences, allowed_groups, skip_consent, require_par, offline_access, access_token_ttl, id_token_ttl, refresh_token_ttl, refresh_idle_ttl, disabled_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      client.client_id,
      client.client_name,
      client.client_uri,
      client.logo_uri,
      JSON.stringify(client.redirect_uris),
      JSON.stringify(client.post_logout_redirect_uris),
      client.backchannel_logout_uri,
      JSON.stringify(client.grant_types),
      client.token_endpoint_auth_method,
      client.client_secret_hash,
      client.jwks === null ? null : JSON.stringify(client.jwks),
      client.jwks_uri,
      JSON.stringify(client.scopes_allowed),
      JSON.stringify(client.audiences),
      client.allowed_groups === null ? null : JSON.stringify(client.allowed_groups),
      client.skip_consent ? 1 : 0,
      client.require_par ? 1 : 0,
      client.offline_access ? 1 : 0,
      client.access_token_ttl,
      client.id_token_ttl,
      client.refresh_token_ttl,
      client.refresh_idle_ttl,
      client.disabled_at,
      client.created_at,
      client.updated_at,
    )
    .run();
  return "created";
}

/** Sets or clears `disabled_at` (TIO-CLIENT-004). Returns whether the client exists. */
export async function setClientDisabled(
  db: Db,
  clientId: string,
  disabledAt: number | null,
  now: number,
): Promise<boolean> {
  const result = await db
    .prepare("UPDATE clients SET disabled_at = ?, updated_at = ? WHERE client_id = ?")
    .bind(disabledAt, now, clientId)
    .run();
  return result.meta.changes === 1;
}

export async function updateClientSecretHash(
  db: Db,
  clientId: string,
  hash: Uint8Array,
  now: number,
): Promise<boolean> {
  const result = await db
    .prepare("UPDATE clients SET client_secret_hash = ?, updated_at = ? WHERE client_id = ?")
    .bind(hash, now, clientId)
    .run();
  return result.meta.changes === 1;
}

export async function deleteClient(db: Db, clientId: string): Promise<boolean> {
  const result = await db.prepare("DELETE FROM clients WHERE client_id = ?").bind(clientId).run();
  return result.meta.changes === 1;
}
