import { z } from "zod";
import { DiscoverySchema, type Upstream } from "../federation/upstreams.ts";
import { parseJson } from "../util/json.ts";
import type { Db } from "./db.ts";

// Repository for the D1 `upstreams` table (spec §4.1): the configured
// providers, secrets sealed under the keystore key (§10.2).

interface RawUpstreamRow extends Record<string, unknown> {
  alias: string;
  issuer: string;
  display_name: string;
  client_id: string;
  token_endpoint_auth_method: Upstream["token_endpoint_auth_method"];
  client_secret_enc: ArrayBuffer | null;
  client_jwk_enc: ArrayBuffer | null;
  scopes: string;
  discovery: string;
  use_userinfo: number;
  trust_email_verified: number;
  claims_map: string;
  required_claims: string;
  extra_authorize_params: string;
  forward_login_hint: number;
  enabled: number;
  created_at: number;
  updated_at: number;
}

const ClaimsMap = z.object({
  email: z.string().optional(),
  email_verified: z.string().optional(),
  name: z.string().optional(),
});
const Scalars = z.record(z.string(), z.union([z.string(), z.number(), z.boolean()]));
const Strings = z.record(z.string(), z.string());

const COLUMNS =
  "alias, issuer, display_name, client_id, token_endpoint_auth_method, client_secret_enc, client_jwk_enc, scopes, discovery, use_userinfo, trust_email_verified, claims_map, required_claims, extra_authorize_params, forward_login_hint, enabled, created_at, updated_at";

/** Decodes a row; null when a JSON column no longer parses (treated as absent, like clients). */
export function decodeUpstreamRow(raw: RawUpstreamRow): Upstream | null {
  const discovery = parseJson(DiscoverySchema, raw.discovery);
  const claimsMap = parseJson(ClaimsMap, raw.claims_map);
  const required = parseJson(Scalars, raw.required_claims);
  const extra = parseJson(Strings, raw.extra_authorize_params);
  if (!discovery.ok || !claimsMap.ok || !required.ok || !extra.ok) return null;
  return {
    alias: raw.alias,
    issuer: raw.issuer,
    display_name: raw.display_name,
    client_id: raw.client_id,
    token_endpoint_auth_method: raw.token_endpoint_auth_method,
    client_secret_enc:
      raw.client_secret_enc === null ? null : new Uint8Array(raw.client_secret_enc),
    client_jwk_enc: raw.client_jwk_enc === null ? null : new Uint8Array(raw.client_jwk_enc),
    scopes: raw.scopes,
    discovery: discovery.value,
    use_userinfo: raw.use_userinfo === 1,
    trust_email_verified: raw.trust_email_verified === 1,
    claims_map: claimsMap.value,
    required_claims: required.value,
    extra_authorize_params: extra.value,
    forward_login_hint: raw.forward_login_hint === 1,
    enabled: raw.enabled === 1,
    created_at: raw.created_at,
    updated_at: raw.updated_at,
  };
}

export async function getUpstream(db: Db, alias: string): Promise<Upstream | null> {
  const raw = await db
    .prepare(["SELECT", COLUMNS, "FROM upstreams WHERE alias = ?"].join(" "))
    .bind(alias)
    .first<RawUpstreamRow>();
  return raw === null ? null : decodeUpstreamRow(raw);
}

export type InsertUpstreamResult = "created" | "upstream_exists";

/** Inserts the record; the alias and the issuer are both unique (`upstream_exists`). */
export async function insertUpstream(db: Db, upstream: Upstream): Promise<InsertUpstreamResult> {
  try {
    await db
      .prepare(
        "INSERT INTO upstreams (alias, issuer, display_name, client_id, token_endpoint_auth_method, client_secret_enc, client_jwk_enc, scopes, discovery, use_userinfo, trust_email_verified, claims_map, required_claims, extra_authorize_params, forward_login_hint, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(...columnValues(upstream), upstream.created_at, upstream.updated_at)
      .run();
  } catch (error) {
    if (String(error).includes("UNIQUE")) return "upstream_exists";
    throw error;
  }
  return "created";
}

export type UpdateUpstreamResult = "changed" | "not_found" | "upstream_exists";

/** Rewrites every mutable column; the alias and `created_at` stay. */
export async function updateUpstream(
  db: Db,
  upstream: Upstream,
  now: number,
): Promise<UpdateUpstreamResult> {
  try {
    const result = await db
      .prepare(
        "UPDATE upstreams SET issuer = ?, display_name = ?, client_id = ?, token_endpoint_auth_method = ?, client_secret_enc = ?, client_jwk_enc = ?, scopes = ?, discovery = ?, use_userinfo = ?, trust_email_verified = ?, claims_map = ?, required_claims = ?, extra_authorize_params = ?, forward_login_hint = ?, enabled = ?, updated_at = ? WHERE alias = ?",
      )
      .bind(...columnValues(upstream).slice(1), now, upstream.alias)
      .run();
    return result.meta.changes === 1 ? "changed" : "not_found";
  } catch (error) {
    if (String(error).includes("UNIQUE")) return "upstream_exists";
    throw error;
  }
}

export async function deleteUpstream(db: Db, alias: string): Promise<boolean> {
  const result = await db.prepare("DELETE FROM upstreams WHERE alias = ?").bind(alias).run();
  return result.meta.changes === 1;
}

export interface UpstreamKeyset {
  created_at: number;
  id: string;
}

export interface ListedUpstream {
  keyset: UpstreamKeyset;
  /** Null for a row that no longer decodes; it still counts for paging. */
  upstream: Upstream | null;
}

/** The keyset query behind `GET /admin/upstreams`, walking `upstreams_created`. */
export async function listUpstreamsPage(
  db: Db,
  after: UpstreamKeyset | null,
  limit: number,
): Promise<ListedUpstream[]> {
  const base = ["SELECT", COLUMNS, "FROM upstreams"].join(" ");
  const order = " ORDER BY created_at, alias LIMIT ?";
  const statement =
    after === null
      ? db.prepare(base + order).bind(limit)
      : db
          .prepare(`${base} WHERE (created_at, alias) > (?, ?)${order}`)
          .bind(after.created_at, after.id, limit);
  const rows = await statement.all<RawUpstreamRow>();
  return rows.results.map((row) => ({
    keyset: { created_at: row.created_at, id: row.alias },
    upstream: decodeUpstreamRow(row),
  }));
}

/** Every enabled upstream, for the login app's method list (§7.3) and the outbound request. */
export async function listEnabledUpstreams(db: Db): Promise<Upstream[]> {
  const rows = await db
    .prepare(
      ["SELECT", COLUMNS, "FROM upstreams WHERE enabled = 1 ORDER BY created_at, alias"].join(" "),
    )
    .all<RawUpstreamRow>();
  return rows.results.map(decodeUpstreamRow).filter((u) => u !== null);
}

/** Every upstream's alias and issuer, enabled or not (the Self-service identities listing names the alias). */
export async function listUpstreamAliases(db: Db): Promise<{ alias: string; issuer: string }[]> {
  const rows = await db
    .prepare("SELECT alias, issuer FROM upstreams ORDER BY alias")
    .all<{ alias: string; issuer: string }>();
  return rows.results;
}

/** The bound values of every column from `alias` to `enabled`, in table order. */
function columnValues(upstream: Upstream): unknown[] {
  return [
    upstream.alias,
    upstream.issuer,
    upstream.display_name,
    upstream.client_id,
    upstream.token_endpoint_auth_method,
    upstream.client_secret_enc,
    upstream.client_jwk_enc,
    upstream.scopes,
    JSON.stringify(upstream.discovery),
    upstream.use_userinfo ? 1 : 0,
    upstream.trust_email_verified ? 1 : 0,
    JSON.stringify(upstream.claims_map),
    JSON.stringify(upstream.required_claims),
    JSON.stringify(upstream.extra_authorize_params),
    upstream.forward_login_hint ? 1 : 0,
    upstream.enabled ? 1 : 0,
  ];
}

export async function countUpstreams(db: Db): Promise<number> {
  const row = await db.prepare("SELECT COUNT(*) AS n FROM upstreams").first<{ n: number }>();
  return (row as { n: number }).n;
}

/** Every upstream with sealed material, for re-encryption under the active master key (TIO-CRYPTO-011). */
export async function listSealedUpstreams(db: Db): Promise<Upstream[]> {
  const rows = await db
    .prepare(
      [
        "SELECT",
        COLUMNS,
        "FROM upstreams WHERE client_secret_enc IS NOT NULL OR client_jwk_enc IS NOT NULL ORDER BY alias",
      ].join(" "),
    )
    .all<RawUpstreamRow>();
  return rows.results.map(decodeUpstreamRow).filter((u) => u !== null);
}

/** Rewrites the sealed material of one upstream (rekey). */
export async function updateUpstreamSecrets(
  db: Db,
  alias: string,
  secretEnc: Uint8Array | null,
  jwkEnc: Uint8Array | null,
): Promise<void> {
  await db
    .prepare("UPDATE upstreams SET client_secret_enc = ?, client_jwk_enc = ? WHERE alias = ?")
    .bind(secretEnc, jwkEnc, alias)
    .run();
}
