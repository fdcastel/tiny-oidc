import { CAPABILITIES, isScope, type Scope } from "./capabilities.ts";
import type { Client } from "./clients.ts";
import { matchRedirectUri } from "./redirect-uri.ts";

// Validation of an authorization request (spec §5.4, steps 5–12), shared by
// `/authorize` and `/par`. Steps 1–4 (method, duplicates, client, PAR,
// `require_par`) are the endpoints' own since their outcomes differ. Errors
// before the redirect URI is trusted are non-redirectable (TIO-AUTHZ-018).

export type PromptValue = "none" | "login" | "consent";

/** The validated parameters, as stored in the interaction (§4.3 `request`). */
export interface AuthorizeRequest {
  redirect_uri: string;
  scope: Scope[];
  state: string;
  nonce: string | null;
  code_challenge: string;
  prompt: PromptValue[];
  max_age: number | null;
  login_hint: string | null;
  ui_locales: string | null;
  acr_values: string[];
}

export type AuthorizeErrorCode =
  | "invalid_request"
  | "unsupported_response_type"
  | "invalid_scope"
  | "unauthorized_client";

export type AuthorizeValidation =
  | { ok: true; request: AuthorizeRequest }
  | { ok: false; redirectable: false; error: "invalid_request"; description: string }
  | {
      ok: false;
      redirectable: true;
      redirect_uri: string;
      /** The request's `state`, echoed only when it is itself valid. */
      state: string | null;
      error: AuthorizeErrorCode;
      description: string;
    };

export const STATE_MAX_LENGTH = 2_048;
export const NONCE_MAX_LENGTH = 512;
export const LOGIN_HINT_MAX_LENGTH = 256;
export const UI_LOCALES_MAX_LENGTH = 64;
export const ACR_VALUES_MAX_LENGTH = 256;
export const MAX_AGE_MAX_DIGITS = 10;

const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;
const CODE_CHALLENGE = /^[A-Za-z0-9._~-]{43,128}$/;
const NON_NEGATIVE_INTEGER = /^(0|[1-9][0-9]*)$/;

function isPrintableState(state: string): boolean {
  return state.length <= STATE_MAX_LENGTH && PRINTABLE_ASCII.test(state);
}

/** Splits a space-delimited list; empty tokens (leading, trailing or doubled spaces) make it invalid. */
function spaceList(value: string): string[] | null {
  const tokens = value.split(" ");
  return tokens.every((t) => t.length > 0) ? tokens : null;
}

/**
 * Runs steps 5–12 of §5.4 over the request parameters. `client` is enabled
 * and may use the authorization code grant (step 2).
 */
export function validateAuthorizeRequest(
  params: ReadonlyMap<string, string>,
  client: Client,
): AuthorizeValidation {
  // 5. redirect_uri (TIO-AUTHZ-005): non-redirectable until it matches.
  const requestedRedirect = params.get("redirect_uri");
  if (requestedRedirect === undefined) {
    return {
      ok: false,
      redirectable: false,
      error: "invalid_request",
      description: "redirect_uri is required",
    };
  }
  if (matchRedirectUri(client.redirect_uris, requestedRedirect) === null) {
    return {
      ok: false,
      redirectable: false,
      error: "invalid_request",
      description: "redirect_uri is not registered",
    };
  }
  // Redirected to the client from here on; the loopback exception keeps the requested port.
  const target = requestedRedirect;
  const rawState = params.get("state");
  const state = rawState !== undefined && isPrintableState(rawState) ? rawState : null;
  const reject = (error: AuthorizeErrorCode, description: string): AuthorizeValidation => ({
    ok: false,
    redirectable: true,
    redirect_uri: target,
    state,
    error,
    description,
  });

  // 6. response_type (TIO-AUTHZ-006).
  if (params.get("response_type") !== CAPABILITIES.response_types_supported[0]) {
    return reject("unsupported_response_type", "response_type must be code");
  }
  // 7. state (TIO-AUTHZ-007).
  if (rawState === undefined || rawState.length === 0 || state === null) {
    return reject("invalid_request", "state is required: 1-2048 printable ASCII characters");
  }
  // 8. PKCE (TIO-AUTHZ-008).
  const code_challenge = params.get("code_challenge") ?? "";
  if (!CODE_CHALLENGE.test(code_challenge)) {
    return reject(
      "invalid_request",
      "code_challenge is required: 43-128 characters of [A-Za-z0-9._~-]",
    );
  }
  if (params.get("code_challenge_method") !== CAPABILITIES.code_challenge_methods_supported[0]) {
    return reject("invalid_request", "code_challenge_method must be S256");
  }
  // 9. scope (TIO-AUTHZ-009, TIO-SCOPE-001).
  const scopeParam = params.get("scope");
  const scopes = scopeParam === undefined ? null : spaceList(scopeParam);
  if (scopes === null) return reject("invalid_scope", "scope is required");
  if (!scopes.every(isScope)) return reject("invalid_scope", "scope contains an unknown value");
  const scope = scopes as Scope[];
  if (!scope.includes("openid")) return reject("invalid_scope", "scope must include openid");
  if (new Set(scope).size !== scope.length)
    return reject("invalid_scope", "scope contains duplicates");
  if (!scope.every((s) => client.scopes_allowed.includes(s))) {
    return reject("invalid_scope", "scope is not allowed for this client");
  }
  // TIO-TOKEN-014: offline_access needs the client flag, not only the scope allowance.
  if (scope.includes("offline_access") && !client.offline_access) {
    return reject("invalid_scope", "offline_access is not enabled for this client");
  }
  // 10. Free-form parameters passed through to the login app (TIO-AUTHZ-010).
  const nonce = params.get("nonce") ?? null;
  if (nonce !== null && (nonce.length === 0 || nonce.length > NONCE_MAX_LENGTH)) {
    return reject("invalid_request", "nonce must be 1-512 characters");
  }
  const login_hint = params.get("login_hint") ?? null;
  if (login_hint !== null && login_hint.length > LOGIN_HINT_MAX_LENGTH) {
    return reject("invalid_request", "login_hint exceeds 256 characters");
  }
  const ui_locales = params.get("ui_locales") ?? null;
  if (ui_locales !== null && ui_locales.length > UI_LOCALES_MAX_LENGTH) {
    return reject("invalid_request", "ui_locales exceeds 64 characters");
  }
  const acrParam = params.get("acr_values") ?? null;
  if (acrParam !== null && acrParam.length > ACR_VALUES_MAX_LENGTH) {
    return reject("invalid_request", "acr_values exceeds 256 characters");
  }
  const acr_values = acrParam === null ? [] : acrParam.split(" ").filter((v) => v.length > 0);
  // 11. prompt (TIO-AUTHZ-011).
  const promptParam = params.get("prompt");
  let prompt: PromptValue[] = [];
  if (promptParam !== undefined) {
    const values = spaceList(promptParam);
    const supported: readonly string[] = CAPABILITIES.prompt_values_supported;
    if (values === null || !values.every((v) => supported.includes(v))) {
      return reject("invalid_request", "prompt contains an unknown value");
    }
    if (new Set(values).size !== values.length)
      return reject("invalid_request", "prompt contains duplicates");
    if (values.includes("none") && values.length > 1) {
      return reject("invalid_request", "prompt=none cannot be combined with other values");
    }
    prompt = [
      ...new Set(values.map((v) => (v === "select_account" ? "login" : v))),
    ] as PromptValue[];
  }
  // 12. max_age (TIO-AUTHZ-012).
  const maxAgeParam = params.get("max_age");
  let max_age: number | null = null;
  if (maxAgeParam !== undefined) {
    if (!NON_NEGATIVE_INTEGER.test(maxAgeParam) || maxAgeParam.length > MAX_AGE_MAX_DIGITS) {
      return reject("invalid_request", "max_age must be a non-negative integer");
    }
    max_age = Number(maxAgeParam);
  }
  // 13. (withdrawn) `resource` and every other unrecognized parameter is ignored.
  return {
    ok: true,
    request: {
      redirect_uri: target,
      scope,
      state,
      nonce,
      code_challenge,
      prompt,
      max_age,
      login_hint,
      ui_locales,
      acr_values,
    },
  };
}
