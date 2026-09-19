import { exportJWK, importJWK, type JWK, jwtVerify, SignJWT } from "jose";

// A minimal OIDC provider for tests and staging (spec TIO-TEST-031): discovery,
// an authorization endpoint that approves every request, a token endpoint with
// the three client authentication methods and PKCE, a JWKS and a userinfo
// endpoint. Faults are injected through query flags on the authorization
// request (carried by the code into the token and userinfo responses) or the
// `x-fake-upstream-fault` control header. Pure: `handle(Request)` touches no
// storage beyond its own memory and imports nothing from the OP.

export type Fault =
  | "bad_iss"
  | "bad_aud"
  | "multi_aud_bad_azp"
  | "multi_aud"
  | "bad_nonce"
  | "expired"
  | "future_iat"
  | "old_iat"
  | "unknown_kid"
  | "alg_none"
  | "no_sub"
  | "long_sub"
  | "string_email_verified"
  | "malformed_token_json"
  | "token_error"
  | "token_500"
  | "userinfo_mismatch"
  | "userinfo_malformed"
  | "userinfo_500"
  | "userinfo_string_email_verified"
  | "authorize_error"
  | "slow_token"
  | "slow_userinfo"
  | "slow_discovery"
  | "discovery_500";

export const FAULTS: readonly Fault[] = [
  "bad_iss",
  "bad_aud",
  "multi_aud_bad_azp",
  "multi_aud",
  "bad_nonce",
  "expired",
  "future_iat",
  "old_iat",
  "unknown_kid",
  "alg_none",
  "no_sub",
  "long_sub",
  "string_email_verified",
  "malformed_token_json",
  "token_error",
  "token_500",
  "userinfo_mismatch",
  "userinfo_malformed",
  "userinfo_500",
  "userinfo_string_email_verified",
  "authorize_error",
  "slow_token",
  "slow_userinfo",
  "slow_discovery",
  "discovery_500",
];

export const FAULT_HEADER = "x-fake-upstream-fault";
/** How long the slow_* faults hold a response, in ms. */
export const SLOW_MS = 150;

export interface FakeUpstreamOptions {
  issuer: string;
  /** Registered relying-party client: id, secret for the secret methods, public JWK for private_key_jwt. */
  client_id: string;
  client_secret?: string;
  client_jwk?: JWK;
  /** The redirect URIs the authorization endpoint accepts. */
  redirect_uris: string[];
  /** The clock the fake stamps tokens with (seconds); defaults to real time. */
  now?: () => number;
}

interface Person {
  sub: string;
  email: string | null;
  email_verified: boolean;
  name: string | null;
  /** Extra claims to merge into the ID token (for required_claims tests). */
  extra: Record<string, unknown>;
}

interface IssuedCode {
  client_id: string;
  redirect_uri: string;
  nonce: string | null;
  code_challenge: string | null;
  person: Person;
  faults: Set<Fault>;
  scope: string;
}

interface Key {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

const encoder = new TextEncoder();

function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(text: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text))));
}

function randomToken(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(24)));
}

async function generateKey(kid: string): Promise<Key> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicJwk = { ...(await exportJWK(pair.publicKey)), kid, alg: "ES256", use: "sig" };
  return { kid, privateKey: pair.privateKey, publicJwk };
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export class FakeUpstream {
  readonly options: FakeUpstreamOptions;
  private readonly codes = new Map<string, IssuedCode>();
  private readonly accessTokens = new Map<string, IssuedCode>();
  private readonly keys: Key[];
  /** Every request seen, oldest first (the outbound allow-list test reads it). */
  readonly requests: { method: string; path: string }[] = [];
  /** A person's claims by subject; the authorization request picks one with `x_sub`. */
  readonly people = new Map<string, Person>();
  /** While set, the discovery document answers 503 (the OP's cache is what keeps logins working). */
  discoveryDown = false;
  /** While set, the discovery document names no userinfo endpoint. */
  withoutUserinfo = false;

  private constructor(options: FakeUpstreamOptions, keys: Key[]) {
    this.options = options;
    this.keys = keys;
  }

  static async create(options: FakeUpstreamOptions): Promise<FakeUpstream> {
    return new FakeUpstream(options, [await generateKey("fake-1"), await generateKey("fake-2")]);
  }

  private get now(): number {
    return this.options.now?.() ?? Math.floor(Date.now() / 1000);
  }

  private get signing(): Key {
    return this.keys[0] as Key;
  }

  /** Rotates the signing key: the JWKS publishes only the new key from now on. */
  rotate(): void {
    this.keys.push(this.keys.shift() as Key);
  }

  /** Registers a person the authorization endpoint can act as (`x_sub=<sub>`); returns the sub. */
  person(input: Partial<Person> & { sub: string }): string {
    this.people.set(input.sub, {
      sub: input.sub,
      email: input.email ?? null,
      email_verified: input.email_verified ?? false,
      name: input.name ?? null,
      extra: input.extra ?? {},
    });
    return input.sub;
  }

  get discovery(): Record<string, unknown> {
    const issuer = this.options.issuer;
    return {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      userinfo_endpoint: `${issuer}/userinfo`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
      ],
      code_challenge_methods_supported: ["S256"],
    };
  }

  /** The faults named on the request; an unknown name is a mistake in the test, not a silent no-op. */
  private faultsOf(request: Request, url: URL): Set<Fault> {
    const faults = new Set<Fault>();
    const header = request.headers.get(FAULT_HEADER);
    const named = [
      ...url.searchParams.getAll("fault"),
      ...(header === null ? [] : header.split(",").map((v) => v.trim())),
    ];
    for (const value of named) {
      const known = FAULTS.find((fault) => fault === value);
      if (known === undefined) throw new Error(`unknown fault: ${value}`);
      faults.add(known);
    }
    return faults;
  }

  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    this.requests.push({ method: request.method, path: url.pathname });
    const faults = this.faultsOf(request, url);
    switch (url.pathname) {
      case "/.well-known/openid-configuration": {
        if (faults.has("slow_discovery")) await sleep(SLOW_MS);
        if (faults.has("discovery_500") || this.discoveryDown) {
          return new Response("down", { status: 503 });
        }
        const { userinfo_endpoint: userinfo, ...rest } = this.discovery;
        return Response.json(
          this.withoutUserinfo ? rest : { ...rest, userinfo_endpoint: userinfo },
        );
      }
      case "/authorize":
        return this.authorize(url, faults);
      case "/token":
        return this.token(request, faults);
      case "/jwks":
        return Response.json({ keys: this.publishedKeys() });
      case "/userinfo":
        return this.userinfo(request);
      default:
        return new Response("not found", { status: 404 });
    }
  }

  private publishedKeys(): JWK[] {
    return [this.signing.publicJwk];
  }

  private authorize(url: URL, faults: Set<Fault>): Response {
    const p = url.searchParams;
    const redirectUri = p.get("redirect_uri");
    if (
      p.get("client_id") !== this.options.client_id ||
      redirectUri === null ||
      !this.options.redirect_uris.includes(redirectUri)
    ) {
      return new Response("unknown client or redirect_uri", { status: 400 });
    }
    if (p.get("response_type") !== "code") return new Response("unsupported", { status: 400 });
    const state = p.get("state");
    const back = new URL(redirectUri);
    if (state !== null) back.searchParams.set("state", state);
    if (faults.has("authorize_error")) {
      back.searchParams.set("error", "access_denied");
      back.searchParams.set("error_description", "the person said no (secret detail)");
      return Response.redirect(back.href, 302);
    }
    const sub = p.get("x_sub") ?? "person-1";
    const person = this.people.get(sub) ?? {
      sub,
      email: `${sub}@upstream.example`,
      email_verified: true,
      name: `Person ${sub}`,
      extra: {},
    };
    const code = randomToken();
    this.codes.set(code, {
      client_id: this.options.client_id,
      redirect_uri: redirectUri,
      nonce: p.get("nonce"),
      code_challenge: p.get("code_challenge"),
      person,
      faults,
      scope: p.get("scope") ?? "openid",
    });
    back.searchParams.set("code", code);
    return Response.redirect(back.href, 302);
  }

  private async authenticateClient(
    request: Request,
    form: URLSearchParams,
  ): Promise<"ok" | "invalid_client"> {
    const header = request.headers.get("authorization");
    const secret = this.options.client_secret;
    if (header?.startsWith("Basic ") === true) {
      const [id, presented] = atob(header.slice(6)).split(":");
      return id === this.options.client_id && secret !== undefined && presented === secret
        ? "ok"
        : "invalid_client";
    }
    const assertion = form.get("client_assertion");
    if (assertion !== null) {
      if (
        form.get("client_assertion_type") !==
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
        this.options.client_jwk === undefined
      ) {
        return "invalid_client";
      }
      try {
        const key = await importJWK(
          this.options.client_jwk,
          this.options.client_jwk.alg ?? "ES256",
        );
        const { payload } = await jwtVerify(assertion, key, {
          issuer: this.options.client_id,
          subject: this.options.client_id,
          audience: `${this.options.issuer}/token`,
          currentDate: new Date(this.now * 1000),
        });
        return typeof payload.jti === "string" ? "ok" : "invalid_client";
      } catch {
        return "invalid_client";
      }
    }
    const presented = form.get("client_secret");
    return form.get("client_id") === this.options.client_id &&
      secret !== undefined &&
      presented === secret
      ? "ok"
      : "invalid_client";
  }

  private async token(request: Request, requestFaults: Set<Fault>): Promise<Response> {
    if (request.method !== "POST") return new Response("method", { status: 405 });
    const form = new URLSearchParams(await request.text());
    const error = (code: string, status = 400) =>
      Response.json({ error: code, error_description: "detail from the provider" }, { status });
    if ((await this.authenticateClient(request, form)) !== "ok")
      return error("invalid_client", 401);
    if (form.get("grant_type") !== "authorization_code") return error("unsupported_grant_type");
    const issued = this.codes.get(form.get("code") ?? "");
    if (!issued) return error("invalid_grant");
    this.codes.delete(form.get("code") as string);
    const faults = new Set([...issued.faults, ...requestFaults]);
    if (form.get("redirect_uri") !== issued.redirect_uri) return error("invalid_grant");
    if (issued.code_challenge !== null) {
      const verifier = form.get("code_verifier");
      if (verifier === null || (await sha256(verifier)) !== issued.code_challenge) {
        return error("invalid_grant");
      }
    }
    if (faults.has("slow_token")) await sleep(SLOW_MS);
    if (faults.has("token_500")) return new Response("down", { status: 500 });
    if (faults.has("token_error")) return error("server_error", 500);
    if (faults.has("malformed_token_json")) {
      return new Response("{not json", { headers: { "content-type": "application/json" } });
    }
    const accessToken = randomToken();
    this.accessTokens.set(accessToken, issued);
    return Response.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      id_token: await this.idToken(issued, faults),
      scope: issued.scope,
    });
  }

  private async idToken(issued: IssuedCode, faults: Set<Fault>): Promise<string> {
    const now = this.now;
    const person = issued.person;
    const claims: Record<string, unknown> = {
      ...person.extra,
      ...(person.email === null ? {} : { email: person.email }),
      email_verified: faults.has("string_email_verified") ? "true" : person.email_verified,
      ...(person.name === null ? {} : { name: person.name }),
    };
    if (issued.nonce !== null)
      claims["nonce"] = faults.has("bad_nonce") ? "other-nonce" : issued.nonce;
    let aud: string | string[] = faults.has("bad_aud") ? "another-client" : issued.client_id;
    if (faults.has("multi_aud")) {
      aud = [issued.client_id, "another-client"];
      claims["azp"] = issued.client_id;
    }
    if (faults.has("multi_aud_bad_azp")) {
      aud = [issued.client_id, "another-client"];
      claims["azp"] = "another-client";
    }
    const iat = faults.has("future_iat") ? now + 120 : faults.has("old_iat") ? now - 700 : now;
    const exp = faults.has("expired") ? now - 120 : now + 3600;
    const sub = faults.has("long_sub") ? "s".repeat(256) : person.sub;
    const key = this.signing;
    const builder = new SignJWT(claims)
      .setProtectedHeader({
        alg: faults.has("alg_none") ? "none" : "ES256",
        kid: faults.has("unknown_kid") ? "no-such-kid" : key.kid,
        typ: "JWT",
      })
      .setIssuer(faults.has("bad_iss") ? `${this.options.issuer}/other` : this.options.issuer)
      .setAudience(aud)
      .setIssuedAt(iat)
      .setExpirationTime(exp);
    if (!faults.has("no_sub")) builder.setSubject(sub);
    if (faults.has("alg_none")) {
      // An unsigned token: header.payload. with an empty signature.
      const header = base64url(encoder.encode(JSON.stringify({ alg: "none", typ: "JWT" })));
      const body = base64url(
        encoder.encode(
          JSON.stringify({
            ...claims,
            iss: this.options.issuer,
            aud,
            iat,
            exp,
            ...(faults.has("no_sub") ? {} : { sub }),
          }),
        ),
      );
      return `${header}.${body}.`;
    }
    return builder.sign(key.privateKey);
  }

  private async userinfo(request: Request): Promise<Response> {
    const header = request.headers.get("authorization") ?? "";
    const issued = this.accessTokens.get(header.replace(/^Bearer\s+/i, ""));
    if (!issued) return new Response("unauthorized", { status: 401 });
    const faults = issued.faults;
    if (faults.has("slow_userinfo")) await sleep(SLOW_MS);
    if (faults.has("userinfo_500")) return new Response("down", { status: 500 });
    if (faults.has("userinfo_malformed")) {
      return new Response("{not json", { headers: { "content-type": "application/json" } });
    }
    const person = issued.person;
    return Response.json({
      sub: faults.has("userinfo_mismatch") ? "someone-else" : person.sub,
      ...(person.email === null ? {} : { email: person.email }),
      email_verified: faults.has("userinfo_string_email_verified") ? "true" : person.email_verified,
      ...(person.name === null ? {} : { name: person.name }),
      ...person.extra,
    });
  }
}
