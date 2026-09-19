// A minimal relying party on openid-client v6 (spec §13.5, TIO-TEST-033): it
// reaches the OP over HTTP only, verifies ID tokens against the live JWKS like
// any real client, and answers JSON so that the end-to-end suite can read it.
//
//   TIO_ISSUER     the OP (default http://localhost:8787)
//   TIO_CLIENT_ID  a public client whose redirect URI matches this server
//   PORT           where to listen (default 8788); the redirect URI is
//                  http://127.0.0.1:<PORT>/callback (loopback, any port)
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import * as client from "openid-client";

const issuer = new URL(process.env["TIO_ISSUER"] ?? "http://localhost:8787");
const clientId = process.env["TIO_CLIENT_ID"] ?? "admin-cli";
const port = Number(process.env["PORT"] ?? "8788");
const base = `http://127.0.0.1:${port}`;
const redirectUri = `${base}/callback`;

interface Pending {
  verifier: string;
  state: string;
  nonce: string;
}

interface Session {
  claims: Record<string, unknown>;
  access_token: string;
  refresh_token: string | null;
  scope: string;
}

let configuration: client.Configuration | undefined;
const pending = new Map<string, Pending>();
const sessions = new Map<string, Session>();
let sessionCounter = 0;

async function config(): Promise<client.Configuration> {
  if (configuration === undefined) {
    configuration = await client.discovery(issuer, clientId, undefined, undefined, {
      // A local OP speaks plain http; a real deployment never does.
      execute: issuer.protocol === "http:" ? [client.allowInsecureRequests] : [],
    });
  }
  return configuration;
}

function json(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
) {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...headers,
  });
  res.end(JSON.stringify(body));
}

function sessionOf(req: IncomingMessage): Session | undefined {
  const match = /(?:^|;\s*)rp=([^;]+)/.exec(req.headers.cookie ?? "");
  return match ? sessions.get(match[1] as string) : undefined;
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", base);
  if (url.pathname === "/login") {
    const cfg = await config();
    const verifier = client.randomPKCECodeVerifier();
    const state = client.randomState();
    const nonce = client.randomNonce();
    pending.set(state, { verifier, state, nonce });
    const params: Record<string, string> = {
      redirect_uri: redirectUri,
      scope: url.searchParams.get("scope") ?? "openid email profile",
      code_challenge: await client.calculatePKCECodeChallenge(verifier),
      code_challenge_method: "S256",
      state,
      nonce,
    };
    for (const key of ["prompt", "max_age", "login_hint"]) {
      const value = url.searchParams.get(key);
      if (value !== null) params[key] = value;
    }
    res.writeHead(302, { location: client.buildAuthorizationUrl(cfg, params).href });
    res.end();
    return;
  }
  if (url.pathname === "/callback") {
    const cfg = await config();
    const state = url.searchParams.get("state") ?? "";
    const expected = pending.get(state);
    pending.delete(state);
    if (expected === undefined) return json(res, 400, { error: "unknown_state" });
    try {
      const tokens = await client.authorizationCodeGrant(cfg, url, {
        pkceCodeVerifier: expected.verifier,
        expectedState: expected.state,
        expectedNonce: expected.nonce,
      });
      const claims = tokens.claims() as Record<string, unknown>;
      const id = String(++sessionCounter);
      sessions.set(id, {
        claims,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token ?? null,
        scope: tokens.scope ?? "",
      });
      return json(
        res,
        200,
        { claims, scope: tokens.scope },
        { "set-cookie": `rp=${id}; Path=/; HttpOnly` },
      );
    } catch (error) {
      // openid-client surfaces the OP's error response (RFC 6749 4.1.2.1) on the error object.
      const cause = error as { error?: string; error_description?: string };
      return json(res, 400, {
        error: "callback_failed",
        detail: String(error),
        oauth_error: cause.error ?? null,
        oauth_error_description: cause.error_description ?? null,
      });
    }
  }
  const session = sessionOf(req);
  if (url.pathname === "/session") {
    return session
      ? json(res, 200, { claims: session.claims, scope: session.scope })
      : json(res, 401, { error: "no_session" });
  }
  if (url.pathname === "/userinfo") {
    if (!session) return json(res, 401, { error: "no_session" });
    const cfg = await config();
    return json(
      res,
      200,
      await client.fetchUserInfo(cfg, session.access_token, session.claims["sub"] as string),
    );
  }
  if (url.pathname === "/refresh") {
    if (!session || session.refresh_token === null) return json(res, 401, { error: "no_session" });
    const cfg = await config();
    const tokens = await client.refreshTokenGrant(cfg, session.refresh_token);
    session.access_token = tokens.access_token;
    session.refresh_token = tokens.refresh_token ?? session.refresh_token;
    session.claims = (tokens.claims() ?? session.claims) as Record<string, unknown>;
    return json(res, 200, { claims: session.claims, scope: tokens.scope });
  }
  if (url.pathname === "/health")
    return json(res, 200, { status: "ok", issuer: issuer.href, client_id: clientId });
  return json(res, 404, { error: "not_found" });
}

createServer((req, res) => {
  handle(req, res).catch((error: unknown) =>
    json(res, 500, { error: "rp_error", detail: String(error) }),
  );
}).listen(port, "127.0.0.1", () => {
  console.log(`rp-node: listening on ${base} for ${issuer.href} as ${clientId}`);
});
