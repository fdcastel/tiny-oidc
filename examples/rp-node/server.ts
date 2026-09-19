// A minimal relying party on openid-client v6 (spec §13.5, TIO-TEST-033): it
// reaches the OP over HTTP only, verifies ID tokens against the live JWKS like
// any real client, and answers JSON so that the end-to-end suite can read it.
// It also plays a first-party app: RP-initiated logout with and without a
// hint, and a "security settings" page that adds passkeys through the
// Self-service API (§8).
//
//   TIO_ISSUER     the OP (default http://localhost:8787)
//   TIO_CLIENT_ID  a public client whose redirect URI matches this server
//   PORT           where to listen (default 8788); the redirect URI is
//                  http://127.0.0.1:<PORT>/callback (loopback, any port)
//
// The loopback callback lives on 127.0.0.1, but a WebAuthn ceremony needs a
// registrable origin that the OP's RP ID covers, so the settings page is
// served on http://localhost:<PORT>; /handoff carries the RP session across
// (browser cookies are per host).
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
  /** Where to send the browser after the callback (a path on this server). */
  return_to: string | null;
}

interface Session {
  claims: Record<string, unknown>;
  access_token: string;
  refresh_token: string | null;
  id_token: string | null;
  scope: string;
}

const settingsOrigin = `http://localhost:${port}`;

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

function sessionIdOf(req: IncomingMessage): string | null {
  const match = /(?:^|;\s*)rp=([^;]+)/.exec(req.headers.cookie ?? "");
  return match ? (match[1] as string) : null;
}

function sessionOf(req: IncomingMessage): Session | undefined {
  const id = sessionIdOf(req);
  return id === null ? undefined : sessions.get(id);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/**
 * The security-settings page: lists the person's passkeys and adds one with a
 * WebAuthn ceremony run against the Self-service API. When the OP asks for a
 * fresh authentication (TIO-ME-003), the page re-authorizes with max_age=0
 * and comes back here.
 */
const SETTINGS_PAGE = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Security settings</title></head>
<body>
<h1>Security settings</h1>
<label>Passkey name <input id="name" value="Second key"></label>
<button id="add">Add a passkey</button>
<pre id="passkeys" aria-label="Passkeys"></pre>
<pre id="result" aria-label="Result"></pre>
<script>
  const show = async () => {
    const res = await fetch("/me/passkeys");
    document.getElementById("passkeys").textContent = JSON.stringify(await res.json());
  };
  const add = async () => {
    const result = document.getElementById("result");
    const options = await fetch("/me/passkeys/options", { method: "POST" });
    const optionsBody = await options.json();
    if (options.status === 403 && optionsBody.error === "reauthentication_required") {
      location.assign("/login?scope=openid%20email%20account&max_age=0&return=%2Fme");
      return;
    }
    if (!options.ok) {
      result.textContent = JSON.stringify({ status: options.status, ...optionsBody });
      return;
    }
    const credential = await navigator.credentials.create({
      publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(optionsBody.publicKey),
    });
    const registered = await fetch("/me/passkeys", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        response: credential.toJSON(),
        name: document.getElementById("name").value,
      }),
    });
    result.textContent = JSON.stringify({ status: registered.status, ...(await registered.json()) });
    await show();
  };
  document.getElementById("add").addEventListener("click", () => {
    add().catch((error) => {
      document.getElementById("result").textContent = JSON.stringify({ error: String(error) });
    });
  });
  show();
</script>
</body>
</html>
`;

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", base);
  if (url.pathname === "/login") {
    const cfg = await config();
    const verifier = client.randomPKCECodeVerifier();
    const state = client.randomState();
    const nonce = client.randomNonce();
    pending.set(state, { verifier, state, nonce, return_to: url.searchParams.get("return") });
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
        id_token: tokens.id_token ?? null,
        scope: tokens.scope ?? "",
      });
      const cookie = `rp=${id}; Path=/; HttpOnly`;
      if (expected.return_to !== null) {
        res.writeHead(302, {
          location: `/handoff?to=${encodeURIComponent(expected.return_to)}`,
          "set-cookie": cookie,
        });
        res.end();
        return;
      }
      return json(res, 200, { claims, scope: tokens.scope }, { "set-cookie": cookie });
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
  if (url.pathname === "/handoff") {
    // From the loopback host to the settings origin, or the settings origin taking the session.
    const to = url.searchParams.get("to") ?? "/me";
    const carried = url.searchParams.get("rp");
    if (carried !== null && sessions.has(carried)) {
      res.writeHead(302, { location: to, "set-cookie": `rp=${carried}; Path=/; HttpOnly` });
      res.end();
      return;
    }
    const current = sessionIdOf(req);
    if (current === null) return json(res, 401, { error: "no_session" });
    res.writeHead(302, {
      location: `${settingsOrigin}/handoff?rp=${current}&to=${encodeURIComponent(to)}`,
    });
    res.end();
    return;
  }
  if (url.pathname === "/loggedout") {
    // The OP sends the browser here after an RP-initiated logout: drop the RP session too.
    const id = sessionIdOf(req);
    if (id !== null) sessions.delete(id);
    return json(
      res,
      200,
      { logged_out: true, state: url.searchParams.get("state") },
      { "set-cookie": "rp=; Path=/; HttpOnly; Max-Age=0" },
    );
  }
  const session = sessionOf(req);
  if (url.pathname === "/logout") {
    // RP-initiated logout (§5.10.1): with the ID token as the hint, or without one
    // (?nohint=1), in which case the OP asks the person to confirm.
    const cfg = await config();
    const params: Record<string, string> = {
      post_logout_redirect_uri: `${base}/loggedout`,
      state: client.randomState(),
    };
    if (url.searchParams.get("nohint") === "1") params["client_id"] = clientId;
    else if (session?.id_token) params["id_token_hint"] = session.id_token;
    res.writeHead(302, { location: client.buildEndSessionUrl(cfg, params).href });
    res.end();
    return;
  }
  if (url.pathname === "/me") {
    if (!session) return json(res, 401, { error: "no_session" });
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(SETTINGS_PAGE);
    return;
  }
  if (url.pathname === "/me/passkeys" || url.pathname === "/me/passkeys/options") {
    // The Self-service API, called with the person's own token (scope account).
    if (!session) return json(res, 401, { error: "no_session" });
    const body = req.method === "POST" ? await readBody(req) : null;
    const upstream = await fetch(`${issuer.href.replace(/\/$/, "")}/api/v1${url.pathname}`, {
      method: req.method ?? "GET",
      headers: {
        authorization: `Bearer ${session.access_token}`,
        ...(body === null ? {} : { "content-type": "application/json" }),
      },
      ...(body === null ? {} : { body }),
    });
    return json(res, upstream.status, await upstream.json());
  }
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
