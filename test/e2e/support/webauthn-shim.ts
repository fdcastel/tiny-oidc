// A page-side WebAuthn shim for browsers without a scriptable virtual
// authenticator (Firefox, WebKit): navigator.credentials.create/get are
// replaced by calls into the test process, where the software authenticator
// of test/support runs the ceremony on Web Crypto. The OP still verifies real
// signatures over real client data for the page's origin; only the browser's
// own authenticator stack is bypassed. Chromium additionally runs the real
// stack through the CDP virtual authenticator (see passkey.spec.ts).

export const WEBAUTHN_BRIDGE = "__tioWebAuthn";

/** The page script; expects `window.__tioWebAuthn(kind, optionsJson, origin)` to be exposed. */
export const WEBAUTHN_SHIM = String.raw`
(() => {
  const toB64Url = (buffer) => {
    let s = "";
    for (const b of new Uint8Array(buffer)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const fromB64Url = (text) => {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)).buffer;
  };
  const bufferOrString = (v) => (typeof v === "string" ? v : toB64Url(v));
  const credentialLike = (json) => ({
    id: json.id,
    rawId: fromB64Url(json.rawId),
    type: json.type,
    authenticatorAttachment: json.authenticatorAttachment ?? null,
    response: json.response,
    getClientExtensionResults: () => json.clientExtensionResults ?? {},
    toJSON: () => json,
  });
  const bridge = (kind, json) => window.__tioWebAuthn(kind, json, location.origin);
  const create = async ({ publicKey }) => {
    const json = {
      ...publicKey,
      challenge: bufferOrString(publicKey.challenge),
      user: { ...publicKey.user, id: bufferOrString(publicKey.user.id) },
      excludeCredentials: (publicKey.excludeCredentials || []).map((c) => ({ ...c, id: bufferOrString(c.id) })),
    };
    return credentialLike(await bridge("create", json));
  };
  const get = async ({ publicKey }) => {
    const json = {
      ...publicKey,
      challenge: bufferOrString(publicKey.challenge),
      allowCredentials: (publicKey.allowCredentials || []).map((c) => ({ ...c, id: bufferOrString(c.id) })),
    };
    return credentialLike(await bridge("get", json));
  };
  Object.defineProperty(CredentialsContainer.prototype, "create", { value: create, configurable: true, writable: true });
  Object.defineProperty(CredentialsContainer.prototype, "get", { value: get, configurable: true, writable: true });
})();
`;
