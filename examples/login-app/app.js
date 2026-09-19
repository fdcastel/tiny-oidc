// Tiny OIDC reference login app (spec §7.9). Dependency-free: reads the
// interaction document, drives the passkey ceremonies and the consent and
// logout decisions against the Interaction API, then sends the browser to
// the completion URL the OP hands back. Every security decision is the OP's.
// Every control carries a stable id (signin-passkey, upstream-<alias>, register,
// consent-grant, consent-deny, logout-confirm, logout-decline, abort, return) so
// browser automation, the conformance suite's included, can drive it.

(() => {
  const params = new URLSearchParams(location.search);
  const meta = document.querySelector('meta[name="tio-issuer"]');
  const issuer = meta?.content || location.origin;
  const app = document.getElementById("app");
  const INVITATION_KEY = "tio.invitation";

  // --- rendering -----------------------------------------------------------

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (value !== null && value !== undefined) node.setAttribute(key, value);
    }
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.append(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function render(...children) {
    app.replaceChildren(...children);
  }

  function clientHeader(client) {
    if (!client) return null;
    const logo = client.logo_uri ? el("img", { src: client.logo_uri, alt: "" }) : null;
    const name = client.client_uri
      ? el("a", { href: client.client_uri, rel: "noopener noreferrer" }, client.client_name)
      : el("strong", {}, client.client_name);
    return el("div", { class: "client" }, logo, el("div", {}, name));
  }

  function errorBox(message) {
    return el("p", { class: "error", role: "alert" }, message);
  }

  // --- API -----------------------------------------------------------------

  async function api(path, method, body) {
    const init = { method, credentials: "include", headers: {} };
    if (body !== undefined) {
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const res = await fetch(`${issuer}/api/v1/interactions/${path}`, init);
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      const error = new Error(data?.error || `HTTP ${res.status}`);
      error.code = data?.error || "http_error";
      error.status = res.status;
      throw error;
    }
    return data;
  }

  // --- WebAuthn JSON helpers (fallbacks for browsers without the *FromJSON statics) ---

  function fromB64Url(text) {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  }

  function toB64Url(buffer) {
    let s = "";
    for (const b of new Uint8Array(buffer)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function creationOptions(json) {
    if (PublicKeyCredential.parseCreationOptionsFromJSON) {
      return PublicKeyCredential.parseCreationOptionsFromJSON(json);
    }
    return {
      ...json,
      challenge: fromB64Url(json.challenge),
      user: { ...json.user, id: fromB64Url(json.user.id) },
      excludeCredentials: (json.excludeCredentials || []).map((c) => ({
        ...c,
        id: fromB64Url(c.id),
      })),
    };
  }

  function requestOptions(json) {
    if (PublicKeyCredential.parseRequestOptionsFromJSON) {
      return PublicKeyCredential.parseRequestOptionsFromJSON(json);
    }
    return {
      ...json,
      challenge: fromB64Url(json.challenge),
      allowCredentials: (json.allowCredentials || []).map((c) => ({ ...c, id: fromB64Url(c.id) })),
    };
  }

  function credentialToJSON(credential) {
    if (typeof credential.toJSON === "function") return credential.toJSON();
    const response = credential.response;
    const out = {
      id: credential.id,
      rawId: toB64Url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: { clientDataJSON: toB64Url(response.clientDataJSON) },
    };
    if (response.attestationObject) {
      out.response.attestationObject = toB64Url(response.attestationObject);
      out.response.transports = response.getTransports ? response.getTransports() : [];
    } else {
      out.response.authenticatorData = toB64Url(response.authenticatorData);
      out.response.signature = toB64Url(response.signature);
      if (response.userHandle) out.response.userHandle = toB64Url(response.userHandle);
    }
    if (credential.authenticatorAttachment) {
      out.authenticatorAttachment = credential.authenticatorAttachment;
    }
    return out;
  }

  // --- flows ---------------------------------------------------------------

  const MESSAGES = {
    passkey_verification_failed: "That passkey was not accepted. Try again.",
    passkey_counter_regression: "This passkey looks cloned and was refused. Use another one.",
    passkey_not_discoverable: "Your authenticator did not create a discoverable passkey.",
    passkey_limit_reached: "This account already holds the maximum number of passkeys.",
    too_many_attempts: "Too many attempts. Start again from the application.",
    registration_closed: "Registration is closed. Ask an administrator for an invitation.",
    invitation_invalid: "This invitation is not valid.",
    invitation_expired: "This invitation has expired.",
    invitation_used: "This invitation was already used.",
    email_invalid: "That email address is not valid.",
    account_exists: "An account with this email already exists. Sign in instead.",
    interaction_not_found: "This sign-in request has expired. Start again from the application.",
    interaction_binding_failed: "This sign-in request belongs to another browser session.",
    origin_not_allowed: "This page is not allowed to talk to the identity provider.",
    interaction_invalid_state: "This step is no longer available. Reload the page.",
    temporarily_unavailable: "The identity provider is temporarily unavailable. Try again shortly.",
    access_denied: "Access was denied.",
    NotAllowedError: "The passkey operation was cancelled or timed out.",
  };

  function describe(error) {
    return (
      MESSAGES[error.code] ||
      MESSAGES[error.name] ||
      `Something went wrong (${error.code || error.name || error.message}).`
    );
  }

  async function step(id, outcome) {
    // ready/failed carry the completion URL; consent_required means "show the document again".
    if (outcome.redirect_to) {
      location.assign(outcome.redirect_to);
      return;
    }
    await show(id);
  }

  async function signIn(id) {
    const { publicKey } = await api(`${id}/passkey/options`, "POST", {});
    const credential = await navigator.credentials.get({ publicKey: requestOptions(publicKey) });
    const outcome = await api(`${id}/passkey/verify`, "POST", {
      response: credentialToJSON(credential),
    });
    await step(id, outcome);
  }

  async function signUp(id, form) {
    const body = {};
    if (form.invitation) body.invitation = form.invitation;
    if (form.email) body.email = form.email;
    if (form.display_name) body.display_name = form.display_name;
    const { publicKey, email_in_use: emailInUse } = await api(
      `${id}/register/options`,
      "POST",
      body,
    );
    if (emailInUse && !form.confirmed) {
      return { emailInUse: true };
    }
    const credential = await navigator.credentials.create({
      publicKey: creationOptions(publicKey),
    });
    const verify = { response: credentialToJSON(credential) };
    if (form.name) verify.name = form.name;
    const outcome = await api(`${id}/register/verify`, "POST", verify);
    sessionStorage.removeItem(INVITATION_KEY);
    await step(id, outcome);
    return { emailInUse: false };
  }

  // --- screens -------------------------------------------------------------

  function busy(fn) {
    return async () => {
      const buttons = app.querySelectorAll("button");
      for (const b of buttons) b.disabled = true;
      const errors = app.querySelectorAll(".error");
      for (const e of errors) e.remove();
      try {
        await fn();
      } catch (error) {
        for (const b of buttons) b.disabled = false;
        app.append(errorBox(describe(error)));
      }
    };
  }

  function loginScreen(id, doc) {
    const hint = doc.request?.login_hint;
    const canRegister =
      doc.methods.registration !== "closed" || sessionStorage.getItem(INVITATION_KEY);
    const signInButton = el(
      "button",
      { class: "primary", id: "signin-passkey" },
      "Sign in with a passkey",
    );
    signInButton.addEventListener(
      "click",
      busy(() => signIn(id)),
    );
    const actions = el("div", { class: "actions" }, signInButton);
    for (const upstream of doc.methods.upstreams || []) {
      const b = el(
        "button",
        { id: `upstream-${upstream.alias}` },
        `Continue with ${upstream.display_name}`,
      );
      b.addEventListener(
        "click",
        busy(async () => {
          const { redirect_to: redirectTo } = await api(
            `${id}/upstream/${encodeURIComponent(upstream.alias)}`,
            "POST",
            {},
          );
          location.assign(redirectTo);
        }),
      );
      actions.append(b);
    }
    if (canRegister) {
      const b = el("button", { class: "linkish", id: "register" }, "Create an account");
      b.addEventListener("click", () => registerScreen(id, doc));
      actions.append(b);
    }
    const abort = el("button", { class: "linkish", id: "abort" }, "Cancel");
    abort.addEventListener(
      "click",
      busy(async () => step(id, await api(`${id}/abort`, "POST", {}))),
    );
    actions.append(abort);
    render(
      clientHeader(doc.client),
      el("h1", {}, "Sign in"),
      hint ? el("p", { class: "muted" }, `Signing in as ${hint}`) : null,
      actions,
      el("p", { class: "muted" }, `${doc.attempts_remaining} attempts left`),
    );
  }

  function registerScreen(id, doc) {
    const stored = sessionStorage.getItem(INVITATION_KEY) || "";
    const email = el("input", { type: "email", name: "email", autocomplete: "email" });
    const displayName = el("input", { type: "text", name: "display_name", autocomplete: "name" });
    const invitation = el("input", {
      type: "text",
      name: "invitation",
      value: stored,
      autocomplete: "off",
    });
    const keyName = el("input", {
      type: "text",
      name: "name",
      placeholder: "This device",
      autocomplete: "off",
    });
    let confirmed = false;
    const submit = el("button", { class: "primary", id: "register-passkey" }, "Create a passkey");
    submit.addEventListener(
      "click",
      busy(async () => {
        const result = await signUp(id, {
          email: email.value.trim(),
          display_name: displayName.value.trim(),
          invitation: invitation.value.trim(),
          name: keyName.value.trim(),
          confirmed,
        });
        if (result.emailInUse) {
          confirmed = true;
          app.append(
            errorBox(
              "An account with this email exists. Press again to create a separate account, or sign in instead.",
            ),
          );
        }
      }),
    );
    const back = el("button", { class: "linkish" }, "Back to sign in");
    back.addEventListener("click", () => loginScreen(id, doc));
    render(
      clientHeader(doc.client),
      el("h1", {}, "Create an account"),
      doc.methods.registration === "invite"
        ? el("p", { class: "muted" }, "An invitation is required.")
        : null,
      el("label", {}, "Invitation (if you have one)", invitation),
      el("label", {}, "Email", email),
      el("label", {}, "Name", displayName),
      el("label", {}, "Passkey name", keyName),
      el("div", { class: "actions" }, submit, back),
    );
  }

  function consentScreen(id, doc) {
    const boxes = doc.consent.scopes.map((scope) => {
      const box = el("input", { type: "checkbox", name: "scope", value: scope.name });
      // Everything requested starts checked; the user may untick optional scopes.
      box.checked = true;
      if (scope.name === "openid") box.disabled = true;
      return el("li", {}, el("label", {}, box, ` ${scope.description}`));
    });
    const allow = el("button", { class: "primary", id: "consent-grant" }, "Allow");
    allow.addEventListener(
      "click",
      busy(async () => {
        const scopes = [...app.querySelectorAll('input[name="scope"]')]
          .filter((b) => b.checked)
          .map((b) => b.value);
        await step(id, await api(`${id}/consent`, "POST", { decision: "grant", scopes }));
      }),
    );
    const deny = el("button", { id: "consent-deny" }, "Deny");
    deny.addEventListener(
      "click",
      busy(async () => step(id, await api(`${id}/consent`, "POST", { decision: "deny" }))),
    );
    const who = doc.session_user
      ? el(
          "p",
          { class: "muted" },
          `Signed in as ${doc.session_user.display_name || doc.session_user.email_masked || "you"}`,
        )
      : null;
    render(
      clientHeader(doc.client),
      el("h1", {}, `${doc.client ? doc.client.client_name : "This application"} wants to`),
      who,
      el("ul", { class: "scopes" }, ...boxes),
      el("div", { class: "actions" }, allow, deny),
    );
  }

  function linkScreen(id, doc) {
    const signInButton = el(
      "button",
      { class: "primary", id: "link-passkey" },
      "Sign in with your passkey to link",
    );
    signInButton.addEventListener(
      "click",
      busy(() => signIn(id)),
    );
    render(
      el("h1", {}, "Link your account"),
      el(
        "p",
        {},
        `An account with the email ${doc.link.email_masked} already exists. Sign in with its passkey to link your ${doc.link.upstream} identity to it.`,
      ),
      el("div", { class: "actions" }, signInButton),
    );
  }

  function logoutScreen(id, doc) {
    const decide = (confirm) =>
      busy(async () => {
        const { redirect_to: redirectTo } = await api(`${id}/logout`, "POST", { confirm });
        location.assign(redirectTo);
      });
    const yes = el("button", { class: "primary", id: "logout-confirm" }, "Sign out");
    yes.addEventListener("click", decide(true));
    const no = el("button", { id: "logout-decline" }, "Stay signed in");
    no.addEventListener("click", decide(false));
    const client = doc.logout?.client;
    render(
      clientHeader(client),
      el("h1", {}, "Sign out?"),
      el(
        "p",
        {},
        client ? `${client.client_name} asked to sign you out.` : "Do you want to sign out?",
      ),
      el("div", { class: "actions" }, yes, no),
    );
  }

  function terminalScreen(id, doc) {
    const completion = `${issuer}/interactions/${id}/complete`;
    if (doc.status === "ready") {
      location.assign(completion);
      render(el("p", { class: "muted" }, "Finishing…"));
      return;
    }
    if (doc.status === "completed") {
      render(el("h1", {}, "Done"), el("p", {}, "You can close this page."));
      return;
    }
    const back = el("button", { class: "primary", id: "return" }, "Return to the application");
    back.addEventListener("click", () => location.assign(completion));
    render(
      el("h1", {}, "Sign-in failed"),
      errorBox(
        doc.error
          ? MESSAGES[doc.error.error] || doc.error.error_description || doc.error.error
          : "Unknown error",
      ),
      el("div", { class: "actions" }, back),
    );
  }

  async function show(id) {
    const doc = await api(id, "GET");
    if (doc.kind === "logout") return logoutScreen(id, doc);
    switch (doc.status) {
      case "login_required":
        return loginScreen(id, doc);
      case "link_required":
        return linkScreen(id, doc);
      case "consent_required":
        return consentScreen(id, doc);
      default:
        return terminalScreen(id, doc);
    }
  }

  // --- entry ---------------------------------------------------------------

  async function main() {
    const invitation = params.get("invitation");
    if (invitation) sessionStorage.setItem(INVITATION_KEY, invitation);
    const id = params.get("interaction");
    if (params.get("error")) {
      render(
        el("h1", {}, "Sign-in failed"),
        errorBox(
          MESSAGES[params.get("error")] || params.get("error_description") || params.get("error"),
        ),
      );
      return;
    }
    if (!id) {
      render(
        el("h1", {}, "Tiny OIDC"),
        el(
          "p",
          {},
          invitation
            ? "Your invitation is saved in this browser. Open the application you want to sign in to and choose “Create an account”."
            : "Open an application that uses this identity provider to sign in.",
        ),
      );
      return;
    }
    if (!window.PublicKeyCredential) {
      render(
        el("h1", {}, "Unsupported browser"),
        errorBox("This browser does not support passkeys."),
      );
      return;
    }
    try {
      await show(id);
    } catch (error) {
      render(el("h1", {}, "Sign-in failed"), errorBox(describe(error)));
    }
  }

  main();
})();
