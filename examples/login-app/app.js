// Tiny OIDC reference login app (spec §7.9). Dependency-free: reads the
// interaction document, drives the passkey ceremonies and the consent and
// logout decisions against the Interaction API, then sends the browser to
// the completion URL the OP hands back. Every security decision is the OP's.
// Every control carries a stable id (signin-passkey, upstream-<alias>, register,
// consent-grant, consent-deny, logout-confirm, logout-decline, abort, return) so
// browser automation, the conformance suite's included, can drive it.
//
// The conformance suite drives this app with HtmlUnit (TIO-TEST-041), whose
// JavaScript engine is a Rhino fork: no async/await, no fetch, no spread or
// rest syntax. So this file is written with Promise chains, XMLHttpRequest
// where fetch is missing, arrays instead of variadic arguments, and no
// trailing comma in argument lists. test/scripts/login-app.test.ts enforces
// the syntax rules; the nightly conformance run is the proof.

(() => {
  const params = new URLSearchParams(location.search);
  const meta = document.querySelector('meta[name="tio-issuer"]');
  const issuer = meta?.content || location.origin;
  const app = document.getElementById("app");
  const INVITATION_KEY = "tio.invitation";

  // --- rendering -----------------------------------------------------------

  /** Appends a child, a string, or an array of them; null and undefined are skipped. */
  function appendAll(node, children) {
    const list = Array.isArray(children) ? children : [children];
    for (const child of list) {
      if (child === null || child === undefined) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    const attributes = attrs || {};
    for (const key of Object.keys(attributes)) {
      const value = attributes[key];
      if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (value !== null && value !== undefined) node.setAttribute(key, value);
    }
    appendAll(node, children);
    return node;
  }

  function render(children) {
    app.textContent = "";
    appendAll(app, children);
  }

  function clientHeader(client) {
    if (!client) return null;
    const logo = client.logo_uri ? el("img", { src: client.logo_uri, alt: "" }) : null;
    const name = client.client_uri
      ? el("a", { href: client.client_uri, rel: "noopener noreferrer" }, client.client_name)
      : el("strong", {}, client.client_name);
    return el("div", { class: "client" }, [logo, el("div", {}, name)]);
  }

  function errorBox(message) {
    return el("p", { class: "error", role: "alert" }, message);
  }

  // --- API -----------------------------------------------------------------

  /**
   * One request to the Interaction API with the binding cookie: `fetch` where
   * the browser has it, XMLHttpRequest otherwise. Resolves { ok, status, data }
   * with `data` null when the body is not JSON.
   */
  function request(url, method, contentType, payload) {
    if (typeof fetch === "function") {
      const init = { method, credentials: "include", headers: {} };
      if (payload !== undefined) {
        init.headers["content-type"] = contentType;
        init.body = payload;
      }
      return fetch(url, init).then((res) =>
        res.json().then(
          (data) => ({ ok: res.ok, status: res.status, data }),
          () => ({ ok: res.ok, status: res.status, data: null })
        )
      );
    }
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open(method, url);
      xhr.withCredentials = true;
      if (payload !== undefined) xhr.setRequestHeader("content-type", contentType);
      xhr.onload = () => {
        let data = null;
        try {
          data = JSON.parse(xhr.responseText);
        } catch (_error) {
          data = null;
        }
        resolve({ ok: xhr.status >= 200 && xhr.status < 300, status: xhr.status, data });
      };
      xhr.onerror = () => reject(new Error("network error"));
      xhr.send(payload);
    });
  }

  function api(path, method, body) {
    return request(
      `${issuer}/api/v1/interactions/${path}`,
      method,
      "application/json",
      body === undefined ? undefined : JSON.stringify(body)
    ).then((res) => {
      const data = res.data;
      if (!res.ok) {
        const error = new Error(data?.error || `HTTP ${res.status}`);
        error.code = data?.error || "http_error";
        error.status = res.status;
        throw error;
      }
      return data;
    });
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

  function withBinaryId(descriptor) {
    return Object.assign({}, descriptor, { id: fromB64Url(descriptor.id) });
  }

  function creationOptions(json) {
    if (PublicKeyCredential.parseCreationOptionsFromJSON) {
      return PublicKeyCredential.parseCreationOptionsFromJSON(json);
    }
    return Object.assign({}, json, {
      challenge: fromB64Url(json.challenge),
      user: Object.assign({}, json.user, { id: fromB64Url(json.user.id) }),
      excludeCredentials: (json.excludeCredentials || []).map(withBinaryId),
    });
  }

  function requestOptions(json) {
    if (PublicKeyCredential.parseRequestOptionsFromJSON) {
      return PublicKeyCredential.parseRequestOptionsFromJSON(json);
    }
    return Object.assign({}, json, {
      challenge: fromB64Url(json.challenge),
      allowCredentials: (json.allowCredentials || []).map(withBinaryId),
    });
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

  /** ready/failed carry the completion URL; consent_required means "show the document again". */
  function step(id, outcome) {
    if (outcome.redirect_to) {
      location.assign(outcome.redirect_to);
      return Promise.resolve();
    }
    return show(id);
  }

  function signIn(id) {
    return api(`${id}/passkey/options`, "POST", {})
      .then((options) =>
        navigator.credentials.get({ publicKey: requestOptions(options.publicKey) })
      )
      .then((credential) =>
        api(`${id}/passkey/verify`, "POST", { response: credentialToJSON(credential) })
      )
      .then((outcome) => step(id, outcome));
  }

  function signUp(id, form) {
    const body = {};
    if (form.invitation) body.invitation = form.invitation;
    if (form.email) body.email = form.email;
    if (form.display_name) body.display_name = form.display_name;
    return api(`${id}/register/options`, "POST", body).then((options) => {
      if (options.email_in_use && !form.confirmed) return { emailInUse: true };
      return navigator.credentials
        .create({ publicKey: creationOptions(options.publicKey) })
        .then((credential) => {
          const verify = { response: credentialToJSON(credential) };
          if (form.name) verify.name = form.name;
          return api(`${id}/register/verify`, "POST", verify);
        })
        .then((outcome) => {
          sessionStorage.removeItem(INVITATION_KEY);
          return step(id, outcome);
        })
        .then(() => ({ emailInUse: false }));
    });
  }

  // --- screens -------------------------------------------------------------

  /**
   * Wraps a control's action: every button is disabled while it runs, and a
   * rejection (or a synchronous throw) re-enables them and shows the message.
   */
  function busy(fn) {
    return () => {
      const buttons = app.querySelectorAll("button");
      for (const b of buttons) b.disabled = true;
      for (const e of app.querySelectorAll(".error")) e.remove();
      Promise.resolve()
        .then(fn)
        .catch((error) => {
          for (const b of buttons) b.disabled = false;
          app.appendChild(errorBox(describe(error)));
        });
    };
  }

  /** Whether this browser can do WebAuthn; without it only federation is offered. */
  const passkeysSupported = () => Boolean(window.PublicKeyCredential);

  function loginScreen(id, doc) {
    const hint = doc.request?.login_hint;
    const upstreams = doc.methods.upstreams || [];
    const passkeys = passkeysSupported();
    // Registration creates a passkey, so it needs the browser's support too.
    const canRegister =
      passkeys && (doc.methods.registration !== "closed" || sessionStorage.getItem(INVITATION_KEY));
    if (!passkeys && upstreams.length === 0) {
      render([
        clientHeader(doc.client),
        el("h1", {}, "Unsupported browser"),
        errorBox("This browser does not support passkeys, and no other sign-in method is offered."),
      ]);
      return;
    }
    const actions = el("div", { class: "actions" });
    if (passkeys) {
      const signInButton = el(
        "button",
        { class: "primary", id: "signin-passkey" },
        "Sign in with a passkey"
      );
      signInButton.addEventListener(
        "click",
        busy(() => signIn(id))
      );
      actions.appendChild(signInButton);
    } else {
      actions.appendChild(
        el("p", { class: "muted", id: "no-passkeys" }, "This browser does not support passkeys.")
      );
    }
    for (const upstream of upstreams) {
      const b = el(
        "button",
        { id: `upstream-${upstream.alias}` },
        `Continue with ${upstream.display_name}`
      );
      b.addEventListener(
        "click",
        busy(() =>
          api(`${id}/upstream/${encodeURIComponent(upstream.alias)}`, "POST", {}).then((outcome) =>
            location.assign(outcome.redirect_to)
          )
        )
      );
      actions.appendChild(b);
    }
    if (canRegister) {
      const b = el("button", { class: "linkish", id: "register" }, "Create an account");
      b.addEventListener("click", () => registerScreen(id, doc));
      actions.appendChild(b);
    }
    const abort = el("button", { class: "linkish", id: "abort" }, "Cancel");
    abort.addEventListener(
      "click",
      busy(() => api(`${id}/abort`, "POST", {}).then((outcome) => step(id, outcome)))
    );
    actions.appendChild(abort);
    render([
      clientHeader(doc.client),
      el("h1", {}, "Sign in"),
      hint ? el("p", { class: "muted" }, `Signing in as ${hint}`) : null,
      actions,
      el("p", { class: "muted" }, `${doc.attempts_remaining} attempts left`),
    ]);
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
      busy(() =>
        signUp(id, {
          email: email.value.trim(),
          display_name: displayName.value.trim(),
          invitation: invitation.value.trim(),
          name: keyName.value.trim(),
          confirmed,
        }).then((result) => {
          if (result.emailInUse) {
            confirmed = true;
            app.appendChild(
              errorBox(
                "An account with this email exists. Press again to create a separate account, or sign in instead."
              )
            );
          }
        })
      )
    );
    const back = el("button", { class: "linkish" }, "Back to sign in");
    back.addEventListener("click", () => loginScreen(id, doc));
    render([
      clientHeader(doc.client),
      el("h1", {}, "Create an account"),
      doc.methods.registration === "invite"
        ? el("p", { class: "muted" }, "An invitation is required.")
        : null,
      el("label", {}, ["Invitation (if you have one)", invitation]),
      el("label", {}, ["Email", email]),
      el("label", {}, ["Name", displayName]),
      el("label", {}, ["Passkey name", keyName]),
      el("div", { class: "actions" }, [submit, back]),
    ]);
  }

  function consentScreen(id, doc) {
    const boxes = doc.consent.scopes.map((scope) => {
      const box = el("input", { type: "checkbox", name: "scope", value: scope.name });
      // Everything requested starts checked; the user may untick optional scopes.
      box.checked = true;
      if (scope.name === "openid") box.disabled = true;
      return el("li", {}, el("label", {}, [box, ` ${scope.description}`]));
    });
    const allow = el("button", { class: "primary", id: "consent-grant" }, "Allow");
    allow.addEventListener(
      "click",
      busy(() => {
        const scopes = Array.from(app.querySelectorAll('input[name="scope"]'))
          .filter((b) => b.checked)
          .map((b) => b.value);
        return api(`${id}/consent`, "POST", { decision: "grant", scopes }).then((outcome) =>
          step(id, outcome)
        );
      })
    );
    const deny = el("button", { id: "consent-deny" }, "Deny");
    deny.addEventListener(
      "click",
      busy(() =>
        api(`${id}/consent`, "POST", { decision: "deny" }).then((outcome) => step(id, outcome))
      )
    );
    const who = doc.session_user
      ? el(
          "p",
          { class: "muted" },
          `Signed in as ${doc.session_user.display_name || doc.session_user.email_masked || "you"}`
        )
      : null;
    render([
      clientHeader(doc.client),
      el("h1", {}, `${doc.client ? doc.client.client_name : "This application"} wants to`),
      who,
      el("ul", { class: "scopes" }, boxes),
      el("div", { class: "actions" }, [allow, deny]),
    ]);
  }

  function linkScreen(id, doc) {
    const signInButton = el(
      "button",
      { class: "primary", id: "link-passkey" },
      "Sign in with your passkey to link"
    );
    signInButton.addEventListener(
      "click",
      busy(() => signIn(id))
    );
    render([
      el("h1", {}, "Link your account"),
      el(
        "p",
        {},
        `An account with the email ${doc.link.email_masked} already exists. Sign in with its passkey to link your ${doc.link.upstream} identity to it.`
      ),
      passkeysSupported()
        ? el("div", { class: "actions" }, signInButton)
        : errorBox("This browser does not support passkeys; link from one that does."),
    ]);
  }

  function logoutScreen(id, doc) {
    const decide = (confirm) =>
      busy(() =>
        api(`${id}/logout`, "POST", { confirm }).then((outcome) =>
          location.assign(outcome.redirect_to)
        )
      );
    const yes = el("button", { class: "primary", id: "logout-confirm" }, "Sign out");
    yes.addEventListener("click", decide(true));
    const no = el("button", { id: "logout-decline" }, "Stay signed in");
    no.addEventListener("click", decide(false));
    const client = doc.logout?.client;
    render([
      clientHeader(client),
      el("h1", {}, "Sign out?"),
      el(
        "p",
        {},
        client ? `${client.client_name} asked to sign you out.` : "Do you want to sign out?"
      ),
      el("div", { class: "actions" }, [yes, no]),
    ]);
  }

  function terminalScreen(id, doc) {
    const completion = `${issuer}/interactions/${id}/complete`;
    if (doc.status === "ready") {
      location.assign(completion);
      render(el("p", { class: "muted" }, "Finishing…"));
      return;
    }
    if (doc.status === "completed") {
      render([el("h1", {}, "Done"), el("p", {}, "You can close this page.")]);
      return;
    }
    const back = el("button", { class: "primary", id: "return" }, "Return to the application");
    back.addEventListener("click", () => location.assign(completion));
    render([
      el("h1", {}, "Sign-in failed"),
      errorBox(
        doc.error
          ? MESSAGES[doc.error.error] || doc.error.error_description || doc.error.error
          : "Unknown error"
      ),
      el("div", { class: "actions" }, back),
    ]);
  }

  function show(id) {
    return api(id, "GET").then((doc) => {
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
    });
  }

  // --- entry ---------------------------------------------------------------

  function main() {
    const invitation = params.get("invitation");
    if (invitation) sessionStorage.setItem(INVITATION_KEY, invitation);
    const id = params.get("interaction");
    if (params.get("error")) {
      render([
        el("h1", {}, "Sign-in failed"),
        errorBox(
          MESSAGES[params.get("error")] || params.get("error_description") || params.get("error")
        ),
      ]);
      return;
    }
    // The default logout landing (logout_landing_url = login_url?event=logged_out, TIO-LOGOUT-002).
    if (params.get("event") === "logged_out") {
      render([
        el("h1", {}, "Signed out"),
        el("p", {}, "You have been signed out of every application. You can close this page."),
      ]);
      return;
    }
    if (!id) {
      render([
        el("h1", {}, "Tiny OIDC"),
        el(
          "p",
          {},
          invitation
            ? "Your invitation is saved in this browser. Open the application you want to sign in to and choose “Create an account”."
            : "Open an application that uses this identity provider to sign in."
        ),
      ]);
      return;
    }
    show(id).catch((error) => {
      render([el("h1", {}, "Sign-in failed"), errorBox(describe(error))]);
    });
  }

  main();
})();
