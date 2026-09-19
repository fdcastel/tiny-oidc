import type { BrowserContext, CDPSession, Page } from "@playwright/test";
import { VirtualAuthenticator } from "../../support/virtual-authenticator.ts";
import { WEBAUTHN_BRIDGE, WEBAUTHN_SHIM } from "./webauthn-shim.ts";

// Passkeys for real browsers. Chromium runs its own WebAuthn stack against a
// CDP virtual authenticator; credentials are carried between browser contexts
// by exporting and re-adding them. Firefox and WebKit have no scriptable
// authenticator, so their pages get the shim backed by the software
// authenticator of test/support, which keeps credentials across contexts on
// its own. Either way the OP verifies real signatures for the page's origin.

interface CdpCredential {
  credentialId: string;
  isResidentCredential: boolean;
  rpId?: string;
  privateKey: string;
  userHandle?: string;
  signCount: number;
}

export interface PasskeyProvider {
  /** Prepares a page (and its context) to answer WebAuthn ceremonies. */
  attach(page: Page): Promise<void>;
  /** Persists the credentials created in the page so a later context can sign in with them. */
  remember(page: Page): Promise<void>;
}

class CdpProvider implements PasskeyProvider {
  private credentials: CdpCredential[] = [];
  private readonly sessions = new WeakMap<Page, { cdp: CDPSession; authenticatorId: string }>();

  async attach(page: Page): Promise<void> {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    for (const credential of this.credentials) {
      await cdp.send("WebAuthn.addCredential", { authenticatorId, credential });
    }
    this.sessions.set(page, { cdp, authenticatorId });
  }

  async remember(page: Page): Promise<void> {
    const session = this.sessions.get(page);
    if (!session) throw new Error("attach() first");
    const { credentials } = await session.cdp.send("WebAuthn.getCredentials", {
      authenticatorId: session.authenticatorId,
    });
    this.credentials = credentials as CdpCredential[];
  }
}

class ShimProvider implements PasskeyProvider {
  private readonly authenticator = new VirtualAuthenticator();
  private readonly contexts = new WeakSet<BrowserContext>();

  async attach(page: Page): Promise<void> {
    const context = page.context();
    if (this.contexts.has(context)) return;
    this.contexts.add(context);
    await context.exposeFunction(WEBAUTHN_BRIDGE, (kind: string, options: never, origin: string) =>
      kind === "create"
        ? this.authenticator.register(options, origin)
        : this.authenticator.authenticate(options, origin),
    );
    await context.addInitScript(WEBAUTHN_SHIM);
  }

  async remember(): Promise<void> {
    // The software authenticator already keeps every credential it created.
  }
}

export function passkeyProvider(browserName: string): PasskeyProvider {
  return browserName === "chromium" ? new CdpProvider() : new ShimProvider();
}
