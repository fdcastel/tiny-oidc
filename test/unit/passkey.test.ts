import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { cose, decodeCredentialPublicKey } from "@simplewebauthn/server/helpers";
import { describe, expect, it } from "vitest";
import {
  assertionIdentity,
  authenticationOptions,
  authenticatorUserName,
  CEREMONY_TIMEOUT_MS,
  CHALLENGE_TTL_SECONDS,
  counterPolicy,
  newChallenge,
  registrationOptions,
  verifyAssertionSignature,
  verifyRegistration,
} from "../../src/auth/passkey.ts";
import { encodeBase64Url } from "../../src/util/base64url.ts";
import {
  type CoseAlgorithm,
  cborEncode,
  VirtualAuthenticator,
} from "../support/virtual-authenticator.ts";

const RP_ID = "example.com";
const ORIGIN = "https://login.example.com";
const ORIGINS = [ORIGIN, "https://app.example.com"];
const userId = new Uint8Array(16).fill(7);

const creation = (challenge = newChallenge()) =>
  registrationOptions({
    rpId: RP_ID,
    rpName: "Example",
    userId,
    userName: "alice@example.com",
    displayName: "Alice",
    challenge,
    excludeCredentialIds: [],
  });

async function registered(algorithm: CoseAlgorithm = -7) {
  const authenticator = new VirtualAuthenticator(algorithm);
  const options = creation();
  const response = await authenticator.register(options, ORIGIN);
  const verified = await verifyRegistration(response, {
    challenge: options.challenge,
    origins: ORIGINS,
    rpId: RP_ID,
  });
  if (!verified.ok) throw new Error(verified.error);
  return { authenticator, options, response, passkey: verified.passkey };
}

describe("virtual authenticator", () => {
  it("[TIO-TEST-030] produces registrations and assertions that @simplewebauthn/server verifies, for ES256, EdDSA and RS256", async () => {
    for (const algorithm of [-7, -8, -257] as const) {
      const authenticator = new VirtualAuthenticator(algorithm);
      const options = creation();
      const response = await authenticator.register(options, ORIGIN);
      const registration = await verifyRegistrationResponse({
        response,
        expectedChallenge: options.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true,
      });
      expect(registration.verified, String(algorithm)).toBe(true);
      const info = registration.registrationInfo;
      expect(info?.fmt).toBe("none");
      expect(info?.credentialDeviceType).toBe("multiDevice");
      expect(info?.credentialBackedUp).toBe(true);
      expect(
        decodeCredentialPublicKey(new Uint8Array(info?.credential.publicKey as Uint8Array)).get(
          cose.COSEKEYS.alg,
        ),
      ).toBe(algorithm);
      const request = authenticationOptions(RP_ID, newChallenge());
      const assertion = await authenticator.authenticate(request, ORIGIN);
      const authentication = await verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: request.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true,
        credential: {
          id: info?.credential.id as string,
          publicKey: new Uint8Array(info?.credential.publicKey as Uint8Array),
          counter: 0,
        },
      });
      expect(authentication.verified, String(algorithm)).toBe(true);
      expect(authentication.authenticationInfo.newCounter).toBe(1);
      expect(assertion.response.userHandle).toBe(encodeBase64Url(userId));
    }
  });

  it("encodes CBOR integers, strings, bytes, arrays and maps", () => {
    const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    expect(hex(cborEncode(0))).toBe("00");
    expect(hex(cborEncode(23))).toBe("17");
    expect(hex(cborEncode(24))).toBe("1818");
    expect(hex(cborEncode(256))).toBe("190100");
    expect(hex(cborEncode(70_000))).toBe("1a00011170");
    expect(hex(cborEncode(-1))).toBe("20");
    expect(hex(cborEncode(-257))).toBe("390100");
    expect(hex(cborEncode("a"))).toBe("6161");
    expect(hex(cborEncode(new Uint8Array([1, 2])))).toBe("420102");
    expect(hex(cborEncode([1, "a"]))).toBe("82016161");
    expect(hex(cborEncode(new Map<number | string, number>([[1, 2]])))).toBe("a10102");
  });
});

describe("passkey options", () => {
  it("[TIO-PK-010] registration options carry the RP, the 16-byte user id, a 32-byte challenge, the three algorithms in order, no attestation, resident key and UV required, exclusions and credProps", () => {
    const challenge = newChallenge();
    const options = registrationOptions({
      rpId: RP_ID,
      rpName: "Example",
      userId,
      userName: "alice@example.com",
      displayName: "Alice",
      challenge,
      excludeCredentialIds: ["c1", "c2"],
    });
    expect(options).toEqual({
      rp: { id: RP_ID, name: "Example" },
      user: { id: encodeBase64Url(userId), name: "alice@example.com", displayName: "Alice" },
      challenge,
      pubKeyCredParams: [
        { type: "public-key", alg: -8 },
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 300_000,
      attestation: "none",
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
      excludeCredentials: [
        { id: "c1", type: "public-key" },
        { id: "c2", type: "public-key" },
      ],
      extensions: { credProps: true },
    });
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(newChallenge()).not.toBe(challenge);
    expect(CEREMONY_TIMEOUT_MS).toBe(300_000);
    expect(CHALLENGE_TTL_SECONDS).toBe(300);
    expect(authenticatorUserName("a@example.com", "0192abcd-1234-7000-8000-000000000000")).toBe(
      "a@example.com",
    );
    expect(authenticatorUserName(null, "0192abcd-1234-7000-8000-000000000000")).toBe(
      "user-0192abcd",
    );
  });

  it("[TIO-PK-020] authentication options carry a 32-byte challenge, the RP ID, the timeout, UV required and no allowed credentials", () => {
    const challenge = newChallenge();
    expect(authenticationOptions(RP_ID, challenge)).toEqual({
      challenge,
      rpId: RP_ID,
      timeout: 300_000,
      userVerification: "required",
      allowCredentials: [],
    });
  });
});

describe("registration verification", () => {
  it("[TIO-PK-012] [TIO-PK-014] accepts a valid registration and records the credential, algorithm, counter, transports, aaguid and backup flags", async () => {
    const { passkey, response } = await registered();
    expect(passkey).toMatchObject({
      credential_id: response.id,
      alg: -7,
      counter: 0,
      transports: ["internal"],
      aaguid: "00000000-0000-0000-0000-000000000000",
      backup_eligible: true,
      backed_up: true,
    });
    expect(passkey.public_key.length).toBeGreaterThan(50);
    const single = new VirtualAuthenticator();
    const options = creation();
    const flagsClear = await single.register(options, ORIGIN, {
      backupEligible: false,
      backedUp: false,
    });
    const verified = await verifyRegistration(flagsClear, {
      challenge: options.challenge,
      origins: ORIGINS,
      rpId: RP_ID,
    });
    expect(verified.ok && verified.passkey).toMatchObject({
      backup_eligible: false,
      backed_up: false,
    });
    const noTransports = await single.register(options, ORIGIN);
    delete noTransports.response.transports;
    const stored = await verifyRegistration(noTransports, {
      challenge: options.challenge,
      origins: ORIGINS,
      rpId: RP_ID,
    });
    expect(stored.ok && stored.passkey.transports).toEqual([]);
  });

  it("[TIO-PK-012] [TIO-PK-002] rejects the wrong type, challenge, origin, RP ID, a clear UP or UV flag, malformed input and unsupported algorithms", async () => {
    const authenticator = new VirtualAuthenticator();
    const options = creation();
    const expected = { challenge: options.challenge, origins: ORIGINS, rpId: RP_ID };
    const cases: Record<string, Parameters<VirtualAuthenticator["register"]>[2]> = {
      type: { type: "webauthn.get" },
      challenge: { challenge: newChallenge() },
      origin: { origin: "https://evil.example.net" },
      rpId: { rpId: "evil.example.net" },
      userPresent: { userPresent: false },
      userVerified: { userVerified: false },
    };
    for (const [name, faults] of Object.entries(cases)) {
      const response = await authenticator.register(options, ORIGIN, faults);
      expect(await verifyRegistration(response, expected), name).toMatchObject({
        ok: false,
        error: "passkey_verification_failed",
        reason: expect.stringMatching(/^[A-Za-z]+: /),
      });
    }
    const malformed = {
      ok: false,
      error: "passkey_verification_failed",
      reason: "malformed registration response",
    };
    expect(await verifyRegistration({ nonsense: true }, expected)).toEqual(malformed);
    expect(await verifyRegistration(null, expected)).toEqual(malformed);
    for (const attestationObject of ["AAAA", "!!!!", "oQ"]) {
      const garbage = await authenticator.register(options, ORIGIN);
      garbage.response.attestationObject = attestationObject;
      expect(await verifyRegistration(garbage, expected), attestationObject).toMatchObject({
        ok: false,
        error: "passkey_verification_failed",
      });
    }
    const otherOrigin = await authenticator.register(options, "https://app.example.com");
    expect((await verifyRegistration(otherOrigin, expected)).ok).toBe(true);
  });

  it("[TIO-PK-013] rejects credProps.rk false and accepts an absent or true rk", async () => {
    const authenticator = new VirtualAuthenticator();
    const options = creation();
    const expected = { challenge: options.challenge, origins: ORIGINS, rpId: RP_ID };
    expect(
      await verifyRegistration(
        await authenticator.register(options, ORIGIN, { residentKey: false }),
        expected,
      ),
    ).toEqual({ ok: false, error: "passkey_not_discoverable", reason: "credProps.rk is false" });
    expect(
      (
        await verifyRegistration(
          await authenticator.register(options, ORIGIN, { residentKey: true }),
          expected,
        )
      ).ok,
    ).toBe(true);
    expect(
      (await verifyRegistration(await authenticator.register(options, ORIGIN), expected)).ok,
    ).toBe(true);
  });

  it("[TIO-PK-012] rejects credential ids shorter than 16 or longer than 1023 bytes and accepts the bounds", async () => {
    const authenticator = new VirtualAuthenticator();
    const options = creation();
    const expected = { challenge: options.challenge, origins: ORIGINS, rpId: RP_ID };
    expect(
      await verifyRegistration(
        await authenticator.register(options, ORIGIN, { credentialIdLength: 15 }),
        expected,
      ),
    ).toEqual({
      ok: false,
      error: "passkey_verification_failed",
      reason: "credential id of 15 bytes",
    });
    expect(
      (
        await verifyRegistration(
          await authenticator.register(options, ORIGIN, { credentialIdLength: 16 }),
          expected,
        )
      ).ok,
    ).toBe(true);
    expect(
      (
        await verifyRegistration(
          await authenticator.register(options, ORIGIN, { credentialIdLength: 1023 }),
          expected,
        )
      ).ok,
    ).toBe(true);
    expect(
      await verifyRegistration(
        await authenticator.register(options, ORIGIN, { credentialIdLength: 1024 }),
        expected,
      ),
    ).toEqual({
      ok: false,
      error: "passkey_verification_failed",
      reason: "credential id of 1024 bytes",
    });
  });

  it("[TIO-PK-012] records the algorithm of EC2, OKP and RSA keys", async () => {
    for (const algorithm of [-7, -8, -257] as const) {
      const { passkey } = await registered(algorithm);
      expect(passkey.alg).toBe(algorithm);
    }
  });

  it("[TIO-PK-012] ignores attestation statements of other formats, valid or not (attestation_policy = ignore)", async () => {
    const authenticator = new VirtualAuthenticator();
    const options = creation();
    const expected = { challenge: options.challenge, origins: ORIGINS, rpId: RP_ID };
    const packed = await authenticator.register(options, ORIGIN, { fmt: "packed" });
    const evaluated = await verifyRegistrationResponse({
      response: packed,
      expectedChallenge: options.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
    expect(evaluated.verified && evaluated.registrationInfo?.fmt).toBe("packed");
    expect((await verifyRegistration(packed, expected)).ok).toBe(true);
    const badSignature = await authenticator.register(options, ORIGIN, {
      fmt: "packed",
      corruptSignature: true,
    });
    expect(
      await verifyRegistrationResponse({
        response: badSignature,
        expectedChallenge: options.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
      }),
    ).toEqual({ verified: false });
    expect((await verifyRegistration(badSignature, expected)).ok).toBe(true);
    const tpm = await authenticator.register(options, ORIGIN, { fmt: "tpm" });
    await expect(
      verifyRegistrationResponse({
        response: tpm,
        expectedChallenge: options.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
      }),
    ).rejects.toThrow();
    const accepted = await verifyRegistration(tpm, expected);
    expect(accepted.ok && accepted.passkey.credential_id).toBe(tpm.id);
  });
});

describe("assertion verification", () => {
  it("[TIO-PK-022] verifies type, challenge, origin, RP ID, UP and UV flags and the signature, returning the new counter", async () => {
    const { authenticator, passkey } = await registered();
    const stored = { credential_id: passkey.credential_id, public_key: passkey.public_key };
    const request = authenticationOptions(RP_ID, newChallenge());
    const expected = { challenge: request.challenge, origins: ORIGINS, rpId: RP_ID };
    const ok = await verifyAssertionSignature(
      await authenticator.authenticate(request, ORIGIN),
      stored,
      expected,
    );
    expect(ok).toEqual({ ok: true, newCounter: 1 });
    const fromApp = await verifyAssertionSignature(
      await authenticator.authenticate(request, "https://app.example.com"),
      stored,
      expected,
    );
    expect(fromApp).toEqual({ ok: true, newCounter: 2 });
    const cases: Record<string, Parameters<VirtualAuthenticator["authenticate"]>[2]> = {
      type: { type: "webauthn.create" },
      challenge: { challenge: newChallenge() },
      origin: { origin: "https://evil.example.net" },
      rpId: { rpId: "evil.example.net" },
      userPresent: { userPresent: false },
      userVerified: { userVerified: false },
      signature: { corruptSignature: true },
      foreignKey: { foreignKey: true },
    };
    for (const [name, faults] of Object.entries(cases)) {
      const response = await authenticator.authenticate(request, ORIGIN, faults);
      expect(await verifyAssertionSignature(response, stored, expected), name).toEqual({
        ok: false,
        error: "passkey_verification_failed",
      });
    }
    expect(await verifyAssertionSignature({ bad: 1 }, stored, expected)).toEqual({
      ok: false,
      error: "passkey_verification_failed",
    });
    const other = await registered();
    expect(
      await verifyAssertionSignature(
        await other.authenticator.authenticate(request, ORIGIN),
        stored,
        expected,
      ),
    ).toEqual({ ok: false, error: "passkey_verification_failed" });
    const identity = assertionIdentity(await authenticator.authenticate(request, ORIGIN));
    expect(identity).toEqual({
      credentialId: passkey.credential_id,
      userHandle: encodeBase64Url(userId),
    });
    expect(
      assertionIdentity(await authenticator.authenticate(request, ORIGIN, { omitUserHandle: true }))
        ?.userHandle,
    ).toBeNull();
    expect(assertionIdentity({})).toBeNull();
  });

  it("[TIO-PK-030] the counter policy accepts 0/0 and increases, and flags everything else as a regression", () => {
    expect(counterPolicy(0, 0)).toBe("accept");
    expect(counterPolicy(0, 1)).toBe("accept");
    expect(counterPolicy(5, 6)).toBe("accept");
    expect(counterPolicy(5, 5)).toBe("regression");
    expect(counterPolicy(5, 4)).toBe("regression");
    expect(counterPolicy(5, 0)).toBe("regression");
  });
});
