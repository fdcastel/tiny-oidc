import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  HANDLE_TYPES,
  type HandleType,
  openHandle,
  sealHandle,
} from "../../src/crypto/envelope.ts";
import { decodeBase64Url, encodeBase64Url } from "../../src/util/base64url.ts";
import { testKeys } from "../support/keys.ts";

const keys = testKeys("1");
const types = Object.keys(HANDLE_TYPES) as HandleType[];

function fieldsArb(type: HandleType) {
  const spec = HANDLE_TYPES[type];
  const shape: Record<string, fc.Arbitrary<Uint8Array>> = {};
  for (const [name, length] of spec.fields)
    shape[name] = fc.uint8Array({ minLength: length, maxLength: length });
  return fc.record(shape);
}

/** Flips one bit of one character of the base64url payload, or of the prefix. */
function flipBit(handle: string, charIndex: number, bit: number): string {
  const code = handle.charCodeAt(charIndex) ^ (1 << bit);
  return handle.slice(0, charIndex) + String.fromCharCode(code) + handle.slice(charIndex + 1);
}

describe("envelope properties", () => {
  it("[TIO-ARCH-006] round-trips random fields of every type and rejects every single-bit flip", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...types),
        fc.nat({ max: 200 }),
        fc.integer({ min: 0, max: 6 }),
        async (type, position, bit) => {
          const fields = await fc.sample(fieldsArb(type), 1)[0];
          const handle = await sealHandle(keys, type, fields as never);
          const opened = await openHandle(keys, type, handle);
          expect(opened).toEqual(fields);
          const index = position % handle.length;
          const flipped = flipBit(handle, index, bit);
          if (flipped !== handle) expect(await openHandle(keys, type, flipped)).toBeNull();
        },
      ),
      { numRuns: 200 },
    );
  });

  it("[TIO-ARCH-006] rejects random strings and random bytes of the right length", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...types),
        fc.string({ maxLength: 120 }),
        async (type, junk) => {
          expect(await openHandle(keys, type, junk)).toBeNull();
          expect(await openHandle(keys, type, `${HANDLE_TYPES[type].prefix}_${junk}`)).toBeNull();
        },
      ),
      { numRuns: 200 },
    );
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...types),
        fc.uint8Array({ minLength: 79, maxLength: 95 }),
        async (type, bytes) => {
          expect(
            await openHandle(keys, type, `${HANDLE_TYPES[type].prefix}_${encodeBase64Url(bytes)}`),
          ).toBeNull();
        },
      ),
      { numRuns: 100 },
    );
  });

  it("base64url decodes exactly what it encodes and nothing non-canonical", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        const text = encodeBase64Url(bytes);
        expect(text).toMatch(/^[A-Za-z0-9_-]*$/);
        expect(decodeBase64Url(text)).toEqual(bytes);
      }),
    );
  });
});
