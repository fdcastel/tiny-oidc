import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import snapshot from "../../doc/openapi.json" with { type: "json" };
import { TEST_ENV } from "../support/keys.ts";

describe("OpenAPI snapshot", () => {
  it("the served document equals the committed doc/openapi.json (drift check, §5.1)", async () => {
    const res = await SELF.fetch(`${TEST_ENV.ISSUER}/api/v1/openapi.json`);
    expect(await res.json()).toEqual(snapshot);
  });
});
