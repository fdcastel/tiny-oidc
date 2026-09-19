import { describe, expect, it } from "vitest";
import snapshot from "../../doc/openapi.json" with { type: "json" };
import { op } from "../support/op.ts";

describe("OpenAPI snapshot", () => {
  it("the served document equals the committed doc/openapi.json (drift check, §5.1)", async () => {
    const res = await op("/api/v1/openapi.json");
    expect(await res.json()).toEqual(snapshot);
  });
});
