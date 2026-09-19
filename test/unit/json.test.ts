import { describe, expect, it } from "vitest";
import { z } from "zod";
import { parseJson, readJsonBody } from "../../src/util/json.ts";

const schema = z.object({ name: z.string(), n: z.int().optional() });

describe("json parsing through a schema", () => {
  it("returns the validated value or a description of the first problem", () => {
    expect(parseJson(schema, '{"name":"a","n":1}')).toEqual({
      ok: true,
      value: { name: "a", n: 1 },
    });
    expect(parseJson(schema, "{")).toEqual({ ok: false, error: "malformed_json" });
    expect(parseJson(schema, '{"n":"x"}')).toEqual({
      ok: false,
      error:
        "name: Invalid input: expected string, received undefined; n: Invalid input: expected number, received string",
    });
    expect(parseJson(z.number(), "5")).toEqual({ ok: true, value: 5 });
    const top = parseJson(z.number(), '"s"');
    expect(top.ok).toBe(false);
    if (!top.ok) expect(top.error).toMatch(/^\$: /);
  });

  it("reads a body within the size limit and rejects larger ones before parsing", async () => {
    const body = (text: string) =>
      new Request("https://op.example/x", { method: "POST", body: text });
    expect(await readJsonBody(body('{"name":"a"}'), schema, 64)).toEqual({
      ok: true,
      value: { name: "a" },
    });
    expect(await readJsonBody(body(`{"name":"${"é".repeat(40)}"}`), schema, 64)).toEqual({
      ok: false,
      error: "payload_too_large",
    });
    expect(await readJsonBody(body("nope"), schema, 64)).toEqual({
      ok: false,
      error: "malformed_json",
    });
  });
});
