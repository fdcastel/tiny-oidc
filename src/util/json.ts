import type { z } from "zod";

// The only place JSON is parsed (lint rule no-unvalidated-json): every parse
// goes through a zod schema, so handlers never touch unvalidated JSON.

export type ParseResult<T> = { ok: true; value: T } | { ok: false; error: string };

export function parseJson<T>(schema: z.ZodType<T>, text: string): ParseResult<T> {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, error: "malformed_json" };
  }
  const result = schema.safeParse(raw);
  return result.success
    ? { ok: true, value: result.data }
    : {
        ok: false,
        error: result.error.issues
          .map((i) => `${i.path.join(".") || "$"}: ${i.message}`)
          .join("; "),
      };
}

/** Reads and validates a JSON body. Bodies over `limit` bytes are rejected before parsing. */
export async function readJsonBody<T>(
  request: Request,
  schema: z.ZodType<T>,
  limit: number,
): Promise<ParseResult<T> | { ok: false; error: "payload_too_large" }> {
  const text = await request.text();
  if (new TextEncoder().encode(text).length > limit)
    return { ok: false, error: "payload_too_large" };
  return parseJson(schema, text);
}
