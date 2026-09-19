import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";

// JSON error model (TIO-ERR-001): `{ error, error_description, request_id }`.
// The description is printable ASCII, at most 256 characters, and never
// carries user data, secrets, SQL, stack traces or storage identifiers.

export interface ErrorBody {
  error: string;
  error_description: string;
  request_id: string;
}

/** Sanitizes a description to printable ASCII of at most 256 characters. */
export function sanitizeDescription(text: string): string {
  return text.replace(/[^\x20-\x7e]/g, "?").slice(0, 256);
}

export function errorBody(requestId: string, error: string, description: string): ErrorBody {
  return { error, error_description: sanitizeDescription(description), request_id: requestId };
}

export function errorResponse(
  c: Context,
  status: ContentfulStatusCode,
  error: string,
  description: string,
  headers: Record<string, string> = {},
): Response {
  const requestId = c.get("requestId") as string;
  c.set("error", error);
  return c.json(errorBody(requestId, error, description), status, headers);
}
