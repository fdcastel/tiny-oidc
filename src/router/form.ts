// Form bodies of the protocol endpoints (TIO-TOKEN-001): only
// `application/x-www-form-urlencoded`, and every parameter at most once.

export const FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

export type FormResult =
  | { ok: true; params: Map<string, string> }
  | { ok: false; reason: "unsupported content type" | "duplicate parameter" };

/** The body's parameters, or why it was refused. The body size has been limited upstream. */
export async function readForm(request: Request): Promise<FormResult> {
  const contentType = request.headers.get("content-type") ?? "";
  const mediaType = (contentType.split(";")[0] as string).trim().toLowerCase();
  if (mediaType !== FORM_CONTENT_TYPE) return { ok: false, reason: "unsupported content type" };
  const params = new Map<string, string>();
  for (const [name, value] of new URLSearchParams(await request.text())) {
    if (params.has(name)) return { ok: false, reason: "duplicate parameter" };
    params.set(name, value);
  }
  return { ok: true, params };
}
