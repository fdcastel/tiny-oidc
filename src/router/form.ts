// Form bodies of the protocol endpoints (TIO-TOKEN-001): only
// `application/x-www-form-urlencoded`, and every parameter at most once.

export const FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

export type ParamsResult =
  | { ok: true; params: Map<string, string> }
  | { ok: false; reason: "duplicate parameter" };

export type FormResult = ParamsResult | { ok: false; reason: "unsupported content type" };

/** The parameters of a query or form body, refusing any name that appears twice (TIO-AUTHZ-001, TIO-TOKEN-001). */
export function uniqueParams(source: URLSearchParams): ParamsResult {
  const params = new Map<string, string>();
  for (const [name, value] of source) {
    if (params.has(name)) return { ok: false, reason: "duplicate parameter" };
    params.set(name, value);
  }
  return { ok: true, params };
}

/** The body's parameters, or why it was refused. The body size has been limited upstream. */
export async function readForm(request: Request): Promise<FormResult> {
  const contentType = request.headers.get("content-type") ?? "";
  const mediaType = (contentType.split(";")[0] as string).trim().toLowerCase();
  if (mediaType !== FORM_CONTENT_TYPE) return { ok: false, reason: "unsupported content type" };
  return uniqueParams(new URLSearchParams(await request.text()));
}
