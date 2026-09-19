import type { Env } from "./env.ts";

export { InteractionDO } from "./do/InteractionDO.ts";
export { UserDO } from "./do/UserDO.ts";

// Single Worker script exporting fetch, queue and scheduled handlers and the two
// Durable Object classes (TIO-ARCH-001). Handlers are filled in by later tasks.
export default {
  async fetch(_request: Request, _env: Env, _ctx: ExecutionContext): Promise<Response> {
    return Response.json({ error: "not_found" }, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
