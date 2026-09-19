import { type Env, systemClock } from "./env.ts";
import { createApp } from "./router/app.ts";

export { InteractionDO } from "./do/InteractionDO.ts";
export { UserDO } from "./do/UserDO.ts";

// Single Worker script exporting fetch, queue and scheduled handlers and the two
// Durable Object classes (TIO-ARCH-001). queue() and scheduled() arrive in
// Phases 6 and 3. One app instance per isolate: its caches are isolate caches.
const app = createApp({ clock: systemClock });

export default {
  fetch: app.fetch,
} satisfies ExportedHandler<Env>;
