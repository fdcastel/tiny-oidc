import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env.ts";

/** One object per authorization, logout or PAR interaction (spec §4.3). */
export class InteractionDO extends DurableObject<Env> {}
