import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env.ts";

/** One object per user: the source of truth for everything about that user (spec §2.3, §4.2). */
export class UserDO extends DurableObject<Env> {}
