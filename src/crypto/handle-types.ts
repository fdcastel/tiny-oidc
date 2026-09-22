// The handle table of spec §2.4: one entry per type, with its prefix, type
// byte and fixed-width plaintext layout. It lives apart from the envelope so
// Node-side tooling (the threat-surface snapshot, `pnpm surface`) can read the
// table without the Workers crypto types that `envelope.ts` pulls in.

type FieldLayout = readonly (readonly [name: string, length: number])[];

export interface HandleSpec {
  prefix: string;
  type: number;
  fields: FieldLayout;
}

/** One entry per handle type of §2.4, with the fixed-width plaintext layout. */
export const HANDLE_TYPES = {
  session: {
    prefix: "tio_ss",
    type: 0x01,
    fields: [
      ["uid", 16],
      ["sid", 16],
      ["secret", 32],
    ],
  },
  code: {
    prefix: "tio_ac",
    type: 0x02,
    fields: [
      ["uid", 16],
      ["secret", 32],
    ],
  },
  refresh: {
    prefix: "tio_rt",
    type: 0x03,
    fields: [
      ["uid", 16],
      ["family", 16],
      ["secret", 32],
    ],
  },
  interaction: {
    prefix: "tio_ix",
    type: 0x04,
    fields: [
      ["ixid", 32],
      ["secret", 32],
    ],
  },
  federation: {
    prefix: "tio_fs",
    type: 0x05,
    fields: [
      ["ixid", 32],
      ["secret", 32],
    ],
  },
  invitation: {
    prefix: "tio_iv",
    type: 0x06,
    fields: [
      ["invid", 16],
      ["secret", 32],
    ],
  },
} as const satisfies Record<string, HandleSpec>;

export type HandleType = keyof typeof HANDLE_TYPES;

type FieldNames<T extends HandleType> = (typeof HANDLE_TYPES)[T]["fields"][number][0];
export type HandleFields<T extends HandleType> = Record<FieldNames<T>, Uint8Array>;
