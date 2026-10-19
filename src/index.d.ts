export type Bytes = string | Uint8Array | ArrayBuffer;

export interface Codec {
  /** Strings are encoded as UTF-8. */
  encode(input: Bytes): string;
  /** Throws a SyntaxError on invalid input. */
  decode(text: string): Uint8Array;
}

export const base32: {
  encode(input: Bytes, options?: { padding?: boolean }): string;
  decode(text: string): Uint8Array;
};
export const base32Crockford: Codec;
export const hex: Codec;
export const base64url: Codec;
/** Throws a RangeError for more than 8192 bytes (the algorithm is quadratic). */
export const base58: Codec;
export function toText(bytes: Uint8Array): string;
