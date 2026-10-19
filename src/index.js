const encoder = new TextEncoder();
const bytesOf = (input) => {
  if (typeof input === "string") return encoder.encode(input);
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  throw new TypeError("expected a string, Uint8Array or ArrayBuffer");
};

function makeBaseN(alphabet, bitsPerChar, { pad = "", ignoreCase = false, name }) {
  const lookup = new Map([...alphabet].map((c, i) => [c, i]));
  if (ignoreCase) for (const [c, i] of [...lookup]) lookup.set(c.toLowerCase(), i);
  const mask = (1 << bitsPerChar) - 1;
  return {
    encode(input, { padding = pad !== "" } = {}) {
      const bytes = bytesOf(input);
      let out = "";
      let buffer = 0;
      let bits = 0;
      for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= bitsPerChar) {
          bits -= bitsPerChar;
          out += alphabet[(buffer >> bits) & mask];
        }
        buffer &= (1 << bits) - 1;
      }
      if (bits > 0) out += alphabet[(buffer << (bitsPerChar - bits)) & mask];
      if (padding && pad) while (out.length % (bitsPerChar === 5 ? 8 : 4) !== 0) out += pad;
      return out;
    },
    decode(text) {
      if (typeof text !== "string") throw new TypeError(`${name}: expected a string`);
      let clean = text.replace(/[\s-]/g, "");
      if (pad) clean = clean.replace(new RegExp(`${pad}+$`), "");
      const out = [];
      let buffer = 0;
      let bits = 0;
      for (const ch of clean) {
        const value = lookup.get(ch);
        if (value === undefined) throw new SyntaxError(`${name}: "${ch}" is not a valid character`);
        buffer = (buffer << bitsPerChar) | value;
        bits += bitsPerChar;
        if (bits >= 8) {
          bits -= 8;
          out.push((buffer >> bits) & 0xff);
        }
        buffer &= (1 << bits) - 1;
      }
      // What is left over is a partial byte: fewer bits than one character and all zero. More than that is a character too many.
      if (bits >= bitsPerChar) throw new SyntaxError(`${name}: the text has a length that no byte string encodes to`);
      if (buffer !== 0) throw new SyntaxError(`${name}: the last character has stray bits; the text is not canonical`);
      return Uint8Array.from(out);
    }
  };
}

/** RFC 4648 base32 (A-Z, 2-7), as used by authenticator apps. Decoding ignores case, spaces, dashes and padding. */
export const base32 = makeBaseN("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 5, { pad: "=", ignoreCase: true, name: "base32" });

/** Crockford base32: no I, L, O, U; decoding reads O as 0 and I or L as 1, so people can type it from paper. */
const crockfordBase = makeBaseN("0123456789ABCDEFGHJKMNPQRSTVWXYZ", 5, { ignoreCase: true, name: "base32 (Crockford)" });
export const base32Crockford = {
  encode: (input) => crockfordBase.encode(input),
  decode: (text) => crockfordBase.decode(typeof text === "string" ? text.replace(/[oO]/g, "0").replace(/[iIlL]/g, "1") : text)
};

/** Hexadecimal. Decoding refuses odd lengths and non-hex characters (Node's own decoder silently stops). */
export const hex = {
  encode(input) {
    return Array.from(bytesOf(input), (b) => b.toString(16).padStart(2, "0")).join("");
  },
  decode(text) {
    if (typeof text !== "string") throw new TypeError("hex: expected a string");
    if (text.length % 2 !== 0 || /[^0-9a-f]/i.test(text)) throw new SyntaxError("hex: not a valid hexadecimal string");
    return Uint8Array.from(text.match(/../g) ?? [], (h) => parseInt(h, 16));
  }
};

/** URL-safe base64 without padding. Decoding is strict: invalid characters, impossible lengths and non-zero spare bits in the last character all throw (Node's decoder accepts them). Padding `=` is accepted and ignored. */
export const base64url = {
  encode: (input) => Buffer.from(bytesOf(input)).toString("base64url"),
  decode(text) {
    if (typeof text !== "string") throw new TypeError("base64url: expected a string");
    const clean = text.replace(/=+$/, "");
    if (!/^[A-Za-z0-9_-]*$/.test(clean) || clean.length % 4 === 1) throw new SyntaxError("base64url: not a valid base64url string");
    const decoded = Buffer.from(clean, "base64url");
    if (decoded.toString("base64url") !== clean) throw new SyntaxError("base64url: the last character has stray bits; the text is not canonical");
    return new Uint8Array(decoded);
  }
};

const BASE58_MAX_BYTES = 8192; // the algorithm is quadratic: 20 000 bytes already take about two seconds, and it blocks the event loop
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/** Base58 (Bitcoin alphabet): no 0, O, I, l. Leading zero bytes are kept as leading 1s. */
export const base58 = {
  encode(input) {
    const bytes = bytesOf(input);
    if (bytes.length > BASE58_MAX_BYTES) throw new RangeError(`base58: input is limited to ${BASE58_MAX_BYTES} bytes`);
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    const digits = [];
    for (let i = zeros; i < bytes.length; i++) {
      let carry = bytes[i];
      for (let j = 0; j < digits.length; j++) {
        carry += digits[j] * 256;
        digits[j] = carry % 58;
        carry = Math.floor(carry / 58);
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = Math.floor(carry / 58);
      }
    }
    return "1".repeat(zeros) + digits.reverse().map((d) => B58[d]).join("");
  },
  decode(text) {
    if (typeof text !== "string") throw new TypeError("base58: expected a string");
    if (text.length > Math.ceil(BASE58_MAX_BYTES * 1.4)) throw new RangeError(`base58: text is limited to ${Math.ceil(BASE58_MAX_BYTES * 1.4)} characters`);
    let zeros = 0;
    while (zeros < text.length && text[zeros] === "1") zeros++;
    const bytes = [];
    for (let i = zeros; i < text.length; i++) {
      const value = B58.indexOf(text[i]);
      if (value < 0) throw new SyntaxError(`base58: "${text[i]}" is not a valid character`);
      let carry = value;
      for (let j = 0; j < bytes.length; j++) {
        carry += bytes[j] * 58;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }
    return Uint8Array.from([...new Array(zeros).fill(0), ...bytes.reverse()]);
  }
};

/** Turns decoded bytes into text (UTF-8). Throws on invalid UTF-8; a leading byte order mark is kept. */
export const toText = (bytes) => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
