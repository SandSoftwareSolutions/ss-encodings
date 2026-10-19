import assert from "node:assert/strict";
import { randomBytes as randomBytesNode } from "node:crypto";
import { test } from "node:test";

import { base32, base32Crockford, base58, base64url, hex, toText } from "./src/index.js";

const bytes = (...n) => Uint8Array.from(n);

test("base32 matches the RFC 4648 test vectors", () => {
  const vectors = { "": "", f: "MY======", fo: "MZXQ====", foo: "MZXW6===", foob: "MZXW6YQ=", fooba: "MZXW6YTB", foobar: "MZXW6YTBOI======" };
  for (const [plain, encoded] of Object.entries(vectors)) {
    assert.equal(base32.encode(plain), encoded, plain);
    assert.equal(toText(base32.decode(encoded)), plain, plain);
  }
  assert.equal(base32.encode("foobar", { padding: false }), "MZXW6YTBOI");
});

test("base32 decoding is forgiving about layout but strict about content", () => {
  assert.equal(toText(base32.decode("mzxw 6ytb-oi")), "foobar");
  assert.equal(toText(base32.decode("MZXW6YTBOI")), "foobar");
  assert.throws(() => base32.decode("MZXW1"), SyntaxError); // 1 is not in the alphabet
  assert.throws(() => base32.decode("MZ"), SyntaxError); // stray bits
  assert.throws(() => base32.decode(5), TypeError);
});

test("an authenticator secret survives a round trip", () => {
  const secret = bytes(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22);
  assert.deepEqual(base32.decode(base32.encode(secret)), secret);
});

test("Crockford reads typos the way people mean them", () => {
  const encoded = base32Crockford.encode("hello");
  assert.deepEqual(base32Crockford.decode(encoded), new TextEncoder().encode("hello"));
  assert.deepEqual(base32Crockford.decode("0O1IL000"), base32Crockford.decode("00111000"));
  assert.ok(!/[ILOU]/.test(base32Crockford.encode(new Uint8Array(100).map((_, i) => i * 7))));
});

test("hex is strict", () => {
  assert.equal(hex.encode(bytes(0, 15, 255)), "000fff");
  assert.deepEqual(hex.decode("000FFF"), bytes(0, 15, 255));
  assert.deepEqual(hex.decode(""), bytes());
  assert.throws(() => hex.decode("abc"), SyntaxError);
  assert.throws(() => hex.decode("zz"), SyntaxError);
});

test("base64url is strict and URL safe", () => {
  const data = bytes(251, 255, 190, 0, 1);
  const text = base64url.encode(data);
  assert.ok(!/[+/=]/.test(text));
  assert.deepEqual(base64url.decode(text), data);
  assert.deepEqual(base64url.decode(`${text}==`), data);
  assert.throws(() => base64url.decode("ab+/"), SyntaxError);
  assert.throws(() => base64url.decode("a"), SyntaxError);
  assert.equal(base64url.encode("Many hands make light work."), "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");
});

test("base58 known values and leading zeros", () => {
  assert.equal(base58.encode("Hello World!"), "2NEpo7TZRRrLZSi2U");
  assert.equal(base58.encode(bytes(0, 0, 1)), "112");
  assert.deepEqual(base58.decode("112"), bytes(0, 0, 1));
  assert.equal(base58.encode(bytes()), "");
  assert.deepEqual(base58.decode(""), bytes());
  assert.throws(() => base58.decode("0OIl"), SyntaxError);
  for (const n of [1, 2, 3, 10, 33]) {
    const data = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 5) % 256);
    assert.deepEqual(base58.decode(base58.encode(data)), data);
  }
});

test("inputs: strings, bytes, buffers; anything else is refused", () => {
  assert.equal(hex.encode("a"), "61");
  assert.equal(hex.encode(new Uint8Array([97]).buffer), "61");
  assert.throws(() => hex.encode(5), TypeError);
  assert.throws(() => toText(bytes(0xff, 0xfe)));
});

// Round trips and comparisons with independent references, on random input of every length around the block sizes.
const randomBytes = (n) => new Uint8Array(randomBytesNode(n));
const lengths = [...Array.from({ length: 70 }, (_, i) => i), 255, 256, 257, 1000, 4097];

function referenceBase32(data, alphabet) {
  let bits = "";
  for (const b of data) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += alphabet[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out;
}
function referenceBase58(data) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  let zeros = 0;
  while (zeros < data.length && data[zeros] === 0) zeros++;
  return "1".repeat(zeros) + out;
}

test("fuzz: hex and base64url agree with Buffer, both ways", () => {
  for (const n of lengths) {
    for (let round = 0; round < 5; round++) {
      const data = randomBytes(n);
      assert.equal(hex.encode(data), Buffer.from(data).toString("hex"));
      assert.deepEqual(hex.decode(hex.encode(data)), data);
      assert.deepEqual(hex.decode(hex.encode(data).toUpperCase()), data);
      assert.equal(base64url.encode(data), Buffer.from(data).toString("base64url"));
      assert.deepEqual(base64url.decode(base64url.encode(data)), data);
      assert.deepEqual(base64url.decode(`${base64url.encode(data)}${"=".repeat((3 - (data.length % 3)) % 3)}`), data); // correctly padded input is accepted
    }
  }
});

test("fuzz: base32 and Crockford agree with a bit-string reference and round trip", () => {
  const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const crock = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  for (const n of lengths) {
    for (let round = 0; round < 5; round++) {
      const data = randomBytes(n);
      const plain = referenceBase32(data, std);
      assert.equal(base32.encode(data, { padding: false }), plain);
      assert.equal(base32.encode(data), plain + "=".repeat((8 - (plain.length % 8)) % 8));
      assert.deepEqual(base32.decode(base32.encode(data)), data);
      assert.deepEqual(base32.decode(plain.toLowerCase()), data);
      assert.equal(base32Crockford.encode(data), referenceBase32(data, crock));
      assert.deepEqual(base32Crockford.decode(base32Crockford.encode(data)), data);
      assert.deepEqual(base32Crockford.decode(base32Crockford.encode(data).toLowerCase()), data);
    }
  }
});

test("fuzz: base58 agrees with a BigInt reference and round trips, with leading zero bytes", () => {
  for (const n of [...Array.from({ length: 40 }, (_, i) => i), 100, 300]) {
    for (let round = 0; round < 5; round++) {
      const data = randomBytes(n);
      if (round % 2 === 0) data.fill(0, 0, Math.min(n, round));
      assert.equal(base58.encode(data), referenceBase58(data));
      assert.deepEqual(base58.decode(base58.encode(data)), data);
    }
  }
});

test("base32 refuses lengths that no byte string can produce", () => {
  // 1, 3 and 6 characters (mod 8) leave 5 bits or more over, which is not a valid encoding even when those bits are zero
  for (const text of ["A", "AAA", "AAAAAA", "MZXW6YTBOIA", "MZXW6YTBOIAAAA"]) {
    assert.throws(() => base32.decode(text), SyntaxError, text);
  }
  assert.throws(() => base32Crockford.decode("0"), SyntaxError);
  assert.throws(() => base32Crockford.decode("000"), SyntaxError);
  assert.deepEqual(base32.decode("AA"), bytes(0)); // 2 characters = 1 byte
  assert.deepEqual(base32.decode("AAAA"), bytes(0, 0));
});

test("base64url refuses text whose last character carries bits that are not data (it must be canonical)", () => {
  assert.deepEqual(base64url.decode("TQ"), bytes(77));
  assert.throws(() => base64url.decode("TR"), SyntaxError); // decodes to the same byte as "TQ" in Node
  assert.deepEqual(base64url.decode("TWE"), bytes(77, 97)); // 3 characters, last one carries 2 spare bits that are zero
  assert.throws(() => base64url.decode("TWF"), SyntaxError); // spare bits not zero
});

test("toText keeps a byte order mark instead of silently dropping it", () => {
  const text = "﻿hello";
  assert.equal(toText(base64url.decode(base64url.encode(text))), text);
  assert.equal(toText(hex.decode("efbbbf41")), "﻿A");
});

test("base58 refuses input large enough to freeze the process", () => {
  assert.throws(() => base58.encode(new Uint8Array(1_000_000)), RangeError);
  assert.throws(() => base58.decode("z".repeat(1_000_000)), RangeError);
  assert.equal(base58.decode(base58.encode(randomBytes(4096))).length, 4096);
});
