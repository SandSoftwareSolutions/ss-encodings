import assert from "node:assert/strict";
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
