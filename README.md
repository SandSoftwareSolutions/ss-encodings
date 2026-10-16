# @sandsoftwaresolutions/encodings

[![CI](https://github.com/SandSoftwareSolutions/ss-encodings/actions/workflows/ci.yml/badge.svg)](https://github.com/SandSoftwareSolutions/ss-encodings/actions/workflows/ci.yml)

Base32, base58, base64url and hex with **strict** decoding. Node's own `Buffer.from(text, "hex")` quietly stops at the first bad character; these throw an error you can act on. No dependencies.

## Install

```bash
npm install @sandsoftwaresolutions/encodings
```

## Usage

```js
import { base32, base32Crockford, base58, base64url, hex, toText } from "@sandsoftwaresolutions/encodings";

base32.encode("foobar");                // "MZXW6YTBOI======"
base32.encode("foobar", { padding: false });
base32.decode("mzxw 6ytb-oi");          // Uint8Array; case, spaces and dashes are ignored
toText(base32.decode("MZXW6YTBOI"));    // "foobar"

base64url.encode(bytes);                // URL safe, no padding
hex.decode("00ff");                     // Uint8Array [0, 255]
base58.encode(bytes);                   // no 0, O, I or l: safe to read aloud
base32Crockford.decode("0O1IL000");     // O reads as 0, I and L as 1
```

Every codec has `encode(input)` (a string is encoded as UTF-8; `Uint8Array` and `ArrayBuffer` are taken as they are) and `decode(text)` (returns a `Uint8Array`).

## Which one?

| Codec | Use for |
| --- | --- |
| `base32` | RFC 4648, what authenticator apps and TOTP secrets use |
| `base32Crockford` | codes people copy from paper or read over the phone (no I, L, O, U) |
| `base58` | short ids without look-alike characters |
| `base64url` | tokens in URLs and JWTs |
| `hex` | hashes and debugging |

## Strictness

- Invalid characters, an odd-length hex string, an impossible base64url length, or a base32 text whose last character carries stray bits throw a `SyntaxError`.
- Whitespace and dashes are allowed in base32 on purpose: people type secrets in groups.
