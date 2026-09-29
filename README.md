# socks5-greeting

Encodes and decodes the SOCKS5 method-selection handshake (RFC 1928, section 3): the client greeting (`VER | NMETHODS | METHODS...`) and the server reply (`VER | METHOD`). Nothing else.

## Usage

```js
import {
  encodeGreeting,
  decodeGreeting,
  encodeSelection,
  decodeSelection,
  METHODS,
  NO_ACCEPTABLE_METHODS,
} from "./src/index.js";

// Client side
const greeting = encodeGreeting([METHODS.NO_AUTH, METHODS.USERNAME_PASSWORD]);
// Uint8Array [0x05, 0x02, 0x00, 0x02]

// Server side
const { version, methods } = decodeGreeting(greeting);
const chosen = methods.includes(METHODS.USERNAME_PASSWORD)
  ? METHODS.USERNAME_PASSWORD
  : NO_ACCEPTABLE_METHODS;
const reply = encodeSelection(chosen);
// Uint8Array [0x05, 0x02]

const { method } = decodeSelection(reply);
```

## Why this exists

The SOCKS5 greeting is a tiny fixed-layout frame, but the layout has two easy-to-mishandle spots: the `NMETHODS` byte is a count (not a terminator), and the server reply is exactly two bytes with no length prefix. This library handles the bounds checking and version validation in one place so a client or server implementation does not have to re-derive it.

The trade-off: `decodeGreeting` expects the complete frame in a single buffer. It does not do streaming accumulation. If you are reading from a socket you must collect bytes until at least the header (2 bytes) is available, read `NMETHODS`, and keep reading until `2 + NMETHODS` bytes are present before calling this function. This keeps the decoder pure and side-effect free.

## Edge cases

- An empty `methods` array is a valid greeting (`NMETHODS = 0`). It means the client offers no authentication methods; the server will almost always reply with `0xFF`.
- Duplicate method bytes are preserved verbatim on encode and decode. RFC 1928 does not forbid repeats.
- Any version byte other than `0x05` causes a `RangeError` on decode. There is no fallback to SOCKS4.
- Method bytes are treated as opaque unsigned values; the `METHODS` constants are provided for convenience but are not enforced.

## Exports

- `SOCKS5_VERSION` — `0x05`
- `NO_ACCEPTABLE_METHODS` — `0xff`
- `METHODS` — frozen object: `{ NO_AUTH: 0x00, GSSAPI: 0x01, USERNAME_PASSWORD: 0x02, NO_ACCEPTABLE: 0xff }`
- `encodeGreeting(methods: number[]) -> Uint8Array`
- `decodeGreeting(buf: Uint8Array) -> { version: number, methods: number[] }`
- `encodeSelection(method: number) -> Uint8Array`
- `decodeSelection(buf: Uint8Array) -> { version: number, method: number }`

## Tests

```
node --test
```
