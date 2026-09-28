/**
 * Core encode/decode logic for the SOCKS5 method-selection greeting.
 *
 * Wire format (RFC 1928, section 3):
 *   Client greeting:  VER | NMETHODS | METHODS...
 *     VER      1 byte  must be 0x05
 *     NMETHODS 1 byte  number of method bytes that follow (0-255)
 *     METHODS  0-255 bytes, one per authentication method the client offers
 *   Server selection: VER | METHOD
 *     VER    1 byte  must be 0x05
 *     METHOD 1 byte  the method the server chose (0xFF = no acceptable methods)
 */

export const SOCKS5_VERSION = 0x05;

export const NO_ACCEPTABLE_METHODS = 0xff;

/**
 * Well-known method bytes from RFC 1928 / RFC 1929.
 * Listed here so callers do not have to memorize magic numbers, but the
 * encoder/decoder itself treats method bytes as opaque unsigned values.
 */
export const METHODS = Object.freeze({
  NO_AUTH: 0x00,
  GSSAPI: 0x01,
  USERNAME_PASSWORD: 0x02,
  NO_ACCEPTABLE: 0xff,
});

/**
 * Encode a client greeting.
 *
 * @param {number[]} methods - Array of method bytes (each 0-255). Duplicates are
 *   preserved verbatim; we do not de-duplicate because RFC 1928 does not forbid
 *   repeats and a server may legitimately treat them as a preference signal.
 *   An empty array is valid on the wire (NMETHODS = 0) and means the client
 *   offers no authentication methods.
 * @returns {Uint8Array} The greeting bytes ready to write to a socket.
 * @throws {TypeError} If `methods` is not an array-like of integers.
 * @throws {RangeError} If the count exceeds 255 or any byte is out of range.
 */
export function encodeGreeting(methods) {
  if (methods == null || typeof methods[Symbol.iterator] !== "function") {
    throw new TypeError("methods must be iterable");
  }
  const arr = Array.from(methods);
  if (arr.length > 255) {
    throw new RangeError("methods length must be 0-255");
  }
  const out = new Uint8Array(arr.length + 2);
  out[0] = SOCKS5_VERSION;
  out[1] = arr.length;
  for (let i = 0; i < arr.length; i++) {
    const m = arr[i];
    if (!Number.isInteger(m) || m < 0 || m > 255) {
      throw new RangeError(`method at index ${i} must be an integer 0-255, got ${m}`);
    }
    out[i + 2] = m;
  }
  return out;
}

/**
 * Decode a client greeting from a buffer.
 *
 * We deliberately do NOT accept a streaming/partial buffer: the caller is
 * responsible for accumulating bytes until at least NMETHODS is readable and
 * then the full METHODS span. This keeps the function pure and side-effect free.
 *
 * @param {Uint8Array|Buffer} buf - The greeting bytes. Must contain the full frame.
 * @returns {{version: number, methods: number[]}} Parsed greeting.
 * @throws {TypeError} If `buf` is not a byte array-like.
 * @throws {RangeError} If the buffer is too short, the version is wrong, or the
 *   declared NMETHODS does not match the available bytes.
 */
export function decodeGreeting(buf) {
  if (!buf || typeof buf.length !== "number") {
    throw new TypeError("buf must be a byte array-like");
  }
  const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (view.length < 2) {
    throw new RangeError("buffer too short for greeting header");
  }
  const version = view[0];
  if (version !== SOCKS5_VERSION) {
    throw new RangeError(`unsupported SOCKS version: ${version}`);
  }
  const nmethods = view[1];
  if (view.length < 2 + nmethods) {
    throw new RangeError(
      `buffer too short: declared ${nmethods} methods but only ${view.length - 2} bytes available`,
    );
  }
  const methods = [];
  for (let i = 0; i < nmethods; i++) {
    methods.push(view[2 + i]);
  }
  return { version, methods };
}

/**
 * Encode a server method-selection reply.
 *
 * @param {number} method - The chosen method byte (0-255). Use 0xFF when none
 *   of the client's offered methods are acceptable.
 * @returns {Uint8Array} Two bytes: [0x05, method].
 * @throws {RangeError} If `method` is not an integer in range.
 */
export function encodeSelection(method) {
  if (!Number.isInteger(method) || method < 0 || method > 255) {
    throw new RangeError(`method must be an integer 0-255, got ${method}`);
  }
  return new Uint8Array([SOCKS5_VERSION, method]);
}

/**
 * Decode a server method-selection reply.
 *
 * @param {Uint8Array|Buffer} buf - At least two bytes.
 * @returns {{version: number, method: number}} Parsed selection.
 * @throws {TypeError} If `buf` is not a byte array-like.
 * @throws {RangeError} If too short or the version byte is not 0x05.
 */
export function decodeSelection(buf) {
  if (!buf || typeof buf.length !== "number") {
    throw new TypeError("buf must be a byte array-like");
  }
  const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (view.length < 2) {
    throw new RangeError("buffer too short for selection reply");
  }
  const version = view[0];
  if (version !== SOCKS5_VERSION) {
    throw new RangeError(`unsupported SOCKS version: ${version}`);
  }
  return { version, method: view[1] };
}
