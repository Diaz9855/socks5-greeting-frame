import { test } from "node:test";
import assert from "node:assert/strict";

import {
  encodeGreeting,
  decodeGreeting,
  encodeSelection,
  decodeSelection,
  SOCKS5_VERSION,
  NO_ACCEPTABLE_METHODS,
  METHODS,
} from "../src/index.js";

test("encodeGreeting produces the correct wire bytes", () => {
  const out = encodeGreeting([0x00, 0x02]);
  assert.deepEqual(Array.from(out), [0x05, 0x02, 0x00, 0x02]);
});

test("encodeGreeting accepts an empty methods array (NMETHODS=0)", () => {
  const out = encodeGreeting([]);
  assert.deepEqual(Array.from(out), [0x05, 0x00]);
});

test("encodeGreeting preserves duplicate methods verbatim", () => {
  const out = encodeGreeting([0x00, 0x00, 0x02]);
  assert.deepEqual(Array.from(out), [0x05, 0x03, 0x00, 0x00, 0x02]);
});

test("encodeGreeting rejects more than 255 methods", () => {
  const tooMany = Array(256).fill(0x00);
  assert.throws(() => encodeGreeting(tooMany), RangeError);
});

test("encodeGreeting rejects non-integer method values", () => {
  assert.throws(() => encodeGreeting([0x00, 1.5]), RangeError);
});

test("encodeGreeting rejects out-of-range method values", () => {
  assert.throws(() => encodeGreeting([-1]), RangeError);
  assert.throws(() => encodeGreeting([256]), RangeError);
});

test("encodeGreeting rejects non-iterable input", () => {
  assert.throws(() => encodeGreeting(42), TypeError);
  assert.throws(() => encodeGreeting(null), TypeError);
});

test("decodeGreeting parses a well-formed greeting", () => {
  const buf = new Uint8Array([0x05, 0x02, 0x00, 0x02]);
  const result = decodeGreeting(buf);
  assert.equal(result.version, 0x05);
  assert.deepEqual(result.methods, [0x00, 0x02]);
});

test("decodeGreeting parses a greeting with zero methods", () => {
  const result = decodeGreeting(new Uint8Array([0x05, 0x00]));
  assert.deepEqual(result.methods, []);
});

test("decodeGreeting rejects a buffer shorter than the header", () => {
  assert.throws(() => decodeGreeting(new Uint8Array([0x05])), RangeError);
});

test("decodeGreeting rejects a buffer shorter than declared NMETHODS", () => {
  assert.throws(() => decodeGreeting(new Uint8Array([0x05, 0x03, 0x00])), RangeError);
});

test("decodeGreeting rejects the wrong SOCKS version", () => {
  assert.throws(() => decodeGreeting(new Uint8Array([0x04, 0x00])), RangeError);
});

test("decodeGreeting accepts a plain Buffer (array-like coercion)", () => {
  const buf = Buffer.from([0x05, 0x01, 0x02]);
  const result = decodeGreeting(buf);
  assert.deepEqual(result.methods, [0x02]);
});

test("encodeSelection produces two bytes", () => {
  const out = encodeSelection(METHODS.NO_AUTH);
  assert.deepEqual(Array.from(out), [0x05, 0x00]);
});

test("encodeSelection encodes the no-acceptable-methods reply", () => {
  const out = encodeSelection(NO_ACCEPTABLE_METHODS);
  assert.deepEqual(Array.from(out), [0x05, 0xff]);
});

test("encodeSelection rejects out-of-range method bytes", () => {
  assert.throws(() => encodeSelection(-1), RangeError);
  assert.throws(() => encodeSelection(256), RangeError);
  assert.throws(() => encodeSelection(1.5), RangeError);
});

test("decodeSelection parses a valid reply", () => {
  const result = decodeSelection(new Uint8Array([0x05, 0x02]));
  assert.equal(result.version, SOCKS5_VERSION);
  assert.equal(result.method, 0x02);
});

test("decodeSelection rejects a short buffer", () => {
  assert.throws(() => decodeSelection(new Uint8Array([0x05])), RangeError);
});

test("decodeSelection rejects the wrong version", () => {
  assert.throws(() => decodeSelection(new Uint8Array([0x04, 0x00])), RangeError);
});

test("encode then decode round-trips a greeting", () => {
  const methods = [0x00, 0x01, 0x02];
  const encoded = encodeGreeting(methods);
  const decoded = decodeGreeting(encoded);
  assert.deepEqual(decoded.methods, methods);
  assert.equal(decoded.version, SOCKS5_VERSION);
});

test("encode then decode round-trips a selection", () => {
  const method = 0x02;
  const encoded = encodeSelection(method);
  const decoded = decodeSelection(encoded);
  assert.equal(decoded.method, method);
});
