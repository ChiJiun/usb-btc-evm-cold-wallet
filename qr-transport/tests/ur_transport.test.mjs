import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { BoundedURScanner, encodeFrames } from "../src/ur_transport.mjs";
import { UR } from "@blockchaincommons/uniform-resources";
import { cbor } from "@blockchaincommons/dcbor";

const fake = (n = 10) => {
  const payload = { tx: "a".repeat(n) };
  return {
    version: 1, direction: "unsigned", network: "sepolia", account: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
    request_id: "1".repeat(32),
    payload_digest: createHash("sha256").update(JSON.stringify(payload)).digest("hex"),
    payload
  };
};
const scan = (frames, opts) => {
  const scanner = new BoundedURScanner(opts);
  for (const frame of frames) scanner.add(frame);
  return scanner;
};

test("single frame UR:BYTES roundtrip", () => {
  const data = fake(1);
  const frames = encodeFrames(data);
  assert.equal(frames.length, 1);
  assert.ok(frames[0].startsWith("ur:bytes/"));
  assert.deepEqual(scan(frames).payload, data);
});

test("fountain-encoded QR roundtrip with out-of-order and repeated frames", () => {
  const data = fake(6500);
  const frames = encodeFrames(data, { fragmentBytes: 150 });
  assert.ok(frames.length > 2);
  const scanner = new BoundedURScanner();
  for (const part of [...frames].reverse()) {
    const first = scanner.add(part);
    if (!first.done) assert.ok(first.progress >= 0 && first.progress <= 1);
  }
  assert.deepEqual(scanner.payload, data);
  assert.throws(() => scanner.add(frames[0]), /completed/);
  scanner.reset();
  assert.equal(scanner.done, false);
  assert.equal(scanner.add(frames[0]).duplicate, false);
  assert.equal(scanner.add(frames[0]).duplicate, true);
});

test("missing multipart QR remains pending", () => {
  const frames = encodeFrames(fake(4000), { fragmentBytes: 80 });
  const scanner = scan(frames.slice(0, -1));
  assert.equal(scanner.done, false);
});

test("reject mismatched UR type, malformed part, huge and mixed framing", () => {
  const frames = encodeFrames(fake(5000), { fragmentBytes: 80 });
  const scanner = new BoundedURScanner();
  assert.throws(() => scanner.add("ur:crypto-seed/abcd"), /Unsupported UR type/);
  assert.throws(() => scanner.add("https://evil.invalid"), /Invalid QR/);
  assert.throws(() => scanner.add("ur:bytes/999999999-999999999/abcd"), /excessive/);
  assert.throws(() => scanner.add("ur:bytes/" + "a".repeat(3100)), /Invalid QR/);
  scanner.add(frames[0]);
  const single = encodeFrames(fake(1))[0];
  assert.throws(() => scanner.add(single), /Mixed single/);
});

test("reject timeout and retry after reset", () => {
  let now = 1000;
  const scanner = new BoundedURScanner({ now: () => now, maxDurationMs: 100 });
  // The browser may remain open indefinitely before the first scan.
  now += 3600000;
  scanner.start();
  now += 101;
  assert.throws(() => scanner.add(encodeFrames(fake(1))[0]), /timed out/);
  scanner.reset();
  scanner.start();
  assert.equal(scanner.add(encodeFrames(fake(1))[0]).done, true);
  scanner.reset();
  now += 3600000;
  // First-frame scan also starts the clock without the browser using start().
  assert.equal(scanner.add(encodeFrames(fake(1))[0]).done, true);
});

test("reject excessive input sizes and huge fragment counts", () => {
  assert.throws(() => encodeFrames(fake(160000)), /too large/);
  assert.throws(() => encodeFrames(fake(30000), { fragmentBytes: 32, maxFrames: 2 }), /fragment count cap/);
  assert.throws(() => encodeFrames(fake(1), { fragmentBytes: 0 }), /parameters/);
});

test("reject hostile UR corpus: corrupt bytewords, duplicate keys, wrong digest and secret fields", () => {
  const valid = fake(1);
  const malformed = [
    '{"version":1,"version":1}',
    JSON.stringify({ ...valid, payload_digest: "0".repeat(64) }),
    JSON.stringify({ ...valid, payload: { mnemonic: "unsafe" } }),
    JSON.stringify({ ...valid, payload: { secretNote: "unsafe" } }),
    JSON.stringify({ ...valid, network: "ethereum-mainnet" }),
    JSON.stringify({ ...valid, version: 2 }),
    JSON.stringify({ ...valid, unexpected: "field" }),
  ];
  const bytes = new TextEncoder();
  for (const text of malformed) {
    const frame = UR.from("bytes", cbor(bytes.encode(text))).toQRString().toLowerCase();
    assert.throws(() => new BoundedURScanner().add(frame), /rejected|Invalid|Unsupported/);
  }
  const source = encodeFrames(valid)[0];
  assert.throws(() => new BoundedURScanner().add(source.slice(0, -5) + "aaaaa"), /rejected/);
});

test("reject mixed QR request frames instead of accepting a different request", () => {
  const a = encodeFrames(fake(3000), { fragmentBytes: 96 });
  const b = encodeFrames({ ...fake(3000), request_id: "2".repeat(32) }, { fragmentBytes: 96 });
  const scanner = new BoundedURScanner();
  scanner.add(a[0]);
  // Fountain checksums and per-part metadata prevent mixed-fountain decoding.
  assert.throws(() => scanner.add(b[1]), /inconsistent|rejected/);
});

test("reject unknown version, network and malformed account", () => {
  assert.throws(() => encodeFrames({ ...fake(), version: 2 }), /binding/);
  assert.throws(() => encodeFrames({ ...fake(), network: "ethereum-mainnet" }), /binding/);
  assert.throws(() => encodeFrames({ ...fake(), account: "x" }), /binding/);
});

test("reject offline-incompatible container sizes, Unicode keys, and account identifiers", () => {
  const tooManyKeys = Object.fromEntries(
    Array.from({ length: 257 }, (_, index) => [`key${index}`, index])
  );
  const attacks = [
    [{ ...fake(), account: "account with spaces" }, /binding/],
    [{ ...fake(), account: "錯誤帳戶識別碼1234" }, /binding/],
    [{ ...fake(), payload: tooManyKeys }, /object too large/],
    [{ ...fake(), payload: Array(1025).fill(1) }, /array too large/],
    [{ ...fake(), payload: { "違規鍵": 1 } }, /object key/],
    [{ ...fake(), payload: { tx: "non-ascii-文字" } }, /ASCII/],
  ];
  for (const [envelope, reason] of attacks) {
    assert.throws(() => encodeFrames(envelope), reason);
  }
});
