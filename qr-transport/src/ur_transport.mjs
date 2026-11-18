/**
 * Bounded Blockchain Commons UR:BYTES framing for QR exchange envelopes.
 *
 * Uses the maintained @blockchaincommons/uniform-resources encoder/decoder;
 * never creates an ad-hoc UR fountain scheme.  UR:BYTES is a temporary
 * internal binding-envelope carrier: it is NOT ERC-4527 eth-sign-request nor
 * interoperable crypto-psbt until the dedicated registry mapping is added.
 */
import { sha256 as hash256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { UR, MultipartEncoder, MultipartDecoder } from "@blockchaincommons/uniform-resources";
import { asBytes, cbor } from "@blockchaincommons/dcbor";

export const MAX_PAYLOAD = 150_000;
export const MAX_FRAGMENT_LENGTH = 480;
export const MAX_FRAGMENTS = 512;
export const MAX_FRAME_CHARS = 3_000;
export const MAX_SCAN_MS = 120_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const exactKeys = (obj, keys) =>
  obj !== null && typeof obj === "object" && !Array.isArray(obj) &&
  Object.keys(obj).sort().join("|") === [...keys].sort().join("|");

function safeJson(text) {
  const parsed = JSON.parse(text, (_, v) => {
    if (typeof v === "number" && !Number.isSafeInteger(v)) {
      throw new Error("Unsafe JSON number");
    }
    return v;
  });
  // Sender emits exactly compact JSON.stringify. Reject duplicate JSON keys,
  // trailing content and alternative representations through roundtrip.
  if (JSON.stringify(parsed) !== text) throw new Error("Noncanonical or duplicate JSON fields");
  return parsed;
}

function noSecrets(value, depth = 0) {
  if (depth > 16) throw new Error("Excessive QR nesting");
  if (Array.isArray(value)) {
    for (const item of value) noSecrets(item, depth + 1);
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (/(mnemonic|passphrase|private|seed|secret|xprv|password|vault)/i.test(key)) {
        throw new Error("QR must not contain secret fields");
      }
      noSecrets(item, depth + 1);
    }
  } else if (typeof value === "string" && [...value].some(ch => ch.codePointAt(0) > 127)) {
    throw new Error("QR protocol payload only accepts ASCII text");
  }
}

// Python qr_session.py computes SHA256 over sorted compact ensure_ascii JSON.
// Restrict payload to ASCII; this serialization is byte-identical in both runtimes.
function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}
function sha256(payload) {
  return bytesToHex(hash256(encoder.encode(canonical(payload))));
}
function equalDigest(a, b) {
  if (!/^[0-9a-f]{64}$/.test(b)) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function parseEnvelope(payload) {
  const text = decoder.decode(payload);
  const parsed = safeJson(text);
  if (!exactKeys(parsed, ["version", "direction", "network", "account", "request_id", "payload_digest", "payload"]) &&
      !exactKeys(parsed, ["version", "direction", "network", "account", "request_id", "request_digest", "payload_digest", "payload"])) {
    throw new Error("QR envelope schema mismatch");
  }
  if (parsed.version !== 1 || !["bitcoin-testnet", "sepolia"].includes(parsed.network) ||
      !["unsigned", "signed"].includes(parsed.direction) ||
      typeof parsed.account !== "string" || parsed.account.length < 8 || parsed.account.length > 150 ||
      typeof parsed.request_id !== "string" || !/^[0-9a-f]{32}$/.test(parsed.request_id) ||
      typeof parsed.payload_digest !== "string" || !/^[0-9a-f]{64}$/.test(parsed.payload_digest) ||
      (parsed.direction === "signed" && !/^[0-9a-f]{64}$/.test(parsed.request_digest ?? "")) ||
      (parsed.direction === "unsigned" && Object.hasOwn(parsed, "request_digest"))) {
    throw new Error("QR envelope binding fields are invalid");
  }
  noSecrets(parsed.payload);
  if (!equalDigest(sha256(parsed.payload), parsed.payload_digest))
    throw new Error("QR payload digest mismatch");
  // Final signed transaction verification is separately mandatory in Python
  // QRSession.check_response; QR framing and checksums are never authorization.
  return parsed;
}

export function encodeFrames(envelope, { fragmentBytes = 220, maxFrames = MAX_FRAGMENTS } = {}) {
  if (!Number.isSafeInteger(fragmentBytes) || fragmentBytes < 32 ||
      fragmentBytes > MAX_FRAGMENT_LENGTH || !Number.isSafeInteger(maxFrames) ||
      maxFrames < 1 || maxFrames > MAX_FRAGMENTS) {
    throw new Error("Invalid frame parameters");
  }
  const checked = parseEnvelope(encoder.encode(JSON.stringify(envelope)));
  const raw = encoder.encode(JSON.stringify(checked));
  if (raw.length === 0 || raw.length > MAX_PAYLOAD) throw new Error("QR payload too large");
  const ur = UR.from("bytes", cbor(raw));
  if (ur.toQRString().length <= 1200) {
    return [ur.toQRString().toLowerCase()];
  }
  const multi = new MultipartEncoder(ur, fragmentBytes);
  if (multi.partCount > maxFrames) throw new Error("QR exceeds fragment count cap");
  const frames = Array.from({ length: multi.partCount }, () => multi.nextPart());
  if (frames.some(frame => frame.length > MAX_FRAME_CHARS)) throw new Error("QR frame too long");
  return frames;
}

export class BoundedURScanner {
  #decoder = new MultipartDecoder();
  #seen = new Set();
  #type = null;
  #start;
  #now;
  #frames = 0;
  #finished = null;
  constructor({ now = () => Date.now(), maxDurationMs = MAX_SCAN_MS } = {}) {
    if (!Number.isSafeInteger(maxDurationMs) || maxDurationMs < 1 || maxDurationMs > MAX_SCAN_MS)
      throw new Error("Invalid scan lifetime");
    this.#now = now;
    this.#start = now();
    this.duration = maxDurationMs;
  }
  get progress() { return this.#finished ? 1 : this.#decoder.progress; }
  get count() { return this.#frames; }
  get done() { return this.#finished !== null; }
  get payload() { return this.#finished; }
  reset() {
    this.#decoder = new MultipartDecoder();
    this.#seen.clear();
    this.#type = null;
    this.#start = this.#now();
    this.#frames = 0;
    this.#finished = null;
  }
  add(frame) {
    if (this.done) throw new Error("QR session already completed; reset before rescanning");
    const time = this.#now() - this.#start;
    if (time < 0 || time > this.duration) throw new Error("QR scan timed out");
    if (typeof frame !== "string" || frame.length > MAX_FRAME_CHARS ||
        !/^ur:[a-z0-9-]+\//i.test(frame)) throw new Error("Invalid QR fragment");
    const normalized = frame.toLowerCase();
    if (!normalized.startsWith("ur:bytes/")) throw new Error("Unsupported UR type");
    const parts = normalized.split("/");
    if (parts.length !== 2 && parts.length !== 3) throw new Error("Malformed UR fragment");
    if (this.#type !== null && this.#type !== parts.length) throw new Error("Mixed single and multipart QR");
    this.#type = parts.length;
    if (parts.length === 3) {
      const header = /^([1-9]\d*)-([1-9]\d*)$/.exec(parts[1]);
      if (!header || Number(header[1]) > MAX_FRAGMENTS * 32 ||
          Number(header[2]) > MAX_FRAGMENTS) throw new Error("Invalid fragment index or excessive count");
    }
    if (this.#seen.has(normalized)) return { progress: this.progress, duplicate: true, done: false };
    if (this.#frames >= MAX_FRAGMENTS) throw new Error("Too many scanned QR frames");
    this.#seen.add(normalized);
    this.#frames++;
    let ur;
    try {
      if (parts.length === 2) {
        ur = UR.parse(normalized);
      } else {
        this.#decoder.add(normalized);
        if (!this.#decoder.done) return { progress: this.progress, duplicate: false, done: false };
        ur = this.#decoder.result;
      }
      if (!ur.isType("bytes")) throw new Error("Unexpected UR data type");
      const bytes = asBytes(ur.cbor);
      if (!(bytes instanceof Uint8Array) || bytes.length > MAX_PAYLOAD) throw new Error("QR message exceeds size cap");
      this.#finished = parseEnvelope(bytes);
      return { progress: 1, duplicate: false, done: true };
    } catch (error) {
      this.#finished = null;
      throw new Error("QR decoding rejected: " + (error?.message ?? String(error)));
    }
  }
}
