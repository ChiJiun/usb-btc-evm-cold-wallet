/**
 * Explicit, testnet-only typed UR registry codec.
 * ERC-4527 (stagnant): eth-sign-request/eth-signature; BCR-2020-006: crypto-psbt.
 * This converts transport bytes only. It cannot authorize or perform signing.
 * The caller MUST match a verified, immutable session and independently check
 * signed transaction / PSBT before broadcasting.
 */
import { UR, MultipartEncoder, MultipartDecoder } from "@blockchaincommons/uniform-resources";
import { cbor, extractCbor, taggedValue, MajorType } from "@blockchaincommons/dcbor";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { MAX_PAYLOAD, MAX_FRAME_CHARS, MAX_FRAGMENT_LENGTH, MAX_FRAGMENTS, MAX_SCAN_MS } from "./ur_transport.mjs";

const TYPES = new Set(["eth-sign-request", "eth-signature", "crypto-psbt"]);
const network = "sepolia";
const ETH_CHAIN = 11155111;
const hex = (bytes) => bytesToHex(bytes);
const bytes = (s, len, label) => {
  if (label === "EVM address" && typeof s === "string" && s.startsWith("0x")) s = s.slice(2);
  if (typeof s !== "string" || !/^(?:[a-fA-F0-9]{2})*$/.test(s) ||
      (len !== undefined && s.length !== len * 2)) throw Error("Invalid " + label);
  return Uint8Array.from(s.match(/../g) ?? [], b => parseInt(b, 16));
};
const expectBytes = (node, min, max, label) => {
  const data = extractCbor(node);
  if (!(data instanceof Uint8Array) || data.length < min || data.length > max) throw Error("Invalid " + label);
  return data;
};
const map = (entries) => new Map(entries);
const getMap = (node, required, allowed = required) => {
  if (node.type !== MajorType.Map) throw Error("Expected CBOR map");
  const value = node.value;
  if (value.size !== required.length && value.size !== allowed.length &&
      !required.every(k=>value.has(k))) throw Error("CBOR map field mismatch");
  for (const key of required) if (!value.has(key)) throw Error("Missing CBOR field " + key);
  for (const [key] of value) if (!allowed.includes(extractCbor(key))) throw Error("Unsupported CBOR field");
  return value;
};
const field = (m, key) => extractCbor(m.getOrThrow(key));
const uuid = (s) => {
  if (!/^[0-9a-f]{32}$/.test(s ?? "")) throw Error("Invalid UUID request ID");
  return taggedValue(37, bytes(s, 16, "UUID"));
};
const readUuid = node => {
  if (node.type !== MajorType.Tagged || Number(node.tag) !== 37) throw Error("Expected CBOR UUID tag 37");
  return hex(expectBytes(node.value, 16, 16, "UUID"));
};
function keypath(path, fingerprint) {
  if (!Array.isArray(path) || path.length < 1 || path.length > 10 ||
      !path.every(v => Number.isSafeInteger(v) && v >= 0 && v < 0x80000000)) {
    throw Error("Invalid bounded EVM derivation path");
  }
  const fp = bytes(fingerprint, 4, "fingerprint");
  const f = new DataView(fp.buffer).getUint32(0, false);
  return taggedValue(304, map([
    [1, path.flatMap(v=>[v,false])], [2,f], [3,path.length]
  ]));
}
function readKeypath(node) {
  if (node.type !== MajorType.Tagged || Number(node.tag) !== 304) throw Error("Expected CBOR keypath tag");
  const m = getMap(node.value, [1,2,3]);
  const values = field(m,1);
  const fp = field(m,2), depth=field(m,3);
  if (!Array.isArray(values) || values.length < 2 || values.length > 20 ||
      values.length % 2 !== 0 || !Number.isSafeInteger(fp) || fp <= 0 ||
      fp > 0xffffffff || depth !== values.length / 2) throw Error("Malformed keypath");
  const path = [];
  for (let i=0;i<values.length;i+=2) {
    if (!Number.isInteger(values[i]) || values[i]<0 || values[i]>=0x80000000 ||
        typeof values[i+1] !== "boolean") throw Error("Unsupported keypath component");
    if (values[i+1]) throw Error("Hardened keypath must be explicitly reviewed offline");
    path.push(values[i]);
  }
  return {path, fingerprint:fp.toString(16).padStart(8,"0")};
}
export function makeTypedUR(type, data) {
  if (!TYPES.has(type)) throw Error("Unsupported typed UR");
  let body;
  if (type === "crypto-psbt") {
    const b = bytes(data.psbtHex, undefined, "PSBT");
    if (b.length < 6 || b.length > MAX_PAYLOAD || hex(b.subarray(0,5)) !== "70736274ff") throw Error("Invalid PSBT magic/size");
    body = cbor(b); // BCR-2020-006: bare CBOR byte string, NO custom map.
  } else if (type === "eth-sign-request") {
    if (data.chainId !== ETH_CHAIN || data.network !== network || data.dataType !== 4) throw Error("Only Sepolia typed EIP-2718 tx allowed");
    const raw = bytes(data.unsignedTxHex,undefined,"unsigned typed tx");
    if (raw.length < 3 || raw.length > MAX_PAYLOAD || raw[0] !== 2) throw Error("Only bounded unsigned type-2 tx");
    const account = bytes(data.address,20,"EVM address");
    if (account.length !== 20) throw Error("Missing EVM signer");
    body = cbor(map([
      [1,uuid(data.requestId)], [2,raw], [3,4], [4,ETH_CHAIN],
      [5,keypath(data.path,data.fingerprint)], [6,account]
    ]));
  } else {
    const signature = bytes(data.signatureHex,65,"65-byte r,s,v signature");
    if (signature[64] !== 0 && signature[64] !== 1 && signature[64] !== 27 && signature[64] !== 28)
      throw Error("Unsupported signature recovery byte");
    body = cbor(map([[1,uuid(data.requestId)],[2,signature]]));
  }
  return UR.from(type,body);
}
export function parseTypedUR(ur) {
  const type = ur.type.name;
  if (!TYPES.has(type)) throw Error("Unsupported typed UR");
  if (type === "crypto-psbt") {
    const raw = expectBytes(ur.cbor, 6, MAX_PAYLOAD, "PSBT");
    if (hex(raw.subarray(0,5)) !== "70736274ff") throw Error("Wrong PSBT magic");
    return {type, psbtHex:hex(raw)};
  }
  const m=type==="eth-sign-request"?
    getMap(ur.cbor,[1,2,3,4,5,6],[1,2,3,4,5,6,7]):getMap(ur.cbor,[1,2],[1,2,3]);
  const requestId=readUuid(m.getOrThrow(1));
  if (type==="eth-signature") {
    const sig=expectBytes(m.getOrThrow(2),65,65,"signature");
    if (![0,1,27,28].includes(sig[64])) throw Error("Invalid recovery byte");
    return {type,requestId,signatureHex:hex(sig)};
  }
  const raw=expectBytes(m.getOrThrow(2),3,MAX_PAYLOAD,"EIP-2718 tx");
  const chain=field(m,4), dataType=field(m,3);
  if (raw[0]!==2 || chain!==ETH_CHAIN || dataType!==4) throw Error("Unsupported transaction type/chain");
  const signer=expectBytes(m.getOrThrow(6),20,20,"signer");
  const kp=readKeypath(m.getOrThrow(5));
  if (m.has(7)) {
    const origin=field(m,7);
    if (typeof origin!=="string" || origin.length>128 || /[^\x20-\x7e]/.test(origin)) throw Error("Invalid origin");
  }
  return {type,requestId, unsignedTxHex:hex(raw), dataType,chainId:chain,
    network, address:"0x"+hex(signer), ...kp};
}
export function encodeTypedFrames(type, data, {fragmentBytes=220,maxFrames=MAX_FRAGMENTS}={}) {
  if (!Number.isSafeInteger(fragmentBytes)||fragmentBytes<32||fragmentBytes>MAX_FRAGMENT_LENGTH||
      !Number.isSafeInteger(maxFrames)||maxFrames<1||maxFrames>MAX_FRAGMENTS) throw Error("Invalid frame limits");
  const ur=makeTypedUR(type,data);
  const one=ur.toQRString().toLowerCase();
  if(one.length<=1200) return [one];
  const multi=new MultipartEncoder(ur,fragmentBytes);
  if(multi.partCount>maxFrames) throw Error("Too many UR fragments");
  const frames=Array.from({length:multi.partCount},()=>multi.nextPart());
  if(frames.some(s=>s.length>MAX_FRAME_CHARS)) throw Error("Oversized typed frame");
  return frames;
}
/** Explicit context binding; do not feed parsed UR directly to a signer. */
export function bindTypedToPending(parsed,pending,{now=Date.now()}={}) {
  if (!pending || !Number.isFinite(now) || now<pending.createdAt ||
      now-pending.createdAt>Math.min(pending.ttlMs??MAX_SCAN_MS,MAX_SCAN_MS) ||
      pending.consumed || pending.cancelled) throw Error("Expired or closed signing session");
  if (parsed.type!==pending.type || parsed.requestId!==pending.requestId ||
      (parsed.chainId!==undefined && parsed.chainId!==pending.chainId) ||
      (parsed.address!==undefined && parsed.address.toLowerCase()!==pending.address?.toLowerCase()) ||
      (parsed.unsignedTxHex!==undefined && hex(sha256(bytes(parsed.unsignedTxHex)))!==pending.unsignedDigest) ||
      (parsed.psbtHex!==undefined && hex(sha256(bytes(parsed.psbtHex)))!==pending.psbtDigest)) {
    throw Error("Typed UR mismatches immutable pending request");
  }
  if (parsed.type==="eth-signature" && typeof pending.unsignedDigest!=="string")
    throw Error("Missing original unsigned signing intent");
  return parsed; // Chain-specific signature/PSBT verification is STILL required.
}
export class TypedURScanner {
  #decoder=new MultipartDecoder();#seen=new Set();#first=null;#mode=null;#type=null;#count=0;#done=null;
  constructor({now=()=>Date.now(),maxDurationMs=MAX_SCAN_MS,expectedType=null}={}) {
    if(!Number.isSafeInteger(maxDurationMs)||maxDurationMs<1||maxDurationMs>MAX_SCAN_MS||
       (expectedType!==null&&!TYPES.has(expectedType))) throw Error("Invalid scanner settings");
    this.now=now;this.maxDurationMs=maxDurationMs;this.expectedType=expectedType;
  }
  get done(){return this.#done!==null;} get payload(){return this.#done;}
  get progress(){return this.done?1:this.#decoder.progress;}
  reset(){this.#decoder=new MultipartDecoder();this.#seen.clear();this.#first=null;this.#mode=null;this.#type=null;this.#count=0;this.#done=null;}
  add(frame) {
    if(this.done)throw Error("Scan already completed");
    if(this.#first===null)this.#first=this.now();
    if(this.now()<this.#first||this.now()-this.#first>this.maxDurationMs)throw Error("Typed scan timed out");
    if(typeof frame!=="string"||frame.length>MAX_FRAME_CHARS)throw Error("Invalid typed fragment");
    const s=frame.toLowerCase(),parts=s.split("/");
    const m=/^ur:([a-z0-9-]+)$/.exec(parts[0]??"");
    if(!m||!TYPES.has(m[1])||(this.expectedType!==null&&m[1]!==this.expectedType)||
       (parts.length!==2&&parts.length!==3))throw Error("Unsupported typed UR frame");
    if(this.#type!==null&&this.#type!==m[1])throw Error("Mixed typed UR messages");
    this.#type=m[1];
    if(this.#mode!==null&&this.#mode!==parts.length)throw Error("Mixed frame modes");
    this.#mode=parts.length;
    if(parts.length===3) {
      const h=/^([1-9]\d*)-([1-9]\d*)$/.exec(parts[1]);
      if(!h||Number(h[1])>MAX_FRAGMENTS*32||Number(h[2])>MAX_FRAGMENTS)throw Error("Excessive fragment index/count");
    }
    if(this.#seen.has(s))return {done:false,duplicate:true,progress:this.progress};
    if(this.#count++>=MAX_FRAGMENTS)throw Error("Too many QR frames");
    this.#seen.add(s);
    try {
      const ur=parts.length===2?UR.parse(s):(this.#decoder.add(s),this.#decoder.done?this.#decoder.result:null);
      if(!ur)return {done:false,duplicate:false,progress:this.progress};
      if(!ur.isType(m[1]))throw Error("Typed UR mismatch");
      this.#done=parseTypedUR(ur);
      return {done:true,duplicate:false,progress:1};
    }catch(err){this.reset();throw Error("Typed UR rejected: "+err.message);}
  }
}
