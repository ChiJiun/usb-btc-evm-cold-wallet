/**
 * Explicit, testnet-only typed UR registry codec.
 * ERC-4527 (stagnant): eth-sign-request/eth-signature; BCR-2020-006: crypto-psbt.
 * This converts transport bytes only. It cannot authorize or perform signing.
 * The caller MUST match a verified, immutable session and independently check
 * signed transaction / PSBT before broadcasting.
 */
import { UR, MultipartEncoder } from "@blockchaincommons/uniform-resources";
import { decodeBytewords } from "@blockchaincommons/uniform-resources/bytewords";
import { FountainDecoder, decodeFountainPart } from "@blockchaincommons/uniform-resources/fountain";
import { cbor, decodeCbor, extractCbor, taggedValue, MajorType } from "@blockchaincommons/dcbor";
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
function checkOrigin(m, key) {
  if (!m.has(key)) return;
  const origin=field(m,key);
  if (typeof origin!=="string" || origin.length>128 || /[^\x20-\x7e]/.test(origin)) throw Error("Invalid origin");
}
function boundedTree(node, depth=0, budget={remaining:256}) {
  if (depth>12 || --budget.remaining<0) throw Error("Excessive CBOR nesting/container");
  if (node.type===MajorType.Map) {
    if (node.value.size>16) throw Error("Excessive CBOR map entries");
    for (const [k,v] of node.value) {boundedTree(k,depth+1,budget);boundedTree(v,depth+1,budget);}
  } else if (node.type===MajorType.Tagged) boundedTree(node.value,depth+1,budget);
  else if (node.type===MajorType.Array) {
    if (node.value.length>32) throw Error("Excessive CBOR array entries");
    for (const v of node.value) boundedTree(v,depth+1,budget);
  }
}
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
      !path.every(v => v && typeof v === "object" && !Array.isArray(v) &&
        Object.keys(v).sort().join(",") === "hardened,index" &&
        Number.isSafeInteger(v.index) && v.index >= 0 && v.index < 0x80000000 &&
        typeof v.hardened === "boolean")) {
    throw Error("Invalid bounded EVM derivation path");
  }
  const fp = bytes(fingerprint, 4, "fingerprint");
  const f = new DataView(fp.buffer).getUint32(0, false);
  if (f === 0) throw Error("Zero fingerprint not permitted");
  return taggedValue(304, map([
    [1, path.flatMap(v=>[v.index,v.hardened])], [2,f], [3,path.length]
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
    path.push({index:values[i],hardened:values[i+1]});
  }
  return {path, fingerprint:fp.toString(16).padStart(8,"0")};
}
// Strict, bounded EIP-2718 type-2 *unsigned* RLP shape; this is a
// transport precondition, never a substitute for offline signing-policy review.
function rlpHead(data, offset) {
  if (offset>=data.length) throw Error("Truncated RLP");
  const head=data[offset];
  if (head<0x80) return {kind:"bytes",start:offset,length:1,next:offset+1};
  const kind=head<0xc0?"bytes":"list";
  const small=head<0xc0?0x80:0xc0, cutoff=head<0xc0?0xb7:0xf7;
  let length,start;
  if(head<=cutoff){length=head-small;start=offset+1;}
  else {
    const width=head-cutoff;
    if(width>3||offset+1+width>data.length||data[offset+1]===0)
      throw Error("Noncanonical RLP length");
    length=0;
    for(let i=0;i<width;i++) length=length*256+data[offset+1+i];
    if(length<56)throw Error("Noncanonical long RLP length");
    start=offset+1+width;
  }
  if(start+length>data.length)throw Error("RLP overflow");
  if(kind==="bytes" && length===1 && data[start]<0x80)
    throw Error("Noncanonical single-byte RLP");
  return {kind,start,length,next:start+length};
}
function rlpUnsignedInteger(data, part) {
  if(part.kind!=="bytes"||part.length>32||
     (part.length>0&&data[part.start]===0))
    throw Error("Noncanonical RLP integer");
  let n=0n;
  for(let i=part.start;i<part.next;i++)n=n*256n+BigInt(data[i]);
  return n;
}
function validateUnsignedType2(raw) {
  if(raw.length<3||raw.length>MAX_PAYLOAD||raw[0]!==2)
    throw Error("Only bounded unsigned type-2 tx");
  const root=rlpHead(raw,1);
  if(root.kind!=="list"||root.next!==raw.length)
    throw Error("Expected exact unsigned EIP-1559 RLP list");
  const fields=[];
  for(let p=root.start;p<root.next;) {
    if(fields.length>=9)throw Error("Signed or oversized EIP-1559 payload");
    const item=rlpHead(raw,p);
    if(item.next>root.next)throw Error("RLP subfield overrun");
    fields.push(item);p=item.next;
  }
  if(fields.length!==9)throw Error("Expected nine unsigned EIP-1559 fields");
  const chain=rlpUnsignedInteger(raw,fields[0]);
  const nonce=rlpUnsignedInteger(raw,fields[1]);
  const priority=rlpUnsignedInteger(raw,fields[2]);
  const maxFee=rlpUnsignedInteger(raw,fields[3]);
  const gas=rlpUnsignedInteger(raw,fields[4]);
  const to=fields[5], value=rlpUnsignedInteger(raw,fields[6]);
  const data=fields[7],accessList=fields[8];
  if(chain!==BigInt(ETH_CHAIN)||nonce>0xffffffffffffffffn||
     priority>maxFee||maxFee===0n||gas!==21000n||value<=0n||
     to.kind!=="bytes"||to.length!==20||
     data.kind!=="bytes"||data.length!==0||
     accessList.kind!=="list"||accessList.length!==0)
    throw Error("Unsafe or wrong-chain unsigned EIP-1559 transfer");
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
    validateUnsignedType2(raw);
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
  boundedTree(ur.cbor);
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
    checkOrigin(m,3);
    return {type,requestId,signatureHex:hex(sig)};
  }
  const raw=expectBytes(m.getOrThrow(2),3,MAX_PAYLOAD,"EIP-2718 tx");
  const chain=field(m,4), dataType=field(m,3);
  if (chain!==ETH_CHAIN || dataType!==4) throw Error("Unsupported transaction type/chain");
  validateUnsignedType2(raw);
  const signer=expectBytes(m.getOrThrow(6),20,20,"signer");
  const kp=readKeypath(m.getOrThrow(5));
  checkOrigin(m,7);
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
/**
 * Context guard, NOT a substitute for chain signature verification.
 * Required callbacks must return literal true synchronously; async, missing,
 * or inconclusive verification fails closed.
 */
export function bindTypedToPending(parsed,pending,{
  now=Date.now(),verifySignature=null,verifySignedPsbt=null
}={}) {
  if (!pending || !Number.isFinite(now) || !Number.isFinite(pending.createdAt) ||
      now<pending.createdAt ||
      now-pending.createdAt>Math.min(pending.ttlMs??MAX_SCAN_MS,MAX_SCAN_MS) ||
      pending.consumed || pending.cancelled) throw Error("Expired or closed signing session");
  // Do not let a caller-supplied partial object bypass mandatory UR bindings.
  // The typed parser normally supplies these fields, but this exported guard
  // must also fail closed when invoked directly by an application adapter.
  if (!parsed || !TYPES.has(parsed.type) || parsed.type === "eth-signature" &&
      (!/^[0-9a-f]{32}$/.test(parsed.requestId ?? "") ||
       !/^[0-9a-f]{128}(?:00|01|1b|1c)$/.test(parsed.signatureHex ?? "")) ||
      parsed.type === "eth-sign-request" &&
      (!/^[0-9a-f]{32}$/.test(parsed.requestId ?? "") ||
       parsed.chainId !== ETH_CHAIN || parsed.network !== network ||
       typeof parsed.address !== "string" ||
       !/^0x[0-9a-f]{40}$/i.test(parsed.address) ||
       typeof parsed.unsignedTxHex !== "string" ||
       !Array.isArray(parsed.path) ||
       !/^[0-9a-f]{8}$/.test(parsed.fingerprint ?? "")) ||
      parsed.type === "crypto-psbt" &&
      (typeof parsed.psbtHex !== "string" ||
       !/^70736274ff(?:[0-9a-f]{2})+$/i.test(parsed.psbtHex) ||
       parsed.psbtHex.length / 2 > MAX_PAYLOAD)) {
    throw Error("Incomplete or invalid typed UR payload");
  }
  const signatureResponse=parsed.type==="eth-signature" && pending.type==="eth-sign-request";
  const isEvm=parsed.type==="eth-sign-request" || signatureResponse;
  if (isEvm && (pending.chainId!==ETH_CHAIN || pending.network!==network ||
      !Array.isArray(pending.path) || !/^[0-9a-f]{8}$/.test(pending.fingerprint ?? "") ||
      !/^0x[0-9a-f]{40}$/i.test(pending.address ?? "") ||
      !/^[0-9a-f]{64}$/.test(pending.unsignedDigest ?? "")))
    throw Error("Missing trusted EVM account/path context");
  if (parsed.type==="crypto-psbt" &&
      (pending.network!=="bitcoin-testnet" ||
       !/^[0-9a-f]{8}$/.test(pending.accountFingerprint ?? "") ||
       !/^[A-Za-z0-9:_-]{8,150}$/.test(pending.accountId ?? "") ||
       !/^[0-9a-f]{64}$/.test(pending.psbtDigest ?? "") ||
       !["unsigned","signed"].includes(pending.phase)))
    throw Error("Missing trusted Bitcoin testnet account context");
  if (!(parsed.type===pending.type || signatureResponse) ||
      (parsed.type !== "crypto-psbt" && parsed.requestId !== pending.requestId) ||
      (parsed.type === "eth-sign-request" &&
       (parsed.chainId !== pending.chainId ||
        parsed.address.toLowerCase() !== pending.address.toLowerCase() ||
        JSON.stringify(parsed.path) !== JSON.stringify(pending.path) ||
        parsed.fingerprint !== pending.fingerprint ||
        hex(sha256(bytes(parsed.unsignedTxHex))) !== pending.unsignedDigest))) {
    throw Error("Typed UR mismatches immutable pending request");
  }
  if (signatureResponse) {
    if (pending.chainId!==ETH_CHAIN || typeof pending.unsignedDigest!=="string" ||
        typeof pending.address!=="string" ||
        typeof verifySignature!=="function" ||
        verifySignature(parsed,pending)!==true) {
      throw Error("Independent EIP-1559 signature verification required");
    }
  }
  if (parsed.psbtHex!==undefined) {
    if (pending.phase==="signed") {
      // crypto-psbt carries no request ID or unsigned payload digest: exact
      // outputs/UTXOs/fees/signatures MUST be checked against original PSBT.
      if(typeof verifySignedPsbt!=="function" ||
         verifySignedPsbt(parsed,pending)!==true)
        throw Error("Independent signed PSBT verification required");
    } else if (hex(sha256(bytes(parsed.psbtHex)))!==pending.psbtDigest) {
      throw Error("PSBT bytes differ from pending unsigned transaction");
    }
  }
  // Consume signed responses synchronously; callers must supply their real session.
  // This never signs or broadcasts and cannot replace cryptographic verification.
  if (signatureResponse || (parsed.type==="crypto-psbt" && pending.phase==="signed")) {
    if (!Object.isExtensible(pending)) throw Error("Signing session must be mutable for replay protection");
    pending.consumed=true;
  }
  return parsed;
}

/**
 * Bound untrusted *encoded* CBOR before calling the recursive dCBOR decoder.
 * This deliberately supports only definite-length primitive/map/array/tag
 * shapes required by the strict typed-UR registries. No indefinite lengths,
 * floats, nested 13+ levels, or oversized arrays/maps/text values.
 */
const MAX_CBOR_BYTES = MAX_PAYLOAD + 2048;
function preflightCbor(input) {
  if (!(input instanceof Uint8Array) || input.length === 0 || input.length > MAX_CBOR_BYTES)
    throw Error("Typed CBOR exceeds byte limit");
  let at = 0, nodes = 0;
  const stack = [{left:1,depth:0}];
  const take = n => {
    if (!Number.isSafeInteger(n) || n < 0 || at + n > input.length)
      throw Error("Invalid or oversized typed CBOR length");
    const p = at;at += n;return p;
  };
  while (stack.length) {
    const top=stack[stack.length-1];
    if (top.left === 0) {stack.pop();continue;}
    top.left--;
    if (++nodes > 256 || top.depth > 12)
      throw Error("Excessive CBOR nesting/container");
    const header=input[take(1)];
    const major=header>>>5, ai=header&31;
    if (major === 7) {
      if (ai !== 20 && ai !== 21) throw Error("Unsupported CBOR simple/float value");
      continue;
    }
    let value;
    if (ai < 24) value=ai;
    else if (ai >= 24 && ai <= 27) {
      const width=2**(ai-24), start=take(width);
      value=0;
      for (let i=0;i<width;i++) value=value*256+input[start+i];
      if (!Number.isSafeInteger(value)) throw Error("Unsupported CBOR integer size");
      if ((ai===24&&value<24)||(ai===25&&value<=255)||
          (ai===26&&value<=65535)||(ai===27&&value<=4294967295))
        throw Error("Noncanonical CBOR length/integer");
    } else throw Error("Indefinite or unsupported typed CBOR");
    if (major===0 || major===1) continue;
    if (major===2 || major===3) {
      if (value > (major===3?128:MAX_PAYLOAD)) throw Error("Oversized typed CBOR string");
      take(value);continue;
    }
    let count;
    if (major===4) {if(value>32)throw Error("Excessive CBOR array entries");count=value;}
    else if (major===5) {if(value>16)throw Error("Excessive CBOR map entries");count=value*2;}
    else if (major===6) count=1;
    else throw Error("Unsupported typed CBOR major type");
    if (count) stack.push({left:count,depth:top.depth+1});
  }
  if (at!==input.length) throw Error("Trailing bytes in typed CBOR");
}
function preflightFountainPart(encoded, outerSeq, outerLen, firstPart) {
  // Bytewords payload is strictly capped by MAX_FRAME_CHARS before decode.
  // Check the *inner* CBOR fountain header before invoking FountainDecoder:
  // upstream uses inner seqLen for allocation; the outer UR header is informational.
  const wire=decodeBytewords(encoded, "minimal");
  const part=decodeFountainPart(wire);
  if (!Number.isSafeInteger(part.seqNum)||part.seqNum!==outerSeq ||
      !Number.isSafeInteger(part.seqLen)||part.seqLen!==outerLen ||
      part.seqNum<1 || part.seqNum>MAX_FRAGMENTS*32 ||
      part.seqLen<1 || part.seqLen>MAX_FRAGMENTS ||
      !Number.isSafeInteger(part.messageLen)||part.messageLen<1 ||
      part.messageLen>MAX_CBOR_BYTES ||
      !(part.data instanceof Uint8Array) ||
      part.data.length<1 || part.data.length>MAX_FRAGMENT_LENGTH ||
      part.seqLen*part.data.length > MAX_CBOR_BYTES+MAX_FRAGMENT_LENGTH ||
      part.messageLen <= (part.seqLen-1)*part.data.length ||
      part.messageLen > part.seqLen*part.data.length)
    throw Error("Untrusted inner fountain part exceeds QR bounds");
  if (firstPart !== null &&
      (part.messageLen!==firstPart.messageLen ||
       part.checksum!==firstPart.checksum ||
       part.data.length!==firstPart.dataLength ||
       part.seqLen!==firstPart.seqLen))
    throw Error("Inconsistent inner fountain message context");
  return part;
}

export class TypedURScanner {
  #decoder=new FountainDecoder();#seen=new Set();#first=null;#mode=null;#type=null;#count=0;#done=null;#totalChars=0;#declared=null;#fountainMeta=null;
  constructor({now=()=>Date.now(),maxDurationMs=MAX_SCAN_MS,expectedType=null}={}) {
    if(!Number.isSafeInteger(maxDurationMs)||maxDurationMs<1||maxDurationMs>MAX_SCAN_MS||
       (expectedType!==null&&!TYPES.has(expectedType))) throw Error("Invalid scanner settings");
    this.now=now;this.maxDurationMs=maxDurationMs;this.expectedType=expectedType;
  }
  get done(){return this.#done!==null;} get payload(){return this.#done;}
  get progress(){return this.done?1:this.#decoder.progress;}
  reset(){this.#decoder=new FountainDecoder();this.#seen.clear();this.#first=null;this.#mode=null;this.#type=null;this.#count=0;this.#done=null;this.#totalChars=0;this.#declared=null;this.#fountainMeta=null;}
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
      if(this.#declared!==null&&this.#declared!==Number(h[2]))throw Error("Mixed multipart counts");
      this.#declared=Number(h[2]);
    }
    if(this.#seen.has(s))return {done:false,duplicate:true,progress:this.progress};
    if(this.#count++>=MAX_FRAGMENTS)throw Error("Too many QR frames");
    this.#totalChars+=s.length;
    if(this.#totalChars>MAX_PAYLOAD*6)throw Error("Typed QR aggregate budget exceeded");
    this.#seen.add(s);
    try {
      let raw;
      if (parts.length===2) {
        raw=decodeBytewords(parts[1],"minimal");
      } else {
        const header=parts[1].split("-").map(Number);
        const part=preflightFountainPart(parts[2],header[0],header[1],this.#fountainMeta);
        this.#fountainMeta??={
          seqLen:part.seqLen,messageLen:part.messageLen,
          checksum:part.checksum,dataLength:part.data.length
        };
        this.#decoder.add(part);
        if (!this.#decoder.done) return {done:false,duplicate:false,progress:this.progress};
        raw=this.#decoder.result;
      }
      // Enforce exact on-wire CBOR resource bounds *before* dCBOR materialization.
      preflightCbor(raw);
      const ur=UR.from(m[1],decodeCbor(raw));
      this.#done=parseTypedUR(ur);
      return {done:true,duplicate:false,progress:1};
    }catch(err){this.reset();throw Error("Typed UR rejected: "+err.message);}
  }
}
