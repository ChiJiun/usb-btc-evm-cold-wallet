import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {UR} from "@blockchaincommons/uniform-resources";
import {encodeCbor,cbor} from "@blockchaincommons/dcbor";
import {makeTypedUR,parseTypedUR,encodeTypedFrames,TypedURScanner,bindTypedToPending} from "../src/typed_registry.mjs";
const rid="1234567890abcdef1234567890abcdef";
const address="0x000000000000000000000000000000000000dead";
const tx={network:"sepolia",chainId:11155111,dataType:4,requestId:rid,
 unsignedTxHex:"02c101",address,path:[44,60,0,0,0],fingerprint:"aabbccdd"};
const psbtHex="70736274ff01000100";
const digest=x=>createHash("sha256").update(Buffer.from(x,"hex")).digest("hex");
const scan=frames=>{const s=new TypedURScanner();for(const f of frames){s.add(f);if(s.done)break;}return s;};
test("BCR crypto-psbt is a real bare CBOR byte string, not JSON or a map",()=>{
 const ur=makeTypedUR("crypto-psbt",{psbtHex});
 assert.equal(ur.toQRString().toLowerCase().startsWith("ur:crypto-psbt/"),true);
 assert.equal(Buffer.from(encodeCbor(ur.cbor)).toString("hex"),"49"+psbtHex);
 assert.deepEqual(parseTypedUR(UR.parse(ur.toQRString().toLowerCase())),{type:"crypto-psbt",psbtHex});
 assert.deepEqual(scan(encodeTypedFrames("crypto-psbt",{psbtHex})).payload,{type:"crypto-psbt",psbtHex});
 assert.throws(()=>makeTypedUR("crypto-psbt",{psbtHex:"deadbeef"}),/magic/);
});
test("ERC-4527 EIP-2718 typed request uses integer-key CBOR and tagged UUID/keypath",()=>{
 const ur=makeTypedUR("eth-sign-request",tx);
 assert.equal(ur.toQRString().toLowerCase().startsWith("ur:eth-sign-request/"),true);
 const out=parseTypedUR(UR.parse(ur.toQRString().toLowerCase()));
 assert.deepEqual(out,{type:"eth-sign-request",requestId:rid,unsignedTxHex:"02c101",
  dataType:4,chainId:11155111,network:"sepolia",address,
  path:[44,60,0,0,0],fingerprint:"aabbccdd"});
 assert.deepEqual(scan(encodeTypedFrames("eth-sign-request",tx)).payload,out);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,chainId:1}),/Sepolia/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,dataType:2}),/typed/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,unsignedTxHex:"01c101"}),/type-2/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,path:[2147483648]}),/path/);
});
test("ERC-4527 response contains precisely 65 r,s,v bytes, never a raw signed transaction",()=>{
 const signatureHex="11".repeat(32)+"22".repeat(32)+"1b";
 const ur=makeTypedUR("eth-signature",{requestId:rid,signatureHex});
 assert.deepEqual(parseTypedUR(UR.parse(ur.toQRString().toLowerCase())),
  {type:"eth-signature",requestId:rid,signatureHex});
 assert.throws(()=>makeTypedUR("eth-signature",{requestId:rid,signatureHex:"02ff"}),/65-byte/);
 assert.throws(()=>makeTypedUR("eth-signature",{requestId:rid,signatureHex:"11".repeat(64)+"ff"}),/recovery/);
});
test("immutable pending context binds chain/account/request/digest and refuses stale, wrong or replayed QR",()=>{
 const parsed=parseTypedUR(makeTypedUR("eth-sign-request",tx));
 const pending={type:parsed.type,chainId:11155111,address,requestId:rid,
   unsignedDigest:digest(tx.unsignedTxHex),createdAt:1000,ttlMs:5000};
 assert.deepEqual(bindTypedToPending(parsed,pending,{now:2000}),parsed);
 for(const changed of [{requestId:"f".repeat(32)},{chainId:1},{address:"0x"+"ff".repeat(20)},
 {unsignedDigest:"0".repeat(64)},{consumed:true},{cancelled:true}]) {
  assert.throws(()=>bindTypedToPending(parsed,{...pending,...changed},{now:2000}),/mismatch|closed|Expired/);
 }
 assert.throws(()=>bindTypedToPending(parsed,pending,{now:7000}),/Expired/);
 const sig=parseTypedUR(makeTypedUR("eth-signature",{requestId:rid,signatureHex:"11".repeat(64)+"1b"}));
 assert.deepEqual(bindTypedToPending(sig,{...pending,type:"eth-signature"},{now:2000}),sig);
 assert.throws(()=>bindTypedToPending(sig,{...pending,type:"eth-signature",unsignedDigest:undefined},{now:2000}),/original unsigned/);
});
test("bounded multipart rejects wrong type, mixed messages, malformed CBOR, scan timeout and excessive frames",()=>{
 const large={psbtHex:"70736274ff"+"aa".repeat(11000)};
 const frames=encodeTypedFrames("crypto-psbt",large,{fragmentBytes:180});
 assert.ok(frames.length>5);
 const scanner=new TypedURScanner({expectedType:"crypto-psbt"});
 for(const f of [...frames].reverse()){scanner.add(f);if(scanner.done)break;}
 assert.equal(scanner.payload.psbtHex,large.psbtHex);
 assert.throws(()=>scanner.add(frames[0]),/already completed/);
 scanner.reset();
 scanner.add(frames[0]);
 assert.equal(scanner.add(frames[0]).duplicate,true);
 assert.throws(()=>scanner.add(encodeTypedFrames("eth-sign-request",tx)[0]),/Unsupported typed|Mixed/);
 const mixed=new TypedURScanner();
 mixed.add(frames[0]);
 const other=encodeTypedFrames("crypto-psbt",{psbtHex:"70736274ff"+"bb".repeat(11000)},{fragmentBytes:180});
 assert.throws(()=>mixed.add(other[1]),/inconsistent|rejected/i);
 assert.throws(()=>new TypedURScanner().add("ur:bytes/aaaa"),/Unsupported/);
 assert.throws(()=>new TypedURScanner().add("ur:crypto-psbt/999999-999999/abcd"),/Excessive/);
 assert.throws(()=>encodeTypedFrames("crypto-psbt",large,{fragmentBytes:32,maxFrames:2}),/fragments/);
 let now=1;
 const timer=new TypedURScanner({now:()=>now,maxDurationMs:10});
 timer.add(frames[0]);now+=11;
 assert.throws(()=>timer.add(frames[1]),/timed out/);
 const poisoned=UR.from("eth-sign-request",cbor(new Map([[1,"fake uuid"]])));
 assert.throws(()=>parseTypedUR(poisoned),/Missing CBOR/);
});
