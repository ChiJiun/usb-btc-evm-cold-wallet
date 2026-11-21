import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {spawnSync} from "node:child_process";
import {readFileSync} from "node:fs";
import {UR} from "@blockchaincommons/uniform-resources";
import {encodeCbor,cbor} from "@blockchaincommons/dcbor";
import {makeTypedUR,parseTypedUR,encodeTypedFrames,TypedURScanner,bindTypedToPending} from "../src/typed_registry.mjs";
const rid="1234567890abcdef1234567890abcdef";
const address="0x000000000000000000000000000000000000dead";
const tx={network:"sepolia",chainId:11155111,dataType:4,requestId:rid,
 unsignedTxHex:"02ea83aa36a780843b9aca00847735940082520894000000000000000000000000000000000000dead0180c0",address,path:[{index:44,hardened:true},{index:60,hardened:true},{index:0,hardened:true},{index:0,hardened:false},{index:0,hardened:false}],fingerprint:"aabbccdd"};
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
 assert.deepEqual(out,{type:"eth-sign-request",requestId:rid,unsignedTxHex:"02ea83aa36a780843b9aca00847735940082520894000000000000000000000000000000000000dead0180c0",
  dataType:4,chainId:11155111,network:"sepolia",address,
  path:[{index:44,hardened:true},{index:60,hardened:true},{index:0,hardened:true},{index:0,hardened:false},{index:0,hardened:false}],fingerprint:"aabbccdd"});
 assert.deepEqual(scan(encodeTypedFrames("eth-sign-request",tx)).payload,out);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,chainId:1}),/Sepolia/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,dataType:2}),/typed/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,unsignedTxHex:"01c101"}),/type-2/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,unsignedTxHex:tx.unsignedTxHex.replace("aa36a7","aa36a8")}),/wrong-chain/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,unsignedTxHex:tx.unsignedTxHex.replace("02ea","02eb")+"80"}),/Signed or oversized/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,unsignedTxHex:tx.unsignedTxHex.replace("0180c0","0181ffc0").replace("02ea","02eb")}),/Unsafe or wrong-chain/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,unsignedTxHex:"02c101"}),/nine unsigned|type-2|RLP/);
 assert.throws(()=>makeTypedUR("eth-sign-request",{...tx,path:[{index:2147483648,hardened:false}]}),/path/);
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
 assert.throws(()=>bindTypedToPending(sig,pending,{now:2000}),/Independent EIP-1559/);
 assert.deepEqual(bindTypedToPending(sig,pending,{now:2000,verifySignature:()=>true}),sig);
 assert.throws(()=>bindTypedToPending(sig,{...pending,unsignedDigest:undefined},{now:2000,verifySignature:()=>true}),/Independent EIP-1559/);
 assert.throws(()=>bindTypedToPending(sig,pending,{now:2000,verifySignature:()=>false}),/Independent EIP-1559/);
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
 assert.throws(()=>parseTypedUR(poisoned),/CBOR map field mismatch|Missing CBOR/);
});

test("independent Python CBOR oracle validates exact standardized typed wire layout",()=>{
 const source=ur=>{
   const py=spawnSync("python3",["tests/python_typed_oracle.py"],{
     cwd:process.cwd(),input:Buffer.from(encodeCbor(ur.cbor)).toString("hex"),
     encoding:"utf8",timeout:5000
   });
   assert.equal(py.status,0,py.stderr);
   return JSON.parse(py.stdout);
 };
 const bitcoin=source(makeTypedUR("crypto-psbt",{psbtHex}));
 assert.deepEqual(bitcoin,{hex:psbtHex}); // direct byte string; no app-specific wrapping
 const request=source(makeTypedUR("eth-sign-request",tx));
 assert.deepEqual(Object.keys(request),["1","2","3","4","5","6"]);
 assert.deepEqual(request["1"],{tag:37,value:{hex:rid}});
 assert.equal(request["2"].hex,tx.unsignedTxHex);
 assert.equal(request["3"],4);
 assert.equal(request["4"],11155111);
 assert.deepEqual(request["5"],{tag:304,value:{
   "1":[44,true,60,true,0,true,0,false,0,false],
   "2":0xaabbccdd,"3":5,
 }});
 assert.equal(request["6"].hex,address.slice(2));
 const sig=source(makeTypedUR("eth-signature",{requestId:rid,signatureHex:"11".repeat(64)+"1b"}));
 assert.deepEqual(Object.keys(sig),["1","2"]);
 assert.deepEqual(sig["1"],{tag:37,value:{hex:rid}});
 assert.equal(sig["2"].hex.length,130);
});

test("Bitcoin Core/Sparrow shared external BIP174 PSBT fixture is preserved byte-for-byte",()=>{
 const fixture=JSON.parse(readFileSync(new URL("../../tests/fixtures/external_psbt_vectors.json",import.meta.url),"utf8"));
 assert.equal(fixture.provenance.bitcoin_core.repository,"bitcoin/bitcoin");
 assert.equal(fixture.provenance.sparrow.repository,"sparrowwallet/drongo");
 const raw=Buffer.from(fixture.vectors.shared_bip174_valid_v0.base64,"base64");
 const psbtHex=raw.toString("hex");
 const frames=encodeTypedFrames("crypto-psbt",{psbtHex},{fragmentBytes:110});
 const typed=scan(frames).payload;
 assert.equal(typed.psbtHex,psbtHex);
 assert.deepEqual(Buffer.from(typed.psbtHex,"hex"),raw);
 // This known P2PKH PSBT is intentionally rejected by the separate P2WPKH
 // wallet-policy verifier. Transport alone does NOT confer signing authority.
 assert.equal(fixture.vectors.shared_bip174_valid_v0.expect_wallet_policy,false);
});

test("signed crypto-psbt cannot be confused with unsigned request without independent verifier",()=>{
 const pending={type:"crypto-psbt",phase:"signed",createdAt:1000,ttlMs:5000,
  psbtDigest:digest(psbtHex),requestId:rid};
 const signed=parseTypedUR(makeTypedUR("crypto-psbt",{psbtHex:"70736274ff"+"aa".repeat(80)}));
 assert.throws(()=>bindTypedToPending(signed,pending,{now:2000}),/Independent signed PSBT/);
 assert.throws(()=>bindTypedToPending(signed,pending,{now:2000,verifySignedPsbt:()=>false}),/Independent signed PSBT/);
 assert.deepEqual(bindTypedToPending(signed,pending,{now:2000,verifySignedPsbt:()=>true}),signed);
 const unsigned={...pending,phase:"unsigned"};
 assert.throws(()=>bindTypedToPending(signed,unsigned,{now:2000}),/PSBT bytes differ/);
});
