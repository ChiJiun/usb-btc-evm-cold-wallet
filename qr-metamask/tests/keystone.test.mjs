import test from 'node:test';
import assert from 'node:assert/strict';
import { Wallet, Transaction, HDNodeWallet } from 'ethers';
import { DataType, EthSignRequest, ETHSignature } from '@keystonehq/bc-ur-registry-eth';
import { QrKeyring } from '@metamask/eth-qr-keyring';
import { makePairingUr, decodeMetaMaskRequest, makeSignedResponseUr,
  unsignedJsonForOffline, framesFromUr, decodeUr, validatePublic } from '../src/adapter.mjs';

// Deterministic, publicly known test-only private key. Never use for funds.
const root = HDNodeWallet.fromSeed(new Uint8Array(64).fill(1));
const accountNode = root.derivePath("m/44'/60'/0'");
const w = accountNode.derivePath('0/0');
const recipient = '0x000000000000000000000000000000000000dEaD';
const info = Object.freeze({
  format:'usb-cold-keystone-public-v1',network:'sepolia',chain_id:11155111,
  master_fingerprint:root.fingerprint.slice(2),account_derivation:'m/44h/60h/0h',
  address_derivation:'m/44h/60h/0h/0/0',
  account_public_key:accountNode.publicKey.slice(2),
  account_chain_code:accountNode.chainCode.slice(2),
  account_parent_fingerprint:accountNode.parentFingerprint.slice(2),
  address_public_key:w.publicKey.slice(2),
  address_chain_code:w.chainCode.slice(2),
  address_parent_fingerprint:w.parentFingerprint.slice(2),address:w.address,
});
const data = Object.freeze({
  type:2,chainId:11155111,nonce:1,to:recipient,
  value:123456789012345678n,gasLimit:21000,maxFeePerGas:5_000_000_000n,
  maxPriorityFeePerGas:1_000_000_000n,data:'0x',accessList:[],
});
function request(override={}) {
  const tx=Transaction.from({...data,...override});
  const envelope=EthSignRequest.constructETHRequest(
    Buffer.from(tx.unsignedSerialized.slice(2),'hex'),DataType.typedTransaction,
    "m/44'/60'/0'/0/0",info.master_fingerprint,'00000000-0000-4000-8000-000000000001',11155111,
  );
  return envelope.toUR();
}
test('MetaMask upstream QrKeyring pairs actual CryptoHDKey and recognizes exact public address/path', async()=>{
  const ur=makePairingUr(info);
  assert.equal(ur.type,'crypto-hdkey');
  const keyring=new QrKeyring({bridge:{requestScan:async()=>{throw Error('Not expected')}}});
  keyring.pairDevice({type:ur.type,cbor:ur.cbor.toString('hex')});
  const page=await keyring.getFirstPage();
  assert.equal(page[0].address,w.address);
  assert.equal(keyring.getPathFromAddress(w.address),"m/44'/60'/0'/0/0");
  const frames=framesFromUr(ur,220,16);
  const decoded=decodeUr(frames,'crypto-hdkey');
  assert.equal(decoded.cbor.toString('hex'),ur.cbor.toString('hex'));
});
test('decode upstream Keystone typed EIP-1559 request with full precision, unchanged signing bytes',()=>{
  const parsed=decodeMetaMaskRequest({type:request().type,cbor:request().cbor.toString('hex')},info);
  assert.equal(parsed.account,w.address);
  assert.equal(parsed.requestId,'00000000000040008000000000000001');
  const serialized=unsignedJsonForOffline(parsed);
  const json=JSON.parse(serialized);
  assert.equal(json.chainId,11155111);
  assert.match(serialized,/"value":123456789012345678/);
  assert.equal(serialized.includes('"value":"'),false);
  assert.equal(parsed.tx.unsignedSerialized,Transaction.from(data).unsignedSerialized);
});
test('Keystone ETHSignature reply is accepted by same upstream registry and matches signed transaction',async()=>{
  const req=request();
  const parsed=decodeMetaMaskRequest({type:req.type,cbor:req.cbor.toString('hex')},info);
  const signed=await w.signTransaction(data);
  const tx=Transaction.from(signed);
  const ur=makeSignedResponseUr(parsed,{signed_raw_transaction:signed,transaction_hash:tx.hash});
  assert.equal(ur.type,'eth-signature');
  const result=ETHSignature.fromCBOR(ur.cbor);
  assert.equal(result.getRequestId().toString('hex'),parsed.requestId);
  assert.equal(result.getSignature().length,65);
  assert.equal(result.getSignature().slice(0,32).toString('hex'),tx.signature.r.slice(2));
  assert.equal(result.getSignature()[64],tx.signature.yParity);
});
test('hard stop for non-Sepolia, blind signing, different path/fingerprint, account or QR response tampering',async()=>{
  assert.throws(()=>validatePublic({...info,seed:'do-not-import'}),/Unexpected/);
  assert.throws(()=>validatePublic({...info,address:recipient}),/mismatch/);
  const good=request();
  const base=decodeMetaMaskRequest({type:good.type,cbor:good.cbor.toString('hex')},info);
  for(const [name,tx] of [
    ['network',{chainId:1}],
    ['contract',{data:'0x12',gasLimit:22000}],
    ['recipient',{to:null}],
    ['gas',{gasLimit:25000}],
    ['accessList',{accessList:[{address:recipient,storageKeys:[]}]}],
  ]) {
    const payload=request(tx);
    assert.throws(()=>decodeMetaMaskRequest({type:payload.type,cbor:payload.cbor.toString('hex')},info),/./,name);
  }
  const wrongPath=EthSignRequest.constructETHRequest(
    Buffer.from(Transaction.from(data).unsignedSerialized.slice(2),'hex'),
    DataType.typedTransaction,"m/44'/60'/1'/0/0",info.master_fingerprint,
    '00000000-0000-4000-8000-000000000001',11155111).toUR();
  assert.throws(()=>decodeMetaMaskRequest({type:wrongPath.type,cbor:wrongPath.cbor.toString('hex')},info),/derivation/);
  const signed=await w.signTransaction({...data,nonce:2});
  const wrong=Transaction.from(signed);
  assert.throws(()=>makeSignedResponseUr(base,{signed_raw_transaction:signed,transaction_hash:wrong.hash}),/does not match/);
  const other= new Wallet('0x'+'22'.repeat(32));
  const otherRaw=await other.signTransaction(data);
  assert.throws(()=>makeSignedResponseUr(base,{signed_raw_transaction:otherRaw,transaction_hash:Transaction.from(otherRaw).hash}),/does not match/);
  assert.throws(()=>decodeUr(['ur:bytes/abcd'],'eth-sign-request'),/./);
});
