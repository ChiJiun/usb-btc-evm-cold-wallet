import test from 'node:test';
import assert from 'node:assert/strict';
import { HDNodeWallet, Transaction } from 'ethers';
import { QrKeyring } from '@metamask/eth-qr-keyring';
import { FeeMarketEIP1559Transaction } from '@ethereumjs/tx';
import { Common, Hardfork } from '@ethereumjs/common';
import { makePairingUr, decodeMetaMaskRequest, makeSignedResponseUr } from '../src/adapter.mjs';

// Publicly compromised deterministic fixture only. NEVER send real funds.
const root=HDNodeWallet.fromSeed(new Uint8Array(64).fill(1));
const accountNode=root.derivePath("m/44'/60'/0'");
const wallet=accountNode.derivePath('0/0');
const recipient='0x000000000000000000000000000000000000dEaD';
const publicInfo={
  format:'usb-cold-keystone-public-v1',network:'sepolia',chain_id:11155111,
  master_fingerprint:root.fingerprint.slice(2),
  account_derivation:'m/44h/60h/0h',address_derivation:'m/44h/60h/0h/0/0',
  account_public_key:accountNode.publicKey.slice(2),account_chain_code:accountNode.chainCode.slice(2),
  account_parent_fingerprint:accountNode.parentFingerprint.slice(2),
  address_public_key:wallet.publicKey.slice(2),address_chain_code:wallet.chainCode.slice(2),
  address_parent_fingerprint:wallet.parentFingerprint.slice(2),address:wallet.address,
};
const txData={
  type:2,chainId:11155111,nonce:1,to:recipient,value:123456789012345678n,
  gasLimit:21000,maxFeePerGas:5000000000n,maxPriorityFeePerGas:1000000000n,
  data:'0x',accessList:[],
};
test('real MetaMask QR Keyring signTransaction -> Keystone request -> offline signed raw -> ETHSignature',async()=>{
  const pair=makePairingUr(publicInfo);
  let sawRequest=false;
  const keyring=new QrKeyring({bridge:{requestScan:async ({type,request})=>{
    assert.equal(type,'sign');
    sawRequest=true;
    const decoded=decodeMetaMaskRequest(request.payload,publicInfo);
    const raw=await wallet.signTransaction(txData);
    const signed=Transaction.from(raw);
    const answer=makeSignedResponseUr(decoded,{signed_raw_transaction:raw,transaction_hash:signed.hash});
    return {type:answer.type,cbor:answer.cbor.toString('hex')};
  }}});
  keyring.pairDevice({type:pair.type,cbor:pair.cbor.toString('hex')});
  const common=Common.custom({chainId:11155111},{hardfork:Hardfork.London});
  const original=FeeMarketEIP1559Transaction.fromTxData({
    nonce:1n,gasLimit:21000n,to:recipient,value:txData.value,
    maxFeePerGas:txData.maxFeePerGas,maxPriorityFeePerGas:txData.maxPriorityFeePerGas,
    chainId:11155111,
  },{common});
  const output=await keyring.signTransaction(wallet.address,original);
  assert.equal(sawRequest,true);
  assert.equal(output.isSigned(),true);
  assert.equal(output.value,txData.value);
});
