/**
 * Optional on-VM cross-language compatibility test. Uses a *publicly
 * compromised* BIP39 reference vector; NEVER use production wallet data.
 * Run: PYTHON_BIN=../.venv/bin/python node --test tests/python-integration.mjs
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { Transaction } from 'ethers';
import { QrKeyring } from '@metamask/eth-qr-keyring';
import { EthSignRequest, DataType, ETHSignature } from '@keystonehq/bc-ur-registry-eth';
import { makePairingUr, decodeMetaMaskRequest, makeSignedResponseUr } from '../src/adapter.mjs';

const python = process.env.PYTHON_BIN;
test('real Python embit public BIP32 and Python eth-account signature -> MetaMask QR Keyring', {skip:!python}, async () => {
  const script = [
    'import json',
    'from usb_cold_wallet.keys import root_from_mnemonic',
    'from usb_cold_wallet.keystone_public import export_keystone_public',
    'from usb_cold_wallet.evm import sign_evm',
    'root = root_from_mnemonic("abandon " * 11 + "about")',
    'recipient = "0x000000000000000000000000000000000000dEaD"',
    'value = 123456789012345678',
    'tx = {"type":2,"chainId":11155111,"nonce":1,"to":recipient,"value":value,"gas":21000,"maxFeePerGas":5000000000,"maxPriorityFeePerGas":1000000000,"data":"0x","accessList":[]}',
    'print(json.dumps({"public":export_keystone_public(root),"signed":sign_evm(root,tx,recipient,value)}))',
  ].join('\n');
  const data=JSON.parse(execFileSync(python,['-c',script],{encoding:'utf8',timeout:30_000,maxBuffer:100000}));
  const pair=makePairingUr(data.public);
  const qr=new QrKeyring({bridge:{requestScan:async()=>{throw Error('Unexpected camera')}}});
  qr.pairDevice({type:pair.type,cbor:pair.cbor.toString('hex')});
  assert.equal((await qr.getFirstPage())[0].address,data.public.address);
  const signed=Transaction.from(data.signed.signed_raw_transaction);
  const request=EthSignRequest.constructETHRequest(
    Buffer.from(signed.unsignedSerialized.slice(2),'hex'),DataType.typedTransaction,
    "m/44'/60'/0'/0/0",data.public.master_fingerprint,
    '00000000-0000-4000-8000-000000000001',11155111).toUR();
  const decoded=decodeMetaMaskRequest({type:request.type,cbor:request.cbor.toString('hex')},data.public);
  const response=makeSignedResponseUr(decoded,data.signed);
  const parsed=ETHSignature.fromCBOR(response.cbor);
  assert.equal(parsed.getRequestId().toString('hex'),decoded.requestId);
  assert.equal(parsed.getSignature().length,65);
  assert.equal(parsed.getSignature()[64],signed.signature.yParity);
});
