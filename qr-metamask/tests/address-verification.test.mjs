import test from 'node:test';
import assert from 'node:assert/strict';
import { verifySelectedAddress } from '../src/address_verification.mjs';

const address='0x000000000000000000000000000000000000dEaD';
const other='0x0000000000000000000000000000000000000001';

test('accepts exact selected MetaMask address in plain and Sepolia account QR forms',()=>{
  assert.equal(verifySelectedAddress(address,address),address);
  assert.equal(verifySelectedAddress(address.toLowerCase(),address),address);
  assert.equal(verifySelectedAddress('ethereum:'+address+'@11155111',address),address);
  assert.equal(verifySelectedAddress('ethereum:'+address,address),address);
});

test('refuses a different MetaMask selected address even when QR is well formed',()=>{
  for(const payload of [other,'ethereum:'+other,'ethereum:'+other+'@11155111']) {
    assert.throws(()=>verifySelectedAddress(payload,address),/不同/);
  }
});

test('rejects mainnet, payment instructions and overlong or invalid QR payloads',()=>{
  for(const payload of [
    'ethereum:'+address+'@1',address+'@11155111',
    'ethereum:'+address+'?value=1',
    'ethereum:'+address+'@11155111?value=1',
    address+'?value=1','0x1234','https://attacker.example/'+address,
    'ethereum:'+address+'/transfer?address='+other,
    '', 'z'.repeat(200), null,
  ]) {
    assert.throws(()=>verifySelectedAddress(payload,address),/./,String(payload));
  }
});
