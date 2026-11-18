/**
 * MetaMask native QR Hardware Wallet adapter using Keystone's upstream
 * CryptoAccount, eth-sign-request and eth-signature CBOR/UR types.
 * PUBLIC-DATA/TRANSPORT CODE ONLY: never accepts a seed or signing key.
 */
import { Buffer } from 'buffer';
import {
  CryptoHDKey, CryptoKeypath, PathComponent,
} from '@keystonehq/bc-ur-registry';
import { DataType, EthSignRequest, ETHSignature } from '@keystonehq/bc-ur-registry-eth';
import { URDecoder, UREncoder } from '@ngraveio/bc-ur';
import { Transaction, getAddress, computeAddress, HDNodeWallet } from 'ethers';

export const MAX_FRAMES = 512;
export const MAX_FRAGMENT = 3000;
export const MAX_CBOR = 100_000;
export const CHAIN_ID = 11155111n;
export const PATH = "44'/60'/0'/0/0";
const FORMAT = 'usb-cold-keystone-public-v1';
const MAX_FEE = 1_000_000_000_000n;
const hexBytes = (v, bytes) => {
  if (typeof v !== 'string' || !new RegExp('^[0-9a-fA-F]{' + bytes * 2 + '}$').test(v)) {
    throw new Error('Invalid public hex field (' + bytes + ' bytes)');
  }
  return Buffer.from(v, 'hex');
};
const checkedAddress = (a) => {
  if (typeof a !== 'string') throw new Error('Invalid EVM address');
  return getAddress(a);
};
const components = () => [44, 60, 0, 0, 0].map((v,i) => new PathComponent({index:v,hardened:i<3}));

export function validatePublic(info) {
  if (!info || typeof info !== 'object' || Array.isArray(info) ||
      info.format !== FORMAT || info.network !== 'sepolia' ||
      info.chain_id !== 11155111 || info.account_derivation !== 'm/44h/60h/0h' ||
      info.address_derivation !== 'm/44h/60h/0h/0/0') {
    throw new Error('Invalid PUBLIC EVM export; Sepolia only');
  }
  const permitted = new Set(['format','network','chain_id','master_fingerprint','account_derivation','address_derivation','account_public_key','account_chain_code','account_parent_fingerprint','address_public_key','address_chain_code','address_parent_fingerprint','address']);
  if (Object.keys(info).some((k)=>!permitted.has(k))) throw new Error('Unexpected field in public-only export');
  const fingerprint = hexBytes(info.master_fingerprint,4);
  const key = hexBytes(info.address_public_key,33);
  const chainCode = hexBytes(info.address_chain_code,32);
  const parentFingerprint = hexBytes(info.address_parent_fingerprint,4);
  if (![2,3].includes(key[0])) throw new Error('Invalid compressed secp256k1 public key');
  const address = checkedAddress(info.address);
  if (computeAddress('0x'+key.toString('hex')) !== address) {
    throw new Error('Public key and address mismatch');
  }
  return {fingerprint,key,chainCode,parentFingerprint,address};
}
export function makePairingUr(publicInfo) {
  const {fingerprint,address} = validatePublic(publicInfo);
  const key=hexBytes(publicInfo.account_public_key,33);
  const chainCode=hexBytes(publicInfo.account_chain_code,32);
  const parentFingerprint=hexBytes(publicInfo.account_parent_fingerprint,4);
  if (![2,3].includes(key[0])) throw new Error('Invalid account xpub');
  const path = new CryptoKeypath(components().slice(0,3),fingerprint);
  const children = new CryptoKeypath([
    new PathComponent({index:0,hardened:false}),
    new PathComponent({hardened:false}), // wildcard: QR Keyring derives index 0..N
  ]);
  const hdKey = new CryptoHDKey({
    isMaster:false,isPrivateKey:false,key,chainCode,parentFingerprint,origin:path,
    children,name:'USB Cold Signer — Sepolia',note:'Only address index 0 can sign',
  });
  // MetaMask QR Keyring requests 5 accounts from an HDKey. Exporting a
  // single-address CryptoAccount fails its getFirstPage() implementation.
  const parsed = CryptoHDKey.fromCBOR(hdKey.toCBOR());
  const first = HDNodeWallet.fromExtendedKey(parsed.getBip32Key()).derivePath('0/0');
  if (first.address !== address) throw new Error('Public account xpub does not derive the exported address');
  return hdKey.toUR();
}
export function decodeUr(input, expectedType) {
  if (input && typeof input === 'object' && !Array.isArray(input) && typeof input.type === 'string' && typeof input.cbor === 'string') {
    if (input.type !== expectedType || input.cbor.length > MAX_CBOR*2 || !/^(?:[0-9a-fA-F]{2})+$/.test(input.cbor)) {
      throw new Error('Wrong or oversized CBOR UR');
    }
    return {type:input.type,cbor:Buffer.from(input.cbor,'hex')};
  }
  const parts = typeof input === 'string' ? input.trim().split(/\s+/) : input;
  if (!Array.isArray(parts) || parts.length < 1 || parts.length > MAX_FRAMES) throw new Error('Invalid QR frame count');
  const decoder = new URDecoder();
  for (const part of parts) {
    if (typeof part !== 'string' || part.length > MAX_FRAGMENT ||
        !/^ur:[a-z0-9-]+\//i.test(part)) throw new Error('Invalid or oversized UR frame');
    decoder.receivePart(part);
    if (decoder.isError()) throw new Error('Invalid QR fragment');
    if (decoder.isComplete()) break;
  }
  if (!decoder.isSuccess()) throw new Error('UR frames incomplete');
  const ur = decoder.resultUR();
  if (ur.type !== expectedType || ur.cbor.length > MAX_CBOR) throw new Error('Unexpected UR type or oversize CBOR');
  return ur;
}
export function framesFromUr(ur, maxFragment=220, count=8) {
  if (!ur || typeof ur.type !== 'string' || !ur.cbor || ur.cbor.length>MAX_CBOR ||
      !Number.isInteger(maxFragment) || maxFragment < 80 || maxFragment > 400 ||
      !Number.isInteger(count) || count<1 || count>MAX_FRAMES) throw new Error('Invalid QR encoding limits');
  const encoder = new UREncoder(ur,maxFragment);
  const frames=[];
  // Each animation repeats, fountain frame sequence may be longer than part count.
  for(let i=0;i<Math.max(count,encoder.fragmentsLength);i++) {
    if(i>=MAX_FRAMES) throw new Error('Too many QR frames');
    const part=encoder.nextPart();
    if(part.length>MAX_FRAGMENT) throw new Error('QR frame too large');
    frames.push(part);
  }
  return frames;
}
export function decodeMetaMaskRequest(input, publicInfo) {
  const account=validatePublic(publicInfo);
  const ur=decodeUr(input,'eth-sign-request');
  const request=EthSignRequest.fromCBOR(ur.cbor);
  if (request.getDataType()!==DataType.typedTransaction ||
      BigInt(request.getChainId() ?? 0)!==CHAIN_ID ||
      request.getDerivationPath()!==PATH ||
      !request.getRequestId() || request.getRequestId().length!==16 ||
      !request.getSourceFingerprint() ||
      !Buffer.from(request.getSourceFingerprint()).equals(account.fingerprint)) {
    throw new Error('Unsupported chain, method, derivation, master fingerprint or missing request ID');
  }
  const requestedAddress=request.getSignRequestAddress();
  if (requestedAddress &&
      checkedAddress('0x'+Buffer.from(requestedAddress).toString('hex'))!==account.address) {
    throw new Error('Transaction requested for different cold account');
  }
  const signData=Buffer.from(request.getSignData());
  if(signData.length<4 || signData.length>4096 || signData[0]!==2) throw new Error('Expected unsigned type-2 transaction bytes');
  const serialized='0x'+signData.toString('hex');
  let tx;
  try { tx=Transaction.from(serialized); } catch { throw new Error('Malformed unsigned EIP-1559 transaction'); }
  if (tx.isSigned() || tx.type!==2 || tx.chainId!==CHAIN_ID || !tx.to ||
      tx.gasLimit!==21000n || tx.value<=0n || tx.data!=='0x' ||
      tx.maxFeePerGas===null || tx.maxPriorityFeePerGas===null ||
      tx.maxFeePerGas<=0n || tx.maxFeePerGas>MAX_FEE ||
      tx.maxPriorityFeePerGas>tx.maxFeePerGas ||
      (tx.accessList?.length ?? 0)!==0 ||
      tx.unsignedSerialized.toLowerCase()!==serialized.toLowerCase() ||
      !Number.isSafeInteger(tx.nonce)) {
    throw new Error('Unsafe or noncanonical Sepolia native ETH transfer');
  }
  return {requestId:Buffer.from(request.getRequestId()).toString('hex'),
    rawUnsigned:serialized,account:account.address,
    fingerprint:account.fingerprint.toString('hex'),tx,ur};
}

/** Return a precise JSON number-token document for the existing Python CLI.
 * Never run JSON.stringify directly on large Wei values. */
export function unsignedJsonForOffline(session) {
  if (!session?.tx || session.tx.type !== 2) throw new Error('Missing approved Sepolia request');
  const t=session.tx;
  return '{"type":2,"chainId":11155111,"nonce":' + t.nonce +
    ',"to":"' + checkedAddress(t.to) +
    '","value":' + t.value.toString(10) +
    ',"gas":21000,"maxFeePerGas":' + t.maxFeePerGas.toString(10) +
    ',"maxPriorityFeePerGas":' + t.maxPriorityFeePerGas.toString(10) +
    ',"data":"0x","accessList":[]}';
}
export function makeSignedResponseUr(requestSession, signedResult) {
  if (!requestSession || !signedResult || typeof signedResult!=='object') throw new Error('Missing signing context');
  const raw=signedResult.signed_raw_transaction;
  if(typeof raw!=='string' || !/^0x[0-9a-fA-F]{4,8192}$/.test(raw)) throw new Error('Invalid signed raw transaction');
  let signed;
  try { signed=Transaction.from(raw); } catch { throw new Error('Signed transaction is invalid RLP'); }
  const unsigned=requestSession.tx;
  if(!signed.isSigned() || !signed.signature || signed.type!==2 || signed.chainId!==CHAIN_ID ||
     signed.from!==requestSession.account ||
     signed.unsignedSerialized!==unsigned.unsignedSerialized ||
     signed.nonce!==unsigned.nonce || signed.value!==unsigned.value ||
     signed.gasLimit!==unsigned.gasLimit || signed.to!==unsigned.to ||
     signed.data!=='0x' || (signed.accessList?.length ?? 0)!==0 ||
     signed.maxFeePerGas!==unsigned.maxFeePerGas ||
     signed.maxPriorityFeePerGas!==unsigned.maxPriorityFeePerGas ||
     signedResult.transaction_hash?.toLowerCase()!==signed.hash?.toLowerCase()) {
    throw new Error('Signed transaction does not match MetaMask QR request');
  }
  const signature=Buffer.concat([
    hexBytes(signed.signature.r.slice(2),32),
    hexBytes(signed.signature.s.slice(2),32),
    Buffer.from([signed.signature.yParity]),
  ]);
  return new ETHSignature(signature, Buffer.from(requestSession.requestId,'hex')).toUR();
}
