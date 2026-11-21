/** Public-only Sepolia transaction and Issue #18 QR v1 binding. No signing keys. */
import { getAddress, sha256, toUtf8Bytes, Transaction } from 'ethers';
import { isLosslessNumber, parse } from 'lossless-json';

export const SEPOLIA_CHAIN_ID = 11155111n;
export const MAX_QR_BYTES = 150_000;
export const MAX_AGE_MS = 10 * 60 * 1000;
const MAX_GWEI = 1000n * 1_000_000_000n;
const UINT256 = (1n << 256n) - 1n;
const TX_KEYS = new Set(['type','chainId','nonce','from','to','value','gas','gasLimit','maxFeePerGas','maxPriorityFeePerGas','data','accessList']);
const SIGNED_KEYS = new Set(['chain_id','from','to','value_wei','signed_raw_transaction','transaction_hash','max_fee_wei','max_total_wei','decoded_transaction']);

export type Normalized = {
  type: '0x2'; chainId: '0xaa36a7'; nonce: string; from: string; to: string;
  value: string; gas: '0x5208'; maxFeePerGas: string; maxPriorityFeePerGas: string;
  data: '0x'; accessList: [];
};
export type Pending = {
  id: string; accountId: string; accountAddress: string; createdAt: number;
  tx: Normalized; qrRequest: string; qrRequestId: string; qrDigest: string;
  status: 'pending' | 'approving' | 'rejected';
};
export function canonical(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'bigint') return value.toString(10);
  if (typeof value === 'string') {
    if (!/^[\x00-\x7f]*$/.test(value)) throw new Error('QR values must be ASCII');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map((key) => canonical(key) + ':' + canonical((value as Record<string, unknown>)[key])).join(',') + '}';
  }
  throw new Error('Unsupported or unsafe QR JSON value');
}
function digest(value: unknown): string { return sha256(toUtf8Bytes(canonical(value))).slice(2); }
export function quantity(value: unknown, field: string): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/.test(value)) {
    throw new Error(field + ' must be a canonical 0x quantity');
  }
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > UINT256) throw new Error(field + ' out of bounds');
  return parsed;
}
const hex = (n: bigint) => '0x' + n.toString(16);
export function checkedAddress(address: unknown): string {
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error('Invalid EVM address');
  return getAddress(address);
}
export function normalizeUnsigned(input: unknown, sender: string): Normalized {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new Error('Missing transaction');
  const tx = input as Record<string, unknown>;
  if (Object.keys(tx).some((key) => !TX_KEYS.has(key))) throw new Error('Unknown transaction field');
  if (tx.gas !== undefined && tx.gasLimit !== undefined) throw new Error('Ambiguous gas fields');
  if (quantity(tx.type, 'type') !== 2n || quantity(tx.chainId, 'chainId') !== SEPOLIA_CHAIN_ID) {
    throw new Error('Sepolia EIP-1559 only');
  }
  if (checkedAddress(tx.from) !== checkedAddress(sender)) throw new Error('Wrong cold account');
  const to = checkedAddress(tx.to);
  const nonce = quantity(tx.nonce, 'nonce');
  const value = quantity(tx.value, 'value');
  const gas = quantity(tx.gasLimit ?? tx.gas, 'gas');
  const maxFee = quantity(tx.maxFeePerGas, 'maxFeePerGas');
  const priority = quantity(tx.maxPriorityFeePerGas, 'maxPriorityFeePerGas');
  if (nonce > BigInt(Number.MAX_SAFE_INTEGER) || value <= 0n || gas !== 21000n || maxFee <= 0n || priority > maxFee || maxFee > MAX_GWEI) {
    throw new Error('Unsafe nonce, value, gas, or fee policy');
  }
  if (tx.data !== undefined && tx.data !== '0x' && tx.data !== '') throw new Error('Contract calldata disabled');
  if (tx.accessList !== undefined && (!Array.isArray(tx.accessList) || tx.accessList.length !== 0)) {
    throw new Error('Access list disabled');
  }
  return { type:'0x2', chainId:'0xaa36a7', nonce:hex(nonce), from:checkedAddress(sender), to,
    value:hex(value), gas:'0x5208', maxFeePerGas:hex(maxFee), maxPriorityFeePerGas:hex(priority),
    data:'0x', accessList:[] };
}
export function makeQrRequest(id: string, accountId: string, account: string, tx: Normalized, now: number, sequence = 0): Pending {
  if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(id)) throw new Error('Invalid MetaMask request ID');
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid timestamp');
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error('Invalid request sequence');
  // A persisted sequence prevents request_id re-use after the bounded
  // closedIds cache evicts an older MetaMask ID. Do not derive solely from id.
  const requestId = sha256(toUtf8Bytes('usb-snap-v1:' + id + ':' + sequence)).slice(2, 34);
  const transaction = {
    type: 2, chainId: 11155111, nonce: BigInt(tx.nonce), to:tx.to,
    value:BigInt(tx.value), gas:21000, maxFeePerGas:BigInt(tx.maxFeePerGas),
    maxPriorityFeePerGas:BigInt(tx.maxPriorityFeePerGas), data:'0x', accessList:[],
  };
  const payload = {kind:'evm', transaction, recipient:tx.to, amount_wei:BigInt(tx.value)};
  const request = { version:1, direction:'unsigned', network:'sepolia', account:checkedAddress(account),
    request_id:requestId, payload_digest:digest(payload), payload };
  const qrRequest = canonical(request);
  if (qrRequest.length > MAX_QR_BYTES) throw new Error('Request too large');
  return { id, accountId, accountAddress:checkedAddress(account), createdAt:now, tx,
    qrRequest, qrRequestId:requestId, qrDigest:digest(request), status:'pending' };
}
/** Reject duplicate JSON properties (including escaped-key aliases) before lossless parsing. */
function rejectDuplicateKeys(raw: string): void {
  if (!/^[\x00-\x7f]*$/.test(raw)) throw new Error('QR response must be ASCII');
  let i = 0;
  const spaces = () => { while (/\s/.test(raw[i] ?? '') && i < raw.length) i++; };
  function stringToken(): string {
    const start = i;
    if (raw[i++] !== '"') throw new Error('Expected JSON string');
    let escaped = false;
    for (; i < raw.length; i++) {
      const ch = raw[i];
      if (!escaped && ch === '"') { i++; return JSON.parse(raw.slice(start, i)) as string; }
      if (!escaped && ch === '\\') escaped = true;
      else escaped = false;
    }
    throw new Error('Unterminated JSON string');
  }
  function value(depth: number): void {
    if (depth > 16) throw new Error('QR response nesting limit');
    spaces();
    if (raw[i] === '{') {
      i++; spaces();
      const seen = new Set<string>();
      if (raw[i] === '}') { i++; return; }
      for (;;) {
        spaces();
        const key = stringToken();
        if (seen.has(key)) throw new Error('Duplicate JSON property: ' + key);
        seen.add(key);
        spaces();
        if (raw[i++] !== ':') throw new Error('Expected JSON colon');
        value(depth + 1);
        spaces();
        if (raw[i] === '}') { i++; return; }
        if (raw[i++] !== ',') throw new Error('Expected JSON comma');
      }
    }
    if (raw[i] === '[') {
      i++; spaces();
      if (raw[i] === ']') { i++; return; }
      for (;;) {
        value(depth + 1);
        spaces();
        if (raw[i] === ']') { i++; return; }
        if (raw[i++] !== ',') throw new Error('Expected JSON comma');
      }
    }
    if (raw[i] === '"') { stringToken(); return; }
    const start = i;
    while (i < raw.length && !/[\s,}\]]/.test(raw[i])) i++;
    if (i === start) throw new Error('Invalid JSON token');
  }
  value(0);
  spaces();
  if (i !== raw.length) throw new Error('Trailing QR response data');
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid ' + name);
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, keys: string[], name: string): void {
  if (Object.keys(value).length !== keys.length || Object.keys(value).some((k) => !keys.includes(k))) {
    throw new Error('Unexpected ' + name + ' fields');
  }
}
const asBig = (value: unknown): bigint => {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  throw new Error('Expected exact integer');
};
export function verifyQrResponse(raw: string, pending: Pending, now: number) {
  if (pending.status !== 'pending') throw new Error('Request already completed');
  if (!Number.isSafeInteger(now) || now < pending.createdAt || now - pending.createdAt > MAX_AGE_MS) {
    throw new Error('Request timed out; no automatic retry');
  }
  if (typeof raw !== 'string' || raw.length > MAX_QR_BYTES || raw.length === 0) throw new Error('Oversize/empty QR response');
  // Preserve arbitrary-precision JSON numbers; native JSON.parse would silently round Wei.
  // Reject ambiguous duplicate object keys before lossless parsing.
  rejectDuplicateKeys(raw);
  const response = object(parse(raw, (_k, v) => isLosslessNumber(v) ? BigInt(v.value) : v), 'response');
  exactKeys(response, ['version','direction','network','account','request_id','request_digest','payload_digest','payload'], 'response');
  if (asBig(response.version) !== 1n || response.direction !== 'signed' || response.network !== 'sepolia'
    || response.account !== pending.accountAddress || response.request_id !== pending.qrRequestId
    || response.request_digest !== pending.qrDigest) throw new Error('QR request/account binding mismatch');
  const payload = object(response.payload, 'signed payload');
  if (typeof response.payload_digest !== 'string' || response.payload_digest !== digest(payload)) {
    throw new Error('QR response checksum mismatch');
  }
  // Only the known offline signer response is accepted. Never take signing commands from response.
  if (Object.keys(payload).some((k) => !SIGNED_KEYS.has(k)) ||
      !['chain_id','from','to','value_wei','signed_raw_transaction','transaction_hash'].every((k) => Object.hasOwn(payload,k))) {
    throw new Error('Unknown signed response shape');
  }
  if (asBig(payload.chain_id) !== SEPOLIA_CHAIN_ID ||
      checkedAddress(payload.from) !== pending.accountAddress ||
      checkedAddress(payload.to) !== pending.tx.to ||
      asBig(payload.value_wei) !== BigInt(pending.tx.value)) {
    throw new Error('Signed response metadata mismatch');
  }
  const rawTx = payload.signed_raw_transaction;
  if (typeof rawTx !== 'string' || !/^0x[0-9a-fA-F]{2,8192}$/.test(rawTx)) throw new Error('Invalid signed transaction');
  let signed: Transaction;
  try { signed = Transaction.from(rawTx); } catch { throw new Error('Malformed signed EIP-1559 transaction'); }
  if (!signed.isSigned() || signed.type !== 2 || signed.chainId !== SEPOLIA_CHAIN_ID ||
      !signed.from || checkedAddress(signed.from) !== pending.accountAddress ||
      !signed.to || checkedAddress(signed.to) !== pending.tx.to ||
      signed.nonce !== Number(BigInt(pending.tx.nonce)) ||
      signed.value !== BigInt(pending.tx.value) ||
      signed.gasLimit !== 21000n ||
      signed.maxFeePerGas !== BigInt(pending.tx.maxFeePerGas) ||
      signed.maxPriorityFeePerGas !== BigInt(pending.tx.maxPriorityFeePerGas) ||
      signed.data !== '0x' || (signed.accessList && signed.accessList.length !== 0)) {
    throw new Error('Signed transaction differs from reviewed request');
  }
  if (!signed.hash || typeof payload.transaction_hash !== 'string' ||
      ('0x' + payload.transaction_hash.replace(/^0x/, '')).toLowerCase() !== signed.hash.toLowerCase()) {
    throw new Error('Signed transaction hash mismatch');
  }
  if (!signed.signature || signed.signature.r === '0x0' || signed.signature.s === '0x0') {
    throw new Error('Missing ECDSA signature');
  }
  // MetaMask Keyring eth_signTransaction expects v/r/s; MetaMask handles broadcast.
  return { v:hex(BigInt(signed.signature.yParity)), r:signed.signature.r, s:signed.signature.s };
}
