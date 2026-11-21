import test from 'node:test';
import assert from 'node:assert/strict';
import { Wallet, Transaction, sha256, toUtf8Bytes } from 'ethers';
import { canonical, checkedAddress, makeQrRequest, normalizeUnsigned, verifyQrResponse, MAX_AGE_MS } from '../src/protocol.js';
import { ColdKeyring, freshState } from '../src/keyring.js';
import type { State } from '../src/keyring.js';
import type { KeyringRequest } from '@metamask/keyring-api';

// Publicly compromised Hardhat test key. It must NEVER receive real funds.
const wallet = new Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const recipient = '0x000000000000000000000000000000000000dEaD';
const WEI = 123456789012345678n;
const intent = {
  type:'0x2', chainId:'0xaa36a7', nonce:'0x1', from:wallet.address, to:recipient,
  value:'0x' + WEI.toString(16), gasLimit:'0x5208',
  maxFeePerGas:'0x12a05f200', maxPriorityFeePerGas:'0x3b9aca00', data:'0x', accessList:[],
};
function setup(now=1000) {
  const events: Array<{event:string;data:Record<string, unknown>}> = [];
  let saved = 0;
  const state = freshState();
  const keyring = new ColdKeyring(state, async () => {saved++;},
    async (event,data) => {events.push({event,data});}, () => now);
  return { keyring, events, state, get saves(){return saved;} };
}
function request(account: string, id='mm-1', tx: object=intent): KeyringRequest {
  return {id, scope:'eip155:11155111', account, request:{method:'eth_signTransaction', params:[tx]}} as KeyringRequest;
}
async function responseFor(pending: ReturnType<typeof makeQrRequest>, overrides: Record<string,unknown> = {}) {
  const signed = await wallet.signTransaction({
    type:2, chainId:11155111, nonce:1, to:recipient, value:WEI, gasLimit:21000,
    maxFeePerGas:5_000_000_000n, maxPriorityFeePerGas:1_000_000_000n, data:'0x', accessList:[],
  });
  const payload = {chain_id:11155111, from:wallet.address,to:recipient, value_wei:WEI,
    signed_raw_transaction:signed, transaction_hash:Transaction.from(signed).hash};
  const fullPayload = {...payload, ...overrides.payload as Record<string, unknown>};
  const ret = {version:1, direction:'signed', network:'sepolia', account:wallet.address,
    request_id:pending.qrRequestId, request_digest:pending.qrDigest,
    payload_digest:sha256(toUtf8Bytes(canonical(fullPayload))).slice(2), payload:fullPayload,
    ...Object.fromEntries(Object.entries(overrides).filter(([k])=>k!=='payload'))};
  return canonical(ret);
}
test('public-only account import; immutable, export forbidden; account switching bound', async () => {
  const {keyring,state} = setup();
  await assert.rejects(() => keyring.createAccount({privateKey:'0x123'}), /public EVM address/);
  await assert.rejects(() => keyring.createAccount({address:wallet.address, extra:'secret'}), /public EVM address/);
  const account = await keyring.createAccount({address:wallet.address});
  assert.equal(account.address,wallet.address);
  assert.deepEqual(account.methods,['eth_signTransaction']);
  assert.deepEqual(await keyring.filterAccountChains(account.id,['eip155:1','eip155:11155111','eip155:10']),['eip155:11155111']);
  await assert.rejects(() => keyring.createAccount({address:wallet.address}), /already/);
  await assert.rejects(() => keyring.exportAccount(account.id),/No private keys/);
  await assert.rejects(() => keyring.updateAccount(account),/immutable/);
  await assert.rejects(() => keyring.setSelectedAccounts(['fake']),/Unknown/);
  await keyring.setSelectedAccounts([account.id]);
  assert.deepEqual(state.selected,[account.id]);
});
test('strict unsigned policy rejects chain, account, contract, arbitrary methods, fee, gas and fields', async () => {
  const {keyring} = setup();
  const account = await keyring.createAccount({address:wallet.address});
  for (const [key,value] of Object.entries({
    chainId:'0x1', type:'0x0', from:recipient, to:null, gasLimit:'0x6000',
    maxFeePerGas:'0x3635c9adc5dea00000', data:'0xdeadbeef', accessList:[{address:recipient}],
    gasPrice:'0x100', nonce:'0x20000000000000', value:'0x0',
  })) {
    await assert.rejects(() => keyring.submitRequest(request(account.id, 'invalid-'+key,{...intent,[key]:value})),/./,key);
  }
  for(const method of ['eth_sign','personal_sign','eth_signTypedData_v4','eth_sendTransaction','eth_signTransactionUnknown']) {
    await assert.rejects(() => keyring.submitRequest({ ...request(account.id), request:{method,params:[intent]}} as KeyringRequest),/Only eth_signTransaction/);
  }
  await assert.rejects(() => keyring.submitRequest({...request(account.id),scope:'eip155:1'} as KeyringRequest),/scope/);
});
test('issue #18-compatible canonical unsigned request keeps full-precision wei', async () => {
  const {keyring,state} = setup();
  const account=await keyring.createAccount({address:wallet.address});
  const accepted=await keyring.submitRequest(request(account.id));
  assert.equal(accepted.pending,true);
  const text=keyring.exportQrRequest('mm-1');
  assert.match(text,/123456789012345678/);
  assert.match(text,/"network":"sepolia"/);
  assert.match(text,/"direction":"unsigned"/);
  assert.equal(text, state.requests['mm-1'].pending.qrRequest);
  assert.equal(state.requests['mm-1'].pending.qrRequestId.length,32);
  await assert.rejects(()=>keyring.submitRequest(request(account.id,'mm-2')),/existing/);
  await assert.rejects(()=>keyring.submitRequest(request(account.id,'mm-1')),/Duplicate/);
  await assert.rejects(()=>keyring.setSelectedAccounts([]), /pending signature/);
  await assert.rejects(()=>keyring.deleteAccount(account.id),/pending requests/);
});
test('signed QR response independently recovers signer and returns exact MetaMask signature components', async () => {
  const {keyring, events,state} = setup();
  const account=await keyring.createAccount({address:wallet.address});
  await keyring.submitRequest(request(account.id));
  const pending=state.requests['mm-1'].pending;
  const response=await responseFor(pending);
  const sig=verifyQrResponse(response,pending,1000);
  assert.match(sig.r,/^0x[0-9a-f]{64}$/);
  assert.match(sig.s,/^0x[0-9a-f]{64}$/);
  assert.ok(['0x0','0x1'].includes(sig.v));
  await keyring.approveRequest('mm-1',{responseJson:response});
  assert.equal(events.at(-1)?.event,'notify:requestApproved');
  assert.deepEqual((events.at(-1)?.data as any).result,sig);
  assert.equal(state.requests['mm-1'],undefined);
  await assert.rejects(() => keyring.approveRequest('mm-1',{responseJson:response}),/replayed/);
  await assert.rejects(() => keyring.submitRequest(request(account.id)),/replayed/);
});
test('wrong QR IDs, account, digest, mismatched signed transaction, or signature fail closed', async () => {
  const tx=normalizeUnsigned(intent,wallet.address);
  const pending=makeQrRequest('mm-1','account1',wallet.address,tx,1000);
  const good=await responseFor(pending);
  const bad=[
    await responseFor(pending,{request_id:'f'.repeat(32)}),
    await responseFor(pending,{request_digest:'a'.repeat(64)}),
    await responseFor(pending,{account:recipient}),
    await responseFor(pending,{network:'bitcoin-testnet'}),
    await responseFor(pending,{payload:{to:recipient.toLowerCase().replace(/dead/i,'beef')}}),
    await responseFor(pending,{payload:{chain_id:1}}),
    await responseFor(pending,{payload:{value_wei:WEI+1n}}),
    await responseFor(pending,{payload:{signed_raw_transaction:'0x02ff'}}),
    await responseFor(pending,{payload:{transaction_hash:'0x'+'a'.repeat(64)}}),
  ];
  for(const [i,raw] of bad.entries()) assert.throws(()=>verifyQrResponse(raw,pending,1000),/./,'bad response '+i);
  assert.throws(()=>verifyQrResponse(good,pending,1000+MAX_AGE_MS+1),/timed out/);
  assert.throws(()=>verifyQrResponse(good,{...pending,status:'rejected'},1000),/completed/);
  assert.throws(()=>verifyQrResponse(good.repeat(200),pending,1000),/Oversize/);
  const tampered=good.replace('"direction":"signed"','"direction":"unsigned"');
  assert.throws(()=>verifyQrResponse(tampered,pending,1000),/binding/);
  const duplicate=good.replace('"network":"sepolia"','"network":"sepolia","network":"sepolia"');
  assert.throws(()=>verifyQrResponse(duplicate,pending,1000),/Duplicate JSON property/);
  const escapedDuplicate=good.replace('"network":"sepolia"','"net\\u0077ork":"sepolia","network":"sepolia"');
  assert.throws(()=>verifyQrResponse(escapedDuplicate,pending,1000),/Duplicate JSON property/);
});
test('signature check rejects different nonce/fee/amount/recipient and account', async () => {
  const tx=normalizeUnsigned(intent,wallet.address);
  const pending=makeQrRequest('mm-1','account1',wallet.address,tx,1000);
  const variants=[
    {nonce:2}, {to:'0x000000000000000000000000000000000000bEEF'}, {value:WEI+1n},
    {maxFeePerGas:6_000_000_000n}, {maxPriorityFeePerGas:2_000_000_000n}, {gasLimit:22000},
    {chainId:1},
  ];
  for (const data of variants) {
    const signed=await wallet.signTransaction({type:2,chainId:11155111,nonce:1,to:recipient,value:WEI,
      gasLimit:21000,maxFeePerGas:5_000_000_000n,maxPriorityFeePerGas:1_000_000_000n,...data});
    const payload={chain_id:11155111,from:wallet.address,to:recipient,value_wei:WEI,
      signed_raw_transaction:signed,transaction_hash:Transaction.from(signed).hash};
    const ret={version:1,direction:'signed',network:'sepolia',account:wallet.address,
      request_id:pending.qrRequestId,request_digest:pending.qrDigest,
      payload_digest:sha256(toUtf8Bytes(canonical(payload))).slice(2),payload};
    assert.throws(()=>verifyQrResponse(canonical(ret),pending,1000),/Signed transaction/);
  }
  const other = new Wallet('0x' + '11'.repeat(32)); // Fixed, PUBLIC compromised test key only.
  const signed = await other.signTransaction({type:2,chainId:11155111,nonce:1,to:recipient,value:WEI,
    gasLimit:21000,maxFeePerGas:5_000_000_000n,maxPriorityFeePerGas:1_000_000_000n});
  const wrongSignerResponse = await responseFor(pending,{payload:{signed_raw_transaction:signed,transaction_hash:Transaction.from(signed).hash}});
  assert.throws(()=>verifyQrResponse(wrongSignerResponse,pending,1000),/Signed transaction/);
});
test('reject/cancel removes pending; errors do not approve; stale session refuses', async () => {
  const {keyring,state,events}=setup();
  const account=await keyring.createAccount({address:wallet.address});
  await keyring.submitRequest(request(account.id));
  await assert.rejects(()=>keyring.approveRequest('mm-1',{responseJson:'bad json'}),/./);
  assert.ok(state.requests['mm-1']);
  await keyring.rejectRequest('mm-1');
  assert.equal(events.at(-1)?.event,'notify:requestRejected');
  assert.deepEqual(await keyring.listRequests(),[]);
  await assert.rejects(()=>keyring.approveRequest('mm-1',{responseJson:'bad json'}),/replayed/);
  await keyring.deleteAccount(account.id);
});
test('tampered checksum fails despite signed fields; canonical rejects unsafe numeric JSON', async () => {
  const tx=normalizeUnsigned(intent,wallet.address);
  const p=makeQrRequest('mm-1','account1',wallet.address,tx,1000);
  const good=await responseFor(p);
  const digest=good.replace('"payload_digest":"','"payload_digest":"f');
  assert.throws(()=>verifyQrResponse(digest,p,1000),/checksum/);
  assert.throws(()=>canonical({unsafe:Number.MAX_SAFE_INTEGER+1}),/unsafe/);
  assert.equal(checkedAddress(wallet.address.toLowerCase()),wallet.address);
});
test('Snap source contains no direct private key import/signing branches', async () => {
  const fs=await import('node:fs/promises');
  for (const file of ['src/keyring.ts','src/index.ts','src/protocol.ts']) {
    const source=await fs.readFile(new URL('../'+file, import.meta.url),'utf8');
    for(const forbidden of [/from\s+['"]\.\.?\/.*vault/i,/snap_getEntropy/,/eth_signTypedData_v4.*\(/,/Wallet\.createRandom\s*\(/,/\.signTransaction\s*\(/]) {
      assert.equal(forbidden.test(source),false,`${file} must not expose online signing/entropy`);
    }
  }
});

test('old signed QR cannot replay after bounded closed request ID cache evicts entry', async () => {
  const {keyring, state} = setup();
  const account = await keyring.createAccount({address:wallet.address});
  await keyring.submitRequest(request(account.id, 'reused-id'));
  const initial = state.requests['reused-id'].pending;
  const oldResponse = await responseFor(initial);
  await keyring.rejectRequest('reused-id');
  for (let i = 0; i < 100; i++) {
    const id = 'closed-' + i;
    await keyring.submitRequest(request(account.id, id));
    await keyring.rejectRequest(id);
  }
  assert.equal(state.closedIds.includes('reused-id'), false, 'bounded history evicts first ID');
  await keyring.submitRequest(request(account.id, 'reused-id'));
  const current = state.requests['reused-id'].pending;
  assert.notEqual(initial.qrRequestId, current.qrRequestId);
  assert.notEqual(initial.qrDigest, current.qrDigest);
  assert.equal(state.requestSequence, 102);
  assert.throws(() => verifyQrResponse(oldResponse, current, 1000), /binding mismatch/);
});

test('persistent request sequence rejects invalid or exhausted state before allocating request', async () => {
  const {keyring, state} = setup();
  const account = await keyring.createAccount({address:wallet.address});
  state.requestSequence = Number.MAX_SAFE_INTEGER;
  await assert.rejects(() => keyring.submitRequest(request(account.id)), /exhausted/);
  assert.deepEqual(state.requests, {});
});


function persistentSnapHarness() {
  let disk: State = freshState();
  let failNextEmit = false;
  let failNextCleanupSave = false;
  let failNextTerminalSave = false;
  const events: Array<{event:string;data:Record<string, unknown>}> = [];
  const open = () => new ColdKeyring(
    structuredClone(disk),
    async (next) => {
      const record = next.requests['mm-1'];
      if (failNextTerminalSave && record?.terminal && !disk.requests['mm-1']?.terminal) {
        failNextTerminalSave = false;
        throw Error('simulated terminal persistence failure');
      }
      if (failNextCleanupSave && !record && disk.requests['mm-1']?.terminal?.attempted) {
        failNextCleanupSave = false;
        throw Error('simulated post-emit persistence failure');
      }
      disk = structuredClone(next);
    },
    async (event, data) => {
      if (failNextEmit) {
        failNextEmit = false;
        throw Error('simulated MetaMask event transport failure');
      }
      events.push({event, data});
    },
    () => 1000,
  );
  return {
    open, events, snapshot:() => disk,
    failEmit:() => {failNextEmit = true;},
    failCleanup:() => {failNextCleanupSave = true;},
    failTerminalSave:() => {failNextTerminalSave = true;},
  };
}

test('approved terminal event is persisted and explicitly recoverable after emit failure/restart', async () => {
  const h = persistentSnapHarness();
  let keyring = h.open();
  const account = await keyring.createAccount({address:wallet.address});
  await keyring.submitRequest(request(account.id));
  const response = await responseFor(h.snapshot().requests['mm-1'].pending);
  h.failEmit();
  await assert.rejects(() => keyring.approveRequest('mm-1', {responseJson:response}), /event transport failure/);
  assert.equal(h.snapshot().requests['mm-1'].pending.status, 'approving');
  assert.equal(h.snapshot().requests['mm-1'].terminal?.kind, 'approved');
  assert.deepEqual(keyring.listTerminalEvents(), [{id:'mm-1',kind:'approved',attempted:true}]);
  assert.deepEqual(await keyring.listRequests(), []);
  await assert.rejects(() => keyring.submitRequest(request(account.id,'mm-2')), /existing/);
  await assert.rejects(
    () => keyring.approveRequest('mm-1', {responseJson:response + ' '}),
    /Different signed QR response/,
  );
  await assert.rejects(() => keyring.rejectRequest('mm-1'), /Cannot reject a persisted approval/);
  keyring = h.open();  // Simulated Snap process restart reloads the durable state.
  await keyring.recoverTerminal('mm-1', 'retry');
  assert.equal(h.snapshot().requests['mm-1'], undefined);
  assert.equal(h.events.at(-1)?.event, 'notify:requestApproved');
  assert.equal(h.events.filter((e) => e.event === 'notify:requestApproved').length, 1);
  await assert.rejects(() => keyring.submitRequest(request(account.id)), /replayed/);
  assert.equal((await keyring.submitRequest(request(account.id,'mm-2'))).pending,true);
});

test('rejected terminal event survives transport failure and resumes without a signature', async () => {
  const h = persistentSnapHarness();
  let keyring = h.open();
  const account = await keyring.createAccount({address:wallet.address});
  await keyring.submitRequest(request(account.id));
  h.failEmit();
  await assert.rejects(() => keyring.rejectRequest('mm-1'), /event transport failure/);
  assert.equal(h.snapshot().requests['mm-1'].pending.status, 'rejected');
  assert.deepEqual(keyring.listTerminalEvents(), [{id:'mm-1',kind:'rejected',attempted:true}]);
  await assert.rejects(() => keyring.approveRequest('mm-1'), /closed/);
  keyring = h.open();
  await keyring.rejectRequest('mm-1');
  assert.equal(h.events.at(-1)?.event, 'notify:requestRejected');
  assert.equal(h.snapshot().requests['mm-1'], undefined);
  assert.equal((await keyring.submitRequest(request(account.id,'mm-2'))).pending,true);
});

test('save-before-emit failure never creates a ghost terminal or notifies MetaMask', async () => {
  const h = persistentSnapHarness();
  const keyring = h.open();
  const account = await keyring.createAccount({address:wallet.address});
  await keyring.submitRequest(request(account.id));
  const response = await responseFor(h.snapshot().requests['mm-1'].pending);
  const priorEventCount = h.events.length;
  h.failTerminalSave();
  await assert.rejects(() => keyring.approveRequest('mm-1',{responseJson:response}), /terminal persistence failure/);
  assert.equal(h.snapshot().requests['mm-1'].pending.status, 'pending');
  assert.equal(keyring.listTerminalEvents().length, 0);
  assert.equal(h.events.length, priorEventCount);
  await keyring.approveRequest('mm-1',{responseJson:response});
  assert.equal(h.snapshot().requests['mm-1'], undefined);
});

test('emit succeeded but final save failed: restart requires explicit retry or abandon', async () => {
  const h = persistentSnapHarness();
  let keyring = h.open();
  const account = await keyring.createAccount({address:wallet.address});
  await keyring.submitRequest(request(account.id));
  const response = await responseFor(h.snapshot().requests['mm-1'].pending);
  h.failCleanup();
  await assert.rejects(() => keyring.approveRequest('mm-1',{responseJson:response}), /post-emit persistence failure/);
  assert.equal(h.events.filter((e) => e.event === 'notify:requestApproved').length,1);
  assert.deepEqual(h.snapshot().requests['mm-1'].terminal?.attempted,true);
  keyring = h.open();
  assert.deepEqual(keyring.listTerminalEvents(), [{id:'mm-1',kind:'approved',attempted:true}]);
  // User first verifies MetaMask already completed or cancels the pending
  // request there, then explicitly abandons the uncertain delivery.
  await keyring.recoverTerminal('mm-1','abandon');
  assert.equal(h.events.filter((e) => e.event === 'notify:requestApproved').length,1);
  assert.equal(h.snapshot().requests['mm-1'],undefined);
  await assert.rejects(() => keyring.submitRequest(request(account.id)),/replayed/);
  await assert.rejects(() => keyring.recoverTerminal('mm-1','retry'),/Unknown terminal/);
});
