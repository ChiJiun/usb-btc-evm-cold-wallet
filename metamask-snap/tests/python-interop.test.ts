import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { ColdKeyring, freshState } from '../src/keyring.js';
import { verifyQrResponse, MAX_AGE_MS } from '../src/protocol.js';

const bridge = resolve('tests/python-gui-signer.py');
const python = process.env.PYTHON_BIN || 'python3';
const pythonEnv = {
  ...process.env,
  PYTHONPATH:resolve('../src'),
  PYTHONNOUSERSITE:'1',
};
function pythonCall(action: string, input=''): string {
  const run=spawnSync(python,[bridge,action],{
    cwd:process.cwd(),env:pythonEnv,encoding:'utf8',input,timeout:30_000,
  });
  if (run.status!==0) throw Error('Python offline bridge failed: '+run.stderr?.slice(0,1800));
  return run.stdout.trim();
}
const recipient='0x000000000000000000000000000000000000dEaD';
const wei=123456789012345678n;
const events: Array<{event:string;data:Record<string,unknown>}> = [];

test('real Python GUI bridge signs Snap QR and exact JS verification accepts it; tamper/expiry/replay rejected', async()=>{
  const address=pythonCall('address');
  const state=freshState();
  let clock=1700000000000;
  const keyring=new ColdKeyring(state,async()=>{},async(event,data)=>{events.push({event,data});},()=>clock);
  const account=await keyring.createAccount({address});
  const tx={
    type:'0x2',chainId:'0xaa36a7',nonce:'0x7',from:address,to:recipient,
    value:'0x'+wei.toString(16),gasLimit:'0x5208',
    maxFeePerGas:'0x77359400',maxPriorityFeePerGas:'0x3b9aca00',
    data:'0x',accessList:[],
  };
  const request={id:'mm-python-1',account:account.id,scope:'eip155:11155111',
    origin:'https://public-test.invalid',request:{method:'eth_signTransaction',params:[tx]}};
  await keyring.submitRequest(request as never);
  const pending=state.requests['mm-python-1'].pending;
  const unsigned=keyring.exportQrRequest('mm-python-1');
  assert.equal(JSON.parse(unsigned).account,address);
  assert.match(unsigned,/123456789012345678/); // preserve full integer precision across languages
  const signed=pythonCall('sign',unsigned);
  const parsed=JSON.parse(signed);
  assert.equal(parsed.request_id,pending.qrRequestId);
  assert.equal(parsed.request_digest,pending.qrDigest);
  const result=verifyQrResponse(signed,pending,clock);
  assert.match(result.r,/^0x[0-9a-f]{64}$/);
  assert.match(result.s,/^0x[0-9a-f]{64}$/);

  const changedPayload=unsigned.replace(recipient,'0x000000000000000000000000000000000000bEEF');
  assert.notEqual(changedPayload,unsigned);
  assert.throws(()=>pythonCall('sign',changedPayload),/offline bridge failed/i);
  const changedRequest=unsigned.replace(pending.qrRequestId,'a'.repeat(32));
  const wrongIdSigned=pythonCall('sign',changedRequest);
  assert.throws(()=>verifyQrResponse(wrongIdSigned,pending,clock),/binding mismatch/);
  // A response with a changed QR request digest must fail even if recomputed in transit.
  assert.throws(()=>verifyQrResponse(signed.replace(pending.qrDigest,'b'.repeat(64)),pending,clock),/binding mismatch/);
  assert.throws(()=>verifyQrResponse(signed,pending,clock+MAX_AGE_MS+1),/timed out/);
  await keyring.approveRequest('mm-python-1',{responseJson:signed});
  assert.equal(events.at(-1)?.event,'notify:requestApproved');
  assert.deepEqual(events.at(-1)?.data.result,result);
  assert.throws(()=>verifyQrResponse(signed,{...pending,status:'approving'},clock),/completed/);
  await assert.rejects(()=>keyring.submitRequest(request as never),/replayed/);
});
