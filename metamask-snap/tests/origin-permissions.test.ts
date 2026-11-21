import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { onRpcRequest, onKeyringRequest } from '../src/index.js';

test('MetaMask manifest RPC permission is limited to the two loopback Companion origins',async()=>{
  const manifest=JSON.parse(await readFile(new URL('../snap.manifest.json',import.meta.url),'utf8'));
  assert.deepEqual(manifest.initialPermissions['endowment:rpc'],{
    allowedOrigins:['http://localhost:8000','http://127.0.0.1:8000'],
  });
  assert.equal(Object.hasOwn(manifest.initialPermissions['endowment:rpc'],'dapps'),false);
  await assert.rejects(()=>onRpcRequest({
    origin:'https://evil.example',
    request:{method:'usb_listTerminalEvents',params:[]},
  } as never),/Unauthorized Snap RPC origin/);
  await assert.rejects(()=>onKeyringRequest({
    origin:'https://evil.example',
    request:{method:'keyring_listAccounts',params:[]},
  } as never),/Origin or keyring method not permitted/);
});
