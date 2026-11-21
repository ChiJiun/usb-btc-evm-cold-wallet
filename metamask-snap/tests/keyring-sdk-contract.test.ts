import test from 'node:test';
import assert from 'node:assert/strict';
import { Wallet } from 'ethers';
import { KeyringSnapRpcClient } from '@metamask/keyring-snap-client';
import { ColdKeyring, freshState } from '../src/keyring.js';

const accountAddress = new Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80').address;
const requestId = '12345678-1234-4123-8123-123456789013';

test('real MetaMask Keyring client schema accepts generated account and pending request', async () => {
  const keyring = new ColdKeyring(freshState(), async()=>{}, async()=>{}, ()=>1000);
  const account = await keyring.createAccount({address:accountAddress});
  assert.match(account.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  const tx = {
    type:'0x2',chainId:'0xaa36a7',nonce:'0x1',from:account.address,
    to:'0x000000000000000000000000000000000000dEaD',
    value:'0x'+(123456789012345678n).toString(16),gasLimit:'0x5208',
    maxFeePerGas:'0x12a05f200',maxPriorityFeePerGas:'0x3b9aca00',
    data:'0x',accessList:[],
  };
  await keyring.submitRequest({
    id:requestId,origin:'https://example.test',scope:'eip155:11155111',
    account:account.id,request:{method:'eth_signTransaction',params:[tx]},
  } as never);
  const client = new KeyringSnapRpcClient('local:http://localhost:8082', {
    request:async ({params}: {params:{request:{method:string}}}) => {
      if (params.request.method === 'keyring_listAccounts') return keyring.listAccounts();
      if (params.request.method === 'keyring_listRequests') return keyring.listRequests();
      throw Error('Unexpected Keyring RPC');
    },
  } as never);
  assert.deepEqual((await client.listAccounts()).map((x)=>x.id),[account.id]);
  const [pending] = await client.listRequests();
  assert.equal(pending.id,requestId);
  assert.equal((pending.request.params as Array<{value:string}>)[0].value,tx.value);
});
