/** Exercise the actual SDK entrypoints with a restartable fake Snap host.
 * The fake only substitutes MetaMask's host, not the keyring RPC dispatcher.
 * This is not a real extension acceptance test.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { Wallet } from 'ethers';
import { onKeyringRequest, onRpcRequest } from '../src/index.js';

const address = new Wallet('0x' + '11'.repeat(32)).address;
const second = new Wallet('0x' + '22'.repeat(32)).address;
const origin = 'http://localhost:8000';

test('SDK keyring RPC: durable account notifications, selection and concurrent creation', async () => {
  let stored: unknown = null;
  const notifications: Array<{method:string;params:unknown}> = [];
  let failNotify = false;
  // onKeyringRequest invokes the real SDK dispatcher and actual Snap handlers.
  // Every RPC reloads the persisted JSON as a fresh Snap invocation would.
  const host = {
    request: async ({method,params}: {method:string;params?:any}) => {
      if (method === 'snap_manageState') {
        if (params?.operation === 'get') return stored === null ? null : structuredClone(stored);
        if (params?.operation === 'update') {
          stored = structuredClone(params.newState);
          return null;
        }
      }
      if (method === 'snap_manageAccounts') {
        if (failNotify) { failNotify = false; throw Error('host event unavailable'); }
        notifications.push({method,params});
        return null;
      }
      throw Error('Unexpected Snap host method: '+method);
    },
  };
  (globalThis as unknown as {snap:typeof host}).snap = host;
  const keyring = (who:string, method:string, params:any={}) =>
    onKeyringRequest({origin:who,request:{method,params}} as never);
  const rpc = (method:string,params?:unknown) =>
    onRpcRequest({origin,request:{method,params}} as never);

  await assert.rejects(() => keyring('https://evil.invalid','keyring_createAccount',{options:{address}}),
    /not permitted/);
  failNotify = true;
  await assert.rejects(() => keyring(origin,'keyring_createAccount',{options:{address}}),
    /host event unavailable/);
  const accountEvents = await rpc('usb_listAccountEvents') as Array<{kind:string;attempted:boolean}>;
  assert.deepEqual(accountEvents.map(e=>[e.kind,e.attempted]),[['created',true]]);
  await assert.rejects(() => keyring(origin,'keyring_createAccount',{options:{address:second}}),
    /previous account notification/);
  await rpc('usb_recoverAccountEvent',{action:'retry'});
  assert.deepEqual(await rpc('usb_listAccountEvents'),[]);
  const accounts = await keyring(origin,'keyring_listAccounts') as Array<{id:string;address:string}>;
  assert.deepEqual(accounts.map(a=>a.address),[address]);

  // Host callbacks use the same serialized state update path.
  await keyring('metamask','keyring_setSelectedAccounts',{accounts:[accounts[0].id]});
  const current = await keyring(origin,'keyring_getAccount',{id:accounts[0].id}) as {id:string};
  assert.equal(current.id,accounts[0].id);
  assert.equal(notifications.length,1);

  // A second RPC may not publish while a persisted account event is uncertain.
  // No additional events are silently emitted during restart/read operations.
  assert.deepEqual(await rpc('usb_listTerminalEvents'),[]);
  assert.equal(notifications.length,1);
});
