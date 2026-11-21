/** MetaMask Account Management Snap POC. Never request key entropy or seed permissions. */
import type { OnKeyringRequestHandler, OnRpcRequestHandler } from '@metamask/snaps-sdk';
import { handleKeyringRequest, emitSnapKeyringEvent } from '@metamask/keyring-snap-sdk';
import { ColdKeyring, freshState } from './keyring.ts';
import type { State } from './keyring.ts';

const COMPANION = new Set(['http://localhost:8000', 'http://127.0.0.1:8000']);
const METAMASK_ALLOWED = new Set([
  'keyring_listAccounts','keyring_getAccount','keyring_filterAccountChains',
  'keyring_deleteAccount','keyring_listRequests','keyring_getRequest',
  'keyring_submitRequest','keyring_rejectRequest','keyring_setSelectedAccounts',
  'keyring_resolveAccountAddress',
]);
const COMPANION_ALLOWED = new Set([
  'keyring_listAccounts','keyring_getAccount','keyring_createAccount',
  'keyring_filterAccountChains','keyring_deleteAccount','keyring_listRequests',
  'keyring_getRequest','keyring_approveRequest','keyring_rejectRequest',
]);
async function createKeyring(): Promise<ColdKeyring> {
  const stored = await snap.request({method:'snap_manageState', params:{operation:'get'}}) as State | null;
  const initial = freshState();
  const state: State = stored ? {...initial, ...stored} : initial;
  return new ColdKeyring(
    state,
    async (next) => { await snap.request({method:'snap_manageState',params:{operation:'update', newState:next}}); },
    async (event, data) => { await emitSnapKeyringEvent(snap, event, data as never); },
  );
}
// Serialize Snap callbacks: concurrent RPC handlers must never load the same
// stale state and overwrite another request/account transition.
let queue: Promise<void> = Promise.resolve();
function serialized<T>(operation: () => Promise<T>): Promise<T> {
  const result = queue.then(operation, operation);
  queue = result.then(() => undefined, () => undefined);
  return result;
}

export const onKeyringRequest: OnKeyringRequestHandler = ({origin, request}) => serialized(async () => {
  const allowed = origin === 'metamask' ? METAMASK_ALLOWED : COMPANION.has(origin) ? COMPANION_ALLOWED : null;
  if (!allowed?.has(request.method)) throw new Error('Origin or keyring method not permitted');
  return (await handleKeyringRequest(await createKeyring(), request)) ?? null;
});
export const onRpcRequest: OnRpcRequestHandler = ({origin, request}) => serialized(async () => {
  if (!COMPANION.has(origin)) throw new Error('Unauthorized Snap RPC origin');
  const keyring = await createKeyring();
  if (request.method === 'usb_listTerminalEvents') return keyring.listTerminalEvents();
  if (!['usb_getQrRequest', 'usb_recoverTerminalEvent'].includes(request.method)) {
    throw new Error('Unauthorized Snap RPC method');
  }
  const params = request.params as {id?: unknown; action?: unknown} | undefined;
  if (typeof params?.id !== 'string') throw new Error('Expected public request ID');
  if (request.method === 'usb_getQrRequest') return keyring.exportQrRequest(params.id);
  if (params.action !== 'retry' && params.action !== 'abandon') {
    throw new Error('Explicit terminal recovery action required');
  }
  await keyring.recoverTerminal(params.id, params.action);
  return {recovered:true};
});
