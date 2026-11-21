/** Keyring state contains PUBLIC addresses and unsigned transaction intents ONLY. */
import type { Keyring, KeyringAccount, KeyringRequest, ResolvedAccountAddress, SubmitRequestResponse } from '@metamask/keyring-api';
import { EthAccountType, EthMethod, EthScope, KeyringEvent } from '@metamask/keyring-api';
import type { Json, JsonRpcRequest, CaipChainId } from '@metamask/utils';
import { sha256, toUtf8Bytes } from 'ethers';
import { checkedAddress, makeQrRequest, normalizeUnsigned, verifyQrResponse } from './protocol.ts';
import type { Pending } from './protocol.ts';

type ApprovedSignature = {v: string; r: string; s: string};
export type TerminalEvent =
  | {kind: 'approved'; result: ApprovedSignature; responseDigest: string; attempted: boolean}
  | {kind: 'rejected'; attempted: boolean};
export type StoredRequest = { request: KeyringRequest; pending: Pending; terminal?: TerminalEvent };
type AccountEvent = {kind: 'created'; account: KeyringAccount; attempted: boolean} | {kind: 'deleted'; id: string; attempted: boolean};
export type State = {
  accounts: Record<string, KeyringAccount>;
  requests: Record<string, StoredRequest>;
  closedIds: string[];
  selected: string[];
  // Durable outbox: MetaMask account notifications are not exactly-once.
  accountEvent?: AccountEvent;
  // Persistent monotonic domain separation for QR request IDs, even when
  // bounded closedIds history discards old MetaMask request identifiers.
  requestSequence: number;
};
export const freshState = (): State => ({ accounts:{}, requests:{}, closedIds:[], selected:[], requestSequence:0 });
type Save = (state: State) => Promise<void>;
type Emit = (event: KeyringEvent, data: Record<string, unknown>) => Promise<void>;

function stableAccountId(address: string): string {
  const h = sha256(toUtf8Bytes('cold-snap-account:' + address.toLowerCase())).slice(2);
  return [h.slice(0,8), h.slice(8,12), '5' + h.slice(13,16), '8' + h.slice(17,20), h.slice(20,32)].join('-');
}
export class ColdKeyring implements Keyring {
  constructor(private readonly state: State, private readonly save: Save, private readonly emit: Emit, private readonly now: () => number = Date.now) {}

  private async persist(next: State): Promise<void> {
    // Never mutate the working state until the durable save has succeeded.
    await this.save(next);
    Object.assign(this.state, next);
  }

  private closedWith(id: string): string[] {
    return [...this.state.closedIds.filter((item) => item !== id), id].slice(-100);
  }

  async listAccounts(): Promise<KeyringAccount[]> { return Object.values(this.state.accounts); }
  async getAccount(id: string): Promise<KeyringAccount> {
    const account = this.state.accounts[id];
    if (!account) throw new Error('Unknown cold account');
    return account;
  }
  async createAccount(options: Record<string, Json> = {}): Promise<KeyringAccount> {
    if (Object.keys(options).length !== 1 || typeof options.address !== 'string') {
      throw new Error('Only a public EVM address is allowed: no key, seed, or mnemonic imports');
    }
    const address = checkedAddress(options.address);
    if (Object.values(this.state.accounts).some((a) => a.address.toLowerCase() === address.toLowerCase())) {
      throw new Error('Cold address already imported');
    }
    const account: KeyringAccount = {
      id:stableAccountId(address), address, type:EthAccountType.Eoa,
      methods:[EthMethod.SignTransaction], scopes:[EthScope.Eoa],
      options:{coldSigner:true, network:'eip155:11155111'},
    };
    if (this.state.accountEvent) throw new Error('Recover the previous account notification first');
    await this.persist({...this.state,
      accounts:{...this.state.accounts, [account.id]:account},
      accountEvent:{kind:'created',account,attempted:false},
    });
    await this.deliverAccountEvent();
    return account;
  }
  async updateAccount(_account: KeyringAccount): Promise<void> {
    throw new Error('Cold accounts are immutable; delete and import public address explicitly');
  }
  async deleteAccount(id: string): Promise<void> {
    await this.getAccount(id);
    if (Object.values(this.state.requests).some((r) => r.pending.accountId === id)) {
      throw new Error('Reject all pending requests before deleting an account');
    }
    if (this.state.accountEvent) throw new Error('Recover the previous account notification first');
    const accounts = {...this.state.accounts};
    delete accounts[id];
    await this.persist({...this.state,
      accounts, selected:this.state.selected.filter((item) => item !== id),
      accountEvent:{kind:'deleted',id,attempted:false},
    });
    await this.deliverAccountEvent();
  }
  private async deliverAccountEvent(): Promise<void> {
    let event = this.state.accountEvent;
    if (!event) throw new Error('No account notification to recover');
    if (!event.attempted) {
      await this.persist({...this.state, accountEvent:{...event,attempted:true}});
      event = this.state.accountEvent;
    }
    if (!event) throw new Error('Account notification vanished');
    if (event.kind === 'created') {
      await this.emit(KeyringEvent.AccountCreated,
        {account:event.account,accountNameSuggestion:'USB Cold Sepolia'});
    } else {
      await this.emit(KeyringEvent.AccountDeleted,{id:event.id});
    }
    await this.persist({...this.state,accountEvent:undefined});
  }

  listAccountEvents(): Array<{kind: 'created' | 'deleted'; id: string; attempted: boolean}> {
    const event = this.state.accountEvent;
    return event ? [{kind:event.kind,id:event.kind === 'created' ? event.account.id : event.id,
      attempted:event.attempted}] : [];
  }

  async recoverAccountEvent(action: 'retry' | 'abandon'): Promise<void> {
    if (!this.state.accountEvent) throw new Error('No pending account notification');
    if (action === 'retry') return this.deliverAccountEvent();
    if (action !== 'abandon') throw new Error('Unsupported account recovery action');
    // The caller must have checked that MetaMask's account view is reconciled.
    await this.persist({...this.state,accountEvent:undefined});
  }

  async exportAccount(_id: string): Promise<Record<string, Json>> {
    throw new Error('No private keys exist in this Snap; export is unavailable');
  }
  async filterAccountChains(id: string, chains: string[]): Promise<string[]> {
    await this.getAccount(id);
    return chains.filter((chain) => chain === 'eip155:11155111');
  }
  async setSelectedAccounts(accounts: string[]): Promise<void> {
    if (this.state.accountEvent) throw new Error('Recover account notification before selecting accounts');
    if (!Array.isArray(accounts) || accounts.some((id) => !this.state.accounts[id])) {
      throw new Error('Unknown selected cold account');
    }
    if (Object.values(this.state.requests).some((r) => !accounts.includes(r.pending.accountId))) {
      throw new Error('Reject pending signature before switching cold accounts');
    }
    await this.persist({...this.state, selected:[...accounts]});
  }
  async resolveAccountAddress(scope: CaipChainId, request: JsonRpcRequest): Promise<ResolvedAccountAddress | null> {
    if (scope !== 'eip155:11155111' || request.method !== EthMethod.SignTransaction) return null;
    const from = (request.params as Array<{from?: string}> | undefined)?.[0]?.from;
    if (!from) return null;
    let address: string;
    try { address = checkedAddress(from); } catch { return null; }
    const match = Object.values(this.state.accounts).find((a) => a.address === address);
    return match ? {address: `${scope}:${address}` as ResolvedAccountAddress['address']} : null;
  }
  async listRequests(): Promise<KeyringRequest[]> {
    return Object.values(this.state.requests).filter((r) => r.pending.status === 'pending').map((r) => r.request);
  }
  async getRequest(id: string): Promise<KeyringRequest> {
    const entry = this.state.requests[id];
    if (!entry || entry.pending.status !== 'pending') throw new Error('Unknown or closed cold request');
    return entry.request;
  }
  exportQrRequest(id: string): string {
    const entry = this.state.requests[id];
    if (!entry || entry.pending.status !== 'pending') throw new Error('Unknown or closed cold request');
    if (this.now() - entry.pending.createdAt > 10 * 60 * 1000) throw new Error('Expired cold request');
    return entry.pending.qrRequest;
  }
  async submitRequest(request: KeyringRequest): Promise<SubmitRequestResponse> {
    if (this.state.accountEvent) throw new Error('Recover account notification before signing');
    const account = await this.getAccount(request.account);
    if (this.state.requests[request.id] || this.state.closedIds.includes(request.id)) throw new Error('Duplicate/replayed request ID');
    if (Object.keys(this.state.requests).length !== 0) throw new Error('Complete or reject existing request before another');
    if (request.scope && request.scope !== 'eip155:11155111') throw new Error('Wrong EVM chain scope');
    if (request.request.method !== EthMethod.SignTransaction ||
        !Array.isArray(request.request.params) || request.request.params.length !== 1) {
      throw new Error('Only eth_signTransaction (Sepolia native transfer) is supported');
    }
    const tx = normalizeUnsigned(request.request.params[0], account.address);
    const sequence = this.state.requestSequence;
    if (!Number.isSafeInteger(sequence) || sequence < 0 ||
        sequence === Number.MAX_SAFE_INTEGER) {
      throw new Error('Invalid or exhausted cold request sequence');
    }
    const pending = makeQrRequest(request.id, account.id, account.address, tx, this.now(), sequence + 1);
    await this.persist({
      ...this.state, requestSequence: sequence + 1,
      requests:{...this.state.requests, [request.id]:{request, pending}},
    });
    return {pending:true, redirect:{
      url:'http://localhost:8000/',
      message:'Review the Sepolia transaction on the offline USB signer. Never enter keys in the browser.',
    }};
  }
  private async deliverTerminal(id: string): Promise<void> {
    let entry = this.state.requests[id];
    if (!entry?.terminal) throw new Error('No persisted terminal event to recover');

    // Persist an ambiguous-delivery marker BEFORE calling MetaMask.
    // If emit succeeds but cleanup persistence fails, the next Snap instance
    // cannot safely assume either success or failure. Never auto-retry.
    if (!entry.terminal.attempted) {
      await this.persist({
        ...this.state,
        requests:{...this.state.requests, [id]:{
          ...entry, terminal:{...entry.terminal, attempted:true},
        }},
      });
      entry = this.state.requests[id];
    }
    const terminal = entry.terminal;
    if (!terminal) throw new Error('Terminal event vanished');
    if (terminal.kind === 'approved') {
      await this.emit(KeyringEvent.RequestApproved, {id, result:terminal.result});
    } else {
      await this.emit(KeyringEvent.RequestRejected, {id});
    }
    // A failure here leaves the immutable terminal payload persisted. The
    // user may explicitly retry or abandon after reconciling MetaMask state.
    const requests = {...this.state.requests};
    delete requests[id];
    await this.persist({...this.state, requests});
  }

  listTerminalEvents(): Array<{id: string; kind: 'approved' | 'rejected'; attempted: boolean}> {
    return Object.entries(this.state.requests).flatMap(([id, entry]) =>
      entry.terminal ? [{id, kind:entry.terminal.kind, attempted:entry.terminal.attempted}] : []);
  }

  async recoverTerminal(id: string, action: 'retry' | 'abandon'): Promise<void> {
    const entry = this.state.requests[id];
    if (!entry?.terminal) throw new Error('Unknown terminal event');
    if (action === 'retry') {
      // Explicit action only. Never validate a different QR signature here:
      // the original event result was persisted after independent verification.
      await this.deliverTerminal(id);
      return;
    }
    if (action !== 'abandon') throw new Error('Unsupported terminal recovery action');
    // Only after the user has confirmed the MetaMask request is already
    // resolved or cancelled. This drops the notification, never signs again.
    const requests = {...this.state.requests};
    delete requests[id];
    await this.persist({...this.state, requests});
  }

  async approveRequest(id: string, data?: Record<string, Json>): Promise<void> {
    const entry = this.state.requests[id];
    if (!entry) throw new Error('Unknown or replayed cold request');
    if (entry.pending.status === 'approving') {
      if (entry.terminal?.kind !== 'approved') throw new Error('Invalid terminal approval');
      if (data && (
          Object.keys(data).length !== 1 || typeof data.responseJson !== 'string' ||
          sha256(toUtf8Bytes(data.responseJson)) !== entry.terminal.responseDigest)) {
        throw new Error('Different signed QR response cannot replace persisted approval');
      }
      await this.deliverTerminal(id);
      return;
    }
    if (entry.pending.status !== 'pending') throw new Error('Unknown or closed cold request');
    if (!data || Object.keys(data).length !== 1 || typeof data.responseJson !== 'string') {
      throw new Error('Exact QR response JSON required');
    }
    const signature = verifyQrResponse(data.responseJson, entry.pending, this.now());
    const updated: StoredRequest = {
      ...entry, pending:{...entry.pending, status:'approving'},
      terminal:{
        kind:'approved', result:signature,
        responseDigest:sha256(toUtf8Bytes(data.responseJson)), attempted:false,
      },
    };
    await this.persist({
      ...this.state, requests:{...this.state.requests, [id]:updated},
      closedIds:this.closedWith(id),
    });
    await this.deliverTerminal(id);
  }

  async rejectRequest(id: string): Promise<void> {
    const entry = this.state.requests[id];
    if (!entry) throw new Error('Unknown or closed cold request');
    if (entry.pending.status === 'rejected') {
      if (entry.terminal?.kind !== 'rejected') throw new Error('Invalid terminal rejection');
      await this.deliverTerminal(id);
      return;
    }
    if (entry.pending.status !== 'pending') throw new Error('Cannot reject a persisted approval');
    await this.persist({
      ...this.state,
      requests:{...this.state.requests, [id]:{
        ...entry, pending:{...entry.pending, status:'rejected'},
        terminal:{kind:'rejected', attempted:false},
      }},
      closedIds:this.closedWith(id),
    });
    await this.deliverTerminal(id);
  }

}
