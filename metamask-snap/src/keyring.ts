/** Keyring state contains PUBLIC addresses and unsigned transaction intents ONLY. */
import type { Keyring, KeyringAccount, KeyringRequest, ResolvedAccountAddress, SubmitRequestResponse } from '@metamask/keyring-api';
import { EthAccountType, EthMethod, EthScope, KeyringEvent } from '@metamask/keyring-api';
import type { Json, JsonRpcRequest, CaipChainId } from '@metamask/utils';
import { sha256, toUtf8Bytes } from 'ethers';
import { checkedAddress, makeQrRequest, normalizeUnsigned, verifyQrResponse } from './protocol.ts';
import type { Pending } from './protocol.ts';

export type StoredRequest = { request: KeyringRequest; pending: Pending };
export type State = {
  accounts: Record<string, KeyringAccount>;
  requests: Record<string, StoredRequest>;
  closedIds: string[];
  selected: string[];
};
export const freshState = (): State => ({ accounts:{}, requests:{}, closedIds:[], selected:[] });
type Save = (state: State) => Promise<void>;
type Emit = (event: KeyringEvent, data: Record<string, unknown>) => Promise<void>;

function stableAccountId(address: string): string {
  const h = sha256(toUtf8Bytes('cold-snap-account:' + address.toLowerCase())).slice(2);
  return [h.slice(0,8), h.slice(8,12), '5' + h.slice(13,16), '8' + h.slice(17,20), h.slice(20,32)].join('-');
}
export class ColdKeyring implements Keyring {
  constructor(private readonly state: State, private readonly save: Save, private readonly emit: Emit, private readonly now: () => number = Date.now) {}

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
    await this.emit(KeyringEvent.AccountCreated, {account, accountNameSuggestion:'USB Cold Sepolia'});
    this.state.accounts[account.id] = account;
    await this.save(this.state);
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
    await this.emit(KeyringEvent.AccountDeleted, {id});
    delete this.state.accounts[id];
    await this.save(this.state);
  }
  async exportAccount(_id: string): Promise<Record<string, Json>> {
    throw new Error('No private keys exist in this Snap; export is unavailable');
  }
  async filterAccountChains(id: string, chains: string[]): Promise<string[]> {
    await this.getAccount(id);
    return chains.filter((chain) => chain === 'eip155:11155111');
  }
  async setSelectedAccounts(accounts: string[]): Promise<void> {
    if (!Array.isArray(accounts) || accounts.some((id) => !this.state.accounts[id])) {
      throw new Error('Unknown selected cold account');
    }
    if (Object.values(this.state.requests).some((r) => !accounts.includes(r.pending.accountId))) {
      throw new Error('Reject pending signature before switching cold accounts');
    }
    this.state.selected = [...accounts];
    await this.save(this.state);
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
    const account = await this.getAccount(request.account);
    if (this.state.requests[request.id] || this.state.closedIds.includes(request.id)) throw new Error('Duplicate/replayed request ID');
    if (Object.keys(this.state.requests).length !== 0) throw new Error('Complete or reject existing request before another');
    if (request.scope && request.scope !== 'eip155:11155111') throw new Error('Wrong EVM chain scope');
    if (request.request.method !== EthMethod.SignTransaction ||
        !Array.isArray(request.request.params) || request.request.params.length !== 1) {
      throw new Error('Only eth_signTransaction (Sepolia native transfer) is supported');
    }
    const tx = normalizeUnsigned(request.request.params[0], account.address);
    const pending = makeQrRequest(request.id, account.id, account.address, tx, this.now());
    this.state.requests[request.id] = {request, pending};
    await this.save(this.state);
    return {pending:true, redirect:{
      url:'http://localhost:8000/',
      message:'Review the Sepolia transaction on the offline USB signer. Never enter keys in the browser.',
    }};
  }
  async approveRequest(id: string, data?: Record<string, Json>): Promise<void> {
    const entry = this.state.requests[id];
    if (!entry) throw new Error('Unknown or replayed cold request');
    if (!data || Object.keys(data).length !== 1 || typeof data.responseJson !== 'string') {
      throw new Error('Exact QR response JSON required');
    }
    const signature = verifyQrResponse(data.responseJson, entry.pending, this.now());
    // Fail closed on event or persistence failure: once emitted, this ID cannot be replayed.
    entry.pending.status = 'approving';
    this.rememberClosed(id);
    await this.save(this.state);
    await this.emit(KeyringEvent.RequestApproved, {id, result:signature});
    delete this.state.requests[id];
    await this.save(this.state);
  }
  async rejectRequest(id: string): Promise<void> {
    const entry = this.state.requests[id];
    if (!entry || entry.pending.status !== 'pending') throw new Error('Unknown or closed cold request');
    entry.pending.status = 'rejected';
    this.rememberClosed(id);
    await this.save(this.state);
    await this.emit(KeyringEvent.RequestRejected, {id});
    delete this.state.requests[id];
    await this.save(this.state);
  }
  private rememberClosed(id: string): void {
    if (!this.state.closedIds.includes(id)) this.state.closedIds.push(id);
    this.state.closedIds = this.state.closedIds.slice(-100);
  }
}
