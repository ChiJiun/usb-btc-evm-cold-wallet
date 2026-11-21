import test from 'node:test';
import assert from 'node:assert/strict';
import { ColdKeyring, freshState } from '../src/keyring.js';
import type { State } from '../src/keyring.js';

const address = '0x000000000000000000000000000000000000dEaD';
function harness() {
  let disk: State = freshState();
  let failSave = false;
  let failEmit = false;
  let failCleanup = false;
  const events: string[] = [];
  const open = () => new ColdKeyring(structuredClone(disk),
    async (next) => {
      if (failSave) {failSave = false; throw Error('save failed');}
      if (failCleanup && !next.accountEvent && disk.accountEvent?.attempted) {
        failCleanup = false; throw Error('cleanup failed');
      }
      disk = structuredClone(next);
    },
    async (event) => {
      if (failEmit) {failEmit = false; throw Error('emit failed');}
      events.push(event);
    },
  );
  return {open, events, snapshot:() => disk,
    failSave:() => {failSave = true;},
    failEmit:() => {failEmit = true;},
    failCleanup:() => {failCleanup = true;}};
}

test('create persists account before emit, then restart retries exact event', async () => {
  const h = harness();
  let k = h.open();
  h.failEmit();
  await assert.rejects(() => k.createAccount({address}), /emit failed/);
  assert.equal(Object.keys(h.snapshot().accounts).length, 1);
  assert.deepEqual(k.listAccountEvents().map((e) => [e.kind,e.attempted]), [['created',true]]);
  await assert.rejects(() => k.createAccount({address:'0x000000000000000000000000000000000000bEEF'}),/previous account notification/);
  k = h.open();
  await k.recoverAccountEvent('retry');
  assert.deepEqual(k.listAccountEvents(),[]);
  assert.equal(h.events.filter((e) => e === 'notify:accountCreated').length,1);
});

test('create save failure cannot notify MetaMask or mutate accounts', async () => {
  const h = harness();
  const k = h.open();
  h.failSave();
  await assert.rejects(() => k.createAccount({address}), /save failed/);
  assert.equal(Object.keys(h.snapshot().accounts).length,0);
  assert.deepEqual(k.listAccountEvents(),[]);
  assert.deepEqual(h.events,[]);
});

test('delete save failure does not notify, emitted delete survives restart cleanup failure', async () => {
  const h = harness();
  let k = h.open();
  const account = await k.createAccount({address});
  h.failSave();
  await assert.rejects(() => k.deleteAccount(account.id), /save failed/);
  assert.equal(h.snapshot().accounts[account.id]?.address,address);
  assert.equal(h.events.filter((e) => e === 'notify:accountDeleted').length,0);
  h.failCleanup();
  await assert.rejects(() => k.deleteAccount(account.id),/cleanup failed/);
  assert.equal(h.snapshot().accounts[account.id],undefined);
  assert.deepEqual(k.listAccountEvents().map((e) => [e.kind,e.attempted]), [['deleted',true]]);
  k = h.open();
  await k.recoverAccountEvent('abandon');
  assert.deepEqual(k.listAccountEvents(),[]);
  assert.equal(h.events.filter((e) => e === 'notify:accountDeleted').length,1);
});

test('delete emit failure preserves event for restart, new account blocked until recovery', async () => {
  const h = harness();
  let k = h.open();
  const account = await k.createAccount({address});
  h.failEmit();
  await assert.rejects(() => k.deleteAccount(account.id), /emit failed/);
  assert.equal(h.snapshot().accounts[account.id],undefined);
  assert.deepEqual(k.listAccountEvents().map((e) => [e.kind,e.attempted]), [['deleted',true]]);
  k = h.open();
  await assert.rejects(() => k.createAccount({address}),/previous account notification/);
  await k.recoverAccountEvent('retry');
  assert.deepEqual(k.listAccountEvents(),[]);
  assert.equal(h.events.filter((e) => e === 'notify:accountDeleted').length,1);
});
