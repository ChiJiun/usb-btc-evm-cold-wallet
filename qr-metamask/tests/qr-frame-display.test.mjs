import test from 'node:test';
import assert from 'node:assert/strict';
import { QrFrameDisplay } from '../src/qr_frame_display.mjs';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
}
function harness(encode) {
  const image = {
    hidden: true,
    src: '',
    removeAttribute(name) {
      assert.equal(name, 'src');
      this.src = '';
    },
  };
  const label = { textContent: '' };
  const tasks = new Map();
  let nextId = 0;
  const errors = [];
  const screen = new QrFrameDisplay({
    encode, image, label,
    schedule: (fn) => { const id = ++nextId; tasks.set(id, fn); return id; },
    unschedule: (id) => tasks.delete(id),
    onError: (err) => errors.push(err.message),
  });
  return { screen, image, label, tasks, errors };
}

test('Cancel invalidates deferred QR encoder and never shows old signature', async () => {
  const pending = deferred();
  const ui = harness(() => pending.promise);
  const show = ui.screen.show({ type: 'eth-signature' }, ['old-signed']);
  assert.equal(ui.image.hidden, true);
  ui.screen.clear();
  pending.resolve('data:image/png;base64,OLD');
  assert.equal(await show, false);
  assert.equal(ui.image.hidden, true);
  assert.equal(ui.image.src, '');
  assert.equal(ui.label.textContent, '');
  assert.equal(ui.tasks.size, 0);
});

test('new pairing/session cannot be overwritten by a previous deferred signed QR', async () => {
  const old = deferred();
  const newer = deferred();
  const ui = harness((frame) => frame === 'old-signed' ? old.promise : newer.promise);
  const oldShow = ui.screen.show({ type: 'eth-signature' }, ['old-signed']);
  const newShow = ui.screen.show({ type: 'crypto-hdkey' }, ['new-pairing']);
  newer.resolve('data:image/png;base64,NEW');
  assert.equal(await newShow, true);
  assert.equal(ui.image.hidden, false);
  assert.equal(ui.image.src, 'data:image/png;base64,NEW');
  old.resolve('data:image/png;base64,OLD');
  assert.equal(await oldShow, false);
  assert.equal(ui.image.src, 'data:image/png;base64,NEW');
  assert.match(ui.label.textContent, /crypto-hdkey/);
  assert.equal(ui.tasks.size, 0);
});

test('animated QR frames serialize async encodes and never run concurrent renders', async () => {
  const pending = [];
  const ui = harness((frame) => {
    const p = deferred();
    pending.push({ frame, ...p });
    return p.promise;
  });
  const first = ui.screen.show({ type: 'eth-sign-request' }, ['frame-0', 'frame-1']);
  assert.equal(pending.length, 1);
  assert.equal(ui.tasks.size, 0, 'no timer before first QR has finished');
  pending[0].resolve('data:image/png;base64,FIRST');
  assert.equal(await first, true);
  assert.equal(ui.tasks.size, 1);
  assert.match(ui.label.textContent, /1\/2/);
  const tick = [...ui.tasks.values()][0];
  ui.tasks.clear();
  tick();
  assert.equal(pending.length, 2);
  assert.equal(pending[1].frame, 'frame-1');
  assert.equal(ui.tasks.size, 0, 'no overlapping timer during pending render');
  ui.screen.clear();
  pending[1].resolve('data:image/png;base64,SECOND');
  await Promise.resolve();
  assert.equal(ui.image.hidden, true);
  assert.equal(ui.image.src, '');
  assert.equal(ui.tasks.size, 0);
});

test('encoder failures in active animation stop the display and report an error', async () => {
  const ui = harness(async (frame) => {
    if (frame === 'bad') throw new Error('encode failed');
    return 'data:image/png;base64,GOOD';
  });
  await ui.screen.show({ type: 'crypto-hdkey' }, ['good', 'bad']);
  const tick = [...ui.tasks.values()][0];
  ui.tasks.clear();
  tick();
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(ui.errors, ['encode failed']);
  assert.equal(ui.image.hidden, true);
  assert.equal(ui.tasks.size, 0);
});
