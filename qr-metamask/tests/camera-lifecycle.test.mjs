import test from 'node:test';
import assert from 'node:assert/strict';
import { CameraLifecycle } from '../src/camera_lifecycle.mjs';

test('scan cancellation before camera permission resolves stops late controls', () => {
  const camera = new CameraLifecycle();
  const old = camera.begin();
  assert.equal(camera.isCurrent(old), true);
  assert.equal(camera.begin(), null, 'must not open duplicate permission prompts');
  camera.cancel();
  assert.equal(camera.isCurrent(old), false);
  let stops = 0;
  assert.equal(camera.attach(old, {stop: () => {stops += 1;}}), false);
  assert.equal(stops, 1, 'late camera must be shut down');
});

test('a stale callback cannot accept QR fragments into a new session', () => {
  const camera = new CameraLifecycle();
  const old = camera.begin();
  camera.cancel();
  const fresh = camera.begin();
  assert.notEqual(fresh, old);
  assert.equal(camera.isCurrent(old), false);
  assert.equal(camera.isCurrent(fresh), true);
  let staleStops = 0;
  assert.equal(camera.attach(old, {stop: () => {staleStops++;}}), false);
  assert.equal(staleStops, 1);
  let freshStops = 0;
  assert.equal(camera.attach(fresh, {stop: () => {freshStops++;}}), true);
  assert.equal(camera.begin(), null, 'must not open while already scanning');
  camera.cancel();
  assert.equal(freshStops, 1);
  assert.equal(camera.isCurrent(fresh), false);
  camera.cancel();
  assert.equal(freshStops, 1, 'cancel is safe to repeat');
});

test('a new scan is allowed after a canceled pending start or active session', () => {
  const camera = new CameraLifecycle();
  const pending = camera.begin();
  camera.cancel();
  const active = camera.begin();
  assert.notEqual(active, pending);
  assert.equal(camera.attach(active, {stop: () => {}}), true);
  camera.cancel();
  assert.equal(camera.isCurrent(active), false);
  assert.ok(camera.begin() > active);
});
