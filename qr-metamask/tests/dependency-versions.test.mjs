import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../package.json', import.meta.url));
const lockPath = fileURLToPath(new URL('../package-lock.json', import.meta.url));

test('all installed UUID copies are patched, including upstream Keystone Keyring',()=>{
  const pkg=JSON.parse(readFileSync(source, 'utf8'));
  const lock=JSON.parse(readFileSync(lockPath, 'utf8'));
  assert.equal(pkg.overrides?.uuid, '11.1.1');
  const uuids=Object.entries(lock.packages)
    .filter(([path])=>path==='node_modules/uuid' || path.endsWith('/node_modules/uuid'));
  assert.ok(uuids.length >= 1, 'Expected real UUID dependencies to audit');
  for (const [path,meta] of uuids) {
    assert.equal(meta.version, '11.1.1', path);
    assert.ok(meta.integrity?.startsWith('sha512-'), path);
  }
});
