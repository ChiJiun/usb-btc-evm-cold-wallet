import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, resolve, extname } from 'node:path';
import { chromium } from 'playwright';
import { HDNodeWallet, Transaction } from 'ethers';
import { EthSignRequest, DataType } from '@keystonehq/bc-ur-registry-eth';
import { framesFromUr } from '../src/adapter.mjs';

// This is a PUBLICLY COMPROMISED test fixture. Never use for real funds.
const root = HDNodeWallet.fromSeed(new Uint8Array(64).fill(1));
const account = root.derivePath("m/44'/60'/0'");
const address = account.derivePath('0/0');
const recipient = '0x000000000000000000000000000000000000dEaD';
const publicInfo = {
  format: 'usb-cold-keystone-public-v1', network: 'sepolia', chain_id: 11155111,
  master_fingerprint: root.fingerprint.slice(2),
  account_derivation: 'm/44h/60h/0h',
  address_derivation: 'm/44h/60h/0h/0/0',
  account_public_key: account.publicKey.slice(2),
  account_chain_code: account.chainCode.slice(2),
  account_parent_fingerprint: account.parentFingerprint.slice(2),
  address_public_key: address.publicKey.slice(2),
  address_chain_code: address.chainCode.slice(2),
  address_parent_fingerprint: address.parentFingerprint.slice(2),
  address: address.address,
};
const transfer = {
  type: 2, chainId: 11155111, nonce: 1, to: recipient, value: 123456789012345678n,
  gasLimit: 21000, maxFeePerGas: 5000000000n,
  maxPriorityFeePerGas: 1000000000n, data: '0x', accessList: [],
};

async function startStaticServer() {
  const base = resolve('dist');
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      const pathname = url.pathname === '/' ? '/index.html' : url.pathname;
      const path = resolve(join(base, pathname.slice(1)));
      if (!path.startsWith(base + '/') && path !== base) {
        res.writeHead(403).end(); return;
      }
      const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
      const body = await readFile(path);
      res.writeHead(200, {
        'Content-Type': types[extname(path)] || 'application/octet-stream',
        'Cache-Control': 'no-store',
      }).end(body);
    } catch {
      res.writeHead(404).end('Not found');
    }
  });
  await new Promise((okay, fail) => {
    server.once('error', fail);
    server.listen(0, '127.0.0.1', okay);
  });
  return {
    address: 'http://127.0.0.1:' + server.address().port,
    close: () => new Promise((done) => server.close(done)),
  };
}

test('built browser bundle passes CSP and native QR pairing/request/signed response flow', {timeout: 45_000}, async (t) => {
  const web = await startStaticServer();
  t.after(() => web.close());
  const browser = await chromium.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (err) => errors.push(err.message));
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(msg.text());
  });
  await page.goto(web.address, { waitUntil: 'networkidle' });
  assert.match(await page.locator('h1').textContent(), /MetaMask/);
  assert.equal(await page.locator('#pair').isDisabled(), true);

  await page.locator('#public-file').setInputFiles({
    name: 'test-public.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(publicInfo)),
  });
  await page.getByText('公開帳戶已讀取', {exact:false}).waitFor();
  assert.equal(await page.locator('#scan').isDisabled(), true,
    'Cannot scan a MetaMask signing request before account verification');
  assert.equal(await page.locator('#parse').isDisabled(), true);
  await page.locator('#pair').click();
  await page.locator('#qr').waitFor({state:'visible'});
  assert.match(await page.locator('#qr').getAttribute('src'), /^data:image\/png;base64,/);
  assert.match(await page.locator('#qr-type').textContent(), /crypto-hdkey/);

  // Mismatched MetaMask account must fail closed, matching account unlocks.
  await page.locator('#metamask-address').fill(recipient);
  await page.locator('#verify-address').click();
  await page.getByText('MetaMask 選取地址與離線可簽地址不同', {exact:false}).waitFor();
  assert.equal(await page.locator('#scan').isDisabled(), true);
  assert.equal(await page.locator('#parse').isDisabled(), true);
  await page.locator('#metamask-address').fill(publicInfo.address.toLowerCase());
  await page.locator('#verify-address').click();
  await page.getByText('MetaMask 所選地址與離線可簽地址完全相同', {exact:false}).waitFor();
  assert.equal(await page.locator('#scan').isEnabled(), true);
  assert.equal(await page.locator('#parse').isEnabled(), true);

  const unsigned = Transaction.from(transfer);
  const request = EthSignRequest.constructETHRequest(
    Buffer.from(unsigned.unsignedSerialized.slice(2), 'hex'), DataType.typedTransaction,
    "m/44'/60'/0'/0/0", publicInfo.master_fingerprint,
    '00000000-0000-4000-8000-000000000001', 11155111,
  ).toUR();
  await page.locator('#ur-input').fill(framesFromUr(request, 220, 10).join('\n'));
  await page.locator('#parse').click();
  assert.match(await page.locator('#intent').textContent(), /123456789012345678/);
  assert.equal(await page.locator('#qr').isHidden(), true, 'old pairing QR must be cleared');

  // Real browser download, not just the adapter's in-memory JSON formatter.
  // Playwright JS uses waitForEvent('download') (expectDownload is not a JS API).
  const [unsignedDownload] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('#download').click(),
  ]);
  assert.equal(
    unsignedDownload.suggestedFilename(),
    'sepolia-unsigned-00000000000040008000000000000001.json',
  );
  assert.equal(await unsignedDownload.failure(), null);
  const unsignedDownloaded = await readFile(await unsignedDownload.path(), 'utf8');
  const downloaded = JSON.parse(unsignedDownloaded);
  assert.deepEqual(Object.keys(downloaded).sort(),
    ['type','chainId','nonce','to','value','gas','maxFeePerGas',
      'maxPriorityFeePerGas','data','accessList'].sort());
  assert.equal(downloaded.type, 2);
  assert.equal(downloaded.chainId, 11155111);
  assert.equal(downloaded.nonce, transfer.nonce);
  assert.equal(downloaded.to, recipient);
  assert.equal(downloaded.gas, 21000);
  assert.equal(downloaded.data, '0x');
  assert.deepEqual(downloaded.accessList, []);
  for (const [field, expected] of [
    ['value', transfer.value],
    ['maxFeePerGas', transfer.maxFeePerGas],
    ['maxPriorityFeePerGas', transfer.maxPriorityFeePerGas],
  ]) {
    const literal = unsignedDownloaded.match(new RegExp('"'+field+'":([0-9]+)(?=[,}])'));
    assert.ok(literal, field+' must be a JSON number token, not a quoted string');
    assert.equal(BigInt(literal[1]), expected, field+' must retain exact Wei');
  }
  assert.equal(Number.isSafeInteger(downloaded.value), false,
    'Large Wei amounts must be checked from the original JSON numeric token');
  assert.match(await page.locator('#status').textContent(), /已產生精確 Wei/);

  const raw = await address.signTransaction(transfer);
  await page.locator('#signed-file').setInputFiles({
    name: 'signed.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      signed_raw_transaction: raw, transaction_hash: Transaction.from(raw).hash,
    })),
  });
  await page.locator('#reply').click();
  await page.waitForFunction(() => {
    const status = document.getElementById('status').textContent;
    return status.includes('簽章符合本次 MetaMask request') || status.startsWith('拒絕／錯誤');
  }, null, { timeout: 10_000 });
  const replyStatus = await page.locator('#status').textContent();
  assert.match(replyStatus, /簽章符合本次 MetaMask request/,
    'Browser signing status: ' + replyStatus + '; errors: ' + errors.join('; '));
  assert.match(await page.locator('#qr-type').textContent(), /eth-signature/);
  assert.match(await page.locator('#qr').getAttribute('src'), /^data:image\/png;base64,/);
  assert.equal(await page.locator('#download').isDisabled(), true,
    'Signed requests must not allow a second unsigned download');

  await page.locator('#cancel').click();
  assert.equal(await page.locator('#download').isDisabled(), true,
    'Cancelled sessions must not expose unsigned downloads');
  assert.equal(await page.locator('#qr').isHidden(), true);
  assert.equal(await page.locator('#qr').getAttribute('src'), null);

  // Browser-level regression for the delayed File.text() race: a previous
  // malformed account import must not overwrite a newer successful import.
  await page.evaluate(() => {
    const original = File.prototype.text;
    File.prototype.text = function () {
      if (this.name === 'stale-import.json') {
        return new Promise((resolve) => {
          window.__resolveStaleImport = () => resolve('not-valid-json');
        });
      }
      return original.call(this);
    };
  });
  await page.locator('#public-file').setInputFiles({
    name:'stale-import.json',mimeType:'application/json',
    buffer:Buffer.from('not-valid-json'),
  });
  await page.waitForFunction(() => typeof window.__resolveStaleImport === 'function');
  await page.locator('#public-file').setInputFiles({
    name:'current-public.json',mimeType:'application/json',
    buffer:Buffer.from(JSON.stringify(publicInfo)),
  });
  await page.getByText('公開帳戶已讀取', {exact:false}).waitFor();
  await page.evaluate(() => window.__resolveStaleImport());
  await page.waitForTimeout(80);
  assert.match(await page.locator('#account').textContent(),
    new RegExp(publicInfo.address, 'i'));
  assert.match(await page.locator('#status').textContent(), /公開帳戶已讀取/);
  assert.equal(await page.locator('#pair').isEnabled(), true);
  assert.equal(await page.locator('#scan').isDisabled(), true,
    'Importing a new public file must reset account selection confirmation');
  assert.equal(await page.locator('#parse').isDisabled(), true);

  // A previously verified user can parse, but changing the selected MetaMask
  // account must revoke any pending unsigned download / signed response.
  await page.locator('#metamask-address').fill(publicInfo.address);
  await page.locator('#verify-address').click();
  await page.getByText('MetaMask 所選地址與離線可簽地址完全相同', {exact:false}).waitFor();
  await page.locator('#ur-input').fill(framesFromUr(request, 220, 10).join('\n'));
  await page.locator('#parse').click();
  assert.equal(await page.locator('#download').isEnabled(), true);
  await page.locator('#metamask-address').fill(recipient);
  assert.equal(await page.locator('#download').isDisabled(), true);
  assert.equal(await page.locator('#signed-file').isDisabled(), true);
  assert.equal(await page.locator('#reply').isDisabled(), true);
  assert.equal(await page.locator('#parse').isDisabled(), true);
  await page.locator('#verify-address').click();
  await page.getByText('MetaMask 選取地址與離線可簽地址不同', {exact:false}).waitFor();
  assert.equal(await page.locator('#download').isDisabled(), true);

  // Simulate Chromium's BFCache lifecycle with an active, authorized request:
  // pagehide + persisted pageshow must revoke access without a full reload.
  await page.locator('#metamask-address').fill(publicInfo.address);
  await page.locator('#verify-address').click();
  await page.getByText('MetaMask 所選地址與離線可簽地址完全相同', {exact:false}).waitFor();
  await page.locator('#ur-input').fill(framesFromUr(request, 220, 10).join('\n'));
  await page.locator('#parse').click();
  assert.equal(await page.locator('#download').isEnabled(), true);
  assert.equal(await page.locator('#reply').isEnabled(), true);
  await page.evaluate(() => {
    window.dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));
    window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
  });
  for (const id of ['download','signed-file','reply','scan','parse']) {
    assert.equal(await page.locator('#'+id).isDisabled(), true,
      id+' must be disabled after a BFCache page lifecycle');
  }
  assert.equal(await page.locator('#qr').isHidden(), true);
  assert.equal(await page.locator('#qr').getAttribute('src'), null);
  assert.equal(await page.locator('#metamask-address').inputValue(), '');
  assert.match(await page.locator('#intent').textContent(), /尚無交易/);
  // An old signed file or unconfirmed address cannot unlock the stale session.
  await page.locator('#metamask-address').fill(publicInfo.address);
  assert.equal(await page.locator('#download').isDisabled(), true);
  assert.equal(await page.locator('#parse').isDisabled(), true);
  await page.locator('#verify-address').click();
  assert.equal(await page.locator('#parse').isEnabled(), true,
    'The restored page may only start a fresh request after re-verification');
  assert.equal(await page.locator('#download').isDisabled(), true);
  assert.deepEqual(errors, [], 'No console or uncaught browser runtime errors');
});
