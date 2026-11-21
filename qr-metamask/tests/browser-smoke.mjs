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
  await page.locator('#pair').click();
  await page.locator('#qr').waitFor({state:'visible'});
  assert.match(await page.locator('#qr').getAttribute('src'), /^data:image\/png;base64,/);
  assert.match(await page.locator('#qr-type').textContent(), /crypto-hdkey/);

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

  await page.locator('#cancel').click();
  assert.equal(await page.locator('#qr').isHidden(), true);
  assert.equal(await page.locator('#qr').getAttribute('src'), null);
  assert.deepEqual(errors, [], 'No console or uncaught browser runtime errors');
});
