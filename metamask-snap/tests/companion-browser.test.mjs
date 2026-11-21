import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, join, extname } from 'node:path';
import { chromium } from 'playwright';

const ROOT = resolve('dist-companion');
const ID = '1'.repeat(32);
const ACCOUNT_ID = '12345678-1234-5123-8123-123456789012';
const ADDRESS = '0x000000000000000000000000000000000000dEaD';
const RECIPIENT = '0x000000000000000000000000000000000000bEEF';
const WEI = '123456789012345678';
const TX = {
  type: '0x2', chainId:'0xaa36a7', nonce:'0x1', from:ADDRESS, to:RECIPIENT,
  value:'0x'+BigInt(WEI).toString(16), gasLimit:'0x5208', maxFeePerGas:'0x12a05f200',
  maxPriorityFeePerGas:'0x3b9aca00', data:'0x', accessList:[],
};
const REQUEST = {id:'metamask-req-1', scope:'eip155:11155111', account:ACCOUNT_ID,
  request:{method:'eth_signTransaction', params:[TX]}};
const ACCOUNT = {id:ACCOUNT_ID,address:ADDRESS,type:'eip155:eoa',
  methods:['eth_signTransaction'],scopes:['eip155:eoa'],options:{coldSigner:true,network:'eip155:11155111'}};
const QR = JSON.stringify({version:1,direction:'unsigned',network:'sepolia',
  request_id:ID,amount_wei:WEI});

async function serve() {
  const server = createServer(async (req,res) => {
    try {
      const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
      const name = pathname === '/' ? '/index.html' : pathname;
      const file = resolve(join(ROOT,name.slice(1)));
      if (file !== ROOT && !file.startsWith(ROOT + '/')) {res.writeHead(403).end();return;}
      const content = await readFile(file);
      const ext = extname(file);
      res.writeHead(200,{'Content-Type':ext==='.js'?'text/javascript':ext==='.css'?'text/css':'text/html',
        'Cache-Control':'no-store'}).end(content);
    } catch {res.writeHead(404).end('missing');}
  });
  await new Promise((yes,no)=>{server.once('error',no);server.listen(0,'127.0.0.1',yes);});
  return {url:'http://127.0.0.1:'+server.address().port,
    close:()=>new Promise((yes)=>server.close(yes))};
}

test('production Companion downloads exact QR JSON with full-precision wei, no eager revoke', {timeout:60_000}, async(t)=>{
  const web=await serve();t.after(()=>web.close());
  const browser=await chromium.launch({headless:true});t.after(()=>browser.close());
  const page=await browser.newPage({acceptDownloads:true});
  const errors=[];page.on('pageerror',(e)=>errors.push(e.message));
  await page.addInitScript(({request,account,qr})=>{
    window.ethereum = {request:async({method,params})=>{
      if(method==='wallet_requestSnaps')return {};
      if(method==='eth_chainId')return '0xaa36a7';
      if(method==='eth_accounts')return [account.address];
      if(method==='eth_getTransactionCount')return '0x1';
      if(method==='wallet_invokeKeyring') {
        const m=params?.request?.method;
        if(m==='keyring_listAccounts')return [account];
        if(m==='keyring_listRequests')return [request];
        throw Error('unexpected keyring method: '+m);
      }
      if(method==='wallet_invokeSnap') {
        const m=params?.request?.method;
        if(m==='usb_listTerminalEvents'||m==='usb_listAccountEvents')return [];
        if(m==='usb_getQrRequest')return qr;
        throw Error('unexpected snap method: '+m);
      }
      throw Error('unexpected MetaMask method: '+method);
    }};
  },{request:REQUEST,account:ACCOUNT,qr:QR});
  await page.goto(web.url,{waitUntil:'networkidle'});
  await page.locator('#connect').click();
  await page.getByText('已連線至本機 Snap',{exact:false}).waitFor();
  assert.match(await page.locator('#details').textContent(), /123456789012345678/);
  const [download]=await Promise.all([page.waitForEvent('download'),page.locator('#export').click()]);
  assert.equal(download.suggestedFilename(), 'cold-sepolia-request-'+ID+'.json');
  assert.equal(await download.failure(),null);
  const payload=await readFile(await download.path(),'utf8');
  assert.equal(payload,QR);
  assert.equal(JSON.parse(payload).amount_wei,WEI);
  assert.deepEqual(errors,[]);
});

test('production Companion rejects wrong chain before downloading and keeps pending intent intact', {timeout:60_000}, async(t)=>{
  const web=await serve();t.after(()=>web.close());
  const browser=await chromium.launch({headless:true});t.after(()=>browser.close());
  const page=await browser.newPage({acceptDownloads:true});
  await page.addInitScript(({request,account,qr})=>{
    window.ethereum={request:async({method,params})=>{
      if(method==='wallet_requestSnaps')return {};
      if(method==='wallet_invokeKeyring') {
        if(params.request.method==='keyring_listAccounts')return [account];
        if(params.request.method==='keyring_listRequests')return [request];
      }
      if(method==='wallet_invokeSnap'){
        if(params.request.method==='usb_getQrRequest')return qr;
        return [];
      }
      if(method==='eth_chainId')return '0x1';
      throw Error('unexpected method: '+method);
    }};
  },{request:REQUEST,account:ACCOUNT,qr:QR});
  await page.goto(web.url,{waitUntil:'networkidle'});
  await page.locator('#connect').click();
  await page.getByText('已連線至本機 Snap',{exact:false}).waitFor();
  let downloads=0;page.on('download',()=>downloads++);
  await page.locator('#export').click();
  await page.getByText('MetaMask 已切換鏈',{exact:false}).waitFor();
  assert.equal(downloads,0);
  assert.match(await page.locator('#details').textContent(),/123456789012345678/);
});
