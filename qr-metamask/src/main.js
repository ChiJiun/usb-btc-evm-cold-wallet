import { BrowserQRCodeReader } from '@zxing/browser';
import QRCode from 'qrcode';
import { makePairingUr, decodeMetaMaskRequest, makeSignedResponseUr,
  framesFromUr, unsignedJsonForOffline, validatePublic, MAX_FRAMES } from './adapter.mjs';

const $ = (id) => document.getElementById(id);
const setStatus = (text) => { $('status').textContent = String(text); };
let publicInfo = null, active = null, used = false, qrTimer = null, videoControls = null;
const collected = [];
const decoder = new BrowserQRCodeReader();

async function guarded(fn) {
  try { await fn(); } catch (err) { setStatus('拒絕／錯誤：' + (err?.message || String(err))); }
}
async function boundedText(file, max = 120_000) {
  if (!file || file.size <= 0 || file.size > max) throw Error('只接受大小有限的 JSON 檔案');
  return file.text();
}
function stopCamera() {
  videoControls?.stop?.();
  videoControls = null;
  $('camera').hidden = true;
  $('stop').disabled = true;
}
function clearSession() {
  stopCamera();
  active = null; used = false; collected.splice(0);
  $('intent').textContent = '尚無交易';
  $('download').disabled = true;
  $('signed-file').disabled = true;
  $('reply').disabled = true;
  $('signed-file').value = '';
  $('ur-input').value = '';
  if(qrTimer) clearInterval(qrTimer);
  qrTimer = null;
  $('qr').hidden = true;
  $('qr-type').textContent = '';
}
async function displayUr(ur) {
  const frames = framesFromUr(ur,220,10);
  if(qrTimer) clearInterval(qrTimer);
  qrTimer = null;
  let index = 0;
  const show = async () => {
    const value = frames[index++ % frames.length];
    $('qr').src = await QRCode.toDataURL(value,{errorCorrectionLevel:'M',margin:1,width:400});
    $('qr').hidden = false;
    $('qr-type').textContent = ur.type + ' · ' + ((index-1)%frames.length+1) + '/' + frames.length;
  };
  await show();
  if(frames.length>1) qrTimer = setInterval(() => { void show().catch((e) => setStatus('QR encoding error: '+e.message)); },400);
}
function download(name,body) {
  const url = URL.createObjectURL(new Blob([body],{type:'application/json'}));
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}
function displayIntent(session) {
  const t=session.tx;
  const maxFee=t.gasLimit*t.maxFeePerGas;
  $('intent').textContent = [
    '鏈別: Sepolia (11155111) / EIP-1559',
    '帳戶: ' + session.account,
    'Request ID: '+session.requestId,
    '收款地址: '+t.to,
    '金額 (Wei): '+t.value.toString(10),
    'Nonce: '+t.nonce,
    'Gas: '+t.gasLimit.toString(10),
    'Max fee per gas (Wei): '+t.maxFeePerGas.toString(10),
    'Priority fee per gas (Wei): '+t.maxPriorityFeePerGas.toString(10),
    '最大交易手續費 (Wei): '+maxFee.toString(10),
    '最大支出 (Wei): '+(t.value+maxFee).toString(10),
    'data: 0x (僅原生 ETH 轉帳)',
  ].join('\n');
}
function acceptRequest(parts) {
  if(!publicInfo) throw Error('先匯入離線錢包的公開帳戶資訊');
  if(active) throw Error('已有待處理請求；請先完成或取消，不可混用 QR 幀');
  const pending=decodeMetaMaskRequest(parts,publicInfo);
  active=pending;used=false;
  stopCamera();
  displayIntent(pending);
  $('download').disabled = false;
  $('signed-file').disabled = false;
  $('reply').disabled = false;
  setStatus('請逐項核對交易，下載 unsigned JSON，由可信離線 CLI 簽署。');
}
$('public-file').addEventListener('change',()=>guarded(async()=>{
  const raw=await boundedText($('public-file').files?.[0],10_000);
  const imported=JSON.parse(raw);
  const validated=validatePublic(imported);
  clearSession();
  publicInfo=imported;
  $('account').textContent='錢包地址：'+validated.address+'（公開資料，請與實體離線電腦比對）';
  $('pair').disabled = false; $('scan').disabled=false; $('parse').disabled=false;
  setStatus('公開帳戶已讀取，可以顯示配對 QR。');
}));
$('pair').addEventListener('click',()=>guarded(async()=>{
  if(!publicInfo) throw Error('尚無公開帳戶');
  if(active) throw Error('請先結束當前交易');
  await displayUr(makePairingUr(publicInfo));
  setStatus('MetaMask → Connect Hardware Wallet → QR-based，掃描這個 crypto-account 公開 QR。');
}));
$('scan').addEventListener('click',()=>guarded(async()=>{
  if(!publicInfo || active) throw Error('需先匯入公開帳戶，且沒有現存待處理交易');
  if(videoControls) return;
  collected.splice(0);
  $('camera').hidden=false;
  $('stop').disabled=false;
  videoControls=await decoder.decodeFromVideoDevice(undefined,$('camera'),(result,err,controls)=>{
    if(!result) return;
    const piece=result.getText().trim();
    if(!piece.toLowerCase().startsWith('ur:eth-sign-request/')) return;
    if(!collected.includes(piece)) collected.push(piece);
    if(collected.length>MAX_FRAMES) { stopCamera();setStatus('QR 幀數超過上限');return; }
    try {
      acceptRequest(collected);
      controls.stop();
    } catch(e) {
      if(!/UR frames incomplete/.test(e.message)) setStatus('掃描尚未成功：'+e.message);
    }
  });
  setStatus('攝影機啟動，請掃描 MetaMask 的 eth-sign-request QR。');
}));
$('stop').addEventListener('click',()=>{stopCamera();setStatus('已停止掃描。');});
$('parse').addEventListener('click',()=>guarded(async()=>{
  acceptRequest($('ur-input').value.trim().split(/\s+/));
}));
$('download').addEventListener('click',()=>guarded(async()=>{
  if(!active || used) throw Error('沒有未處理請求');
  download('sepolia-unsigned-'+active.requestId+'.json',unsignedJsonForOffline(active));
  setStatus('已產生精確 Wei 的交易 JSON，請於實體斷網電腦獨立核對後簽署。');
}));
$('reply').addEventListener('click',()=>guarded(async()=>{
  if(!active || used) throw Error('請先掃描新的 MetaMask request');
  const signed=JSON.parse(await boundedText($('signed-file').files?.[0]));
  const response=makeSignedResponseUr(active,signed);
  used=true;
  $('reply').disabled=true;$('download').disabled=true;
  await displayUr(response);
  setStatus('簽章符合本次 MetaMask request，可供 MetaMask「Get Signature」掃描。不代表已廣播或確認。');
}));
$('cancel').addEventListener('click',()=>{
  clearSession();setStatus('已清除目前請求與 QR 動畫。若 MetaMask 尚在等待，請在 MetaMask 取消該交易。');
});
window.addEventListener('pagehide',()=>{stopCamera();if(qrTimer)clearInterval(qrTimer);});
