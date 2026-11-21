import { BrowserQRCodeReader } from '@zxing/browser';
import QRCode from 'qrcode';
import { CameraLifecycle } from './camera_lifecycle.mjs';
import { QrFrameDisplay } from './qr_frame_display.mjs';
import { PublicAccountImport } from './public_account_import.mjs';
import { verifySelectedAddress } from './address_verification.mjs';
import { makePairingUr, decodeMetaMaskRequest, makeSignedResponseUr,
  framesFromUr, unsignedJsonForOffline, validatePublic, MAX_FRAMES } from './adapter.mjs';

const $ = (id) => document.getElementById(id);
const setStatus = (text) => { $('status').textContent = String(text); };
let publicInfo = null, active = null, used = false, confirmedAddress = null;
const publicImporter = new PublicAccountImport(validatePublic);
const camera = new CameraLifecycle();
const qrDisplay = new QrFrameDisplay({
  encode: (frame, options) => QRCode.toDataURL(frame, options),
  image: $('qr'), label: $('qr-type'),
  onError: (err) => setStatus('QR encoding error: ' + err.message),
});
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
  camera.cancel();
  $('camera').hidden = true;
  $('stop').disabled = true;
}
function invalidateAddressConfirmation() {
  confirmedAddress=null;
  $('scan').disabled=true; $('parse').disabled=true;
}
function confirmSelectedAddress(value) {
  if(!publicInfo) throw Error('先匯入離線公開帳戶');
  const address=verifySelectedAddress(value,validatePublic(publicInfo).address);
  confirmedAddress=address;
  $('metamask-address').value=address;
  $('scan').disabled=false; $('parse').disabled=false;
  setStatus('MetaMask 所選地址與離線可簽地址完全相同，已允許處理交易 QR。');
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
  qrDisplay.clear();
}
async function displayUr(ur) {
  return qrDisplay.show(ur, framesFromUr(ur, 220, 10));
}
function download(name,body) {
  const url = URL.createObjectURL(new Blob([body],{type:'application/json'}));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  // Attach the element and leave the blob alive while the browser starts its
  // download; immediate revocation can race asynchronous download handling.
  document.body.appendChild(a);
  try {
    a.click();
  } finally {
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
  }
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
  if(!confirmedAddress || confirmedAddress!==validatePublic(publicInfo).address) {
    throw Error('必須先核對 MetaMask 已選帳戶的完整地址');
  }
  if(active) throw Error('已有待處理請求；請先完成或取消，不可混用 QR 幀');
  const pending=decodeMetaMaskRequest(parts,publicInfo);
  active=pending;used=false;
  qrDisplay.clear();
  stopCamera();
  displayIntent(pending);
  $('download').disabled = false;
  $('signed-file').disabled = false;
  $('reply').disabled = false;
  setStatus('請逐項核對交易，下載 unsigned JSON，由可信離線 CLI 簽署。');
}
$('public-file').addEventListener('change',()=>{
  const file=$('public-file').files?.[0];
  // Revoke the previous account and signing request before awaiting file I/O.
  clearSession(); publicInfo=null; invalidateAddressConfirmation();
  $('account').textContent='';
  $('metamask-address').value='';
  $('metamask-address').disabled=true;
  $('verify-address').disabled=true; $('scan-address').disabled=true;
  $('pair').disabled=true;
  const pending=publicImporter.read(file);
  void guarded(async()=>{
    const result=await pending;
    if (!result || $('public-file').files?.[0] !== file) return;
    publicInfo=result.info;
    $('account').textContent='錢包地址：'+result.validated.address+'（公開資料，請與實體離線電腦比對）';
    $('pair').disabled=false;
    $('metamask-address').disabled=false;
    $('verify-address').disabled=false; $('scan-address').disabled=false;
    setStatus('公開帳戶已讀取。配對 MetaMask 後，請先核對所選地址才能掃描交易。');
  });
});
$('metamask-address').addEventListener('input',()=>{
  // Any selection change invalidates a pending signing request, even if the
  // user later types the same address again.
  invalidateAddressConfirmation();
  clearSession();
  setStatus('MetaMask 帳戶地址已變更；請重新核對完整地址。');
});
$('verify-address').addEventListener('click',()=>guarded(async()=>{
  confirmSelectedAddress($('metamask-address').value);
}));
$('scan-address').addEventListener('click',()=>guarded(async()=>{
  if(!publicInfo || active) throw Error('先匯入公開帳戶，並結束目前交易');
  // Selecting a new MetaMask account must invalidate an earlier verification,
  // even if this scan later fails, is stopped or gets denied camera access.
  invalidateAddressConfirmation();
  clearSession();
  const epoch=camera.begin();
  if(epoch===null) return;
  $('camera').hidden=false;
  $('stop').disabled=false;
  try {
    const controls=await decoder.decodeFromVideoDevice(
      undefined,$('camera'),(result,_err,readerControls)=>{
        if(!camera.isCurrent(epoch)) { readerControls?.stop?.(); return; }
        if(!result) return;
        try {
          confirmSelectedAddress(result.getText());
          stopCamera();
          readerControls?.stop?.();
        } catch(err) {
          stopCamera();
          setStatus('拒絕 MetaMask 帳戶 QR：'+err.message);
        }
      }
    );
    if(!camera.attach(epoch,controls)) return;
    if(!confirmedAddress) setStatus('請顯示 MetaMask 目前所選帳戶的收款地址 QR。');
  } catch(err) {
    if(!camera.isCurrent(epoch)) return;
    stopCamera();
    throw err;
  }
}));
$('pair').addEventListener('click',()=>guarded(async()=>{
  if(!publicInfo) throw Error('尚無公開帳戶');
  if(active) throw Error('請先結束當前交易');
  const accountAtStart=publicInfo;
  if (await displayUr(makePairingUr(accountAtStart)) && publicInfo===accountAtStart) {
    setStatus('MetaMask → Connect Hardware Wallet → QR-based，掃描這個 crypto-hdkey 公開 QR。');
  }
}));
$('scan').addEventListener('click',()=>guarded(async()=>{
  if(!publicInfo || active || confirmedAddress!==validatePublic(publicInfo).address) {
    throw Error('先驗證 MetaMask 所選地址，並完成／取消目前交易');
  }
  // Never start a second camera session while the previous permission dialog
  // is still pending. Stop/Cancel invalidates callbacks from that dialog.
  const epoch=camera.begin();
  if(epoch===null) return;
  collected.splice(0);
  $('camera').hidden=false;
  $('stop').disabled=false;
  try {
    const controls=await decoder.decodeFromVideoDevice(undefined,$('camera'),(result,err,readerControls)=>{
      if(!camera.isCurrent(epoch)) { readerControls?.stop?.(); return; }
      if(!result) return;
      const piece=result.getText().trim();
      if(!piece.toLowerCase().startsWith('ur:eth-sign-request/')) return;
      if(!collected.includes(piece)) collected.push(piece);
      if(collected.length>MAX_FRAMES) { stopCamera();setStatus('QR 幀數超過上限');return; }
      try {
        acceptRequest(collected);
        readerControls?.stop?.();
      } catch(e) {
        if(!/UR frames incomplete/.test(e.message)) setStatus('掃描尚未成功：'+e.message);
      }
    });
    if(!camera.attach(epoch,controls)) return;
    setStatus('攝影機啟動，請掃描 MetaMask 的 eth-sign-request QR。');
  } catch(err) {
    // A canceled start may reject after a newer scan is active; do not
    // overwrite that session's UI or leave a live camera behind.
    if(!camera.isCurrent(epoch)) return;
    stopCamera();
    throw err;
  }
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
  const pendingRequest = active;
  const signed=JSON.parse(await boundedText($('signed-file').files?.[0]));
  // Cancel or account change during File.text() must invalidate the response.
  if (active !== pendingRequest || used) return;
  const response=makeSignedResponseUr(pendingRequest,signed);
  used=true;
  $('reply').disabled=true;$('download').disabled=true;
  if (await displayUr(response)) {
    setStatus('簽章符合本次 MetaMask request，可供 MetaMask「Get Signature」掃描。不代表已廣播或確認。');
  }
}));
$('cancel').addEventListener('click',()=>{
  clearSession();setStatus('已清除目前請求與 QR 動畫。若 MetaMask 尚在等待，請在 MetaMask 取消該交易。');
});
window.addEventListener('pagehide',()=>{publicImporter.cancel();stopCamera();qrDisplay.clear();});
