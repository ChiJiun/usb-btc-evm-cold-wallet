import { KeyringSnapRpcClient } from '@metamask/keyring-snap-client';

const SNAP_ID = 'local:http://localhost:8082';
const REQUIRED_CHAIN = 11155111n;
const MAX_FILE_BYTES = 150_000;
const $ = (id) => document.getElementById(id);
const status = (message) => { $('status').textContent = message; };
let client = null;
let pending = [];
let accounts = [];
let terminalEvents = [];
let accountEvents = [];
async function snapRecovery(method, params = undefined) {
  return provider().request({method:'wallet_invokeSnap', params:{
    snapId:SNAP_ID, request:{method, ...(params ? {params} : {})},
  }});
}
const provider = () => {
  if (!window.ethereum?.request) throw Error('未偵測到 MetaMask provider，請使用 MetaMask 的開發／Flask 版本。');
  return window.ethereum;
};
async function guarded(fn) {
  try { await fn(); } catch(err) { status('錯誤：' + (err instanceof Error ? err.message : String(err))); }
}
function requireClient() {
  if (!client) throw Error('請先安裝 Snap 並連線。');
  return client;
}
function selected() {
  const id = $('requests').value;
  const item = pending.find((v)=>v.id === id);
  if (!item) throw Error('請選擇一筆待簽請求。');
  return item;
}
async function refresh() {
  accounts = await requireClient().listAccounts();
  pending = await requireClient().listRequests();
  terminalEvents = await snapRecovery('usb_listTerminalEvents');
  accountEvents = await snapRecovery('usb_listAccountEvents');
  if (!Array.isArray(terminalEvents) || !Array.isArray(accountEvents)) throw Error('Snap 未回傳合法的恢復狀態');
  $('account-terminal').replaceChildren();
  for (const item of accountEvents) {
    const option = document.createElement('option');
    option.value = item.id;
    option.textContent = item.kind + ' · ' + item.id +
      (item.attempted ? '（通知結果可能已送達）' : '（尚未嘗試通知）');
    $('account-terminal').appendChild(option);
  }
  $('terminal').replaceChildren();
  for (const item of terminalEvents) {
    const option = document.createElement('option');
    option.value = item.id;
    option.textContent = item.id + ' · ' + item.kind +
      (item.attempted ? '（通知結果可能已送達）' : '（尚未嘗試通知）');
    $('terminal').appendChild(option);
  }
  $('accounts').textContent = accounts.length ? accounts.map((a)=>a.address + '  [' + a.id + ']').join('\n') : '尚無 USB 冷錢包帳戶';
  $('requests').replaceChildren();
  for (const p of pending) {
    const option = document.createElement('option');
    option.value = p.id;
    const account = accounts.find((a)=>a.id === p.account);
    option.textContent = p.id + ' · ' + (account?.address || p.account);
    $('requests').appendChild(option);
  }
  showRequest();
}
function showRequest() {
  const item = pending.find((v)=>v.id === $('requests').value);
  const tx = item?.request?.params?.[0];
  $('details').textContent = tx ? [
    'NETWORK: SEPOLIA only (chainId 11155111)',
    'Request ID: ' + item.id,
    'From: ' + tx.from, 'To: ' + tx.to,
    'Value (wei): ' + BigInt(tx.value).toString(10),
    'Nonce: ' + BigInt(tx.nonce).toString(10),
    'Gas: ' + BigInt(tx.gasLimit ?? tx.gas).toString(10),
    'Max fee per gas: ' + BigInt(tx.maxFeePerGas).toString(10),
    'Priority fee per gas: ' + BigInt(tx.maxPriorityFeePerGas).toString(10),
    'Data: ' + (tx.data || '0x'),
  ].join('\n') : '目前沒有待簽請求';
}
async function assertLiveIntent(item) {
  const rpc = provider();
  const chainId = await rpc.request({method:'eth_chainId'});
  if (BigInt(chainId) !== REQUIRED_CHAIN) throw Error('MetaMask 已切換鏈，請取消本筆並重新建立。');
  const account = accounts.find((a)=>a.id === item.account);
  if (!account) throw Error('MetaMask 冷錢包帳戶已切換或刪除。');
  const selectedAccounts = await rpc.request({method:'eth_accounts'});
  if (!Array.isArray(selectedAccounts) || !selectedAccounts.some((a)=>a.toLowerCase() === account.address.toLowerCase())) {
    throw Error('目前 dApp 未被授權使用此冷錢包帳戶，或 MetaMask 已切換選取帳戶。');
  }
  const tx = item.request?.params?.[0];
  if (!tx || account.address.toLowerCase() !== tx.from?.toLowerCase()) throw Error('請求來源帳戶已變更。');
  const nonce = await rpc.request({method:'eth_getTransactionCount',params:[account.address,'pending']});
  if (BigInt(nonce) !== BigInt(tx.nonce)) {
    throw Error('Nonce 已過期或 RPC 回應異常；不要重送或自動加價，請在鏈上檢查後重新發起。');
  }
  // RPC may be untrusted; Snap still independently validates the signed transaction.
}
function download(filename,content) {
  if (!/^cold-sepolia-request-[0-9a-f]{32}\.json$/.test(filename)) {
    throw Error('不合法的下載檔名');
  }
  const file = new Blob([content],{type:'application/json'});
  const url = URL.createObjectURL(file);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.hidden = true;
  document.body.appendChild(anchor);
  try {
    anchor.click();
  } finally {
    anchor.remove();
    // Keep the Blob alive until the browser has started the download.
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }
}
$('connect').addEventListener('click',()=>guarded(async()=>{
  const rpc=provider();
  await rpc.request({method:'wallet_requestSnaps',params:{[SNAP_ID]:{version:'0.1.0'}}});
  client = new KeyringSnapRpcClient(SNAP_ID,rpc);
  await refresh();
  status('已連線至本機 Snap；目前僅支援 Sepolia 原生 ETH。');
}));
$('permit').addEventListener('click',()=>guarded(async()=>{
  await provider().request({method:'eth_requestAccounts'});
  status('已送出帳戶授權請求。請在 MetaMask 內選擇 USB Cold 帳戶。');
}));
$('import').addEventListener('click',()=>guarded(async()=>{
  const address=$('address').value.trim();
  if(!/^0x[0-9a-fA-F]{40}$/.test(address)) throw Error('請輸入正確的公開地址，不可輸入助記詞或私鑰');
  const account=await requireClient().createAccount({address});
  await refresh(); status('已新增獨立冷錢包帳戶：'+account.address);
  $('address').value='';
}));
$('refresh').addEventListener('click',()=>guarded(async()=>{await refresh();status('已更新待簽請求。');}));
$('requests').addEventListener('change',()=>guarded(async()=>showRequest()));
$('export').addEventListener('click',()=>guarded(async()=>{
  const item=selected();
  await assertLiveIntent(item);
  const qr=await provider().request({method:'wallet_invokeSnap',params:{
    snapId:SNAP_ID,request:{method:'usb_getQrRequest',params:{id:item.id}},
  }});
  if(typeof qr!=='string' || qr.length>MAX_FILE_BYTES) throw Error('不合法的 QR request');
  const requestId = JSON.parse(qr).request_id; // ID only; never parse Wei here.
  if (typeof requestId !== 'string' || !/^[0-9a-f]{32}$/.test(requestId)) {
    throw Error('不合法的 QR request ID');
  }
  download('cold-sepolia-request-'+requestId+'.json',qr);
  status('請用 #18 QR transport 顯示此請求，在離線裝置獨立驗證交易後簽署。');
}));
$('approve').addEventListener('click',()=>guarded(async()=>{
  const item=selected();
  const file=$('response').files?.[0];
  if(!file || file.size>MAX_FILE_BYTES) throw Error('請選擇小於 150 KB 的 signed QR response');
  await assertLiveIntent(item);
  const responseJson=await file.text();
  if(responseJson.length>MAX_FILE_BYTES) throw Error('回覆超出上限');
  await requireClient().approveRequest(item.id,{responseJson});
  $('response').value='';
  await refresh();
  status('已交由 MetaMask 處理已驗證簽章。請在 MetaMask 確認廣播狀態；不自動重試。');
}));
$('reject').addEventListener('click',()=>guarded(async()=>{
  const item=selected();
  await requireClient().rejectRequest(item.id);
  await refresh();status('已拒絕此請求；同一 Request ID 不可重播。');
}));

$('retry-account').addEventListener('click',()=>guarded(async()=>{
  if (!accountEvents.length) throw Error('沒有待恢復帳戶通知');
  if (!window.confirm('重送原本的帳戶事件？若已成功送達，MetaMask 可能收到重複事件。')) return;
  await snapRecovery('usb_recoverAccountEvent',{action:'retry'});
  await refresh(); status('已重送帳戶通知，請檢查 MetaMask 帳戶列表。');
}));
$('abandon-account').addEventListener('click',()=>guarded(async()=>{
  if (!accountEvents.length) throw Error('沒有待恢復帳戶通知');
  if (!window.confirm('請先確認 MetaMask 帳戶列表與 Snap 已儲存的帳戶狀態一致。確定要放棄原本通知？')) return;
  await snapRecovery('usb_recoverAccountEvent',{action:'abandon'});
  await refresh(); status('已清除帳戶通知狀態。');
}));
$('retry-terminal').addEventListener('click',()=>guarded(async()=>{
  const item = terminalEvents.find((event)=>event.id === $('terminal').value);
  if(!item) throw Error('沒有待恢復事件');
  if (!window.confirm('重新通知 MetaMask 相同的已驗證結果？如果先前送達但保存失敗，MetaMask 可能收到重複通知。')) return;
  await snapRecovery('usb_recoverTerminalEvent',{id:item.id,action:'retry'});
  await refresh();
  status('已嘗試重送原本的事件。請在 MetaMask 確認結果，不會建立新簽章。');
}));
$('abandon-terminal').addEventListener('click',()=>guarded(async()=>{
  const item = terminalEvents.find((event)=>event.id === $('terminal').value);
  if(!item) throw Error('沒有待恢復事件');
  if (!window.confirm('請先確認 MetaMask 已完成或取消該筆請求。確定要清除 Snap 內保留的通知狀態？此操作不會傳送交易或簽章。')) return;
  await snapRecovery('usb_recoverTerminalEvent',{id:item.id,action:'abandon'});
  await refresh();
  status('已清除該筆不確定通知狀態。原請求 ID 仍保留重播保護。');
}));
