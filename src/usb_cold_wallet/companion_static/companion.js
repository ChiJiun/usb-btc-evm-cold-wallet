"use strict";
// Intentionally no storage, remote scripts, wallet-key inputs, or automatic broadcast.
const token = document.querySelector('meta[name="companion-token"]').content;
const $ = (id) => document.getElementById(id);
let pending = null;
let requestEnvelope = null;
let walletLoaded = false;

function message(text, failed=false) {
  const el = $("message");
  el.textContent = text;
  el.className = failed ? "message error" : "message";
}
async function api(path, body) {
  const opt = {cache:"no-store",headers:{"X-Companion-Token":token}};
  if (body !== undefined) {
    opt.method="POST";
    opt.headers["Content-Type"]="application/json";
    opt.body=JSON.stringify(body);
  }
  const response=await fetch(path,opt);
  const data=await response.json();
  if(!response.ok || data.error) throw new Error(data.error || "操作失敗");
  return data;
}
async function action(fn) {
  try { await fn(); }
  catch (err) {
    message(err.message || "操作失敗",true);
    // A timed-out broadcast has an ambiguous outcome; refresh the button states.
    try { renderWallet(await api("/api/wallet")); } catch (_) { /* preserve original error */ }
  }
}
function eth(wei) {
  const n=BigInt(wei);
  return (n / 1000000000000000000n).toString()+"."+((n%1000000000000000000n).toString().padStart(18,"0").replace(/0+$/,"") || "0");
}
function gwei(wei){return (BigInt(wei)/1000000000n).toString()+"."+((BigInt(wei)%1000000000n).toString().padStart(9,"0").replace(/0+$/,"")||"0");}
function saveJson(name, data) {
  const blob = new Blob([JSON.stringify(data,null,2)+"\n"],{type:"application/json"});
  const url=URL.createObjectURL(blob);
  const anchor=document.createElement("a");
  anchor.href=url;anchor.download=name;document.body.append(anchor);anchor.click();anchor.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function fileContents(inputId) {
  const file=$(inputId).files[0];
  if(!file) throw new Error("請先選擇檔案");
  if(file.size>200000) throw new Error("檔案過大（上限 200 KB）");
  return await file.text();
}
function renderWallet(data) {
  walletLoaded=!!data.loaded;
  $("refreshBtn").disabled=!walletLoaded;
  $("prepareBtn").disabled=!walletLoaded || !!data.pending;
  if(!walletLoaded) return;
  $("walletInfo").textContent="EVM（Sepolia）：\n"+data.evm_address+
    "\n\nRPC："+data.rpc+"\n\nBTC（Testnet）帳戶 tpub：\n"+data.btc_account_tpub+
    "\n\n※ Watch-only 匯入的 checksum 不證明資料來源，應與離線裝置核對地址。";
  const list=$("btcList");list.replaceChildren();
  data.btc_addresses.forEach((addr,index)=>{
    const div=document.createElement("div");div.className="address";
    div.textContent="Receive #"+index+": "+addr;list.append(div);
  });
  if(data.pending) renderPending(data.pending);
}
function renderPending(p) {
  pending=p;
  $("prepareBtn").disabled=!walletLoaded || !!p;
  $("cancelBtn").disabled=!p;
  const prepared=p && p.stage==="prepared";
  $("downloadBtn").disabled=!prepared;
  $("legacyBtn").disabled=!prepared;
  $("verifyBtn").disabled=!prepared;
  $("broadcastBtn").disabled=!(p && p.stage==="verified");
  $("statusBtn").disabled=!(p && p.tx_hash);
  if(!p) {
    $("pending").textContent="尚無交易";
    $("verification").textContent="尚未驗證簽章";
    $("status").textContent="尚無鏈上交易";
    return;
  }
  const tx=p.tx;
  const maxFee=BigInt(tx.gas)*BigInt(tx.maxFeePerGas);
  $("pending").textContent="交易編號（本機 Session）："+p.request_id+
    "\nNetwork：Sepolia (11155111)"+
    "\n收款地址："+tx.to+"\n金額："+eth(tx.value)+" ETH"+
    "\nNonce："+tx.nonce+"\nGas Limit："+tx.gas+
    "\n最高 Gas 單價："+gwei(tx.maxFeePerGas)+" Gwei"+
    "\n最高網路費用："+eth(maxFee)+" ETH"+
    "\n最高總支出："+eth(BigInt(tx.value)+maxFee)+" ETH"+
    "\nRequest SHA-256："+p.digest+
    "\n\n原始待簽欄位：\n"+JSON.stringify(tx,null,2);
  $("verification").textContent=p.tx_hash?
    "簽章已與原始請求逐欄比對成功。\nTx Hash: "+p.tx_hash+
    "\n這不代表交易已上鏈，仍需使用者點擊廣播。":
    "等待使用者在離線電腦核對、簽名並匯入結果。";
  $("status").textContent=p.result?
    "RPC 回報狀態："+p.result+"\nTx Hash："+(p.tx_hash||"")+
    (p.block_number!==null && p.block_number!==undefined?"\n區塊高度："+p.block_number:"")+
    (p.reorg_warning?"\n⚠ 曾觀察到疑似鏈重組；請重新檢查交易確認數。":"") :
    (p.stage==="broadcast_unknown"?"廣播回應不明：請先查詢狀態，不要盲目重新送出。" :
      p.stage==="broadcasted"?"已提交 RPC，尚未確認。請查詢鏈上狀態。":"尚未廣播");
}
$("importBtn").addEventListener("click",()=>action(async()=>{
  const data=await api("/api/import",{raw:await fileContents("watchFile")});
  renderWallet(data);
  message("公開帳戶已載入。請獨立核對所匯入的完整地址。");
}));
$("refreshBtn").addEventListener("click",()=>action(async()=>{
  const data=await api("/api/overview");
  $("overview").textContent="地址："+data.address+
    "\nRPC："+data.rpc+"\n餘額："+eth(data.balance_wei)+" ETH"+
    "\n待處理 Nonce："+data.pending_nonce+
    "\n建議 Max Fee："+data.suggested_max_fee_gwei+" Gwei"+
    "\n建議 Priority Fee："+data.suggested_priority_fee_gwei+" Gwei";
  message("已讀取最新 Sepolia RPC 資訊；請注意 RPC 報價可能不準確。");
}));
$("sendForm").addEventListener("submit",(event)=>{
  event.preventDefault();
  action(async()=>{
    const data=await api("/api/prepare",{
      recipient:$("recipient").value.trim(),
      amount_eth:$("amount").value.trim(),
      max_fee_gwei:$("maxFee").value.trim()
    });
    requestEnvelope=data.envelope;
    renderPending(data.pending);
    message("已建立未簽章交易；請確認摘要後下載交換檔。");
  });
});
$("downloadBtn").addEventListener("click",()=>action(async()=>{
  if(!pending || pending.stage!=="prepared")throw new Error("沒有待簽請求");
  if(!requestEnvelope)requestEnvelope=await api("/api/request");
  saveJson("sepolia-unsigned-"+pending.request_id+".json",requestEnvelope);
  message("已下載完整性檢查的交換封裝，適用 #5 離線 signer。");
}));
$("legacyBtn").addEventListener("click",()=>action(async()=>{
  if(!pending || pending.stage!=="prepared")throw new Error("沒有待簽請求");
  saveJson("sepolia-legacy-"+pending.request_id+".json",pending.tx);
  message("已下載舊版 JSON。請在 main 版離線 signer 使用 --tx；此檔不包含封裝完整性雜湊。");
}));
$("verifyBtn").addEventListener("click",()=>action(async()=>{
  const result=await api("/api/accept",{raw:await fileContents("signedFile")});
  renderPending(result);
  message("簽章回傳已通過原始 raw tx 欄位和 signer 地址核對；尚未廣播。");
}));
$("broadcastBtn").addEventListener("click",()=>action(async()=>{
  if(!pending || pending.stage!=="verified")throw new Error("尚未完成簽章驗證");
  if(!window.confirm("確定將這筆已驗證的 Sepolia 測試交易廣播？\n\n收款人："+pending.tx.to+
      "\n金額："+eth(pending.tx.value)+" ETH\n最高 Gas："+gwei(pending.tx.maxFeePerGas)+" Gwei")) return;
  const result=await api("/api/broadcast",{});
  renderPending(result);
  message("已提交 Sepolia RPC。請查詢 Tx Hash 的鏈上確認狀態。");
}));
$("statusBtn").addEventListener("click",()=>action(async()=>{
  renderPending(await api("/api/status",{}));
  message("已更新鏈上回報。未找到交易不等於確定未曾被 RPC 接受。");
}));
$("cancelBtn").addEventListener("click",()=>action(async()=>{
  if(!window.confirm("清除本機待簽請求？已廣播或可能廣播的交易無法藉此撤回。"))return;
  await api("/api/cancel",{});
  requestEnvelope=null;
  pending=null;
  renderPending(null);
  $("prepareBtn").disabled=!walletLoaded;
  message("已清除本機 Session。鏈上交易不會被撤回。");
}));
action(async()=>{const data=await api("/api/wallet");renderWallet(data);});
