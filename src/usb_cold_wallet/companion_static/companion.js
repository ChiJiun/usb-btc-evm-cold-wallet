"use strict";
// Intentionally no storage, remote scripts, wallet-key inputs, or automatic broadcast.
const token = document.querySelector('meta[name="companion-token"]').content;
const $ = (id) => document.getElementById(id);
let pending = null;
let walletLoaded = false;
let importedEvmAddress="", importedBtcAddress="";
let evmConfirmedKey=null, btcConfirmedKey=null;
let latestEvmBalance=null, latestBtcBalance=null;
function requestKey(p){return p?p.request_id+":"+p.digest:null;}
function amountAtoms(value,scale,label){
  if(typeof value!=="string" || !/^(?:0|[1-9][0-9]{0,20})(?:\.[0-9]+)?$/.test(value))throw new Error(label+"必須是一般十進位正數");
  const [whole,fraction=""]=value.split(".");
  if(fraction.length>scale)throw new Error(label+"最多 "+scale+" 位小數");
  const n=BigInt(whole)*10n**BigInt(scale)+BigInt(fraction.padEnd(scale,"0")||"0");
  if(n<=0n)throw new Error(label+"必須大於零");
  return n;
}
function statusMeaning(stage,result){
  if(result==="confirmed")return "已確認（可能發生鏈重組）";
  if(result==="reverted")return "失敗（已上鏈，可能仍有網路費用）";
  if(result==="reorg_suspected")return "疑似鏈重組";
  if(result==="pending")return "等待鏈上確認";
  if(result==="not_found")return "尚未找到（不代表未廣播）";
  if(stage==="broadcast_unknown")return "廣播結果不明，禁止重送";
  if(stage==="broadcasted")return "已送出，待確認";
  if(stage==="verified")return "離線簽章已驗證，等待手動廣播";
  if(stage==="prepared")return "等待離線人工確認";
  return "尚無交易";
}
function switchAsset(asset){
  const btc=asset==="btc";
  $("evmFlow").hidden=btc;$("btcFlow").hidden=!btc;
  for(const [id,on] of [["evmTab",!btc],["btcTab",btc]]){
    $(id).classList.toggle("active",on);
    $(id).setAttribute("aria-pressed",String(on));
  }
}
$("evmTab").addEventListener("click",()=>switchAsset("evm"));
$("btcTab").addEventListener("click",()=>switchAsset("btc"));
async function copyPublicAddress(address){
  if(!address||!navigator.clipboard?.writeText)throw new Error("剪貼簿不可用，請手動複製公開地址");
  await navigator.clipboard.writeText(address);
  message("已複製收款地址；收款前應與離線裝置核對。");
}
$("evmCopyBtn").addEventListener("click",()=>action(()=>copyPublicAddress(importedEvmAddress)));
$("btcCopyBtn").addEventListener("click",()=>action(()=>copyPublicAddress(importedBtcAddress)));

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
async function rawUnsigned(path) {
  const response = await fetch(path, {cache:"no-store",headers:{"X-Companion-Token":token}});
  if (!response.ok) throw new Error("無法從本機取得未經數字轉換的完整交易 JSON");
  const raw = await response.text();
  if (raw.length > 200000) throw new Error("交換檔超出安全尺寸");
  return raw;
}
function saveRaw(name, raw) {
  // Never pass Wei-bearing data through JSON.parse/JSON.stringify (JS Number).
  const blob = new Blob([raw], {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
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
  if(!walletLoaded){importedEvmAddress="";importedBtcAddress="";$("evmCopyBtn").disabled=true;$("btcCopyBtn").disabled=true;renderPending(null);return;}
  importedEvmAddress=data.evm_address;
  importedBtcAddress=data.btc_addresses[0]||"";
  $("evmCopyBtn").disabled=!importedEvmAddress;
  $("btcCopyBtn").disabled=!importedBtcAddress;
  $("walletInfo").textContent="EVM（Sepolia）：\n"+data.evm_address+
    "\n\nRPC："+data.rpc+"\n\nBTC（Testnet）帳戶 tpub：\n"+data.btc_account_tpub+
    "\n\n※ Watch-only 匯入的 checksum 不證明資料來源，應與離線裝置核對地址。";
  const list=$("btcList");list.replaceChildren();
  data.btc_addresses.forEach((addr,index)=>{
    const div=document.createElement("div");div.className="address";
    div.textContent="Receive #"+index+": "+addr;list.append(div);
  });
  renderPending(data.pending||null);
}
function renderPending(p) {
  pending=p;
  $("prepareBtn").disabled=!walletLoaded || !!p;
  $("cancelBtn").disabled=!p;
  const prepared=p && p.stage==="prepared";
  const confirmed=prepared&&evmConfirmedKey===requestKey(p);
  $("evmReview").hidden=!prepared||confirmed;
  $("evmAcknowledge").checked=confirmed;
  $("confirmRequestBtn").disabled=!prepared||confirmed;
  $("downloadBtn").disabled=!confirmed;
  $("legacyBtn").disabled=!confirmed;
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
  $("pending").textContent="目前狀態："+statusMeaning(p.stage,p.result)+
    "\n交易編號（本機 Session）："+p.request_id+
    "\nNetwork：Sepolia (11155111)"+
    "\n收款地址："+tx.to+"\n金額："+eth(tx.value)+" ETH"+
    "\nNonce："+tx.nonce+"\nGas Limit："+tx.gas+
    "\n最高 Gas 單價："+gwei(tx.maxFeePerGas)+" Gwei"+
    "\n最高網路費用："+eth(maxFee)+" ETH"+
    "\n最高總支出："+eth(BigInt(tx.value)+maxFee)+" ETH"+
    "\nRequest SHA-256："+p.digest+
    "\n\n原始待簽欄位：\n"+JSON.stringify(tx,null,2);
  $("evmRecovery").textContent=(p.stage==="broadcast_unknown"||p.result==="not_found"||p.reorg_warning)?
    "回覆不明：只能查詢，禁止自動重送。程式重啟後 Session 會消失，請保留 Tx Hash 從可信來源確認。":
    "廣播需手動確認；清除 Session 不會撤回已送出的交易。";
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
  await refreshBtc();
  message("公開帳戶已載入。請獨立核對所匯入的完整地址。");
}));
$("refreshBtn").addEventListener("click",()=>action(async()=>{
  latestEvmBalance=null;
  $("overview").textContent="正在查詢 Sepolia；先前的餘額已作廢。";
  const data=await api("/api/overview");
  if(data.chain_id!==11155111||data.address!==importedEvmAddress)throw new Error("RPC 鏈別或帳戶與匯入資料不一致");
  latestEvmBalance=BigInt(data.balance_wei);
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
    const atoms=amountAtoms($("amount").value.trim(),18,"ETH 金額");
    if(latestEvmBalance!==null&&atoms>latestEvmBalance)throw new Error("ETH 金額超過估計餘額（未計入網路費用）");
    const data=await api("/api/prepare",{
      recipient:$("recipient").value.trim(),
      amount_eth:$("amount").value.trim(),
      max_fee_gwei:$("maxFee").value.trim()
    });
    evmConfirmedKey=null;
    renderPending(data.pending);
    $("evmAcknowledge").checked=false;
    $("confirmRequestBtn").disabled=true;
    message("請檢查收款地址、金額及最高費用，確認後開放下載交換檔。");
  });
});
$("downloadBtn").addEventListener("click",()=>action(async()=>{
  if(!pending||pending.stage!=="prepared"||evmConfirmedKey!==requestKey(pending))throw new Error("請先核對並確認待簽交易");
  saveRaw("sepolia-unsigned-"+pending.request_id+".json",await rawUnsigned("/api/request-raw"));
  message("已下載完整性檢查的交換封裝，適用 #5 離線 signer。");
}));
$("legacyBtn").addEventListener("click",()=>action(async()=>{
  if(!pending || pending.stage!=="prepared")throw new Error("沒有待簽請求");
  saveRaw("sepolia-legacy-"+pending.request_id+".json",await rawUnsigned("/api/request-legacy"));
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
  pending=null;
  evmConfirmedKey=null;
  renderPending(null);
  $("prepareBtn").disabled=!walletLoaded;
  message("已清除本機 Session。鏈上交易不會被撤回。");
}));
action(async()=>{const data=await api("/api/wallet");renderWallet(data);if(data.loaded)await refreshBtc();});

let btcPending=null;
let btcExchange=null;
let btcReady=false;

function btcSats(n) {
  const value=BigInt(n);
  const whole=value/100000000n;
  const fraction=(value%100000000n).toString().padStart(8,"0");
  return whole+"."+fraction+" BTC";
}
function renderBtc(p) {
  btcPending=p;
  const prepared=!!p && p.stage==="prepared";
  $("btcPrepareBtn").disabled=!btcReady || !!p;
  $("btcRefreshBtn").disabled=!walletLoaded;
  const confirmed=prepared&&btcConfirmedKey===requestKey(p);
  $("btcReview").hidden=!prepared||confirmed;
  $("btcAcknowledge").checked=confirmed;
  $("btcConfirmRequestBtn").disabled=!prepared||confirmed;
  $("btcDownloadBtn").disabled=!confirmed;
  $("btcLegacyBtn").disabled=!confirmed;
  $("btcVerifyBtn").disabled=!prepared;
  $("btcBroadcastBtn").disabled=!(p && p.stage==="verified");
  $("btcStatusBtn").disabled=!(p && p.txid);
  $("btcCancelBtn").disabled=!p;
  if(!p){
    $("btcPending").textContent="尚無待簽 BTC 交易";
    $("btcStatus").textContent="尚未廣播";
    return;
  }
  $("btcPending").textContent="目前狀態："+statusMeaning(p.stage,p.result)+"\nNetwork：Bitcoin Testnet"+
    "\n收款人："+p.recipient+
    "\n金額："+btcSats(p.amount_sats)+
    "\n預估總手續費："+p.fee_sats+" sats"+
    "\n費率估計："+p.fee_rate+" sat/vB"+
    "\n找零："+btcSats(p.change_sats)+
    "\n找零索引："+(p.change_index===null?"無":p.change_index)+
    "\n輸入 UTXO 數："+p.input_count+
    "\nPSBT SHA-256："+p.digest+
    "\n請在離線 signer 獨立核對完整地址、金額、費用及找零。"+
    (p.txid?"\n\n驗證後交易 ID："+p.txid:"");
  $("btcRecovery").textContent=(p.stage==="broadcast_unknown"||p.result==="not_found"||p.reorg_warning)?
    "BTC 結果不明：只能查詢，不得自動重送。程式重啟會失去 Session，請保留 TxID。":
    "每次廣播都要手動確認，離線裝置須獨立核對 UTXO、收款人與找零。";
  $("btcStatus").textContent=(p.result?"RPC 回報狀態："+p.result:"狀態："+p.stage)+
    (p.txid?"\nTxID："+p.txid:"")+
    (p.reorg_warning?"\n⚠ 偵測到疑似重組，請重新確認區塊狀態":"");
}
async function refreshBtc(){
  if(!walletLoaded)return;
  const wallet=await api("/api/btc/wallet");
  btcReady=wallet.spending_ready;
  $("btcWalletStatus").textContent=
    "Bitcoin Testnet Esplora："+wallet.endpoint+
    (btcReady?"\n✓ 已有公開 master fingerprint，可建立測試網 PSBT。":
      "\n⚠ 舊版公開帳戶缺少 master fingerprint，請在更新的離線 Signer 重新匯出。")+
    "\n公開資料/網路回覆仍不代表真實鏈上狀態。";
  renderBtc(wallet.pending);
}
$("btcRefreshBtn").addEventListener("click",()=>action(async()=>{
  const data=await api("/api/btc/overview");
  if(data.network!=="Bitcoin testnet")throw new Error("Bitcoin 網路與帳戶不一致");
  latestBtcBalance=BigInt(data.confirmed_sats);
  $("btcOverview").textContent=
    "Network："+data.network+"\nEndpoint："+data.endpoint+
    "\n已確認餘額："+btcSats(data.confirmed_sats)+
    "\n已確認 UTXO："+data.confirmed_utxo_count+
    "\n建議費率："+data.fee_rate_sat_vb+" sat/vB"+
    "\n掃描接收地址："+data.scan_receive_addresses+
    "\n掃描找零地址："+data.scan_change_addresses+
    "\n⚠ 掃描範圍有限，僅視為網路端估計；需要離線核對。";
  message("BTC Testnet 資料已更新。");
}));
$("btcSendForm").addEventListener("submit",(event)=>{
  event.preventDefault();
  action(async()=>{
    const feeText=$("btcMaxFee").value.trim();
    const rateText=$("btcRate").value.trim();
    if(!/^[0-9]{1,6}$/.test(feeText) || (rateText!=="" && !/^[0-9]{1,3}$/.test(rateText)))
      throw new Error("BTC 費率與最大手續費必須是有限正整數");
    const atoms=amountAtoms($("btcAmount").value.trim(),8,"BTC 金額");
    if(latestBtcBalance!==null&&atoms>latestBtcBalance)throw new Error("BTC 金額超過估計餘額（未計入費用）");
    const data=await api("/api/btc/prepare",{
      recipient:$("btcRecipient").value.trim(),
      amount_btc:$("btcAmount").value.trim(),
      max_fee_sats:Number(feeText),
      fee_rate_sat_vb:rateText===""?null:Number(rateText)
    });
    btcExchange=data.envelope;
    btcConfirmedKey=null;
    renderBtc(data.pending);
    $("btcAcknowledge").checked=false;
    $("btcConfirmRequestBtn").disabled=true;
    message("已建立 BTC Testnet PSBT，請下載後在離線 Signer 上逐項核對。");
  });
});
$("btcDownloadBtn").addEventListener("click",()=>action(async()=>{
  if(!btcPending||btcPending.stage!=="prepared"||btcConfirmedKey!==requestKey(btcPending))throw new Error("請先核對並確認 BTC PSBT");
  if(!btcExchange)btcExchange=await api("/api/btc/request");
  saveJson("bitcoin-testnet-unsigned-"+btcPending.request_id+".json",btcExchange);
  message("已下載 BTC PSBT 交換封裝，請使用純資料 USB-B 傳輸。");
}));
$("btcLegacyBtn").addEventListener("click",()=>action(async()=>{
  if(!btcPending || btcPending.stage!=="prepared")throw new Error("目前沒有待簽 BTC PSBT");
  const psbtText=await api("/api/btc/request-plain");
  const blob=new Blob([psbtText+"\n"],{type:"text/plain"});
  const url=URL.createObjectURL(blob);
  const anchor=document.createElement("a");
  anchor.href=url;
  anchor.download="bitcoin-testnet-legacy-"+btcPending.request_id+".psbt";
  document.body.append(anchor);anchor.click();anchor.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  message("已下載舊版 PSBT，適用 --psbt 路徑；請離線核對完整交易。");
}));
$("btcVerifyBtn").addEventListener("click",()=>action(async()=>{
  const result=await api("/api/btc/accept",{raw:await fileContents("btcSignedFile")});
  renderBtc(result);
  message("BTC 簽署 PSBT 已通過原始請求與密碼學簽章驗證，尚未廣播。");
}));
$("btcBroadcastBtn").addEventListener("click",()=>action(async()=>{
  if(!btcPending || btcPending.stage!=="verified")throw new Error("尚未完成離線簽章驗證");
  if(!window.confirm("確定廣播 Bitcoin Testnet 測試交易？\n收款人："+btcPending.recipient+
      "\n金額："+btcSats(btcPending.amount_sats)+"\n總手續費："+btcPending.fee_sats+" sats"))return;
  renderBtc(await api("/api/btc/broadcast",{}));
  message("BTC 測試交易已送往 Esplora。請查詢 TxID 狀態，勿自動重送。");
}));
$("btcStatusBtn").addEventListener("click",()=>action(async()=>{
  renderBtc(await api("/api/btc/status",{}));
  message("BTC 測試網狀態已更新；未找到不等於交易未曾被網路接受。");
}));
$("btcCancelBtn").addEventListener("click",()=>action(async()=>{
  if(!window.confirm("清除本機 BTC 交易？這無法撤銷已廣播的交易。"))return;
  await api("/api/btc/cancel",{});
  btcExchange=null;
  btcConfirmedKey=null;
  renderBtc(null);
  message("已清除本機 BTC 工作階段。");
}));

$("evmAcknowledge").addEventListener("change",()=>{
  $("confirmRequestBtn").disabled=!pending||pending.stage!=="prepared"||!$("evmAcknowledge").checked;
});
$("confirmRequestBtn").addEventListener("click",()=>{
  if(!pending||pending.stage!=="prepared"||!$("evmAcknowledge").checked)return;
  evmConfirmedKey=requestKey(pending);
  renderPending(pending);
  message("已核對 Sepolia 交易。離線裝置仍必須獨立審核。");
});
$("btcAcknowledge").addEventListener("change",()=>{
  $("btcConfirmRequestBtn").disabled=!btcPending||btcPending.stage!=="prepared"||!$("btcAcknowledge").checked;
});
$("btcConfirmRequestBtn").addEventListener("click",()=>{
  if(!btcPending||btcPending.stage!=="prepared"||!$("btcAcknowledge").checked)return;
  btcConfirmedKey=requestKey(btcPending);
  renderBtc(btcPending);
  message("已核對 BTC 交易。離線裝置仍必須獨立審核。");
});

$("lookupForm").addEventListener("submit",(event)=>{
  event.preventDefault();
  action(async()=>{
    const asset=$("lookupAsset").value;
    const txid=$("lookupHash").value.trim();
    const valid=asset==="sepolia"?/^0x[0-9a-fA-F]{64}$/.test(txid):
      asset==="bitcoin-testnet"&&/^[0-9a-fA-F]{64}$/.test(txid);
    if(!valid)throw new Error("請輸入與測試網相符的完整 Tx Hash／TXID");
    $("lookupResult").textContent="正在唯讀查詢；結果僅供交叉確認。";
    try{
      const result=await api("/api/lookup",{asset,txid});
      if(result.asset!==asset||result.txid.toLowerCase()!==txid.toLowerCase()||result.untrusted_rpc!==true)
        throw new Error("RPC 查詢結果未通過鏈別／交易識別驗證");
      $("lookupResult").textContent="測試網："+result.asset+
        "\n交易："+result.txid+"\n狀態："+statusMeaning(null,result.result)+
        "\n來源：不可信 RPC／Explorer。此查詢不會允許重播、簽署或廣播。";
      message("已完成唯讀狀態查詢，未送出任何交易。");
    }catch(err){
      $("lookupResult").textContent="查詢失敗或結果不明；不可推論交易未廣播。";
      throw err;
    }
  });
});
