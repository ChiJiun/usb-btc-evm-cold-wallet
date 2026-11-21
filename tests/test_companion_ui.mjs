/** Browser-style interaction tests without remote assets or browser storage. */
import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const source=readFileSync(new URL("../src/usb_cold_wallet/companion_static/companion.js",import.meta.url),"utf8");
const ADDRESS="0x000000000000000000000000000000000000dEaD";
const BTC_ADDRESS="tb1qtestreceivingaddress";
const wallet={loaded:true,evm_address:ADDRESS,btc_addresses:[BTC_ADDRESS],btc_account_tpub:"tpub-public-test",rpc:"https://mock.invalid",pending:null};
const makePending=()=>({stage:"prepared",request_id:"request-01",digest:"a".repeat(64),tx:{
  to:ADDRESS,value:"123456789012345678",gas:21000,maxFeePerGas:"2000000000",
  nonce:7,maxPriorityFeePerGas:"1000000000",chainId:11155111,type:2,data:"0x"}});
const makeBtc=()=>({stage:"prepared",request_id:"btc-01",digest:"b".repeat(64),recipient:BTC_ADDRESS,
  amount_sats:120001,fee_sats:432,fee_rate:2,change_sats:3000,change_index:0,input_count:1});
function harness(){
  const elements=new Map(),calls=[],blobs=[];
  let evmPending=null,btcPending=null,failOverview=false,failBroadcast=false;
  function element(id){
    if(elements.has(id))return elements.get(id);
    const listeners=new Map();
    const e={id,disabled:false,hidden:false,checked:false,value:"",files:[],textContent:"",className:"",
      classList:{toggle(){}},setAttribute(){},replaceChildren(){},append(){},remove(){},click(){},
      addEventListener(name,handler){listeners.set(name,handler)},
      dispatch(name){const f=listeners.get(name);if(!f)throw Error("No "+name+" listener on "+id);return f({preventDefault(){}});}
    };
    elements.set(id,e);return e;
  }
  const document={
    querySelector(){return {content:"public-test-token"}},
    getElementById:element,
    createElement:()=>element("anchor-"+Math.random()),
    body:{append(){}},
  };
  async function fetch(path,options={}){
    calls.push({path,method:options.method||"GET",body:options.body});
    const payload=options.body?JSON.parse(options.body):{};
    let data={},status=200;
    if(path==="/api/wallet")data={...wallet,pending:evmPending};
    else if(path==="/api/btc/wallet")data={network:"Bitcoin testnet",endpoint:"https://mock.invalid",spending_ready:true,pending:btcPending};
    else if(path==="/api/overview"){
      if(failOverview){data={error:"RPC timed out"};status=400;}
      else data={chain_id:11155111,address:ADDRESS,balance_wei:"999999999999999999",pending_nonce:7,local:true,
        suggested_max_fee_gwei:"2",suggested_priority_fee_gwei:"1",rpc:"https://mock.invalid"};
    }
    else if(path==="/api/btc/overview")data={network:"Bitcoin testnet",endpoint:"https://mock.invalid",
      confirmed_sats:500000,confirmed_utxo_count:1,fee_rate_sat_vb:2,scan_receive_addresses:1,scan_change_addresses:20};
    else if(path==="/api/prepare"){evmPending=makePending();data={pending:evmPending};}
    else if(path==="/api/btc/prepare"){btcPending=makeBtc();data={pending:btcPending,envelope:{kind:"btc-request",payload:"safe"}};}
    else if(path==="/api/request-raw")return {ok:true,text:async()=>"{\"value\":123456789012345678}"};
    else if(path==="/api/btc/request")data={kind:"btc-request",payload:"safe"};
    else if(path==="/api/accept"){evmPending={...evmPending,stage:"verified",tx_hash:"0x"+"b".repeat(64)};data=evmPending;}
    else if(path==="/api/btc/accept"){btcPending={...btcPending,stage:"verified",txid:"c".repeat(64)};data=btcPending;}
    else if(path==="/api/broadcast"){
      if(failBroadcast){data={error:"Broadcast result unknown"};status=400;}
      else{evmPending={...evmPending,stage:"broadcasted"};data=evmPending;}
    }
    else if(path==="/api/btc/broadcast"){btcPending={...btcPending,stage:"broadcasted"};data=btcPending;}
    else if(path==="/api/lookup"){data={asset:payload.asset,txid:payload.txid,result:"pending",untrusted_rpc:true};}
    else if(path==="/api/status"){data={...evmPending,result:"pending"};}
    else if(path==="/api/btc/status"){data={...btcPending,result:"pending"};}
    else if(path==="/api/cancel"){evmPending=null;data={cancelled:true};}
    else if(path==="/api/btc/cancel"){btcPending=null;data={cancelled:true};}
    else {data={error:"unexpected "+path};status=404;}
    return {ok:status===200,json:async()=>data};
  }
  const sandbox={document,fetch,Blob,URL:{createObjectURL(blob){blobs.push(blob);return "blob:local"},revokeObjectURL(){}},
    navigator:{clipboard:{async writeText(t){sandbox.copied=t;}}},window:{confirm(){return true}},
    setTimeout(){},BigInt,console};
  runInNewContext(source,sandbox,{filename:"companion.js"});
  const tick=async()=>{for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));};
  return {element,calls,blobs,tick,sandbox,failOverview(){failOverview=true;},failBroadcast(){failBroadcast=true;}};
}
test("watch-only receive address copy and two-asset navigation",async()=>{
  const h=harness();await h.tick();
  assert.equal(h.element("evmCopyBtn").disabled,false);
  h.element("evmCopyBtn").dispatch("click");await h.tick();
  assert.equal(h.sandbox.copied,ADDRESS);
  h.element("btcTab").dispatch("click");
  assert.equal(h.element("btcFlow").hidden,false);
  assert.equal(h.element("evmFlow").hidden,true);
  h.element("btcCopyBtn").dispatch("click");await h.tick();
  assert.equal(h.sandbox.copied,BTC_ADDRESS);
});
test("EVM precise Wei, user review gate, signed verification and explicit broadcast",async()=>{
  const h=harness();await h.tick();
  h.element("recipient").value=ADDRESS;
  h.element("amount").value="0.123456789012345678";
  h.element("maxFee").value="2";
  h.element("sendForm").dispatch("submit");await h.tick();
  assert.equal(h.element("downloadBtn").disabled,true);
  assert.match(h.element("pending").textContent,/0.123456789012345678 ETH/);
  h.element("evmAcknowledge").checked=true;
  h.element("evmAcknowledge").dispatch("change");
  h.element("confirmRequestBtn").dispatch("click");
  assert.equal(h.element("downloadBtn").disabled,false);
  assert.equal(h.element("broadcastBtn").disabled,true);
  h.element("downloadBtn").dispatch("click");await h.tick();
  assert.equal(await h.blobs.at(-1).text(),'{"value":123456789012345678}');
  h.element("signedFile").files=[{size:100,text:async()=>'{"signed":"fixture"}'}];
  h.element("verifyBtn").dispatch("click");await h.tick();
  assert.equal(h.element("broadcastBtn").disabled,false);
  assert.equal(h.calls.filter(c=>c.path==="/api/broadcast").length,0);
  h.element("broadcastBtn").dispatch("click");await h.tick();
  assert.equal(h.calls.filter(c=>c.path==="/api/broadcast").length,1);
  assert.equal(h.element("broadcastBtn").disabled,true);
});
test("BTC fee summary and review acknowledgement gate",async()=>{
  const h=harness();await h.tick();
  h.element("btcRecipient").value=BTC_ADDRESS;
  h.element("btcAmount").value="0.00120001";
  h.element("btcMaxFee").value="50000";
  h.element("btcRate").value="2";
  h.element("btcSendForm").dispatch("submit");await h.tick();
  assert.equal(h.element("btcDownloadBtn").disabled,true);
  assert.match(h.element("btcPending").textContent,/0.00120001 BTC/);
  h.element("btcAcknowledge").checked=true;
  h.element("btcAcknowledge").dispatch("change");
  h.element("btcConfirmRequestBtn").dispatch("click");
  assert.equal(h.element("btcDownloadBtn").disabled,false);
  assert.equal(h.element("btcBroadcastBtn").disabled,true);
});
test("invalid precision and insufficient displayed balance do not submit transaction",async()=>{
  const h=harness();await h.tick();
  h.element("amount").value="0.1234567890123456789";
  h.element("sendForm").dispatch("submit");await h.tick();
  assert.equal(h.calls.filter(c=>c.path==="/api/prepare").length,0);
  assert.match(h.element("message").textContent,/18 位小數/);
  h.element("amount").value="2";
  h.element("refreshBtn").dispatch("click");await h.tick();
  h.element("sendForm").dispatch("submit");await h.tick();
  assert.equal(h.calls.filter(c=>c.path==="/api/prepare").length,0);
});
test("RPC failure never implies balance is valid, cancellation clears prior approval",async()=>{
  const h=harness();await h.tick();
  h.failOverview();
  h.element("refreshBtn").dispatch("click");await h.tick();
  assert.match(h.element("message").textContent,/RPC timed out/);
  h.element("amount").value="0.01";
  h.element("sendForm").dispatch("submit");await h.tick();
  h.element("evmAcknowledge").checked=true;
  h.element("evmAcknowledge").dispatch("change");
  h.element("confirmRequestBtn").dispatch("click");
  h.element("cancelBtn").dispatch("click");await h.tick();
  assert.equal(h.element("downloadBtn").disabled,true);
  assert.equal(h.element("broadcastBtn").disabled,true);
});

test("public transaction lookup rejects wrong network syntax and never grants broadcast",async()=>{
  const h=harness();await h.tick();
  h.element("lookupAsset").value="sepolia";
  h.element("lookupHash").value="0xnot-a-hash";
  h.element("lookupForm").dispatch("submit");await h.tick();
  assert.equal(h.calls.filter(c=>c.path==="/api/lookup").length,0);
  assert.match(h.element("message").textContent,/Tx Hash/);
  h.element("lookupHash").value="0x"+"a".repeat(64);
  h.element("lookupForm").dispatch("submit");await h.tick();
  assert.equal(h.calls.filter(c=>c.path==="/api/lookup").length,1);
  assert.match(h.element("lookupResult").textContent,/等待鏈上確認/);
  assert.equal(h.element("broadcastBtn").disabled,true);
  assert.equal(h.calls.filter(c=>c.path==="/api/broadcast").length,0);
});
