import QRCode from "qrcode";
import { BrowserQRCodeReader } from "@zxing/browser";
import { encodeFrames, BoundedURScanner, MAX_PAYLOAD } from "./ur_transport.mjs";
import "./web.css";

// This page never signs, calls RPCs, or transmits over the network.
// Treat every scanned image as attacker-controlled data.
const el = id => document.getElementById(id);
const status = message => { el("status").textContent = message; };
let frames = [];
let animation = null;
let index = 0;
let scanner = new BoundedURScanner();
let readerControls = null;
let cameraOpening = false;
let cameraEpoch = 0;
let scanned = null;

function stopAnimation() {
  if (animation) clearInterval(animation);
  animation = null;
}
async function renderFrame() {
  if (frames.length === 0) return;
  const frame = frames[index % frames.length];
  await QRCode.toCanvas(el("qrCanvas"), frame, {
    width: 380, margin: 2, errorCorrectionLevel: "M",
  });
  el("frameLabel").textContent = `傳輸資料（非授權）· QR ${index % frames.length + 1} / ${frames.length}`;
}
function startAnimation() {
  stopAnimation();
  if (!frames.length) return;
  renderFrame().catch(e => status(e.message));
  if (frames.length > 1) {
    animation = setInterval(() => {
      index = (index + 1) % frames.length;
      renderFrame().catch(e => { stopAnimation(); status(e.message); });
    }, 450);
  }
}
el("prepare").addEventListener("click", async () => {
  stopAnimation();
  frames = [];
  index = 0;
  const file = el("inputFile").files?.[0];
  if (!file) return status("請先選擇資料交換 JSON 檔案。");
  if (file.size > MAX_PAYLOAD) return status("檔案太大，超過 150 KB。");
  try {
    const message = JSON.parse(await file.text());
    frames = encodeFrames(message);
    status(`QR 傳入/傳出均不代表簽章授權。已生成 ${frames.length} 張 QR。`);
    startAnimation();
  } catch (e) {
    status(`拒絕資料：${e.message}`);
  }
});
el("stopAnimation").addEventListener("click", stopAnimation);
el("resumeAnimation").addEventListener("click", startAnimation);
function stopCamera() {
  // Also invalidate a camera permission/open request still awaiting resolution.
  cameraEpoch++;
  readerControls?.stop();
  readerControls = null;
  const video = el("preview");
  if (video.srcObject) {
    for (const track of video.srcObject.getTracks()) track.stop();
    video.srcObject = null;
  }
}
el("stopScan").addEventListener("click", () => {
  stopCamera();
  status("已停止攝影機。");
});
el("resetScan").addEventListener("click", () => {
  stopCamera();
  scanner.reset();
  scanned = null;
  el("save").disabled = true;
  el("progress").value = 0;
  el("progressLabel").textContent = "0%";
  status("已重置，等待新的 QR 掃描。");
});
el("startScan").addEventListener("click", async () => {
  if (readerControls || cameraOpening) return;
  if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
    return status("無法使用攝影機：請使用 HTTPS / localhost 安全環境，或 USB-B 備援。");
  }
  if (scanner.done) return status("請先按重新掃描以建立新的掃描 session。");
  // A scan with no received frames starts fresh even when the page has been
  // open longer than the scan deadline. A partial scan retains its deadline.
  if (scanner.count === 0) scanner.reset();
  scanner.start();
  const reader = new BrowserQRCodeReader(undefined, { delayBetweenScanAttempts: 150 });
  const epoch = ++cameraEpoch;
  cameraOpening = true;
  try {
    const controls = await reader.decodeFromVideoDevice(undefined, el("preview"), (result, error) => {
      if (epoch !== cameraEpoch || !result) return;
      try {
        const progress = scanner.add(result.getText());
        el("progress").value = Math.round(progress.progress * 100);
        el("progressLabel").textContent = `${el("progress").value}%`;
        if (progress.done) {
          scanned = scanner.payload;
          el("save").disabled = false;
          stopCamera();
          status(`掃描完成：${scanned.direction === "unsigned" ? "傳入待簽資料" : "傳出已簽資料"} · ${scanned.network}。尚未驗證交易簽章，禁止自動廣播。`);
        }
      } catch (e) {
        stopCamera();
        status(`掃描失敗：${e.message}。請重設掃描，或採 USB-B 備援。`);
      }
    });
    // A successful scan or user cancellation may precede this await resolving.
    // In that case, close the late-arriving controls instead of leaking camera access.
    if (epoch !== cameraEpoch || scanner.done) {
      controls.stop();
      return;
    }
    readerControls = controls;
    status("攝影機已啟動，僅限離線主機的本機可信任攝影機。");
  } catch (e) {
    if (epoch === cameraEpoch) {
      stopCamera();
      status(`攝影機不可用：${e.message}。改用 USB-B 備援。`);
    }
  } finally {
    cameraOpening = false;
  }
});
el("save").addEventListener("click", () => {
  if (!scanned) return;
  const data = new Blob([JSON.stringify(scanned, null, 2)], { type: "application/json" });
  const href = URL.createObjectURL(data);
  const link = document.createElement("a");
  link.href = href;
  link.download = `qr-${scanned.direction}-${scanned.network}-${scanned.request_id}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
});
window.addEventListener("pagehide", () => {
  stopAnimation();
  stopCamera();
});
