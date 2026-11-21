"""Minimal local offline review GUI for Issue #19.

Tk/ttk is used deliberately: there is no WebView, browser, JavaScript runtime,
RPC client, plugin system, or remote content in the offline trusted computing
base. All transaction semantics come from :mod:`usb_cold_wallet.review`.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys
import time
from typing import Callable

from .keys import btc_address, evm_account, root_from_mnemonic
from .review import ReviewPlan, ReviewSession, load_review_file, load_review_qr
from .signer_session import SignerSession, State, DEFAULT_IDLE_SECONDS
from .vault import load_vault

DEFAULT_VAULT = Path("/mnt/cold-vault/wallet.vault")
DEFAULT_TRANSFER = Path("/mnt/transfer")
BOOT_CHECKS = Path("/run/usb-wallet/boot-checks.txt")
LOCKDOWN = Path("/run/usb-wallet/lockdown")
MOUNTINFO = Path("/proc/self/mountinfo")
VAULT_DEVICE = Path("/run/usb-wallet/vault-device")
IDLE_SECONDS = DEFAULT_IDLE_SECONDS
PUBLIC_TEST_EVM = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
PUBLIC_TEST_BTC = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"

_TEXT = {
    "en": {
        "title": "Offline Transaction Review",
        "testnet": "TESTNET RESEARCH ONLY — NOT AUDITED FOR REAL FUNDS",
        "dev": "DEVELOPMENT MODE — offline boot audit bypassed; PUBLIC TEST VECTORS ONLY",
        "choose": "Choose transaction type",
        "btc": "Bitcoin testnet payment",
        "evm": "Ethereum Sepolia payment",
        "unlock": "Unlock vault",
        "vault_password": "Vault encryption passphrase",
        "bip39_password": "Optional BIP39 passphrase (leave empty if none)",
        "import": "Import unsigned request",
        "usb": "Import from TX_TRANSFER USB-B",
        "qr": "Scan / import QR",
        "qr_unavailable": "QR camera/decoder is unavailable. Use TX_TRANSFER USB-B instead.",
        "back": "Back",
        "next": "Next",
        "reject": "Reject",
        "sign": "Confirm signing",
        "ack": "I verified every value on this page on the trusted offline display.",
        "source": "Source",
        "challenge": "Type this exact challenge; Enter never signs:",
        "signed": "Signed. Short attended session remains unlocked for a limited number of transactions. Lock now when finished.",
        "export": "Export signed response to USB-B",
        "signed_qr": "Show signed QR",
        "qr_output_unavailable": "Signed QR presentation requires the #18 QR adapter.",
        "done": "Done / lock",
        "error": "Transaction rejected",
        "idle": "Wallet locked after inactivity.",
        "locked": "Wallet locked.",
        "audit_failed": "Offline boot/runtime audit failed. GUI signing is disabled.",
        "output_exists": "Output already exists; choose a new filename.",
        "camera_failed": "QR capture failed or the camera was removed. No transaction was loaded.",
        "review_progress": "Review page {current} of {total}",
        "integrity_warning": "The request checksum detects changes; it does NOT authenticate the online computer.",
    },
    "zh-TW": {
        "title": "離線交易核對",
        "testnet": "僅限測試網研究用途 — 未完成真實資產安全審計",
        "dev": "開發模式 — 已略過離線開機稽核；只能使用公開測試向量",
        "choose": "選擇交易類型",
        "btc": "Bitcoin testnet 付款",
        "evm": "Ethereum Sepolia 付款",
        "unlock": "解鎖 Vault",
        "vault_password": "Vault 加密密碼",
        "bip39_password": "BIP39 額外密碼（沒有則留空）",
        "import": "匯入待簽請求",
        "usb": "從 TX_TRANSFER USB-B 匯入",
        "qr": "掃描／匯入 QR",
        "qr_unavailable": "目前沒有可用的 QR 攝影機／解碼器，請改用 TX_TRANSFER USB-B。",
        "back": "上一頁",
        "next": "下一頁",
        "reject": "拒絕",
        "sign": "確認簽章",
        "ack": "我已在可信任的離線畫面逐項核對本頁所有資料。",
        "source": "資料來源",
        "challenge": "請完整輸入以下確認字串；按 Enter 永遠不會簽章：",
        "signed": "簽章完成；短暫在場工作階段仍可能解鎖以處理下一筆。完成後請立即鎖定。",
        "export": "將已簽回覆匯出至 USB-B",
        "signed_qr": "顯示已簽 QR",
        "qr_output_unavailable": "顯示已簽 QR 需等待 #18 QR adapter 整合。",
        "done": "完成／鎖定",
        "error": "交易已拒絕",
        "idle": "因閒置逾時，錢包已鎖定。",
        "locked": "錢包已鎖定。",
        "audit_failed": "離線開機／執行期安全稽核失敗，GUI 簽章已停用。",
        "output_exists": "輸出檔已存在，請改用新的檔名。",
        "camera_failed": "QR 讀取失敗或攝影機已移除；未載入任何交易。",
        "review_progress": "核對頁面 {current} / {total}",
        "integrity_warning": "請求 checksum 只能偵測變更，不能證明 Online 電腦可信。",
    },
}

_PAGE_TITLES = {
    "en": {
        "network_account": "1. Network and signing account",
        "integrity": "2. Request and review digests",
        "recipient": "Recipient",
        "inputs": "Bitcoin inputs",
        "outputs": "Bitcoin outputs and change",
        "amount_fee": "Amount, nonce and fees",
        "policy": "Offline signing policy",
    },
    "zh-TW": {
        "network_account": "1. 網路與簽章帳戶",
        "integrity": "2. 請求與核對 Digest",
        "recipient": "完整收款地址",
        "inputs": "Bitcoin Inputs",
        "outputs": "Bitcoin Outputs 與找零",
        "amount_fee": "金額、Nonce 與費用",
        "policy": "離線簽章政策",
    },
}

_STATIC_LABELS = {
    "en": {
        "network": "Network",
        "chain_id": "Chain ID",
        "account": "Signing account",
        "transaction_type": "Transaction type",
        "request_digest": "Request SHA-256",
        "review_digest": "Offline review SHA-256",
        "recipient": "Recipient",
        "amount_wei": "Amount (wei)",
        "amount_display": "Amount",
        "nonce": "Nonce",
        "gas_limit": "Gas limit",
        "max_priority_fee_per_gas": "Max priority fee / gas",
        "max_fee_per_gas": "Max fee / gas",
        "max_network_fee_wei": "Maximum network fee (wei)",
        "max_total_spend_wei": "Maximum total spend (wei)",
        "operation": "Operation",
        "calldata": "Calldata",
        "access_list": "Access list",
        "contract_calls": "Contract calls",
        "input_count": "Input count",
        "amount_sats": "Recipient amount (sats)",
        "change_sats": "Change (sats)",
        "input_total_sats": "Input total (sats)",
        "output_total_sats": "Output total (sats)",
        "fee_sats": "Network fee (sats)",
    },
    "zh-TW": {
        "network": "網路",
        "chain_id": "Chain ID",
        "account": "簽章帳戶",
        "transaction_type": "交易類型",
        "request_digest": "請求 SHA-256",
        "review_digest": "離線核對 SHA-256",
        "recipient": "完整收款地址",
        "amount_wei": "金額（wei）",
        "amount_display": "金額",
        "nonce": "Nonce",
        "gas_limit": "Gas 上限",
        "max_priority_fee_per_gas": "最高 Priority Fee / Gas",
        "max_fee_per_gas": "最高 Fee / Gas",
        "max_network_fee_wei": "最高網路費（wei）",
        "max_total_spend_wei": "最高總支出（wei）",
        "operation": "操作",
        "calldata": "Calldata",
        "access_list": "Access List",
        "contract_calls": "合約呼叫",
        "input_count": "Input 數量",
        "amount_sats": "收款金額（sats）",
        "change_sats": "找零（sats）",
        "input_total_sats": "Input 總額（sats）",
        "output_total_sats": "Output 總額（sats）",
        "fee_sats": "網路費（sats）",
    },
}


class CameraUnavailable(RuntimeError):
    pass


def _is_public_test_root(root) -> bool:
    try:
        return evm_account(root).address == PUBLIC_TEST_EVM and btc_address(root, 0, 0) == PUBLIC_TEST_BTC
    except Exception:
        return False


def _current_mount_evidence(mountinfo: Path, vault_device: Path) -> list[str]:
    """Revalidate current kernel mount identities; boot PASS lines are historical."""
    try:
        source_expected = vault_device.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"/dev/[A-Za-z0-9._/-]{2,80}", source_expected):
            raise ValueError("Invalid verified vault device identity")
        lines = mountinfo.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError, ValueError):
        return ["FAIL: live mountinfo or verified vault device identity unavailable"]

    mounts = []
    for line in lines:
        try:
            left, right = line.split(" - ", 1)
            left_cols, right_cols = left.split(), right.split()
            if len(left_cols) < 6 or len(right_cols) < 3:
                raise ValueError("Malformed mountinfo")
            mounts.append({
                "target": left_cols[4], "options": set(left_cols[5].split(",")),
                "type": right_cols[0], "source": right_cols[1],
                "super": set(right_cols[2].split(",")),
            })
        except (IndexError, ValueError):
            return ["FAIL: malformed live mountinfo"]

    findings = []
    root = [m for m in mounts if m["target"] == "/"]
    vault = [m for m in mounts if m["target"] == "/mnt/cold-vault"]
    transfer = [m for m in mounts if m["target"] == "/mnt/transfer"]
    if len(root) != 1 or root[0]["type"] not in ("rootfs", "tmpfs"):
        findings.append("FAIL: live root filesystem is not uniquely RAM-backed")
    else:
        findings.append("PASS: live RAM-backed root")
    required = {"rw", "nodev", "nosuid", "noexec", "sync"}
    if (len(vault) != 1 or vault[0]["type"] != "vfat"
            or vault[0]["source"] != source_expected
            or not required <= (vault[0]["options"] | vault[0]["super"])):
        findings.append("FAIL: live COLD_VAULT source, type or mount options changed")
    else:
        findings.append("PASS: live COLD_VAULT verified device and mount flags")

    # TX_TRANSFER is mounted only during imports/exports. If present, require
    # separate media and restrictive flags; it must not replace the vault.
    if transfer and (len(transfer) != 1 or transfer[0]["type"] != "vfat"
                     or transfer[0]["source"] == source_expected
                     or not required <= (transfer[0]["options"] | transfer[0]["super"])):
        findings.append("FAIL: live TX_TRANSFER mount has unsafe identity or options")
    safe_pseudo = {
        "rootfs", "tmpfs", "proc", "sysfs", "devtmpfs", "devpts",
        "cgroup2", "pstore", "tracefs",
    }
    for mounted in mounts:
        options = mounted["options"] | mounted["super"]
        if ("rw" in options and mounted["type"] not in safe_pseudo
                and mounted["target"] not in ("/mnt/cold-vault", "/mnt/transfer")):
            findings.append("FAIL: unexpected live writable persistent mount")
            break
    if not any(x.startswith("FAIL:") for x in findings):
        findings.append("PASS: no unexpected writable persistent filesystem mounted now")
    return findings


def runtime_audit(
    *,
    boot_checks: Path = BOOT_CHECKS,
    lockdown: Path = LOCKDOWN,
    proc_net: Path = Path("/proc/net"),
    proc_swaps: Path = Path("/proc/swaps"),
    proc_mountinfo: Path = MOUNTINFO,
    vault_device: Path = VAULT_DEVICE,
) -> tuple[bool, tuple[str, ...]]:
    """Check historical boot evidence AND live kernel state before every unlock/sign."""
    findings: list[str] = []
    if lockdown.exists():
        findings.append("FAIL: offline lockdown marker exists")
    try:
        lines = boot_checks.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
        findings.append("FAIL: boot security audit missing")
    checks = [line for line in lines if line.startswith(("PASS:", "FAIL:"))]
    if not checks:
        findings.append("FAIL: boot security audit contained no checks")
    else:
        findings.extend(checks)
        required_boot = (
            ("network isolation", ("network stack absent", "/proc/net absent")),
            ("no active swap", ("no active swap",)),
            ("RAM-backed root", ("root filesystem is RAM-backed",)),
            ("COLD_VAULT mount", ("COLD_VAULT mounted",)),
            ("no unexpected writable persistent filesystem", ("no unexpected writable persistent filesystem",)),
        )
        for name, markers in required_boot:
            if not any(
                line.startswith("PASS:") and any(marker in line for marker in markers)
                for line in checks
            ):
                findings.append(f"FAIL: required boot audit result missing: {name}")
    if proc_net.exists():
        findings.append("FAIL: live /proc/net exists")
    else:
        findings.append("PASS: live network stack absent")
    try:
        swaps = proc_swaps.read_text(encoding="utf-8").strip().splitlines()
        findings.append("PASS: no active swap" if len(swaps) <= 1 else "FAIL: active swap detected")
    except OSError:
        findings.append("FAIL: unable to inspect swap")
    findings.extend(_current_mount_evidence(proc_mountinfo, vault_device))
    ok = bool(findings) and not any(line.startswith("FAIL:") for line in findings)
    return ok, tuple(findings)


def _label(key: str, language: str) -> str:
    static = _STATIC_LABELS[language]
    if key in static:
        return static[key]
    match = re.fullmatch(r"input_(\d+)_(outpoint|value_sats|derivation)", key)
    if match:
        index = int(match.group(1)) + 1
        suffix = {
            "en": {
                "outpoint": "outpoint",
                "value_sats": "value (sats)",
                "derivation": "derivation",
            },
            "zh-TW": {
                "outpoint": "前一輸出點",
                "value_sats": "金額（sats）",
                "derivation": "衍生路徑",
            },
        }[language][match.group(2)]
        return f"Input {index} {suffix}"
    match = re.fullmatch(r"output_(\d+)_(role|address|value_sats|change_index)", key)
    if match:
        index = int(match.group(1)) + 1
        suffix = {
            "en": {
                "role": "role",
                "address": "full address",
                "value_sats": "value (sats)",
                "change_index": "change index",
            },
            "zh-TW": {
                "role": "用途",
                "address": "完整地址",
                "value_sats": "金額（sats）",
                "change_index": "找零 index",
            },
        }[language][match.group(2)]
        return f"Output {index} {suffix}"
    return key.replace("_", " ")


class OfflineReviewApp:
    def __init__(
        self,
        tk,
        ttk,
        filedialog,
        messagebox,
        simpledialog,
        *,
        vault: Path,
        transfer_dir: Path,
        language: str,
        audit_ok: bool,
        audit_lines: tuple[str, ...],
        development_mode: bool = False,
        qr_reader: Callable[[], str] | None = None,
        qr_presenter: Callable[[str], None] | None = None,
        idle_seconds: int = IDLE_SECONDS,
    ):
        self.tk = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.simpledialog = simpledialog
        self.vault = Path(vault)
        self.transfer_dir = Path(transfer_dir)
        self.language = language if language in _TEXT else "en"
        self.audit_ok = audit_ok
        self.audit_lines = audit_lines
        self.development_mode = development_mode
        self.qr_reader = qr_reader
        self.qr_presenter = qr_presenter
        self.idle_seconds = idle_seconds

        self.root = tk.Tk()
        self.root.title(_TEXT[self.language]["title"])
        self.root.geometry("900x680")
        self.root.minsize(640, 480)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.report_callback_exception = self._callback_exception
        self.root.bind("<FocusOut>", self._focus_out, add="+")
        self.root.bind_all("<Any-KeyPress>", self._activity, add="+")
        self.root.bind_all("<Any-Button>", self._activity, add="+")

        self.wallet_root = None
        self._active_usb_file = None
        self._active_usb_identity = None
        self.last_activity = time.monotonic()
        self.security = SignerSession(
            audit=lambda: self.development_mode or (self.audit_ok and runtime_audit()[0]),
            on_lock=self._drop_wallet_references,
            idle_seconds=idle_seconds,
        )
        self.selected_kind: str | None = None
        self.session: ReviewSession | None = None
        self.page_index = 0
        self.status_message = ""
        self._confirmation_var = None

        self.container = ttk.Frame(self.root, padding=16)
        self.container.pack(fill="both", expand=True)
        self._render_home()
        self.root.after_idle(self._mark_locked_ready)
        self.root.after(1000, self._idle_tick)

    def _mark_locked_ready(self) -> None:
        """Kernel-to-locked-GUI metric only; not a power-on benchmark."""
        if self.security.state == State.LOCKED and hasattr(time, "CLOCK_BOOTTIME"):
            elapsed_ms = round(time.clock_gettime(time.CLOCK_BOOTTIME) * 1000)
            print(f"READY locked_gui kernel_boot_elapsed_ms={elapsed_ms}", flush=True)

    def t(self, key: str) -> str:
        return _TEXT[self.language][key]

    def run(self) -> None:
        self.root.mainloop()

    def _activity(self, _event=None):
        self.last_activity = time.monotonic()
        if self.security.state in (State.REVIEWING, State.APPROVED, State.SIGNED):
            try:
                self.security.activity()
            except ValueError:
                self._lock_wallet(self.t("idle"))
                self._render_home()

    def _idle_tick(self):
        if self.security.tick() or not self._transport_available():
            self._lock_wallet(self.t("idle"))
            self._render_home()
        self.root.after(1000, self._idle_tick)

    def _transport_available(self) -> bool:
        if self._active_usb_file is None:
            return True
        try:
            info = self._active_usb_file.lstat()
            return stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == self._active_usb_identity
        except OSError:
            return False

    def _drop_wallet_references(self):
        self.wallet_root = None
        self._active_usb_file = None
        self._active_usb_identity = None
        if self.session and not self.session.signed:
            self.session.cancel()
            self.session = None

    def _callback_exception(self, _exc_type, _exc, _traceback):
        signed = bool(self.session and self.session.signed)
        self.security.lock("ui_exception")
        self.status_message = self.t("locked")
        self.messagebox.showerror(
            self.t("error"),
            "Unexpected local UI error. Wallet locked. "
            + ("The already-signed public response remains in memory." if signed else "No signing confirmation remains active."),
            parent=self.root,
        )
        self._render_home() if not signed else self._render_signed()

    def _focus_out(self, _event=None):
        if self.session and not self.session.signed:
            self.session.clear_confirmation()
            if self._confirmation_var is not None:
                self._confirmation_var.set("")
            self._update_sign_button()

    def _clear(self):
        for child in self.container.winfo_children():
            child.destroy()

    def _banner(self, parent):
        ttk.Label(parent, text=self.t("testnet"), anchor="center").pack(fill="x", pady=(0, 6))
        if self.development_mode:
            ttk.Label(parent, text=self.t("dev"), anchor="center").pack(fill="x", pady=(0, 6))
        if self.security.unlocked:
            ttk.Label(parent, text=f"{self.security.state.value} · signed {self.security.transaction_count}/{self.security.max_transactions} · idle lock {self.idle_seconds}s", anchor="center").pack(fill="x", pady=(0, 6))

    def _language_buttons(self, parent):
        row = self.ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 10))
        self.ttk.Button(row, text="English", command=lambda: self._set_language("en")).pack(side="right")
        self.ttk.Button(row, text="繁體中文", command=lambda: self._set_language("zh-TW")).pack(side="right", padx=6)

    def _set_language(self, language: str):
        self.language = language
        self.root.title(self.t("title"))
        if self.session and self.session.signed:
            self._render_signed()
        elif self.session:
            self._render_review()
        elif self.selected_kind:
            self._render_import()
        else:
            self._render_home()

    def _render_home(self):
        self._clear()
        self.selected_kind = None
        self._language_buttons(self.container)
        self._banner(self.container)
        self.ttk.Label(self.container, text=self.t("title"), font=("", 22, "bold")).pack(pady=(12, 18))
        if self.status_message:
            self.ttk.Label(self.container, text=self.status_message, wraplength=780).pack(fill="x", pady=(0, 12))
        if not self.audit_ok and not self.development_mode:
            self.ttk.Label(self.container, text=self.t("audit_failed"), wraplength=780).pack(fill="x", pady=12)
            for line in self.audit_lines:
                self.ttk.Label(self.container, text=line, wraplength=780).pack(fill="x")
            return
        self.ttk.Label(self.container, text=self.t("choose"), font=("", 15, "bold")).pack(pady=(16, 12))
        self.ttk.Label(self.container, text="Session: " + self.security.state.value + f" · Idle auto-lock: {self.idle_seconds}s · Python RAM zeroization cannot be guaranteed", wraplength=780).pack(fill="x", pady=4)
        self.ttk.Button(self.container, text="Lock now / 立即鎖定", command=self._cancel_to_home).pack(fill="x", pady=4)
        self.ttk.Button(self.container, text="Exit signer / 離開（不等於電腦關機）", command=self._close).pack(fill="x", pady=4)
        choices = self.ttk.Frame(self.container)
        choices.pack(fill="x", expand=True, pady=12)
        self.ttk.Button(
            choices,
            text=self.t("btc"),
            command=lambda: self._choose_kind("btc-request"),
        ).pack(side="left", fill="both", expand=True, padx=(0, 8), ipady=24)
        self.ttk.Button(
            choices,
            text=self.t("evm"),
            command=lambda: self._choose_kind("evm-request"),
        ).pack(side="left", fill="both", expand=True, padx=(8, 0), ipady=24)

    def _choose_kind(self, kind: str):
        if not self._unlock():
            return
        self.selected_kind = kind
        self.session = None
        self.page_index = 0
        self._render_import()

    def _unlock(self) -> bool:
        if self.wallet_root is not None:
            try:
                self.security.activity()
                if self.security.tick():
                    raise ValueError("Session locked due to failed safety audit")
                return True
            except ValueError:
                self._lock_wallet(self.t("locked"))
                return False
        try:
            self.security.begin_unlock()
        except ValueError as exc:
            self.messagebox.showerror(self.t("error"), str(exc)[:300], parent=self.root)
            return False
        password = self.simpledialog.askstring(
            self.t("unlock"),
            self.t("vault_password"),
            show="*",
            parent=self.root,
        )
        if password is None:
            self.security.lock("cancel_unlock")
            return False
        bip39_password = self.simpledialog.askstring(
            self.t("unlock"),
            self.t("bip39_password"),
            show="*",
            parent=self.root,
        )
        if bip39_password is None:
            self.security.lock("cancel_unlock")
            return False
        try:
            mnemonic = load_vault(self.vault, password)
            wallet_root = root_from_mnemonic(mnemonic, bip39_password)
        except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self.security.unlock_failed()
            self.messagebox.showerror(self.t("error"), "Vault unlock failed. Retry is rate-limited.", parent=self.root)
            return False
        finally:
            password = ""
            bip39_password = ""
            if "mnemonic" in locals():
                mnemonic = ""
        if self.development_mode and not _is_public_test_root(wallet_root):
            self.security.unlock_failed()
            self.messagebox.showerror(
                self.t("error"),
                "Development audit bypass only permits the repository's known-compromised public test wallet.",
                parent=self.root,
            )
            return False
        try:
            self.security.unlock_succeeded()
        except ValueError as exc:
            self.messagebox.showerror(self.t("error"), str(exc)[:300], parent=self.root)
            return False
        self.wallet_root = wallet_root
        self._activity()
        return True

    def _render_import(self):
        self._clear()
        self._language_buttons(self.container)
        self._banner(self.container)
        chain = self.t("evm") if self.selected_kind == "evm-request" else self.t("btc")
        self.ttk.Label(self.container, text=chain, font=("", 18, "bold")).pack(pady=(14, 6))
        self.ttk.Label(self.container, text=self.t("integrity_warning"), wraplength=780).pack(fill="x", pady=(0, 18))
        self.ttk.Label(self.container, text=self.t("import"), font=("", 14, "bold")).pack(pady=(8, 14))
        self.ttk.Button(self.container, text=self.t("usb"), command=self._import_usb).pack(fill="x", ipady=12, pady=6)
        self.ttk.Button(self.container, text=self.t("qr"), command=self._import_qr).pack(fill="x", ipady=12, pady=6)
        self.ttk.Button(self.container, text=self.t("back"), command=self._cancel_to_home).pack(pady=(24, 0))

    def _path_allowed(self, path: Path) -> bool:
        if self.development_mode:
            return True
        try:
            common = os.path.commonpath([str(path.absolute()), str(self.transfer_dir.absolute())])
        except ValueError:
            return False
        return common == str(self.transfer_dir.absolute())

    def _import_usb(self):
        if self.wallet_root is None and not self._unlock():
            return
        filename = self.filedialog.askopenfilename(
            parent=self.root,
            initialdir=str(self.transfer_dir),
            title=self.t("usb"),
            filetypes=(("JSON exchange", "*.json"), ("All files", "*")),
        )
        if not filename:
            self._lock_wallet(self.t("locked"))
            self._render_home()
            return
        path = Path(filename)
        if not self._path_allowed(path):
            self._lock_wallet(self.t("locked"))
            self.messagebox.showerror(self.t("error"), "Request must come from TX_TRANSFER.", parent=self.root)
            self._render_home()
            return
        try:
            plan = load_review_file(path, self.wallet_root, self.selected_kind)
        except (ValueError, OSError, KeyError, TypeError, OverflowError) as exc:
            self._lock_wallet(self.t("locked"))
            self.messagebox.showerror(self.t("error"), str(exc)[:300], parent=self.root)
            self._render_home()
            return
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Transfer request is not a regular file")
            self._active_usb_file = path
            self._active_usb_identity = (info.st_dev, info.st_ino)
        except (OSError, ValueError):
            self._lock_wallet(self.t("locked"))
            self._render_home()
            return
        self._start_review(plan)

    def _import_qr(self):
        # A camera decoder can block the Tk event loop indefinitely. Capture
        # with the wallet locked; only unlock after obtaining validated bytes.
        requested_kind = self.selected_kind
        self._lock_wallet()
        if self.qr_reader is None:
            self._lock_wallet(self.t("locked"))
            self.messagebox.showwarning(self.t("error"), self.t("qr_unavailable"), parent=self.root)
            self._render_home()
            return
        try:
            text = self.qr_reader()
            if not text:
                raise CameraUnavailable("empty QR capture")
            from .exchange import decode_envelope
            decode_envelope(text, requested_kind)  # Validate untrusted data before unlock.
        except CameraUnavailable:
            self._lock_wallet(self.t("locked"))
            self.messagebox.showwarning(self.t("error"), self.t("camera_failed"), parent=self.root)
            self._render_home()
            return
        except (ValueError, OSError, KeyError, TypeError, OverflowError):
            self._lock_wallet(self.t("locked"))
            self.messagebox.showerror(self.t("error"), self.t("camera_failed"), parent=self.root)
            self._render_home()
            return
        if not self._unlock():
            self._render_home()
            return
        try:
            plan = load_review_qr(text, self.wallet_root, requested_kind)
        except (ValueError, OSError, KeyError, TypeError, OverflowError):
            self._lock_wallet(self.t("locked"))
            self.messagebox.showerror(self.t("error"), self.t("camera_failed"), parent=self.root)
            self._render_home()
            return
        self.selected_kind = requested_kind
        self._active_usb_file = None
        self._active_usb_identity = None
        self._start_review(plan)

    def _start_review(self, plan: ReviewPlan):
        try:
            self.security.start_review(plan.review_digest)
        except ValueError as exc:
            self._lock_wallet(self.t("locked"))
            self.messagebox.showerror(self.t("error"), str(exc)[:300], parent=self.root)
            self._render_home()
            return
        self.session = ReviewSession(plan)
        self.page_index = 0
        self.status_message = ""
        self._activity()
        self._render_review()

    def _scrollable(self):
        outer = self.ttk.Frame(self.container)
        outer.pack(fill="both", expand=True)
        canvas = self.tk.Canvas(outer, highlightthickness=0)
        scrollbar = self.ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = self.ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return inner

    def _render_review(self):
        if not self.session:
            self._render_import()
            return
        self._clear()
        self._language_buttons(self.container)
        self._banner(self.container)
        plan = self.session.plan
        page = plan.pages[self.page_index]
        self.ttk.Label(
            self.container,
            text=self.t("review_progress").format(current=self.page_index + 1, total=len(plan.pages)),
        ).pack(fill="x")
        self.ttk.Label(
            self.container,
            text=_PAGE_TITLES[self.language].get(page.key, page.key),
            font=("", 17, "bold"),
        ).pack(fill="x", pady=(4, 8))
        self.ttk.Label(self.container, text=self.t("integrity_warning"), wraplength=820).pack(fill="x", pady=(0, 8))

        inner = self._scrollable()
        for field in page.fields:
            block = self.ttk.Frame(inner, padding=(4, 8))
            block.pack(fill="x")
            self.ttk.Label(block, text=_label(field.key, self.language), font=("", 11, "bold")).pack(fill="x")
            height = max(1, min(4, (len(field.value) // 78) + 1))
            value = self.tk.Text(block, height=height, wrap="char", relief="solid", borderwidth=1)
            value.insert("1.0", field.value)
            value.configure(state="disabled", takefocus=True)
            value.pack(fill="x", pady=(2, 2))
            self.ttk.Label(
                block,
                text=f"{self.t('source')}: {field.source}",
                wraplength=800,
            ).pack(fill="x")

        acknowledged = self.page_index in self.session.acknowledged_pages
        ack_var = self.tk.BooleanVar(value=acknowledged)
        ack = self.ttk.Checkbutton(
            self.container,
            text=self.t("ack"),
            variable=ack_var,
            command=lambda: self._toggle_ack(ack_var.get()),
        )
        ack.pack(fill="x", pady=(10, 6))

        self._confirmation_var = None
        if self.page_index == len(plan.pages) - 1:
            self.ttk.Label(self.container, text=self.t("challenge"), wraplength=820).pack(fill="x", pady=(6, 2))
            self.ttk.Label(self.container, text=plan.challenge, font=("TkFixedFont", 12, "bold")).pack(fill="x")
            confirmation = self.tk.StringVar(value="")
            self._confirmation_var = confirmation
            entry = self.ttk.Entry(self.container, textvariable=confirmation)
            entry.pack(fill="x", pady=(4, 8))
            entry.bind("<Return>", lambda _e: "break")
            confirmation.trace_add("write", lambda *_: self._confirmation_changed(confirmation.get()))
            sign_button = self.ttk.Button(self.container, text=self.t("sign"), command=self._sign)
            sign_button.pack(fill="x", ipady=10, pady=(2, 8))
            self._sign_button = sign_button
            self._update_sign_button()

        navigation = self.ttk.Frame(self.container)
        navigation.pack(fill="x", pady=(6, 0))
        self.ttk.Button(navigation, text=self.t("reject"), command=self._reject).pack(side="left")
        if self.page_index > 0:
            self.ttk.Button(navigation, text=self.t("back"), command=self._previous_page).pack(side="right", padx=4)
        if self.page_index < len(plan.pages) - 1:
            next_button = self.ttk.Button(navigation, text=self.t("next"), command=self._next_page)
            next_button.pack(side="right", padx=4)
            if not acknowledged:
                next_button.state(["disabled"])
            self._next_button = next_button

    def _toggle_ack(self, checked: bool):
        if not self.session:
            return
        try:
            if checked:
                self.session.acknowledge(self.page_index, self.session.plan.review_digest)
            else:
                self.session.revoke(self.page_index)
        except ValueError as exc:
            self.messagebox.showerror(self.t("error"), str(exc), parent=self.root)
        self._render_review()

    def _previous_page(self):
        if self.page_index > 0:
            self.page_index -= 1
            self._render_review()

    def _next_page(self):
        if not self.session or self.page_index not in self.session.acknowledged_pages:
            return
        if self.page_index < len(self.session.plan.pages) - 1:
            self.page_index += 1
            self._render_review()

    def _confirmation_changed(self, value: str):
        if not self.session:
            return
        try:
            self.session.set_confirmation(value, self.session.plan.review_digest)
        except ValueError:
            return
        self._update_sign_button()

    def _update_sign_button(self):
        button = getattr(self, "_sign_button", None)
        if button is None or not self.session:
            return
        if self.session.can_sign:
            button.state(["!disabled"])
        else:
            button.state(["disabled"])

    def _sign(self):
        if not self.session or self.wallet_root is None:
            return
        digest = self.session.plan.review_digest
        try:
            if not self._transport_available():
                raise ValueError("USB transport removed or changed; signing canceled")
            if not self.session.can_sign:
                raise ValueError("Explicit confirmation required for every transaction")
            self.security.approve(digest)
            self.security.signing(digest)
            self.session.sign(self.wallet_root)
            self.security.signed(digest)
        except (ValueError, OSError, KeyError, TypeError, OverflowError) as exc:
            self._lock_wallet(self.t("locked"))
            self.messagebox.showerror(self.t("error"), str(exc)[:300], parent=self.root)
            self._render_home()
            return
        self._render_signed()

    def _render_signed(self):
        if not self.session or not self.session.signed:
            self._render_home()
            return
        self._clear()
        self._language_buttons(self.container)
        self._banner(self.container)
        signed_status = self.t("signed") if self.security.state == State.SIGNED else self.t("locked")
        self.ttk.Label(self.container, text=signed_status, font=("", 16, "bold"), wraplength=820).pack(pady=(20, 12))
        envelope = json.loads(self.session.signed_envelope_text())
        self.ttk.Label(self.container, text=f"Signed envelope SHA-256: {envelope['sha256']}", wraplength=820).pack(fill="x", pady=6)
        self.ttk.Label(self.container, text=f"Request SHA-256: {self.session.plan.request_digest}", wraplength=820).pack(fill="x", pady=6)
        self.ttk.Label(self.container, text=f"Review SHA-256: {self.session.plan.review_digest}", wraplength=820).pack(fill="x", pady=6)
        self.ttk.Button(self.container, text=self.t("export"), command=self._export_signed).pack(fill="x", ipady=10, pady=(18, 6))
        qr_button = self.ttk.Button(self.container, text=self.t("signed_qr"), command=self._present_signed_qr)
        qr_button.pack(fill="x", ipady=10, pady=6)
        if self.qr_presenter is None:
            qr_button.state(["disabled"])
            self.ttk.Label(self.container, text=self.t("qr_output_unavailable"), wraplength=820).pack(fill="x")
        if self.security.state == State.SIGNED and self.wallet_root is not None:
            self.ttk.Button(self.container, text="Review next transaction / 下一筆重新審核", command=self._next_transaction).pack(fill="x", pady=8)
        self.ttk.Button(self.container, text=self.t("done"), command=self._done).pack(pady=(24, 0))

    def _export_signed(self):
        if not self.session:
            return
        filename = self.filedialog.asksaveasfilename(
            parent=self.root,
            initialdir=str(self.transfer_dir),
            defaultextension=".json",
            filetypes=(("JSON exchange", "*.json"),),
            title=self.t("export"),
        )
        if not filename:
            return
        path = Path(filename)
        if not self._path_allowed(path):
            self.messagebox.showerror(self.t("error"), "Signed response must be written to TX_TRANSFER.", parent=self.root)
            return
        try:
            self.session.export_signed(path)
        except FileExistsError:
            self.messagebox.showerror(self.t("error"), self.t("output_exists"), parent=self.root)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            self._lock_wallet(self.t("locked"))
            self.messagebox.showerror(self.t("error"), str(exc)[:300], parent=self.root)
            self._render_home()

    def _present_signed_qr(self):
        if not self.session or self.qr_presenter is None:
            return
        try:
            self.qr_presenter(self.session.signed_envelope_text())
        except Exception:
            self._lock_wallet(self.t("locked"))
            self.messagebox.showwarning(self.t("error"), self.t("qr_output_unavailable"), parent=self.root)
            self._render_home()

    def _reject(self):
        if self.session:
            self.session.cancel()
        self._lock_wallet(self.t("locked"))
        self._render_home()

    def _cancel_to_home(self):
        self._lock_wallet(self.t("locked"))
        self._render_home()

    def _lock_wallet(self, message: str = ""):
        self.security.lock("manual_or_failure")
        self.session = None
        self.selected_kind = None
        self.page_index = 0
        self.status_message = message

    def _next_transaction(self):
        if self.security.state != State.SIGNED or self.wallet_root is None:
            self._lock_wallet(self.t("locked"))
        else:
            self.session = None
            self.selected_kind = None
            self.page_index = 0
            self.status_message = "Next transaction needs a new full review and typed confirmation."
        self._render_home()

    def _done(self):
        self._lock_wallet(self.t("locked"))
        self._render_home()

    def _close(self):
        self._lock_wallet(self.t("locked"))
        self.root.destroy()


def _block_process_core_dumps() -> None:
    """Process-local defense: never leave an unencrypted wallet in core files."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    if soft != 0 or hard != 0:
        raise RuntimeError("Cannot disable core dumps on offline signer")


def _load_tk():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, simpledialog, ttk
    except ImportError as exc:
        raise RuntimeError("Tkinter is required for the local offline GUI") from exc
    return tk, ttk, filedialog, messagebox, simpledialog


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="usb-cold-wallet-gui",
        description="Local TESTNET-only offline transaction review GUI; no WebView or network client.",
    )
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    parser.add_argument("--transfer-dir", type=Path, default=DEFAULT_TRANSFER)
    parser.add_argument("--lang", choices=["en", "zh-TW"], default="en")
    parser.add_argument(
        "--public-test-vector-mode",
        action="store_true",
        help="DEVELOPMENT ONLY: bypass boot audit, but only the repository's known public test wallet may unlock",
    )
    args = parser.parse_args(argv)

    audit_ok, findings = runtime_audit()
    if not audit_ok and not args.public_test_vector_mode:
        print("ERROR: offline boot/runtime audit failed; refusing to start signing GUI", file=sys.stderr)
        for line in findings:
            print(line, file=sys.stderr)
        return 2

    try:
        _block_process_core_dumps()
        os.umask(0o077)
        tk, ttk, filedialog, messagebox, simpledialog = _load_tk()
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    os.environ["HISTFILE"] = "/dev/null"
    app = OfflineReviewApp(
        tk,
        ttk,
        filedialog,
        messagebox,
        simpledialog,
        vault=args.vault,
        transfer_dir=args.transfer_dir,
        language=args.lang,
        audit_ok=audit_ok,
        audit_lines=findings,
        development_mode=args.public_test_vector_mode,
    )
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
