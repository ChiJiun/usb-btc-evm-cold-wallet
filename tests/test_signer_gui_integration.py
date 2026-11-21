"""GUI-to-signer integration without Tk/physical wallet or any secret fixture."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

from usb_cold_wallet import gui
from usb_cold_wallet.gui import OfflineReviewApp
from usb_cold_wallet.signer_session import SignerSession, State


class StubReview:
    def __init__(self, digest, approved=True):
        self.plan = SimpleNamespace(review_digest=digest)
        self.can_sign = approved
        self.signed = False
        self.sign_calls = 0

    def sign(self, root):
        assert root is not None
        self.sign_calls += 1
        self.signed = True

    def cancel(self):
        self.can_sign = False


class StubMessagebox:
    def __init__(self):
        self.errors = []

    def showerror(self, *args, **kwargs):
        self.errors.append(args)

    def showwarning(self, *args, **kwargs):
        self.errors.append(args)


def ui_fixture():
    # Avoid constructing Tk; exercise the actual GUI methods with a fake root.
    app = OfflineReviewApp.__new__(OfflineReviewApp)
    app.language = "en"
    app.wallet_root = object()
    app._active_usb_file = None
    app._active_usb_identity = None
    app._active_usb_digest = None
    app.session = None
    app.selected_kind = None
    app.page_index = 0
    app.status_message = ""
    app.messagebox = StubMessagebox()
    app.root = object()
    app.transfer_dir = Path("/tmp")
    app.development_mode = False
    app.filedialog = SimpleNamespace(askopenfilename=lambda **kwargs: "")
    app.qr_reader = None
    app.rendered = []
    app._render_signed = lambda: app.rendered.append("signed")
    app._render_home = lambda: app.rendered.append("home")
    clock = {"now": 100.0}
    app.security = SignerSession(audit=lambda: True,
                                  on_lock=app._drop_wallet_references,
                                  clock=lambda: clock["now"])
    app.security.begin_unlock()
    app.security.unlock_succeeded()
    return app, clock


def test_gui_signing_still_requires_each_review_and_keeps_short_session():
    app, clock = ui_fixture()
    first = StubReview("a" * 64)
    app.session = first
    app.security.start_review(first.plan.review_digest)
    app._sign()
    assert first.signed and app.wallet_root is not None
    assert app.security.state == State.SIGNED
    assert app.rendered == ["signed"]
    app._next_transaction()
    assert app.wallet_root is not None and app.session is None

    second = StubReview("b" * 64, approved=False)
    app.session = second
    app.security.start_review(second.plan.review_digest)
    app._sign()
    assert second.sign_calls == 0
    assert app.wallet_root is None
    assert app.security.state == State.LOCKED
    assert app.messagebox.errors


def test_usb_removal_or_replacement_blocks_signing(tmp_path):
    app, _ = ui_fixture()
    transfer = tmp_path / "unsigned-request.json"
    transfer.write_text("{}")
    info = transfer.lstat()
    app._active_usb_file = transfer
    app._active_usb_identity = (info.st_dev, info.st_ino)
    review = StubReview("a" * 64)
    app.session = review
    app.security.start_review(review.plan.review_digest)
    transfer.unlink()
    app._sign()
    assert review.sign_calls == 0
    assert app.security.state == State.LOCKED
    assert app.wallet_root is None


def test_gui_manual_lock_clears_wallet_and_review():
    app, clock = ui_fixture()
    app.session = StubReview("d" * 64)
    app._lock_wallet("manual")
    assert app.wallet_root is None
    assert app.session is None
    assert app.security.state == State.LOCKED


def test_gui_post_sign_idle_locks_and_blocks_future_sign():
    app, clock = ui_fixture()
    first = StubReview("a" * 64)
    app.session = first
    app.security.start_review(first.plan.review_digest)
    app._sign()
    clock["now"] += 600
    assert app.security.tick()
    assert app.wallet_root is None
    second = StubReview("b" * 64)
    app.session = second
    app._sign()
    assert second.sign_calls == 0
    assert app.security.state == State.LOCKED


def test_gui_cancelled_usb_import_locks_wallet():
    app, _ = ui_fixture()
    app._import_usb()
    assert app.security.state == State.LOCKED
    assert app.wallet_root is None


def test_gui_unavailable_qr_camera_locks_wallet():
    app, _ = ui_fixture()
    app._import_qr()
    assert app.security.state == State.LOCKED
    assert app.wallet_root is None


def test_process_local_core_dump_limit_is_required(monkeypatch):
    calls = []
    monkeypatch.setattr(gui.resource, "setrlimit", lambda kind, limit: calls.append((kind, limit)))
    monkeypatch.setattr(gui.resource, "getrlimit", lambda kind: (0, 0))
    gui._block_process_core_dumps()
    assert calls == [(gui.resource.RLIMIT_CORE, (0, 0))]


def test_gui_quota_locks_after_third_signature():
    app, clock = ui_fixture()
    for index in range(3):
        digest = str(index) * 64
        session = StubReview(digest)
        app.session = session
        app.security.start_review(digest)
        app._sign()
        assert session.signed
        if index < 2:
            assert app.wallet_root is not None
            app._next_transaction()
    assert app.wallet_root is None
    assert app.security.state == State.LOCKED


def test_qr_reader_never_blocks_with_unlocked_wallet_root():
    app, _ = ui_fixture()
    app.selected_kind = "evm-request"
    snapshots = []

    def stuck_camera():
        # The GUI event loop cannot run a timer while this callback blocks.
        snapshots.append((app.wallet_root, app.security.state))
        raise gui.CameraUnavailable("camera unavailable")

    app.qr_reader = stuck_camera
    app._import_qr()
    assert snapshots == [(None, State.LOCKED)]
    assert app.wallet_root is None
    assert app.security.state == State.LOCKED


def test_in_place_usb_mutation_blocks_signing_with_same_inode(tmp_path):
    app, _ = ui_fixture()
    transfer = tmp_path / "unsigned-request.json"
    original = b"original snapshot bytes"
    transfer.write_bytes(original)
    info = transfer.lstat()
    app._active_usb_file = transfer
    app._active_usb_identity = (info.st_dev, info.st_ino)
    app._active_usb_digest = hashlib.sha256(original).digest()
    review = StubReview("f" * 64)
    app.session = review
    app.security.start_review(review.plan.review_digest)
    assert app._transport_available()
    transfer.write_bytes(b"rewritten snapshot data")
    assert (transfer.lstat().st_dev, transfer.lstat().st_ino) == app._active_usb_identity
    assert not app._transport_available()
    app._sign()
    assert review.sign_calls == 0
    assert app.security.state == State.LOCKED


def test_choose_kind_defers_unlock_until_after_usb_or_camera_capture():
    app, _ = ui_fixture()
    app._lock_wallet()
    app._unlock = lambda: (_ for _ in ()).throw(AssertionError("Do not unlock at menu selection"))
    app._render_import = lambda: app.rendered.append("import")
    app._choose_kind("evm-request")
    assert app.selected_kind == "evm-request"
    assert app.wallet_root is None
    assert app.security.state == State.LOCKED
    assert app.rendered == ["import"]


def test_bad_usb_is_rejected_without_unlocking_wallet(tmp_path):
    app, _ = ui_fixture()
    app._lock_wallet()
    app.selected_kind = "evm-request"
    malicious = tmp_path / "request.json"
    malicious.write_bytes(b"not a valid exchange")
    app.filedialog = SimpleNamespace(askopenfilename=lambda **kwargs: str(malicious))
    app._unlock = lambda: (_ for _ in ()).throw(AssertionError("Reject bad USB before unlock"))
    app._import_usb()
    assert app.security.state == State.LOCKED
    assert app.wallet_root is None
    assert app.messagebox.errors


def test_usb_import_reviews_exact_bytes_and_unlocks_only_after_validation(tmp_path):
    import json
    from usb_cold_wallet.exchange import package
    from usb_cold_wallet.keys import root_from_mnemonic

    app, _ = ui_fixture()
    app._lock_wallet()
    app.selected_kind = "evm-request"
    app.transfer_dir = tmp_path
    real_root = root_from_mnemonic("abandon " * 11 + "about")
    tx = {
        "type": 2, "chainId": 11155111, "nonce": 1,
        "to": "0x000000000000000000000000000000000000dEaD",
        "value": 123456789123456789, "gas": 21000,
        "maxFeePerGas": 2000000000, "maxPriorityFeePerGas": 1000000000,
    }
    request = tmp_path / "unsigned.json"
    raw = json.dumps(package("evm-request", tx)).encode("ascii")
    request.write_bytes(raw)
    app.filedialog = SimpleNamespace(askopenfilename=lambda **kwargs: str(request))
    unlocked = []
    def unlock():
        unlocked.append("after input parsed")
        app.wallet_root = real_root
        return True
    app._unlock = unlock
    captured = []
    app._start_review = lambda plan: captured.append(plan)
    app._import_usb()
    assert unlocked == ["after input parsed"]
    assert len(captured) == 1
    assert captured[0].request_digest == package("evm-request", tx)["sha256"]
    assert app._active_usb_digest == hashlib.sha256(raw).digest()
    assert app._transport_available()


def test_usb_mutation_while_unlocking_fails_before_review(tmp_path):
    import json
    from usb_cold_wallet.exchange import package
    from usb_cold_wallet.keys import root_from_mnemonic

    app, _ = ui_fixture()
    app._lock_wallet()
    app.selected_kind = "evm-request"
    app.transfer_dir = tmp_path
    tx = {
        "type": 2, "chainId": 11155111, "nonce": 1,
        "to": "0x000000000000000000000000000000000000dEaD",
        "value": 1000000000000, "gas": 21000,
        "maxFeePerGas": 2000000000, "maxPriorityFeePerGas": 1000000000,
    }
    request = tmp_path / "unsigned.json"
    request.write_bytes(json.dumps(package("evm-request", tx)).encode("ascii"))
    app.filedialog = SimpleNamespace(askopenfilename=lambda **kwargs: str(request))
    def unlock():
        # Same inode: content changes while the modal passphrase is entered.
        request.write_bytes(b"tampered after pre-unlock validation")
        app.wallet_root = root_from_mnemonic("abandon " * 11 + "about")
        return True
    app._unlock = unlock
    app._start_review = lambda _: (_ for _ in ()).throw(AssertionError("Must not review changed USB"))
    app._import_usb()
    assert app.wallet_root is None
    assert app.security.state == State.LOCKED
    assert app.messagebox.errors
