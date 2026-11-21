"""GUI-to-signer integration without Tk/physical wallet or any secret fixture."""
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
    app.session = None
    app.selected_kind = None
    app.page_index = 0
    app.status_message = ""
    app.messagebox = StubMessagebox()
    app.root = object()
    app.transfer_dir = Path("/tmp")
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
