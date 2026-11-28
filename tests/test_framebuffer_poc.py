"""Host security tests for the framebuffer POC; never substitute for QEMU pixels."""
from dataclasses import replace
from pathlib import Path
import ast
import hashlib
import struct

import pytest

import usb_cold_wallet.framebuffer_poc as fb
from usb_cold_wallet.exchange import package
from usb_cold_wallet.keys import root_from_mnemonic
from usb_cold_wallet.review import (ReviewField, ReviewPage, build_review_plan,
                                    _canonical, _review_document)
from usb_cold_wallet.signer_session import SignerSession, State


PUBLIC_TEST_MNEMONIC = "abandon " * 11 + "about"
EVM_RECIPIENT = "0x000000000000000000000000000000000000dEaD"


def _font():
    return (8, 16, bytes(256 * 16))


def _plan():
    root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    tx = {
        "type": 2,
        "chainId": 11155111,
        "nonce": 7,
        "to": EVM_RECIPIENT,
        "value": 1_000_000_000_000,
        "gas": 21_000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
        "data": "0x",
        "accessList": [],
    }
    return build_review_plan(package("evm-request", tx), root, "evm-request")


def _rebind_pages(plan, pages):
    pages = tuple(pages)
    reviewed = (pages[0], *pages[2:])
    digest = hashlib.sha256(
        _canonical(_review_document(plan.kind, plan.request_digest, reviewed))
    ).hexdigest()
    integrity = ReviewPage(
        "integrity",
        (
            ReviewField("request_digest", plan.request_digest, "verified exchange envelope.sha256"),
            ReviewField("review_digest", digest, "SHA-256(canonical offline reviewed fields)"),
        ),
    )
    return replace(
        plan,
        review_digest=digest,
        pages=(pages[0], integrity, *pages[2:]),
        challenge=f"SIGN {plan.kind.upper()} {plan.recipient[-8:]} {digest[:8]}",
    )


def test_renderer_accepts_real_backend_review_plan_and_never_elides_long_fields():
    display = fb.Surface(640, 480, _font())
    plan = _plan()
    long_field = ReviewField("calldata", "X" * 5000, "payload.data")
    pages = list(plan.pages)
    pages[-1] = ReviewPage(pages[-1].key, pages[-1].fields + (long_field,))
    plan = _rebind_pages(plan, pages)

    count = fb.render_review(display, plan, len(plan.pages) - 1)
    assert count > (display.height - 160) // 19
    assert display.ppm().startswith(b"P6\n640 480\n255\n")
    assert fb.render_review(display, plan, len(plan.pages) - 1, line_offset=100) == count


def test_all_real_review_pages_require_explicit_acknowledgement_and_separate_confirm():
    plan = _plan()
    ctrl = fb.ReviewController(plan, audit=lambda: True)
    for index in range(len(plan.pages)):
        if index:
            ctrl.action("RIGHT")
        assert ctrl.action("ENTER") is False
    assert ctrl.seen == set(range(len(plan.pages)))
    assert ctrl.action("CONFIRM") is True


def test_long_page_cannot_acknowledge_before_scrolling_to_end():
    ctrl = fb.ReviewController(_plan(), audit=lambda: True)
    ctrl.scroll_bottom = 4
    assert ctrl.action("ENTER") is False
    for _ in range(4):
        ctrl.action("DOWN")
    assert ctrl.action("ENTER") is False
    assert ctrl.seen == {0}


def test_cancel_and_audit_failure_fail_closed():
    ctrl = fb.ReviewController(_plan(), audit=lambda: True)
    assert ctrl.action("ESC") is False
    assert ctrl.cancelled
    assert ctrl.action("ENTER") is False

    ctrl = fb.ReviewController(_plan(), audit=lambda: False)
    assert ctrl.action("ENTER") is False
    assert ctrl.locked
    assert not ctrl.seen

    ctrl = fb.ReviewController(_plan(), audit=lambda: (_ for _ in ()).throw(OSError("audit")))
    assert ctrl.action("ENTER") is False
    assert ctrl.locked


def test_only_existing_review_plan_type_is_accepted():
    with pytest.raises(TypeError):
        fb.ReviewController(object(), audit=lambda: True)


def test_secret_bearing_review_fields_are_rejected():
    plan = _plan()
    pages = list(plan.pages)
    pages[0] = ReviewPage(
        pages[0].key,
        pages[0].fields + (ReviewField("wallet_passphrase", "do-not-display", "vault passphrase"),),
    )
    plan = _rebind_pages(plan, pages)
    with pytest.raises(ValueError, match="Secret-bearing"):
        fb.render_review(fb.Surface(640, 480, _font()), plan, 0)


def test_invalid_page_and_geometry_rejected():
    surface = fb.Surface(320, 240, _font())
    with pytest.raises(ValueError):
        fb.render_review(surface, _plan(), 99)
    with pytest.raises(ValueError):
        fb.Surface(100, 100, _font())


def test_unrepresentable_review_text_fails_closed():
    plan = _plan()
    pages = list(plan.pages)
    pages[0] = ReviewPage(
        pages[0].key,
        pages[0].fields + (ReviewField("memo", "pay\nnow", "payload.memo"),),
    )
    plan = _rebind_pages(plan, pages)
    with pytest.raises(ValueError, match="cannot represent exactly"):
        fb.render_review(fb.Surface(640, 480, _font()), plan, 0)


def test_tampered_review_pages_are_rejected_before_render():
    plan = _plan()
    pages = list(plan.pages)
    original = pages[-1]
    pages[-1] = ReviewPage(
        original.key,
        original.fields + (ReviewField("recipient", EVM_RECIPIENT[:-1] + "0", "tampered"),),
    )
    tampered = replace(plan, pages=tuple(pages))
    with pytest.raises(ValueError, match="do not match review digest"):
        fb.render_review(fb.Surface(640, 480, _font()), tampered, len(pages) - 1)


def test_tampered_integrity_page_is_rejected():
    plan = _plan()
    pages = list(plan.pages)
    pages[1] = ReviewPage(
        "integrity",
        (
            ReviewField("request_digest", plan.request_digest, "verified exchange envelope.sha256"),
            ReviewField("review_digest", "0" * 64, "SHA-256(canonical offline reviewed fields)"),
        ),
    )
    with pytest.raises(ValueError, match="integrity page is inconsistent"):
        fb.render_review(fb.Surface(640, 480, _font()), replace(plan, pages=tuple(pages)), 1)


def test_psf2_font_is_exact_bounded_direct_index_format(tmp_path: Path):
    font = tmp_path / "font.psf"
    font.write_bytes(b"no")
    with pytest.raises(ValueError):
        fb.load_psf2(font)

    header = struct.pack("<8I", fb.PSF2_MAGIC, 0, 32, 0, 256, 16, 16, 8)
    font.write_bytes(header + bytes(256 * 16))
    assert fb.load_psf2(font)[:2] == (8, 16)

    font.write_bytes(struct.pack("<8I", fb.PSF2_MAGIC, 0, 32, 1, 256, 16, 16, 8) + bytes(256 * 16))
    with pytest.raises(ValueError):
        fb.load_psf2(font)

    font.write_bytes(header + bytes(256 * 16) + b"trailing")
    with pytest.raises(ValueError):
        fb.load_psf2(font)


def test_split_arrow_sequence_is_parsed_and_malformed_escape_cancels(monkeypatch):
    reads = iter((b"\x1b", b"[", b"B"))
    monkeypatch.setattr(fb.select, "select", lambda *args: ([3], [], []))
    monkeypatch.setattr(fb.os, "read", lambda fd, size: next(reads))
    assert fb._read_key(3) == "DOWN"

    calls = iter((([3], [], []), ([], [], [])))
    monkeypatch.setattr(fb.select, "select", lambda *args: next(calls))
    monkeypatch.setattr(fb.os, "read", lambda fd, size: b"\x1b")
    assert fb._read_key(3) == "ESC"


def test_runtime_imports_have_no_socket_x11_or_subprocess_dependency():
    source = Path(fb.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported |= {
        node.module.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not ({"socket", "subprocess", "tkinter", "Xlib"} & imported)
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "AF_UNIX"
        for node in ast.walk(tree)
    )
    assert "SignerSession(" not in source
    assert "sign_review_plan(" not in source


def test_vt_return_flushes_gui_keystrokes_before_restoring_menu(monkeypatch):
    calls = []
    original = ["canonical-menu-state"]
    monkeypatch.setattr(
        fb.termios, "tcflush",
        lambda fd, how: calls.append(("flush", fd, how)),
    )
    monkeypatch.setattr(
        fb.termios, "tcsetattr",
        lambda fd, when, value: calls.append(("restore", fd, when, value)),
    )
    fb._restore_tty_input(17, original)
    assert calls == [
        ("flush", 17, fb.termios.TCIFLUSH),
        ("restore", 17, fb.termios.TCSAFLUSH, original),
    ]


def test_vt_flush_failure_still_restores_tty_but_fails_closed(monkeypatch):
    calls = []
    def fail_flush(fd, how):
        calls.append(("flush", fd, how))
        raise OSError("input flush failed")
    monkeypatch.setattr(fb.termios, "tcflush", fail_flush)
    monkeypatch.setattr(
        fb.termios, "tcsetattr",
        lambda fd, when, settings: calls.append(("restore", fd, when)),
    )
    with pytest.raises(RuntimeError, match="buffered GUI keyboard"):
        fb._restore_tty_input(17, ["canonical"])
    assert calls[-1] == ("restore", 17, fb.termios.TCSAFLUSH)


def test_vt_graphics_and_switch_lock_controls_remain_required():
    assert fb.KD_GRAPHICS == 1
    assert fb.KD_TEXT == 0
    assert fb.VT_LOCKSWITCH != fb.VT_UNLOCKSWITCH


def test_framebuffer_idle_timeout_clears_all_acknowledgements():
    clock = [0.0]
    ctrl = fb.ReviewController(_plan(), audit=lambda: True, clock=lambda: clock[0])
    assert ctrl.action("ENTER") is False
    assert ctrl.seen == {0}
    clock[0] = 599.0
    assert ctrl.action("") is False
    clock[0] = 600.0
    assert ctrl.action("ENTER") is False
    assert ctrl.locked is True
    assert ctrl.lock_reason == "idle_timeout"
    assert ctrl.seen == set()
    clock[0] = 601.0
    assert ctrl.action("ENTER") is False


def test_framebuffer_ignored_keys_cannot_extend_idle_deadline():
    clock = [0.0]
    ctrl = fb.ReviewController(_plan(), audit=lambda: True, clock=lambda: clock[0])
    clock[0] = 599.0
    assert ctrl.action("UNKNOWN") is False
    clock[0] = 600.0
    assert ctrl.action("ENTER") is False
    assert ctrl.lock_reason == "idle_timeout"


def test_framebuffer_clock_rollback_and_nonfinite_clock_fail_closed():
    clock = [100.0]
    ctrl = fb.ReviewController(_plan(), audit=lambda: True, clock=lambda: clock[0])
    ctrl.action("ENTER")
    clock[0] = 99.0
    assert ctrl.action("ENTER") is False
    assert ctrl.lock_reason == "clock_reversed"
    assert ctrl.seen == set()

    clock[0] = 100.0
    ctrl = fb.ReviewController(_plan(), audit=lambda: True, clock=lambda: clock[0])
    clock[0] = float("nan")
    assert ctrl.action("ENTER") is False
    assert ctrl.lock_reason == "clock_failed"
    assert ctrl.seen == set()


def test_framebuffer_idle_timeout_rejects_unsafe_configuration():
    for value in (0, 601, True, 600.0):
        with pytest.raises(ValueError, match="idle timeout"):
            fb.ReviewController(_plan(), audit=lambda: True, idle_seconds=value)



def test_evdev_decoder_never_maps_mouse_or_key_repeat_to_confirmation():
    press_enter = fb._INPUT_EVENT.pack(1, 0, fb.EV_KEY, fb.KEY_ENTER, 1)
    press_confirm = fb._INPUT_EVENT.pack(1, 1, fb.EV_KEY, fb.KEY_C, 1)
    repeat_confirm = fb._INPUT_EVENT.pack(1, 2, fb.EV_KEY, fb.KEY_C, 2)
    mouse_left = fb._INPUT_EVENT.pack(1, 3, fb.EV_KEY, 272, 1)
    assert fb._decode_evdev(press_enter) == "ENTER"
    assert fb._decode_evdev(press_confirm) == "CONFIRM"
    assert fb._decode_evdev(repeat_confirm) == ""
    assert fb._decode_evdev(mouse_left) == ""


def test_framebuffer_discovery_is_unambiguous_and_fails_closed(tmp_path: Path):
    with pytest.raises(OSError, match="Exactly one"):
        fb._discover_framebuffer(dev_root=tmp_path)
    first = tmp_path / "fb0"
    first.write_bytes(b"")
    assert fb._discover_framebuffer(dev_root=tmp_path) == str(first)
    (tmp_path / "fb1").write_bytes(b"")
    with pytest.raises(OSError, match="Exactly one"):
        fb._discover_framebuffer(dev_root=tmp_path)


def _unlocked_signer(plan, audit=lambda: True):
    signer = SignerSession(audit=audit, on_lock=lambda: None)
    signer.begin_unlock()
    signer.unlock_succeeded()
    signer.start_review(plan.review_digest)
    return signer


def test_signer_session_cannot_cross_signing_gate_before_framebuffer_confirm():
    plan = _plan()
    signer = _unlocked_signer(plan)
    with pytest.raises(ValueError, match="independent approval"):
        signer.signing(plan.review_digest)
    assert signer.state == State.LOCKED


def test_framebuffer_confirm_rebuilds_same_plan_before_signer_approval():
    plan = _plan()
    signer = _unlocked_signer(plan)
    intent = fb.ReviewIntent(plan.review_digest, True, "reviewed")
    assert fb.authorize_review_intent(
        plan, intent, signer, rebuild_plan=_plan, audit=lambda: True)
    assert signer.state == State.APPROVED
    signer.signing(plan.review_digest)


def test_framebuffer_reject_or_changed_request_locks_signer():
    plan = _plan()
    signer = _unlocked_signer(plan)
    rejected = fb.ReviewIntent(plan.review_digest, False, "cancelled")
    assert not fb.authorize_review_intent(
        plan, rejected, signer, rebuild_plan=_plan, audit=lambda: True)
    assert signer.state == State.LOCKED

    signer = _unlocked_signer(plan)
    intent = fb.ReviewIntent(plan.review_digest, True, "reviewed")
    with pytest.raises(ValueError, match="changed after framebuffer review"):
        fb.authorize_review_intent(
            plan,
            intent,
            signer,
            rebuild_plan=lambda: replace(plan, network="wrong-network"),
            audit=lambda: True,
        )
    assert signer.state == State.LOCKED


def test_framebuffer_final_runtime_audit_failure_locks_signer():
    plan = _plan()
    signer = _unlocked_signer(plan)
    intent = fb.ReviewIntent(plan.review_digest, True, "reviewed")
    with pytest.raises(ValueError, match="safety audit failed"):
        fb.authorize_review_intent(
            plan, intent, signer, rebuild_plan=_plan, audit=lambda: False)
    assert signer.state == State.LOCKED



def test_evdev_same_path_replacement_fails_closed(tmp_path: Path):
    event = tmp_path / "event0"
    event.write_bytes(b"old")
    with fb.EvdevInput(tmp_path) as inputs:
        original = tmp_path / "event0.old"
        event.rename(original)
        event.write_bytes(b"new")
        with pytest.raises(fb.InputDeviceChanged, match="identity changed"):
            inputs._assert_stable()



def _fake_fb_ioctl(*, xres=800, yres=600, xv=800, yv=600, bpp=32,
                   red=(16, 8, 0), green=(8, 8, 0), blue=(0, 8, 0)):
    def ioctl(_fd, request, buf, _mutate):
        if request == fb.FBIOGET_VSCREENINFO:
            struct.pack_into("<7I", buf, 0, xres, yres, xv, yv, 0, 0, bpp)
            for offset, field in ((32, red), (44, green), (56, blue)):
                struct.pack_into("<III", buf, offset, *field)
        elif request == fb.FBIOGET_FSCREENINFO:
            struct.pack_into("<I", buf, 24, xres * yres * max(1, bpp // 8))
            struct.pack_into("<I", buf, 48, xres * max(1, bpp // 8))
        else:
            raise AssertionError("unexpected ioctl")
        return 0
    return ioctl


def test_framebuffer_resolution_and_pixel_format_fail_closed(monkeypatch):
    monkeypatch.setattr(fb.fcntl, "ioctl", _fake_fb_ioctl(xv=801))
    with pytest.raises(ValueError, match="pixel layout"):
        fb._fb_geometry(3)

    monkeypatch.setattr(fb.fcntl, "ioctl", _fake_fb_ioctl(bpp=24))
    with pytest.raises(ValueError, match="pixel layout"):
        fb._fb_geometry(3)

    monkeypatch.setattr(
        fb.fcntl, "ioctl",
        _fake_fb_ioctl(red=(0, 8, 0), green=(8, 8, 0), blue=(16, 8, 0)),
    )
    with pytest.raises(ValueError, match="XRGB8888"):
        fb._fb_geometry(3)

    monkeypatch.setattr(
        fb.fcntl, "ioctl",
        _fake_fb_ioctl(
            bpp=16, red=(11, 5, 0), green=(5, 6, 0), blue=(0, 5, 0)
        ),
    )
    assert fb._fb_geometry(3) == (800, 600, 16, 1600)


def test_framebuffer_open_rejects_regular_file_and_symlink(tmp_path: Path):
    fake = tmp_path / "fb0"
    fake.write_bytes(b"not a device")
    with pytest.raises(OSError, match="character device"):
        fb._open_framebuffer(str(fake))
    link = tmp_path / "fb1"
    link.symlink_to(fake)
    with pytest.raises(OSError):
        fb._open_framebuffer(str(link))


def test_framebuffer_identity_comparison_rejects_unpinned_device(monkeypatch):
    # A real character device is sufficient to test a changed expected inode.
    import os
    device = "/dev/null"
    identity = os.stat(device)
    with pytest.raises(OSError, match="identity changed"):
        fb._open_framebuffer(device, (identity.st_dev, identity.st_ino + 1, identity.st_rdev))


def test_menu_marker_is_distinct_from_one_shot_console_ready():
    """Regression for CI run 46144840043: two READY markers on the first menu."""
    root = Path(__file__).resolve().parents[1]
    appliance = (root / "src/usb_cold_wallet/appliance.py").read_text()
    verifier = (root / "scripts/verify_framebuffer_qemu.sh").read_text()
    assert '_serial_marker("USB_WALLET_CONSOLE_READY")' not in appliance
    assert '_serial_marker("USB_WALLET_CONSOLE_MENU")' in appliance
    assert 'marker_count USB_WALLET_CONSOLE_MENU)"' in verifier
    assert 'observed="$(marker_count USB_WALLET_CONSOLE_READY)"' not in verifier

